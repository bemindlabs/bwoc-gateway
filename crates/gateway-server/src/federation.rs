//! Multi-gateway federation: peer gateways relay across regions/orgs so an
//! agent homed on gateway A can reach an agent homed on gateway B.
//!
//! Topology is a **static peer list** (`BWOC_GATEWAY_PEERS`, comma-separated
//! base URLs). When a recipient is offline locally, [`Federation::forward`]
//! asks each peer — over plain HTTP `POST /v1/federate` — to deliver to a
//! *locally-connected* agent. The first peer that reports `delivered` wins.
//!
//! **Loop-safe by construction:** the `/v1/federate` handler only attempts
//! local presence delivery and never forwards onward, so a federated envelope
//! is relayed at most one extra hop. No TTL or seen-set is needed.
//!
//! Federation does not change the trust model: peers exchange the same opaque,
//! end-to-end-signed envelopes. A malicious peer can drop or misreport delivery
//! but cannot forge a `sender` or read an (encrypted) `body`.
//!
//! **Optional peer secret.** `BWOC_GATEWAY_FEDERATE_TOKEN`, when set, must be
//! presented as `Authorization: Bearer <token>` on `POST /v1/federate`, and is
//! attached to this node's own outbound federation calls — so all peers in a
//! mesh share one value. It only fences the gateway-to-gateway door against
//! random internet traffic; it is not an identity and confers no trust on the
//! envelopes (those stay end-to-end signed and verified by the recipient).

use crate::wire::Envelope;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Result of a federation-ingress attempt, returned by `POST /v1/federate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederateResult {
    /// True iff the receiving gateway delivered to a locally-connected agent.
    pub delivered: bool,
}

/// Static set of peer gateways this node will fan out to.
pub struct Federation {
    peers: Vec<String>,
    http: reqwest::Client,
    /// Shared peer secret (`BWOC_GATEWAY_FEDERATE_TOKEN`); `None` = open door.
    token: Option<String>,
}

impl Federation {
    /// Build from `BWOC_GATEWAY_PEERS` (comma-separated base URLs, e.g.
    /// `https://gw-eu.example,https://gw-us.example`). Empty when unset.
    pub fn from_env() -> Self {
        let peers = std::env::var("BWOC_GATEWAY_PEERS")
            .map(|s| Self::parse_peers(&s))
            .unwrap_or_default();
        if peers.is_empty() {
            tracing::info!("federation: disabled (set BWOC_GATEWAY_PEERS to enable)");
        } else {
            tracing::info!(count = peers.len(), "federation: enabled");
        }
        let token = std::env::var("BWOC_GATEWAY_FEDERATE_TOKEN")
            .ok()
            .filter(|t| !t.is_empty());
        if token.is_some() {
            tracing::info!("federation: /v1/federate requires the shared peer token");
        }
        Self {
            peers,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("build federation http client"),
            token,
        }
    }

    /// Whether a `/v1/federate` request may proceed: always when no token is
    /// configured, otherwise only with `Authorization: Bearer <token>`
    /// (compared in constant time).
    pub fn ingress_allowed(&self, authorization: Option<&str>) -> bool {
        let Some(expected) = &self.token else {
            return true;
        };
        authorization
            .and_then(|h| h.strip_prefix("Bearer "))
            .is_some_and(|got| ct_eq(got.as_bytes(), expected.as_bytes()))
    }

    fn parse_peers(raw: &str) -> Vec<String> {
        raw.split(',')
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// Ask peers to deliver `env` to a locally-connected recipient. Returns
    /// `true` as soon as one peer reports delivery; `false` if none did (caller
    /// then parks for store-and-forward).
    pub async fn forward(&self, env: &Envelope) -> bool {
        for peer in &self.peers {
            let url = format!("{peer}/v1/federate");
            let mut req = self.http.post(&url).json(env);
            if let Some(token) = &self.token {
                req = req.bearer_auth(token);
            }
            match req.send().await {
                Ok(resp) if resp.status().is_success() => {
                    match resp.json::<FederateResult>().await {
                        Ok(r) if r.delivered => return true,
                        Ok(_) => {}
                        Err(e) => tracing::warn!(error = %e, %url, "bad federate response"),
                    }
                }
                Ok(resp) => tracing::debug!(status = %resp.status(), %url, "peer declined"),
                Err(e) => tracing::warn!(error = %e, %url, "peer unreachable"),
            }
        }
        false
    }
}

/// Constant-time byte comparison (length is not secret).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fed(token: Option<&str>) -> Federation {
        Federation {
            peers: vec![],
            http: reqwest::Client::new(),
            token: token.map(str::to_string),
        }
    }

    #[test]
    fn ingress_is_open_without_a_token() {
        assert!(fed(None).ingress_allowed(None));
        assert!(fed(None).ingress_allowed(Some("Bearer anything")));
    }

    #[test]
    fn ingress_requires_the_exact_bearer_token_when_set() {
        let f = fed(Some("s3cret"));
        assert!(f.ingress_allowed(Some("Bearer s3cret")));
        assert!(!f.ingress_allowed(None));
        assert!(!f.ingress_allowed(Some("Bearer wrong")));
        assert!(!f.ingress_allowed(Some("Bearer s3cret2")));
        assert!(!f.ingress_allowed(Some("s3cret")));
    }

    #[test]
    fn parses_and_normalizes_peer_list() {
        let peers = Federation::parse_peers(" https://a.example/ , https://b.example ,, ");
        assert_eq!(peers, vec!["https://a.example", "https://b.example"]);
    }

    #[test]
    fn empty_env_means_no_peers() {
        assert!(Federation::parse_peers("").is_empty());
    }

    #[tokio::test]
    async fn forward_with_no_peers_is_false() {
        let f = fed(None);
        let env = Envelope {
            recipient: "agent-x".into(),
            sender: "agent-y".into(),
            signature: "00".into(),
            body: serde_json::json!({}),
        };
        assert!(!f.forward(&env).await);
    }
}
