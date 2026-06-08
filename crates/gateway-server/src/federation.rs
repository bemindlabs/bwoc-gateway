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
        Self {
            peers,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("build federation http client"),
        }
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
            match self.http.post(&url).json(env).send().await {
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let f = Federation {
            peers: vec![],
            http: reqwest::Client::new(),
        };
        let env = Envelope {
            recipient: "agent-x".into(),
            sender: "agent-y".into(),
            signature: "00".into(),
            body: serde_json::json!({}),
        };
        assert!(!f.forward(&env).await);
    }
}
