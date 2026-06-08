//! BWOC Gateway client (stub).
//!
//! This is the connector an agent / the harness uses to reach a `bwoc-gateway`
//! server — the intended home of a new `RouteTarget::Gateway` in the framework's
//! routing table (`routes.toml`), alongside `mqtt` and `a2a`.
//!
//! MVP plan (not yet implemented here):
//!   1. Open a WebSocket to `wss://<gateway>/v1/connect`.
//!   2. Send `ClientHello { agent_id, pubkey }`.
//!   3. Receive a `Challenge { nonce }`; sign it with the agent's ed25519 key;
//!      reply with the signature. (The keypair is the login.)
//!   4. Stream signed envelopes both ways; the server relays by `recipient`.
//!
//! The client never trusts the gateway: inbound envelopes are still
//! signature-verified and Kalyāṇamitta-7-gated by the receiving harness.

/// Configuration for a gateway connection (placeholder).
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// e.g. `wss://gateway.bemind.tech/v1/connect`.
    pub url: String,
    /// The agent id this connection presents.
    pub agent_id: String,
}

impl GatewayConfig {
    pub fn new(url: impl Into<String>, agent_id: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            agent_id: agent_id.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_builds() {
        let c = GatewayConfig::new("wss://example/v1/connect", "agent-erlang");
        assert_eq!(c.agent_id, "agent-erlang");
    }
}
