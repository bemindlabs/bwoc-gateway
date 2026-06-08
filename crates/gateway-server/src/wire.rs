//! On-the-wire types. The gateway treats the envelope `body` as opaque bytes —
//! it routes only on the cleartext `recipient` header. Bodies are signed
//! end-to-end (and, in a fast-follow, will be E2E-encrypted to the recipient's
//! key so the relay cannot read them).

use serde::{Deserialize, Serialize};

/// First frame a client sends after the WebSocket opens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    /// The agent's id (e.g. `agent-erlang`). Display/routing label only —
    /// trust derives from the keypair, not this string.
    pub agent_id: String,
    /// Hex-encoded ed25519 public key (32 bytes). This is the agent's identity.
    pub pubkey: String,
}

impl ClientHello {
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

/// A message relayed between agents. The gateway never mutates or signs it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Routing target — the only field the gateway reads.
    pub recipient: String,
    /// Claimed sender. Cannot be forged usefully: the recipient verifies
    /// `signature` against the sender's known key (framework SIGNING spec).
    pub sender: String,
    /// Hex ed25519 signature over the canonical `(sender, recipient, body)`.
    pub signature: String,
    /// Opaque payload (the inbox envelope). The gateway does not interpret it.
    pub body: serde_json::Value,
}

impl Envelope {
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

/// Frames the server sends to a client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerFrame {
    /// Authentication challenge: sign `nonce` and return it.
    Challenge { agent_id: String, nonce: String },
    /// An inbound envelope addressed to this agent.
    Deliver(Envelope),
}

impl ServerFrame {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("serialize server frame")
    }
}
