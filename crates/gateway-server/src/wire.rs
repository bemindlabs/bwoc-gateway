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
    /// Whether this connection wants to *receive* (register presence). A one-shot
    /// sender sets `false` so it does NOT claim `agent_id`'s presence slot and
    /// evict that agent's live receiver (`Presence::register` is last-writer-wins).
    /// Defaults to `true` so existing receivers (which omit the field) still
    /// register.
    #[serde(default = "default_recv")]
    pub recv: bool,
}

fn default_recv() -> bool {
    true
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

/// Where an inbound envelope ended up — reported back to the sender as a
/// `Receipt` so a one-shot `bwoc-gateway-send` can tell *delivered-live* from
/// *parked-while-offline* (and reflect it in its exit code) instead of always
/// exiting 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    /// Handed to a live connection (local presence or a peer gateway).
    Delivered,
    /// Recipient offline; durably parked for store-and-forward.
    Parked,
}

/// Frames the server sends to a client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerFrame {
    /// Authentication challenge: sign `nonce` and return it.
    Challenge { agent_id: String, nonce: String },
    /// An inbound envelope addressed to this agent.
    Deliver(Envelope),
    /// Delivery receipt for an envelope the client just sent.
    Receipt {
        recipient: String,
        status: DeliveryStatus,
    },
}

impl ServerFrame {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("serialize server frame")
    }
}
