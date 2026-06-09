//! BWOC Gateway client — the connector an agent / the harness uses to reach a
//! `bwoc-gateway` server. It is the runtime behind the framework's
//! `RouteTarget::Gateway` (`routes.toml`), alongside `mqtt` and `a2a`.
//!
//! Flow:
//!   1. Open a WebSocket to `wss://<gateway>/v1/connect`.
//!   2. Send `ClientHello { agent_id, pubkey }`.
//!   3. Receive a `Challenge { nonce }`; sign it with the agent's ed25519 key;
//!      reply with the signature. (The keypair IS the login.)
//!   4. Stream signed envelopes both ways; the server relays by `recipient`.
//!
//! The client never trusts the gateway: inbound envelopes are still
//! signature-verified and Kalyāṇamitta-7-gated by the receiving harness, and
//! bodies may be sealed end-to-end via [`crypto`] so the relay sees only
//! ciphertext.

pub mod crypto;

use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};

/// Configuration for a gateway connection.
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

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("websocket: {0}")]
    Ws(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("handshake: {0}")]
    Handshake(&'static str),
    #[error("connection closed")]
    Closed,
}

// ---- wire types (mirror gateway-server/src/wire.rs) ----------------------

#[derive(Serialize)]
struct ClientHello<'a> {
    agent_id: &'a str,
    pubkey: String,
}

#[derive(Serialize)]
struct ChallengeResponse {
    signature: String,
}

/// A message relayed between agents. `body` is opaque to the gateway; seal it
/// with [`crypto::seal_to_hex`] for end-to-end confidentiality.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub recipient: String,
    pub sender: String,
    pub signature: String,
    pub body: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerFrame {
    // The server also sends `agent_id` here; the client doesn't need it, and
    // serde ignores the extra field.
    Challenge { nonce: String },
    Deliver(Envelope),
}

/// A live, authenticated connection to a gateway.
pub struct GatewayClient {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    agent_id: String,
}

impl GatewayClient {
    /// Connect, authenticate with `signing_key`, and return a ready client.
    pub async fn connect(
        config: &GatewayConfig,
        signing_key: &SigningKey,
    ) -> Result<Self, ClientError> {
        let (mut ws, _) = connect_async(&config.url).await?;

        // 1. ClientHello
        let pubkey = hex::encode(signing_key.verifying_key().to_bytes());
        let hello = ClientHello {
            agent_id: &config.agent_id,
            pubkey,
        };
        ws.send(Message::Text(serde_json::to_string(&hello)?))
            .await?;

        // 2. Challenge → sign nonce
        let nonce_hex = match next_text(&mut ws).await? {
            Some(t) => match serde_json::from_str::<ServerFrame>(&t)? {
                ServerFrame::Challenge { nonce } => nonce,
                ServerFrame::Deliver(_) => {
                    return Err(ClientError::Handshake("expected challenge"))
                }
            },
            None => return Err(ClientError::Closed),
        };
        let nonce = hex::decode(&nonce_hex).map_err(|_| ClientError::Handshake("bad nonce hex"))?;
        let sig = signing_key.sign(&nonce);
        let resp = ChallengeResponse {
            signature: hex::encode(sig.to_bytes()),
        };
        ws.send(Message::Text(serde_json::to_string(&resp)?))
            .await?;

        Ok(Self {
            ws,
            agent_id: config.agent_id.clone(),
        })
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// Send a (already signed, optionally sealed) envelope to the gateway.
    pub async fn send(&mut self, env: &Envelope) -> Result<(), ClientError> {
        self.ws
            .send(Message::Text(serde_json::to_string(env)?))
            .await?;
        Ok(())
    }

    /// Gracefully close the connection: send a Close frame and drain the stream
    /// until the relay completes the close handshake. A one-shot sender MUST
    /// call this after `send` — otherwise the process can exit (dropping the TCP
    /// socket) before the relay has read the just-sent frame, silently losing
    /// the message.
    pub async fn close(&mut self) -> Result<(), ClientError> {
        self.ws.close(None).await?;
        // Drain until the server's close ack ends the stream.
        while self.ws.next().await.transpose()?.is_some() {}
        Ok(())
    }

    /// Await the next envelope delivered to us, or `None` when the stream ends.
    pub async fn next_envelope(&mut self) -> Result<Option<Envelope>, ClientError> {
        while let Some(t) = next_text(&mut self.ws).await? {
            match serde_json::from_str::<ServerFrame>(&t)? {
                ServerFrame::Deliver(env) => return Ok(Some(env)),
                ServerFrame::Challenge { .. } => continue, // unexpected post-auth; ignore
            }
        }
        Ok(None)
    }
}

/// Pull the next text frame, transparently answering pings and skipping other
/// control/binary frames.
async fn next_text(
    ws: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
) -> Result<Option<String>, ClientError> {
    while let Some(msg) = ws.next().await {
        match msg? {
            Message::Text(t) => return Ok(Some(t.to_string())),
            Message::Ping(p) => ws.send(Message::Pong(p)).await?,
            Message::Close(_) => return Ok(None),
            _ => {}
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_builds() {
        let c = GatewayConfig::new("wss://example/v1/connect", "agent-erlang");
        assert_eq!(c.agent_id, "agent-erlang");
    }

    #[test]
    fn envelope_roundtrips_json() {
        let e = Envelope {
            recipient: "agent-b".into(),
            sender: "agent-a".into(),
            signature: "00".into(),
            body: serde_json::json!({"k": "v"}),
        };
        let s = serde_json::to_string(&e).unwrap();
        let back: Envelope = serde_json::from_str(&s).unwrap();
        assert_eq!(back.recipient, "agent-b");
    }
}
