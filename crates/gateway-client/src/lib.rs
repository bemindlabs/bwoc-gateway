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

use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};

/// Default receive-side read timeout: 3× the server's 30 s liveness heartbeat.
///
/// The server Pings every `BWOC_GATEWAY_HEARTBEAT_SECS` (default 30 s), so a
/// live connection delivers *some* frame well inside this window even when it
/// is otherwise idle. Going three intervals without a single frame therefore
/// means the socket is half-open, not quiet.
const DEFAULT_RECV_READ_TIMEOUT: Duration = Duration::from_secs(90);

/// How long a receiving connection may go without reading **any** frame before
/// it is declared dead. `None` disables the check.
///
/// Override with `BWOC_GATEWAY_RECV_READ_TIMEOUT_SECS`; `0` (or a negative /
/// non-finite value) disables it, an unparseable value falls back to the
/// default rather than silently disabling the guard.
pub fn recv_read_timeout() -> Option<Duration> {
    let Ok(raw) = std::env::var("BWOC_GATEWAY_RECV_READ_TIMEOUT_SECS") else {
        return Some(DEFAULT_RECV_READ_TIMEOUT);
    };
    match raw.trim().parse::<f64>() {
        Ok(secs) if secs > 0.0 && secs.is_finite() => Some(Duration::from_secs_f64(secs)),
        // An explicit 0 / negative / inf means "disable" — the operator asked.
        Ok(_) => None,
        // Garbage must not disable a liveness guard: fail safe to the default.
        Err(_) => Some(DEFAULT_RECV_READ_TIMEOUT),
    }
}

/// Configuration for a gateway connection.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// e.g. `wss://gateway.bemind.tech/v1/connect`.
    pub url: String,
    /// The agent id this connection presents.
    pub agent_id: String,
    /// Whether this connection registers to *receive* (presence). Receivers set
    /// `true`; a one-shot sender sets `false` so it does not evict the agent's
    /// live receiver (which shares the same `agent_id`).
    pub recv: bool,
}

impl GatewayConfig {
    /// A receiving connection (registers presence). The default intent.
    pub fn new(url: impl Into<String>, agent_id: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            agent_id: agent_id.into(),
            recv: true,
        }
    }

    /// A send-only connection: it routes the envelopes it sends but never
    /// registers presence, so it cannot evict the agent's receiver.
    pub fn sender(url: impl Into<String>, agent_id: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            agent_id: agent_id.into(),
            recv: false,
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
    /// No frame — not even the server's liveness Ping — arrived in time. The
    /// socket is half-open: the relay has already evicted us and every message
    /// addressed here is being parked. Surfacing this as an error (rather than
    /// blocking forever) is what lets the supervisor respawn us and reconnect.
    #[error("read timeout: no frame from the relay in {0:?}; connection is half-open")]
    ReadTimeout(Duration),
}

// ---- wire types (mirror gateway-server/src/wire.rs) ----------------------

#[derive(Serialize)]
struct ClientHello<'a> {
    agent_id: &'a str,
    pubkey: String,
    /// `false` for one-shot senders so the relay does not register (and thus
    /// evict) the agent's receiver presence slot.
    recv: bool,
}

/// Where the relay routed an envelope this client sent (mirror of the server's
/// `DeliveryStatus`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    /// Handed to a live connection (local presence or a peer gateway).
    Delivered,
    /// Recipient offline; durably parked for store-and-forward.
    Parked,
}

/// A delivery receipt the relay returns for a sent envelope.
#[derive(Debug, Clone)]
pub struct DeliveryReceipt {
    pub recipient: String,
    pub status: DeliveryStatus,
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
    Challenge {
        nonce: String,
    },
    Deliver(Envelope),
    Receipt {
        recipient: String,
        status: DeliveryStatus,
    },
}

/// A live, authenticated connection to a gateway.
pub struct GatewayClient {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    agent_id: String,
    /// Liveness guard for the long-lived receive loop; `None` on one-shot
    /// senders, which are bounded by their own send/receipt round-trip.
    read_timeout: Option<Duration>,
}

impl GatewayClient {
    /// Connect, authenticate with `signing_key`, and return a ready client.
    pub async fn connect(
        config: &GatewayConfig,
        signing_key: &SigningKey,
    ) -> Result<Self, ClientError> {
        let (mut ws, _) = connect_async(&config.url).await?;
        // Receivers hold this socket open indefinitely, so they need the
        // liveness guard; a sender's exchange is bounded by its own receipt.
        let read_timeout = if config.recv {
            recv_read_timeout()
        } else {
            None
        };

        // 1. ClientHello
        let pubkey = hex::encode(signing_key.verifying_key().to_bytes());
        let hello = ClientHello {
            agent_id: &config.agent_id,
            pubkey,
            recv: config.recv,
        };
        ws.send(Message::Text(serde_json::to_string(&hello)?))
            .await?;

        // 2. Challenge → sign nonce
        let nonce_hex = match next_text(&mut ws, read_timeout).await? {
            Some(t) => match serde_json::from_str::<ServerFrame>(&t)? {
                ServerFrame::Challenge { nonce } => nonce,
                ServerFrame::Deliver(_) | ServerFrame::Receipt { .. } => {
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
            read_timeout,
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

    /// Flush and close the connection so a one-shot sender's just-sent frame is
    /// read by the relay before the process exits (otherwise the socket can drop
    /// before the relay reads it, silently losing the message).
    ///
    /// Best-effort and **error-tolerant**: send a Close frame, then drain until
    /// the stream ends. The relay closes abruptly (a reset, not a graceful close
    /// handshake) after it breaks its relay loop — that surfaces as a
    /// `ConnectionReset` here and is expected, NOT a failure: by then it has
    /// already read and routed our frame. So drain errors are swallowed; only
    /// the prior `send` reports real send failures.
    pub async fn close(&mut self) -> Result<(), ClientError> {
        let _ = self.ws.close(None).await;
        while let Some(Ok(_)) = self.ws.next().await {}
        Ok(())
    }

    /// Await the next envelope delivered to us, or `None` when the stream ends.
    pub async fn next_envelope(&mut self) -> Result<Option<Envelope>, ClientError> {
        while let Some(t) = next_text(&mut self.ws, self.read_timeout).await? {
            match serde_json::from_str::<ServerFrame>(&t)? {
                ServerFrame::Deliver(env) => return Ok(Some(env)),
                // Unexpected post-auth on a receiver; ignore and keep reading.
                ServerFrame::Challenge { .. } | ServerFrame::Receipt { .. } => continue,
            }
        }
        Ok(None)
    }

    /// Await the relay's delivery receipt for an envelope we just sent. Returns
    /// `None` if the stream ends before a receipt arrives (treat as unknown /
    /// failure). Used by one-shot senders to reflect delivery in their exit code.
    pub async fn await_receipt(&mut self) -> Result<Option<DeliveryReceipt>, ClientError> {
        while let Some(t) = next_text(&mut self.ws, self.read_timeout).await? {
            match serde_json::from_str::<ServerFrame>(&t)? {
                ServerFrame::Receipt { recipient, status } => {
                    return Ok(Some(DeliveryReceipt { recipient, status }))
                }
                // A sender shouldn't get deliveries/challenges; ignore and wait.
                ServerFrame::Deliver(_) | ServerFrame::Challenge { .. } => continue,
            }
        }
        Ok(None)
    }
}

/// Pull the next text frame, transparently answering pings and skipping other
/// control/binary frames.
///
/// `read_timeout` bounds the wait for **each frame**, not for the next *text*
/// frame — an idle-but-healthy connection still carries the server's periodic
/// Ping, which resets the clock. Bounding the text-frame wait instead would tear
/// down perfectly good connections that simply have no mail to deliver.
async fn next_text(
    ws: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
    read_timeout: Option<Duration>,
) -> Result<Option<String>, ClientError> {
    loop {
        // Scoped so the `ws.next()` borrow ends before we Pong on the same `ws`.
        let frame = {
            let next = ws.next();
            match read_timeout {
                Some(d) => tokio::time::timeout(d, next)
                    .await
                    .map_err(|_| ClientError::ReadTimeout(d))?,
                None => next.await,
            }
        };
        let Some(msg) = frame else { return Ok(None) };
        match msg? {
            Message::Text(t) => return Ok(Some(t.to_string())),
            Message::Ping(p) => ws.send(Message::Pong(p)).await?,
            Message::Close(_) => return Ok(None),
            _ => {}
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

    /// One test, sequential cases: the env var is process-global, so splitting
    /// these into separate `#[test]`s would let the parallel harness race them.
    #[test]
    fn recv_read_timeout_env_matrix() {
        const VAR: &str = "BWOC_GATEWAY_RECV_READ_TIMEOUT_SECS";

        // Unset → the default guard is ON. This is the case that matters: the
        // bridge must never idle forever just because nobody configured it.
        std::env::remove_var(VAR);
        assert_eq!(recv_read_timeout(), Some(DEFAULT_RECV_READ_TIMEOUT));
        assert!(
            DEFAULT_RECV_READ_TIMEOUT >= Duration::from_secs(90),
            "default must clear several server heartbeats or healthy idle \
             connections get torn down"
        );

        std::env::set_var(VAR, "45");
        assert_eq!(recv_read_timeout(), Some(Duration::from_secs(45)));

        std::env::set_var(VAR, " 12.5 ");
        assert_eq!(recv_read_timeout(), Some(Duration::from_secs_f64(12.5)));

        // Explicit opt-out.
        std::env::set_var(VAR, "0");
        assert_eq!(recv_read_timeout(), None);
        std::env::set_var(VAR, "-5");
        assert_eq!(recv_read_timeout(), None);

        // Garbage must fail *safe* (guard on), not silently disable it.
        std::env::set_var(VAR, "banana");
        assert_eq!(recv_read_timeout(), Some(DEFAULT_RECV_READ_TIMEOUT));
        std::env::set_var(VAR, "");
        assert_eq!(recv_read_timeout(), Some(DEFAULT_RECV_READ_TIMEOUT));
        std::env::set_var(VAR, "inf");
        assert_eq!(recv_read_timeout(), None, "non-finite is not a duration");

        std::env::remove_var(VAR);
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
