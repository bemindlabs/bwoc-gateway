//! BWOC Gateway — rendezvous + relay server for multi-place agent communication.
//!
//! Design principle (matches BWOC's decentralized grain): the gateway is a
//! **dumb, untrusted relay**, never a trust anchor.
//!   - Envelopes stay **end-to-end ed25519-signed** (authentication lives with
//!     the agents, per the framework SIGNING spec) — the gateway cannot forge a
//!     `sender`.
//!   - It is **presence/rendezvous, not the identity source of truth**: an
//!     agent's identity is its keypair, not a gateway account. The gateway only
//!     maps `agent_id -> live connection` and relays by `recipient`.
//!   - Authorization (Kalyāṇamitta-7) and capability gating stay in the
//!     receiving harness. The gateway never elevates trust.
//!
//! MVP (this scaffold): persistent WebSocket per agent, signed-challenge auth
//! (the keypair IS the login), online relay-by-recipient. Deferred: durable
//! store-and-forward, end-to-end body encryption, multi-gateway federation.

mod auth;
mod presence;
mod wire;

use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use presence::Presence;
use std::sync::Arc;
use wire::{ClientHello, Envelope, ServerFrame};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "gateway_server=info".into()),
        )
        .init();

    let presence = Arc::new(Presence::default());
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/connect", get(ws_upgrade))
        .with_state(presence);

    let addr = std::env::var("BWOC_GATEWAY_ADDR").unwrap_or_else(|_| "0.0.0.0:8787".into());
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("bind gateway address");
    tracing::info!(%addr, "bwoc-gateway listening");
    axum::serve(listener, app).await.expect("serve");
}

async fn ws_upgrade(
    ws: WebSocketUpgrade,
    State(presence): State<Arc<Presence>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, presence))
}

/// One connection: signed-challenge auth → register presence → relay loop.
async fn handle_socket(mut socket: WebSocket, presence: Arc<Presence>) {
    let agent_id = match authenticate(&mut socket).await {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(error = %e, "auth failed; closing");
            let _ = socket.send(Message::Close(None)).await;
            return;
        }
    };
    tracing::info!(%agent_id, "agent connected");

    // Inbound queue: other connections push envelopes addressed to this agent.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Envelope>(256);
    presence.register(agent_id.clone(), tx).await;

    // Single-task relay loop over the one socket: deliver queued envelopes to
    // this agent, and route envelopes this agent sends to their recipient.
    loop {
        tokio::select! {
            // Outbound: someone addressed this agent.
            queued = rx.recv() => {
                match queued {
                    Some(env) => {
                        let frame = ServerFrame::Deliver(env);
                        if socket.send(Message::Text(frame.to_json().into())).await.is_err() {
                            break;
                        }
                    }
                    None => break, // presence dropped our sender
                }
            }
            // Inbound: this agent sent an envelope to route.
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Text(txt))) => match Envelope::from_json(txt.as_str()) {
                        Ok(env) => {
                            // Route on the cleartext `recipient` header only. The
                            // gateway does NOT verify the signature (the recipient
                            // harness does) and cannot forge `sender`.
                            if !presence.route(&env).await {
                                tracing::debug!(
                                    recipient = %env.recipient,
                                    "recipient offline; dropped (store-and-forward deferred)"
                                );
                            }
                        }
                        Err(e) => tracing::warn!(error = %e, "bad envelope; ignored"),
                    },
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {} // ignore ping/pong/binary in MVP
                    Some(Err(e)) => {
                        tracing::debug!(error = %e, "socket error");
                        break;
                    }
                }
            }
        }
    }

    presence.unregister(&agent_id).await;
    tracing::info!(%agent_id, "agent disconnected");
}

/// Signed-challenge handshake. The client sends `ClientHello{agent_id, pubkey}`;
/// the server replies with a random nonce; the client returns the nonce signed
/// with its ed25519 key. The keypair IS the login — no passwords.
async fn authenticate(socket: &mut WebSocket) -> Result<String, auth::AuthError> {
    let hello: ClientHello = match socket.recv().await {
        Some(Ok(Message::Text(t))) => {
            ClientHello::from_json(t.as_str()).map_err(|_| auth::AuthError::BadHello)?
        }
        _ => return Err(auth::AuthError::NoHello),
    };
    let challenge = auth::Challenge::new(&hello.pubkey)?;
    socket
        .send(Message::Text(challenge.frame_json(&hello.agent_id).into()))
        .await
        .map_err(|_| auth::AuthError::Transport)?;
    let signed = match socket.recv().await {
        Some(Ok(Message::Text(t))) => t,
        _ => return Err(auth::AuthError::NoResponse),
    };
    challenge.verify_response(signed.as_str())?;
    Ok(hello.agent_id)
}
