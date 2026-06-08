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
//! This build: persistent WebSocket per agent, signed-challenge auth (the
//! keypair IS the login), online relay-by-recipient, **durable store-and-forward**
//! for offline recipients (`store`), and **multi-gateway federation** (`federation`).
//! Delivery order for an inbound envelope: local presence → peer gateways →
//! park for store-and-forward. End-to-end body encryption is a client-side
//! concern (`gateway-client::crypto`); the relay keeps treating `body` as opaque.

mod auth;
mod federation;
mod presence;
mod store;
mod wire;

use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use federation::{FederateResult, Federation};
use presence::Presence;
use std::sync::Arc;
use store::Store;
use wire::{ClientHello, Envelope, ServerFrame};

/// Shared relay state, cheap to clone (everything behind `Arc`).
#[derive(Clone)]
struct AppState {
    presence: Arc<Presence>,
    store: Arc<Store>,
    federation: Arc<Federation>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "gateway_server=info".into()),
        )
        .init();

    let state = AppState {
        presence: Arc::new(Presence::default()),
        store: Arc::new(Store::from_env().await),
        federation: Arc::new(Federation::from_env()),
    };

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/connect", get(ws_upgrade))
        // Gateway-to-gateway: a peer asks us to deliver to a *locally* connected
        // agent. We never re-federate from here, so federation cannot loop.
        .route("/v1/federate", post(federate))
        .with_state(state);

    let addr = std::env::var("BWOC_GATEWAY_ADDR").unwrap_or_else(|_| "0.0.0.0:8787".into());
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("bind gateway address");
    tracing::info!(%addr, "bwoc-gateway listening");
    axum::serve(listener, app).await.expect("serve");
}

async fn ws_upgrade(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

/// Federation ingress: deliver `env` only if its recipient is connected *here*.
/// Loop-safe by construction — this handler never forwards onward.
async fn federate(
    State(state): State<AppState>,
    Json(env): Json<Envelope>,
) -> Json<FederateResult> {
    let delivered = state.presence.route(&env).await;
    tracing::debug!(recipient = %env.recipient, delivered, "federation ingress");
    Json(FederateResult { delivered })
}

/// One connection: signed-challenge auth → register presence → drain parked
/// mail → relay loop.
async fn handle_socket(mut socket: WebSocket, state: AppState) {
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
    state.presence.register(agent_id.clone(), tx).await;

    // Store-and-forward: flush anything parked while this agent was offline,
    // oldest first, before entering the live relay loop.
    for env in state.store.drain(&agent_id).await {
        let frame = ServerFrame::Deliver(env);
        if socket
            .send(Message::Text(frame.to_json().into()))
            .await
            .is_err()
        {
            state.presence.unregister(&agent_id).await;
            return;
        }
    }

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
                        Ok(env) => deliver(&state, env).await,
                        Err(e) => tracing::warn!(error = %e, "bad envelope; ignored"),
                    },
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {} // ignore ping/pong/binary
                    Some(Err(e)) => {
                        tracing::debug!(error = %e, "socket error");
                        break;
                    }
                }
            }
        }
    }

    state.presence.unregister(&agent_id).await;
    tracing::info!(%agent_id, "agent disconnected");
}

/// Deliver an envelope, escalating reachability: local presence → peer gateways
/// (federation) → durable store-and-forward. The gateway routes on the cleartext
/// `recipient` only; it never verifies the signature (the recipient harness does)
/// and cannot forge `sender`.
async fn deliver(state: &AppState, env: Envelope) {
    if state.presence.route(&env).await {
        return; // delivered to a locally-connected agent
    }
    if state.federation.forward(&env).await {
        tracing::debug!(recipient = %env.recipient, "delivered via peer gateway");
        return;
    }
    tracing::debug!(recipient = %env.recipient, "recipient offline; parking for store-and-forward");
    state.store.park(env).await;
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
