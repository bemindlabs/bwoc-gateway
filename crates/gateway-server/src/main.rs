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
mod resource;
mod store;
mod wire;

use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use federation::{FederateResult, Federation};
use presence::Presence;
use std::sync::Arc;
use std::time::Duration;
use store::Store;
use wire::{ClientHello, DeliveryStatus, Envelope, ServerFrame};

/// Shared relay state, cheap to clone (everything behind `Arc`).
#[derive(Clone)]
struct AppState {
    presence: Arc<Presence>,
    store: Arc<Store>,
    federation: Arc<Federation>,
    resources: Arc<resource::ResourceRegistry>,
}

#[tokio::main]
async fn main() {
    // Log to **stderr** (unbuffered) so logs aren't lost to stdout block-buffering
    // under docker/non-TTY. The default filter targets `bwoc_gateway` — the actual
    // binary crate name (`[[bin]] name = "bwoc-gateway"`), NOT the package name
    // `gateway-server`. A filter of `gateway_server=…` matches NOTHING (no event
    // has that target), which is exactly why the relay looked log-silent.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "bwoc_gateway=info".into()),
        )
        .init();

    let state = AppState {
        presence: Arc::new(Presence::default()),
        store: Arc::new(Store::from_env().await),
        federation: Arc::new(Federation::from_env()),
        resources: Arc::new(resource::ResourceRegistry::default()),
    };

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/connect", get(ws_upgrade))
        // Gateway-to-gateway: a peer asks us to deliver to a *locally* connected
        // agent. We never re-federate from here, so federation cannot loop.
        .route("/v1/federate", post(federate))
        // Resource broker (discovery half): providers advertise a snapshot,
        // consumers discover matching offers. Claim/lease rides the relay.
        .route("/v1/resource/advertise", post(resource::advertise))
        .route("/v1/resource/discover", post(resource::discover))
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

/// How long federation ingress waits for room in a local recipient's queue.
/// Kept under the peer's 5 s HTTP timeout so a full queue answers `delivered:
/// false` (the peer then parks it) instead of tying up the request.
const FEDERATE_DELIVERY_TIMEOUT: Duration = Duration::from_secs(2);

/// Federation ingress: deliver `env` only if its recipient is connected *here*.
/// Loop-safe by construction — this handler never forwards onward. Gated by the
/// optional shared peer token (see `federation`).
async fn federate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(env): Json<Envelope>,
) -> Response {
    let auth = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok());
    if !state.federation.ingress_allowed(auth) {
        tracing::warn!("federation ingress refused: missing or wrong peer token");
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let delivered = tokio::time::timeout(FEDERATE_DELIVERY_TIMEOUT, state.presence.route(&env))
        .await
        .unwrap_or(false);
    tracing::info!(recipient = %env.recipient, delivered, "federation ingress");
    Json(FederateResult { delivered }).into_response()
}

/// One connection: signed-challenge auth → register presence → drain parked
/// mail → relay loop.
async fn handle_socket(mut socket: WebSocket, state: AppState) {
    let (agent_id, wants_recv) = match authenticate(&mut socket).await {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(error = %e, "auth failed; closing");
            let _ = socket.send(Message::Close(None)).await;
            return;
        }
    };
    tracing::info!(%agent_id, wants_recv, "agent connected");

    // Inbound queue: other connections push envelopes addressed to this agent.
    // A one-shot sender (`wants_recv == false`) must NOT register: that would
    // claim `agent_id`'s presence slot (last-writer-wins) and evict the agent's
    // live receiver. So registration / store-drain / unregister are all gated on
    // `wants_recv` — a pure sender only routes the envelope it pushes.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Envelope>(256);
    // `token` identifies THIS registration so a stale teardown cannot evict a
    // newer connection that took over the slot (see presence.rs). `0` for a pure
    // sender, which never registers.
    let token = if wants_recv {
        let token = state.presence.register(agent_id.clone(), tx).await;

        // Store-and-forward: flush anything parked while this agent was offline,
        // oldest first, before entering the live relay loop.
        for env in state.store.drain(&agent_id).await {
            let frame = ServerFrame::Deliver(env);
            if socket
                .send(Message::Text(frame.to_json().into()))
                .await
                .is_err()
            {
                state.presence.unregister(&agent_id, token).await;
                return;
            }
        }
        token
    } else {
        0
    };

    // Liveness heartbeat: a half-open socket (e.g. a proxy/tailnet that drops
    // the downstream direction without a Close frame) keeps this agent's
    // presence slot registered, so the relay reports "delivered" while the
    // bytes vanish — the silent reverse-delivery bug. We Ping each interval and
    // require a Pong by the next one; a missing Pong means the connection is
    // dead → break → unregister → subsequent mail parks for redelivery on
    // reconnect.
    //
    // Assumption: a receiver pongs promptly. The gateway-client's read loop
    // (`next_text`) replies to a Ping explicitly the instant it reads one, and
    // the recv bridge sits continuously in that read — so a live receiver always
    // pongs within microseconds and a full interval of grace is generous. (A
    // recv connection that stops reading for a whole interval is, for our
    // purposes, dead — which is exactly what we want to evict.)
    let mut heartbeat = tokio::time::interval(heartbeat_interval());
    let mut pong_pending = false;

    // Single-task relay loop over the one socket: deliver queued envelopes to
    // this agent, and route envelopes this agent sends to their recipient.
    loop {
        tokio::select! {
            // Liveness: ping on each tick; a tick with a still-pending pong from
            // the previous round means the peer is gone.
            _ = heartbeat.tick() => {
                if pong_pending {
                    tracing::info!(%agent_id, "heartbeat: no pong within interval; closing dead connection");
                    break;
                }
                if socket.send(Message::Ping(Default::default())).await.is_err() {
                    break;
                }
                pong_pending = true;
            }
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
                            let recipient = env.recipient.clone();
                            let status = deliver(&state, env).await;
                            // Receipt back to the sender so it can tell delivered
                            // from parked (and set its exit code accordingly).
                            let receipt = ServerFrame::Receipt { recipient, status };
                            if socket
                                .send(Message::Text(receipt.to_json().into()))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(e) => tracing::warn!(error = %e, "bad envelope; ignored"),
                    },
                    // Liveness reply: clears the pending-pong so the heartbeat
                    // knows the peer is alive.
                    Some(Ok(Message::Pong(_))) => pong_pending = false,
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {} // ignore ping/binary
                    Some(Err(e)) => {
                        tracing::debug!(error = %e, "socket error");
                        break;
                    }
                }
            }
        }
    }

    // Only a registered receiver owns a presence slot to clear. A pure sender
    // never registered, so unregistering by `agent_id` here would wrongly evict
    // that agent's *receiver* connection (same id) — guard it.
    if wants_recv {
        state.presence.unregister(&agent_id, token).await;
    }
    tracing::info!(%agent_id, "agent disconnected");
}

/// Deliver an envelope, escalating reachability: local presence → peer gateways
/// (federation) → durable store-and-forward. The gateway routes on the cleartext
/// `recipient` only; it never verifies the signature (the recipient harness does)
/// and cannot forge `sender`.
async fn deliver(state: &AppState, env: Envelope) -> DeliveryStatus {
    if state.presence.route(&env).await {
        tracing::info!(recipient = %env.recipient, sender = %env.sender, "delivered (local presence)");
        return DeliveryStatus::Delivered; // delivered to a locally-connected agent
    }
    if state.federation.forward(&env).await {
        tracing::info!(recipient = %env.recipient, sender = %env.sender, "delivered (peer gateway)");
        return DeliveryStatus::Delivered;
    }
    tracing::info!(recipient = %env.recipient, sender = %env.sender, "recipient offline; parking for store-and-forward");
    state.store.park(env).await;
    DeliveryStatus::Parked
}

/// Heartbeat ping cadence. A receiver connection is closed if it misses a pong
/// for a full interval (so dead-connection detection takes [interval, 2×interval]).
/// Defaults to 30s; `BWOC_GATEWAY_HEARTBEAT_SECS` overrides it (accepts a
/// fractional value so tests can drive a sub-second cadence). A non-positive or
/// unparseable value falls back to the default.
fn heartbeat_interval() -> Duration {
    std::env::var("BWOC_GATEWAY_HEARTBEAT_SECS")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .filter(|s| *s > 0.0 && s.is_finite())
        .map(Duration::from_secs_f64)
        .unwrap_or(Duration::from_secs(30))
}

/// Signed-challenge handshake. The client sends `ClientHello{agent_id, pubkey}`;
/// the server replies with a random nonce; the client returns the nonce signed
/// with its ed25519 key. The keypair IS the login — no passwords.
async fn authenticate(socket: &mut WebSocket) -> Result<(String, bool), auth::AuthError> {
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
    Ok((hello.agent_id, hello.recv))
}
