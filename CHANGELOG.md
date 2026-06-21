# Changelog

All notable changes to `bwoc-gateway` are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Relayed inbox envelopes dropped the authenticated sender id + timestamp** (#321). `bwoc-gateway-recv` appended the inner `body` verbatim, so a body without `from`/`ts` (e.g. a raw `{"text":"hi"}`) landed in the recipient's `.bwoc/inbox.jsonl` with no usable sender or time — downstream tooling rendered `from = "?"` and had no per-message timestamp. recv now stamps the **ed25519-authenticated** `Envelope.sender` as `from` and a receive `ts` into the persisted body **when those fields are absent**. Present fields are never overwritten — a signed inner envelope carries its own `from`/`ts` in its signed payload, so signature verification stays valid. A relayed envelope whose authenticated `sender` is `user` is dropped too (the local-operator principal can never be a remote sender).

- **Log-silence root cause: wrong `EnvFilter` target.** The default directive (and the deployed `RUST_LOG`) used `gateway_server=info`, but the binary crate is `bwoc_gateway` (`[[bin]] name = "bwoc-gateway"`), so `gateway_server=…` matched **no** events and the relay looked completely log-silent. Default is now `bwoc_gateway=info`. Deployments must use `RUST_LOG=bwoc_gateway=…` (or leave it unset).
- **Logs now go to stderr** (unbuffered) instead of block-buffered stdout, so the delivery path stays visible in `docker logs`. Delivery decisions (`delivered (local presence)` / `delivered (peer gateway)` / `parking`) are now logged at **info**.
- **Presence self-collision.** `bwoc-gateway-send` reused the agent's own `agent_id`, and the relay registered presence for every connection (last-writer-wins) — so a one-shot send **evicted that agent's live receiver**, knocking it offline. Senders now connect with `recv = false` (new `ClientHello.recv`, defaults `true`) and the relay skips registration/store-drain/unregister for them.

### Added

- **Delivery receipts.** The relay returns a `Receipt { recipient, status }` (`delivered` | `parked`) for each routed envelope. `bwoc-gateway-send` waits for it and reflects it in its exit code — `0` delivered-live, `4` parked-while-offline — ending the "exit 0 but never arrived" blind spot. New `GatewayClient::await_receipt`, `GatewayConfig::sender`, and `DeliveryStatus`/`DeliveryReceipt` in `gateway-client`.

## [1.0.0] - 2026-06-09

First **stable** release — the wire protocol and the `gateway-client` API are now considered stable. The relay is deployed and **live-verified cross-machine** (auth → relay → end-to-end crypto → store-and-forward) on the bemind server (`relay.bemind.tech`).

### Added

- **Durable store-and-forward** for offline recipients — in-memory by default; persistent via `BWOC_GATEWAY_STORE_DIR` (per-recipient append-log, bounded, recipient id hex-encoded into the filename so it cannot escape the store dir). Parked envelopes drain oldest-first on (re)connect.
- **End-to-end body encryption** (`gateway-client::crypto`) — seal the opaque `body` to the recipient's key (ed25519→x25519 libsodium conversion + anonymous sealed box), so the relay and any peer carry only ciphertext.
- **Multi-gateway federation** — static peer list (`BWOC_GATEWAY_PEERS`); on a local miss the envelope is forwarded over `POST /v1/federate`. Loop-safe by construction (the federate handler never re-forwards).
- **Real WebSocket client** + the **`bwoc-gateway-send`** binary — the transport the BWOC harness shells out to for a `routes.toml` `transport = "gateway"` route (wired in BWOC-Framework 2.28.0).
- **End-to-end integration test** that spawns the real binary and drives the full path (auth → relay → e2e → store-and-forward).

### Changed

- Delivery now escalates **local presence → peer gateways (federation) → durable store-and-forward**.

## [0.1.0] - 2026-06-09

### Added

- MVP scaffold: signed-challenge authentication, presence mapping (`agent_id → live connection`), and online relay-by-recipient over WebSocket.
- `gateway-server` crate — axum WebSocket server exposing `/healthz` and `/v1/connect`, listening on `0.0.0.0:8787` (override with `BWOC_GATEWAY_ADDR`).
- `gateway-client` crate — connector for agents/harness.
- ed25519 signed-envelope relay: the keypair *is* the login; the gateway relays opaquely and cannot forge a `sender`.
- Bilingual design docs under `docs/{en,th}/`.
- `deploy/` Dockerfile (+ compose) for the long-running service.

[Unreleased]: https://github.com/bemindlabs/bwoc-gateway/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/bemindlabs/bwoc-gateway/releases/tag/v1.0.0
[0.1.0]: https://github.com/bemindlabs/bwoc-gateway/releases/tag/v0.1.0
