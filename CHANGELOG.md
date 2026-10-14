# Changelog

All notable changes to `bwoc-gateway` are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.0] - 2026-10-14

### Added

- **Optional federation peer token.** `BWOC_GATEWAY_FEDERATE_TOKEN`, when set, must be sent as `Authorization: Bearer <token>` on `POST /v1/federate` (401 otherwise) and is attached to this node's own calls to its peers. Unset keeps the previous open behaviour. Federation ingress also stops waiting after 2 s for room in a full recipient queue and answers `delivered: false`, so the peer parks the envelope.

### Fixed

- **File-backed store: replay kept the oldest envelopes and the log grew without bound.** Replay now keeps the newest `MAX_PER_RECIPIENT` (the same drop-oldest policy as at runtime), and a recipient's log is compacted from memory once it reaches twice the cap.
- Presence tokens start at 1, so `0` stays reserved for a never-registered sender. Docs: README resource-broker shapes now match the real JSON; `stamp_provenance` docs say it also replaces a non-string `from`/`ts`.

## [1.1.0] - 2026-10-14

### Added

- **Opt-in on-message hook for acting on mail without a live session** (#18). `bwoc-gateway-recv --on-message <program> --trust-key <agent-id>=<pubkey-hex>` runs an operator-configured program for each message, with the message on stdin. The gateway stays a relay: it executes the program and implements no task logic. Because this lets remote input trigger local execution, the gate is the inner `bwoc_signing` signature and never the (unauthenticated) envelope `sender`: the hook runs only when the signature verifies against a key pinned for `from`, the signed `to` is this agent, the signed `ts` is within `--on-message-max-age-secs` (default 300) and the `(from, messageId, nonce)` has not fired before. The program is executed directly (no shell, nothing from the message in argv), at most 4 at once, each killed after `--on-message-timeout-secs` (default 60). Every message is written to the inbox first, so a failing, slow or skipped hook never loses mail. Verification is pinned to the framework's `bwoc_signing` by a test vector that crate produced. Off by default; `--on-message` without a `--trust-key` is a usage error.

- **Opt-in auto-pong for connectivity checks** (#19). `bwoc-gateway-recv --auto-pong` answers a `{"type":"ping"}` body with a `{"type":"pong"}` from the bridge itself, so a ping no longer waits for a live agent session to notice it. Deliberately narrow: the pong is a fixed shape (only a ≤128-char `id` is echoed), a pong is never answered (no loops), and pongs are rate-limited to one per second per claimed sender with a bounded limiter. With the flag on, pings and pongs are kept out of the inbox and received pongs are appended to `gateway-pong.jsonl` beside it (`--pong-log` to override). Off by default — without the flag a ping is ordinary mail, as before. The receive loop moved into `gateway_client::bridge` so it is driven in-process by new end-to-end tests against the real relay.

### Fixed

- **A half-open socket no longer wedges the receive bridge or a one-shot send** (#16, #17). Every read is now bounded (90 s for the long-lived receiver, 30 s for a sender; `BWOC_GATEWAY_RECV_READ_TIMEOUT_SECS` / `BWOC_GATEWAY_SEND_READ_TIMEOUT_SECS` to override, `0` to disable). Without a frame in that window the client exits non-zero so its supervisor reconnects, instead of idling on a dead connection while the relay parks its mail.
- **`ClientError::Ws` now boxes the WebSocket error.** A newer stable clippy (`result_large_err`) rejects the ~136-byte variant, which had turned CI red for every change to `gateway-client`. `?` on a tungstenite error still converts; code that pattern-matches `ClientError::Ws(e)` now gets a `Box`.
- **Docs claimed `Envelope.sender` was authenticated; it is not.** `bwoc-gateway-recv` and the 1.0 notes described the relay-reported `sender` as "ed25519-authenticated". The relay verifies that a connection holds the key it presented, but it does not pin an `agent_id` to a key and does not compare an envelope's `sender` with the connection that sent it. The comments and overview now say so: `sender` is a claim, and only the inner signature identifies a sender. No behaviour change.

## [1.0.1] - 2026-07-27

### Added

- **Resource broker — the discovery half of the BWOC Resource Protocol** (framework `docs/en/RESOURCE-PROTOCOL.en.md`, slice B). Two new HTTP routes turn the relay into the fleet's resource-offer registry: `POST /v1/resource/advertise` (a provider publishes its `ResourceSnapshot` + offered kinds + a TTL) and `POST /v1/resource/discover` (a consumer queries by kind + minimum spec — `min_vram_mb` / `min_ram_mb` / `min_cpu_cores` — and gets matching live offers, best-free-VRAM first). The registry is in-memory and **TTL-evicted** (clamped ≤ 300 s), one live offer per provider id (last-writer-wins), so a crashed provider self-evicts and registry pollution stays bounded. True to the dumb-untrusted-relay grain: the broker never mints a lease and never executes work — the `RES.CLAIM` → `RES.LEASE` round trip rides the existing signed-envelope relay, and trust is deferred to the consumer verifying the provider's lease signature. 6 unit tests (kind match, min-spec filter, best-fit sort, last-writer-wins, TTL eviction + clamp).

- **Delivery receipts.** The relay returns a `Receipt { recipient, status }` (`delivered` | `parked`) for each routed envelope. `bwoc-gateway-send` waits for it and reflects it in its exit code — `0` delivered-live, `4` parked-while-offline — ending the "exit 0 but never arrived" blind spot. New `GatewayClient::await_receipt`, `GatewayConfig::sender`, and `DeliveryStatus`/`DeliveryReceipt` in `gateway-client`.

### Fixed

- **Resource broker hardening** (Copilot review of the broker PR). Three fixes: `discover` no longer holds the registry mutex across its `O(n log n)` sort (the lock scope now ends before the sort, so it can't block a concurrent advertise/discover or pin a Tokio worker); `snapshot_cpu_cores` clamps `u64 → u32` instead of `as`-truncating (an untrusted snapshot's absurd core count can no longer wrap small and spuriously pass a `min_cpu_cores` filter); and the registry gained a hard `MAX_OFFERS` count cap (soonest-expiry eviction) so a flood of distinct `provider` ids can't grow the in-memory map without bound — TTL bounds time, this bounds count. 2 new tests.
- **Relayed inbox envelopes dropped the sender id + timestamp** (#321). `bwoc-gateway-recv` appended the inner `body` verbatim, so a body without `from`/`ts` (e.g. a raw `{"text":"hi"}`) landed in the recipient's `.bwoc/inbox.jsonl` with no usable sender or time — downstream tooling rendered `from = "?"` and had no per-message timestamp. recv now stamps the relay-reported `Envelope.sender` (a claim, not a proof — see the entry above) as `from` and a receive `ts` into the persisted body **when those fields are absent**. Present fields are never overwritten — a signed inner envelope carries its own `from`/`ts` in its signed payload, so signature verification stays valid. A relayed envelope whose `sender` is `user` is dropped too (the local-operator principal can never be a remote sender).

- **Log-silence root cause: wrong `EnvFilter` target.** The default directive (and the deployed `RUST_LOG`) used `gateway_server=info`, but the binary crate is `bwoc_gateway` (`[[bin]] name = "bwoc-gateway"`), so `gateway_server=…` matched **no** events and the relay looked completely log-silent. Default is now `bwoc_gateway=info`. Deployments must use `RUST_LOG=bwoc_gateway=…` (or leave it unset).
- **Logs now go to stderr** (unbuffered) instead of block-buffered stdout, so the delivery path stays visible in `docker logs`. Delivery decisions (`delivered (local presence)` / `delivered (peer gateway)` / `parking`) are now logged at **info**.
- **Presence self-collision.** `bwoc-gateway-send` reused the agent's own `agent_id`, and the relay registered presence for every connection (last-writer-wins) — so a one-shot send **evicted that agent's live receiver**, knocking it offline. Senders now connect with `recv = false` (new `ClientHello.recv`, defaults `true`) and the relay skips registration/store-drain/unregister for them.

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

[Unreleased]: https://github.com/bemindlabs/bwoc-gateway/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/bemindlabs/bwoc-gateway/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/bemindlabs/bwoc-gateway/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/bemindlabs/bwoc-gateway/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/bemindlabs/bwoc-gateway/releases/tag/v1.0.0
[0.1.0]: https://github.com/bemindlabs/bwoc-gateway/releases/tag/v0.1.0
