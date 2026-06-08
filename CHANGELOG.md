# Changelog

All notable changes to `bwoc-gateway` are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Deferred (planned, not yet implemented)

- Durable store-and-forward for offline recipients.
- End-to-end body encryption.
- Multi-gateway federation.
- Framework-side `routes.toml` `RouteTarget::Gateway` wiring.

## [0.1.0] - 2026-06-09

### Added

- MVP scaffold: signed-challenge authentication, presence mapping (`agent_id → live connection`), and online relay-by-recipient over WebSocket.
- `gateway-server` crate — axum WebSocket server exposing `/healthz` and `/v1/connect`, listening on `0.0.0.0:8787` (override with `BWOC_GATEWAY_ADDR`).
- `gateway-client` crate — connector for agents/harness.
- ed25519 signed-envelope relay: the keypair *is* the login; the gateway relays opaquely and cannot forge a `sender`.
- Bilingual design docs under `docs/{en,th}/`.
- `deploy/` Dockerfile (+ compose) for the long-running service.

[Unreleased]: https://github.com/bemindlabs/bwoc-gateway/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/bemindlabs/bwoc-gateway/releases/tag/v0.1.0
