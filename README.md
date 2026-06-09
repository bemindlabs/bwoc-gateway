<div align="center">

# 📡 bwoc-gateway

**Rendezvous + relay server for multi-place agent communication.**

[![CI](https://github.com/bemindlabs/bwoc-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/bemindlabs/bwoc-gateway/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org/)
[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](CHANGELOG.md)
[![Docs](https://img.shields.io/badge/docs-EN%20%7C%20TH-blue.svg)](docs/)
[![Status](https://img.shields.io/badge/status-v0.1.0%20released-brightgreen.svg)](#-status)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

</div>

BWOC agents normally reach each other by direct connectivity — A2A over HTTP, an MQTT broker, or `routes.toml` peer paths. That breaks across NAT, firewalls, and the open internet. `bwoc-gateway` is an **optional** server that lets agents in *different places* (machines, networks, orgs) exchange messages without direct reachability.

## 🧭 Design principle — a dumb, untrusted relay

The gateway never becomes a central authority (BWOC is deliberately decentralized — *no central registry*, end-to-end signed envelopes, Kalyāṇamitta-7 trust):

- **Envelopes stay end-to-end ed25519-signed.** The gateway relays them opaquely and **cannot forge a `sender`**.
- **Presence, not identity.** An agent's identity is its keypair, not a gateway account. The gateway only maps `agent_id → live connection` and routes on the cleartext `recipient` header.
- **No trust elevation.** Authorization (Kalyāṇamitta-7) and capability gating stay in the *receiving* harness. The gateway is the untrusted-ingress edge — it inherits Phase 5 *saṃvara* discipline (TLS, per-agent rate-limits, signature checks at the door).

## 🔌 Protocol

```
client ──WS──▶ /v1/connect
  → ClientHello { agent_id, pubkey }
  ◀ Challenge   { nonce }
  → { signature }              # nonce signed with the agent's ed25519 key
  ⇄ Envelope { recipient, sender, signature, body }   # relayed by recipient

gateway ──HTTP──▶ POST /v1/federate { Envelope }      # peer-to-peer (federation)
  ◀ { delivered: bool }                               # delivered to a *local* agent? (never re-forwards)
```

The keypair **is** the login — no passwords, no server-side accounts. Delivery
escalates: **local presence → peer gateways (federation) → durable
store-and-forward**. The `body` is opaque — seal it end-to-end with
`gateway-client`'s `crypto` so the relay carries only ciphertext.

## 🗂️ Layout

```
crates/gateway-server/   axum server: auth, presence, store-and-forward, federation, relay (the bwoc-gateway binary)
crates/gateway-client/   connector + e2e crypto for agents/harness (→ framework RouteTarget::Gateway)
docs/{en,th}/            bilingual design docs
deploy/                  Dockerfile (+ compose) — long-running service
```

## ▶️ Run

```bash
cargo run -p gateway-server          # listens on 0.0.0.0:8787 (BWOC_GATEWAY_ADDR to override)
curl localhost:8787/healthz          # → ok
```

Optional environment:

```bash
BWOC_GATEWAY_STORE_DIR=/var/lib/bwoc-gateway   # durable store-and-forward (default: in-memory)
BWOC_GATEWAY_PEERS=https://gw-eu.example,https://gw-us.example   # federation peers (default: none)
```

## 📊 Status

Online relay-by-recipient with signed-challenge auth (the keypair is the login),
**durable store-and-forward** for offline recipients, **multi-gateway
federation** (loop-safe single-hop peer forwarding), and a real WebSocket
**client + end-to-end body encryption** (ed25519→x25519 sealed box).
**Deferred:** the `routes.toml` `RouteTarget::Gateway` wiring in the framework
(separate repo).

## 🤝 Contributing

PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). This is an untrusted-ingress security service, so changes preserve the [security invariants](SECURITY.md#security-invariants) (no sender forgery, presence ≠ identity, no trust elevation). Report vulnerabilities privately per [SECURITY.md](SECURITY.md), not via public issues. By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## 📄 License

MIT.
