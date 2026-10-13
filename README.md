<div align="center">

# 📡 bwoc-gateway

**Rendezvous + relay server for multi-place agent communication.**

[![CI](https://github.com/bemindlabs/bwoc-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/bemindlabs/bwoc-gateway/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org/)
[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](CHANGELOG.md)
[![Docs](https://img.shields.io/badge/docs-EN%20%7C%20TH-blue.svg)](docs/)
[![Status](https://img.shields.io/badge/status-v1.0.0%20stable-brightgreen.svg)](#-status)
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

provider ─HTTP─▶ POST /v1/resource/advertise { snapshot, kinds, ttl }   # publish a live offer
consumer ─HTTP─▶ POST /v1/resource/discover { kind, min spec }          # find matching offers
  ◀ [ offers ]                                        # best-free-VRAM first, TTL-evicted registry
```

The keypair **is** the login — no passwords, no server-side accounts. Delivery
escalates: **local presence → peer gateways (federation) → durable
store-and-forward**. The `body` is opaque — seal it end-to-end with
`gateway-client`'s `crypto` so the relay carries only ciphertext.

The `/v1/resource/*` routes are the **discovery half of the BWOC Resource Protocol** — an in-memory, TTL-evicted offer registry (providers advertise a `ResourceSnapshot` + kinds; consumers discover by kind + minimum spec). It is discovery only: the `RES.CLAIM → RES.LEASE` handshake rides the existing signed-envelope relay, so the broker never mints a lease or executes work.

## 🗂️ Layout

```
crates/gateway-server/   axum server: auth, presence, store-and-forward, federation, relay, resource broker (the bwoc-gateway binary)
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

### Receive bridge

An agent receives relayed mail by running `bwoc-gateway-recv`, which appends each
delivered body to its `.bwoc/inbox.jsonl`:

```bash
bwoc-gateway-recv --url wss://gw.example/v1/connect --agent-id agent-me \
                  --key-file .bwoc/agent.key --inbox .bwoc/inbox.jsonl
```

Add `--auto-pong` (off by default) to have the bridge answer connectivity checks
itself, with no live agent session involved:

```bash
# on the peer being checked
bwoc-gateway-recv ... --auto-pong

# from the checker (its own bridge also runs --auto-pong)
echo '{"type":"ping","id":"check-1"}' | bwoc-gateway-send --to agent-me ...
tail -n1 .bwoc/gateway-pong.jsonl     # {"type":"pong","from":"agent-me","id":"check-1",...}
```

A pong is a fixed shape (only a short `id` is echoed), a pong is never answered,
and pongs are rate-limited to one per second per claimed sender. With
`--auto-pong`, pings and pongs stay out of the inbox; received pongs go to
`gateway-pong.jsonl` beside it (`--pong-log` to move it). The envelope `sender`
is a claim, not a proof, so a pong tells you the bridge is up — not who asked.

#### Acting on mail without a live session

`--on-message <program>` (off by default) runs a program for each message, with
the message on its stdin. The gateway stays a relay — it runs your program and
nothing else — and because this is remote input triggering local execution, the
gate is the inner signature, never the envelope `sender`:

```bash
bwoc-gateway-recv ... \
  --on-message /usr/local/bin/handle-mail \
  --trust-key agent-busaba=<agent-busaba's signingPublicKey hex>
```

- Runs only for a `bwoc_signing` envelope that verifies against the key pinned
  for its `from`, and whose signed `to` is this agent. At least one
  `--trust-key` is required; repeat it per trusted sender.
- The signed `ts` must be within `--on-message-max-age-secs` (default 300) of
  now, and each `(from, messageId, nonce)` fires once. Mail parked longer than
  that is delivered but does not fire the hook.
- Executed directly, no shell; nothing from the message reaches argv. The
  verified sender and id are in `BWOC_GATEWAY_FROM` / `BWOC_GATEWAY_MESSAGE_ID`.
- At most 4 runs at once; each is killed after `--on-message-timeout-secs`
  (default 60). The kill reaches the program, not processes it started.
- Every message is written to the inbox first. A hook that fails, times out or
  is skipped never loses mail.

What the program does with a verified message is yours to bound: it runs with
the bridge's privileges, on input a trusted peer chose.

## 📊 Status

**v1.0.0 — stable.** Online relay-by-recipient with signed-challenge auth (the
keypair is the login), **durable store-and-forward** for offline recipients,
**multi-gateway federation** (loop-safe single-hop peer forwarding), and a real
WebSocket **client + end-to-end body encryption** (ed25519→x25519 sealed box).
The framework-side `routes.toml` `transport = "gateway"` wiring shipped in
BWOC-Framework 2.28.0. Deployed and live-verified cross-machine. Also carries a
**resource broker** — an in-memory, TTL-evicted offer registry (the discovery
half of the BWOC Resource Protocol) over `POST /v1/resource/{advertise,discover}`.

## 🤝 Contributing

PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). This is an untrusted-ingress security service, so changes preserve the [security invariants](SECURITY.md#security-invariants) (no sender forgery, presence ≠ identity, no trust elevation). Report vulnerabilities privately per [SECURITY.md](SECURITY.md), not via public issues. By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## 📄 License

MIT.
