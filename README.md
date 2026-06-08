# bwoc-gateway

**Rendezvous + relay server for multi-place agent communication.**

BWOC agents normally reach each other by direct connectivity — A2A over HTTP, an MQTT broker, or `routes.toml` peer paths. That breaks across NAT, firewalls, and the open internet. `bwoc-gateway` is an **optional** server that lets agents in *different places* (machines, networks, orgs) exchange messages without direct reachability.

## Design principle — a dumb, untrusted relay

The gateway never becomes a central authority (BWOC is deliberately decentralized — *no central registry*, end-to-end signed envelopes, Kalyāṇamitta-7 trust):

- **Envelopes stay end-to-end ed25519-signed.** The gateway relays them opaquely and **cannot forge a `sender`**.
- **Presence, not identity.** An agent's identity is its keypair, not a gateway account. The gateway only maps `agent_id → live connection` and routes on the cleartext `recipient` header.
- **No trust elevation.** Authorization (Kalyāṇamitta-7) and capability gating stay in the *receiving* harness. The gateway is the untrusted-ingress edge — it inherits Phase 5 *saṃvara* discipline (TLS, per-agent rate-limits, signature checks at the door).

## Protocol (MVP)

```
client ──WS──▶ /v1/connect
  → ClientHello { agent_id, pubkey }
  ◀ Challenge   { nonce }
  → { signature }              # nonce signed with the agent's ed25519 key
  ⇄ Envelope { recipient, sender, signature, body }   # relayed by recipient
```

The keypair **is** the login — no passwords, no server-side accounts.

## Layout

```
crates/gateway-server/   axum WebSocket server: auth, presence, relay (the bwoc-gateway binary)
crates/gateway-client/   connector for agents/harness (→ framework RouteTarget::Gateway)
docs/{en,th}/            bilingual design docs
deploy/                  Dockerfile (+ compose) — long-running service
```

## Run

```bash
cargo run -p gateway-server          # listens on 0.0.0.0:8787 (BWOC_GATEWAY_ADDR to override)
curl localhost:8787/healthz          # → ok
```

## Status

MVP scaffold: signed-challenge auth + presence + online relay-by-recipient.
**Deferred:** durable store-and-forward, end-to-end body encryption, multi-gateway federation, the `routes.toml` `RouteTarget::Gateway` wiring in the framework.

## License

MIT.
