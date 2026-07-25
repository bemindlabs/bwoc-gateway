# bwoc-gateway — Overview

> Thai version: [../th/OVERVIEW.th.md](../th/OVERVIEW.th.md)

## Why

Agents in different places (machines, networks, organizations) cannot always reach each other directly — NAT, firewalls, and the open internet get in the way. The existing transports each have a gap for this case:

| Transport | Gap for multi-place |
|---|---|
| **A2A** (HTTP JSON-RPC) | Inbound HTTP; loopback-default; no NAT traversal; no server-push. |
| **MQTT** | Needs a shared broker both sides can reach; broker becomes infra to run. |
| **peer / routes.toml** | Requires a reachable path/address per peer. |

`bwoc-gateway` adds a **persistent, authenticated, presence-aware relay**: each agent holds one outbound WebSocket to the gateway, and the gateway relays signed envelopes between connected agents by `recipient`. NAT-friendly (outbound only), server-push (the gateway can deliver the moment a recipient is online).

## What it is — and is not

- **Is:** an optional rendezvous + relay. Maps `agent_id → live connection`; routes by `recipient`; authenticates via signed challenge.
- **Is not:** a trust anchor, an identity registry, or a mandatory hop. Identity stays in the keypairs; trust decisions stay in the receiving harness.

## Security posture (Phase 5 *saṃvara* at the edge)

The gateway is, by definition, an **untrusted-ingress surface** on the open internet, so it inherits the framework's saṃvara discipline:

- **Authentication = signed challenge.** The agent signs a server nonce with its ed25519 key; the keypair is the login. No passwords, no accounts to breach.
- **End-to-end signatures.** Envelopes are signed by the *sender* agent; the gateway cannot forge `sender`. The recipient verifies the signature itself.
- **No payload trust.** The gateway routes on the cleartext `recipient` header only; it does not interpret or vouch for the body. (E2E body encryption — so the relay cannot even read payloads — ships in `gateway-client::crypto`.)
- **Edge controls.** TLS, per-agent rate limiting, bounded queues. Capability/Kalyāṇamitta-7 authorization remains in the receiving harness — the gateway never elevates trust.

## Roadmap

1. ✅ **MVP (scaffold):** WS relay + signed-challenge auth + presence + online relay.
2. ✅ Durable **store-and-forward** for offline recipients.
3. ✅ **End-to-end body encryption** (relay routes on header, cannot read content).
4. ✅ Framework wiring: a `RouteTarget::Gateway` in `routes.toml` + a `gateway-client` the harness drives (BWOC-Framework 2.28.0).
5. ✅ **Multi-gateway federation** (gateways peer to relay across regions/orgs).
6. ✅ **Resource broker** — the discovery half of the BWOC Resource Protocol (in-memory, TTL-evicted offer registry; claim/lease rides the relay).
