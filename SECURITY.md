# Security Policy

`bwoc-gateway` is, by design, an **untrusted-ingress relay** — it sits on the open internet and accepts connections from agents it cannot vouch for. Its security posture is therefore not "trust the gateway" but "the gateway can be hostile and the system still holds." See [`README.md` § Design principle](README.md#-design-principle--a-dumb-untrusted-relay).

## Reporting a Vulnerability

**Do not open a public issue or pull request for security vulnerabilities.**

Email **info@bemind.tech** with:

- A description of the issue and the impact you observed.
- Steps to reproduce (proof-of-concept, minimal repro, or commands).
- Affected version (commit SHA or release tag).
- Any suggested mitigation, if known.

Acknowledgement, triage, remediation, and disclosure timelines are negotiated case-by-case with the reporter. The project does not currently publish a fixed-window service-level commitment.

## Disclosure

We follow **coordinated disclosure**. Once a fix is available, we will:

1. Publish a patched release.
2. Credit the reporter (unless anonymity is requested).
3. Open a public advisory describing the issue, impact, and remediation.

## Scope

In scope:

- `crates/gateway-server/` — the WebSocket server: signed-challenge auth (`auth.rs`), presence mapping (`presence.rs`), envelope relay, and wire framing (`wire.rs`).
- `crates/gateway-client/` — the connector library used by agents/harness.
- `deploy/` — the Dockerfile and compose deployment surface.
- Transport security and rate-limiting at the ingress edge.

Out of scope:

- **Authorization decisions.** Trust (Kalyāṇamitta-7) and capability gating live in the *receiving* harness, never in the gateway. A relayed-but-unauthorized message is a harness concern, not a gateway vulnerability.
- **Envelope contents.** The gateway relays opaque, end-to-end ed25519-signed envelopes; it cannot read or forge them. Body confidentiality (e2e encryption) is a deferred feature, not a current guarantee — see Status in `README.md`.
- Third-party LLM backends and downstream agents — report to the respective maintainer.
- Social-engineering or physical attacks against contributors.

## Security Invariants

These properties must hold for any change to be mergeable:

- **No sender forgery.** The gateway relays envelopes opaquely and must never be able to mint or alter a `sender`.
- **Presence ≠ identity.** An agent's identity is its keypair; the gateway only maps `agent_id → live connection`. It must not become a server-side account authority or central registry.
- **No trust elevation.** Relaying a message must not confer authorization. The door does signature checks, TLS, and per-agent rate-limits (*saṃvara* discipline) — nothing more.
- **No secrets at rest or in logs.** Private keys never touch the server; nonces and signatures are not logged in a way that aids replay.
