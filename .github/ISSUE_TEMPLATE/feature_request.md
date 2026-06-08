---
name: Feature request
about: Suggest a new capability or protocol addition for the gateway.
title: '[Feature] '
labels: ['enhancement']
assignees: ''
---

## Problem / motivation

What problem are you trying to solve? Concrete examples beat abstract goals — name the failing scenario (which agents, which network topology, what breaks today).

## Proposed solution

How would you address it? If it touches the wire protocol, sketch the message flow (see the Protocol section in [`README.md`](../../README.md#-protocol-mvp)).

## Alternatives considered

Other approaches you weighed, and why this one wins.

## Scope

- **Surface affected:** (`gateway-server` / `gateway-client` / wire protocol / `deploy/`)
- **Relates to a deferred item?** (durable store-and-forward / e2e body encryption / multi-gateway federation / `RouteTarget::Gateway` wiring / new)
- **Backwards compatibility:** (additive / breaking wire-protocol change / breaking client API)

## Design-principle alignment

Does the proposal keep the gateway a **dumb, untrusted relay**? Confirm it does not add server-side identity, central registry, or trust elevation — or explain why an exception is warranted (see [`README.md` § Design principle](../../README.md#-design-principle--a-dumb-untrusted-relay)).

## Additional context

Prior art, related discussions, sketches.
