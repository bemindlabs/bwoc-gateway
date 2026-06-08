---
name: Bug report
about: Report a defect in the gateway server, client connector, or deployment.
title: '[Bug] '
labels: ['bug']
assignees: ''
---

## Description

A clear, concrete description of what is wrong.

## Steps to reproduce

1.
2.
3.

## Expected behavior

What you expected to happen.

## Actual behavior

What actually happened. Include error output and relevant server logs verbatim (in a code block). Redact keys and signatures.

## Environment

- **Version:** (release tag or commit SHA)
- **OS:** (macOS / Linux / Windows + version, or container image)
- **Rust toolchain:** (`rustc --version`, if building from source)
- **Surface:** (`gateway-server` / `gateway-client` / wire protocol / `deploy/`)
- **Deployment:** (local `cargo run` / Docker / compose / behind a reverse proxy)
- **`BWOC_GATEWAY_ADDR`:** (if overridden)

## Additional context

Links to related issues or the relevant section of `docs/`. A minimal repro (client + server steps) is the fastest path to a fix.

## Security

If this report contains information that could be exploited (auth bypass, sender forgery, replay, etc.), **stop and email `info@bemind.tech` instead** per [`SECURITY.md`](../../SECURITY.md). Do not include exploit details in this public issue.
