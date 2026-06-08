# Contributing to bwoc-gateway

Thank you for considering a contribution. `bwoc-gateway` is the optional rendezvous + relay server for multi-place BWOC agent communication — a small, security-sensitive Rust service. Contributions should be technical, kind, and verifiable.

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

---

## How You Can Contribute

- **Report a bug** — open an issue using the *Bug report* template.
- **Suggest an enhancement** — open an issue using the *Feature request* template.
- **Improve documentation** — typos, clarifications, bilingual (English/Thai) parity under `docs/{en,th}/`.
- **Work a deferred feature** — durable store-and-forward, end-to-end body encryption, multi-gateway federation, or the framework-side `routes.toml` `RouteTarget::Gateway` wiring (see Status in [README.md](README.md#-status)). Open an issue first to align on the wire protocol.

---

## Development Workflow

We use **trunk-based** development: `main` is the only long-lived branch and is always releasable; all work happens on short-lived topic branches deleted after merge.

1. **Fork** and create a topic branch from `main`. Branch `type` uses commit-type vocabulary (`feat fix docs refactor test chore perf style ci`):
   ```bash
   git checkout -b feat/<short-name>
   git checkout -b fix/<short-name>
   ```
2. **Make your changes** — keep diffs focused. One concern per PR. Respect the [security invariants](SECURITY.md#security-invariants): no sender forgery, presence ≠ identity, no trust elevation.
3. **Verify** before committing:
   ```bash
   cargo fmt --all
   cargo clippy --all-targets -- -D warnings
   cargo test
   cargo build -p gateway-server
   ```
   If you touch the wire format, keep `crates/gateway-server/src/wire.rs` and `crates/gateway-client/` in sync, and update both `docs/en/` and `docs/th/`.
4. **Commit** with a descriptive message — see [Commit Style](#commit-style).
5. **Open a Pull Request** against `main` using the PR template.

---

## Commit Style

Lightweight [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short summary>

[optional body — explain *why*, not *what*]
[optional footer — refs/closes #issue]
```

**Types:** `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`, `style`, `ci`.
**Scopes (typical):** `server`, `client`, `auth`, `presence`, `wire`, `deploy`, `docs`, `ci`.

**Examples:**
- `feat(server): add per-agent connection rate-limit`
- `fix(auth): reject replayed challenge nonce`
- `docs(en): document the relay-by-recipient flow`

---

## Pull Request Checklist

Before requesting review, ensure:

- [ ] Branch is up to date with `main`
- [ ] PR title follows commit style
- [ ] Description explains *why* the change is needed
- [ ] Related issues are linked (`Closes #123`)
- [ ] `cargo fmt --check`, `cargo clippy -D warnings`, and `cargo test` pass
- [ ] Security invariants preserved (no sender forgery / presence ≠ identity / no trust elevation)
- [ ] Bilingual EN/TH docs pair preserved (if `docs/` changed)
- [ ] No secrets, credentials, or personal paths committed

---

## Merging & External PRs

**`main` is a protected branch.** Changes land **only** through a pull request that auto-merges once its gates (fmt + clippy, build + test) are green — never by direct push.

Because this is an untrusted-ingress security service, **fork PRs get a full review — never a blind merge**. Any code that parses untrusted input or handles auth/relay is scrutinized for injection, replay, path-traversal, and trust-elevation. If a fork PR has a security or correctness blocker, request changes rather than merging "to fix later."

---

## Reporting Security Issues

**Do not open public issues for security vulnerabilities.** See [SECURITY.md](SECURITY.md) for the private disclosure process.

---

## Questions

- General questions → open an issue tagged `question`.
- Sensitive matters → email **info@bemind.tech**.

---

## Recognition

Contributors are credited in commit history and release notes. See [CODEOWNERS](.github/CODEOWNERS).
