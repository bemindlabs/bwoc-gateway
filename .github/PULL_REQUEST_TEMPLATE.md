## Summary

One or two sentences on *why* this change is needed.

## What changed

- Bullet list of the concrete edits, grouped by surface (`gateway-server` / `gateway-client` / wire protocol / `deploy/` / docs / CI).

## Related

- Closes #
- Refs #
- Wire protocol changed? (yes/no — if yes, both `wire.rs` and the client are updated)

## Checklist

(Per [`CONTRIBUTING.md` § Pull Request Checklist](../CONTRIBUTING.md#pull-request-checklist).)

- [ ] Branch is up to date with `main`
- [ ] PR title follows commit style (`type(scope): subject`)
- [ ] Description explains *why* the change is needed (not just *what*)
- [ ] Related issues are linked (`Closes #123`)
- [ ] `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test` all pass
- [ ] **Security invariants preserved** — no sender forgery, presence ≠ identity, no trust elevation ([SECURITY.md](../SECURITY.md#security-invariants))
- [ ] **Bilingual EN/TH docs pair preserved** (if `docs/` changed)
- [ ] **No secrets, credentials, or personal paths committed**

## Risk and rollback

How would a reviewer roll this back if it breaks something? (Single commit revert / staged behind config / docs-only — no rollback needed.)
