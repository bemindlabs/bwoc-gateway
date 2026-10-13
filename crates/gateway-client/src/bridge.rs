//! The receive bridge: relay WebSocket → the agent's `.bwoc/inbox.jsonl`.
//!
//! This is the loop `bwoc-gateway-recv` runs, kept in the library so it can be
//! driven in-process against a real relay by the integration tests.
//!
//! # What `Envelope.sender` is — and is not
//!
//! The relay authenticates the *connection* (the client proves it holds the key
//! it presented) but it does not pin an `agent_id` to a key, and it does not
//! check that an envelope's `sender` matches the connection that sent it. So
//! `sender` is a **claim**, exactly like a `from` inside an unsigned body. The
//! only identity proof is the inner `bwoc_signing` signature, which the
//! receiving agent's trust gate verifies against the sender's pinned key.
//! Nothing in this module may treat `sender` as authenticated.
//!
//! # Auto-pong (opt-in)
//!
//! With [`BridgeOptions::auto_pong`] a body of `{"type":"ping"}` is answered
//! with `{"type":"pong"}` straight from the bridge, so a connectivity check
//! needs no live agent session. It is deliberately narrow:
//!
//! - The reply is a fixed shape. Nothing from the ping is echoed back except
//!   an optional short `id`, so a ping cannot be used to make this agent say
//!   something chosen by the sender.
//! - A `pong` is never answered, so two bridges cannot ping-pong forever.
//! - Because `sender` is only a claim, a forged ping can aim one pong at a
//!   third party. That is one small frame out per frame in (no amplification)
//!   and it is rate-limited per claimed sender.
//! - A pong says only "this bridge is connected", which the relay's own
//!   delivered/parked receipt already reveals.
//!
//! Pings and pongs are transport chatter, so with auto-pong on they are kept
//! out of the inbox: an agent is never woken by one. Received pongs are
//! appended to [`BridgeOptions::pong_log`] for whoever sent the ping to read.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::{Envelope, GatewayClient};

/// Longest ping `id` echoed back in a pong. Anything longer is dropped rather
/// than truncated, so the echoed value is always exactly what was sent.
const MAX_PING_ID_LEN: usize = 128;

/// Minimum gap between two pongs to the same claimed sender.
const PONG_MIN_INTERVAL: Duration = Duration::from_secs(1);

/// Cap on distinct claimed senders remembered by the limiter. A flood of
/// made-up sender ids would otherwise grow the map without bound.
const PONG_LIMITER_MAX_SENDERS: usize = 1024;

/// How the bridge should run.
#[derive(Debug, Clone)]
pub struct BridgeOptions {
    /// The agent's `.bwoc/inbox.jsonl`.
    pub inbox: PathBuf,
    /// Answer `{"type":"ping"}` with a pong and keep ping/pong out of the inbox.
    pub auto_pong: bool,
    /// Where received pongs are appended (JSON lines) when `auto_pong` is on.
    pub pong_log: PathBuf,
}

impl BridgeOptions {
    /// Deliver everything to `inbox`; auto-pong off.
    pub fn new(inbox: impl Into<PathBuf>) -> Self {
        let inbox = inbox.into();
        let pong_log = default_pong_log(&inbox);
        Self {
            inbox,
            auto_pong: false,
            pong_log,
        }
    }
}

/// `gateway-pong.jsonl` next to the inbox.
pub fn default_pong_log(inbox: &Path) -> PathBuf {
    inbox.with_file_name("gateway-pong.jsonl")
}

/// A transport-level control body, recognised only when auto-pong is on.
#[derive(Debug, PartialEq, Eq)]
enum Control {
    Ping { id: Option<String> },
    Pong,
}

/// Classify `body` as ping/pong by its `type` field. Only an exact, lowercase
/// string match counts, so an ordinary message that merely mentions "ping" is
/// never mistaken for one.
fn control_of(body: &Value) -> Option<Control> {
    match body.get("type")?.as_str()? {
        "ping" => {
            let id = body
                .get("id")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty() && s.len() <= MAX_PING_ID_LEN)
                .map(str::to_string);
            Some(Control::Ping { id })
        }
        "pong" => Some(Control::Pong),
        _ => None,
    }
}

/// The pong envelope for a ping claimed to be from `to`.
fn build_pong(self_id: &str, to: &str, id: Option<&str>, ts: &str) -> Envelope {
    let mut body = serde_json::json!({
        "type": "pong",
        "from": self_id,
        "to": to,
        "ts": ts,
    });
    if let Some(id) = id {
        body["id"] = Value::String(id.to_string());
    }
    Envelope {
        recipient: to.to_string(),
        sender: self_id.to_string(),
        signature: String::new(),
        body,
    }
}

/// Per-claimed-sender pong rate limit.
#[derive(Default)]
struct PongLimiter {
    last: HashMap<String, Instant>,
}

impl PongLimiter {
    /// Whether a pong to `sender` is allowed at `now`; records it if so.
    fn allow(&mut self, sender: &str, now: Instant) -> bool {
        if let Some(prev) = self.last.get(sender) {
            if now.duration_since(*prev) < PONG_MIN_INTERVAL {
                return false;
            }
        }
        if self.last.len() >= PONG_LIMITER_MAX_SENDERS && !self.last.contains_key(sender) {
            // Forget senders whose window has already passed; if that frees
            // nothing the map is full of live entries, so refuse.
            self.last
                .retain(|_, t| now.duration_since(*t) < PONG_MIN_INTERVAL);
            if self.last.len() >= PONG_LIMITER_MAX_SENDERS {
                return false;
            }
        }
        self.last.insert(sender.to_string(), now);
        true
    }
}

/// Run the bridge until the relay closes the stream or a read fails. Always
/// returns `Err`: the caller exits non-zero so a supervisor respawns it, and a
/// respawn is the reconnect.
pub async fn run(client: &mut GatewayClient, opts: &BridgeOptions) -> Result<(), String> {
    let mut limiter = PongLimiter::default();
    loop {
        match client.next_envelope().await {
            Ok(Some(env)) => handle(client, opts, &mut limiter, env).await?,
            Ok(None) => return Err("relay closed the connection".into()),
            Err(e) => return Err(format!("recv: {e}")),
        }
    }
}

async fn handle(
    client: &mut GatewayClient,
    opts: &BridgeOptions,
    limiter: &mut PongLimiter,
    env: Envelope,
) -> Result<(), String> {
    // Security guard at the ingress boundary: a relayed message can NEVER be
    // from the local-trusted `user` principal — `user` is the operator at the
    // local IPC, not a remote sender. The recipient's trust gate auto-passes
    // `from = "user"`, so letting a relayed `user` envelope reach the inbox
    // would forge local trust. Drop it outright.
    if env.body.get("from").and_then(|v| v.as_str()) == Some("user") || env.sender == "user" {
        eprintln!("bwoc-gateway-recv: dropped a relayed envelope claiming from=user");
        return Ok(());
    }

    if opts.auto_pong {
        match control_of(&env.body) {
            Some(Control::Ping { id }) => {
                let self_id = client.agent_id().to_string();
                if env.sender.is_empty() || env.sender == self_id {
                    return Ok(());
                }
                if !limiter.allow(&env.sender, Instant::now()) {
                    eprintln!(
                        "bwoc-gateway-recv: ping from {} rate-limited; no pong",
                        env.sender
                    );
                    return Ok(());
                }
                let pong = build_pong(&self_id, &env.sender, id.as_deref(), &now_rfc3339());
                // A failed write means the socket is gone; surface it so the
                // supervisor reconnects instead of the bridge idling on a dead
                // connection.
                client
                    .send(&pong)
                    .await
                    .map_err(|e| format!("send pong: {e}"))?;
                eprintln!("bwoc-gateway-recv: pong → {}", env.sender);
                return Ok(());
            }
            Some(Control::Pong) => {
                let body = stamp_provenance(env.body, &env.sender, &now_rfc3339());
                return append_jsonl(&opts.pong_log, &body);
            }
            None => {}
        }
    }

    // Stamp the relay-reported sender id + a receive timestamp into the
    // persisted envelope so the recipient's tooling always has a `from`/`ts`
    // instead of `?`. Absent-only: a properly signed inner envelope already
    // carries `from`/`ts` as part of its signed payload, so we must NOT
    // overwrite them (that would invalidate the signature).
    let body = stamp_provenance(env.body, &env.sender, &now_rfc3339());
    append_jsonl(&opts.inbox, &body)
}

/// Fill in `from` (= the relay-reported `sender`, a claim — see the module
/// docs) and `ts` (= receive time) on
/// the persisted envelope **only when absent**. A properly signed inner envelope
/// already carries both inside its signed payload, so leaving present fields
/// untouched keeps the recipient's signature verification valid; a raw body that
/// lacks them gets an attribution + timestamp instead of rendering as
/// `?`. A non-object body is wrapped as `{from, ts, message: <body>}` so it is
/// still attributable. `from`/`ts` are not overwritten even if the body claims
/// its own (the recipient's trust gate is the authority on a claimed identity).
fn stamp_provenance(body: Value, sender: &str, ts: &str) -> Value {
    let mut obj = match body {
        Value::Object(map) => map,
        other => {
            // Non-object body (e.g. a bare string/number) — wrap it so the
            // recipient still gets `from`/`ts` and the original under `message`.
            let mut m = serde_json::Map::new();
            m.insert("message".to_string(), other);
            m
        }
    };
    if !obj.get("from").is_some_and(|v| v.is_string()) {
        obj.insert("from".to_string(), Value::String(sender.to_string()));
    }
    if !obj.get("ts").is_some_and(|v| v.is_string()) {
        obj.insert("ts".to_string(), Value::String(ts.to_string()));
    }
    Value::Object(obj)
}

/// Current UTC time as an RFC 3339 / ISO 8601 string (`YYYY-MM-DDThh:mm:ssZ`),
/// matching the framework's canonical envelope `ts`. Self-contained (no time
/// crate): civil date from the Unix day count (Hinnant's algorithm).
fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    unix_to_rfc3339(secs)
}

fn unix_to_rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // civil_from_days (Howard Hinnant): days since 1970-01-01 → (y, m, d).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Append one `body` as a single `\n`-terminated JSON line. The whole
/// line is written in one call so a concurrent inbox reader only ever sees
/// complete, newline-terminated records (a torn tail is left for the next poll).
fn append_jsonl(path: &Path, body: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let line = format!(
        "{}\n",
        serde_json::to_string(body).map_err(|e| e.to_string())?
    );
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    f.write_all(line.as_bytes())
        .map_err(|e| format!("write {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn stamps_from_and_ts_when_absent() {
        // The repro: a raw body with neither field.
        let out = stamp_provenance(json!({"text": "hi"}), "agent-inao", "2026-06-21T00:00:00Z");
        assert_eq!(out["from"], "agent-inao");
        assert_eq!(out["ts"], "2026-06-21T00:00:00Z");
        assert_eq!(out["text"], "hi");
    }

    #[test]
    fn preserves_a_signed_envelopes_own_from_and_ts() {
        // A signed inner envelope carries from/ts in its signed payload — never
        // overwrite (that would invalidate the signature). `sender` is ignored.
        let signed = json!({
            "from": "agent-busaba", "to": "agent-inao",
            "ts": "2026-06-20T10:00:00Z", "message": "hi", "sig": "deadbeef",
        });
        let out = stamp_provenance(signed.clone(), "agent-evil", "2026-06-21T00:00:00Z");
        assert_eq!(
            out["from"], "agent-busaba",
            "must not override a present from"
        );
        assert_eq!(
            out["ts"], "2026-06-20T10:00:00Z",
            "must not override a present ts"
        );
        assert_eq!(out["sig"], "deadbeef");
    }

    #[test]
    fn wraps_a_non_object_body() {
        let out = stamp_provenance(json!("plain string"), "agent-x", "2026-06-21T00:00:00Z");
        assert_eq!(out["from"], "agent-x");
        assert_eq!(out["message"], "plain string");
    }

    #[test]
    fn rfc3339_formats_known_epochs() {
        assert_eq!(unix_to_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(unix_to_rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
        // A leap-year date (2024-02-29) to exercise the civil-date math.
        assert_eq!(unix_to_rfc3339(1_709_208_000), "2024-02-29T12:00:00Z");
    }

    #[test]
    fn only_an_exact_type_is_a_control_body() {
        assert_eq!(
            control_of(&json!({"type": "ping"})),
            Some(Control::Ping { id: None })
        );
        assert_eq!(
            control_of(&json!({"type": "ping", "id": "abc"})),
            Some(Control::Ping {
                id: Some("abc".into())
            })
        );
        assert_eq!(control_of(&json!({"type": "pong"})), Some(Control::Pong));
        // An ordinary message that talks about pinging is not a ping.
        assert_eq!(control_of(&json!({"message": "ping me back"})), None);
        assert_eq!(control_of(&json!({"type": "PING"})), None);
        assert_eq!(control_of(&json!({"type": 1})), None);
        assert_eq!(control_of(&json!("ping")), None);
    }

    #[test]
    fn an_oversized_or_non_string_ping_id_is_not_echoed() {
        let long = "x".repeat(MAX_PING_ID_LEN + 1);
        assert_eq!(
            control_of(&json!({"type": "ping", "id": long})),
            Some(Control::Ping { id: None })
        );
        assert_eq!(
            control_of(&json!({"type": "ping", "id": {"nested": true}})),
            Some(Control::Ping { id: None })
        );
    }

    #[test]
    fn a_pong_carries_nothing_from_the_ping_but_its_id() {
        let pong = build_pong("agent-me", "agent-you", Some("abc"), "2026-10-13T00:00:00Z");
        assert_eq!(pong.recipient, "agent-you");
        assert_eq!(pong.sender, "agent-me");
        assert_eq!(
            pong.body,
            json!({
                "type": "pong", "from": "agent-me", "to": "agent-you",
                "ts": "2026-10-13T00:00:00Z", "id": "abc",
            })
        );
        // The reply to a pong would be nothing: a pong is never a ping.
        assert_eq!(control_of(&pong.body), Some(Control::Pong));
    }

    #[test]
    fn the_limiter_spaces_pongs_per_claimed_sender() {
        let mut l = PongLimiter::default();
        let t0 = Instant::now();
        assert!(l.allow("a", t0));
        assert!(!l.allow("a", t0 + Duration::from_millis(500)));
        // A different sender has its own window.
        assert!(l.allow("b", t0 + Duration::from_millis(500)));
        assert!(l.allow("a", t0 + PONG_MIN_INTERVAL));
    }

    #[test]
    fn the_limiter_stays_bounded_under_a_flood_of_sender_ids() {
        let mut l = PongLimiter::default();
        let t0 = Instant::now();
        for i in 0..PONG_LIMITER_MAX_SENDERS {
            assert!(l.allow(&format!("s{i}"), t0));
        }
        // Full of live entries: a new id is refused, not remembered.
        assert!(!l.allow("one-more", t0));
        assert_eq!(l.last.len(), PONG_LIMITER_MAX_SENDERS);
        // Once the windows pass, the stale entries make room.
        assert!(l.allow("one-more", t0 + PONG_MIN_INTERVAL));
        assert_eq!(l.last.len(), 1);
    }
}
