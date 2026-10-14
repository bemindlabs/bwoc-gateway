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

//!
//! # On-message hook (opt-in)
//!
//! With [`BridgeOptions::hook`] the bridge runs one operator-configured program
//! per message, so an agent can act on mail without a live session. The
//! gateway stays a relay: it runs the program and nothing else.
//!
//! This is remote input triggering local execution, so the gate is the inner
//! signature and never `sender`:
//!
//! - The hook runs only for an envelope whose `bwoc_signing` signature verifies
//!   against a key the operator pinned for its `from` ([`HookOptions::trust_keys`]),
//!   and whose signed `to` is this agent.
//! - The signed `ts` must be within [`HookOptions::max_age`] of now, and a
//!   `(from, messageId, nonce)` is accepted once, so a captured envelope cannot
//!   be replayed. Mail parked longer than `max_age` therefore reaches the inbox
//!   but does not fire the hook.
//! - The program is executed directly, never through a shell. The message
//!   arrives on **stdin**; nothing from it is placed in argv. The verified
//!   sender and message id are passed in `BWOC_GATEWAY_FROM` and
//!   `BWOC_GATEWAY_MESSAGE_ID`, and this agent's own id in
//!   `BWOC_GATEWAY_AGENT_ID`.
//! - Runs are bounded: at most [`HOOK_MAX_CONCURRENT`] at once (extra messages
//!   skip the hook) and each is killed after [`HookOptions::timeout`], which
//!   covers feeding it the message as well as waiting for it to exit.
//!   The kill reaches the program itself, not processes it started, so a hook
//!   that launches long work should `exec` it or manage its own children.
//!
//! Every message is written to the inbox first, whatever the hook does; a hook
//! that fails, times out or is skipped never loses mail.

use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;

use crate::{Envelope, GatewayClient};

/// Longest ping `id` echoed back in a pong. Anything longer is dropped rather
/// than truncated, so the echoed value is always exactly what was sent.
const MAX_PING_ID_LEN: usize = 128;

/// Minimum gap between two pongs to the same claimed sender.
const PONG_MIN_INTERVAL: Duration = Duration::from_secs(1);

/// Cap on distinct claimed senders remembered by the limiter. A flood of
/// made-up sender ids would otherwise grow the map without bound.
const PONG_LIMITER_MAX_SENDERS: usize = 1024;

/// Most hook processes alive at once. A message arriving while all are busy is
/// still delivered to the inbox; it just does not fire the hook.
pub const HOOK_MAX_CONCURRENT: usize = 4;

/// Default wall-clock limit for one hook run.
pub const DEFAULT_HOOK_TIMEOUT: Duration = Duration::from_secs(60);

/// Default freshness window for a signed `ts`, and so how long a replay is
/// remembered.
pub const DEFAULT_HOOK_MAX_AGE: Duration = Duration::from_secs(300);

/// Cap on remembered `(from, messageId, nonce)` triples inside the window.
const REPLAY_MAX_ENTRIES: usize = 4096;

/// The opt-in on-message hook. See the module docs for the trust rules.
#[derive(Debug, Clone)]
pub struct HookOptions {
    /// Program to execute (directly, no shell) with the message on stdin.
    pub program: PathBuf,
    /// Pinned ed25519 public keys by agent id. Only these senders fire the hook.
    pub trust_keys: HashMap<String, VerifyingKey>,
    /// Kill a run that takes longer than this.
    pub timeout: Duration,
    /// Accept a signed `ts` at most this far from now, in either direction.
    pub max_age: Duration,
}

/// Parse a pinned key given as `<agent-id>=<64 hex chars>`.
pub fn parse_trust_key(spec: &str) -> Result<(String, VerifyingKey), String> {
    let (id, hex_key) = spec
        .split_once('=')
        .ok_or_else(|| format!("trust key must be <agent-id>=<pubkey-hex>: {spec}"))?;
    if id.is_empty() || id == "user" {
        return Err(format!("trust key has an unusable agent id: {spec}"));
    }
    let bytes: [u8; 32] = hex::decode(hex_key.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| format!("trust key for {id} must be 32 bytes of hex"))?;
    let key = VerifyingKey::from_bytes(&bytes)
        .map_err(|_| format!("trust key for {id} is not a valid ed25519 key"))?;
    Ok((id.to_string(), key))
}

/// How the bridge should run.
#[derive(Debug, Clone)]
pub struct BridgeOptions {
    /// The agent's `.bwoc/inbox.jsonl`.
    pub inbox: PathBuf,
    /// Answer `{"type":"ping"}` with a pong and keep ping/pong out of the inbox.
    pub auto_pong: bool,
    /// Where received pongs are appended (JSON lines) when `auto_pong` is on.
    pub pong_log: PathBuf,
    /// Run a program for each verified message. `None` = off.
    pub hook: Option<HookOptions>,
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
            hook: None,
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
    let mut state = BridgeState::default();
    loop {
        match client.next_envelope().await {
            Ok(Some(env)) => handle(client, opts, &mut state, env).await?,
            Ok(None) => return Err("relay closed the connection".into()),
            Err(e) => return Err(format!("recv: {e}")),
        }
    }
}

/// What the loop remembers between envelopes.
struct BridgeState {
    limiter: PongLimiter,
    replay: ReplayGuard,
    hook_slots: Arc<Semaphore>,
}

impl Default for BridgeState {
    fn default() -> Self {
        Self {
            limiter: PongLimiter::default(),
            replay: ReplayGuard::default(),
            hook_slots: Arc::new(Semaphore::new(HOOK_MAX_CONCURRENT)),
        }
    }
}

async fn handle(
    client: &mut GatewayClient,
    opts: &BridgeOptions,
    state: &mut BridgeState,
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
                if !state.limiter.allow(&env.sender, Instant::now()) {
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
    // carries `from`/`ts` (strings) as part of its signed payload, so we must
    // NOT overwrite them (that would invalidate the signature).
    let body = stamp_provenance(env.body, &env.sender, &now_rfc3339());
    append_jsonl(&opts.inbox, &body)?;

    if let Some(hook) = &opts.hook {
        let self_id = client.agent_id();
        match verify_for_hook(&body, self_id, hook, now_unix(), &mut state.replay) {
            Ok(verified) => spawn_hook(hook, self_id, verified, &body, &state.hook_slots),
            Err(why) => eprintln!("bwoc-gateway-recv: on-message not run: {why}"),
        }
    }
    Ok(())
}

/// The parts of a message the signature vouches for, once it has verified.
#[derive(Debug, PartialEq, Eq)]
struct Verified {
    from: String,
    message_id: String,
}

/// Remembers accepted `(from, messageId, nonce)` triples for the freshness
/// window so a captured envelope fires the hook once.
#[derive(Default)]
struct ReplayGuard {
    /// key → the envelope's signed `ts` (unix seconds).
    seen: HashMap<String, i64>,
}

impl ReplayGuard {
    /// Record `key`; `false` if it was already seen or the guard is full.
    fn first_time(&mut self, key: String, ts: i64, now: i64, max_age: i64) -> bool {
        // Anything outside the window would be refused as stale anyway, so it
        // no longer needs remembering.
        self.seen.retain(|_, t| (now - *t).abs() <= max_age);
        if self.seen.contains_key(&key) || self.seen.len() >= REPLAY_MAX_ENTRIES {
            return false;
        }
        self.seen.insert(key, ts);
        true
    }
}

/// The RFC 8785 canonical bytes `bwoc_signing` signs: the six string fields as
/// a JSON object with sorted keys and no whitespace. Must stay byte-identical
/// to `bwoc_signing::canonical_bytes` — the test vector below was produced by
/// that crate.
fn canonical_bytes(
    from: &str,
    to: &str,
    ts: &str,
    message_id: &str,
    message: &str,
    nonce: &str,
) -> Vec<u8> {
    let map: BTreeMap<&str, &str> = BTreeMap::from([
        ("from", from),
        ("to", to),
        ("ts", ts),
        ("messageId", message_id),
        ("message", message),
        ("nonce", nonce),
    ]);
    serde_json::to_vec(&map).expect("BTreeMap<&str,&str> is always serializable")
}

/// Decide whether `body` may fire the hook. Every refusal is a reason string
/// for the log; none of them stops the message reaching the inbox.
fn verify_for_hook(
    body: &Value,
    self_id: &str,
    hook: &HookOptions,
    now: i64,
    replay: &mut ReplayGuard,
) -> Result<Verified, &'static str> {
    let field = |k: &str| body.get(k).and_then(Value::as_str);
    let (Some(from), Some(to), Some(ts), Some(message_id), Some(message), Some(nonce), Some(sig)) = (
        field("from"),
        field("to"),
        field("ts"),
        field("messageId"),
        field("message"),
        field("nonce"),
        field("sig"),
    ) else {
        return Err("not a signed envelope");
    };
    if to != self_id {
        return Err("signed for a different recipient");
    }
    let key = hook
        .trust_keys
        .get(from)
        .ok_or("sender has no pinned key")?;
    let sig: [u8; 64] = hex::decode(sig.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("bad signature")?;
    key.verify(
        &canonical_bytes(from, to, ts, message_id, message, nonce),
        &Signature::from_bytes(&sig),
    )
    .map_err(|_| "bad signature")?;

    // Only now is `ts` trustworthy enough to reason about.
    let max_age = i64::try_from(hook.max_age.as_secs()).unwrap_or(i64::MAX);
    let sent = rfc3339_to_unix(ts).ok_or("unreadable ts")?;
    if (now - sent).abs() > max_age {
        return Err("outside the freshness window");
    }
    if !replay.first_time(format!("{from}\n{message_id}\n{nonce}"), sent, now, max_age) {
        return Err("replayed or replay guard full");
    }
    Ok(Verified {
        from: from.to_string(),
        message_id: message_id.to_string(),
    })
}

/// Start the hook for a verified message without blocking the receive loop.
fn spawn_hook(
    hook: &HookOptions,
    self_id: &str,
    verified: Verified,
    body: &Value,
    slots: &Arc<Semaphore>,
) {
    let Ok(permit) = slots.clone().try_acquire_owned() else {
        eprintln!(
            "bwoc-gateway-recv: on-message busy ({HOOK_MAX_CONCURRENT} running); skipped {}",
            verified.message_id
        );
        return;
    };
    let Ok(mut line) = serde_json::to_vec(body) else {
        return;
    };
    line.push(b'\n');
    let mut cmd = tokio::process::Command::new(&hook.program);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .env("BWOC_GATEWAY_FROM", &verified.from)
        .env("BWOC_GATEWAY_MESSAGE_ID", &verified.message_id)
        .env("BWOC_GATEWAY_AGENT_ID", self_id)
        .kill_on_drop(true);
    let (program, timeout) = (hook.program.clone(), hook.timeout);

    tokio::spawn(async move {
        let _permit = permit;
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("bwoc-gateway-recv: on-message {}: {e}", program.display());
                return;
            }
        };
        // The write is inside the timed future on purpose: a hook that never
        // drains stdin blocks `write_all` once the message outgrows the pipe
        // buffer, and an untimed write would hold this run's slot forever.
        let stdin = child.stdin.take();
        let run = async {
            if let Some(mut stdin) = stdin {
                // A hook that exits without reading closes the pipe; that is
                // its business, not an error worth more than the exit status.
                let _ = stdin.write_all(&line).await;
            }
            child.wait().await
        };
        let outcome = tokio::time::timeout(timeout, run).await;
        match outcome {
            Ok(Ok(status)) if status.success() => {}
            Ok(Ok(status)) => eprintln!(
                "bwoc-gateway-recv: on-message for {} exited {status}",
                verified.message_id
            ),
            Ok(Err(e)) => eprintln!("bwoc-gateway-recv: on-message wait: {e}"),
            Err(_) => {
                let _ = child.kill().await;
                eprintln!(
                    "bwoc-gateway-recv: on-message for {} killed after {timeout:?}",
                    verified.message_id
                );
            }
        }
    });
}

/// Fill in `from` (= the relay-reported `sender`, a claim — see the module
/// docs) and `ts` (= receive time) on
/// the persisted envelope **only when absent or not a string**. A properly signed inner envelope
/// already carries both inside its signed payload, so leaving present fields
/// untouched keeps the recipient's signature verification valid; a raw body that
/// lacks them gets an attribution + timestamp instead of rendering as
/// `?`. A non-string `from`/`ts` is replaced too: it is not a valid
/// `bwoc_signing` field (those are strings), so it could not be part of a
/// verifiable signature and would otherwise still render as `?`. A non-object body is wrapped as `{from, ts, message: <body>}` so it is
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

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Parse the framework's canonical `YYYY-MM-DDThh:mm:ssZ` back to unix seconds.
/// Deliberately strict — exactly that shape, UTC only — because the value is a
/// security input (the freshness check); anything else is refused.
fn rfc3339_to_unix(ts: &str) -> Option<i64> {
    let b = ts.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let s = &ts[r];
        s.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| s.parse().ok())?
    };
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hh, mm, ss) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 59 {
        return None;
    }
    // days_from_civil (Howard Hinnant), the inverse of `unix_to_rfc3339`.
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + hh * 3600 + mm * 60 + ss;
    // Reject dates that do not exist (e.g. Feb 30) rather than rolling them over.
    (unix_to_rfc3339(secs) == ts).then_some(secs)
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
        assert_eq!(out["ts"], "2026-06-21T00:00:00Z");
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

    // Produced by the framework's own `bwoc_signing` crate (seed `[7; 32]`),
    // so this pins our canonical form and verification to theirs.
    const VEC_PUB: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
    const VEC_SIG: &str = "57ad87a3476091397cdbf43e5a9520d73efba1be5aa61346c9df4549b16a7954\
                           c6812dd2e4a1d3db0139d72b8355d46f29a99c4e3b44914f1ad778578f547108";
    const VEC_TS: &str = "2026-10-13T12:00:00Z";

    fn vec_body() -> Value {
        json!({
            "from": "agent-alpha", "to": "agent-beta", "ts": VEC_TS,
            "messageId": "msg-20261013T120000Z-ab123",
            "message": "deploy \"now\" — ไทย\n",
            "nonce": "00112233445566778899aabbccddeeff",
            "sig": VEC_SIG,
        })
    }

    fn vec_hook() -> HookOptions {
        let (id, key) = parse_trust_key(&format!("agent-alpha={VEC_PUB}")).unwrap();
        HookOptions {
            program: "/bin/true".into(),
            trust_keys: HashMap::from([(id, key)]),
            timeout: DEFAULT_HOOK_TIMEOUT,
            max_age: DEFAULT_HOOK_MAX_AGE,
        }
    }

    fn vec_now() -> i64 {
        rfc3339_to_unix(VEC_TS).unwrap()
    }

    #[test]
    fn canonical_bytes_match_the_frameworks() {
        // Fields come from the fixture so the vector is written down once.
        let body = vec_body();
        let f = |k: &str| body[k].as_str().unwrap();
        let got = canonical_bytes(
            f("from"),
            f("to"),
            f("ts"),
            f("messageId"),
            f("message"),
            f("nonce"),
        );
        assert_eq!(
            String::from_utf8(got).unwrap(),
            r#"{"from":"agent-alpha","message":"deploy \"now\" — ไทย\n","messageId":"msg-20261013T120000Z-ab123","nonce":"00112233445566778899aabbccddeeff","to":"agent-beta","ts":"2026-10-13T12:00:00Z"}"#
        );
    }

    #[test]
    fn a_framework_signed_envelope_verifies() {
        let got = verify_for_hook(
            &vec_body(),
            "agent-beta",
            &vec_hook(),
            vec_now() + 5,
            &mut ReplayGuard::default(),
        );
        assert_eq!(
            got,
            Ok(Verified {
                from: "agent-alpha".into(),
                message_id: "msg-20261013T120000Z-ab123".into(),
            })
        );
    }

    #[test]
    fn the_hook_gate_refuses_everything_the_signature_does_not_cover() {
        let hook = vec_hook();
        let check = |body: &Value, me: &str, now: i64| {
            verify_for_hook(body, me, &hook, now, &mut ReplayGuard::default())
        };

        // Any signed field changed → the signature no longer matches.
        for (k, v) in [
            ("message", "deploy something else"),
            ("ts", "2026-10-13T12:00:01Z"),
            ("messageId", "msg-other"),
            ("nonce", "ffffffffffffffffffffffffffffffff"),
        ] {
            let mut b = vec_body();
            b[k] = json!(v);
            assert_eq!(
                check(&b, "agent-beta", vec_now()),
                Err("bad signature"),
                "{k}"
            );
        }

        // Re-aimed at another agent: `to` is signed, and it must be us.
        assert_eq!(
            check(&vec_body(), "agent-gamma", vec_now()),
            Err("signed for a different recipient")
        );

        // A sender we hold no key for — including one that just claims a name.
        let mut b = vec_body();
        b["from"] = json!("agent-mallory");
        assert_eq!(
            check(&b, "agent-beta", vec_now()),
            Err("sender has no pinned key")
        );

        // Unsigned / partial bodies never reach verification.
        assert_eq!(
            check(
                &json!({"from": "agent-alpha", "message": "hi"}),
                "agent-beta",
                vec_now()
            ),
            Err("not a signed envelope")
        );
        let mut b = vec_body();
        b["sig"] = json!("00");
        assert_eq!(check(&b, "agent-beta", vec_now()), Err("bad signature"));
    }

    #[test]
    fn a_valid_envelope_is_refused_when_stale_or_from_the_future() {
        let hook = vec_hook();
        let age = DEFAULT_HOOK_MAX_AGE.as_secs() as i64;
        let check = |now: i64| {
            verify_for_hook(
                &vec_body(),
                "agent-beta",
                &hook,
                now,
                &mut ReplayGuard::default(),
            )
        };
        assert!(check(vec_now() + age).is_ok());
        assert_eq!(
            check(vec_now() + age + 1),
            Err("outside the freshness window")
        );
        assert!(check(vec_now() - age).is_ok());
        assert_eq!(
            check(vec_now() - age - 1),
            Err("outside the freshness window")
        );
    }

    #[test]
    fn a_replayed_envelope_fires_once() {
        let hook = vec_hook();
        let mut guard = ReplayGuard::default();
        assert!(verify_for_hook(&vec_body(), "agent-beta", &hook, vec_now(), &mut guard).is_ok());
        assert_eq!(
            verify_for_hook(&vec_body(), "agent-beta", &hook, vec_now() + 1, &mut guard),
            Err("replayed or replay guard full")
        );
    }

    #[test]
    fn the_replay_guard_forgets_only_what_is_already_stale() {
        let mut g = ReplayGuard::default();
        assert!(g.first_time("k".into(), 1000, 1000, 300));
        assert!(!g.first_time("k".into(), 1000, 1300, 300));
        // Past the window the entry is dropped — safe, because the same
        // envelope is now refused as stale before it gets here.
        assert!(g.first_time("other".into(), 1400, 1400, 300));
        assert!(!g.seen.contains_key("k"));

        let mut g = ReplayGuard::default();
        for i in 0..REPLAY_MAX_ENTRIES {
            assert!(g.first_time(format!("k{i}"), 0, 0, 300));
        }
        assert!(
            !g.first_time("overflow".into(), 0, 0, 300),
            "full guard fails closed"
        );
    }

    #[test]
    fn trust_keys_parse_strictly() {
        assert!(parse_trust_key(&format!("agent-alpha={VEC_PUB}")).is_ok());
        assert!(parse_trust_key(VEC_PUB).is_err(), "no agent id");
        assert!(parse_trust_key(&format!("={VEC_PUB}")).is_err());
        assert!(parse_trust_key("agent-alpha=abcd").is_err(), "short key");
        assert!(parse_trust_key("agent-alpha=zz").is_err());
        // `user` is the local operator and can never be a remote sender.
        assert!(parse_trust_key(&format!("user={VEC_PUB}")).is_err());
    }

    #[test]
    fn rfc3339_parses_only_the_canonical_shape() {
        for secs in [0, 1_700_000_000, 1_709_208_000, 4_102_444_799] {
            assert_eq!(rfc3339_to_unix(&unix_to_rfc3339(secs)), Some(secs));
        }
        for bad in [
            "",
            "2026-10-13T12:00:00",
            "2026-10-13T12:00:00+07:00",
            "2026-10-13 12:00:00Z",
            "2026-10-13T12:00:00.5Z",
            "2026-02-30T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-10-13T24:00:00Z",
            "+026-10-13T12:00:00Z",
        ] {
            assert_eq!(rfc3339_to_unix(bad), None, "{bad:?}");
        }
    }
}
