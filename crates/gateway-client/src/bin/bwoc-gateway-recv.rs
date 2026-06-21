//! `bwoc-gateway-recv` — the receive counterpart of `bwoc-gateway-send`.
//!
//! It is the **transport artifact a standalone BWOC agent runs** to receive
//! gateway-relayed messages, the inverse of the send binary. It opens an
//! authenticated WebSocket to the relay (the agent's ed25519 keypair IS the
//! login = registration), then for every delivered envelope appends the inner
//! message `body` — the full `bwoc_signing` envelope the sender built — as one
//! newline-terminated JSON line to the agent's `.bwoc/inbox.jsonl`. From there
//! the existing `bwoc-agent --serve` inbox poller + trust gate take over,
//! exactly as for a locally-delivered message.
//!
//! Before persisting, it stamps the **authenticated sender id** (`Envelope.sender`,
//! which the relay verified by ed25519 at connect) as `from` and a receive `ts`
//! into the body **when those fields are absent** — so a recipient always has a
//! trustworthy `from`/`ts` instead of `?`. Present fields are never overwritten:
//! a signed inner envelope carries its own `from`/`ts` inside the signed payload,
//! so leaving them untouched keeps signature verification valid (#321).
//!
//! The relay is a dumb, untrusted relay: this binary does NOT verify the inner
//! signature — that stays on the receiving side (the agent's trust gate), which
//! must hold the sender's pinned public key. This binary is a pure transport
//! pipe: relay WS → inbox line.
//!
//! Usage (typically supervised by `bwoc-agent --serve`):
//!   bwoc-gateway-recv --url <wss://gw/v1/connect> --agent-id <self> \
//!                     --key-file <hex-seed> --inbox <.bwoc/inbox.jsonl>
//!
//! On stream end or any WebSocket error it exits non-zero so a supervisor can
//! respawn it (respawn = reconnect).

use std::io::Write;
use std::process::ExitCode;

use ed25519_dalek::SigningKey;
use gateway_client::{GatewayClient, GatewayConfig};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("bwoc-gateway-recv: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let args = Args::parse()?;
    let signing_key = load_key(&args.key_file)?;

    let config = GatewayConfig::new(&args.url, &args.agent_id);
    let mut client = GatewayClient::connect(&config, &signing_key)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    eprintln!(
        "bwoc-gateway-recv: connected as {} → {}",
        args.agent_id, args.url
    );

    loop {
        match client.next_envelope().await {
            Ok(Some(env)) => {
                // Security guard at the ingress boundary: a relayed message can
                // NEVER be from the local-trusted `user` principal — `user` is
                // the operator at the local IPC, not a remote sender. The
                // recipient's trust gate auto-passes `from = "user"`, so letting
                // a relayed `user` envelope reach the inbox would forge local
                // trust. Drop it outright.
                if env.body.get("from").and_then(|v| v.as_str()) == Some("user")
                    || env.sender == "user"
                {
                    eprintln!("bwoc-gateway-recv: dropped a relayed envelope claiming from=user");
                    continue;
                }
                // Stamp the cryptographically-authenticated sender id + a receive
                // timestamp into the persisted envelope so the recipient's tooling
                // always has a trustworthy `from`/`ts` (the relay verified the
                // ed25519 identity = `env.sender`). Absent-only: a properly signed
                // inner envelope already carries `from`/`ts` as part of its signed
                // payload, so we must NOT overwrite them (that would invalidate the
                // signature) — we only fill them in when missing (e.g. a raw body).
                let body = stamp_provenance(env.body, &env.sender, &now_rfc3339());
                append_inbox(&args.inbox, &body)?;
            }
            // Stream closed by the relay — exit non-zero so the supervisor
            // respawns us (a fresh connection).
            Ok(None) => return Err("relay closed the connection".into()),
            Err(e) => return Err(format!("recv: {e}")),
        }
    }
}

/// Fill in `from` (= the authenticated `sender`) and `ts` (= receive time) on
/// the persisted envelope **only when absent**. A properly signed inner envelope
/// already carries both inside its signed payload, so leaving present fields
/// untouched keeps the recipient's signature verification valid; a raw body that
/// lacks them gets a trustworthy attribution + timestamp instead of rendering as
/// `?`. A non-object body is wrapped as `{from, ts, message: <body>}` so it is
/// still attributable. `from`/`ts` are not overwritten even if the body claims
/// its own (the recipient's trust gate is the authority on a claimed identity).
fn stamp_provenance(body: serde_json::Value, sender: &str, ts: &str) -> serde_json::Value {
    use serde_json::Value;
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

/// Append one envelope `body` as a single `\n`-terminated JSON line. The whole
/// line is written in one call so a concurrent inbox reader only ever sees
/// complete, newline-terminated records (a torn tail is left for the next poll).
fn append_inbox(inbox: &str, body: &serde_json::Value) -> Result<(), String> {
    if let Some(parent) = std::path::Path::new(inbox).parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let line = format!(
        "{}\n",
        serde_json::to_string(body).map_err(|e| e.to_string())?
    );
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(inbox)
        .map_err(|e| format!("open inbox {inbox}: {e}"))?;
    f.write_all(line.as_bytes())
        .map_err(|e| format!("write inbox {inbox}: {e}"))
}

/// Load a hex-encoded 32-byte ed25519 seed from `path` (trailing whitespace ok).
fn load_key(path: &str) -> Result<SigningKey, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read key file {path}: {e}"))?;
    let seed: [u8; 32] = hex::decode(raw.trim())
        .map_err(|e| format!("key hex: {e}"))?
        .try_into()
        .map_err(|_| "key must be 32 bytes".to_string())?;
    Ok(SigningKey::from_bytes(&seed))
}

struct Args {
    url: String,
    agent_id: String,
    key_file: String,
    inbox: String,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let (mut url, mut agent_id, mut key_file, mut inbox) = (None, None, None, None);
        let mut it = std::env::args().skip(1);
        while let Some(flag) = it.next() {
            let mut value = || it.next().ok_or_else(|| format!("missing value for {flag}"));
            match flag.as_str() {
                "--url" => url = Some(value()?),
                "--agent-id" => agent_id = Some(value()?),
                "--key-file" => key_file = Some(value()?),
                "--inbox" => inbox = Some(value()?),
                other => return Err(format!("unknown argument: {other}")),
            }
        }
        Ok(Self {
            url: url.ok_or("missing --url")?,
            agent_id: agent_id.ok_or("missing --agent-id")?,
            key_file: key_file.ok_or("missing --key-file")?,
            inbox: inbox.ok_or("missing --inbox")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{stamp_provenance, unix_to_rfc3339};
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
}
