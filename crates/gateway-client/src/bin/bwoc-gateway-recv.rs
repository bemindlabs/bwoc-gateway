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
                if env.body.get("from").and_then(|v| v.as_str()) == Some("user") {
                    eprintln!("bwoc-gateway-recv: dropped a relayed envelope claiming from=user");
                    continue;
                }
                append_inbox(&args.inbox, &env.body)?;
            }
            // Stream closed by the relay — exit non-zero so the supervisor
            // respawns us (a fresh connection).
            Ok(None) => return Err("relay closed the connection".into()),
            Err(e) => return Err(format!("recv: {e}")),
        }
    }
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
