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
//! Before persisting, it stamps the relay-reported sender id (`Envelope.sender`)
//! as `from` and a receive `ts` into the body **when those fields are absent** —
//! so a recipient always has a `from`/`ts` instead of `?`. That `sender` is a
//! claim, not a proof (see `gateway_client::bridge`). Present fields are never
//! overwritten: a signed inner envelope carries its own `from`/`ts` inside the
//! signed payload, so leaving them untouched keeps signature verification valid
//! (#321).
//!
//! The relay is a dumb, untrusted relay: this binary does NOT verify the inner
//! signature — that stays on the receiving side (the agent's trust gate), which
//! must hold the sender's pinned public key. This binary is a pure transport
//! pipe: relay WS → inbox line.
//!
//! Usage (typically supervised by `bwoc-agent --serve`):
//!   bwoc-gateway-recv --url <wss://gw/v1/connect> --agent-id <self> \
//!                     --key-file <hex-seed> --inbox <.bwoc/inbox.jsonl> \
//!                     [--auto-pong] [--pong-log <path>]
//!
//! `--auto-pong` (off by default) answers a `{"type":"ping"}` body with a pong
//! from the bridge itself and keeps ping/pong out of the inbox; received pongs
//! go to `--pong-log` (default: `gateway-pong.jsonl` beside the inbox).
//!
//! On stream end or any WebSocket error it exits non-zero so a supervisor can
//! respawn it (respawn = reconnect).

use std::process::ExitCode;

use ed25519_dalek::SigningKey;
use gateway_client::bridge::{self, BridgeOptions};
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
    let args = Args::parse(std::env::args().skip(1))?;
    let signing_key = load_key(&args.key_file)?;

    let config = GatewayConfig::new(&args.url, &args.agent_id);
    let mut client = GatewayClient::connect(&config, &signing_key)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    eprintln!(
        "bwoc-gateway-recv: connected as {} → {}{}",
        args.agent_id,
        args.url,
        if args.bridge.auto_pong {
            " (auto-pong on)"
        } else {
            ""
        }
    );

    bridge::run(&mut client, &args.bridge).await
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

#[derive(Debug)]
struct Args {
    url: String,
    agent_id: String,
    key_file: String,
    bridge: BridgeOptions,
}

impl Args {
    fn parse(args: impl Iterator<Item = String>) -> Result<Self, String> {
        let (mut url, mut agent_id, mut key_file, mut inbox) = (None, None, None, None);
        let (mut auto_pong, mut pong_log) = (false, None);
        let mut it = args;
        while let Some(flag) = it.next() {
            let mut value = || it.next().ok_or_else(|| format!("missing value for {flag}"));
            match flag.as_str() {
                "--url" => url = Some(value()?),
                "--agent-id" => agent_id = Some(value()?),
                "--key-file" => key_file = Some(value()?),
                "--inbox" => inbox = Some(value()?),
                "--auto-pong" => auto_pong = true,
                "--pong-log" => pong_log = Some(value()?),
                other => return Err(format!("unknown argument: {other}")),
            }
        }
        let mut bridge = BridgeOptions::new(inbox.ok_or("missing --inbox")?);
        bridge.auto_pong = auto_pong;
        if let Some(p) = pong_log {
            if !auto_pong {
                return Err("--pong-log needs --auto-pong".into());
            }
            bridge.pong_log = p.into();
        }
        Ok(Self {
            url: url.ok_or("missing --url")?,
            agent_id: agent_id.ok_or("missing --agent-id")?,
            key_file: key_file.ok_or("missing --key-file")?,
            bridge,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Args;
    use std::path::Path;

    fn parse(extra: &[&str]) -> Result<Args, String> {
        let base = [
            "--url",
            "ws://x",
            "--agent-id",
            "a",
            "--key-file",
            "k",
            "--inbox",
            "/w/.bwoc/inbox.jsonl",
        ];
        Args::parse(base.iter().chain(extra).map(|s| s.to_string()))
    }

    #[test]
    fn auto_pong_is_off_unless_asked_for() {
        let a = parse(&[]).unwrap();
        assert!(!a.bridge.auto_pong);
    }

    #[test]
    fn auto_pong_defaults_the_pong_log_beside_the_inbox() {
        let a = parse(&["--auto-pong"]).unwrap();
        assert!(a.bridge.auto_pong);
        assert_eq!(a.bridge.pong_log, Path::new("/w/.bwoc/gateway-pong.jsonl"));
        let a = parse(&["--auto-pong", "--pong-log", "/tmp/p.jsonl"]).unwrap();
        assert_eq!(a.bridge.pong_log, Path::new("/tmp/p.jsonl"));
    }

    #[test]
    fn a_pong_log_without_auto_pong_is_a_usage_error() {
        assert!(parse(&["--pong-log", "/tmp/p.jsonl"]).is_err());
    }
}
