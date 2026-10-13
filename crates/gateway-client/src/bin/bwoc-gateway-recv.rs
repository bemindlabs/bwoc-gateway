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
//!                     [--auto-pong] [--pong-log <path>] \
//!                     [--on-message <program> --trust-key <agent-id>=<pubkey-hex>...
//!                      [--on-message-timeout-secs <n>] [--on-message-max-age-secs <n>]]
//!
//! `--auto-pong` (off by default) answers a `{"type":"ping"}` body with a pong
//! from the bridge itself and keeps ping/pong out of the inbox; received pongs
//! go to `--pong-log` (default: `gateway-pong.jsonl` beside the inbox).
//!
//! `--on-message` (off by default) runs a program for each message whose inner
//! signature verifies against a `--trust-key` pinned for its sender; the message
//! arrives on the program's stdin. See `gateway_client::bridge` for the rules.
//!
//! On stream end or any WebSocket error it exits non-zero so a supervisor can
//! respawn it (respawn = reconnect).

use std::collections::HashMap;
use std::process::ExitCode;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use gateway_client::bridge::{self, BridgeOptions, HookOptions};
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
    if let Some(hook) = &args.bridge.hook {
        let mut trusted: Vec<&str> = hook.trust_keys.keys().map(String::as_str).collect();
        trusted.sort_unstable();
        eprintln!(
            "bwoc-gateway-recv: on-message {} for signed mail from: {}",
            hook.program.display(),
            trusted.join(", ")
        );
    }

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
        let (mut on_message, mut trust_keys) = (None, HashMap::new());
        let (mut hook_timeout, mut hook_max_age) = (None, None);
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
                "--on-message" => on_message = Some(value()?),
                "--trust-key" => {
                    let (id, key) = bridge::parse_trust_key(&value()?)?;
                    if trust_keys.insert(id.clone(), key).is_some() {
                        return Err(format!("--trust-key given twice for {id}"));
                    }
                }
                "--on-message-timeout-secs" => {
                    hook_timeout = Some(positive_secs(&flag, &value()?)?)
                }
                "--on-message-max-age-secs" => {
                    hook_max_age = Some(positive_secs(&flag, &value()?)?)
                }
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
        match on_message {
            Some(program) => {
                // Without a pinned key nothing could ever verify, and running
                // the hook on unverified mail is exactly what this must not do.
                if trust_keys.is_empty() {
                    return Err("--on-message needs at least one --trust-key".into());
                }
                bridge.hook = Some(HookOptions {
                    program: program.into(),
                    trust_keys,
                    timeout: hook_timeout.unwrap_or(bridge::DEFAULT_HOOK_TIMEOUT),
                    max_age: hook_max_age.unwrap_or(bridge::DEFAULT_HOOK_MAX_AGE),
                });
            }
            None => {
                if !trust_keys.is_empty() || hook_timeout.is_some() || hook_max_age.is_some() {
                    return Err("--trust-key / --on-message-* need --on-message".into());
                }
            }
        }
        Ok(Self {
            url: url.ok_or("missing --url")?,
            agent_id: agent_id.ok_or("missing --agent-id")?,
            key_file: key_file.ok_or("missing --key-file")?,
            bridge,
        })
    }
}

/// A whole number of seconds, at least 1. Zero is refused rather than read as
/// "no limit": both flags bound something that must stay bounded.
fn positive_secs(flag: &str, raw: &str) -> Result<Duration, String> {
    match raw.trim().parse::<u64>() {
        Ok(n) if n > 0 => Ok(Duration::from_secs(n)),
        _ => Err(format!("{flag} must be a whole number of seconds ≥ 1")),
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

    const KEY: &str =
        "agent-alpha=ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";

    #[test]
    fn the_hook_is_off_unless_asked_for() {
        assert!(parse(&[]).unwrap().bridge.hook.is_none());
    }

    #[test]
    fn the_hook_needs_a_pinned_key() {
        let err = parse(&["--on-message", "/bin/true"]).unwrap_err();
        assert!(err.contains("--trust-key"), "{err}");
        let hook = parse(&["--on-message", "/bin/true", "--trust-key", KEY])
            .unwrap()
            .bridge
            .hook
            .unwrap();
        assert_eq!(hook.program, Path::new("/bin/true"));
        assert!(hook.trust_keys.contains_key("agent-alpha"));
        assert_eq!(hook.timeout, gateway_client::bridge::DEFAULT_HOOK_TIMEOUT);
        assert_eq!(hook.max_age, gateway_client::bridge::DEFAULT_HOOK_MAX_AGE);
    }

    #[test]
    fn hook_flags_without_the_hook_are_usage_errors() {
        assert!(parse(&["--trust-key", KEY]).is_err());
        assert!(parse(&["--on-message-timeout-secs", "5"]).is_err());
    }

    #[test]
    fn hook_limits_must_be_positive_whole_seconds() {
        let with = |flag: &str, v: &str| {
            parse(&["--on-message", "/bin/true", "--trust-key", KEY, flag, v])
        };
        for flag in ["--on-message-timeout-secs", "--on-message-max-age-secs"] {
            assert!(with(flag, "0").is_err(), "{flag} 0 must not mean unlimited");
            assert!(with(flag, "-1").is_err());
            assert!(with(flag, "soon").is_err());
        }
        let hook = with("--on-message-timeout-secs", "5")
            .unwrap()
            .bridge
            .hook
            .unwrap();
        assert_eq!(hook.timeout, std::time::Duration::from_secs(5));
    }

    #[test]
    fn a_repeated_or_malformed_trust_key_is_refused() {
        assert!(parse(&[
            "--on-message",
            "/bin/true",
            "--trust-key",
            KEY,
            "--trust-key",
            KEY
        ])
        .is_err());
        assert!(parse(&[
            "--on-message",
            "/bin/true",
            "--trust-key",
            "agent-alpha=abcd"
        ])
        .is_err());
    }

    #[test]
    fn a_pong_log_without_auto_pong_is_a_usage_error() {
        assert!(parse(&["--pong-log", "/tmp/p.jsonl"]).is_err());
    }
}
