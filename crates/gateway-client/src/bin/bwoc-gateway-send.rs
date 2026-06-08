//! `bwoc-gateway-send` — one-shot relay of a single message through a gateway.
//!
//! This is the **transport artifact the BWOC harness shells out to** for a
//! `RouteTarget::Gateway` route, mirroring `bwoc-mqtt publish`. The harness
//! builds and signs its message envelope (the `bwoc_signing` signature the
//! recipient harness verifies) and pipes that JSON on **stdin** — exactly as it
//! does for MQTT. This binary wraps it into a gateway transport `Envelope`
//! (routing by `--to`, like MQTT's `--topic`), opens an authenticated
//! WebSocket with the sender's key, sends it, and exits.
//!
//! The gateway is a dumb relay: it routes on `recipient` and never inspects the
//! `body`. Authenticity is the *inner* message envelope's concern (the harness
//! verifies that on the far side), so the transport `Envelope.signature` is left
//! empty here — it is not part of BWOC's trust path.
//!
//! Usage:
//!   bwoc-gateway-send --url <wss://gw/v1/connect> --agent-id <from> --to <recipient> --key-file <hex-seed>
//!   echo '<message json>' | bwoc-gateway-send ...
//!
//! The key file holds the sender's hex-encoded 32-byte ed25519 seed — used only
//! for the gateway login handshake (the keypair IS the login). Reading the
//! message from stdin avoids `ARG_MAX` (E2BIG) on long messages.

use std::io::Read;
use std::process::ExitCode;

use ed25519_dalek::SigningKey;
use gateway_client::{Envelope, GatewayClient, GatewayConfig};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("bwoc-gateway-send: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let args = Args::parse()?;

    let signing_key = load_key(&args.key_file)?;
    let mut body_json = String::new();
    std::io::stdin()
        .read_to_string(&mut body_json)
        .map_err(|e| format!("read stdin: {e}"))?;
    let body: serde_json::Value =
        serde_json::from_str(&body_json).map_err(|e| format!("parse message body: {e}"))?;

    // Wrap the harness message into a transport envelope. The relay routes on
    // `recipient`; the inner `body` already carries the BWOC signature, so the
    // transport `signature` is intentionally empty (see module docs).
    let envelope = Envelope {
        recipient: args.to,
        sender: args.agent_id.clone(),
        signature: String::new(),
        body,
    };

    let config = GatewayConfig::new(args.url, args.agent_id);
    let mut client = GatewayClient::connect(&config, &signing_key)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    client
        .send(&envelope)
        .await
        .map_err(|e| format!("send: {e}"))?;
    Ok(())
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
    to: String,
    key_file: String,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let (mut url, mut agent_id, mut to, mut key_file) = (None, None, None, None);
        let mut it = std::env::args().skip(1);
        while let Some(flag) = it.next() {
            let mut value = || it.next().ok_or_else(|| format!("missing value for {flag}"));
            match flag.as_str() {
                "--url" => url = Some(value()?),
                "--agent-id" => agent_id = Some(value()?),
                "--to" => to = Some(value()?),
                "--key-file" => key_file = Some(value()?),
                other => return Err(format!("unknown argument: {other}")),
            }
        }
        Ok(Self {
            url: url.ok_or("missing --url")?,
            agent_id: agent_id.ok_or("missing --agent-id")?,
            to: to.ok_or("missing --to")?,
            key_file: key_file.ok_or("missing --key-file")?,
        })
    }
}
