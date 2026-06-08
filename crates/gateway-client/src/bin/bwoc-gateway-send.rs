//! `bwoc-gateway-send` — one-shot relay of a single signed envelope.
//!
//! This is the **transport artifact the BWOC harness shells out to** for a
//! `RouteTarget::Gateway` route, mirroring `bwoc-mqtt publish`. The harness
//! already builds and signs the envelope (the canonical `(sender, recipient,
//! body)` signature its peer will verify); this binary is a dumb pipe: read the
//! complete envelope JSON from **stdin**, open an authenticated WebSocket to the
//! gateway with the sender's key, send it, exit.
//!
//! Usage:
//!   bwoc-gateway-send --url <wss://gw/v1/connect> --agent-id <self> --key-file <hex-seed>
//!   echo '<envelope json>' | bwoc-gateway-send ...
//!
//! The key file holds the sender's hex-encoded 32-byte ed25519 seed — used only
//! for the gateway login handshake (the keypair IS the login). Reading the
//! envelope from stdin avoids `ARG_MAX` (E2BIG) on long messages.

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
    let mut envelope_json = String::new();
    std::io::stdin()
        .read_to_string(&mut envelope_json)
        .map_err(|e| format!("read stdin: {e}"))?;
    let envelope: Envelope =
        serde_json::from_str(&envelope_json).map_err(|e| format!("parse envelope: {e}"))?;

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
    key_file: String,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let (mut url, mut agent_id, mut key_file) = (None, None, None);
        let mut it = std::env::args().skip(1);
        while let Some(flag) = it.next() {
            let mut value = || it.next().ok_or_else(|| format!("missing value for {flag}"));
            match flag.as_str() {
                "--url" => url = Some(value()?),
                "--agent-id" => agent_id = Some(value()?),
                "--key-file" => key_file = Some(value()?),
                other => return Err(format!("unknown argument: {other}")),
            }
        }
        Ok(Self {
            url: url.ok_or("missing --url")?,
            agent_id: agent_id.ok_or("missing --agent-id")?,
            key_file: key_file.ok_or("missing --key-file")?,
        })
    }
}
