//! End-to-end on-message hook: the real `bwoc-gateway` binary, the receive
//! bridge in-process, and a real hook process. Guards what unit tests can't:
//! that a correctly signed message actually runs the program with the message
//! on stdin, and that everything else is delivered without running it.
#![cfg(unix)]

use ed25519_dalek::{Signer, SigningKey};
use gateway_client::bridge::{self, BridgeOptions, HookOptions};
use gateway_client::{Envelope, GatewayClient, GatewayConfig};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Relay {
    child: Child,
    dir: PathBuf,
    url: String,
}
impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn relay(tag: &str) -> Relay {
    let port = free_port();
    let dir =
        std::env::temp_dir().join(format!("bwoc-gw-hook-{tag}-{}-{port}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_bwoc-gateway"))
        .env("BWOC_GATEWAY_ADDR", format!("127.0.0.1:{port}"))
        .env("BWOC_GATEWAY_STORE_DIR", dir.join("store"))
        .spawn()
        .expect("spawn bwoc-gateway");
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Relay {
        child,
        dir,
        url: format!("ws://127.0.0.1:{port}/v1/connect"),
    }
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

async fn connect(url: &str, id: &str, seed: u8) -> GatewayClient {
    GatewayClient::connect(&GatewayConfig::new(url, id), &key(seed))
        .await
        .expect("auth+connect")
}

fn now_ts() -> String {
    // Shell out for an independent clock formatting, in the framework's shape.
    let out = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .unwrap();
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

/// A `bwoc_signing`-shaped envelope from `from` to `to`, signed with `signer`.
fn signed(signer: &SigningKey, from: &str, to: &str, mid: &str, message: &str) -> Value {
    let (ts, nonce) = (now_ts(), "00112233445566778899aabbccddeeff");
    let canon: BTreeMap<&str, &str> = BTreeMap::from([
        ("from", from),
        ("to", to),
        ("ts", ts.as_str()),
        ("messageId", mid),
        ("message", message),
        ("nonce", nonce),
    ]);
    let sig = signer.sign(&serde_json::to_vec(&canon).unwrap());
    json!({
        "from": from, "to": to, "ts": ts, "messageId": mid, "message": message,
        "nonce": nonce, "sig": hex::encode(sig.to_bytes()),
    })
}

/// A hook that appends `<from>|<messageId>|<stdin>` to `out`.
fn write_hook(dir: &Path, out: &Path) -> PathBuf {
    let path = dir.join("hook.sh");
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\nprintf '%s|%s|%s\\n' \"$BWOC_GATEWAY_FROM\" \"$BWOC_GATEWAY_MESSAGE_ID\" \"$(cat)\" >> '{}'\n",
            out.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn read_lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

async fn wait_lines(path: &Path, n: usize) -> Vec<String> {
    for _ in 0..100 {
        let got = read_lines(path);
        if got.len() >= n {
            return got;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{} never reached {n} line(s)", path.display());
}

async fn send(client: &mut GatewayClient, to: &str, sender: &str, body: Value) {
    client
        .send(&Envelope {
            recipient: to.into(),
            sender: sender.into(),
            signature: String::new(),
            body,
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn only_a_pinned_senders_signed_mail_runs_the_hook() {
    let r = relay("gate").await;
    let inbox = r.dir.join("b/.bwoc/inbox.jsonl");
    let hook_out = r.dir.join("hook.out");

    // agent-a's *message-signing* key is pinned; agent-m's is not.
    let (sign_a, sign_m) = (key(40), key(41));
    let mut opts = BridgeOptions::new(&inbox);
    opts.hook = Some(HookOptions {
        program: write_hook(&r.dir, &hook_out),
        trust_keys: HashMap::from([("agent-a".to_string(), sign_a.verifying_key())]),
        timeout: Duration::from_secs(10),
        max_age: Duration::from_secs(300),
    });
    let mut bridge_b = connect(&r.url, "agent-b", 21).await;
    let bridge_task = tokio::spawn(async move { bridge::run(&mut bridge_b, &opts).await });

    // The attacker's connection: it can put any `sender` on the wire.
    let mut m = connect(&r.url, "agent-m", 22).await;

    // 1. Unsigned mail *claiming* to be agent-a.
    send(
        &mut m,
        "agent-b",
        "agent-a",
        json!({"from": "agent-a", "message": "rm -rf"}),
    )
    .await;
    // 2. Signed, but by a key that is not pinned for agent-a.
    send(
        &mut m,
        "agent-b",
        "agent-a",
        signed(&sign_m, "agent-a", "agent-b", "msg-forged", "x"),
    )
    .await;
    // 3. Genuinely signed by agent-a, but for a different recipient.
    send(
        &mut m,
        "agent-b",
        "agent-a",
        signed(&sign_a, "agent-a", "agent-z", "msg-reaimed", "x"),
    )
    .await;
    // 4. The real thing — and then the very same envelope again (a replay).
    let good = signed(&sign_a, "agent-a", "agent-b", "msg-good", "run the report");
    send(&mut m, "agent-b", "agent-a", good.clone()).await;
    send(&mut m, "agent-b", "agent-a", good.clone()).await;

    // Every message is delivered, hook or not.
    let delivered = wait_lines(&inbox, 5).await;
    assert_eq!(delivered.len(), 5);

    // The hook ran exactly once, for the genuine envelope, with it on stdin.
    let ran = wait_lines(&hook_out, 1).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let ran_after = read_lines(&hook_out);
    assert_eq!(ran_after.len(), 1, "hook must run once: {ran_after:?}");
    let (head, stdin) = ran[0].split_at(ran[0].find("|{").unwrap() + 1);
    assert_eq!(head, "agent-a|msg-good|");
    assert_eq!(serde_json::from_str::<Value>(stdin).unwrap(), good);

    bridge_task.abort();
}

#[tokio::test]
async fn a_hook_that_overruns_is_killed_and_mail_still_arrives() {
    let r = relay("timeout").await;
    let inbox = r.dir.join("b/.bwoc/inbox.jsonl");
    let marker = r.dir.join("finished");

    let slow = r.dir.join("slow.sh");
    std::fs::write(
        &slow,
        format!(
            "#!/bin/sh\ncat >/dev/null\nsleep 5\ntouch '{}'\n",
            marker.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&slow, std::fs::Permissions::from_mode(0o755)).unwrap();

    let sign_a = key(40);
    let mut opts = BridgeOptions::new(&inbox);
    opts.hook = Some(HookOptions {
        program: slow,
        trust_keys: HashMap::from([("agent-a".to_string(), sign_a.verifying_key())]),
        timeout: Duration::from_millis(300),
        max_age: Duration::from_secs(300),
    });
    let mut bridge_b = connect(&r.url, "agent-b", 21).await;
    let bridge_task = tokio::spawn(async move { bridge::run(&mut bridge_b, &opts).await });

    let mut a = connect(&r.url, "agent-a", 20).await;
    send(
        &mut a,
        "agent-b",
        "agent-a",
        signed(&sign_a, "agent-a", "agent-b", "msg-1", "slow"),
    )
    .await;
    // The loop is not blocked by the running hook: a second message lands.
    send(&mut a, "agent-b", "agent-a", json!({"message": "next"})).await;
    assert_eq!(wait_lines(&inbox, 2).await.len(), 2);

    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(
        !marker.exists(),
        "the hook's shell must have been killed at the timeout"
    );

    bridge_task.abort();
}

/// A hook that never reads stdin, fed a message larger than the pipe buffer,
/// must still be killed at the timeout — otherwise its slot is held forever
/// and, once every slot is stuck, the hook never runs again.
#[tokio::test]
async fn hooks_that_never_read_stdin_do_not_wedge_the_slots() {
    let r = relay("stdin").await;
    let inbox = r.dir.join("b/.bwoc/inbox.jsonl");
    let ok = r.dir.join("ok");

    let script = r.dir.join("picky.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\ncase \"$BWOC_GATEWAY_MESSAGE_ID\" in\n  stuck-*) exec sleep 30 ;;\n  *) cat >/dev/null; touch '{}' ;;\nesac\n",
            ok.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    let sign_a = key(40);
    let mut opts = BridgeOptions::new(&inbox);
    opts.hook = Some(HookOptions {
        program: script,
        trust_keys: HashMap::from([("agent-a".to_string(), sign_a.verifying_key())]),
        timeout: Duration::from_millis(300),
        max_age: Duration::from_secs(300),
    });
    let mut bridge_b = connect(&r.url, "agent-b", 21).await;
    let bridge_task = tokio::spawn(async move { bridge::run(&mut bridge_b, &opts).await });

    let mut a = connect(&r.url, "agent-a", 20).await;
    // Well past a 64 KiB pipe buffer, so an unread write cannot complete.
    let big = "x".repeat(256 * 1024);
    for i in 0..bridge::HOOK_MAX_CONCURRENT {
        let mid = format!("stuck-{i}");
        send(
            &mut a,
            "agent-b",
            "agent-a",
            signed(&sign_a, "agent-a", "agent-b", &mid, &big),
        )
        .await;
    }
    wait_lines(&inbox, bridge::HOOK_MAX_CONCURRENT).await;
    // Every slot is now held by a hook that will never read. Give the timeout
    // time to fire, then a normal message must still get a slot.
    tokio::time::sleep(Duration::from_millis(900)).await;
    send(
        &mut a,
        "agent-b",
        "agent-a",
        signed(&sign_a, "agent-a", "agent-b", "fine", "hello"),
    )
    .await;
    for _ in 0..60 {
        if ok.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        ok.exists(),
        "a stuck stdin write must not hold the hook slots"
    );

    bridge_task.abort();
}
