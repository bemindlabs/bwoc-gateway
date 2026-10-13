//! End-to-end auto-pong: the real `bwoc-gateway` binary, with the receive
//! bridge (`gateway_client::bridge`) running in-process on one side and a plain
//! client on the other. Guards the two things a unit test can't: that a pong
//! really crosses the relay back to the pinger, and that ping/pong stay out of
//! the inbox while ordinary mail still lands there.

use ed25519_dalek::SigningKey;
use gateway_client::bridge::{self, BridgeOptions};
use gateway_client::{Envelope, GatewayClient, GatewayConfig};
use serde_json::{json, Value};
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

/// Owns the relay process and the scratch dir; cleans both up on drop.
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
        std::env::temp_dir().join(format!("bwoc-gw-pong-{tag}-{}-{port}", std::process::id()));
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

fn envelope(to: &str, from: &str, body: Value) -> Envelope {
    Envelope {
        recipient: to.into(),
        sender: from.into(),
        signature: String::new(),
        body,
    }
}

async fn next(client: &mut GatewayClient) -> Envelope {
    tokio::time::timeout(Duration::from_secs(5), client.next_envelope())
        .await
        .expect("recv timed out")
        .expect("recv error")
        .expect("stream closed")
}

fn lines(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).expect("jsonl line"))
        .collect()
}

/// Poll until `path` holds `n` lines (the bridge writes asynchronously).
async fn wait_lines(path: &Path, n: usize) -> Vec<Value> {
    for _ in 0..100 {
        let got = lines(path);
        if got.len() >= n {
            return got;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{} never reached {n} line(s)", path.display());
}

#[tokio::test]
async fn a_ping_is_ponged_and_kept_out_of_the_inbox() {
    let r = relay("on").await;
    let inbox = r.dir.join("b/.bwoc/inbox.jsonl");

    let mut opts = BridgeOptions::new(&inbox);
    opts.auto_pong = true;
    let mut bridge_b = connect(&r.url, "agent-b", 21).await;
    let bridge_task = tokio::spawn(async move { bridge::run(&mut bridge_b, &opts).await });

    let mut a = connect(&r.url, "agent-a", 20).await;
    a.send(&envelope(
        "agent-b",
        "agent-a",
        json!({"type": "ping", "id": "p1"}),
    ))
    .await
    .unwrap();

    let pong = next(&mut a).await;
    assert_eq!(pong.sender, "agent-b");
    assert_eq!(pong.body["type"], "pong");
    assert_eq!(pong.body["from"], "agent-b");
    assert_eq!(pong.body["to"], "agent-a");
    assert_eq!(pong.body["id"], "p1");

    // Ordinary mail still reaches the inbox — and it is the only line there:
    // the ping that came first was never written.
    a.send(&envelope("agent-b", "agent-a", json!({"message": "hello"})))
        .await
        .unwrap();
    let got = wait_lines(&inbox, 1).await;
    assert_eq!(got.len(), 1, "the ping must not be in the inbox: {got:?}");
    assert_eq!(got[0]["message"], "hello");
    assert_eq!(got[0]["from"], "agent-a");

    bridge_task.abort();
}

#[tokio::test]
async fn a_second_ping_inside_the_window_gets_no_pong() {
    let r = relay("limit").await;
    let mut opts = BridgeOptions::new(r.dir.join("b/.bwoc/inbox.jsonl"));
    opts.auto_pong = true;
    let mut bridge_b = connect(&r.url, "agent-b", 21).await;
    let bridge_task = tokio::spawn(async move { bridge::run(&mut bridge_b, &opts).await });

    let mut a = connect(&r.url, "agent-a", 20).await;
    for id in ["first", "second"] {
        a.send(&envelope(
            "agent-b",
            "agent-a",
            json!({"type": "ping", "id": id}),
        ))
        .await
        .unwrap();
    }
    assert_eq!(next(&mut a).await.body["id"], "first");
    // The second ping arrived well inside the 1 s window: nothing more comes.
    let more = tokio::time::timeout(Duration::from_millis(400), a.next_envelope()).await;
    assert!(more.is_err(), "a rate-limited ping must not be answered");

    bridge_task.abort();
}

#[tokio::test]
async fn a_received_pong_goes_to_the_pong_log_and_is_never_answered() {
    let r = relay("log").await;
    let inbox = r.dir.join("b/.bwoc/inbox.jsonl");
    let mut opts = BridgeOptions::new(&inbox);
    opts.auto_pong = true;
    let pong_log = opts.pong_log.clone();
    let mut bridge_b = connect(&r.url, "agent-b", 21).await;
    let bridge_task = tokio::spawn(async move { bridge::run(&mut bridge_b, &opts).await });

    let mut a = connect(&r.url, "agent-a", 20).await;
    a.send(&envelope(
        "agent-b",
        "agent-a",
        json!({"type": "pong", "id": "p9"}),
    ))
    .await
    .unwrap();

    let logged = wait_lines(&pong_log, 1).await;
    assert_eq!(logged[0]["type"], "pong");
    assert_eq!(logged[0]["id"], "p9");
    assert_eq!(logged[0]["from"], "agent-a");
    assert!(lines(&inbox).is_empty(), "a pong must not reach the inbox");
    // No reply to a pong — otherwise two bridges would loop forever.
    let reply = tokio::time::timeout(Duration::from_millis(400), a.next_envelope()).await;
    assert!(reply.is_err(), "a pong must never be answered");

    bridge_task.abort();
}

#[tokio::test]
async fn without_auto_pong_a_ping_is_ordinary_mail() {
    let r = relay("off").await;
    let inbox = r.dir.join("b/.bwoc/inbox.jsonl");
    let opts = BridgeOptions::new(&inbox);
    let mut bridge_b = connect(&r.url, "agent-b", 21).await;
    let bridge_task = tokio::spawn(async move { bridge::run(&mut bridge_b, &opts).await });

    let mut a = connect(&r.url, "agent-a", 20).await;
    a.send(&envelope("agent-b", "agent-a", json!({"type": "ping"})))
        .await
        .unwrap();

    let got = wait_lines(&inbox, 1).await;
    assert_eq!(got[0]["type"], "ping");
    let reply = tokio::time::timeout(Duration::from_millis(400), a.next_envelope()).await;
    assert!(reply.is_err(), "auto-pong is opt-in");

    bridge_task.abort();
}
