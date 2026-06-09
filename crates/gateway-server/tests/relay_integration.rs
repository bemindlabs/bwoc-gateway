//! End-to-end integration: spawn the real `bwoc-gateway` binary and drive it
//! with `gateway-client` through the full path — signed-challenge auth →
//! online relay-by-recipient → end-to-end body encryption → durable
//! store-and-forward. This is the regression guard for the live behaviour the
//! smoke test exercised by hand.

use ed25519_dalek::SigningKey;
use gateway_client::{crypto, Envelope, GatewayClient, GatewayConfig};
use std::process::{Child, Command};
use std::time::Duration;

/// Bind an ephemeral port, then release it so the server can claim it. A small
/// race is acceptable for a single local test process.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Owns the spawned server; kills it on drop so a failed assertion never leaks
/// a process.
struct Server {
    child: Child,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn wait_ready(port: u16) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("gateway did not become ready on port {port}");
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn pubhex(k: &SigningKey) -> String {
    hex::encode(k.verifying_key().to_bytes())
}

async fn recv(client: &mut GatewayClient) -> Envelope {
    tokio::time::timeout(Duration::from_secs(5), client.next_envelope())
        .await
        .expect("recv timed out")
        .expect("recv error")
        .expect("stream closed")
}

#[tokio::test]
async fn relay_crypto_and_store_and_forward() {
    let port = free_port();
    let store = std::env::temp_dir().join(format!("bwoc-gw-it-{}-{port}", std::process::id()));
    let _ = std::fs::remove_dir_all(&store);

    let child = Command::new(env!("CARGO_BIN_EXE_bwoc-gateway"))
        .env("BWOC_GATEWAY_ADDR", format!("127.0.0.1:{port}"))
        .env("BWOC_GATEWAY_STORE_DIR", &store)
        .spawn()
        .expect("spawn bwoc-gateway");
    let _server = Server { child };
    wait_ready(port).await;
    let url = format!("ws://127.0.0.1:{port}/v1/connect");

    let (a, b, c) = (key(10), key(11), key(12));

    // ── online relay + e2e crypto ──────────────────────────────────────────
    let mut recv_b = GatewayClient::connect(&GatewayConfig::new(&url, "agent-b"), &b)
        .await
        .expect("agent-b auth+connect");
    let mut send_a = GatewayClient::connect(&GatewayConfig::new(&url, "agent-a"), &a)
        .await
        .expect("agent-a auth+connect");

    let plaintext = b"relay must not read this";
    let sealed = crypto::seal_to_hex(&pubhex(&b), plaintext).unwrap();
    send_a
        .send(&Envelope {
            recipient: "agent-b".into(),
            sender: "agent-a".into(),
            signature: String::new(),
            body: serde_json::json!({ "enc": sealed }),
        })
        .await
        .unwrap();

    let got = recv(&mut recv_b).await;
    assert_eq!(got.sender, "agent-a");
    let opened = crypto::open_from_hex(&b, got.body["enc"].as_str().unwrap()).unwrap();
    assert_eq!(opened, plaintext, "agent-b must decrypt to the original");

    // ── durable store-and-forward (recipient offline at send time) ─────────
    let sealed_c = crypto::seal_to_hex(&pubhex(&c), b"parked while offline").unwrap();
    send_a
        .send(&Envelope {
            recipient: "agent-c".into(),
            sender: "agent-a".into(),
            signature: String::new(),
            body: serde_json::json!({ "enc": sealed_c }),
        })
        .await
        .unwrap();
    // give the server a moment to park it
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut recv_c = GatewayClient::connect(&GatewayConfig::new(&url, "agent-c"), &c)
        .await
        .expect("agent-c auth+connect");
    let parked = recv(&mut recv_c).await;
    let opened_c = crypto::open_from_hex(&c, parked.body["enc"].as_str().unwrap()).unwrap();
    assert_eq!(
        opened_c, b"parked while offline",
        "agent-c must drain its parked mail"
    );

    let _ = std::fs::remove_dir_all(&store);
}
