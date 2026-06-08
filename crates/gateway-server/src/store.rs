//! Durable store-and-forward for offline recipients.
//!
//! When `presence.route()` finds the recipient offline, the envelope is parked
//! here instead of dropped; the queue is drained to the recipient the moment
//! they (re)connect. The store stays true to the *dumb, untrusted relay*
//! principle — it holds opaque, end-to-end-signed envelopes it cannot read or
//! forge, keyed only by the cleartext `recipient`.
//!
//! Two backings share one type:
//!   - **memory** (default): ephemeral; queues live only for the process.
//!   - **file** (`BWOC_GATEWAY_STORE_DIR`): durable across restarts; each
//!     recipient is a `<hex(recipient)>.jsonl` append-log, replayed on boot.
//!
//! *Saṃvara* (restraint) at the edge: per-recipient queues are bounded
//! (`MAX_PER_RECIPIENT`) so an attacker cannot turn the relay into an unbounded
//! spool. The recipient id is **hex-encoded** into the filename, so an
//! attacker-chosen `recipient` can never escape the store dir (no path
//! traversal).

use crate::wire::Envelope;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::sync::Mutex;

/// Hard cap on parked envelopes per offline recipient. Beyond this the oldest
/// is evicted (the sender's transport is expected to retry / the loss is
/// surfaced upstream — the relay refuses to be an unbounded spool).
const MAX_PER_RECIPIENT: usize = 1024;

/// Store-and-forward queue, optionally file-backed for durability.
pub struct Store {
    queues: Mutex<HashMap<String, Vec<Envelope>>>,
    dir: Option<PathBuf>,
}

impl Store {
    /// In-memory only (ephemeral). Used by default and in tests.
    pub fn in_memory() -> Self {
        Self {
            queues: Mutex::new(HashMap::new()),
            dir: None,
        }
    }

    /// File-backed store rooted at `dir`. Creates the dir if absent and replays
    /// any existing per-recipient logs into memory.
    pub async fn file_backed(dir: impl Into<PathBuf>) -> std::io::Result<Self> {
        let dir = dir.into();
        tokio::fs::create_dir_all(&dir).await?;
        let queues = Self::replay(&dir).await?;
        Ok(Self {
            queues: Mutex::new(queues),
            dir: Some(dir),
        })
    }

    /// Construct from the environment: `BWOC_GATEWAY_STORE_DIR` → file-backed,
    /// otherwise in-memory.
    pub async fn from_env() -> Self {
        match std::env::var("BWOC_GATEWAY_STORE_DIR") {
            Ok(dir) if !dir.is_empty() => match Self::file_backed(&dir).await {
                Ok(s) => {
                    tracing::info!(dir = %dir, "store-and-forward: file-backed");
                    s
                }
                Err(e) => {
                    tracing::warn!(error = %e, dir = %dir, "store dir unusable; falling back to memory");
                    Self::in_memory()
                }
            },
            _ => {
                tracing::info!(
                    "store-and-forward: in-memory (set BWOC_GATEWAY_STORE_DIR to persist)"
                );
                Self::in_memory()
            }
        }
    }

    /// Park an envelope for an offline recipient.
    pub async fn park(&self, env: Envelope) {
        let mut queues = self.queues.lock().await;
        let q = queues.entry(env.recipient.clone()).or_default();
        if q.len() >= MAX_PER_RECIPIENT {
            q.remove(0); // evict oldest
        }
        q.push(env.clone());
        if let Some(dir) = &self.dir {
            // Best-effort durability; a write failure degrades to in-memory for
            // this item rather than dropping the live relay.
            if let Err(e) = Self::append_line(dir, &env).await {
                tracing::warn!(error = %e, recipient = %env.recipient, "store append failed");
            }
        }
    }

    /// Take and clear everything parked for `recipient` (called on connect).
    /// Also removes the durable log so a redelivered envelope is not replayed
    /// after a later restart.
    pub async fn drain(&self, recipient: &str) -> Vec<Envelope> {
        let taken = {
            let mut queues = self.queues.lock().await;
            queues.remove(recipient).unwrap_or_default()
        };
        if let Some(dir) = &self.dir {
            let _ = tokio::fs::remove_file(Self::log_path(dir, recipient)).await;
        }
        taken
    }

    #[cfg(test)]
    pub async fn parked_count(&self, recipient: &str) -> usize {
        self.queues
            .lock()
            .await
            .get(recipient)
            .map(|q| q.len())
            .unwrap_or(0)
    }

    // ---- file backing helpers -------------------------------------------

    /// Per-recipient log path. The recipient id is hex-encoded, so the filename
    /// is always `[0-9a-f]+.jsonl` — no separators, no traversal.
    fn log_path(dir: &Path, recipient: &str) -> PathBuf {
        dir.join(format!("{}.jsonl", hex::encode(recipient.as_bytes())))
    }

    async fn append_line(dir: &Path, env: &Envelope) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        let line = format!("{}\n", serde_json::to_string(env)?);
        let mut f = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(Self::log_path(dir, &env.recipient))
            .await?;
        f.write_all(line.as_bytes()).await
    }

    async fn replay(dir: &Path) -> std::io::Result<HashMap<String, Vec<Envelope>>> {
        let mut queues: HashMap<String, Vec<Envelope>> = HashMap::new();
        let mut entries = tokio::fs::read_dir(dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }
            let content = tokio::fs::read_to_string(&path).await?;
            for line in content.lines().filter(|l| !l.trim().is_empty()) {
                match serde_json::from_str::<Envelope>(line) {
                    Ok(env) => {
                        let q = queues.entry(env.recipient.clone()).or_default();
                        if q.len() < MAX_PER_RECIPIENT {
                            q.push(env);
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, ?path, "skipping corrupt store line"),
                }
            }
        }
        Ok(queues)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn env(to: &str, n: u64) -> Envelope {
        Envelope {
            recipient: to.into(),
            sender: "agent-a".into(),
            signature: "00".into(),
            body: json!({ "seq": n }),
        }
    }

    #[tokio::test]
    async fn park_then_drain_returns_fifo() {
        let s = Store::in_memory();
        s.park(env("agent-b", 1)).await;
        s.park(env("agent-b", 2)).await;
        let drained = s.drain("agent-b").await;
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].body, json!({"seq": 1}));
        assert_eq!(s.parked_count("agent-b").await, 0); // cleared
    }

    #[tokio::test]
    async fn drain_unknown_recipient_is_empty() {
        let s = Store::in_memory();
        assert!(s.drain("nobody").await.is_empty());
    }

    #[tokio::test]
    async fn queue_is_bounded() {
        let s = Store::in_memory();
        for i in 0..(MAX_PER_RECIPIENT as u64 + 10) {
            s.park(env("agent-b", i)).await;
        }
        assert_eq!(s.parked_count("agent-b").await, MAX_PER_RECIPIENT);
        // oldest evicted: first surviving seq is 10
        let drained = s.drain("agent-b").await;
        assert_eq!(drained[0].body, json!({"seq": 10}));
    }

    #[tokio::test]
    async fn file_backing_survives_reopen() {
        let dir = std::env::temp_dir().join(format!("bwoc-gw-store-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        {
            let s = Store::file_backed(&dir).await.unwrap();
            s.park(env("agent-b", 1)).await;
            s.park(env("agent-b", 2)).await;
        }
        // reopen: parked envelopes replay from disk
        let s2 = Store::file_backed(&dir).await.unwrap();
        let drained = s2.drain("agent-b").await;
        assert_eq!(drained.len(), 2);
        // drain removed the log → a third open sees nothing
        let s3 = Store::file_backed(&dir).await.unwrap();
        assert!(s3.drain("agent-b").await.is_empty());
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn recipient_id_cannot_escape_store_dir() {
        let dir = std::env::temp_dir().join(format!("bwoc-gw-traversal-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        let s = Store::file_backed(&dir).await.unwrap();
        s.park(env("../../etc/evil", 1)).await;
        // the only file created is inside dir, hex-named — no traversal
        let mut names = vec![];
        let mut rd = tokio::fs::read_dir(&dir).await.unwrap();
        while let Some(e) = rd.next_entry().await.unwrap() {
            names.push(e.file_name().to_string_lossy().to_string());
        }
        assert_eq!(names.len(), 1);
        let stem = names[0].strip_suffix(".jsonl").expect("hex stem + .jsonl");
        // The whole id is hex-encoded, so no `/`, `.`, or `..` survives into the
        // filename — the malicious recipient cannot escape the store dir.
        assert!(!stem.is_empty() && stem.chars().all(|c| c.is_ascii_hexdigit()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
