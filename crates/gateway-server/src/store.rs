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

/// The on-disk log is append-only, so evicted envelopes stay in it until it is
/// compacted. Once a recipient's log reaches this many lines it is rewritten
/// from the in-memory queue, so a recipient that never reconnects cannot grow
/// its file without bound (at most `2 × MAX_PER_RECIPIENT` lines on disk).
const MAX_LOG_LINES: usize = 2 * MAX_PER_RECIPIENT;

/// One offline recipient's parked mail plus how many lines its log holds.
#[derive(Default)]
struct Queue {
    items: Vec<Envelope>,
    disk_lines: usize,
}

/// Store-and-forward queue, optionally file-backed for durability.
///
/// Disk writes happen under the queue lock on purpose: memory and log must not
/// diverge (a `park` racing a `drain` could otherwise re-create a log of mail
/// that was already delivered, and replay it after a restart).
pub struct Store {
    queues: Mutex<HashMap<String, Queue>>,
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
        if q.items.len() >= MAX_PER_RECIPIENT {
            q.items.remove(0); // evict oldest
        }
        q.items.push(env.clone());
        if let Some(dir) = &self.dir {
            // Best-effort durability; a write failure degrades to in-memory for
            // this item rather than dropping the live relay.
            let written = if q.disk_lines >= MAX_LOG_LINES {
                Self::rewrite_log(dir, &env.recipient, &q.items)
                    .await
                    .map(|()| q.disk_lines = q.items.len())
            } else {
                Self::append_line(dir, &env)
                    .await
                    .map(|()| q.disk_lines += 1)
            };
            if let Err(e) = written {
                tracing::warn!(error = %e, recipient = %env.recipient, "store write failed");
            }
        }
    }

    /// Take and clear everything parked for `recipient` (called on connect).
    /// Also removes the durable log so a redelivered envelope is not replayed
    /// after a later restart.
    pub async fn drain(&self, recipient: &str) -> Vec<Envelope> {
        let taken = {
            let mut queues = self.queues.lock().await;
            queues.remove(recipient).unwrap_or_default().items
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
            .map(|q| q.items.len())
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

    /// Replace a recipient's log with exactly `items` (compaction). Written to a
    /// sibling temp file and renamed over the log, so a crash mid-write leaves
    /// the old log intact rather than a truncated one. The temp name does not
    /// end in `.jsonl`, so `replay` never reads it.
    async fn rewrite_log(dir: &Path, recipient: &str, items: &[Envelope]) -> std::io::Result<()> {
        let mut buf = String::new();
        for env in items {
            buf.push_str(&serde_json::to_string(env)?);
            buf.push('\n');
        }
        let path = Self::log_path(dir, recipient);
        let tmp = path.with_extension("jsonl.tmp");
        tokio::fs::write(&tmp, buf).await?;
        tokio::fs::rename(&tmp, &path).await
    }

    async fn replay(dir: &Path) -> std::io::Result<HashMap<String, Queue>> {
        let mut queues: HashMap<String, Queue> = HashMap::new();
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
                        // Keep the most recent `MAX_PER_RECIPIENT`, the same
                        // drop-oldest policy `park` applies at runtime.
                        let q = queues.entry(env.recipient.clone()).or_default();
                        q.disk_lines += 1;
                        if q.items.len() >= MAX_PER_RECIPIENT {
                            q.items.remove(0);
                        }
                        q.items.push(env);
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

    /// A recipient that stays offline past the cap: replay must keep the newest
    /// envelopes (as `park` does), and the log must be compacted rather than
    /// growing with every evicted envelope.
    #[tokio::test]
    async fn file_backing_keeps_newest_and_bounds_the_log() {
        let dir = std::env::temp_dir().join(format!("bwoc-gw-cap-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        let total = 3 * MAX_PER_RECIPIENT as u64;
        {
            let s = Store::file_backed(&dir).await.unwrap();
            for i in 0..total {
                s.park(env("agent-b", i)).await;
            }
        }
        let log = tokio::fs::read_to_string(Store::log_path(&dir, "agent-b"))
            .await
            .unwrap();
        assert!(
            log.lines().count() <= MAX_LOG_LINES,
            "log grew to {} lines",
            log.lines().count()
        );
        let s2 = Store::file_backed(&dir).await.unwrap();
        let drained = s2.drain("agent-b").await;
        assert_eq!(drained.len(), MAX_PER_RECIPIENT);
        assert_eq!(
            drained[0].body,
            json!({ "seq": total - MAX_PER_RECIPIENT as u64 })
        );
        assert_eq!(drained.last().unwrap().body, json!({ "seq": total - 1 }));
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
