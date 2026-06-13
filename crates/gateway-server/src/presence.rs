//! Presence registry: `agent_id -> live inbound queue`. This is soft, ephemeral
//! routing state — NOT a registry of identity (that stays with the keypairs) and
//! NOT durable (store-and-forward for offline agents lives in `store`).
//!
//! Each registration carries a monotonic **token** so that a *stale* connection
//! tearing down cannot evict a *newer* connection that already took over the
//! same `agent_id` slot. Without this, the sequence
//!   recv#1 registers → recv#2 reconnects and replaces the slot (last-writer-
//!   wins) → recv#1's queue drops, its task ends and calls `unregister(agent_id)`
//! would remove **recv#2's** slot — leaving the agent with no presence at all
//! and silently parking everything addressed to it. Token-scoped `unregister`
//! closes that race (a frequent trigger of the "I can send but never receive"
//! asymmetry behind a flaky/half-open proxy).

use crate::wire::Envelope;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{mpsc, Mutex};

#[derive(Default)]
pub struct Presence {
    /// One sender per connected agent, tagged with the registration token that
    /// owns the slot. `route` pushes an envelope onto the recipient's queue,
    /// which their connection task drains to the socket.
    connections: Mutex<HashMap<String, (u64, mpsc::Sender<Envelope>)>>,
    /// Hands out a unique token per `register` so `unregister` can verify it is
    /// clearing its own slot and not a successor's.
    next_token: AtomicU64,
}

impl Presence {
    /// Register a freshly-authenticated agent and return the **token** that
    /// identifies this registration (pass it back to [`unregister`]). A reconnect
    /// replaces the prior sender (last-writer-wins; the old connection's queue is
    /// dropped) and is logged so a collision is visible in the relay log.
    ///
    /// [`unregister`]: Presence::unregister
    pub async fn register(&self, agent_id: String, tx: mpsc::Sender<Envelope>) -> u64 {
        let token = self.next_token.fetch_add(1, Ordering::Relaxed);
        let prev = self
            .connections
            .lock()
            .await
            .insert(agent_id.clone(), (token, tx));
        if prev.is_some() {
            tracing::warn!(
                %agent_id,
                "presence: a new connection replaced a prior one for this agent \
                 (reconnect or collision)"
            );
        }
        token
    }

    /// Clear this agent's slot **only if it still holds `token`**. A stale
    /// connection (already superseded by a reconnect) tearing down is a no-op,
    /// so it cannot evict the live successor.
    pub async fn unregister(&self, agent_id: &str, token: u64) {
        let mut map = self.connections.lock().await;
        match map.get(agent_id) {
            Some((cur, _)) if *cur == token => {
                map.remove(agent_id);
            }
            Some(_) => {
                tracing::debug!(
                    %agent_id,
                    "presence: stale unregister ignored (slot owned by a newer connection)"
                );
            }
            None => {}
        }
    }

    /// Route an envelope to its recipient if online. Returns `false` when the
    /// recipient is not connected (caller decides to federate / store-and-forward).
    pub async fn route(&self, env: &Envelope) -> bool {
        let tx = {
            let map = self.connections.lock().await;
            map.get(&env.recipient).map(|(_, tx)| tx.clone())
        };
        match tx {
            Some(tx) => tx.send(env.clone()).await.is_ok(),
            None => false,
        }
    }

    #[cfg(test)]
    pub async fn online_count(&self) -> usize {
        self.connections.lock().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn env(to: &str) -> Envelope {
        Envelope {
            recipient: to.into(),
            sender: "agent-a".into(),
            signature: "00".into(),
            body: json!({"hello": "world"}),
        }
    }

    #[tokio::test]
    async fn routes_to_online_recipient() {
        let p = Presence::default();
        let (tx, mut rx) = mpsc::channel(4);
        p.register("agent-b".into(), tx).await;
        assert!(p.route(&env("agent-b")).await);
        assert!(rx.recv().await.is_some());
    }

    #[tokio::test]
    async fn offline_recipient_returns_false() {
        let p = Presence::default();
        assert!(!p.route(&env("nobody")).await);
        assert_eq!(p.online_count().await, 0);
    }

    /// A stale connection's `unregister` must NOT evict the live successor that
    /// already replaced its slot — this is the reconnect/collision race that
    /// otherwise leaves an agent silently unrouteable.
    #[tokio::test]
    async fn stale_unregister_does_not_evict_successor() {
        let p = Presence::default();
        let (tx1, _rx1) = mpsc::channel(4);
        let (tx2, mut rx2) = mpsc::channel(4);

        let t1 = p.register("agent-b".into(), tx1).await; // conn #1
        let t2 = p.register("agent-b".into(), tx2).await; // conn #2 takes the slot
        assert_ne!(t1, t2, "tokens must be unique");

        // Conn #1 tears down late and unregisters with ITS (stale) token.
        p.unregister("agent-b", t1).await;

        // The successor (#2) must still own the slot and receive routed mail.
        assert_eq!(p.online_count().await, 1);
        assert!(p.route(&env("agent-b")).await);
        assert!(rx2.recv().await.is_some());

        // The owner's own unregister clears it.
        p.unregister("agent-b", t2).await;
        assert_eq!(p.online_count().await, 0);
    }

    #[tokio::test]
    async fn owner_unregister_clears_slot() {
        let p = Presence::default();
        let (tx, _rx) = mpsc::channel(4);
        let t = p.register("agent-c".into(), tx).await;
        assert_eq!(p.online_count().await, 1);
        p.unregister("agent-c", t).await;
        assert_eq!(p.online_count().await, 0);
    }
}
