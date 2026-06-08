//! Presence registry: `agent_id -> live inbound queue`. This is soft, ephemeral
//! routing state — NOT a registry of identity (that stays with the keypairs) and
//! NOT durable (store-and-forward for offline agents is a deferred MVP item).

use crate::wire::Envelope;
use std::collections::HashMap;
use tokio::sync::{mpsc, Mutex};

#[derive(Default)]
pub struct Presence {
    /// One sender per connected agent; `route` pushes an envelope onto the
    /// recipient's queue, which their connection task drains to the socket.
    connections: Mutex<HashMap<String, mpsc::Sender<Envelope>>>,
}

impl Presence {
    /// Register a freshly-authenticated agent. A reconnect replaces the prior
    /// sender (last-writer-wins; the old connection's queue is dropped).
    pub async fn register(&self, agent_id: String, tx: mpsc::Sender<Envelope>) {
        self.connections.lock().await.insert(agent_id, tx);
    }

    pub async fn unregister(&self, agent_id: &str) {
        self.connections.lock().await.remove(agent_id);
    }

    /// Route an envelope to its recipient if online. Returns `false` when the
    /// recipient is not connected (caller decides to drop / store-and-forward).
    pub async fn route(&self, env: &Envelope) -> bool {
        let tx = {
            let map = self.connections.lock().await;
            map.get(&env.recipient).cloned()
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
}
