//! Resource broker — the discovery half of the BWOC Resource Protocol
//! (framework `docs/en/RESOURCE-PROTOCOL.en.md`).
//!
//! A provider POSTs an **advertise** (its `ResourceSnapshot` + offered kinds +
//! a TTL); the broker holds it in an in-memory, **TTL-evicted** registry. A
//! consumer POSTs a **discover** (a kind + minimum spec) and gets back the live
//! offers that fit. That is all the broker does for resources — matching offers
//! to queries.
//!
//! It stays true to the gateway's "dumb, untrusted relay" grain:
//!   - **No claim/lease brokering here.** The `RES.CLAIM` → `RES.LEASE` round
//!     trip rides the existing signed-envelope relay (an envelope addressed to
//!     the provider; the provider mints and relays the lease back). The broker
//!     never mints a lease and never executes work.
//!   - **Trust is deferred to the lease.** The registry does not verify the
//!     advertise signature — a spoofed offer is a phantom that fails at claim
//!     time (the provider never responds / the consumer can't verify the lease
//!     signature). One live offer per `provider` id (last-writer-wins), TTL
//!     eviction (time bound), and a hard `MAX_OFFERS` count cap (soonest-expiry
//!     eviction) together bound registry pollution under a distinct-id flood.
//!
//! The registry is a cache of live offers, never a system of record.

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// One advertised offer, as the consumer sees it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Offer {
    /// The provider's agent id — also the `offer_id` (one live offer per host)
    /// and the `recipient` a `RES.CLAIM` envelope is relayed to.
    pub provider: String,
    /// Kinds this provider offers (`compute` / `kv` / `knowledge`).
    pub kinds: Vec<String>,
    /// The provider's `ResourceSnapshot`, opaque to the broker except for the
    /// numeric fields `discover` filters on.
    pub snapshot: serde_json::Value,
}

/// A stored offer with its expiry (monotonic — immune to wall-clock jumps).
struct StoredOffer {
    offer: Offer,
    expires_at: Instant,
}

/// In-memory offer registry, keyed by provider id. Cheap to clone (Arc'd in
/// `AppState`).
#[derive(Default)]
pub struct ResourceRegistry {
    offers: Mutex<HashMap<String, StoredOffer>>,
}

/// Guard: an absurd TTL (a provider trying to pin an offer forever) is clamped.
const MAX_TTL_SECS: u64 = 300;

/// Hard cap on distinct live offers. TTL eviction bounds *time*; this bounds
/// *count* — a flood of distinct `provider` ids (each valid up to `MAX_TTL_SECS`)
/// can't grow the map without limit. At the cap, a new provider evicts the
/// soonest-to-expire existing offer (same spirit as `Store`'s `MAX_PER_RECIPIENT`).
const MAX_OFFERS: usize = 1024;

impl ResourceRegistry {
    /// Insert/replace this provider's offer, expiring after `ttl_secs` (clamped
    /// to `MAX_TTL_SECS`, floored at 1s). Returns the count of live offers after
    /// insertion (for the advertise response).
    pub fn advertise(&self, offer: Offer, ttl_secs: u64, now: Instant) -> usize {
        let ttl = Duration::from_secs(ttl_secs.clamp(1, MAX_TTL_SECS));
        let mut map = self.offers.lock().expect("registry lock");
        evict_expired(&mut map, now);
        // A *new* provider at the cap evicts the soonest-to-expire entry so the
        // map stays bounded even under a distinct-id flood. Refreshing an
        // existing provider (already keyed) never trips this.
        if !map.contains_key(&offer.provider) && map.len() >= MAX_OFFERS {
            if let Some(victim) = map
                .iter()
                .min_by_key(|(_, s)| s.expires_at)
                .map(|(k, _)| k.clone())
            {
                map.remove(&victim);
            }
        }
        map.insert(
            offer.provider.clone(),
            StoredOffer {
                offer,
                expires_at: now + ttl,
            },
        );
        map.len()
    }

    /// Return the live offers matching `query`, best-fit first (most free VRAM,
    /// then most free RAM). Evicts expired entries as a side effect.
    pub fn discover(&self, query: &DiscoverQuery, now: Instant) -> Vec<Offer> {
        // Scope the lock to evict + filter + collect — the (potentially
        // O(n log n)) sort runs after the guard drops, so the sort itself does
        // not extend the time a concurrent advertise/discover waits on the mutex.
        let mut out: Vec<Offer> = {
            let mut map = self.offers.lock().expect("registry lock");
            evict_expired(&mut map, now);
            map.values()
                .map(|s| &s.offer)
                .filter(|o| offer_matches(o, query))
                .cloned()
                .collect()
        };
        out.sort_by(|a, b| {
            snapshot_best_vram(&b.snapshot)
                .cmp(&snapshot_best_vram(&a.snapshot))
                .then(snapshot_ram_free(&b.snapshot).cmp(&snapshot_ram_free(&a.snapshot)))
        });
        out
    }

    #[cfg(test)]
    fn live_count(&self, now: Instant) -> usize {
        let mut map = self.offers.lock().expect("registry lock");
        evict_expired(&mut map, now);
        map.len()
    }
}

fn evict_expired(map: &mut HashMap<String, StoredOffer>, now: Instant) {
    map.retain(|_, s| s.expires_at > now);
}

// --- Matching --------------------------------------------------------------

/// A consumer's discovery query: a required kind + optional minimum spec.
#[derive(Debug, Clone, Deserialize)]
pub struct DiscoverQuery {
    pub kind: String,
    #[serde(default)]
    pub min_vram_mb: Option<u64>,
    #[serde(default)]
    pub min_ram_mb: Option<u64>,
    #[serde(default)]
    pub min_cpu_cores: Option<u32>,
}

fn offer_matches(offer: &Offer, q: &DiscoverQuery) -> bool {
    if !offer.kinds.iter().any(|k| k == &q.kind) {
        return false;
    }
    if let Some(min) = q.min_vram_mb {
        if snapshot_best_vram(&offer.snapshot) < min {
            return false;
        }
    }
    if let Some(min) = q.min_ram_mb {
        if snapshot_ram_free(&offer.snapshot) < min {
            return false;
        }
    }
    if let Some(min) = q.min_cpu_cores {
        if snapshot_cpu_cores(&offer.snapshot) < min {
            return false;
        }
    }
    true
}

/// Best single-GPU free VRAM in a snapshot (0 if no GPUs).
fn snapshot_best_vram(snap: &serde_json::Value) -> u64 {
    snap.get("gpus")
        .and_then(|v| v.as_array())
        .map(|gpus| {
            gpus.iter()
                .filter_map(|g| g.get("vram_free_mb").and_then(serde_json::Value::as_u64))
                .max()
                .unwrap_or(0)
        })
        .unwrap_or(0)
}

fn snapshot_ram_free(snap: &serde_json::Value) -> u64 {
    snap.get("ram_free_mb")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}

fn snapshot_cpu_cores(snap: &serde_json::Value) -> u32 {
    // Snapshots are untrusted/opaque — clamp rather than `as`-truncate, so an
    // absurd `cpu_cores` stays "very large" and can't wrap to a small number
    // that would wrongly pass a `min_cpu_cores` filter.
    snap.get("cpu_cores")
        .and_then(serde_json::Value::as_u64)
        .map(|n| u32::try_from(n).unwrap_or(u32::MAX))
        .unwrap_or(0)
}

// --- HTTP handlers ---------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct AdvertiseRequest {
    pub provider: String,
    #[serde(default)]
    pub kinds: Vec<String>,
    pub snapshot: serde_json::Value,
    #[serde(default = "default_ttl")]
    pub ttl_secs: u64,
}

fn default_ttl() -> u64 {
    30
}

#[derive(Debug, Clone, Serialize)]
pub struct AdvertiseResponse {
    pub ok: bool,
    pub offer_id: String,
    pub live_offers: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoverResponse {
    pub ok: bool,
    pub offers: Vec<Offer>,
}

/// `POST /v1/resource/advertise` — a provider (re)publishes its offer.
pub async fn advertise(
    State(state): State<crate::AppState>,
    Json(req): Json<AdvertiseRequest>,
) -> Json<AdvertiseResponse> {
    let provider = req.provider.clone();
    let offer = Offer {
        provider: req.provider,
        kinds: req.kinds,
        snapshot: req.snapshot,
    };
    let live = state
        .resources
        .advertise(offer, req.ttl_secs, Instant::now());
    tracing::info!(%provider, live, "resource advertise");
    Json(AdvertiseResponse {
        ok: true,
        offer_id: provider,
        live_offers: live,
    })
}

/// `POST /v1/resource/discover` — a consumer queries for matching offers.
pub async fn discover(
    State(state): State<crate::AppState>,
    Json(query): Json<DiscoverQuery>,
) -> Json<DiscoverResponse> {
    let offers = state.resources.discover(&query, Instant::now());
    tracing::info!(kind = %query.kind, matched = offers.len(), "resource discover");
    Json(DiscoverResponse { ok: true, offers })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn snap(vram_free: u64, ram_free: u64, cores: u32) -> serde_json::Value {
        json!({
            "host": "h",
            "gpus": if vram_free > 0 {
                json!([{ "index": 0, "model": "G", "vram_total_mb": vram_free + 1000,
                         "vram_free_mb": vram_free, "util_pct": 3 }])
            } else { json!([]) },
            "cpu_cores": cores,
            "ram_free_mb": ram_free,
            "ram_total_mb": ram_free + 1000,
        })
    }

    fn offer(provider: &str, kinds: &[&str], vram: u64, ram: u64, cores: u32) -> Offer {
        Offer {
            provider: provider.into(),
            kinds: kinds.iter().map(|s| s.to_string()).collect(),
            snapshot: snap(vram, ram, cores),
        }
    }

    #[test]
    fn advertise_then_discover_matches_kind() {
        let reg = ResourceRegistry::default();
        let now = Instant::now();
        reg.advertise(
            offer("bemind", &["compute", "knowledge"], 40000, 96000, 128),
            30,
            now,
        );
        let q = DiscoverQuery {
            kind: "compute".into(),
            min_vram_mb: None,
            min_ram_mb: None,
            min_cpu_cores: None,
        };
        assert_eq!(reg.discover(&q, now).len(), 1);
        let q_kv = DiscoverQuery {
            kind: "kv".into(),
            min_vram_mb: None,
            min_ram_mb: None,
            min_cpu_cores: None,
        };
        assert!(
            reg.discover(&q_kv, now).is_empty(),
            "kv not offered → no match"
        );
    }

    #[test]
    fn discover_filters_on_min_spec() {
        let reg = ResourceRegistry::default();
        let now = Instant::now();
        reg.advertise(offer("small", &["compute"], 8000, 16000, 8), 30, now);
        reg.advertise(offer("big", &["compute"], 40000, 96000, 128), 30, now);
        let q = DiscoverQuery {
            kind: "compute".into(),
            min_vram_mb: Some(24000),
            min_ram_mb: None,
            min_cpu_cores: None,
        };
        let offers = reg.discover(&q, now);
        assert_eq!(offers.len(), 1);
        assert_eq!(offers[0].provider, "big");
    }

    #[test]
    fn discover_sorts_best_vram_first() {
        let reg = ResourceRegistry::default();
        let now = Instant::now();
        reg.advertise(offer("mid", &["compute"], 24000, 48000, 32), 30, now);
        reg.advertise(offer("big", &["compute"], 40000, 96000, 128), 30, now);
        reg.advertise(offer("small", &["compute"], 8000, 16000, 8), 30, now);
        let q = DiscoverQuery {
            kind: "compute".into(),
            min_vram_mb: None,
            min_ram_mb: None,
            min_cpu_cores: None,
        };
        let offers = reg.discover(&q, now);
        assert_eq!(
            offers
                .iter()
                .map(|o| o.provider.as_str())
                .collect::<Vec<_>>(),
            vec!["big", "mid", "small"]
        );
    }

    #[test]
    fn advertise_is_last_writer_wins_per_provider() {
        let reg = ResourceRegistry::default();
        let now = Instant::now();
        reg.advertise(offer("bemind", &["compute"], 40000, 96000, 128), 30, now);
        reg.advertise(offer("bemind", &["compute"], 4000, 96000, 128), 30, now); // GPU now busy
        assert_eq!(
            reg.live_count(now),
            1,
            "same provider replaces, not duplicates"
        );
        let q = DiscoverQuery {
            kind: "compute".into(),
            min_vram_mb: Some(10000),
            min_ram_mb: None,
            min_cpu_cores: None,
        };
        assert!(
            reg.discover(&q, now).is_empty(),
            "refreshed snapshot reflects the busy GPU"
        );
    }

    #[test]
    fn ttl_evicts_stale_offers() {
        let reg = ResourceRegistry::default();
        let now = Instant::now();
        reg.advertise(offer("bemind", &["compute"], 40000, 96000, 128), 5, now);
        assert_eq!(reg.live_count(now), 1);
        let later = now + Duration::from_secs(6);
        assert_eq!(reg.live_count(later), 0, "offer expired after its TTL");
    }

    #[test]
    fn registry_is_count_bounded() {
        let reg = ResourceRegistry::default();
        let now = Instant::now();
        // Flood with more distinct providers than the cap allows.
        for i in 0..(MAX_OFFERS + 50) {
            reg.advertise(
                offer(&format!("p{i}"), &["compute"], 1000, 1000, 1),
                300,
                now,
            );
        }
        assert!(
            reg.live_count(now) <= MAX_OFFERS,
            "distinct-provider flood must stay bounded by MAX_OFFERS"
        );
    }

    #[test]
    fn huge_cpu_cores_clamps_not_wraps() {
        // cpu_cores far beyond u32::MAX must stay "large" (clamp), so a min-cores
        // filter still matches — not wrap to a small number that spuriously fails.
        let snap = json!({ "gpus": [], "cpu_cores": u64::MAX, "ram_free_mb": 1000 });
        assert_eq!(snapshot_cpu_cores(&snap), u32::MAX);
        let reg = ResourceRegistry::default();
        let now = Instant::now();
        reg.advertise(
            Offer {
                provider: "big".into(),
                kinds: vec!["compute".into()],
                snapshot: snap,
            },
            30,
            now,
        );
        let q = DiscoverQuery {
            kind: "compute".into(),
            min_vram_mb: None,
            min_ram_mb: None,
            min_cpu_cores: Some(1_000_000),
        };
        assert_eq!(
            reg.discover(&q, now).len(),
            1,
            "huge core count must satisfy the min filter"
        );
    }

    #[test]
    fn ttl_is_clamped() {
        let reg = ResourceRegistry::default();
        let now = Instant::now();
        reg.advertise(offer("bemind", &["compute"], 40000, 96000, 128), 99999, now);
        // Still live just before the clamp ceiling, gone after.
        assert_eq!(
            reg.live_count(now + Duration::from_secs(MAX_TTL_SECS - 1)),
            1
        );
        assert_eq!(
            reg.live_count(now + Duration::from_secs(MAX_TTL_SECS + 1)),
            0
        );
    }
}
