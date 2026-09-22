//! In-memory Mode-S store (§6.1) — the v1 floor backing for `:put` / `:poll`.
//!
//! Mode S is **inbox-shaped but self-contained** (§6.1): it does NOT delegate
//! to the INBOX op. The store is keyed by `(namespace, entry_hash)` and keeps a
//! **relay-owned, monotonically-increasing cursor** per namespace so `:poll`
//! can page in stable insertion order. The cursor is the relay's own concern
//! (NOT INBOX's, §3.2/§6.1); cross-impl tests compare the *entries observed on
//! advance*, never the cursor bytes (handoff Open/TBD #3).
//!
//! Persistence is out of v1 floor scope — in-memory only; restart is not
//! required to preserve entries (handoff Open/TBD #2). A deployment MAY back a
//! namespace with durable storage, out of RELAY v1 scope (§6.1).

use std::collections::HashMap;
use std::sync::Mutex;

use entity_hash::Hash;

/// One stored Mode-S entry: a pointer to the `store-entry` entity plus the
/// relay-owned sequence number that orders it within its namespace.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredEntry {
    /// Hash of the stored `system/relay/store-entry` entity (§4.2 `entry_hash`).
    pub entry_hash: Hash,
    /// Relay-owned monotonic sequence within the namespace (the cursor basis).
    pub seq: u64,
    /// ms-since-epoch expiry; `None` = no expiry. Expired entries are skipped
    /// on poll (and eligible for GC, §8).
    pub expires_at: Option<i64>,
    /// **v1.3 (§8.2)** — this entry's contribution to the relay-wide live byte
    /// total. See [`ModeStore::live_bytes`] for the metric and its caveat.
    pub cost: u64,
}

#[derive(Default)]
struct NamespaceLog {
    next_seq: u64,
    entries: Vec<StoredEntry>,
}

/// The result of a `:poll` page (§4.2 `poll-result` payload, pre-encode).
#[derive(Debug, Clone, PartialEq)]
pub struct PollPage {
    pub entries: Vec<Hash>,
    /// Opaque relay-owned cursor — the seq to resume strictly after. Encoded on
    /// the wire as 8-byte big-endian (matching Go for free byte-equality; R8
    /// does not byte-compare cursors regardless).
    pub cursor: u64,
    pub has_more: bool,
}

/// Thread-safe in-memory Mode-S store.
#[derive(Default)]
pub struct ModeStore {
    inner: Mutex<HashMap<String, NamespaceLog>>,
}

impl ModeStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an entry to a namespace; returns its assigned relay-owned seq.
    /// Idempotent placement is NOT assumed — re-putting the same `entry_hash`
    /// appends a new seq (content-addressed dedup happens in the content store;
    /// the poll log records each placement).
    pub fn put(
        &self,
        namespace: &str,
        entry_hash: Hash,
        expires_at: Option<i64>,
        cost: u64,
        now_ms: i64,
    ) -> u64 {
        let mut guard = self.inner.lock().expect("relay store mutex");
        let log = guard.entry(namespace.to_string()).or_default();
        // §8 reclamation, taken on write. Expiry is honored on READ regardless
        // (`poll` filters), so this is memory hygiene rather than a visibility
        // rule — but it is what keeps `live_bytes` from counting bytes the
        // relay is no longer obliged to hold, which would make §8.2 refuse a
        // put for capacity that is in fact free.
        log.entries.retain(|e| !is_expired(e.expires_at, now_ms));
        let seq = log.next_seq;
        log.next_seq += 1;
        log.entries.push(StoredEntry {
            entry_hash,
            seq,
            expires_at,
            cost,
        });
        seq
    }

    /// Is a hash-equal entry already stored in this namespace? — the §8.2
    /// **idempotency gate**.
    ///
    /// A re-put of an entry already held adds no bytes, so refusing it on a
    /// full store would report `storage_full` for a request that needs no
    /// storage. The store is content-addressed, so "same hash" is "same
    /// entry" without qualification.
    pub fn contains(&self, namespace: &str, entry_hash: &Hash) -> bool {
        let guard = self.inner.lock().expect("relay store mutex");
        guard
            .get(namespace)
            .is_some_and(|log| log.entries.iter().any(|e| &e.entry_hash == entry_hash))
    }

    /// Relay-wide live byte total (§8.2), summed over every namespace.
    ///
    /// **The metric is `len(store-entry.data) + len(inner.data)` per live
    /// entry** — the two entity `data` payloads the relay actually holds on the
    /// putter's behalf, and it matches core-go's `entryCost` so the two seats
    /// bound the same quantity.
    ///
    /// **It is not ruled.** §8.2 says a full store refuses; it does not define
    /// what `max_storage_bytes` counts (wire size? entity size? plus tree
    /// index? plus per-entry overhead?), which is why core-go filed spec-issue
    /// `2026-09-01-a` and deliberately did NOT ship the storage-full wire row —
    /// a cross-impl check on this number would test one seat's reading. The
    /// choice is written here so it is a stated interim, not a silent one.
    ///
    /// The bound is relay-wide rather than per-namespace: §8.2 names
    /// `max_storage_bytes` as the relay's advertised limit (§4.1), and a
    /// per-namespace reading would let N namespaces hold N times the bound.
    pub fn live_bytes(&self, now_ms: i64) -> u64 {
        let guard = self.inner.lock().expect("relay store mutex");
        guard
            .values()
            .flat_map(|log| log.entries.iter())
            .filter(|e| !is_expired(e.expires_at, now_ms))
            .map(|e| e.cost)
            .sum()
    }

    /// Page the namespace from `since` (exclusive; `None` = from start),
    /// skipping entries expired at `now_ms`, up to `limit` (`None` = the backend
    /// default). An unknown/empty namespace returns an empty page (§4.2 — empty
    /// is NOT `namespace_not_found`; this in-memory floor never requires
    /// provisioning).
    pub fn poll(
        &self,
        namespace: &str,
        since: Option<u64>,
        limit: Option<usize>,
        now_ms: i64,
    ) -> PollPage {
        let guard = self.inner.lock().expect("relay store mutex");
        let after = since
            .unwrap_or(0)
            .saturating_add(if since.is_some() { 1 } else { 0 });
        // `since` is the last-seen seq → start strictly after it. `None` → seq 0.
        let start = if since.is_some() { after } else { 0 };

        let Some(log) = guard.get(namespace) else {
            // Empty steady state — the freshly-created-inbox case (§4.2).
            return PollPage {
                entries: Vec::new(),
                cursor: since.unwrap_or(0),
                has_more: false,
            };
        };

        let limit = limit.unwrap_or(DEFAULT_POLL_LIMIT).max(1);

        // Live (non-expired) entries with seq >= start, in insertion order.
        let live: Vec<&StoredEntry> = log
            .entries
            .iter()
            .filter(|e| e.seq >= start && !is_expired(e.expires_at, now_ms))
            .collect();

        let has_more = live.len() > limit;
        let page: Vec<&StoredEntry> = live.into_iter().take(limit).collect();

        let cursor = page
            .last()
            .map(|e| e.seq)
            // No entries returned → echo the incoming cursor so the caller can
            // re-poll from the same point (stable cursor, handoff Open/TBD #3).
            .unwrap_or_else(|| since.unwrap_or(0));

        PollPage {
            entries: page.iter().map(|e| e.entry_hash).collect(),
            cursor,
            has_more,
        }
    }
}

/// Backend default page size when `:poll` omits `limit` (§4.2). Conservative;
/// deployments tune per workload.
pub const DEFAULT_POLL_LIMIT: usize = 256;

fn is_expired(expires_at: Option<i64>, now_ms: i64) -> bool {
    matches!(expires_at, Some(e) if e <= now_ms)
}
