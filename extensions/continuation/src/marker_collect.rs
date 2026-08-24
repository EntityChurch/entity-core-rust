//! §3.10 chain-error marker collection — the reaper half of the MUST-bind.
//!
//! **`EXTENSION-CONTINUATION` v1.23 §3.4 A.1: *"Collection is `MUST` for any
//! peer that binds `[MUST]`, and the collector is the binder."*** Binding was
//! elevated SHOULD → MUST while collection stayed MAY, which is a leak by
//! construction: a retry loop with no `on_error` mints a marker per failed
//! attempt — roughly 1,440 a day against one dead counterpart — into a tree
//! nothing was obliged to reap. v1.23 closes the asymmetry and names both the
//! actor and the window.
//!
//! **The actor falls out of the own-tree/own-authority invariant** (§3.10.7):
//! markers are bound in the observing peer's own tree under its own authority,
//! so the binder can always collect them — and nobody else can. There is no
//! operator step, no external reaper, and no substrate behavior to depend on.
//!
//! **The window is `system/config/chain-errors` → `retention_ms`, default 24 h.**
//! Before v1.23 that window was suggested but had no key, so an impl that wanted
//! the knob had to invent one (Go had, at `system/runtime/chain-errors/retention-ms`,
//! and retired it for this). Rust had no reaper at all, which is the state this
//! module ends.
//!
//! Everything here is **best-effort and non-reactive**, like every other
//! operation on this tree: an unreadable or undecodable binding is skipped
//! rather than removed, a failed removal is dropped, and collection can never
//! affect a chain — it removes observations, never behavior.

use std::sync::Arc;

use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};

/// The config entity an operator sets the retention window on (v1.23 §3.4 A.1),
/// peer-qualified at use. The window is the `retention_ms` **field within that
/// entity**, not a leaf path of its own.
pub const MARKER_RETENTION_CONFIG_PATH: &str = "system/config/chain-errors";

/// The field inside [`MARKER_RETENTION_CONFIG_PATH`], a window in milliseconds.
pub const MARKER_RETENTION_FIELD: &str = "retention_ms";

/// §3.4 A.1's default window: 24 hours.
pub const DEFAULT_MARKER_RETENTION_MS: u64 = 24 * 60 * 60 * 1000;

/// Retention `0` disables collection.
///
/// Collection is a MUST and this opting out of it is not a contradiction: the
/// MUST exists to close an **asymmetry**, not to force deletion. What an impl
/// gets wrong by omission is *having no reaper with a bounded default* — which
/// is exactly what this module supplies. An operator who wants the full history
/// is a legitimate case (the tree IS the event log) and says so; what they
/// cannot get is unbounded growth **by accident**.
///
/// Go flagged the same reading to arch and shipped the same knob. If §3.4 A.1's
/// MAY→MUST was meant as "markers MUST be deleted at 24 h, no opt-out", both
/// impls are non-conformant here in the same way and the ruling should say so.
pub const RETAIN_MARKERS_FOREVER: u64 = 0;

/// The §3.10 marker entity type. **Both kinds carry it** — `lost` (sender-side:
/// the continuation engine and the subscription engine) and `rejected`
/// (receiver-side: the dispatcher) — so one type check covers the whole tree,
/// and §5's collect obligation ("applies to both kinds") is one sweep.
pub const TYPE_CHAIN_ERROR_LOST: &str = "system/runtime/chain-error-lost";

/// The marker subtree, peer-qualified. Rust binds absolute paths
/// (`/{peer_id}/system/runtime/chain-errors/...`), so the sweep is rooted at
/// this peer's own prefix and cannot reach another peer's markers even if a
/// shared index held them.
pub fn marker_root(local_peer_id: &str) -> String {
    format!("/{}/system/runtime/chain-errors/", local_peer_id)
}

/// Remove every §3.10 marker whose **origination** timestamp is older than
/// `retention_ms` before `now_ms`, returning how many bindings were collected.
///
/// Self-collection: this peer reaping its own markers out of its own tree.
///
/// Only the **binding** is removed; the entity stays in the content store. It is
/// content-addressed and may be referenced from anywhere — a reaper that
/// followed a path removal with a store delete would be a data-loss bug wearing
/// a GC costume. The tree is the index this obligation is about.
pub fn collect_expired_markers(
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
    local_peer_id: &str,
    retention_ms: u64,
    now_ms: u64,
) -> usize {
    if retention_ms == RETAIN_MARKERS_FOREVER {
        return 0;
    }
    // Clock before epoch+window: nothing can be expired yet, and an unsigned
    // subtraction here would wrap into a cutoff that collects everything.
    if now_ms <= retention_ms {
        return 0;
    }
    let cutoff = now_ms - retention_ms;

    let mut collected = 0;
    for entry in location_index.list(&marker_root(local_peer_id)) {
        let Some(entity) = content_store.get(&entry.hash) else {
            continue;
        };
        if entity.entity_type != TYPE_CHAIN_ERROR_LOST {
            // Not a marker — an intermediate binding, or something else's.
            // Removing a binding we did not identify is how a reaper becomes a
            // data-loss bug.
            continue;
        }
        let Some(timestamp) = marker_timestamp_ms(&entity.data) else {
            continue;
        };
        // The timestamp is captured at failure **origination** (§3.10.6), not at
        // bind time, which is what makes it a sound age: a redelivered marker
        // does not look younger than the failure it records. A marker with no
        // timestamp (or `0`) is never aged out — absent evidence is not evidence
        // of age.
        if timestamp == 0 || timestamp > cutoff {
            continue;
        }
        if location_index.remove(&entry.path).is_some() {
            collected += 1;
        }
    }
    collected
}

/// Read the v1.23 operator knob — `retention_ms` out of this peer's own
/// `system/config/chain-errors` entity.
///
/// `None` when the operator has set nothing here: an unresolved path, a missing
/// entity, an undecodable body, and an absent field are all the same answer.
/// The config is advisory over a working default, never a precondition — a
/// malformed config must not turn collection off, which would silently restore
/// the leak it exists to close.
///
/// `Some(0)` is meaningful and distinct from `None`: it is the operator
/// explicitly choosing [`RETAIN_MARKERS_FOREVER`], which is why this returns an
/// `Option` rather than folding "absent" and "zero" together.
pub fn retention_from_config(
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
    local_peer_id: &str,
) -> Option<u64> {
    let path = format!("/{}/{}", local_peer_id, MARKER_RETENTION_CONFIG_PATH);
    let hash: Hash = location_index.get(&path)?;
    let entity = content_store.get(&hash)?;
    decode_retention_ms(&entity.data)
}

/// `retention_ms` out of a `system/config/chain-errors` body. Unknown fields are
/// MUST-ignore ([ADR-0002]), so a config carrying keys this build has never seen
/// still yields the window.
fn decode_retention_ms(data: &[u8]) -> Option<u64> {
    let value: ciborium::Value = ciborium::from_reader(data).ok()?;
    for (k, v) in value.as_map()? {
        if k.as_text() == Some(MARKER_RETENTION_FIELD) {
            return v
                .as_integer()
                .and_then(|i| u64::try_from(i128::from(i)).ok());
        }
    }
    None
}

/// `timestamp` out of a marker body (§3.10.6 reserves it across both kinds).
fn marker_timestamp_ms(data: &[u8]) -> Option<u64> {
    let value: ciborium::Value = ciborium::from_reader(data).ok()?;
    for (k, v) in value.as_map()? {
        if k.as_text() == Some("timestamp") {
            return v
                .as_integer()
                .and_then(|i| u64::try_from(i128::from(i)).ok());
        }
    }
    None
}
