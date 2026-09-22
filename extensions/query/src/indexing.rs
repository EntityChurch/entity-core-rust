//! IndexingLocationIndex — LocationIndex decorator for synchronous index updates.
//!
//! Slots between the base LocationIndex and NotifyingLocationIndex in the
//! PeerBuilder chain. Ensures query indexes are updated inline during every
//! `set()` and `remove()`, satisfying spec §3.3 synchronous consistency.

use std::sync::Arc;

use entity_hash::Hash;
use entity_store::{ContentStore, LocationEntry, LocationIndex};

use crate::index::QueryIndexStore;

/// A LocationIndex decorator that synchronously updates query indexes
/// on every mutation.
pub struct IndexingLocationIndex {
    inner: Arc<dyn LocationIndex>,
    content_store: Arc<dyn ContentStore>,
    indexes: Arc<dyn QueryIndexStore>,
}

impl IndexingLocationIndex {
    pub fn new(
        inner: Arc<dyn LocationIndex>,
        content_store: Arc<dyn ContentStore>,
        indexes: Arc<dyn QueryIndexStore>,
    ) -> Self {
        Self {
            inner,
            content_store,
            indexes,
        }
    }
}

impl LocationIndex for IndexingLocationIndex {
    fn set(&self, path: &str, hash: Hash) {
        let previous = self.inner.get(path);

        // Short-circuit if hash unchanged
        if let Some(prev) = previous {
            if prev == hash {
                self.inner.set(path, hash);
                return;
            }
            // Remove old index entries
            self.indexes.remove_entries_for_path(path);
        }

        // Perform the write
        self.inner.set(path, hash);

        // Add new index entries
        if let Some(entity) = self.content_store.get(&hash) {
            self.indexes.add_entries_for_entity(path, &entity);
        }
    }

    fn get(&self, path: &str) -> Option<Hash> {
        self.inner.get(path)
    }

    fn has(&self, path: &str) -> bool {
        self.inner.has(path)
    }

    fn remove(&self, path: &str) -> Option<Hash> {
        self.indexes.remove_entries_for_path(path);
        self.inner.remove(path)
    }

    fn list(&self, prefix: &str) -> Vec<LocationEntry> {
        self.inner.list(prefix)
    }

    fn len_prefix(&self, prefix: &str) -> usize {
        self.inner.len_prefix(prefix)
    }

    // --- The CAS trio: FORWARDED, and it has to be. -----------------------
    //
    // `LocationIndex`'s default `compare_and_swap` / `compare_and_remove` /
    // `compare_and_create` are a non-atomic `get` + `set`, and the trait says so
    // at the definition: *"Real backends MUST override this with an atomic
    // implementation."* This decorator is not a backend, which is exactly the
    // trap — it forwards `get`/`set`/`remove` and reads as complete, while every
    // method it does NOT name silently falls back to that default. It sits
    // unconditionally between the base index and `NotifyingLocationIndex`
    // whenever the `query` feature is on (the default), so `MemoryLocationIndex`'s
    // genuinely-atomic CAS was reachable in unit tests and unreachable in the
    // peer: `NotifyingLocationIndex::cas_swap_impl` called through to THIS type's
    // inherited get+set, and every CAS in the peer degraded to a read followed by
    // an unconditional write.
    //
    // Measured consequence, on a live peer: two concurrent root-tracker updates
    // both "succeeded" a CAS against the same expected root, so one write's path
    // was dropped from the tracked trie permanently (the last-burst-write loss).
    // The blast radius is wider than that — §3.9's `expected_hash` on
    // `system/tree:put` is the wire-facing concurrency primitive and it ran on
    // the same broken path.
    //
    // Index maintenance mirrors `set`/`remove` above: it happens only once the
    // inner CAS has actually committed, so a losing CAS leaves the indexes alone.
    fn compare_and_swap(
        &self,
        path: &str,
        expected: Hash,
        new_hash: Hash,
    ) -> Result<(), entity_store::CasError> {
        self.inner.compare_and_swap(path, expected, new_hash)?;
        if expected != new_hash {
            self.indexes.remove_entries_for_path(path);
            if let Some(entity) = self.content_store.get(&new_hash) {
                self.indexes.add_entries_for_entity(path, &entity);
            }
        }
        Ok(())
    }

    fn compare_and_remove(
        &self,
        path: &str,
        expected: Hash,
    ) -> Result<Hash, entity_store::CasError> {
        let removed = self.inner.compare_and_remove(path, expected)?;
        self.indexes.remove_entries_for_path(path);
        Ok(removed)
    }

    fn compare_and_create(&self, path: &str, new_hash: Hash) -> Result<(), entity_store::CasError> {
        self.inner.compare_and_create(path, new_hash)?;
        if let Some(entity) = self.content_store.get(&new_hash) {
            self.indexes.add_entries_for_entity(path, &entity);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::QueryIndexes;
    use entity_entity::Entity;
    use entity_store::{MemoryContentStore, MemoryLocationIndex};

    fn make_entity(type_str: &str, data_str: &str) -> Entity {
        Entity::new(type_str, entity_ecf::to_ecf(&entity_ecf::text(data_str))).unwrap()
    }

    #[test]
    fn test_set_updates_indexes() {
        let content_store = Arc::new(MemoryContentStore::new());
        let base_index = Arc::new(MemoryLocationIndex::new());
        let indexes = Arc::new(QueryIndexes::new());
        let indexing =
            IndexingLocationIndex::new(base_index.clone(), content_store.clone(), indexes.clone());

        let entity = make_entity("app/user", "alice");
        let hash = content_store.put(entity).unwrap();
        indexing.set("users/alice", hash);

        // Verify index was updated synchronously
        let results = indexes.query_type_index("app/user");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].path, "users/alice");
    }

    #[test]
    fn test_remove_cleans_indexes() {
        let content_store = Arc::new(MemoryContentStore::new());
        let base_index = Arc::new(MemoryLocationIndex::new());
        let indexes = Arc::new(QueryIndexes::new());
        let indexing =
            IndexingLocationIndex::new(base_index.clone(), content_store.clone(), indexes.clone());

        let entity = make_entity("app/user", "alice");
        let hash = content_store.put(entity).unwrap();
        indexing.set("users/alice", hash);
        assert_eq!(indexes.query_type_index("app/user").len(), 1);

        indexing.remove("users/alice");
        assert!(indexes.query_type_index("app/user").is_empty());
    }

    #[test]
    fn test_update_replaces_indexes() {
        let content_store = Arc::new(MemoryContentStore::new());
        let base_index = Arc::new(MemoryLocationIndex::new());
        let indexes = Arc::new(QueryIndexes::new());
        let indexing =
            IndexingLocationIndex::new(base_index.clone(), content_store.clone(), indexes.clone());

        let e1 = make_entity("app/user", "alice");
        let h1 = content_store.put(e1).unwrap();
        indexing.set("path/x", h1);
        assert_eq!(indexes.query_type_index("app/user").len(), 1);

        let e2 = make_entity("app/order", "order1");
        let h2 = content_store.put(e2).unwrap();
        indexing.set("path/x", h2);
        assert!(indexes.query_type_index("app/user").is_empty());
        assert_eq!(indexes.query_type_index("app/order").len(), 1);
    }

    #[test]
    fn test_same_hash_no_reindex() {
        let content_store = Arc::new(MemoryContentStore::new());
        let base_index = Arc::new(MemoryLocationIndex::new());
        let indexes = Arc::new(QueryIndexes::new());
        let indexing =
            IndexingLocationIndex::new(base_index.clone(), content_store.clone(), indexes.clone());

        let entity = make_entity("app/user", "alice");
        let hash = content_store.put(entity).unwrap();
        indexing.set("users/alice", hash);
        indexing.set("users/alice", hash); // same hash — no-op

        assert_eq!(indexes.query_type_index("app/user").len(), 1);
    }

    #[test]
    fn test_delegates_reads() {
        let content_store = Arc::new(MemoryContentStore::new());
        let base_index = Arc::new(MemoryLocationIndex::new());
        let indexes = Arc::new(QueryIndexes::new());
        let indexing =
            IndexingLocationIndex::new(base_index.clone(), content_store.clone(), indexes.clone());

        let entity = make_entity("app/user", "alice");
        let hash = content_store.put(entity).unwrap();
        indexing.set("users/alice", hash);

        assert_eq!(indexing.get("users/alice"), Some(hash));
        assert!(indexing.has("users/alice"));
        assert!(!indexing.has("nonexistent"));

        let entries = indexing.list("users/");
        assert_eq!(entries.len(), 1);
    }

    // -----------------------------------------------------------------------
    // CAS forwarding — the decorator must not synthesize it from get+set
    // -----------------------------------------------------------------------

    /// A base index that records whether the atomic CAS entry points were
    /// actually reached, and how many plain `set`s it saw.
    ///
    /// This is the discriminator the class needs. A decorator that inherits
    /// `LocationIndex`'s default `compare_and_swap` still returns the RIGHT
    /// ANSWER single-threaded — it reads, compares, and writes — so no
    /// value-based assertion can tell the two apart. What differs is which
    /// method the base sees: a forwarding decorator reaches `compare_and_swap`,
    /// an inheriting one reaches `get` + `set` and the base's atomicity is never
    /// used at all.
    struct CasSpy {
        inner: MemoryLocationIndex,
        cas_calls: std::sync::atomic::AtomicUsize,
        set_calls: std::sync::atomic::AtomicUsize,
    }

    impl CasSpy {
        fn new() -> Self {
            Self {
                inner: MemoryLocationIndex::new(),
                cas_calls: std::sync::atomic::AtomicUsize::new(0),
                set_calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }
        fn cas_calls(&self) -> usize {
            self.cas_calls.load(std::sync::atomic::Ordering::SeqCst)
        }
        fn set_calls(&self) -> usize {
            self.set_calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl LocationIndex for CasSpy {
        fn set(&self, path: &str, hash: Hash) {
            self.set_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.set(path, hash)
        }
        fn get(&self, path: &str) -> Option<Hash> {
            self.inner.get(path)
        }
        fn has(&self, path: &str) -> bool {
            self.inner.has(path)
        }
        fn remove(&self, path: &str) -> Option<Hash> {
            self.inner.remove(path)
        }
        fn list(&self, prefix: &str) -> Vec<LocationEntry> {
            self.inner.list(prefix)
        }
        fn len_prefix(&self, prefix: &str) -> usize {
            self.inner.len_prefix(prefix)
        }
        fn compare_and_swap(
            &self,
            path: &str,
            expected: Hash,
            new_hash: Hash,
        ) -> Result<(), entity_store::CasError> {
            self.cas_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.compare_and_swap(path, expected, new_hash)
        }
        fn compare_and_remove(
            &self,
            path: &str,
            expected: Hash,
        ) -> Result<Hash, entity_store::CasError> {
            self.cas_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.compare_and_remove(path, expected)
        }
        fn compare_and_create(
            &self,
            path: &str,
            new_hash: Hash,
        ) -> Result<(), entity_store::CasError> {
            self.cas_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.compare_and_create(path, new_hash)
        }
    }

    /// ENTITY-CORE-PROTOCOL §3.9 — this decorator MUST forward the CAS trio to
    /// the backend, never let the trait's non-atomic `get`+`set` default stand in.
    ///
    /// `IndexingLocationIndex` sits unconditionally between the base index and
    /// `NotifyingLocationIndex` whenever `query` is enabled (the default), so a
    /// CAS it does not forward is a CAS the whole peer does not have — the
    /// backend's atomic implementation becomes unreachable in the one
    /// composition that ships. Measured on a live peer before this was fixed:
    /// two concurrent root-tracker updates both "won" a CAS against the same
    /// expected root and one write was dropped from the tracked trie
    /// permanently, and §3.9's `expected_hash` on `system/tree:put` ran on the
    /// same broken path.
    ///
    /// **Mutation:** delete the three CAS methods from the `impl` above (letting
    /// the trait defaults apply) and this goes RED — `cas_calls` is 0 and the
    /// base sees plain `set`s instead. Note the value assertions below stay
    /// GREEN under that mutation, which is the whole point: single-threaded,
    /// the broken path returns the right answer.
    #[test]
    fn cas_is_forwarded_to_the_backend_not_synthesized_from_get_and_set() {
        let content_store = Arc::new(MemoryContentStore::new());
        let spy = Arc::new(CasSpy::new());
        let indexes = Arc::new(QueryIndexes::new());
        let indexing = IndexingLocationIndex::new(
            spy.clone() as Arc<dyn LocationIndex>,
            content_store.clone(),
            indexes.clone(),
        );

        let h1 = content_store.put(make_entity("app/user", "alice")).unwrap();
        let h2 = content_store.put(make_entity("app/user", "bob")).unwrap();

        // create → swap → remove, the full trio.
        indexing.compare_and_create("p/x", h1).expect("create");
        indexing.compare_and_swap("p/x", h1, h2).expect("swap");
        assert_eq!(indexing.get("p/x"), Some(h2));
        indexing.compare_and_remove("p/x", h2).expect("remove");
        assert_eq!(indexing.get("p/x"), None);

        assert_eq!(
            spy.cas_calls(),
            3,
            "the decorator did not forward the CAS trio — the backend's atomic \
             implementation was never reached, so every CAS in the peer degraded to \
             a non-atomic get+set (§3.9 says a real backend MUST be atomic)"
        );
        assert_eq!(
            spy.set_calls(),
            0,
            "a CAS reached the backend as a plain set — that is the non-atomic \
             default standing in for the atomic path"
        );
    }

    /// The losing side of a CAS must leave the query indexes untouched: a
    /// rejected compare-and-swap wrote nothing, so it must not re-index either.
    #[test]
    fn a_losing_cas_does_not_disturb_the_indexes() {
        let content_store = Arc::new(MemoryContentStore::new());
        let base = Arc::new(MemoryLocationIndex::new());
        let indexes = Arc::new(QueryIndexes::new());
        let indexing =
            IndexingLocationIndex::new(base.clone(), content_store.clone(), indexes.clone());

        let h1 = content_store.put(make_entity("app/user", "alice")).unwrap();
        let h2 = content_store
            .put(make_entity("app/order", "order1"))
            .unwrap();
        indexing.set("p/x", h1);
        assert_eq!(indexes.query_type_index("app/user").len(), 1);

        // Expect a value that is not there: the CAS must fail and change nothing.
        let stale = content_store.put(make_entity("app/user", "stale")).unwrap();
        assert!(indexing.compare_and_swap("p/x", stale, h2).is_err());
        assert_eq!(indexing.get("p/x"), Some(h1), "a losing CAS wrote anyway");
        assert_eq!(
            indexes.query_type_index("app/user").len(),
            1,
            "a losing CAS disturbed the indexes"
        );
        assert!(indexes.query_type_index("app/order").is_empty());
    }
}
