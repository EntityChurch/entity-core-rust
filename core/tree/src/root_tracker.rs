//! Incremental trie root tracker — EXTENSION-TREE §3.4.
//!
//! A synchronous emit pathway consumer (SYSTEM-COMPOSITION §2.2, position 6)
//! that maintains trie root hashes for configured prefixes. For each enabled
//! `system/tree/tracking-config` entity, the tracker reflects every tree
//! mutation under the config's prefix into a stored trie, writing the current
//! root hash to `system/tree/root/{prefix}`.
//!
//! Self-guard: mutations at or under `system/tree/root` are ignored to prevent
//! recursive updates when the tracker itself writes root hashes.
//!
//! Feedback-loop guard: writes tagged with a handler pattern whose output
//! *describes* trie state rather than contributing content (the published-root
//! publisher, the history transition recorder) are ignored too — see
//! [`is_feedback_loop_handler`].
//!
//! Config hot-reload: writes to `system/tree/tracking-config/*` trigger an
//! initial build (or clear) for the affected prefix.

use std::sync::{Arc, RwLock};

use entity_entity::Entity;
use entity_hash::Hash;
use entity_store::{ContentStore, ExecutionContext, LocationIndex, SyncTreeHook, TreeChangeEvent};

use crate::trie;

/// A decoded `system/tree/tracking-config` entry.
#[derive(Debug, Clone)]
struct TrackingConfig {
    /// Bare prefix (relative to the peer), MUST end with `/`. The value `"/"`
    /// designates the universal tree root (EXTENSION-TREE §3.4.1a).
    prefix: String,
    enabled: bool,
}

/// `handler_pattern` tag the published-root publisher stamps on its own tree
/// writes so this tracker can skip them ([`is_feedback_loop_handler`]).
///
/// The publisher binds its manifest at `system/peer/published-root` and its
/// signature at `system/signature/{hex}` — both inside a `system/`-or-universal
/// tracked prefix. Untagged, the publisher's own write advances the trie root,
/// which fires the publisher again; Go measured that runaway at ~55 publishes/s
/// with no external traffic.
pub const PUBLISHED_ROOT_HANDLER_PATTERN: &str = "system/peer/published-root";

/// Bound on [`RootTrackerEngine::apply_event`]'s CAS-retry loop.
///
/// Each losing attempt means another thread's cascade advanced this prefix's
/// root in between our read and our write, so the bound is really a bound on
/// simultaneous writers to one prefix; realistic contention resolves in one or
/// two attempts. Exhaustion is NOT a silent give-up — it halts the cascade, so
/// the writer learns its write is not in the root instead of the peer serving a
/// root that quietly lost it.
const MAX_ROOT_CAS_RETRIES: usize = 64;

/// Does `pattern` name a sync-hook consumer whose writes inside a tracked
/// prefix would loop the trie-root → consumer → trie-root cycle?
///
/// The set is intentionally narrow: only consumers whose output *describes*
/// trie state (published-root manifests + signatures, history transitions)
/// belong here, never consumers that contribute user content. Two concrete
/// cycles it breaks, both of which only reach far enough to bite once a
/// tracked prefix is wide enough to contain `system/` (the universal prefix
/// `"/"` always is):
///
/// - publisher writes published-root → trie root advances → publisher fires
///   again (needs no history at all);
/// - tracker writes the tracked root → history records that write under
///   `system/history/` → trie root advances → history records that … (runs
///   with no publisher in the picture).
///
/// Matches `entity-core-go`'s `isFeedbackLoopHandler` (`core/tree/root_tracker.go`).
pub fn is_feedback_loop_handler(pattern: &str) -> bool {
    matches!(pattern, PUBLISHED_ROOT_HANDLER_PATTERN | "system/history")
}

/// EXTENSION-TREE §3.4.1 canonical prefix form: strip leading **and** trailing
/// `/`. The universal-tree prefix `"/"` collapses to the empty string, which is
/// what selects the un-suffixed `system/tree/root` storage path.
fn canonical_prefix(bare_prefix: &str) -> &str {
    bare_prefix.trim_matches('/')
}

/// Build a `system/tree/tracking-config` entity for `prefix` (which MUST end
/// with `/`; `"/"` is the universal tree root per §3.4.1a).
pub fn tracking_config_entity(prefix: &str, enabled: bool) -> Option<Entity> {
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (entity_ecf::text("enabled"), entity_ecf::bool_val(enabled)),
        (entity_ecf::text("prefix"), entity_ecf::text(prefix)),
    ]));
    Entity::new("system/tree/tracking-config", data).ok()
}

pub struct RootTrackerEngine {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    local_peer_id: String,
    /// Pre-computed prefix `/{peer_id}/system/tree/root/` for the self-guard
    /// check and for writing root entries.
    root_path_prefix: String,
    /// Pre-computed `/{peer_id}/system/tree/root` — the §3.4.1 storage path for
    /// the universal prefix, and the exact-match half of the self-guard (it has
    /// no trailing `/`, so `root_path_prefix` alone would not catch it).
    root_path_exact: String,
    /// Pre-computed prefix `/{peer_id}/system/tree/tracking-config/` for
    /// the config-change branch.
    config_path_prefix: String,
    /// Cached enabled configs. Refreshed at bootstrap and on every event under
    /// `config_path_prefix`. The per-put hot path reads this cache instead of
    /// scanning + decoding the location index on every tree mutation.
    cached_configs: RwLock<Vec<TrackingConfig>>,
}

impl RootTrackerEngine {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
    ) -> Self {
        let root_path_exact = format!("/{}/system/tree/root", &local_peer_id);
        let root_path_prefix = format!("{}/", &root_path_exact);
        let config_path_prefix = format!("/{}/system/tree/tracking-config/", &local_peer_id);
        Self {
            content_store,
            location_index,
            local_peer_id,
            root_path_prefix,
            root_path_exact,
            config_path_prefix,
            cached_configs: RwLock::new(Vec::new()),
        }
    }

    /// Scan existing tracking configs and rebuild tries for all enabled
    /// prefixes. Called once at peer startup.
    pub fn bootstrap(&self) {
        let configs = self.load_all_configs();
        tracing::info!(
            peer_id = %self.local_peer_id,
            configs = configs.len(),
            "[root-tracker] bootstrap"
        );
        for cfg in &configs {
            if cfg.enabled {
                self.rebuild_prefix(&cfg.prefix);
            }
        }
        *self.cached_configs.write().unwrap() = configs;
    }

    fn load_all_configs(&self) -> Vec<TrackingConfig> {
        let entries = self.location_index.list(&self.config_path_prefix);
        entries
            .into_iter()
            .filter_map(|e| {
                let entity = self.content_store.get(&e.hash)?;
                decode_tracking_config(&entity)
            })
            .collect()
    }

    fn refresh_cache(&self) {
        let configs = self.load_all_configs();
        *self.cached_configs.write().unwrap() = configs;
    }

    /// Compute the qualified absolute path for the root entry of `bare_prefix`,
    /// per the EXTENSION-TREE §3.4.1 path substitution: canonical form `P` is
    /// the prefix with leading and trailing `/` stripped; an empty `P` (the
    /// universal prefix `"/"`) stores at `system/tree/root`, otherwise at
    /// `system/tree/root/{P}`.
    pub fn qualified_root_path(&self, bare_prefix: &str) -> String {
        let p = canonical_prefix(bare_prefix);
        if p.is_empty() {
            self.root_path_exact.clone()
        } else {
            format!("{}{}", self.root_path_prefix, p)
        }
    }

    /// Qualified prefix for events under `bare_prefix` (e.g. `/{peer}/project/`).
    /// The universal prefix `"/"` qualifies to `/{peer}/` — every path in the
    /// peer's tree.
    ///
    /// **This is EXTENSION-TREE §3.3's `absolute_prefix`** — the operand trie
    /// keys are relative to, and therefore exactly what a published root must
    /// declare in its §3.3a `prefix` field. It is public for that one caller:
    /// a publisher that derived the declaration any other way could drift from
    /// the trim actually applied, and the whole point of the field is that the
    /// declaration and the keys agree.
    ///
    /// Always ends with `/`, which §3.3a requires.
    ///
    /// **Our config's `"/"` is the §3.3 *peer-qualified* shape, not the
    /// universal one.** §3.3 (arch `391c92b`) ruled that a configured `"/"`
    /// means a **no-op** trim spanning every peer-id, leaving keys fully
    /// qualified — because under the universal tree "the peer_id" is not a
    /// single value, and trimming the local one produces a mixed key space.
    /// This tracker instead maps `"/"` to `/{peer}/`: peer-scoped, keys
    /// peer-stripped. That is a legitimate shape — it is the table's
    /// `"/{peer_id}/"` row — and it is what we declare on the wire, so the
    /// published root is correct. What is left is a **spelling mismatch in our
    /// own config**: an operator writing `prefix: "/"` here gets the
    /// peer-qualified reading, not the universal one. Changing it would move
    /// the tracked-root storage path (§3.4.1 substitutes `""` → `system/tree/root`)
    /// and re-key every published trie, so it is deliberately not done here.
    pub fn qualified_bare_prefix(&self, bare_prefix: &str) -> String {
        let p = canonical_prefix(bare_prefix);
        if p.is_empty() {
            format!("/{}/", self.local_peer_id)
        } else {
            format!("/{}/{}/", self.local_peer_id, p)
        }
    }

    /// Read the currently tracked root hash for a prefix, if any.
    ///
    /// The binding at `system/tree/root/{prefix}` points directly at the
    /// root trie node's content hash — no wrapper entity
    /// (EXTENSION-TREE §3.4.1 + TREE-ROOT-PATH-AMBIGUITY.md direct-binding).
    pub fn tracked_root(&self, bare_prefix: &str) -> Option<Hash> {
        self.load_tracked_root(bare_prefix)
    }

    fn load_tracked_root(&self, bare_prefix: &str) -> Option<Hash> {
        self.location_index
            .get(&self.qualified_root_path(bare_prefix))
    }

    /// Is `path` one of this tracker's own output bindings? Both the
    /// un-suffixed universal path and the `{prefix}`-suffixed ones.
    fn is_self_path(&self, path: &str) -> bool {
        path == self.root_path_exact || path.starts_with(&self.root_path_prefix)
    }

    /// Bind the trie root hash directly at `system/tree/root/{prefix}`.
    /// No wrapper: the binding is the trie root node's content hash.
    fn store_tracked_root(
        &self,
        bare_prefix: &str,
        root_hash: Hash,
        ctx: Option<&ExecutionContext>,
    ) {
        let path = self.qualified_root_path(bare_prefix);
        match ctx {
            Some(c) => {
                let _cascade = self
                    .location_index
                    .set_with_context(&path, root_hash, c.clone());
            }
            None => self.location_index.set(&path, root_hash),
        }
    }

    fn remove_tracked_root(&self, bare_prefix: &str, ctx: Option<&ExecutionContext>) {
        let path = self.qualified_root_path(bare_prefix);
        match ctx {
            Some(c) => {
                let _cascade = self.location_index.remove_with_context(&path, c.clone());
            }
            None => {
                self.location_index.remove(&path);
            }
        }
    }

    /// Full rebuild of the trie for `bare_prefix` from the current bindings
    /// in the location index. Used on config creation and startup discovery.
    fn rebuild_prefix(&self, bare_prefix: &str) {
        let qualified = self.qualified_bare_prefix(bare_prefix);
        let entries = self.location_index.list(&qualified);
        let mut bindings = std::collections::BTreeMap::new();
        for e in entries {
            // Skip the tracker's own output paths to avoid circular inclusion.
            if self.is_self_path(&e.path) {
                continue;
            }
            // Strip the qualified prefix to get the relative path the trie indexes by.
            let rel = &e.path[qualified.len()..];
            bindings.insert(rel.to_string(), e.hash);
        }
        match trie::build_trie(self.content_store.as_ref(), &bindings) {
            Ok(root) => {
                tracing::info!(
                    prefix = %bare_prefix,
                    root = %root,
                    bindings = bindings.len(),
                    "[root-tracker] rebuild"
                );
                self.store_tracked_root(bare_prefix, root, None);
            }
            Err(e) => {
                tracing::warn!(prefix = %bare_prefix, error = %e, "[root-tracker] build_trie failed");
            }
        }
    }

    /// Incrementally apply a single tree-change event to the trie for
    /// `bare_prefix`. Returns silently when the event's path is not under
    /// the prefix.
    ///
    /// **The read-modify-write is CAS-guarded, and it has to be.** Sync hooks do
    /// NOT run under any cross-thread lock: `NotifyingLocationIndex::set_impl`
    /// mutates the inner index and then calls `dispatch_event` with nothing held,
    /// so two threads writing two different paths under one tracked prefix run
    /// two cascades — and therefore two copies of this function — in parallel.
    /// Read-`trie_put`-store with a plain `set` is then a textbook lost update:
    /// both threads read root `R0`, both compute `R0 + their own path`, and the
    /// later store silently drops the earlier one's binding. It is **terminal**,
    /// because the live index keeps both paths while the tracked root keeps one
    /// and nothing re-derives the root from the index afterwards — which makes it
    /// data loss in every downstream consumer of the root (the version a write
    /// gets captured in, the published root a follower syncs from).
    ///
    /// `trie_put`/`trie_remove` are pure functions of `(root, rel, hash)`, so a
    /// CAS miss is repaired by re-reading and recomputing; the retry converges
    /// because each attempt observes a strictly newer root. EXTENSION-REVISION
    /// §6.1 "Contention handling" names CAS+retry as a conformant mechanism.
    /// Exhaustion is reported to the caller rather than swallowed — see
    /// [`Self::on_tree_change`].
    fn apply_event(
        &self,
        bare_prefix: &str,
        event: &TreeChangeEvent,
        ctx: Option<&ExecutionContext>,
    ) -> Result<(), String> {
        let qualified = self.qualified_bare_prefix(bare_prefix);
        if !event.path.starts_with(&qualified) {
            return Ok(());
        }
        let rel = &event.path[qualified.len()..];
        let path = self.qualified_root_path(bare_prefix);

        for _ in 0..MAX_ROOT_CAS_RETRIES {
            let current_root = self.load_tracked_root(bare_prefix);

            let new_root = match event.new_hash {
                Some(new) => trie::trie_put(self.content_store.as_ref(), current_root, rel, new),
                None => trie::trie_remove(self.content_store.as_ref(), current_root, rel),
            }
            .map_err(|e| e.to_string())?;

            // Nothing to do — this event is already reflected in the root.
            if current_root == Some(new_root) {
                return Ok(());
            }

            let outcome = match current_root {
                Some(expected) => match ctx {
                    Some(c) => self
                        .location_index
                        .compare_and_swap_with_context(&path, expected, new_root, c.clone())
                        .map(|_| ()),
                    None => self
                        .location_index
                        .compare_and_swap(&path, expected, new_root),
                },
                None => match ctx {
                    Some(c) => self
                        .location_index
                        .compare_and_create_with_context(&path, new_root, c.clone())
                        .map(|_| ()),
                    None => self.location_index.compare_and_create(&path, new_root),
                },
            };

            match outcome {
                Ok(()) => {
                    tracing::info!(
                        prefix = %bare_prefix,
                        path = %event.path,
                        root = %new_root,
                        "[root-tracker] update"
                    );
                    return Ok(());
                }
                // Another thread's cascade advanced the root between our read and
                // our write. Re-read and re-apply this event onto the newer root.
                Err(entity_store::CasError::Mismatch(_))
                | Err(entity_store::CasError::NotFound) => continue,
            }
        }

        Err(format!(
            "tracked root at {} lost {} CAS races — this event is not reflected in the root",
            path, MAX_ROOT_CAS_RETRIES
        ))
    }

    fn handle_config_change(&self, event: &TreeChangeEvent, ctx: Option<&ExecutionContext>) {
        // Decode the new config if present.
        let new_cfg = event
            .new_hash
            .and_then(|h| self.content_store.get(&h))
            .as_ref()
            .and_then(decode_tracking_config);

        let previous_cfg = event
            .previous_hash
            .and_then(|h| self.content_store.get(&h))
            .as_ref()
            .and_then(decode_tracking_config);

        match (previous_cfg.as_ref(), new_cfg.as_ref()) {
            (None, Some(cfg)) if cfg.enabled => {
                self.rebuild_prefix(&cfg.prefix);
            }
            (Some(prev), Some(cfg)) => {
                if prev.prefix != cfg.prefix {
                    // Prefix changed: clear the old root and rebuild for the new one.
                    self.remove_tracked_root(&prev.prefix, ctx);
                    if cfg.enabled {
                        self.rebuild_prefix(&cfg.prefix);
                    }
                } else if prev.enabled && !cfg.enabled {
                    self.remove_tracked_root(&cfg.prefix, ctx);
                } else if !prev.enabled && cfg.enabled {
                    self.rebuild_prefix(&cfg.prefix);
                }
            }
            (Some(prev), None) => {
                // Config removed — clear the tracked root.
                self.remove_tracked_root(&prev.prefix, ctx);
            }
            _ => {}
        }
    }
}

impl SyncTreeHook for RootTrackerEngine {
    fn on_tree_change(
        &self,
        event: &TreeChangeEvent,
        ctx: &mut ExecutionContext,
    ) -> Result<(), entity_store::CascadeHalt> {
        if self.is_self_path(&event.path) {
            return Ok(());
        }

        // Break the feedback cycles a wide tracked prefix opens up: a consumer
        // that writes *about* the tree from inside the tracked prefix would
        // otherwise advance the root and re-trigger itself. See
        // `is_feedback_loop_handler`.
        if let Some(pattern) = event
            .context
            .as_ref()
            .and_then(|c| c.handler_pattern.as_deref())
        {
            if is_feedback_loop_handler(pattern) {
                return Ok(());
            }
        }

        if event.path.starts_with(&self.config_path_prefix) {
            self.handle_config_change(event, Some(ctx));
            self.refresh_cache();
            return Ok(());
        }

        // Hot path: read cached configs instead of scanning + decoding the
        // index on every tree mutation. Scope the read lock so apply_event
        // (which writes the index → re-enters this hook for the root path)
        // can't deadlock against another thread upgrading the cache.
        let configs: Vec<TrackingConfig> = {
            let guard = self.cached_configs.read().unwrap();
            if guard.is_empty() {
                return Ok(());
            }
            guard.clone()
        };
        for cfg in configs {
            if !cfg.enabled {
                continue;
            }
            // A tracked root that silently lost this write is data loss with no
            // later event to repair it (the last write of a burst has no next
            // event), so the failure is surfaced to the writer rather than
            // logged and dropped.
            if let Err(e) = self.apply_event(&cfg.prefix, event, Some(ctx)) {
                tracing::error!(
                    prefix = %cfg.prefix,
                    path = %event.path,
                    error = %e,
                    "tree: tracked-root update failed — halting cascade"
                );
                return Err(entity_store::CascadeHalt {
                    consumer_name: self.name().to_string(),
                    error_code: 500,
                    error_message: format!("tracked-root update failed: {}", e),
                    is_error: false,
                });
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "tree/root-tracker"
    }

    fn handler_pattern(&self) -> &str {
        "system/tree"
    }
}

// ---------------------------------------------------------------------------
// Entity encoders / decoders
// ---------------------------------------------------------------------------

fn decode_tracking_config(entity: &Entity) -> Option<TrackingConfig> {
    if entity.entity_type != "system/tree/tracking-config" {
        return None;
    }
    let value: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).ok()?;
    let map = value.as_map()?;
    let mut prefix = None;
    let mut enabled = None;
    for (k, v) in map {
        match k.as_text()? {
            "prefix" => prefix = v.as_text().map(|s| s.to_string()),
            "enabled" => enabled = v.as_bool(),
            _ => {}
        }
    }
    let prefix = prefix?;
    if !prefix.ends_with('/') {
        return None;
    }
    Some(TrackingConfig {
        prefix,
        enabled: enabled.unwrap_or(false),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use entity_store::{MemoryContentStore, MemoryLocationIndex};
    use std::collections::BTreeMap;

    fn peer_id() -> String {
        "peerTEST".to_string()
    }

    fn make_entity(et: &str, data_str: &str) -> Entity {
        let data = entity_ecf::to_ecf(&entity_ecf::text(data_str));
        Entity::new(et, data).unwrap()
    }

    fn make_tracking_config_entity(prefix: &str, enabled: bool) -> Entity {
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("enabled"), entity_ecf::bool_val(enabled)),
            (entity_ecf::text("prefix"), entity_ecf::text(prefix)),
        ]));
        Entity::new("system/tree/tracking-config", data).unwrap()
    }

    fn setup() -> (
        Arc<MemoryContentStore>,
        Arc<MemoryLocationIndex>,
        Arc<RootTrackerEngine>,
    ) {
        let cs: Arc<MemoryContentStore> = Arc::new(MemoryContentStore::new());
        let li: Arc<MemoryLocationIndex> = Arc::new(MemoryLocationIndex::new());
        let engine = Arc::new(RootTrackerEngine::new(cs.clone(), li.clone(), peer_id()));
        (cs, li, engine)
    }

    /// Store an entity at a path (under the peer's qualified prefix).
    fn put_at(cs: &dyn ContentStore, li: &dyn LocationIndex, path: &str, entity: Entity) -> Hash {
        let hash = cs.put(entity).unwrap();
        li.set(path, hash);
        hash
    }

    fn synthetic_event(
        path: &str,
        new_hash: Option<Hash>,
        previous_hash: Option<Hash>,
    ) -> TreeChangeEvent {
        TreeChangeEvent {
            path: path.to_string(),
            hash: new_hash.or(previous_hash).unwrap_or(Hash::zero()),
            previous_hash,
            new_hash,
            change_type: if new_hash.is_some() {
                if previous_hash.is_some() {
                    entity_store::ChangeType::Modified
                } else {
                    entity_store::ChangeType::Created
                }
            } else {
                entity_store::ChangeType::Deleted
            },
            context: None,
        }
    }

    #[test]
    fn self_guard_skips_root_paths() {
        let (cs, li, engine) = setup();
        // Install a config for prefix "project/".
        let cfg = make_tracking_config_entity("project/", true);
        put_at(
            cs.as_ref(),
            li.as_ref(),
            &format!("/{}/system/tree/tracking-config/project", peer_id()),
            cfg,
        );
        engine.bootstrap();

        // Simulate an event at a root path — should be ignored entirely.
        let bogus = Hash::compute("t", b"bogus");
        let mut ctx = ExecutionContext::default();
        let event = synthetic_event(
            &format!("/{}/system/tree/root/project", peer_id()),
            Some(bogus),
            None,
        );
        // Should not panic or overwrite the root.
        let _ = engine.on_tree_change(&event, &mut ctx);

        // The existing tracked root (from bootstrap) must still decode.
        let tracked = engine.load_tracked_root("project/");
        assert!(tracked.is_some());
        // And it must differ from the bogus hash we tried to inject.
        assert_ne!(tracked.unwrap(), bogus);
    }

    #[test]
    fn tracks_put_updates_root() {
        let (cs, li, engine) = setup();
        let cfg = make_tracking_config_entity("project/", true);
        put_at(
            cs.as_ref(),
            li.as_ref(),
            &format!("/{}/system/tree/tracking-config/project", peer_id()),
            cfg,
        );
        engine.bootstrap();

        let hash_a = cs.put(make_entity("t", "a")).unwrap();
        li.set(&format!("/{}/project/src/a.rs", peer_id()), hash_a);
        let mut ctx = ExecutionContext::default();
        let _ = engine.on_tree_change(
            &synthetic_event(
                &format!("/{}/project/src/a.rs", peer_id()),
                Some(hash_a),
                None,
            ),
            &mut ctx,
        );

        let root = engine.load_tracked_root("project/").unwrap();
        let bindings = trie::collect_all_bindings(cs.as_ref(), root, "");
        assert_eq!(bindings.get("src/a.rs"), Some(&hash_a));
    }

    #[test]
    fn tracks_remove_updates_root() {
        let (cs, li, engine) = setup();
        let cfg = make_tracking_config_entity("project/", true);
        put_at(
            cs.as_ref(),
            li.as_ref(),
            &format!("/{}/system/tree/tracking-config/project", peer_id()),
            cfg,
        );

        let hash_a = cs.put(make_entity("t", "a")).unwrap();
        li.set(&format!("/{}/project/src/a.rs", peer_id()), hash_a);
        engine.bootstrap();

        // Now remove the binding and emit a Deleted event.
        li.remove(&format!("/{}/project/src/a.rs", peer_id()));
        let mut ctx = ExecutionContext::default();
        let _ = engine.on_tree_change(
            &synthetic_event(
                &format!("/{}/project/src/a.rs", peer_id()),
                None,
                Some(hash_a),
            ),
            &mut ctx,
        );

        let root = engine.load_tracked_root("project/").unwrap();
        let bindings = trie::collect_all_bindings(cs.as_ref(), root, "");
        assert!(bindings.is_empty());
    }

    #[test]
    fn config_disable_removes_tracked_root() {
        let (cs, li, engine) = setup();
        let enabled = make_tracking_config_entity("project/", true);
        let cfg_path = format!("/{}/system/tree/tracking-config/project", peer_id());
        put_at(cs.as_ref(), li.as_ref(), &cfg_path, enabled.clone());
        engine.bootstrap();
        assert!(engine.load_tracked_root("project/").is_some());

        // Replace with disabled config.
        let disabled = make_tracking_config_entity("project/", false);
        let old_hash = li.get(&cfg_path).unwrap();
        let new_hash = cs.put(disabled).unwrap();
        li.set(&cfg_path, new_hash);
        let mut ctx = ExecutionContext::default();
        let _ = engine.on_tree_change(
            &synthetic_event(&cfg_path, Some(new_hash), Some(old_hash)),
            &mut ctx,
        );
        assert!(engine.load_tracked_root("project/").is_none());
    }

    /// EXTENSION-TREE §3.4.1 path substitution, including the universal-prefix
    /// row of the spec's table (`"/"` → canonical `""` → `system/tree/root`,
    /// with no trailing separator). Getting that row wrong is not cosmetic: the
    /// old form wrote to `system/tree/root/`, which no consumer reads.
    #[test]
    fn root_storage_path_follows_3_4_1_substitution() {
        let (_, _, engine) = setup();
        let base = format!("/{}/system/tree/root", peer_id());
        assert_eq!(engine.qualified_root_path("/"), base);
        assert_eq!(
            engine.qualified_root_path("project/"),
            format!("{}/project", base)
        );
        assert_eq!(
            engine.qualified_root_path("project/src/"),
            format!("{}/project/src", base)
        );
    }

    /// The universal prefix tracks every path in the peer's tree. Before the
    /// §3.4.1 canonicalization fix this silently tracked nothing: the qualified
    /// prefix came out as `/{peer}//`, which no event path starts with, so
    /// every `apply_event` returned early and the root never moved.
    #[test]
    fn universal_prefix_tracks_the_whole_peer_subtree() {
        let (cs, li, engine) = setup();
        let cfg = make_tracking_config_entity("/", true);
        let cfg_rel = "system/tree/tracking-config/universal";
        let cfg_hash = put_at(
            cs.as_ref(),
            li.as_ref(),
            &format!("/{}/{}", peer_id(), cfg_rel),
            cfg,
        );
        engine.bootstrap();

        let mut ctx = ExecutionContext::default();
        let mut expected = BTreeMap::new();
        // The config binding itself is under the universal prefix, so the
        // tracked trie legitimately carries it.
        expected.insert(cfg_rel.to_string(), cfg_hash);
        for (i, rel) in ["system/content/public/a", "local/files/docs/b"]
            .iter()
            .enumerate()
        {
            let hash = cs.put(make_entity("t", &format!("e{}", i))).unwrap();
            let abs = format!("/{}/{}", peer_id(), rel);
            li.set(&abs, hash);
            let _ = engine.on_tree_change(&synthetic_event(&abs, Some(hash), None), &mut ctx);
            expected.insert(rel.to_string(), hash);
        }

        let tracked = engine
            .tracked_root("/")
            .expect("universal prefix must maintain a root");
        // Keys are peer-prefix-stripped under the universal prefix — the
        // convention `PublishedRootClient::resolve` walks with.
        assert_eq!(tracked, trie::build_trie(cs.as_ref(), &expected).unwrap());
    }

    /// Under the universal prefix the tracker's own output binding is
    /// `/{peer}/system/tree/root` — no trailing `/`, so the prefix half of the
    /// self-guard does not cover it. Left unguarded, writing the root re-enters
    /// the tracker and folds the root hash into the trie that produced it.
    #[test]
    fn self_guard_covers_the_unsuffixed_universal_root_path() {
        let (cs, li, engine) = setup();
        let cfg = make_tracking_config_entity("/", true);
        put_at(
            cs.as_ref(),
            li.as_ref(),
            &format!("/{}/system/tree/tracking-config/universal", peer_id()),
            cfg,
        );
        engine.bootstrap();
        let before = engine.tracked_root("/").unwrap();

        let bogus = Hash::compute("t", b"bogus");
        let mut ctx = ExecutionContext::default();
        let root_path = format!("/{}/system/tree/root", peer_id());
        let _ = engine.on_tree_change(&synthetic_event(&root_path, Some(bogus), None), &mut ctx);

        assert_eq!(
            engine.tracked_root("/").unwrap(),
            before,
            "a write at the universal root path must not advance the root"
        );
    }

    /// Writes tagged by a feedback-loop consumer never move the trie root.
    /// This is what stops the published-root publisher (whose manifest and
    /// signature both land under `system/`) from re-triggering itself, and the
    /// tracker→history→tracker cycle that runs with no publisher at all.
    #[test]
    fn feedback_loop_handler_writes_do_not_move_the_root() {
        let (cs, li, engine) = setup();
        let cfg = make_tracking_config_entity("/", true);
        put_at(
            cs.as_ref(),
            li.as_ref(),
            &format!("/{}/system/tree/tracking-config/universal", peer_id()),
            cfg,
        );
        engine.bootstrap();
        let before = engine.tracked_root("/").unwrap();

        for pattern in [PUBLISHED_ROOT_HANDLER_PATTERN, "system/history"] {
            let hash = cs.put(make_entity("t", pattern)).unwrap();
            let abs = format!("/{}/system/peer/published-root", peer_id());
            li.set(&abs, hash);
            let mut event = synthetic_event(&abs, Some(hash), None);
            event.context = Some(ExecutionContext {
                handler_pattern: Some(pattern.to_string()),
                ..Default::default()
            });
            let mut ctx = ExecutionContext::default();
            let _ = engine.on_tree_change(&event, &mut ctx);
            assert_eq!(
                engine.tracked_root("/").unwrap(),
                before,
                "{pattern} write must not advance the tracked root"
            );
        }

        // Control: the same write untagged DOES advance it, so the assertions
        // above are about the tag and not about the path.
        let hash = cs.put(make_entity("t", "untagged")).unwrap();
        let abs = format!("/{}/system/peer/published-root", peer_id());
        li.set(&abs, hash);
        let mut ctx = ExecutionContext::default();
        let _ = engine.on_tree_change(&synthetic_event(&abs, Some(hash), None), &mut ctx);
        assert_ne!(engine.tracked_root("/").unwrap(), before);
    }

    #[test]
    fn incremental_root_matches_full_rebuild() {
        let (cs, li, engine) = setup();
        let cfg = make_tracking_config_entity("project/", true);
        put_at(
            cs.as_ref(),
            li.as_ref(),
            &format!("/{}/system/tree/tracking-config/project", peer_id()),
            cfg,
        );
        engine.bootstrap();

        let paths = [
            "src/main.rs",
            "src/lib.rs",
            "Cargo.toml",
            "tests/unit.rs",
            "tests/integration.rs",
            "docs/README.md",
        ];
        let mut expected = BTreeMap::new();
        let mut ctx = ExecutionContext::default();
        for (i, rel) in paths.iter().enumerate() {
            let entity = make_entity("t", &format!("e{}", i));
            let hash = cs.put(entity).unwrap();
            let abs = format!("/{}/project/{}", peer_id(), rel);
            li.set(&abs, hash);
            let _ = engine.on_tree_change(&synthetic_event(&abs, Some(hash), None), &mut ctx);
            expected.insert(rel.to_string(), hash);
        }

        // Remove one, insert another.
        let abs_main = format!("/{}/project/src/main.rs", peer_id());
        let prev_main = li.get(&abs_main).unwrap();
        li.remove(&abs_main);
        let _ = engine.on_tree_change(&synthetic_event(&abs_main, None, Some(prev_main)), &mut ctx);
        expected.remove("src/main.rs");

        let extra_entity = make_entity("t", "new");
        let extra_hash = cs.put(extra_entity).unwrap();
        let abs_extra = format!("/{}/project/src/extra.rs", peer_id());
        li.set(&abs_extra, extra_hash);
        let _ = engine.on_tree_change(
            &synthetic_event(&abs_extra, Some(extra_hash), None),
            &mut ctx,
        );
        expected.insert("src/extra.rs".to_string(), extra_hash);

        let tracked = engine.load_tracked_root("project/").unwrap();
        let from_build = trie::build_trie(cs.as_ref(), &expected).unwrap();
        assert_eq!(tracked, from_build);
    }

    // -----------------------------------------------------------------------
    // Concurrent-burst capture loss (the lost-update half)
    // -----------------------------------------------------------------------

    /// A `LocationIndex` that fires a one-shot injected write the first time the
    /// tracked-root path is read, AFTER sampling the value the caller will get
    /// back. That reproduces the exact interleave two concurrent cascades hit —
    /// thread A reads root `R0`, thread B lands `R0 + pathB`, thread A then
    /// writes `R0 + pathA` over it — deterministically, in one thread.
    ///
    /// This is the forced-interleave net the mechanism needs. A load test can
    /// only show the bug when the scheduler cooperates; this one cannot pass
    /// against a read-modify-write that does not re-check what it read.
    struct InterleaveOnRead {
        inner: Arc<MemoryLocationIndex>,
        watch_path: String,
        injection: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
    }

    impl InterleaveOnRead {
        fn new(inner: Arc<MemoryLocationIndex>, watch_path: &str) -> Arc<Self> {
            Arc::new(Self {
                inner,
                watch_path: watch_path.to_string(),
                injection: std::sync::Mutex::new(None),
            })
        }
        fn arm(&self, f: Box<dyn FnOnce() + Send>) {
            *self.injection.lock().unwrap() = Some(f);
        }
    }

    impl LocationIndex for InterleaveOnRead {
        fn get(&self, path: &str) -> Option<Hash> {
            // Sample first: this is the stale value the racing writer's store
            // will invalidate a moment later.
            let sampled = self.inner.get(path);
            if path == self.watch_path {
                let taken = self.injection.lock().unwrap().take();
                if let Some(f) = taken {
                    f();
                }
            }
            sampled
        }
        fn set(&self, path: &str, hash: Hash) {
            self.inner.set(path, hash)
        }
        fn has(&self, path: &str) -> bool {
            self.inner.has(path)
        }
        fn remove(&self, path: &str) -> Option<Hash> {
            self.inner.remove(path)
        }
        fn list(&self, prefix: &str) -> Vec<entity_store::LocationEntry> {
            self.inner.list(prefix)
        }
        fn len_prefix(&self, prefix: &str) -> usize {
            self.inner.len_prefix(prefix)
        }
        // Forward the CAS trio to the inner index — the default trait impls are
        // a non-atomic get+set, which would defeat the very thing under test.
        fn compare_and_swap(
            &self,
            path: &str,
            expected: Hash,
            new_hash: Hash,
        ) -> Result<(), entity_store::CasError> {
            self.inner.compare_and_swap(path, expected, new_hash)
        }
        fn compare_and_remove(
            &self,
            path: &str,
            expected: Hash,
        ) -> Result<Hash, entity_store::CasError> {
            self.inner.compare_and_remove(path, expected)
        }
        fn compare_and_create(
            &self,
            path: &str,
            new_hash: Hash,
        ) -> Result<(), entity_store::CasError> {
            self.inner.compare_and_create(path, new_hash)
        }
    }

    /// EXTENSION-TREE §3.4 — the tracked root MUST reflect every write under the
    /// prefix, including two that land concurrently.
    ///
    /// `apply_event` is a read-`trie_put`-store cycle and sync hooks run under no
    /// cross-thread lock (`NotifyingLocationIndex::set_impl` dispatches with
    /// nothing held), so with a plain `set` the second store clobbers the first
    /// and the live index keeps a path the tracked root has lost — permanently,
    /// since nothing re-derives the root from the index afterwards.
    ///
    /// **Mutation:** replace the CAS in `apply_event` with
    /// `self.store_tracked_root(bare_prefix, new_root, ctx)` and this goes RED
    /// with `racer.md` missing from the tracked root.
    #[test]
    fn concurrent_root_update_does_not_clobber_the_racing_write() {
        let cs: Arc<MemoryContentStore> = Arc::new(MemoryContentStore::new());
        let raw: Arc<MemoryLocationIndex> = Arc::new(MemoryLocationIndex::new());
        let root_path = format!("/{}/system/tree/root/project", peer_id());
        let li = InterleaveOnRead::new(raw.clone(), &root_path);
        let engine = Arc::new(RootTrackerEngine::new(
            cs.clone(),
            li.clone() as Arc<dyn LocationIndex>,
            peer_id(),
        ));

        let cfg = make_tracking_config_entity("project/", true);
        put_at(
            cs.as_ref(),
            li.as_ref(),
            &format!("/{}/system/tree/tracking-config/project", peer_id()),
            cfg,
        );
        engine.bootstrap();

        // The racing writer: lands `racer.md` in the live index and advances the
        // tracked root to include it, in the window between our read and write.
        let racer_hash = cs.put(make_entity("test/doc", "racer")).unwrap();
        let racer_path = format!("/{}/project/racer.md", peer_id());
        {
            let cs2 = cs.clone();
            let li2 = li.clone();
            let engine2 = engine.clone();
            let racer_path2 = racer_path.clone();
            let root_path2 = root_path.clone();
            li.arm(Box::new(move || {
                li2.inner.set(&racer_path2, racer_hash);
                let base = li2.inner.get(&root_path2);
                let advanced = trie::trie_put(cs2.as_ref(), base, "racer.md", racer_hash).unwrap();
                li2.inner.set(&root_path2, advanced);
                drop(engine2);
            }));
        }

        // Our write: `ours.md`. Its apply_event reads the root (firing the
        // injection), then must not overwrite what the racer stored.
        let ours_hash = cs.put(make_entity("test/doc", "ours")).unwrap();
        let ours_path = format!("/{}/project/ours.md", peer_id());
        li.inner.set(&ours_path, ours_hash);
        let mut ctx = ExecutionContext::default();
        let event = synthetic_event(&ours_path, Some(ours_hash), None);
        engine.on_tree_change(&event, &mut ctx).unwrap();

        // Both paths are in the live index; both MUST be in the tracked root.
        let tracked = engine.load_tracked_root("project/").expect("tracked root");
        let bindings = trie::collect_all_bindings(cs.as_ref(), tracked, "");
        assert_eq!(
            bindings.get("ours.md"),
            Some(&ours_hash),
            "our own write is missing from the tracked root"
        );
        assert_eq!(
            bindings.get("racer.md"),
            Some(&racer_hash),
            "the concurrent write was clobbered — tracked root lost a path the live index still has \
             (this is the last-burst-write loss: live tree has it, no version does)"
        );
    }

    /// The control for the test above: with no racing writer, the ordinary
    /// single-write path still lands. Fails if the CAS loop is wired so that a
    /// first-ever root (the `compare_and_create` arm) never stores.
    #[test]
    fn uncontended_root_update_still_lands() {
        let (cs, li, engine) = setup();
        let cfg = make_tracking_config_entity("project/", true);
        put_at(
            cs.as_ref(),
            li.as_ref(),
            &format!("/{}/system/tree/tracking-config/project", peer_id()),
            cfg,
        );
        engine.bootstrap();

        let h = cs.put(make_entity("test/doc", "solo")).unwrap();
        let p = format!("/{}/project/solo.md", peer_id());
        li.set(&p, h);
        let mut ctx = ExecutionContext::default();
        engine
            .on_tree_change(&synthetic_event(&p, Some(h), None), &mut ctx)
            .unwrap();

        let tracked = engine.load_tracked_root("project/").expect("tracked root");
        assert_eq!(
            trie::collect_all_bindings(cs.as_ref(), tracked, "").get("solo.md"),
            Some(&h)
        );
    }
}
