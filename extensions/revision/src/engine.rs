//! Revision engine — per-write auto-versioning (SyncTreeHook).
//!
//! Implements PROPOSAL-REVISION-AUTO-VERSION-FIX §6.1 as a synchronous emit
//! pathway consumer registered at SYSTEM-COMPOSITION §2.2 position 7, after
//! the structural-summaries root tracker (position 6) and before subscription
//! (position 8).
//!
//! For each tree write that matches a tracked prefix:
//!   1. Reads the tracked root from `system/tree/root/{canonical P}`.
//!   2. If `current_head.data.root == tracked_root`, dedups (no-op).
//!   3. Otherwise creates a `system/revision/entry` with
//!      `{root: tracked_root, parents: [current_head]}` and advances head.
//!   4. Advances the active-branch pointer when set.
//!
//! If auto-version is enabled for a prefix but the tracking-config / tracked
//! root binding is absent, the per-write invariant (§3 item 1) cannot be
//! satisfied: the error is logged (see §6.1 "Internal failure handling" /
//! §6D.5). Cascade-halt is not available through the current SyncTreeHook
//! interface — tracked as an implementation gap.

use std::sync::{Arc, RwLock};

use entity_entity::Entity;
use entity_hash::Hash;
use entity_store::{
    ChangeType, ContentStore, ExecutionContext, LocationIndex, SyncTreeHook, TreeChangeEvent,
};

use crate::dag::{build_revision_entry, decode_revision_entry, RevisionEntryData};
use entity_tree::trie;

// ---------------------------------------------------------------------------
// RevisionEngine — auto-version SyncTreeHook (spec position 7)
// ---------------------------------------------------------------------------

pub struct RevisionEngine {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    local_peer_id_str: String,
    /// Pre-computed `/{peer_id}/system/revision/` prefix for reentrancy guard
    /// and config listing (hash-addressed subtrees live under this prefix).
    revision_path_prefix: String,
    /// Pre-computed `/{peer_id}/system/tree/root/` for tracked-root lookups.
    root_path_prefix: String,
    /// Cached auto-version configs. Populated lazily from `None`. Invalidated
    /// when an event arrives at any `{revision_prefix}{66hex}/config` path so
    /// the hot path doesn't scan + decode the revision subtree per put.
    cached_configs: RwLock<Option<Vec<RevisionConfig>>>,
}

impl RevisionEngine {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id_str: String,
    ) -> Self {
        let revision_path_prefix = format!("/{}/system/revision/", &local_peer_id_str);
        let root_path_prefix = format!("/{}/system/tree/root/", &local_peer_id_str);
        Self {
            content_store,
            location_index,
            local_peer_id_str,
            revision_path_prefix,
            root_path_prefix,
            cached_configs: RwLock::new(None),
        }
    }

    fn invalidate_config_cache(&self) {
        *self.cached_configs.write().unwrap() = None;
    }

    /// Storage path for the tracked root of a given canonical prefix
    /// (EXTENSION-TREE §3.4.1 path-substitution rule, §6B Amendment 1).
    fn tracked_root_path(&self, canonical: &str) -> String {
        if canonical.is_empty() {
            // Universal tree canonical form.
            format!("/{}/system/tree/root", self.local_peer_id_str)
        } else {
            format!("{}{}", self.root_path_prefix, canonical)
        }
    }

    /// Match a bare event path (relative to peer) against one config's prefix
    /// and exclude list. Returns true if auto-version should fire for this
    /// event under this config.
    fn config_matches(&self, event_bare_path: &str, config: &RevisionConfig) -> bool {
        let canonical = canonicalize_prefix(&config.prefix);
        let relative = if canonical.is_empty() {
            event_bare_path
        } else if let Some(r) = event_bare_path.strip_prefix(&format!("{}/", canonical)) {
            r
        } else if event_bare_path == canonical {
            ""
        } else {
            return false;
        };

        // Reentrancy: required excludes for universal-tree configs are
        // validated at coordination time (engine::validate_revision_config).
        // Here we only filter per the config's declared excludes.
        for pat in &config.exclude {
            if glob_match(pat, relative) {
                return false;
            }
        }
        true
    }

    /// Load + decode every auto-version-enabled config from the location index.
    /// Used by `cached_auto_version_configs` on cache miss and by the bootstrap
    /// path; not called per put.
    fn load_auto_version_configs(&self) -> Vec<RevisionConfig> {
        let mut result = Vec::new();
        let entries = self.location_index.list(&self.revision_path_prefix);
        for entry in entries {
            if !is_prefix_config_path(&entry.path, &self.revision_path_prefix) {
                continue;
            }
            let Some(entity) = self.content_store.get(&entry.hash) else {
                continue;
            };
            if entity.entity_type != "system/revision/config" {
                continue;
            }
            let Some(config) = decode_revision_config(&entity.data) else {
                continue;
            };
            if !config.auto_version {
                continue;
            }
            result.push(config);
        }
        result
    }

    /// Read-through cache for auto-version configs.
    fn cached_auto_version_configs(&self) -> Vec<RevisionConfig> {
        if let Some(ref cached) = *self.cached_configs.read().unwrap() {
            return cached.clone();
        }
        let loaded = self.load_auto_version_configs();
        *self.cached_configs.write().unwrap() = Some(loaded.clone());
        loaded
    }

    /// Collect configs whose `auto_version` is true and whose prefix + excludes
    /// match the event. Reads from the cached config list (refreshed on writes
    /// under the revision prefix-config subtree).
    fn matching_configs(&self, bare_path: &str) -> Vec<RevisionConfig> {
        self.cached_auto_version_configs()
            .into_iter()
            .filter(|c| self.config_matches(bare_path, c))
            .collect()
    }

    /// Apply the config's `exclude` / `exclude_types` to the tracked root, so
    /// the auto-version path emits the trie `commit` builds for the same live
    /// state and config (EXTENSION-REVISION §6.1 D1).
    ///
    /// **The O(1) adoption is preserved exactly**: with neither field set the
    /// filtered trie IS the tracked root by construction (§6.1 states this
    /// normatively), and it is returned with no walk and no rebuild — every
    /// non-filtering config, the common case, pays nothing per put. A config
    /// that does filter pays a trie rebuild per emit, which is the cost §6.1
    /// requires; the alternative is minting version identities that disagree
    /// across peers.
    fn filtered_root(&self, tracked_root: Hash, config: &RevisionConfig) -> Result<Hash, String> {
        if config.exclude.is_empty() && config.exclude_types.is_empty() {
            return Ok(tracked_root);
        }

        let store = self.content_store.as_ref();
        let mut filtered = std::collections::BTreeMap::new();
        for (relative, hash) in trie::collect_all_bindings(store, tracked_root, "") {
            if config.exclude.iter().any(|p| glob_match(p, &relative)) {
                continue;
            }
            if !config.exclude_types.is_empty() {
                if let Some(entity) = store.get(&hash) {
                    if config
                        .exclude_types
                        .iter()
                        .any(|p| glob_match(p, &entity.entity_type))
                    {
                        continue;
                    }
                }
            }
            filtered.insert(relative, hash);
        }
        trie::build_trie(store, &filtered)
    }

    /// Execute the per-write auto-version algorithm for one config
    /// (PROPOSAL-REVISION-AUTO-VERSION-FIX §6.1).
    fn auto_version_once(
        &self,
        config: &RevisionConfig,
        ctx: &ExecutionContext,
    ) -> Result<(), String> {
        let canonical = canonicalize_prefix(&config.prefix);
        let tracked_root_path = self.tracked_root_path(&canonical);

        // Resolve prefix to absolute form, then compute the hash-addressed
        // subtree key (EXTENSION-REVISION v3.0 §3.1).
        let abs_prefix = crate::resolve_prefix(&config.prefix, &self.local_peer_id_str);
        let ph = crate::prefix_hash(&abs_prefix);

        let head_path = crate::rev_head_path(&self.local_peer_id_str, &ph);

        for _ in 0..MAX_HEAD_CAS_RETRIES {
            // READ THE HEAD BEFORE THE TRACKED ROOT. The order is the invariant,
            // not a style choice. Within one writer's cascade the root tracker
            // (position 6) stores the tracked root strictly before this hook
            // (position 7) advances the head, so observing another thread's head
            // write implies its tracked-root store is already visible — reading
            // the head first therefore guarantees the root we read below is at
            // least as new as the head we will chain from. Reversed, a thread can
            // read a stale root, then read a head that another writer has since
            // advanced, and CAS a version that drops that writer's path with the
            // dedup check passing.
            let current_head = self.location_index.get(&head_path);

            // §6.1 precondition: tracked root must be populated. If absent, the
            // tracking-config coordination invariant is violated (§6D.5 MUST).
            let tracked_root = self.location_index.get(&tracked_root_path).ok_or_else(|| {
                format!(
                    "auto-version: tracking-config missing or disabled for prefix {:?} \
                     (no binding at {})",
                    config.prefix, tracked_root_path
                )
            })?;

            match self.try_emit_once(config, ctx, &head_path, &ph, current_head, tracked_root)? {
                EmitOutcome::Settled => return Ok(()),
                EmitOutcome::Contended => continue,
            }
        }

        Err(format!(
            "auto-version: head at {} lost {} CAS races — this write is in no version",
            head_path, MAX_HEAD_CAS_RETRIES
        ))
    }

    /// One attempt of the §6.1 emit: dedup, build, and CAS the head forward.
    ///
    /// Split out so the retry loop above has exactly one exit per outcome.
    /// `current_head` and `tracked_root` are the values the caller observed, in
    /// that order; a CAS miss means another cascade advanced the head underneath
    /// us and the caller must re-observe both.
    #[allow(clippy::too_many_arguments)]
    fn try_emit_once(
        &self,
        config: &RevisionConfig,
        ctx: &ExecutionContext,
        head_path: &str,
        ph: &str,
        current_head: Option<Hash>,
        tracked_root: Hash,
    ) -> Result<EmitOutcome, String> {
        // D1 (§6.1) — the version root is the EXCLUDE-FILTERED trie, the same
        // computation `handle_commit` performs; it is NOT the raw tracked root.
        // The tracked root comes from EXTENSION-TREE §3.4.1a's structural
        // summary, which knows nothing of any revision `exclude` ("a direct
        // pointer", no filtering stage) — so adopting it wholesale emitted, one
        // write late, a version whose root committed to exactly the data the
        // config says is not versioned. Suppressing the version FOR an excluded
        // write (`config_matches`, above) is the emission gate, and conflating
        // it with the filter is the trap the ruling names: a version entry's
        // identity IS its root, so the same tree state under the same config
        // minted two different entry hashes depending on which path emitted it.
        let version_root = self.filtered_root(tracked_root, config)?;

        // Dedup: if current head already records this root, nothing to do.
        if let Some(h) = current_head {
            if let Some(entry) = self
                .content_store
                .get(&h)
                .and_then(|e| decode_revision_entry(&e))
            {
                if entry.root == version_root {
                    return Ok(EmitOutcome::Settled);
                }
            }
        }

        // Build and store the new revision entry.
        let mut parents: Vec<Hash> = current_head.into_iter().collect();
        trie::sorted_parents(&mut parents);
        let entry = build_revision_entry(&RevisionEntryData {
            root: version_root,
            parents,
        })?;
        let entry_hash = self.content_store.put(entry).map_err(|e| e.to_string())?;

        // Advance head. §6.1 "Contention handling" names two conformant
        // mechanisms — CAS+retry, or single-writer-per-prefix serialization —
        // and this is the CAS one.
        //
        // It used to be a plain `set()`, justified by a comment claiming
        // SyncTreeHooks "fire synchronously within a single cascade thread" so
        // the serialization arm applied. **That claim was false.**
        // `NotifyingLocationIndex::set_impl` mutates the inner index and then
        // calls `dispatch_event` holding no lock at all, so N threads writing N
        // paths run N cascades — and N copies of this function — concurrently.
        // Two of them would read the same `current_head`, build two entries both
        // chained from it, and both `set()`: last writer wins and the loser's
        // version is orphaned, so the head commits to a root missing that
        // writer's path. Terminal, because the last write of a burst has no next
        // event to re-fire. Measured against a live peer as 4 of 8 concurrent
        // writes left in `status.pending` permanently.
        //
        // Single-writer-per-prefix was the other option and is NOT available
        // here: this write re-enters the cascade, and for a universal-prefix
        // config the path back through the root tracker re-enters this very
        // function for the same prefix — a per-prefix mutex would deadlock.
        let cas = match current_head {
            Some(expected) => self.location_index.compare_and_swap_with_context(
                head_path,
                expected,
                entry_hash,
                ctx.clone(),
            ),
            None => self.location_index.compare_and_create_with_context(
                head_path,
                entry_hash,
                ctx.clone(),
            ),
        };
        if cas.is_err() {
            // Another cascade advanced the head between our read and our write.
            // The entry we just put is unreferenced (content-store puts are
            // idempotent); the caller re-observes and rebuilds from the new head.
            return Ok(EmitOutcome::Contended);
        }

        // Advance active-branch pointer when set (§6.1 algorithm step 4).
        let ab_path = crate::rev_active_branch_path(&self.local_peer_id_str, ph);
        if let Some(ab_hash) = self.location_index.get(&ab_path) {
            if let Some(ab_entity) = self.content_store.get(&ab_hash) {
                if let Some(name) = decode_active_branch_name(&ab_entity) {
                    let branch_path = crate::rev_branch_path(&self.local_peer_id_str, ph, &name);
                    let _cascade =
                        self.location_index
                            .set_with_context(&branch_path, entry_hash, ctx.clone());
                }
            }
        }

        Ok(EmitOutcome::Settled)
    }
}

/// Result of one [`RevisionEngine::try_emit_once`] attempt.
///
/// `Contended` is not a failure: it means the head moved under us and the emit
/// must be rebuilt from the newer head. It is deliberately NOT an `Ok(())` the
/// caller can drop on the floor — the last write of a burst has no next event,
/// so an emit abandoned here is a write that ends up in no version at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EmitOutcome {
    Settled,
    Contended,
}

/// Bound on [`RevisionEngine::auto_version_once`]'s CAS-retry loop.
///
/// A losing attempt means another writer's cascade advanced this prefix's head
/// in between our read and our CAS, so the bound is a bound on simultaneous
/// writers to one tracked prefix. Exhaustion halts the cascade rather than
/// abandoning the emit quietly: `entity-core-go`'s equivalent give-up
/// ("next event will retry") is precisely what made the same class of loss
/// terminal there, and the last write of a burst has no next event.
const MAX_HEAD_CAS_RETRIES: usize = 64;

impl SyncTreeHook for RevisionEngine {
    fn on_tree_change(
        &self,
        event: &TreeChangeEvent,
        ctx: &mut ExecutionContext,
    ) -> Result<(), entity_store::CascadeHalt> {
        if event.path.starts_with(&self.revision_path_prefix) {
            // Writes under our own subtree don't trigger auto-version, but a
            // write to a `{revision_prefix}{66hex}/config` entry must
            // invalidate the cached config view so the next put sees fresh
            // configs.
            if is_prefix_config_path(&event.path, &self.revision_path_prefix) {
                self.invalidate_config_cache();
            }
            return Ok(());
        }

        let bare_path = match event
            .path
            .strip_prefix(&format!("/{}/", self.local_peer_id_str))
        {
            Some(s) => s,
            None => return Ok(()),
        };

        let configs = self.matching_configs(bare_path);
        if configs.is_empty() {
            return Ok(());
        }

        for config in configs {
            match self.auto_version_once(&config, ctx) {
                Ok(()) => tracing::debug!(
                    prefix = %config.prefix,
                    path = %event.path,
                    "revision: auto-version fired"
                ),
                Err(e) => {
                    tracing::error!(
                        prefix = %config.prefix,
                        path = %event.path,
                        error = %e,
                        "revision: auto-version failed — halting cascade"
                    );
                    return Err(entity_store::CascadeHalt {
                        consumer_name: self.name().to_string(),
                        error_code: 500,
                        error_message: format!("auto-version invariant violation: {}", e),
                        is_error: false,
                    });
                }
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "revision/auto-version"
    }

    fn handler_pattern(&self) -> &str {
        "system/revision"
    }
}

/// EXTENSION-REVISION §2.4 `glob_match` — the `exclude` / `exclude_types`
/// matcher, **exactly four forms and no others**, tested in the spec's order.
/// `subject` is the prefix-relative path for `exclude` and the entity type
/// name for `exclude_types`.
///
/// 1. `*` — MATCH-ALL.
/// 2. `<lit>/*` — SUBTREE PREFIX, identical to ENTITY-CORE-PROTOCOL §5.4
///    `matches_pattern`: the `*` crosses `/` at ANY depth. The trailing `*` is
///    dropped and the `/` is RETAINED, so `system/revision/*` reaches
///    `system/revision/head/{H}/deep` yet not the sibling `system/revisionary`.
///    This is why §6.1's Reentrancy exclusion needs no second wildcard.
/// 3. `*<lit>` — TRAILING LITERAL, a byte-suffix over the WHOLE subject; `/` is
///    NOT special. `*.cache` matches `a/b/foo.cache` and `.cache`, not
///    `a/cache/b` or `foo.cache.tmp`. The one form beyond §5.4's vocabulary, and
///    it exists for match-by-extension.
/// 4. `<lit>` — EXACT. `docs` matches `docs`, **not** `docs/x` — the old
///    literal-prefix fallback here was over-exclusion with no pattern
///    authorizing it.
///
/// The grammar is CLOSED and hash-determining: it decides trie membership,
/// membership decides the version `root`, and `root` is the version entry's
/// identity — two peers reading a pattern differently mint different version
/// hashes for identical content with nothing failing anywhere. There is no `**`
/// and no segment-scoped `*`; anything outside the four forms is refused at
/// config write by [`valid_exclude_pattern`] (§4.4.17 V6) and never reaches here.
pub(crate) fn glob_match(pattern: &str, subject: &str) -> bool {
    // 1. MATCH-ALL
    if pattern == "*" {
        return true;
    }
    // 2. SUBTREE PREFIX — drop the `*`, retain the `/`.
    if pattern.ends_with("/*") {
        return subject.starts_with(&pattern[..pattern.len() - 1]);
    }
    // 3. TRAILING LITERAL — whole-subject byte suffix.
    if let Some(lit) = pattern.strip_prefix('*') {
        return subject.ends_with(lit);
    }
    // 4. EXACT
    subject == pattern
}

/// EXTENSION-REVISION §4.4.17 **V6** — an `exclude` / `exclude_types` pattern
/// MUST be one of [`glob_match`]'s four forms and nothing else: at most one
/// `*`, positioned as the whole pattern, the final character after a `/`, or
/// the first character. `**`, `a/**/b`, `a*b` and `*a*` are all
/// `400 config/invalid-exclude-pattern`.
///
/// This is the load-bearing half of the rule. A matcher that merely *omits*
/// `**` and one that *rejects* it are indistinguishable until a config carries
/// one — and a stored pattern two peers evaluate differently is a DAG fork by
/// configuration. Refusing at write time is what makes the grammar closed
/// rather than merely described.
pub(crate) fn valid_exclude_pattern(pattern: &str) -> bool {
    match pattern.matches('*').count() {
        0 => true, // form 4 — exact
        1 => {
            pattern == "*"                  // form 1
                || pattern.ends_with("/*")  // form 2 — final char, preceded by `/`
                || pattern.starts_with('*') // form 3 — first char
        }
        _ => false, // two or more `*`
    }
}

/// Test whether `path` is a hash-addressed prefix config entry under
/// `revision_prefix` (= `/{pid}/system/revision/`). The expected shape is
/// `{revision_prefix}{hex(H)}/config`.
///
/// **The hex width follows the hash's own leading format byte and is never a
/// constant** (`SPECIFICATION-FORMAT` §8.4.5): 66 chars under ECFv1-SHA-256
/// (`00`), 98 under ECFv1-SHA-384 (`01`). The former fixed-66 was silent while
/// one algorithm shipped and stopped recognising the peer's *own* prefix-config
/// entries the moment its home format was SHA-384 — the writer emits
/// `Hash::to_hex`, which is format-relative, so this reader disagreed with its
/// own writer. Checking the declared format's implied length is strictly
/// stronger than a constant: it also rejects a 98-char string claiming `00`.
fn is_prefix_config_path(path: &str, revision_prefix: &str) -> bool {
    let rest = match path.strip_prefix(revision_prefix) {
        Some(r) => r,
        None => return false,
    };
    let hash_part = match rest.strip_suffix("/config") {
        Some(h) => h,
        None => return false,
    };
    if !hash_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    hex_width_matches_its_format_byte(hash_part)
}

/// Whether `hex` is a full-wire-form content-hash hex whose character count is
/// the one its own leading format byte implies (§8.4.5). Single-byte format
/// codes only — no multi-byte LEB128 code is allocated (v7.67 §5.4).
fn hex_width_matches_its_format_byte(hex: &str) -> bool {
    if hex.len() < 2 {
        return false;
    }
    let Ok(code) = u8::from_str_radix(&hex[0..2], 16) else {
        return false;
    };
    match entity_hash::digest_len_for_format(code) {
        Some(digest) => hex.len() == 2 + digest * 2,
        None => false,
    }
}

fn decode_active_branch_name(entity: &Entity) -> Option<String> {
    let val: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).ok()?;
    let map = val.as_map()?;
    for (k, v) in map {
        if k.as_text() == Some("name") {
            return v.as_text().map(|s| s.to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Config decoding
// ---------------------------------------------------------------------------

/// Default value for `merge_order` when unset — required for p2p convergence
/// across peers without coordination (PROPOSAL-REVISION-AUTO-VERSION-FIX §6D.1).
pub const DEFAULT_MERGE_ORDER: &str = "deterministic";

/// Default value for `checkout_under_auto_version` when unset
/// (PROPOSAL-REVISION-AUTO-VERSION-FIX §6A.4).
pub const DEFAULT_CHECKOUT_POLICY: &str = "warn";

/// Paths whose writes MUST be excluded from universal-tree auto-version to
/// avoid reentrancy cascades (PROPOSAL-REVISION-AUTO-VERSION-FIX §4 Reentrancy
/// + §6D.4). Each entry is a canonical-prefix form (no leading or trailing
///   slash) matched against a config's canonical prefix.
pub const REQUIRED_EXCLUDES: &[&str] = &[
    "system/revision",
    "system/tree/root",
    "system/tree/tracking-config",
    "system/history",
    "system/clock",
];

#[derive(Clone)]
pub struct RevisionConfig {
    pub prefix: String,
    pub auto_version: bool,
    pub merge_order: String,
    pub oscillation_depth: Option<u64>,
    pub exclude: Vec<String>,
    pub exclude_types: Vec<String>,
    pub checkout_under_auto_version: String,
}

pub fn decode_revision_config(data: &[u8]) -> Option<RevisionConfig> {
    let val: ciborium::Value = ciborium::from_reader(data).ok()?;
    let map = val.as_map()?;

    let mut prefix = None;
    let mut auto_version = false;
    let mut merge_order: Option<String> = None;
    let mut oscillation_depth = None;
    let mut exclude = Vec::new();
    let mut exclude_types = Vec::new();
    let mut checkout_policy: Option<String> = None;

    for (k, v) in map {
        match k.as_text()? {
            "prefix" => {
                prefix = v.as_text().map(|s| s.to_string());
            }
            "auto_version" => {
                auto_version = v.as_bool().unwrap_or(false);
            }
            "merge_order" => {
                merge_order = v.as_text().map(|s| s.to_string());
            }
            "oscillation_depth" => {
                oscillation_depth = v.as_integer().map(|i| i128::from(i) as u64);
            }
            "exclude" => {
                if let Some(arr) = v.as_array() {
                    for item in arr {
                        if let Some(s) = item.as_text() {
                            exclude.push(s.to_string());
                        }
                    }
                }
            }
            "exclude_types" => {
                if let Some(arr) = v.as_array() {
                    for item in arr {
                        if let Some(s) = item.as_text() {
                            exclude_types.push(s.to_string());
                        }
                    }
                }
            }
            "checkout_under_auto_version" => {
                checkout_policy = v.as_text().map(|s| s.to_string());
            }
            _ => {}
        }
    }

    Some(RevisionConfig {
        prefix: prefix?,
        auto_version,
        merge_order: merge_order.unwrap_or_else(|| DEFAULT_MERGE_ORDER.to_string()),
        oscillation_depth,
        exclude,
        exclude_types,
        checkout_under_auto_version: checkout_policy
            .unwrap_or_else(|| DEFAULT_CHECKOUT_POLICY.to_string()),
    })
}

/// Strip leading and trailing `/` from a prefix, yielding its canonical form.
/// `"/"` and `""` both collapse to `""` (the universal-tree canonical form).
/// Used for both storage-path substitution (EXTENSION-TREE §3.4.1) and
/// exclude-rule matching.
pub fn canonicalize_prefix(prefix: &str) -> String {
    prefix.trim_matches('/').to_string()
}

/// Validate a revision config against the PROPOSAL-REVISION-AUTO-VERSION-FIX
/// normative rules. Returns `Err` describing the first violation found.
///
/// Currently enforces:
/// - §6D.4 — when `auto_version: true` and the prefix encompasses a required-
///   exclude path, that path MUST appear (or be covered by) the `exclude` list.
/// - checkout policy and merge_order values are validated against the
///   enumerated options.
pub fn validate_revision_config(config: &RevisionConfig) -> Result<(), ConfigValidationError> {
    if config.prefix.is_empty() {
        return Err(ConfigValidationError {
            code: "config/invalid-prefix".into(),
            message: "prefix must not be empty".into(),
            status: 400,
        });
    }

    // V6 (§4.4.17) — every exclude / exclude_types pattern is one of §2.4's
    // four forms. Checked BEFORE the required-exclude coverage below, so a
    // pattern we cannot evaluate is never *interpreted* by a coverage check on
    // its way to being stored.
    for (field, patterns) in [
        ("exclude", &config.exclude),
        ("exclude_types", &config.exclude_types),
    ] {
        for pattern in patterns {
            if !valid_exclude_pattern(pattern) {
                return Err(ConfigValidationError {
                    code: "config/invalid-exclude-pattern".into(),
                    message: format!(
                        "{} pattern {:?} is not one of §2.4's four forms \
                         (*, <literal>/*, *<literal>, exact): a valid pattern has at most \
                         one *, either the whole pattern, the final char after a /, or the \
                         first char",
                        field, pattern
                    ),
                    status: 400,
                });
            }
        }
    }

    match config.merge_order.as_str() {
        "deterministic" | "caller-perspective" => {}
        other => {
            return Err(ConfigValidationError {
                code: "config/invalid-merge-order".into(),
                message: format!(
                    "merge_order {:?}: must be \"deterministic\" or \"caller-perspective\"",
                    other
                ),
                status: 400,
            });
        }
    }

    if let Some(depth) = config.oscillation_depth {
        if depth < 2 {
            return Err(ConfigValidationError {
                code: "config/oscillation-depth-below-minimum".into(),
                message: format!("oscillation_depth {} is below minimum 2", depth),
                status: 400,
            });
        }
    }

    match config.checkout_under_auto_version.as_str() {
        "allow" | "warn" | "deny" => {}
        other => {
            return Err(ConfigValidationError {
                code: "config/invalid-checkout-policy".into(),
                message: format!(
                    "checkout_under_auto_version {:?}: must be \"allow\", \"warn\", or \"deny\"",
                    other
                ),
                status: 400,
            });
        }
    }

    if !config.auto_version {
        return Ok(());
    }

    let canonical = canonicalize_prefix(&config.prefix);
    for required in REQUIRED_EXCLUDES {
        if !prefix_encompasses(&canonical, required) {
            continue;
        }
        if !exclude_list_covers(&config.exclude, &canonical, required) {
            return Err(ConfigValidationError {
                code: "config/missing-required-exclude".into(),
                message: format!(
                    "auto_version enabled on prefix {:?} encompasses {:?}; \
                     add exclude pattern (e.g., {:?})",
                    config.prefix,
                    required,
                    default_exclude_pattern(&canonical, required),
                ),
                status: 400,
            });
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ConfigValidationError {
    pub code: String,
    pub message: String,
    pub status: u32,
}

/// Does `canonical_prefix` (canonical form, no slashes) encompass `target`
/// (canonical form)? Empty prefix encompasses everything; otherwise `target`
/// must equal `canonical_prefix` or start with `canonical_prefix/`.
fn prefix_encompasses(canonical_prefix: &str, target: &str) -> bool {
    if canonical_prefix.is_empty() {
        return true;
    }
    target == canonical_prefix || target.starts_with(&format!("{}/", canonical_prefix))
}

/// Does the exclude list contain a pattern that covers `target` (canonical
/// form) relative to `canonical_prefix`?
///
/// §6.1's Reentrancy MUST is about a **subtree**: every write under
/// `system/revision/…` must be suppressed, not just the node itself. Under
/// §2.4's closed grammar only two of the four forms can express that — form 1
/// (`*`) and form 2 (`<literal>/*`, which crosses `/` at any depth). An exact
/// pattern (form 4) excludes one path and leaves its descendants versioned, and
/// a trailing literal (form 3) is an extension filter; neither covers a
/// subtree, so neither satisfies the requirement. That is stricter than the
/// pre-§2.4 code here, which treated any literal as a prefix.
fn exclude_list_covers(excludes: &[String], canonical_prefix: &str, target: &str) -> bool {
    let target_relative = if canonical_prefix.is_empty() {
        target.to_string()
    } else if target == canonical_prefix {
        String::new()
    } else {
        target
            .strip_prefix(&format!("{}/", canonical_prefix))
            .unwrap_or(target)
            .to_string()
    };
    // What must be covered is the target AND everything below it.
    let target_subtree = if target_relative.is_empty() {
        String::new()
    } else {
        format!("{}/", target_relative)
    };

    excludes.iter().any(|pattern| {
        if pattern == "*" {
            return true; // form 1 — everything
        }
        match pattern.strip_suffix('*') {
            // form 2 — the retained `/` is what stops `system/revisionary/*`
            // from reading as coverage of `system/revision`.
            Some(literal) if literal.ends_with('/') => target_subtree.starts_with(literal),
            _ => false,
        }
    })
}

// ---------------------------------------------------------------------------
// ConfigCoordinationHook
// ---------------------------------------------------------------------------

/// SyncTreeHook that coordinates `system/tree/tracking-config` state with
/// `system/revision/config/*` writes (filtered by entity type).
///
/// When a revision config is written with `auto_version: true`, ensures a
/// `system/tree/tracking-config` entity exists for the prefix with
/// `enabled: true`. When the revision config is removed or `auto_version`
/// flips to `false`, disables the matching tracking-config entity.
///
/// This is the config-write-time side of the coordination specified in
/// PROPOSAL-REVISION-AUTO-VERSION-FIX §4 "Trie root tracking coordination":
/// a valid tracking-config MUST exist whenever auto-version is enabled, and
/// the revision extension owns enforcing that invariant. The hook fires
/// inline during the same tree write that produced the revision config,
/// so the two entities stay in sync within a single emit cascade.
///
/// Validation: configs that fail `validate_revision_config` are logged and
/// skipped. Write-time rejection of such configs (spec §6D.4) is not yet
/// plumbed at the tree-write boundary; the runtime emit-time error (§6D.5)
/// will be added with the auto-version hook in a later stage.
pub struct ConfigCoordinationHook {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    /// Pre-computed `/{peer_id}/system/revision/` for detecting config events
    /// at `/{pid}/system/revision/{66hex}/config`.
    revision_prefix: String,
    tracking_path_prefix: String,
}

impl ConfigCoordinationHook {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
    ) -> Self {
        let revision_prefix = format!("/{}/system/revision/", &local_peer_id);
        let tracking_path_prefix = format!("/{}/system/tree/tracking-config/", &local_peer_id);
        Self {
            content_store,
            location_index,
            revision_prefix,
            tracking_path_prefix,
        }
    }

    /// Compute the tracking-config tree path for a canonical prefix
    /// (no leading/trailing slashes). Universal prefix (empty canonical) is
    /// stored at `.../tracking-config/` via a sentinel segment to avoid the
    /// empty-trailing-segment ambiguity.
    fn tracking_path(&self, canonical: &str) -> String {
        if canonical.is_empty() {
            // Universal tree — represent with a reserved "root" segment so
            // the path has no trailing slash.
            format!("{}root", self.tracking_path_prefix)
        } else {
            format!("{}{}", self.tracking_path_prefix, canonical)
        }
    }

    fn build_tracking_config_entity(canonical: &str, enabled: bool) -> Option<Entity> {
        build_tracking_config_entity(canonical, enabled)
    }

    fn write_tracking_config(&self, canonical: &str, enabled: bool, ctx: &ExecutionContext) {
        let Some(entity) = Self::build_tracking_config_entity(canonical, enabled) else {
            tracing::error!(canonical = %canonical, "failed to build tracking-config entity");
            return;
        };
        let hash = match self.content_store.put(entity) {
            Ok(h) => h,
            Err(e) => {
                tracing::error!(error = %e, "tracking-config content_store.put failed");
                return;
            }
        };
        let path = self.tracking_path(canonical);
        let _cascade = self
            .location_index
            .set_with_context(&path, hash, ctx.clone());
        tracing::debug!(
            path = %path,
            enabled,
            "revision: tracking-config coordinated"
        );
    }

    fn coordinate_from_config(&self, config: &RevisionConfig, ctx: &ExecutionContext) {
        if let Err(e) = validate_revision_config(config) {
            tracing::error!(
                prefix = %config.prefix,
                error = %e.message,
                "revision: invalid config; skipping tracking-config coordination"
            );
            return;
        }
        let canonical = canonicalize_prefix(&config.prefix);
        self.write_tracking_config(&canonical, config.auto_version, ctx);
    }

    fn decode_config_at(&self, hash: &entity_hash::Hash) -> Option<RevisionConfig> {
        let entity = self.content_store.get(hash)?;
        // Only top-level config entities; skip sub-config types like
        // system/revision/config/merge/** entries that share the path tree.
        if entity.entity_type != "system/revision/config" {
            return None;
        }
        decode_revision_config(&entity.data)
    }
}

impl SyncTreeHook for ConfigCoordinationHook {
    fn on_tree_change(
        &self,
        event: &TreeChangeEvent,
        ctx: &mut ExecutionContext,
    ) -> Result<(), entity_store::CascadeHalt> {
        if !is_prefix_config_path(&event.path, &self.revision_prefix) {
            return Ok(());
        }

        match event.change_type {
            ChangeType::Created | ChangeType::Modified => {
                if let Some(config) = self.decode_config_at(&event.hash) {
                    if let Err(e) = validate_revision_config(&config) {
                        tracing::error!(
                            prefix = %config.prefix,
                            error = %e.message,
                            "revision: invalid config written directly — halting cascade"
                        );
                        return Err(entity_store::CascadeHalt {
                            consumer_name: self.name().to_string(),
                            error_code: e.status,
                            error_message: format!("{}: {}", e.code, e.message),
                            is_error: false,
                        });
                    }
                    self.coordinate_from_config(&config, ctx);
                }
            }
            ChangeType::Deleted => {
                if let Some(prev) = event.previous_hash {
                    if let Some(config) = self.decode_config_at(&prev) {
                        let canonical = canonicalize_prefix(&config.prefix);
                        self.write_tracking_config(&canonical, false, ctx);
                    }
                }
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "revision/config-coordination"
    }

    fn handler_pattern(&self) -> &str {
        "system/revision/config"
    }
}

pub fn build_tracking_config_entity(canonical: &str, enabled: bool) -> Option<Entity> {
    let prefix = tracking_prefix_field(canonical);
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (entity_ecf::text("enabled"), entity_ecf::bool_val(enabled)),
        (entity_ecf::text("prefix"), entity_ecf::text(&prefix)),
    ]));
    Entity::new("system/tree/tracking-config", data).ok()
}

fn tracking_prefix_field(canonical: &str) -> String {
    if canonical.is_empty() {
        "/".to_string()
    } else {
        format!("{}/", canonical)
    }
}

pub fn tracking_config_path(local_peer_id: &str, canonical: &str) -> String {
    let prefix = format!("/{}/system/tree/tracking-config/", local_peer_id);
    if canonical.is_empty() {
        format!("{}root", prefix)
    } else {
        format!("{}{}", prefix, canonical)
    }
}

fn default_exclude_pattern(canonical_prefix: &str, target: &str) -> String {
    let rel = if canonical_prefix.is_empty() {
        target.to_string()
    } else if target == canonical_prefix {
        String::new()
    } else {
        target
            .strip_prefix(&format!("{}/", canonical_prefix))
            .unwrap_or(target)
            .to_string()
    };
    // §2.4 form 2 crosses `/` at any depth, so the subtree pattern needs no
    // second wildcard — `system/revision/*` already reaches
    // `system/revision/head/{H}/…`. (Was `**` until the grammar was closed.)
    if rel.is_empty() {
        "*".to_string()
    } else {
        format!("{}/*", rel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use entity_hash::Hash;
    use entity_store::{ChangeType, MemoryContentStore, MemoryLocationIndex};

    fn make_stores() -> (Arc<MemoryContentStore>, Arc<MemoryLocationIndex>) {
        (
            Arc::new(MemoryContentStore::new()),
            Arc::new(MemoryLocationIndex::new()),
        )
    }

    fn test_peer_id() -> String {
        // Real Base58 46-char peer ID (§5.4 validate_absolute_path requires
        // this shape on the first segment of every tree path).
        entity_crypto::Keypair::from_seed([42u8; 32])
            .peer_id()
            .as_str()
            .to_string()
    }

    /// Compute the prefix hash for a bare prefix resolved against a peer ID.
    fn test_ph(peer_id: &str, prefix: &str) -> String {
        crate::prefix_hash(&crate::resolve_prefix(prefix, peer_id))
    }

    /// §8.4.5: the prefix-config reader must accept whatever width the hash's
    /// OWN format byte implies — 66 chars under `00`, 98 under `01` — and
    /// reject a width that disagrees with the byte it declares.
    ///
    /// Mutation run: restoring the former `rest.len() != 66 + "/config".len()`
    /// gate fails the SHA-384 row (a peer whose home format is `01` stopped
    /// recognising its own entries) and *passes* the two mismatch rows only by
    /// accident, since they are the wrong length for 66 as well — which is why
    /// the mismatch rows carry the width the OTHER format implies.
    #[test]
    fn prefix_config_hex_width_follows_its_own_format_byte() {
        let prefix = "/peer/system/revision/";
        let sha256 = format!("00{}", "ab".repeat(32)); // 66 chars
        let sha384 = format!("01{}", "cd".repeat(48)); // 98 chars

        for hex in [&sha256, &sha384] {
            assert!(
                is_prefix_config_path(&format!("{prefix}{hex}/config"), prefix),
                "{} hex chars beginning {} must be accepted",
                hex.len(),
                &hex[0..2]
            );
        }

        // A width that disagrees with its own declared format byte is rejected
        // — strictly stronger than a constant, and the half a fixed gate misses.
        let wide_sha256 = format!("00{}", "ab".repeat(48)); // 98 chars claiming 00
        let narrow_sha384 = format!("01{}", "cd".repeat(32)); // 66 chars claiming 01
        for hex in [&wide_sha256, &narrow_sha384] {
            assert!(
                !is_prefix_config_path(&format!("{prefix}{hex}/config"), prefix),
                "hex of {} chars declaring {} must be rejected",
                hex.len(),
                &hex[0..2]
            );
        }

        // An unallocated format code is rejected rather than length-guessed.
        let unknown = format!("7f{}", "ab".repeat(32));
        assert!(!is_prefix_config_path(
            &format!("{prefix}{unknown}/config"),
            prefix
        ));
        // Non-hex and missing suffix still fail.
        assert!(!is_prefix_config_path(
            &format!("{prefix}{sha256}/other"),
            prefix
        ));
        assert!(!is_prefix_config_path(
            &format!("{prefix}zz{}/config", "ab".repeat(32)),
            prefix
        ));
    }

    // ConfigCoordinationHook tests --------------------------------------

    fn make_config_entity(cfg: &RevisionConfig) -> Entity {
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("auto_version"),
                entity_ecf::bool_val(cfg.auto_version),
            ),
            (
                entity_ecf::text("exclude"),
                entity_ecf::Value::Array(cfg.exclude.iter().map(entity_ecf::text).collect()),
            ),
            (
                entity_ecf::text("exclude_types"),
                entity_ecf::Value::Array(cfg.exclude_types.iter().map(entity_ecf::text).collect()),
            ),
            (
                entity_ecf::text("merge_order"),
                entity_ecf::text(&cfg.merge_order),
            ),
            (entity_ecf::text("prefix"), entity_ecf::text(&cfg.prefix)),
        ]));
        Entity::new("system/revision/config", data).unwrap()
    }

    fn decode_tracking_config_entity(entity: &Entity) -> Option<(String, bool)> {
        assert_eq!(entity.entity_type, "system/tree/tracking-config");
        let val: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).ok()?;
        let map = val.as_map()?;
        let mut prefix = None;
        let mut enabled = None;
        for (k, v) in map {
            match k.as_text()? {
                "prefix" => prefix = v.as_text().map(|s| s.to_string()),
                "enabled" => enabled = v.as_bool(),
                _ => {}
            }
        }
        Some((prefix?, enabled.unwrap_or(false)))
    }

    #[test]
    fn coordination_creates_tracking_config_on_auto_version_enable() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let hook = ConfigCoordinationHook::new(store.clone(), li.clone(), peer_id.clone());

        let cfg = base_config("project/", true);
        let cfg_entity = make_config_entity(&cfg);
        let cfg_hash = store.put(cfg_entity).unwrap();
        let ph = test_ph(&peer_id, "project/");

        let event = TreeChangeEvent {
            path: crate::rev_config_path(&peer_id, &ph),
            hash: cfg_hash,
            previous_hash: None,
            new_hash: Some(cfg_hash),
            change_type: ChangeType::Created,
            context: None,
        };
        let mut ctx = ExecutionContext::default();
        let _ = hook.on_tree_change(&event, &mut ctx);

        let tc_path = format!("/{}/system/tree/tracking-config/project", peer_id);
        let tc_hash = li.get(&tc_path).expect("tracking-config should be created");
        let tc_entity = store.get(&tc_hash).expect("tc entity");
        let (pfx, enabled) = decode_tracking_config_entity(&tc_entity).unwrap();
        assert_eq!(pfx, "project/");
        assert!(enabled);
    }

    #[test]
    fn coordination_disables_tracking_config_on_auto_version_false() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let hook = ConfigCoordinationHook::new(store.clone(), li.clone(), peer_id.clone());

        let cfg = base_config("project/", false);
        let cfg_hash = store.put(make_config_entity(&cfg)).unwrap();
        let ph = test_ph(&peer_id, "project/");
        let event = TreeChangeEvent {
            path: crate::rev_config_path(&peer_id, &ph),
            hash: cfg_hash,
            previous_hash: None,
            new_hash: Some(cfg_hash),
            change_type: ChangeType::Created,
            context: None,
        };
        let _ = hook.on_tree_change(&event, &mut ExecutionContext::default());

        let tc_path = format!("/{}/system/tree/tracking-config/project", peer_id);
        let tc_hash = li.get(&tc_path).expect("tracking-config still created");
        let tc_entity = store.get(&tc_hash).unwrap();
        let (_, enabled) = decode_tracking_config_entity(&tc_entity).unwrap();
        assert!(!enabled);
    }

    #[test]
    fn coordination_disables_on_config_removal() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let hook = ConfigCoordinationHook::new(store.clone(), li.clone(), peer_id.clone());

        let cfg = base_config("project/", true);
        let prev_hash = store.put(make_config_entity(&cfg)).unwrap();
        let ph = test_ph(&peer_id, "project/");

        let event = TreeChangeEvent {
            path: crate::rev_config_path(&peer_id, &ph),
            hash: Hash::zero(),
            previous_hash: Some(prev_hash),
            new_hash: None,
            change_type: ChangeType::Deleted,
            context: None,
        };
        let _ = hook.on_tree_change(&event, &mut ExecutionContext::default());

        let tc_path = format!("/{}/system/tree/tracking-config/project", peer_id);
        let tc_hash = li.get(&tc_path).expect("tc written on removal");
        let tc_entity = store.get(&tc_hash).unwrap();
        let (_, enabled) = decode_tracking_config_entity(&tc_entity).unwrap();
        assert!(!enabled);
    }

    #[test]
    fn coordination_skips_invalid_configs() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let hook = ConfigCoordinationHook::new(store.clone(), li.clone(), peer_id.clone());

        // Universal prefix with auto_version:true but no excludes → invalid.
        let cfg = base_config("/", true);
        let cfg_hash = store.put(make_config_entity(&cfg)).unwrap();
        let ph = test_ph(&peer_id, "/");
        let event = TreeChangeEvent {
            path: crate::rev_config_path(&peer_id, &ph),
            hash: cfg_hash,
            previous_hash: None,
            new_hash: Some(cfg_hash),
            change_type: ChangeType::Created,
            context: None,
        };
        let _ = hook.on_tree_change(&event, &mut ExecutionContext::default());

        // No tracking-config was written.
        let tc_path = format!("/{}/system/tree/tracking-config/root", peer_id);
        assert!(li.get(&tc_path).is_none());
    }

    #[test]
    fn coordination_universal_prefix_uses_root_segment() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let hook = ConfigCoordinationHook::new(store.clone(), li.clone(), peer_id.clone());

        let mut cfg = base_config("/", true);
        cfg.exclude = vec!["system/*".to_string()];
        let cfg_hash = store.put(make_config_entity(&cfg)).unwrap();
        let ph = test_ph(&peer_id, "/");
        let event = TreeChangeEvent {
            path: crate::rev_config_path(&peer_id, &ph),
            hash: cfg_hash,
            previous_hash: None,
            new_hash: Some(cfg_hash),
            change_type: ChangeType::Created,
            context: None,
        };
        let _ = hook.on_tree_change(&event, &mut ExecutionContext::default());

        let tc_path = format!("/{}/system/tree/tracking-config/root", peer_id);
        let tc_hash = li.get(&tc_path).expect("universal tracking-config");
        let tc_entity = store.get(&tc_hash).unwrap();
        let (pfx, enabled) = decode_tracking_config_entity(&tc_entity).unwrap();
        assert_eq!(pfx, "/");
        assert!(enabled);
    }

    #[test]
    fn coordination_ignores_unrelated_paths() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let hook = ConfigCoordinationHook::new(store.clone(), li.clone(), peer_id.clone());

        let event = TreeChangeEvent {
            path: format!("/{}/project/foo", peer_id),
            hash: Hash::zero(),
            previous_hash: None,
            new_hash: Some(Hash::zero()),
            change_type: ChangeType::Created,
            context: None,
        };
        let _ = hook.on_tree_change(&event, &mut ExecutionContext::default());

        assert!(li.list("/").is_empty());
    }

    // RevisionEngine tests -----------------------------------------------

    #[test]
    fn test_skips_system_revision_paths() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let engine = RevisionEngine::new(store.clone(), li.clone(), peer_id.clone());
        let ph = test_ph(&peer_id, "data/");

        let event = TreeChangeEvent {
            path: format!("/{}/system/revision/{}/head", peer_id, ph),
            hash: Hash::zero(),
            previous_hash: None,
            new_hash: Some(Hash::zero()),
            change_type: ChangeType::Created,
            context: None,
        };
        let _ = engine.on_tree_change(&event, &mut ExecutionContext::default());

        // No version created
        assert!(li.get(&crate::rev_head_path(&peer_id, &ph)).is_none());
    }

    fn base_config(prefix: &str, auto_version: bool) -> RevisionConfig {
        RevisionConfig {
            prefix: prefix.to_string(),
            auto_version,
            merge_order: DEFAULT_MERGE_ORDER.to_string(),
            oscillation_depth: None,
            exclude: Vec::new(),
            exclude_types: Vec::new(),
            checkout_under_auto_version: DEFAULT_CHECKOUT_POLICY.to_string(),
        }
    }

    #[test]
    fn canonicalize_prefix_forms() {
        assert_eq!(canonicalize_prefix("/"), "");
        assert_eq!(canonicalize_prefix(""), "");
        assert_eq!(canonicalize_prefix("project/"), "project");
        assert_eq!(canonicalize_prefix("/project/src/"), "project/src");
        assert_eq!(canonicalize_prefix("project/src"), "project/src");
    }

    #[test]
    fn default_merge_order_is_deterministic() {
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("prefix"),
            entity_ecf::Value::Text("project/".to_string()),
        )]));
        let cfg = decode_revision_config(&data).expect("decode");
        assert_eq!(cfg.merge_order, "deterministic");
        assert_eq!(cfg.checkout_under_auto_version, "warn");
    }

    #[test]
    fn explicit_merge_order_preserved() {
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("prefix"),
                entity_ecf::Value::Text("project/".to_string()),
            ),
            (
                entity_ecf::text("merge_order"),
                entity_ecf::Value::Text("caller-perspective".to_string()),
            ),
        ]));
        let cfg = decode_revision_config(&data).expect("decode");
        assert_eq!(cfg.merge_order, "caller-perspective");
    }

    #[test]
    fn validate_accepts_auto_version_off() {
        // auto_version off — encompassing excludes are not required.
        let cfg = base_config("/", false);
        validate_revision_config(&cfg).expect("valid");
    }

    #[test]
    fn validate_accepts_non_encompassing_prefix() {
        let cfg = base_config("project/", true);
        validate_revision_config(&cfg).expect("valid");
    }

    #[test]
    fn validate_rejects_universal_without_excludes() {
        let cfg = base_config("/", true);
        let err = validate_revision_config(&cfg).expect_err("should reject");
        assert!(
            err.message.contains("system/revision"),
            "err was: {}",
            err.message
        );
    }

    #[test]
    fn validate_accepts_universal_with_system_shorthand() {
        let mut cfg = base_config("/", true);
        cfg.exclude = vec!["system/*".to_string()];
        validate_revision_config(&cfg).expect("valid");
    }

    #[test]
    fn validate_accepts_universal_with_full_enumeration() {
        let mut cfg = base_config("/", true);
        cfg.exclude = REQUIRED_EXCLUDES
            .iter()
            .map(|p| format!("{}/*", p))
            .collect();
        validate_revision_config(&cfg).expect("valid");
    }

    #[test]
    fn validate_rejects_partial_enumeration() {
        let mut cfg = base_config("/", true);
        // Missing system/history and system/clock.
        cfg.exclude = vec![
            "system/revision/*".to_string(),
            "system/tree/root/*".to_string(),
            "system/tree/tracking-config/*".to_string(),
        ];
        let err = validate_revision_config(&cfg).expect_err("should reject");
        assert!(
            err.message.contains("system/history"),
            "err was: {}",
            err.message
        );
    }

    #[test]
    fn validate_rejects_encompassing_system_prefix() {
        // prefix /system/ encompasses system/revision, system/history, etc.
        let cfg = base_config("system/", true);
        let err = validate_revision_config(&cfg).expect_err("should reject");
        assert!(
            err.code == "config/missing-required-exclude",
            "code was: {}",
            err.code
        );
    }

    #[test]
    fn validate_rejects_bogus_merge_order() {
        let mut cfg = base_config("project/", true);
        cfg.merge_order = "random".to_string();
        validate_revision_config(&cfg).expect_err("should reject");
    }

    #[test]
    fn validate_rejects_bogus_checkout_policy() {
        let mut cfg = base_config("project/", true);
        cfg.checkout_under_auto_version = "maybe".to_string();
        validate_revision_config(&cfg).expect_err("should reject");
    }

    #[test]
    fn validate_accepts_all_checkout_policies() {
        for policy in ["allow", "warn", "deny"] {
            let mut cfg = base_config("project/", true);
            cfg.checkout_under_auto_version = policy.to_string();
            validate_revision_config(&cfg).expect("valid");
        }
    }

    #[test]
    fn test_no_auto_version_without_config() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let engine = RevisionEngine::new(store.clone(), li.clone(), peer_id.clone());
        let ph = test_ph(&peer_id, "data/");

        let event = TreeChangeEvent {
            path: "data/foo".to_string(),
            hash: Hash::zero(),
            previous_hash: None,
            new_hash: Some(Hash::zero()),
            change_type: ChangeType::Created,
            context: None,
        };
        let _ = engine.on_tree_change(&event, &mut ExecutionContext::default());

        // No config, no version created
        assert!(li.get(&crate::rev_head_path(&peer_id, &ph)).is_none());
    }

    /// Install a revision config in the tree at its hash-addressed path.
    /// `/{peer}/system/revision/{prefix_hash}/config` where prefix_hash is
    /// derived from the resolved absolute prefix.
    fn install_config(
        store: &Arc<MemoryContentStore>,
        li: &Arc<MemoryLocationIndex>,
        peer_id: &str,
        _name: &str,
        cfg: &RevisionConfig,
    ) {
        let cfg_hash = store.put(make_config_entity(cfg)).unwrap();
        let ph = test_ph(peer_id, &cfg.prefix);
        li.set(&crate::rev_config_path(peer_id, &ph), cfg_hash);
    }

    /// Seed the tracked-root binding that the root tracker would normally
    /// produce at position 6.
    fn seed_tracked_root(
        li: &Arc<MemoryLocationIndex>,
        peer_id: &str,
        canonical: &str,
        hash: Hash,
    ) {
        let path = if canonical.is_empty() {
            format!("/{}/system/tree/root", peer_id)
        } else {
            format!("/{}/system/tree/root/{}", peer_id, canonical)
        };
        li.set(&path, hash);
    }

    fn event_for(peer_id: &str, path: &str, hash: Hash) -> TreeChangeEvent {
        TreeChangeEvent {
            path: format!("/{}/{}", peer_id, path),
            hash,
            previous_hash: None,
            new_hash: Some(hash),
            change_type: ChangeType::Created,
            context: None,
        }
    }

    fn sample_hash(byte: u8) -> Hash {
        let mut digest = [0u8; 32];
        digest[0] = byte;
        Hash::new(0, digest)
    }

    #[test]
    fn auto_version_creates_entry_from_tracked_root() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let engine = RevisionEngine::new(store.clone(), li.clone(), peer_id.clone());

        let cfg = base_config("project/", true);
        install_config(&store, &li, &peer_id, "main", &cfg);

        let root = sample_hash(0x42);
        seed_tracked_root(&li, &peer_id, "project", root);

        let evt = event_for(&peer_id, "project/file.txt", sample_hash(0x01));
        let _ = engine.on_tree_change(&evt, &mut ExecutionContext::default());

        let ph = test_ph(&peer_id, "project/");
        let head_hash = li
            .get(&crate::rev_head_path(&peer_id, &ph))
            .expect("head set");
        let head_entity = store.get(&head_hash).unwrap();
        let entry = decode_revision_entry(&head_entity).unwrap();
        assert_eq!(entry.root, root);
        assert!(entry.parents.is_empty());
    }

    #[test]
    fn auto_version_dedups_when_root_unchanged() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let engine = RevisionEngine::new(store.clone(), li.clone(), peer_id.clone());

        let cfg = base_config("project/", true);
        install_config(&store, &li, &peer_id, "main", &cfg);

        let root = sample_hash(0x42);
        seed_tracked_root(&li, &peer_id, "project", root);

        let ph = test_ph(&peer_id, "project/");
        let evt = event_for(&peer_id, "project/file.txt", sample_hash(0x01));
        let _ = engine.on_tree_change(&evt, &mut ExecutionContext::default());
        let first_head = li.get(&crate::rev_head_path(&peer_id, &ph)).unwrap();

        // Same tracked root, another event — must dedup.
        let _ = engine.on_tree_change(&evt, &mut ExecutionContext::default());
        let second_head = li.get(&crate::rev_head_path(&peer_id, &ph)).unwrap();
        assert_eq!(first_head, second_head);
    }

    #[test]
    fn auto_version_chains_on_root_change() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let engine = RevisionEngine::new(store.clone(), li.clone(), peer_id.clone());

        let cfg = base_config("project/", true);
        install_config(&store, &li, &peer_id, "main", &cfg);

        let ph = test_ph(&peer_id, "project/");
        seed_tracked_root(&li, &peer_id, "project", sample_hash(0x01));
        let evt = event_for(&peer_id, "project/file.txt", sample_hash(0xaa));
        let _ = engine.on_tree_change(&evt, &mut ExecutionContext::default());
        let first_head = li.get(&crate::rev_head_path(&peer_id, &ph)).unwrap();

        seed_tracked_root(&li, &peer_id, "project", sample_hash(0x02));
        let _ = engine.on_tree_change(&evt, &mut ExecutionContext::default());
        let second_head = li.get(&crate::rev_head_path(&peer_id, &ph)).unwrap();

        assert_ne!(first_head, second_head);
        let entry = decode_revision_entry(&store.get(&second_head).unwrap()).unwrap();
        assert_eq!(entry.root, sample_hash(0x02));
        assert_eq!(entry.parents, vec![first_head]);
    }

    #[test]
    fn auto_version_errors_when_tracked_root_missing() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let engine = RevisionEngine::new(store.clone(), li.clone(), peer_id.clone());

        let cfg = base_config("project/", true);
        install_config(&store, &li, &peer_id, "main", &cfg);

        // No seed — tracking-config invariant violated.
        let ph = test_ph(&peer_id, "project/");
        let evt = event_for(&peer_id, "project/file.txt", sample_hash(0x01));
        let _ = engine.on_tree_change(&evt, &mut ExecutionContext::default());

        assert!(li.get(&crate::rev_head_path(&peer_id, &ph)).is_none());
    }

    #[test]
    fn auto_version_skips_own_path() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let engine = RevisionEngine::new(store.clone(), li.clone(), peer_id.clone());

        // Config covers universal tree; reentrancy guard still excludes us.
        let mut cfg = base_config("/", true);
        cfg.exclude = vec!["system/*".to_string()];
        install_config(&store, &li, &peer_id, "universal", &cfg);
        seed_tracked_root(&li, &peer_id, "", sample_hash(0x11));

        let evt = event_for(
            &peer_id,
            "system/revision/head/something",
            sample_hash(0xff),
        );
        let _ = engine.on_tree_change(&evt, &mut ExecutionContext::default());

        // No head was advanced anywhere — own-path write is ignored.
        assert!(li.list("/").iter().all(|e| !e.path.ends_with("/head")));
    }

    #[test]
    fn auto_version_respects_exclude_patterns() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let engine = RevisionEngine::new(store.clone(), li.clone(), peer_id.clone());

        let mut cfg = base_config("project/", true);
        cfg.exclude = vec!["build/*".to_string()];
        install_config(&store, &li, &peer_id, "main", &cfg);
        seed_tracked_root(&li, &peer_id, "project", sample_hash(0x01));

        let ph = test_ph(&peer_id, "project/");
        let evt = event_for(&peer_id, "project/build/out.bin", sample_hash(0xbb));
        let _ = engine.on_tree_change(&evt, &mut ExecutionContext::default());

        assert!(li.get(&crate::rev_head_path(&peer_id, &ph)).is_none());
    }

    /// End-to-end: install both hooks on a NotifyingLocationIndex, write a
    /// revision config, then a tracked-prefix entity, and verify the config-
    /// coordination + auto-version cascade produces a version entry. The
    /// tracked-root step is hand-seeded here since the position-6 root
    /// tracker lives in `core/tree` (outside this crate).
    #[test]
    fn end_to_end_cascade_through_notifying_index() {
        use entity_store::NotifyingLocationIndex;

        let peer_id = test_peer_id();
        let inner = Arc::new(MemoryLocationIndex::new());
        let store = Arc::new(MemoryContentStore::new());
        let noop_broadcast: Arc<dyn Fn(TreeChangeEvent) + Send + Sync> = Arc::new(|_| {});
        let notifying = Arc::new(NotifyingLocationIndex::new(inner.clone(), noop_broadcast));

        let coord = Arc::new(ConfigCoordinationHook::new(
            store.clone(),
            notifying.clone(),
            peer_id.clone(),
        ));
        let engine = Arc::new(RevisionEngine::new(
            store.clone(),
            notifying.clone(),
            peer_id.clone(),
        ));
        notifying.register_hook(coord);
        notifying.register_hook(engine);

        let ph = test_ph(&peer_id, "project/");

        // Step 1: write a revision config through the notifying index. This
        // triggers the coord hook, which creates a tracking-config entity.
        let cfg = base_config("project/", true);
        let cfg_hash = store.put(make_config_entity(&cfg)).unwrap();
        entity_store::LocationIndex::set(
            notifying.as_ref(),
            &crate::rev_config_path(&peer_id, &ph),
            cfg_hash,
        );
        let tc_path = format!("/{}/system/tree/tracking-config/project", peer_id);
        assert!(
            inner.get(&tc_path).is_some(),
            "config-coordination hook must have written tracking-config"
        );

        // Step 2: simulate the position-6 root tracker producing a tracked
        // root for the prefix. In the real peer this binding is maintained
        // incrementally by `entity_tree::root_tracker::RootTrackerEngine`.
        let tracked_root = sample_hash(0x99);
        entity_store::LocationIndex::set(
            notifying.as_ref(),
            &format!("/{}/system/tree/root/project", peer_id),
            tracked_root,
        );

        // Step 3: a tree write under the tracked prefix. The auto-version
        // hook at position 7 reads the tracked root and creates an entry.
        entity_store::LocationIndex::set(
            notifying.as_ref(),
            &format!("/{}/project/file.txt", peer_id),
            sample_hash(0x01),
        );

        let head_hash = inner
            .get(&crate::rev_head_path(&peer_id, &ph))
            .expect("auto-version must have created an entry");
        let entry = decode_revision_entry(&store.get(&head_hash).unwrap()).unwrap();
        assert_eq!(entry.root, tracked_root);
        assert!(entry.parents.is_empty(), "first version has no parents");
    }

    #[test]
    fn auto_version_overlapping_prefixes_each_get_version() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let engine = RevisionEngine::new(store.clone(), li.clone(), peer_id.clone());

        let cfg_outer = base_config("project/", true);
        install_config(&store, &li, &peer_id, "outer", &cfg_outer);
        let cfg_inner = base_config("project/src/", true);
        install_config(&store, &li, &peer_id, "inner", &cfg_inner);

        seed_tracked_root(&li, &peer_id, "project", sample_hash(0xaa));
        seed_tracked_root(&li, &peer_id, "project/src", sample_hash(0xbb));

        let ph_outer = test_ph(&peer_id, "project/");
        let ph_inner = test_ph(&peer_id, "project/src/");

        let evt = event_for(&peer_id, "project/src/file.rs", sample_hash(0x11));
        let _ = engine.on_tree_change(&evt, &mut ExecutionContext::default());

        let outer = li
            .get(&crate::rev_head_path(&peer_id, &ph_outer))
            .expect("outer head");
        let inner = li
            .get(&crate::rev_head_path(&peer_id, &ph_inner))
            .expect("inner head");
        assert_ne!(outer, inner);
        assert_eq!(
            decode_revision_entry(&store.get(&outer).unwrap())
                .unwrap()
                .root,
            sample_hash(0xaa)
        );
        assert_eq!(
            decode_revision_entry(&store.get(&inner).unwrap())
                .unwrap()
                .root,
            sample_hash(0xbb)
        );
    }

    // -----------------------------------------------------------------------
    // EXTENSION-REVISION §6.1 D1 — the version root is exclude-filtered on
    // BOTH paths that emit a version. `REV-AUTOVERSION-EXCLUDE-PARITY-1`.
    // -----------------------------------------------------------------------

    /// Bind an entity into the live tree under the peer-qualified path, the way
    /// a `tree:put` would, and return its hash.
    fn put_live(
        store: &Arc<MemoryContentStore>,
        li: &Arc<MemoryLocationIndex>,
        peer_id: &str,
        bare_path: &str,
        entity_type: &str,
        content: &str,
    ) -> Hash {
        let data = entity_ecf::to_ecf(&entity_ecf::text(content));
        let hash = store.put(Entity::new(entity_type, data).unwrap()).unwrap();
        li.set(&format!("/{}/{}", peer_id, bare_path), hash);
        hash
    }

    #[test]
    fn rev_autoversion_exclude_parity_1() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let engine = RevisionEngine::new(store.clone(), li.clone(), peer_id.clone());

        let mut cfg = base_config("project/", true);
        cfg.exclude = vec!["build/*".to_string()];
        install_config(&store, &li, &peer_id, "main", &cfg);

        let keep = put_live(
            &store,
            &li,
            &peer_id,
            "project/keep.txt",
            "test/doc",
            "keep",
        );
        let dropped = put_live(
            &store,
            &li,
            &peer_id,
            "project/build/out.bin",
            "test/doc",
            "artifact",
        );

        // The tracked root is EXTENSION-TREE §3.4.1a's structural summary: the
        // trie over every live binding under the prefix, with no filtering
        // stage anywhere in its derivation.
        let tracked = trie::build_trie(
            store.as_ref(),
            &std::collections::BTreeMap::from([
                ("build/out.bin".to_string(), dropped),
                ("keep.txt".to_string(), keep),
            ]),
        )
        .unwrap();
        seed_tracked_root(&li, &peer_id, "project", tracked);

        let evt = event_for(&peer_id, "project/keep.txt", keep);
        engine
            .on_tree_change(&evt, &mut ExecutionContext::default())
            .unwrap();

        let ph = test_ph(&peer_id, "project/");
        let head = li.get(&crate::rev_head_path(&peer_id, &ph)).expect("head");
        let emitted = decode_revision_entry(&store.get(&head).unwrap())
            .unwrap()
            .root;

        assert_ne!(
            emitted, tracked,
            "the raw tracked root still carries build/out.bin — adopting it is the D1 defect"
        );
        let bindings = trie::collect_all_bindings(store.as_ref(), emitted, "");
        assert!(bindings.contains_key("keep.txt"));
        assert!(
            !bindings.contains_key("build/out.bin"),
            "an excluded path must not be IN the emitted trie, not merely fail to trigger it"
        );

        // The parity claim itself: the same live state and config through the
        // explicit `commit` path must produce the same root, because a version
        // entry's identity is its root.
        let (_, commit_root, _) =
            crate::commit_logic::perform_commit(store.as_ref(), li.as_ref(), "project/", &peer_id)
                .unwrap();
        assert_eq!(
            emitted, commit_root,
            "auto-version and commit must agree on the root over identical state"
        );
    }

    #[test]
    fn autoversion_exclude_types_reaches_the_trie_too() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let engine = RevisionEngine::new(store.clone(), li.clone(), peer_id.clone());

        let mut cfg = base_config("project/", true);
        // Form 3 — `app/*-draft` would be an infix `*` and is refused by V6.
        cfg.exclude_types = vec!["*-draft".to_string()];
        install_config(&store, &li, &peer_id, "main", &cfg);

        let keep = put_live(&store, &li, &peer_id, "project/a", "app/note", "keep");
        let dropped = put_live(&store, &li, &peer_id, "project/b", "app/note-draft", "wip");

        let tracked = trie::build_trie(
            store.as_ref(),
            &std::collections::BTreeMap::from([
                ("a".to_string(), keep),
                ("b".to_string(), dropped),
            ]),
        )
        .unwrap();
        seed_tracked_root(&li, &peer_id, "project", tracked);

        engine
            .on_tree_change(
                &event_for(&peer_id, "project/a", keep),
                &mut ExecutionContext::default(),
            )
            .unwrap();

        let ph = test_ph(&peer_id, "project/");
        let head = li.get(&crate::rev_head_path(&peer_id, &ph)).expect("head");
        let emitted = decode_revision_entry(&store.get(&head).unwrap())
            .unwrap()
            .root;
        let bindings = trie::collect_all_bindings(store.as_ref(), emitted, "");
        assert!(bindings.contains_key("a"));
        assert!(!bindings.contains_key("b"), "excluded by type, at the trie");
    }

    #[test]
    fn autoversion_without_filters_still_adopts_the_tracked_root() {
        // The §6.1 fast path is normative, and it is what keeps auto-version
        // O(1) per put for every config that does not filter.
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let engine = RevisionEngine::new(store.clone(), li.clone(), peer_id.clone());

        let cfg = base_config("project/", true);
        install_config(&store, &li, &peer_id, "main", &cfg);
        let tracked = sample_hash(0x42);
        seed_tracked_root(&li, &peer_id, "project", tracked);

        engine
            .on_tree_change(
                &event_for(&peer_id, "project/file.txt", sample_hash(0x01)),
                &mut ExecutionContext::default(),
            )
            .unwrap();

        let ph = test_ph(&peer_id, "project/");
        let head = li.get(&crate::rev_head_path(&peer_id, &ph)).expect("head");
        // `tracked` is not a real trie node — adopting it verbatim is the point:
        // no walk, no rebuild, and no content-store read of the root at all.
        assert_eq!(
            decode_revision_entry(&store.get(&head).unwrap())
                .unwrap()
                .root,
            tracked
        );
    }

    // -----------------------------------------------------------------------
    // EXTENSION-REVISION §2.4 / §4.4.17 V6 — the closed four-form grammar.
    // The `REV-GLOB-*` conformance vectors, pinned here because the matcher is
    // hash-determining: it decides trie membership, membership decides `root`,
    // `root` is the version entry's identity.
    // -----------------------------------------------------------------------

    #[test]
    fn rev_glob_prefix_1_subtree_form_crosses_slash_at_any_depth() {
        // Form 2 is §5.4's subtree match — this is the §6.1 Reentrancy case,
        // and it needs no second wildcard.
        assert!(glob_match(
            "system/revision/*",
            "system/revision/head/abc/deep/x"
        ));
        assert!(glob_match("system/revision/*", "system/revision/head"));
    }

    #[test]
    fn rev_glob_prefix_2_retained_slash_blocks_the_sibling_prefix() {
        // The `/` is retained when the `*` is dropped, so a sibling whose name
        // merely starts with the literal does NOT match.
        assert!(!glob_match("system/revision/*", "system/revisionary/x"));
        assert!(!glob_match("build/*", "buildings/x"));
    }

    #[test]
    fn rev_glob_suffix_1_and_2_trailing_literal_is_a_whole_subject_suffix() {
        assert!(glob_match("*.cache", "a/b/foo.cache"));
        assert!(glob_match("*.cache", ".cache"));
        // `/` is not special, and the suffix must terminate the subject.
        assert!(!glob_match("*.cache", "a/cache/b"));
        assert!(!glob_match("*.cache", "foo.cache.tmp"));
    }

    #[test]
    fn rev_glob_exact_1_form_four_is_exact_not_a_prefix() {
        assert!(glob_match("docs", "docs"));
        // The pre-§2.4 matcher returned true here — a literal was treated as a
        // path prefix, silently over-excluding every descendant.
        assert!(!glob_match("docs", "docs/x"));
    }

    #[test]
    fn rev_glob_all_1_bare_star_matches_everything() {
        assert!(glob_match("*", "a/b/c"));
        assert!(glob_match("*", ""));
    }

    #[test]
    fn rev_glob_types_1_the_same_forms_apply_to_the_type_subject() {
        assert!(glob_match("app/*", "app/note"));
        assert!(!glob_match("app/*", "application/note"));
        assert!(glob_match("*-draft", "app/note-draft"));
        assert!(!glob_match("*-draft", "app/note"));
    }

    #[test]
    fn rev_glob_reject_1_doublestar_is_refused_at_config_write() {
        // The load-bearing vector: a matcher that merely *omits* `**` and one
        // that *rejects* it are indistinguishable until a config carries one.
        assert!(!valid_exclude_pattern("**"));

        let mut cfg = base_config("project/", false);
        cfg.exclude = vec!["**".to_string()];
        let err = validate_revision_config(&cfg).expect_err("`**` must be refused");
        assert_eq!(err.code, "config/invalid-exclude-pattern");
        assert_eq!(err.status, 400);
    }

    #[test]
    fn rev_glob_reject_2_infix_and_multi_star_forms_are_refused() {
        for bad in ["a/**/b", "a*b", "*a*", "**/*.cache", "sys*/x"] {
            assert!(!valid_exclude_pattern(bad), "{bad:?} must be invalid");
            let mut cfg = base_config("project/", false);
            cfg.exclude = vec![bad.to_string()];
            let err = validate_revision_config(&cfg).expect_err("must reject");
            assert_eq!(err.code, "config/invalid-exclude-pattern", "for {bad:?}");
        }
        // …and the same rule binds `exclude_types`, which is the second field
        // §4.4.17 V6 names.
        let mut cfg = base_config("project/", false);
        cfg.exclude_types = vec!["app/**".to_string()];
        let err = validate_revision_config(&cfg).expect_err("must reject");
        assert_eq!(err.code, "config/invalid-exclude-pattern");
        assert!(err.message.contains("exclude_types"), "{}", err.message);
    }

    #[test]
    fn v6_accepts_exactly_the_four_forms() {
        for good in ["*", "system/revision/*", "*.cache", "docs", ""] {
            assert!(valid_exclude_pattern(good), "{good:?} must be valid");
        }
        let mut cfg = base_config("project/", false);
        cfg.exclude = vec![
            "*".into(),
            "system/revision/*".into(),
            "*.cache".into(),
            "docs".into(),
        ];
        cfg.exclude_types = vec!["app/*".into(), "*-draft".into()];
        validate_revision_config(&cfg).expect("the four forms are valid");
    }

    #[test]
    fn v6_runs_before_the_required_exclude_coverage_check() {
        // An invalid pattern must never be *interpreted* by a coverage check on
        // its way to being stored: `system/**` would otherwise be read as
        // covering the required excludes and stored as a pattern we refuse to
        // evaluate.
        let mut cfg = base_config("/", true);
        cfg.exclude = vec!["system/**".to_string()];
        let err = validate_revision_config(&cfg).expect_err("must reject");
        assert_eq!(err.code, "config/invalid-exclude-pattern");
    }

    #[test]
    fn required_exclude_coverage_needs_a_subtree_form() {
        // Form 4 (exact) excludes the node and leaves its descendants
        // versioned, so it does not satisfy §6.1's Reentrancy MUST — the
        // pre-§2.4 code accepted it by treating every literal as a prefix.
        let mut cfg = base_config("/", true);
        cfg.exclude = vec!["system".to_string()];
        let err = validate_revision_config(&cfg).expect_err("exact form is not coverage");
        assert_eq!(err.code, "config/missing-required-exclude");

        cfg.exclude = vec!["system/*".to_string()];
        validate_revision_config(&cfg).expect("the subtree form covers");
    }

    // -----------------------------------------------------------------------
    // The last-burst-write loss, revision half (§6.1 "Contention handling")
    // -----------------------------------------------------------------------

    /// A `LocationIndex` that fires a one-shot injected write the first time a
    /// watched path is read, AFTER sampling the value the caller gets back.
    ///
    /// Sync hooks run under no cross-thread lock — `NotifyingLocationIndex::
    /// set_impl` mutates then dispatches holding nothing — so two writers to one
    /// tracked prefix run two copies of `auto_version_once` concurrently. This
    /// decorator reproduces the losing interleave deterministically in one
    /// thread, which a load test can only do when the scheduler cooperates.
    struct InterleaveOnRead {
        inner: Arc<MemoryLocationIndex>,
        watch_path: String,
        injection: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
    }

    impl InterleaveOnRead {
        fn new(inner: Arc<MemoryLocationIndex>, watch_path: String) -> Arc<Self> {
            Arc::new(Self {
                inner,
                watch_path,
                injection: std::sync::Mutex::new(None),
            })
        }
        fn arm(&self, f: Box<dyn FnOnce() + Send>) {
            *self.injection.lock().unwrap() = Some(f);
        }
    }

    impl entity_store::LocationIndex for InterleaveOnRead {
        fn get(&self, path: &str) -> Option<Hash> {
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
        // Forward the CAS trio — the default trait impls are a non-atomic
        // get+set, which would defeat the thing under test.
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

    /// Build a revision entry, store it, and return its hash.
    fn put_version(store: &Arc<MemoryContentStore>, root: Hash, parents: Vec<Hash>) -> Hash {
        let entry = build_revision_entry(&RevisionEntryData { root, parents }).unwrap();
        store.put(entry).unwrap()
    }

    /// §6.1 — a concurrent emit MUST NOT orphan the version another writer just
    /// advanced the head to.
    ///
    /// Pre-fix the head advance was a plain `set()`, justified by a comment
    /// claiming SyncTreeHooks are serialized. They are not. Two cascades read the
    /// same head, build two entries both chained from it, and both `set`: the
    /// loser's version is orphaned and the head commits to a root missing that
    /// writer's path — terminally, since a burst's last write has no next event.
    ///
    /// **Mutation:** restore the plain
    /// `self.location_index.set_with_context(head_path, entry_hash, ctx.clone())`
    /// and this goes RED — the racer's version is unreachable from the head.
    #[test]
    fn concurrent_emit_does_not_orphan_the_racing_version() {
        let peer_id = test_peer_id();
        let store = Arc::new(MemoryContentStore::new());
        let raw = Arc::new(MemoryLocationIndex::new());
        let ph = test_ph(&peer_id, "project/");
        let head_path = crate::rev_head_path(&peer_id, &ph);
        let li = InterleaveOnRead::new(raw.clone(), head_path.clone());

        let cfg = base_config("project/", true);
        let cfg_hash = store.put(make_config_entity(&cfg)).unwrap();
        raw.set(&crate::rev_config_path(&peer_id, &ph), cfg_hash);
        let tracked_root = sample_hash(0xaa);
        raw.set(
            &format!("/{}/system/tree/root/project", peer_id),
            tracked_root,
        );

        let engine = RevisionEngine::new(store.clone(), li.clone(), peer_id.clone());

        // The racing writer lands its own version at the head while we are
        // mid-emit, chained from nothing (it got there first).
        let racer_root = sample_hash(0xbb);
        let racer_version = put_version(&store, racer_root, Vec::new());
        {
            let raw2 = raw.clone();
            let head2 = head_path.clone();
            li.arm(Box::new(move || {
                raw2.set(&head2, racer_version);
            }));
        }

        let evt = event_for(&peer_id, "project/file.rs", sample_hash(0x11));
        engine
            .on_tree_change(&evt, &mut ExecutionContext::default())
            .expect("emit must not halt the cascade");

        // The head must reach the racer's version through the parent chain —
        // i.e. our emit chained onto it instead of overwriting it.
        let head = raw.get(&head_path).expect("head");
        let entry = decode_revision_entry(&store.get(&head).unwrap()).unwrap();
        assert_eq!(
            entry.root, tracked_root,
            "our emit must carry the live root"
        );
        assert!(
            entry.parents.contains(&racer_version),
            "the concurrently-advanced version was orphaned — the head no longer reaches it, \
             so the write it captured is in no version a follower can reach"
        );
    }

    /// §6.1 — the head MUST be read BEFORE the tracked root, and this is the
    /// test that says so.
    ///
    /// Within one writer's cascade the root tracker (position 6) stores the
    /// tracked root strictly before this hook (position 7) advances the head, so
    /// observing another thread's head implies its root store is already
    /// visible. Read the root first and that implication is lost: a thread can
    /// sample a stale root, then read a head another writer has since advanced,
    /// and CAS a version that silently drops the other writer's path — the CAS
    /// succeeds, because the head is exactly what the thread read.
    ///
    /// **Mutation:** move the `let current_head = ...get(&head_path)` line below
    /// the `tracked_root` read in `auto_version_once` and this goes RED with the
    /// head committing to the stale root. CAS alone does not save it.
    #[test]
    fn head_is_read_before_the_tracked_root() {
        let peer_id = test_peer_id();
        let store = Arc::new(MemoryContentStore::new());
        let raw = Arc::new(MemoryLocationIndex::new());
        let ph = test_ph(&peer_id, "project/");
        let head_path = crate::rev_head_path(&peer_id, &ph);
        let root_path = format!("/{}/system/tree/root/project", peer_id);
        let li = InterleaveOnRead::new(raw.clone(), root_path.clone());

        let cfg = base_config("project/", true);
        let cfg_hash = store.put(make_config_entity(&cfg)).unwrap();
        raw.set(&crate::rev_config_path(&peer_id, &ph), cfg_hash);

        // The root as it stands when we sample it — already stale by then.
        let stale_root = sample_hash(0xaa);
        raw.set(&root_path, stale_root);

        // The racer's cascade completes entirely inside our read window: it
        // stores the fuller root FIRST (position 6) and advances the head to a
        // version over it SECOND (position 7) — the real hook order.
        let full_root = sample_hash(0xbb);
        let racer_version = put_version(&store, full_root, Vec::new());
        {
            let raw2 = raw.clone();
            let root2 = root_path.clone();
            let head2 = head_path.clone();
            li.arm(Box::new(move || {
                raw2.set(&root2, full_root);
                raw2.set(&head2, racer_version);
            }));
        }

        let engine = RevisionEngine::new(store.clone(), li.clone(), peer_id.clone());
        let evt = event_for(&peer_id, "project/file.rs", sample_hash(0x11));
        engine
            .on_tree_change(&evt, &mut ExecutionContext::default())
            .expect("emit must not halt the cascade");

        let head = raw.get(&head_path).expect("head");
        let entry = decode_revision_entry(&store.get(&head).unwrap()).unwrap();
        assert_eq!(
            entry.root, full_root,
            "the head committed to a root that predates a write already in the live tree — \
             reading the tracked root before the head loses the happens-before that makes \
             the observed head imply the observed root"
        );
    }
}
