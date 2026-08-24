//! Three-way merge framework — path-by-path merge with configurable strategies.
//!
//! Implements spec §4.3.4 merge algorithm and §5 merge strategy framework.

use std::collections::BTreeMap;

use entity_entity::{canonical_deletion_marker_hash, Entity};
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};

/// EXTENSION-REVISION v3.1 §2.3 Amendment 4 — `merge-config.deletion_resolution`.
/// Applies when the three-way merge classifies a (local, remote) pair as
/// "both changed differently" AND exactly one side is the canonical
/// deletion marker. Default `preserve-on-conflict`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeletionResolution {
    /// Entity supersedes the deletion marker. Edit-loss risk: the delete
    /// signal is silently discarded. Recommended for collaborative edit
    /// workflows. Default.
    #[default]
    PreserveOnConflict,
    /// Deletion marker supersedes the entity. Sticky delete; the edit
    /// signal is silently discarded. Recommended for security-sensitive
    /// workflows (e.g., access-control revocation).
    DeletionWins,
    /// Surface as a conflict entity (same shape as edit-vs-edit).
    ThreeWayFallthrough,
    /// Deterministic: lower-hash wins. The marker hash is canonical so
    /// the outcome is stable across peers.
    Deterministic,
}

impl DeletionResolution {
    /// Parse a `deletion_resolution` string. Returns `None` for any
    /// rejected-at-config-write value (`lww`, `keep-both`) and for
    /// unknown values.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "preserve-on-conflict" => Some(Self::PreserveOnConflict),
            "deletion-wins" => Some(Self::DeletionWins),
            "three-way-fallthrough" => Some(Self::ThreeWayFallthrough),
            "deterministic" => Some(Self::Deterministic),
            _ => None,
        }
    }

    /// Per v3.1 §2.3: `lww` and `keep-both` MUST be rejected at
    /// config-write time. Implementations encountering either return
    /// `invalid_strategy` rather than silently accepting.
    pub fn is_rejected_at_config_write(s: &str) -> bool {
        matches!(s, "lww" | "keep-both")
    }
}

// crate::dag is not directly used here; merge operates on flat bindings.

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Result of merging two snapshots.
#[derive(Debug)]
pub struct MergeResult {
    /// Final merged bindings (relative_path -> entity_hash).
    pub merged_bindings: BTreeMap<String, Hash>,
    /// Paths that should be deleted from the tree.
    pub deletions: Vec<String>,
    /// Conflict descriptions for unresolved paths.
    pub conflicts: Vec<ConflictInfo>,
    /// Additional bindings produced by strategies like KeepBoth (R4).
    pub additional_bindings: Vec<(String, Hash)>,
}

/// Info about a single conflict, used for storage.
#[derive(Debug, Clone)]
pub struct ConflictInfo {
    pub path: String,
    pub base: Option<Hash>,
    pub local: Option<Hash>,
    pub remote: Option<Hash>,
    pub strategy: String,
}

/// The custom-dispatch sentinel (§2.3, corrected v3.9). `strategy` names the
/// sentinel; the companion `handler` field carries the target path. A bare
/// path in `strategy` is the retracted encoding and is not accepted.
pub const STRATEGY_HANDLER_SENTINEL: &str = "handler";

/// Merge strategy (EXTENSION-REVISION §2.3 built-in table / §5.1 cascade).
///
/// Every value in §2.3's table has a named arm here. That is not a style
/// preference: v3.10 pins that an accepted-but-unresolvable strategy MUST
/// degrade to a conflict entity and MUST NOT be swept into a default arm —
/// a strategy that falls into `default` is indistinguishable from one nobody
/// has heard of, and whether a peer records a divergence or silently picks a
/// side is cross-peer observable.
#[derive(Debug, Clone, PartialEq)]
pub enum MergeStrategy {
    ThreeWay,
    SourceWins,
    TargetWins,
    Manual,
    KeepBoth,
    /// §5.3 custom dispatch — the sentinel plus its companion handler path.
    /// Delegation (`merge-request` → `merge-response`) is not built here, so
    /// this degrades to a conflict entity; see the §5.3 note in `AGENTS.md`
    /// terms: the disposition for a handler that cannot be reached is a
    /// conflict entity for the one path, never a failed merge and never a
    /// silent auto-resolve.
    Handler(String),
    /// Accepted vocabulary this peer cannot resolve. `lww` is the only member
    /// today: v3.10 rules it a spec gap (the comparison basis is unspecified),
    /// keeps it in the vocabulary, and pins that it MUST degrade to a conflict
    /// entity rather than auto-resolve on a guessed basis.
    Unresolvable(String),
}

impl MergeStrategy {
    /// Parse a `strategy` value together with its companion `handler` path
    /// (§2.3). Returns `None` for a value outside the built-in table — the
    /// caller treats that config as absent and continues the cascade.
    pub fn parse(strategy: &str, handler: Option<&str>) -> Option<MergeStrategy> {
        match strategy {
            "three-way" => Some(MergeStrategy::ThreeWay),
            "source-wins" => Some(MergeStrategy::SourceWins),
            "target-wins" => Some(MergeStrategy::TargetWins),
            "manual" => Some(MergeStrategy::Manual),
            "keep-both" => Some(MergeStrategy::KeepBoth),
            "lww" => Some(MergeStrategy::Unresolvable("lww".to_string())),
            STRATEGY_HANDLER_SENTINEL => match handler {
                // The write path rejects the sentinel without a companion
                // path (§2.3); a config persisted through some other route,
                // or a bare `strategy` override, still must not resolve.
                Some(p) if !p.trim().is_empty() => Some(MergeStrategy::Handler(p.to_string())),
                _ => Some(MergeStrategy::Unresolvable(
                    STRATEGY_HANDLER_SENTINEL.to_string(),
                )),
            },
            _ => None,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            MergeStrategy::ThreeWay => "three-way",
            MergeStrategy::SourceWins => "source-wins",
            MergeStrategy::TargetWins => "target-wins",
            MergeStrategy::Manual => "manual",
            MergeStrategy::KeepBoth => "keep-both",
            MergeStrategy::Handler(_) => STRATEGY_HANDLER_SENTINEL,
            MergeStrategy::Unresolvable(name) => name.as_str(),
        }
    }
}

/// Normalize merge sides for deterministic ordering.
///
/// In "deterministic" mode, the side with the lower hash (by binary comparison)
/// is always "local" and the higher is "remote". This ensures two peers
/// independently merging the same versions produce the same result.
pub fn normalize_merge_sides<'a>(
    local: &'a BTreeMap<String, Hash>,
    remote: &'a BTreeMap<String, Hash>,
    local_version: Hash,
    remote_version: Hash,
    merge_order: &str,
) -> (
    &'a BTreeMap<String, Hash>,
    &'a BTreeMap<String, Hash>,
    Hash,
    Hash,
) {
    if merge_order == "deterministic" && remote_version < local_version {
        (remote, local, remote_version, local_version)
    } else {
        (local, remote, local_version, remote_version)
    }
}

// ---------------------------------------------------------------------------
// Merge snapshots (spec §4.3.4)
// ---------------------------------------------------------------------------

/// Merge two snapshots against a common ancestor.
///
/// `ancestor` is `None` when there is no common ancestor (create/create scenario).
/// `local` and `remote` are the two diverged snapshot bindings.
/// `prefix` is used for conflict storage paths.
/// `strategy_override` overrides per-path config lookup.
#[allow(clippy::too_many_arguments)]
pub fn merge_snapshots(
    ancestor: Option<&BTreeMap<String, Hash>>,
    local: &BTreeMap<String, Hash>,
    remote: &BTreeMap<String, Hash>,
    _prefix: &str,
    strategy_override: Option<&str>,
    store: &dyn ContentStore,
    location_index: &dyn LocationIndex,
    _local_version: Hash,
    _remote_version: Hash,
    local_peer_id: &str,
) -> MergeResult {
    let empty = BTreeMap::new();
    let base = ancestor.unwrap_or(&empty);

    // Collect all paths from all three snapshots
    let mut all_paths: Vec<String> = Vec::new();
    for path in base.keys().chain(local.keys()).chain(remote.keys()) {
        if !all_paths.contains(path) {
            all_paths.push(path.clone());
        }
    }
    all_paths.sort();

    let mut merged = BTreeMap::new();
    let mut deletions = Vec::new();
    let mut conflicts = Vec::new();
    let mut additional_bindings: Vec<(String, Hash)> = Vec::new();

    // EXTENSION-REVISION v3.1 §4.4.4 — canonical deletion-marker hash
    // (O(1) equality check; the spec recommends this over content-store
    // lookup). Under v3.1, *absence* preserves from the other side; only
    // an explicit marker is deletion.
    let marker = canonical_deletion_marker_hash();
    let is_marker = |h: &Hash| *h == marker;

    for path in &all_paths {
        let base_hash = base.get(path);
        let local_hash = local.get(path);
        let remote_hash = remote.get(path);

        match (base_hash, local_hash, remote_hash) {
            // Defensive: shouldn't appear in all_paths.
            (None, None, None) => {}

            // Both-absent fallback (v3.1 §4.4.4): preserved-unbound.
            // Cannot arise under post-v3.1 commits (which emit explicit
            // markers); normative for pre-v3.1 trees and non-conforming
            // peers.
            (Some(_), None, None) => {}

            // Same hash on both sides — same real entity OR same marker.
            // Markers are canonical so deletion-vs-deletion is NOT
            // divergent; both branches produce the same merged hash.
            (_, Some(l), Some(r)) if l == r => {
                merged.insert(path.clone(), *l);
            }

            // Local has an opinion, remote does NOT (v3.1: absence = no
            // opinion, not deletion). Preserve from local — whether
            // marker or real entity.
            (_, Some(l), None) => {
                merged.insert(path.clone(), *l);
            }

            // Remote has an opinion, local does NOT. Preserve from remote.
            (_, None, Some(r)) => {
                merged.insert(path.clone(), *r);
            }

            // Both have opinions, l != r.
            (_, Some(l), Some(r)) => {
                let l_marker = is_marker(l);
                let r_marker = is_marker(r);
                if l_marker ^ r_marker {
                    // Marker-vs-entity. Per EXTENSION-REVISION §2.3
                    // Amendment 4, `deletion_resolution` applies only when
                    // the classifier says "both changed differently". If
                    // base equals one side, this is a clean three-way:
                    // take whichever side changed.
                    if base_hash == Some(l) {
                        // Only remote changed from base — take remote.
                        merged.insert(path.clone(), *r);
                        if r_marker {
                            deletions.push(path.clone());
                        }
                    } else if base_hash == Some(r) {
                        // Only local changed from base — take local.
                        merged.insert(path.clone(), *l);
                        if l_marker {
                            deletions.push(path.clone());
                        }
                    } else {
                        // Both changed differently — `deletion_resolution`.
                        let dr =
                            find_deletion_resolution(path, location_index, store, local_peer_id);
                        let entity_side_hash = if l_marker { *r } else { *l };
                        match dr {
                            DeletionResolution::PreserveOnConflict => {
                                // Entity supersedes the marker; delete silently discarded.
                                merged.insert(path.clone(), entity_side_hash);
                            }
                            DeletionResolution::DeletionWins => {
                                // Sticky delete; edit silently discarded.
                                merged.insert(path.clone(), marker);
                                deletions.push(path.clone());
                            }
                            DeletionResolution::ThreeWayFallthrough => {
                                // Surface as conflict (edit-vs-edit shape).
                                conflicts.push(ConflictInfo {
                                    path: path.clone(),
                                    base: base_hash.copied(),
                                    local: Some(*l),
                                    remote: Some(*r),
                                    strategy: "three-way-fallthrough".to_string(),
                                });
                                // Pick local as the placeholder binding (live
                                // tree apply will translate marker → unbind).
                                merged.insert(path.clone(), *l);
                            }
                            DeletionResolution::Deterministic => {
                                // EXTENSION-REVISION v3.3 D2: lower hash
                                // wins under byte-wise lexicographic
                                // comparison. The canonical marker hash
                                // is stable, so the outcome converges
                                // across peers.
                                let winner = if l < r { *l } else { *r };
                                merged.insert(path.clone(), winner);
                                if winner == marker {
                                    deletions.push(path.clone());
                                }
                            }
                        }
                    }
                } else {
                    // Standard edit-vs-edit divergence — both real entities.
                    let strategy = find_merge_strategy(
                        path,
                        strategy_override,
                        location_index,
                        store,
                        Some(l),
                        Some(r),
                        local_peer_id,
                    );
                    match strategy {
                        MergeStrategy::SourceWins => {
                            merged.insert(path.clone(), *r);
                        }
                        MergeStrategy::TargetWins => {
                            merged.insert(path.clone(), *l);
                        }
                        MergeStrategy::ThreeWay => {
                            if base_hash.is_some() && base_hash == Some(l) {
                                merged.insert(path.clone(), *r);
                            } else if base_hash.is_some() && base_hash == Some(r) {
                                merged.insert(path.clone(), *l);
                            } else {
                                conflicts.push(ConflictInfo {
                                    path: path.clone(),
                                    base: base_hash.copied(),
                                    local: Some(*l),
                                    remote: Some(*r),
                                    strategy: "three-way".to_string(),
                                });
                                merged.insert(path.clone(), *l);
                            }
                        }
                        MergeStrategy::KeepBoth => {
                            // R4: KeepBoth only for edit-vs-edit. Local
                            // keeps original path; remote gets alternate.
                            merged.insert(path.clone(), *l);
                            let hash_prefix: String = r.digest()[0..4]
                                .iter()
                                .map(|b| format!("{:02x}", b))
                                .collect();
                            additional_bindings
                                .push((format!("{}.keep-both-{}", path, hash_prefix), *r));
                        }
                        // `manual` always conflicts by definition. The other
                        // two arms are the v3.10 [MUST]: a strategy this peer
                        // accepts but cannot resolve records the divergence
                        // instead of picking a side. `Handler` lands here
                        // because §5.3 delegation is not built — the
                        // disposition for an unreachable handler is a
                        // conflict entity for the one path, not a failed
                        // merge and not an invented resolution.
                        MergeStrategy::Manual
                        | MergeStrategy::Handler(_)
                        | MergeStrategy::Unresolvable(_) => {
                            conflicts.push(ConflictInfo {
                                path: path.clone(),
                                base: base_hash.copied(),
                                local: Some(*l),
                                remote: Some(*r),
                                strategy: strategy.as_str().to_string(),
                            });
                            merged.insert(path.clone(), *l);
                        }
                    }
                }
            }
        }
    }

    MergeResult {
        merged_bindings: merged,
        deletions,
        conflicts,
        additional_bindings,
    }
}

/// Look up `deletion_resolution` for a path. Currently scans the
/// global merge-config paths at `system/revision/config/merge/path/*`
/// (same convention as `find_merge_strategy`). Default
/// `preserve-on-conflict` if no matching config or no field.
fn find_deletion_resolution(
    path: &str,
    location_index: &dyn LocationIndex,
    store: &dyn ContentStore,
    local_peer_id: &str,
) -> DeletionResolution {
    let path_config_prefix = format!("/{}/system/revision/config/merge/path/", local_peer_id,);
    // §4.4.18's total order. This is the *sibling site* of `find_merge_strategy`
    // below: §4.4.18's pseudocode names Step 2's strategy selection, and the
    // identical selection over the identical config namespace also decides
    // `deletion_resolution`. One routed pointer, two binding sites — a fix at
    // only one leaves half the merge outcome resolved by store enumeration.
    let mut best_match: Option<((u8, usize), String, String, DeletionResolution)> = None;
    for entry in location_index.list(&path_config_prefix) {
        if let Some(config_entity) = store.get(&entry.hash) {
            if let Some((pattern, dr)) = decode_deletion_resolution_config(&config_entity.data) {
                if !path_pattern_matches(&pattern, path) {
                    continue;
                }
                let name = config_name_of(&entry.path);
                let key = pattern_specificity(&pattern);
                let wins = match &best_match {
                    None => true,
                    Some((best_key, best_pattern, best_name, _)) => {
                        more_specific((key, &pattern, name), (*best_key, best_pattern, best_name))
                    }
                };
                if wins {
                    best_match = Some((key, pattern, name.to_string(), dr));
                }
            }
        }
    }
    best_match.map(|(_, _, _, dr)| dr).unwrap_or_default()
}

fn decode_deletion_resolution_config(data: &[u8]) -> Option<(String, DeletionResolution)> {
    let val: ciborium::Value = ciborium::from_reader(data).ok()?;
    let map = val.as_map()?;
    let mut pattern = None;
    let mut dr = None;
    for (k, v) in map {
        match k.as_text() {
            Some("pattern") => pattern = v.as_text().map(|s| s.to_string()),
            Some("deletion_resolution") => {
                dr = v.as_text().and_then(DeletionResolution::parse);
            }
            _ => {}
        }
    }
    Some((pattern?, dr?))
}

// ---------------------------------------------------------------------------
// Conflict storage
// ---------------------------------------------------------------------------

/// Store a conflict entity at `/{pid}/system/revision/{prefix_hash}/conflicts/{path}`.
pub fn store_conflict(
    store: &dyn ContentStore,
    location_index: &dyn LocationIndex,
    prefix_hash: &str,
    info: &ConflictInfo,
    local_version: Hash,
    remote_version: Hash,
    local_peer_id: &str,
) -> Result<Hash, String> {
    let conflict_path = format!(
        "/{}/system/revision/{}/conflicts/{}",
        local_peer_id, prefix_hash, info.path
    );

    // Check for existing conflict to supersede
    let supersedes = location_index.get(&conflict_path);

    let mut fields = Vec::new();

    if let Some(base) = &info.base {
        fields.push((
            entity_ecf::text("base"),
            entity_ecf::Value::Bytes(base.to_bytes().to_vec()),
        ));
    }
    if let Some(local) = &info.local {
        fields.push((
            entity_ecf::text("local"),
            entity_ecf::Value::Bytes(local.to_bytes().to_vec()),
        ));
    }
    fields.push((entity_ecf::text("path"), entity_ecf::text(&info.path)));
    if let Some(remote) = &info.remote {
        fields.push((
            entity_ecf::text("remote"),
            entity_ecf::Value::Bytes(remote.to_bytes().to_vec()),
        ));
    }
    fields.push((
        entity_ecf::text("strategy"),
        entity_ecf::text(&info.strategy),
    ));
    if let Some(sup) = supersedes {
        fields.push((
            entity_ecf::text("supersedes"),
            entity_ecf::Value::Bytes(sup.to_bytes().to_vec()),
        ));
    }
    fields.push((
        entity_ecf::text("version_local"),
        entity_ecf::Value::Bytes(local_version.to_bytes().to_vec()),
    ));
    fields.push((
        entity_ecf::text("version_remote"),
        entity_ecf::Value::Bytes(remote_version.to_bytes().to_vec()),
    ));

    // Sort by key for ECF determinism
    fields.sort_by(|(a, _), (b, _)| {
        let a_text = if let entity_ecf::Value::Text(s) = a {
            s.as_str()
        } else {
            ""
        };
        let b_text = if let entity_ecf::Value::Text(s) = b {
            s.as_str()
        } else {
            ""
        };
        a_text
            .len()
            .cmp(&b_text.len())
            .then_with(|| a_text.cmp(b_text))
    });

    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
    let entity = Entity::new("system/revision/conflict", data).map_err(|e| e.to_string())?;
    let hash = store.put(entity).map_err(|e| e.to_string())?;
    location_index.set(&conflict_path, hash);
    Ok(hash)
}

// ---------------------------------------------------------------------------
// Strategy resolution (spec §5.1)
// ---------------------------------------------------------------------------

/// Find the merge strategy for a given path.
///
/// Priority (§5.1): override > per-type config > per-path config > default (three-way).
/// Global merge configs (not prefix-scoped) stored at:
///   `system/revision/config/merge/type/{type_name}` (per-type)
///   `system/revision/config/merge/path/{name}` (per-path pattern)
pub fn find_merge_strategy(
    path: &str,
    override_strategy: Option<&str>,
    location_index: &dyn LocationIndex,
    store: &dyn ContentStore,
    local_hash: Option<&Hash>,
    remote_hash: Option<&Hash>,
    local_peer_id: &str,
) -> MergeStrategy {
    if let Some(s) = override_strategy {
        if let Some(strategy) = MergeStrategy::parse(s, None) {
            return strategy;
        }
    }

    // Step 1 — per-type config. §5.1: local type first (the existing
    // entity), then the remote type when it differs (the incoming one);
    // either side's config may understand the cross-type merge. The ordering
    // is what makes two peers merging the same pair select the same config.
    let mut types_to_check: Vec<String> = Vec::new();
    for h in [local_hash, remote_hash].into_iter().flatten() {
        if let Some(entity) = store.get(h) {
            if !types_to_check.contains(&entity.entity_type) {
                types_to_check.push(entity.entity_type);
            }
        }
    }
    for type_name in &types_to_check {
        let type_config_path = format!(
            "/{}/system/revision/config/merge/type/{}",
            local_peer_id, type_name
        );
        if let Some(config_hash) = location_index.get(&type_config_path) {
            if let Some(config_entity) = store.get(&config_hash) {
                // A type-scoped config is keyed by the type name, so it
                // carries no `pattern` — requiring one here silently skipped
                // step 1 for every canonically-shaped per-type config.
                if let Some(strategy) = decode_merge_config(&config_entity.data).strategy {
                    return strategy;
                }
            }
        }
    }

    // Step 2 — per-path config: global at system/revision/config/merge/path/
    let path_config_prefix = format!("/{}/system/revision/config/merge/path/", local_peer_id,);
    // §4.4.18's total order — see `pattern_specificity` / `more_specific`.
    // `pattern.len()` was the prior scorer and it is wrong on both the rows
    // §4.4.18 calls load-bearing: it ties `*` against `a` (MERGE-SPEC-ORDER-2)
    // and it ranks `*.lock` above `docs/*` (MERGE-SPEC-ORDER-1), because
    // length is not form.
    let mut best_match: Option<((u8, usize), String, String, MergeStrategy)> = None;
    for entry in location_index.list(&path_config_prefix) {
        if let Some(config_entity) = store.get(&entry.hash) {
            let config = decode_merge_config(&config_entity.data);
            if let (Some(pattern), Some(strategy)) = (config.pattern, config.strategy) {
                if !path_pattern_matches(&pattern, path) {
                    continue;
                }
                let name = config_name_of(&entry.path);
                let key = pattern_specificity(&pattern);
                let wins = match &best_match {
                    None => true,
                    Some((best_key, best_pattern, best_name, _)) => {
                        more_specific((key, &pattern, name), (*best_key, best_pattern, best_name))
                    }
                };
                if wins {
                    best_match = Some((key, pattern, name.to_string(), strategy));
                }
            }
        }
    }
    if let Some((_, _, _, strategy)) = best_match {
        return strategy;
    }

    // Step 3 — default three-way (§5.2).
    MergeStrategy::ThreeWay
}

/// The fields of a `system/revision/merge-config` entity this module reads.
/// `pattern` is absent on type-scoped configs (they are keyed by type name);
/// `strategy` is `None` when the value is outside §2.3's built-in table, in
/// which case the caller treats the config as absent and keeps descending
/// the cascade.
struct DecodedMergeConfig {
    pattern: Option<String>,
    strategy: Option<MergeStrategy>,
}

fn decode_merge_config(data: &[u8]) -> DecodedMergeConfig {
    let mut pattern = None;
    let mut strategy_name = None;
    let mut handler = None;

    if let Ok(val) = ciborium::from_reader::<ciborium::Value, _>(data) {
        if let Some(map) = val.as_map() {
            for (k, v) in map {
                match k.as_text() {
                    Some("pattern") => pattern = v.as_text().map(|s| s.to_string()),
                    Some("strategy") => strategy_name = v.as_text().map(|s| s.to_string()),
                    Some("handler") => handler = v.as_text().map(|s| s.to_string()),
                    _ => {}
                }
            }
        }
    }

    let strategy = strategy_name
        .as_deref()
        .and_then(|s| MergeStrategy::parse(s, handler.as_deref()));
    DecodedMergeConfig { pattern, strategy }
}

/// Per-path merge-config matching (§4.4.4 Step 2 pseudocode: `glob_match(
/// config.data.pattern, path)`). Same closed four-form grammar as `exclude` —
/// `entity-core-go` resolves merge configs through its `globMatch` too, so this
/// is the cohort-aligned reading.
///
/// The hand-rolled version this replaces had two defects the grammar removes:
/// it dropped the `/` when stripping `/*` (so `docs/*` matched the sibling
/// `docsy/readme`), and it carried a `/**` form that no longer exists anywhere
/// in the corpus.
fn path_pattern_matches(pattern: &str, path: &str) -> bool {
    crate::engine::glob_match(pattern, path)
}

// ---------------------------------------------------------------------------
// §4.4.18 `pattern_specificity` — the total order, pinned `[v3.12]`
// ---------------------------------------------------------------------------

/// Rank a merge-config `pattern` by §4.4.18's table. Higher is more specific.
///
/// | Rank | Form | Rationale |
/// |---|---|---|
/// | 3 | `<lit>` — **exact** | constrains the whole subject; matches one path |
/// | 2 | `<lit>/*` — **subtree prefix** | anchored at the trie root; longer `lit` outranks shorter |
/// | 1 | `*<lit>` — **trailing literal** | unanchored — matches at any depth; longer `lit` outranks shorter |
/// | 0 | `*` — **match-all** | constrains nothing |
///
/// `literal` is the pattern with its single `*` removed, so the second
/// component orders within a rank. The rank is primary and the length never
/// crosses it: `a` (rank 3, literal length 1) outranks `docs/*` (rank 2,
/// literal length 5).
///
/// **Rank 2 above rank 1 is the one genuinely chosen rung** and §4.4.18
/// records it as a choice: for `docs/a.lock` both `docs/*` and `*.lock` match
/// and neither contains the other. The prefix names a location the operator
/// laid out; the suffix names a file kind that may appear anywhere, so the
/// anchored claim is the narrower one.
///
/// **This is revision-local and MUST NOT be shared with `EXTENSION-HISTORY`
/// §6.2's function of the same name.** That one orders *tree paths* by
/// literal segments then depth; this one orders *merge patterns* by form.
/// §4.4.18 says so in as many words — *"an implementation that shares one
/// function between the two sites is wrong at whichever site it did not come
/// from."* Ours are two private functions in two crates, which is why this
/// paragraph exists rather than a `pub use`.
fn pattern_specificity(pattern: &str) -> (u8, usize) {
    if pattern == "*" {
        return (0, 0);
    }
    if let Some(lit) = pattern.strip_suffix("/*") {
        // The `/` belongs to the literal — it is what blocks the
        // sibling-prefix false positive in `glob_match`, so it is part of
        // what the pattern constrains.
        return (2, lit.len() + 1);
    }
    if let Some(lit) = pattern.strip_prefix('*') {
        return (1, lit.len());
    }
    (3, pattern.len())
}

/// The §4.4.18 total order over `(specificity, pattern, config {name})`.
/// Returns whether `cand` beats `best`.
///
/// **Ties are impossible, and that is the requirement `[MUST]`.** Rank plus
/// literal length is not yet a total order — two configs may legitimately
/// carry the same `pattern` under different `{name}`s. The remaining tie goes
/// to lexicographic byte order on `pattern`, then on `{name}`; both are
/// peer-independent, so every conformant peer selects the same config. The
/// `specificity > best_specificity` comparison this replaces kept whichever
/// config `location_index.list` happened to yield first, and that ordering is
/// unspecified — two peers with identical configs and identical content could
/// resolve the same conflict differently, with nothing failing anywhere.
fn more_specific(cand: ((u8, usize), &str, &str), best: ((u8, usize), &str, &str)) -> bool {
    let (cand_key, cand_pattern, cand_name) = cand;
    let (best_key, best_pattern, best_name) = best;
    match cand_key.cmp(&best_key) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        // Both remaining keys run lower-wins, the opposite direction from the
        // rank — spelled out rather than folded into one tuple compare.
        std::cmp::Ordering::Equal => match cand_pattern.cmp(best_pattern) {
            std::cmp::Ordering::Less => true,
            std::cmp::Ordering::Greater => false,
            std::cmp::Ordering::Equal => cand_name < best_name,
        },
    }
}

/// The `{name}` of a `…/system/revision/config/merge/path/{name}` binding.
///
/// Read from the binding path, not the entity: two configs with byte-identical
/// data are one content-addressed entity under two paths, so the name is the
/// only thing that distinguishes them.
fn config_name_of(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use entity_store::{MemoryContentStore, MemoryLocationIndex};

    fn stores() -> (MemoryContentStore, MemoryLocationIndex) {
        (MemoryContentStore::new(), MemoryLocationIndex::new())
    }

    fn put_test_entity(store: &dyn ContentStore, type_str: &str, content: &str) -> Hash {
        let data = entity_ecf::to_ecf(&entity_ecf::text(content));
        let entity = Entity::new(type_str, data).unwrap();
        store.put(entity).unwrap()
    }

    #[test]
    fn test_clean_merge_no_conflicts() {
        let (store, li) = stores();
        let h1 = put_test_entity(&store, "test/type", "file1");
        let h2 = put_test_entity(&store, "test/type", "file2");
        let h3 = put_test_entity(&store, "test/type", "file3");

        let mut base = BTreeMap::new();
        base.insert("a".to_string(), h1);

        let mut local = BTreeMap::new();
        local.insert("a".to_string(), h1); // unchanged
        local.insert("b".to_string(), h2); // local added

        let mut remote = BTreeMap::new();
        remote.insert("a".to_string(), h1); // unchanged
        remote.insert("c".to_string(), h3); // remote added

        let result = merge_snapshots(
            Some(&base),
            &local,
            &remote,
            "data/",
            None,
            &store,
            &li,
            Hash::zero(),
            Hash::zero(),
            "test-peer",
        );

        assert!(result.conflicts.is_empty());
        assert!(result.deletions.is_empty());
        assert_eq!(result.merged_bindings.len(), 3);
        assert_eq!(result.merged_bindings["a"], h1);
        assert_eq!(result.merged_bindings["b"], h2);
        assert_eq!(result.merged_bindings["c"], h3);
    }

    #[test]
    fn test_both_changed_same_value() {
        let (store, li) = stores();
        let h1 = put_test_entity(&store, "test/type", "old");
        let h2 = put_test_entity(&store, "test/type", "new");

        let mut base = BTreeMap::new();
        base.insert("a".to_string(), h1);

        let mut local = BTreeMap::new();
        local.insert("a".to_string(), h2);

        let mut remote = BTreeMap::new();
        remote.insert("a".to_string(), h2);

        let result = merge_snapshots(
            Some(&base),
            &local,
            &remote,
            "data/",
            None,
            &store,
            &li,
            Hash::zero(),
            Hash::zero(),
            "test-peer",
        );

        assert!(result.conflicts.is_empty());
        assert_eq!(result.merged_bindings["a"], h2);
    }

    #[test]
    fn test_three_way_only_remote_changed() {
        let (store, li) = stores();
        let h1 = put_test_entity(&store, "test/type", "original");
        let h2 = put_test_entity(&store, "test/type", "changed");

        let mut base = BTreeMap::new();
        base.insert("a".to_string(), h1);

        let mut local = BTreeMap::new();
        local.insert("a".to_string(), h1); // unchanged

        let mut remote = BTreeMap::new();
        remote.insert("a".to_string(), h2); // changed

        let result = merge_snapshots(
            Some(&base),
            &local,
            &remote,
            "data/",
            None,
            &store,
            &li,
            Hash::zero(),
            Hash::zero(),
            "test-peer",
        );

        assert!(result.conflicts.is_empty());
        assert_eq!(result.merged_bindings["a"], h2); // takes remote
    }

    #[test]
    fn test_conflict_both_changed_differently() {
        let (store, li) = stores();
        let h0 = put_test_entity(&store, "test/type", "base");
        let h1 = put_test_entity(&store, "test/type", "local_change");
        let h2 = put_test_entity(&store, "test/type", "remote_change");

        let mut base = BTreeMap::new();
        base.insert("a".to_string(), h0);

        let mut local = BTreeMap::new();
        local.insert("a".to_string(), h1);

        let mut remote = BTreeMap::new();
        remote.insert("a".to_string(), h2);

        let result = merge_snapshots(
            Some(&base),
            &local,
            &remote,
            "data/",
            None,
            &store,
            &li,
            Hash::zero(),
            Hash::zero(),
            "test-peer",
        );

        assert_eq!(result.conflicts.len(), 1);
        assert_eq!(result.conflicts[0].path, "a");
        // Local stays visible
        assert_eq!(result.merged_bindings["a"], h1);
    }

    #[test]
    fn delete_vs_edit_default_preserve_on_conflict() {
        // EXTENSION-REVISION v3.1 §2.3 Amendment 4: delete-vs-edit
        // (deletion marker on one side, real entity on the other) is
        // governed by `deletion_resolution`. Default `preserve-on-conflict`
        // — the entity supersedes the marker; the delete is silently
        // discarded; no conflict entity written.
        let (store, li) = stores();
        let h0 = put_test_entity(&store, "test/type", "base");
        let h1 = put_test_entity(&store, "test/type", "edited");
        let marker = canonical_deletion_marker_hash();

        let mut base = BTreeMap::new();
        base.insert("a".to_string(), h0);

        // Local bound the deletion marker (= explicit delete); remote edited.
        let mut local = BTreeMap::new();
        local.insert("a".to_string(), marker);
        let mut remote = BTreeMap::new();
        remote.insert("a".to_string(), h1);

        let result = merge_snapshots(
            Some(&base),
            &local,
            &remote,
            "data/",
            None,
            &store,
            &li,
            Hash::zero(),
            Hash::zero(),
            "test-peer",
        );

        // Default preserve-on-conflict: no conflict; remote entity wins.
        assert_eq!(result.conflicts.len(), 0);
        assert_eq!(result.merged_bindings["a"], h1);
    }

    #[test]
    fn absent_side_preserves_other_side_under_v3_1() {
        // EXTENSION-REVISION v3.1 §4.4.4: absence is "no opinion", not
        // deletion. Pre-v3.1, this case would have been classified as
        // edit-vs-delete; under v3.1, the side with an opinion wins
        // without surfacing a conflict.
        let (store, li) = stores();
        let h0 = put_test_entity(&store, "test/type", "base");
        let h1 = put_test_entity(&store, "test/type", "edited");

        let mut base = BTreeMap::new();
        base.insert("a".to_string(), h0);

        let local = BTreeMap::new();
        let mut remote = BTreeMap::new();
        remote.insert("a".to_string(), h1);

        let result = merge_snapshots(
            Some(&base),
            &local,
            &remote,
            "data/",
            None,
            &store,
            &li,
            Hash::zero(),
            Hash::zero(),
            "test-peer",
        );

        assert_eq!(result.conflicts.len(), 0);
        assert_eq!(result.merged_bindings["a"], h1);
    }

    #[test]
    fn test_source_wins_strategy() {
        let (store, li) = stores();
        let h0 = put_test_entity(&store, "test/type", "base");
        let h1 = put_test_entity(&store, "test/type", "local");
        let h2 = put_test_entity(&store, "test/type", "remote");

        let mut base = BTreeMap::new();
        base.insert("a".to_string(), h0);

        let mut local = BTreeMap::new();
        local.insert("a".to_string(), h1);

        let mut remote = BTreeMap::new();
        remote.insert("a".to_string(), h2);

        let result = merge_snapshots(
            Some(&base),
            &local,
            &remote,
            "data/",
            Some("source-wins"),
            &store,
            &li,
            Hash::zero(),
            Hash::zero(),
            "test-peer",
        );

        assert!(result.conflicts.is_empty());
        assert_eq!(result.merged_bindings["a"], h2); // remote wins
    }

    #[test]
    fn test_target_wins_strategy() {
        let (store, li) = stores();
        let h0 = put_test_entity(&store, "test/type", "base");
        let h1 = put_test_entity(&store, "test/type", "local");
        let h2 = put_test_entity(&store, "test/type", "remote");

        let mut base = BTreeMap::new();
        base.insert("a".to_string(), h0);

        let mut local = BTreeMap::new();
        local.insert("a".to_string(), h1);

        let mut remote = BTreeMap::new();
        remote.insert("a".to_string(), h2);

        let result = merge_snapshots(
            Some(&base),
            &local,
            &remote,
            "data/",
            Some("target-wins"),
            &store,
            &li,
            Hash::zero(),
            Hash::zero(),
            "test-peer",
        );

        assert!(result.conflicts.is_empty());
        assert_eq!(result.merged_bindings["a"], h1); // local wins
    }

    #[test]
    fn test_conflict_storage_with_supersedes() {
        let (store, li) = stores();

        let info = ConflictInfo {
            path: "foo/bar".to_string(),
            base: None,
            local: Some(Hash::zero()),
            remote: Some(Hash::zero()),
            strategy: "three-way".to_string(),
        };

        let ph = crate::prefix_hash(&crate::resolve_prefix("data/", "peer1"));
        let h1 =
            store_conflict(&store, &li, &ph, &info, Hash::zero(), Hash::zero(), "peer1").unwrap();
        assert!(h1 != Hash::zero());

        // Store again — should supersede
        let h2 =
            store_conflict(&store, &li, &ph, &info, Hash::zero(), Hash::zero(), "peer1").unwrap();
        assert!(h2 != Hash::zero());

        // The second conflict should have a supersedes field pointing to h1
        let entity = store.get(&h2).unwrap();
        let val: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let has_supersedes = map.iter().any(|(k, _)| k.as_text() == Some("supersedes"));
        assert!(has_supersedes);
    }

    #[test]
    fn test_keep_both_edit_edit() {
        let (store, li) = stores();
        let h0 = put_test_entity(&store, "test/type", "base");
        let h1 = put_test_entity(&store, "test/type", "local_v");
        let h2 = put_test_entity(&store, "test/type", "remote_v");

        let mut base = BTreeMap::new();
        base.insert("a".to_string(), h0);

        let mut local = BTreeMap::new();
        local.insert("a".to_string(), h1);

        let mut remote = BTreeMap::new();
        remote.insert("a".to_string(), h2);

        let result = merge_snapshots(
            Some(&base),
            &local,
            &remote,
            "data/",
            Some("keep-both"),
            &store,
            &li,
            Hash::zero(),
            Hash::zero(),
            "test-peer",
        );

        assert!(result.conflicts.is_empty());
        assert_eq!(result.merged_bindings["a"], h1);
        assert_eq!(result.additional_bindings.len(), 1);
        let (ref keep_path, keep_hash) = result.additional_bindings[0];
        assert!(keep_path.starts_with("a.keep-both-"));
        assert_eq!(keep_hash, h2);
        // Hash prefix is 8 hex chars
        let suffix = keep_path.strip_prefix("a.keep-both-").unwrap();
        assert_eq!(suffix.len(), 8);
    }

    #[test]
    fn keep_both_does_not_apply_to_delete_vs_edit() {
        // EXTENSION-REVISION v3.1 §2.3: `keep-both` is rejected for
        // `deletion_resolution` (the path falls through to the default
        // `preserve-on-conflict`). Even if the strategy override is
        // `keep-both`, the delete-vs-edit case is governed by
        // deletion_resolution, NOT merge strategy. With default
        // preserve-on-conflict, no conflict and no additional binding.
        let (store, li) = stores();
        let h0 = put_test_entity(&store, "test/type", "base");
        let h1 = put_test_entity(&store, "test/type", "edited");
        let marker = canonical_deletion_marker_hash();

        let mut base = BTreeMap::new();
        base.insert("a".to_string(), h0);

        // Local bound the deletion marker; remote edited.
        let mut local = BTreeMap::new();
        local.insert("a".to_string(), marker);
        let mut remote = BTreeMap::new();
        remote.insert("a".to_string(), h1);

        let result = merge_snapshots(
            Some(&base),
            &local,
            &remote,
            "data/",
            Some("keep-both"),
            &store,
            &li,
            Hash::zero(),
            Hash::zero(),
            "test-peer",
        );

        assert_eq!(result.conflicts.len(), 0);
        assert!(result.additional_bindings.is_empty());
        assert_eq!(result.merged_bindings["a"], h1);
    }

    #[test]
    fn test_merge_config_wildcard_strategy() {
        let (store, li) = stores();

        // Global merge config at system/revision/config/merge/path/{name}
        let cfg_data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "pattern" => entity_ecf::text("*"),
            "strategy" => entity_ecf::text("source-wins")
        });
        let cfg_entity = Entity::new("system/revision/merge-config", cfg_data).unwrap();
        let cfg_hash = store.put(cfg_entity).unwrap();
        li.set("/test-peer/system/revision/config/merge/path/all", cfg_hash);

        let h0 = put_test_entity(&store, "test/type", "base");
        let h1 = put_test_entity(&store, "test/type", "local");
        let h2 = put_test_entity(&store, "test/type", "remote");

        let mut base = BTreeMap::new();
        base.insert("a".to_string(), h0);
        let mut local = BTreeMap::new();
        local.insert("a".to_string(), h1);
        let mut remote = BTreeMap::new();
        remote.insert("a".to_string(), h2);

        // No strategy override — should discover from config
        let result = merge_snapshots(
            Some(&base),
            &local,
            &remote,
            "data/",
            None,
            &store,
            &li,
            Hash::zero(),
            Hash::zero(),
            "test-peer",
        );

        assert!(result.conflicts.is_empty());
        assert_eq!(result.merged_bindings["a"], h2); // source-wins → remote
    }

    #[test]
    fn test_merge_config_path_pattern() {
        let (store, li) = stores();

        // Global merge config for "docs/*" paths
        let cfg_data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "pattern" => entity_ecf::text("docs/*"),
            "strategy" => entity_ecf::text("target-wins")
        });
        let cfg_entity = Entity::new("system/revision/merge-config", cfg_data).unwrap();
        let cfg_hash = store.put(cfg_entity).unwrap();
        li.set(
            "/test-peer/system/revision/config/merge/path/docs-rule",
            cfg_hash,
        );

        let h0 = put_test_entity(&store, "test/type", "base");
        let h1 = put_test_entity(&store, "test/type", "local");
        let h2 = put_test_entity(&store, "test/type", "remote");

        let mut base = BTreeMap::new();
        base.insert("docs/readme".to_string(), h0);
        let mut local = BTreeMap::new();
        local.insert("docs/readme".to_string(), h1);
        let mut remote = BTreeMap::new();
        remote.insert("docs/readme".to_string(), h2);

        let result = merge_snapshots(
            Some(&base),
            &local,
            &remote,
            "data/",
            None,
            &store,
            &li,
            Hash::zero(),
            Hash::zero(),
            "test-peer",
        );

        assert!(result.conflicts.is_empty());
        assert_eq!(result.merged_bindings["docs/readme"], h1); // target-wins → local
    }

    #[test]
    fn test_merge_config_keep_both_via_config() {
        let (store, li) = stores();

        // Global merge config: keep-both for all paths
        let cfg_data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "pattern" => entity_ecf::text("*"),
            "strategy" => entity_ecf::text("keep-both")
        });
        let cfg_entity = Entity::new("system/revision/merge-config", cfg_data).unwrap();
        let cfg_hash = store.put(cfg_entity).unwrap();
        li.set("/test-peer/system/revision/config/merge/path/all", cfg_hash);

        let h0 = put_test_entity(&store, "test/type", "base");
        let h1 = put_test_entity(&store, "test/type", "local_v");
        let h2 = put_test_entity(&store, "test/type", "remote_v");

        let mut base = BTreeMap::new();
        base.insert("shared".to_string(), h0);
        let mut local = BTreeMap::new();
        local.insert("shared".to_string(), h1);
        let mut remote = BTreeMap::new();
        remote.insert("shared".to_string(), h2);

        let result = merge_snapshots(
            Some(&base),
            &local,
            &remote,
            "data/",
            None,
            &store,
            &li,
            Hash::zero(),
            Hash::zero(),
            "test-peer",
        );

        assert!(
            result.conflicts.is_empty(),
            "keep-both via config should resolve edit-vs-edit"
        );
        assert_eq!(result.merged_bindings["shared"], h1);
        assert_eq!(result.additional_bindings.len(), 1);
        assert!(result.additional_bindings[0]
            .0
            .starts_with("shared.keep-both-"));
        assert_eq!(result.additional_bindings[0].1, h2);
    }

    // -----------------------------------------------------------------
    // §5.1 cascade — step 1 (per-type config) and the v3.10 vocabulary
    // -----------------------------------------------------------------

    /// Drive the same edit-vs-edit divergence every cascade test below uses:
    /// one path, all three sides different, so the strategy arm is what
    /// decides the outcome.
    fn diverge(
        store: &dyn ContentStore,
        li: &dyn LocationIndex,
        local_type: &str,
        remote_type: &str,
    ) -> (MergeResult, Hash, Hash) {
        let h0 = put_test_entity(store, local_type, "base");
        let h1 = put_test_entity(store, local_type, "local");
        let h2 = put_test_entity(store, remote_type, "remote");

        let mut base = BTreeMap::new();
        base.insert("doc".to_string(), h0);
        let mut local = BTreeMap::new();
        local.insert("doc".to_string(), h1);
        let mut remote = BTreeMap::new();
        remote.insert("doc".to_string(), h2);

        let result = merge_snapshots(
            Some(&base),
            &local,
            &remote,
            "data/",
            None,
            store,
            li,
            Hash::zero(),
            Hash::zero(),
            "test-peer",
        );
        (result, h1, h2)
    }

    fn install_config(
        store: &dyn ContentStore,
        li: &dyn LocationIndex,
        tree_path: &str,
        fields: Vec<(&str, &str)>,
    ) {
        let pairs: Vec<(entity_ecf::Value, entity_ecf::Value)> = fields
            .into_iter()
            .map(|(k, v)| (entity_ecf::text(k), entity_ecf::text(v)))
            .collect();
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(pairs));
        let entity = Entity::new("system/revision/merge-config", data).unwrap();
        let hash = store.put(entity).unwrap();
        li.set(tree_path, hash);
    }

    /// CONTROL for the per-type rows: the identical divergence with NO config
    /// conflicts. Without it a per-type PASS cannot be attributed to the
    /// config.
    #[test]
    fn test_cascade_control_no_config_conflicts() {
        let (store, li) = stores();
        let (result, h1, _) = diverge(&store, &li, "test/typed-doc", "test/typed-doc");
        assert_eq!(result.conflicts.len(), 1, "no config → three-way conflict");
        assert_eq!(result.conflicts[0].strategy, "three-way");
        assert_eq!(result.merged_bindings["doc"], h1);
    }

    /// §5.1 step 1. A type-scoped config is keyed by the type name and
    /// carries no `pattern` — the shape every implementation writes. Requiring
    /// `pattern` here skipped step 1 entirely for the canonical shape.
    #[test]
    fn test_per_type_config_without_pattern_is_consulted() {
        let (store, li) = stores();
        install_config(
            &store,
            &li,
            "/test-peer/system/revision/config/merge/type/test/typed-doc",
            vec![("strategy", "source-wins")],
        );
        let (result, _, h2) = diverge(&store, &li, "test/typed-doc", "test/typed-doc");
        assert!(
            result.conflicts.is_empty(),
            "per-type source-wins must resolve the conflict"
        );
        assert_eq!(result.merged_bindings["doc"], h2);
    }

    /// §5.1 cascade order: step 1 (type) outranks step 2 (path).
    #[test]
    fn test_per_type_config_outranks_per_path_config() {
        let (store, li) = stores();
        install_config(
            &store,
            &li,
            "/test-peer/system/revision/config/merge/type/test/typed-doc",
            vec![("strategy", "source-wins")],
        );
        install_config(
            &store,
            &li,
            "/test-peer/system/revision/config/merge/path/all",
            vec![("pattern", "*"), ("strategy", "target-wins")],
        );
        let (result, _, h2) = diverge(&store, &li, "test/typed-doc", "test/typed-doc");
        assert!(result.conflicts.is_empty());
        assert_eq!(
            result.merged_bindings["doc"], h2,
            "type config (source-wins) must outrank the path config (target-wins)"
        );
    }

    /// §5.1: when the types differ, the remote type's config gets its turn
    /// after the local type's — either side's config may understand the merge.
    #[test]
    fn test_per_type_config_falls_through_to_remote_type() {
        let (store, li) = stores();
        install_config(
            &store,
            &li,
            "/test-peer/system/revision/config/merge/type/test/incoming-doc",
            vec![("strategy", "source-wins")],
        );
        let (result, _, h2) = diverge(&store, &li, "test/local-doc", "test/incoming-doc");
        assert!(result.conflicts.is_empty());
        assert_eq!(result.merged_bindings["doc"], h2);
    }

    /// v3.10 [MUST]: the `handler` sentinel this peer cannot dispatch degrades
    /// to a conflict entity — not a silent fall-through to three-way, and not
    /// an invented resolution. The conflict names the strategy that produced
    /// it, which is what distinguishes this from the config being ignored.
    #[test]
    fn test_unreachable_handler_degrades_to_conflict() {
        let (store, li) = stores();
        install_config(
            &store,
            &li,
            "/test-peer/system/revision/config/merge/type/test/typed-doc",
            vec![
                ("strategy", "handler"),
                ("handler", "app/merge/not-installed"),
            ],
        );
        let (result, h1, _) = diverge(&store, &li, "test/typed-doc", "test/typed-doc");
        assert_eq!(result.conflicts.len(), 1);
        assert_eq!(
            result.conflicts[0].strategy, "handler",
            "the conflict must name the configured strategy, not the default arm"
        );
        assert_eq!(result.merged_bindings["doc"], h1);
    }

    /// v3.10 [MUST]: `lww` stays in the vocabulary and MUST degrade to a
    /// conflict entity — the comparison basis it needs is unspecified, so
    /// resolving it on a guessed basis is a per-implementation convergence bug.
    #[test]
    fn test_lww_strategy_degrades_to_conflict() {
        let (store, li) = stores();
        install_config(
            &store,
            &li,
            "/test-peer/system/revision/config/merge/path/all",
            vec![("pattern", "*"), ("strategy", "lww")],
        );
        let (result, h1, _) = diverge(&store, &li, "test/typed-doc", "test/typed-doc");
        assert_eq!(result.conflicts.len(), 1);
        assert_eq!(result.conflicts[0].strategy, "lww");
        assert_eq!(result.merged_bindings["doc"], h1);
    }

    /// §5.1 "Path argument scope": a `pattern: "*"` config matches ALL paths
    /// within any merge, nested keys included — the peer-wide footgun v7.70
    /// A1 names. (Single-segment `*` is what every implementation's stdlib
    /// glob gives by default; this asserts the specified reading.)
    #[test]
    fn test_star_pattern_matches_nested_path() {
        assert!(path_pattern_matches("*", "docs/deep/readme"));
        assert!(path_pattern_matches("*", "top"));
        // §2.4 form 2 crosses `/` at any depth, so the subtree form is
        // `docs/*` — `docs/**` is not in the grammar any more.
        assert!(path_pattern_matches("docs/*", "docs/deep/readme"));
        assert!(!path_pattern_matches("docs/*", "other/readme"));
        // The retained `/` — the sibling-prefix false positive the old
        // hand-rolled matcher had (it stripped `/*` down to `docs`).
        assert!(!path_pattern_matches("docs/*", "docsy/readme"));
    }

    // -----------------------------------------------------------------
    // §4.4.18 merge-matcher vectors (REQUIRED, `[v3.12]`)
    //
    // "This surface is merge-outcome-determining, so it is not validated by
    // prose." Each drives `find_merge_strategy` directly, which is the
    // function §4.4.18 Step 2 describes; the two `SPEC-ORDER` rows and the
    // `SPEC-TIE` row are the ones that need more than one matching config,
    // which is the configuration an operator reaches as soon as they have
    // both a location rule and a file-kind rule.
    // -----------------------------------------------------------------

    /// Bind a path-scoped merge config at `…/config/merge/path/{name}`.
    fn put_path_config(
        store: &dyn ContentStore,
        li: &dyn LocationIndex,
        name: &str,
        pattern: &str,
        strategy: &str,
    ) {
        let data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "pattern" => entity_ecf::text(pattern),
            "strategy" => entity_ecf::text(strategy)
        });
        let hash = store
            .put(Entity::new("system/revision/merge-config", data).unwrap())
            .unwrap();
        li.set(
            &format!("/test-peer/system/revision/config/merge/path/{}", name),
            hash,
        );
    }

    fn strategy_for(li: &dyn LocationIndex, store: &dyn ContentStore, path: &str) -> MergeStrategy {
        find_merge_strategy(path, None, li, store, None, None, "test-peer")
    }

    /// `MERGE-PATTERN-SUFFIX-1` — form 3 is a **whole-subject byte suffix**
    /// and reaches any depth. §5.1's own worked example, and it is
    /// unexpressible under §5.4.
    #[test]
    fn merge_pattern_suffix_1() {
        let (store, li) = stores();
        put_path_config(&store, &li, "lockfiles", "*.lock", "source-wins");
        assert_eq!(
            strategy_for(&li, &store, "deep/nested/a.lock"),
            MergeStrategy::SourceWins
        );
    }

    /// `MERGE-PATTERN-SUBTREE-1` — form 2 crosses `/` at depth, and the
    /// retained `/` blocks the sibling-prefix false positive.
    #[test]
    fn merge_pattern_subtree_1() {
        let (store, li) = stores();
        put_path_config(&store, &li, "docs-rule", "docs/*", "target-wins");
        assert_eq!(
            strategy_for(&li, &store, "docs/deep/nested/x"),
            MergeStrategy::TargetWins
        );
        // `docsy/x` is NOT matched — falls through to the §5.2 default.
        assert_eq!(
            strategy_for(&li, &store, "docsy/x"),
            MergeStrategy::ThreeWay
        );
    }

    /// `MERGE-SPEC-ORDER-1` — **the row that fails on a first-match-wins
    /// implementation.** `docs/*` (rank 2, anchored subtree) outranks
    /// `*.lock` (rank 1, floating suffix) at `docs/a.lock`, where both match
    /// and neither contains the other.
    ///
    /// Also the row that fails on the `pattern.len()` scorer this replaced:
    /// `*.lock` is 6 bytes and `docs/*` is 6, so length alone ties and the
    /// store's enumeration decided.
    #[test]
    fn merge_spec_order_1_anchored_prefix_outranks_floating_suffix() {
        for (label, order) in [
            ("docs first", ["docs-rule", "lock-rule"]),
            ("lock first", ["lock-rule", "docs-rule"]),
        ] {
            let (store, li) = stores();
            for name in order {
                match name {
                    "docs-rule" => put_path_config(&store, &li, name, "docs/*", "target-wins"),
                    _ => put_path_config(&store, &li, name, "*.lock", "source-wins"),
                }
            }
            assert_eq!(
                strategy_for(&li, &store, "docs/a.lock"),
                MergeStrategy::TargetWins,
                "insertion order: {label}"
            );
        }
    }

    /// `MERGE-SPEC-ORDER-2` — exact (rank 3) outranks match-all (rank 0)
    /// **regardless of enumeration order**. The pattern strings are
    /// deliberately one character each: any scorer that ranks by total
    /// pattern length rather than by form ties here, and a tie is resolved by
    /// store enumeration order.
    #[test]
    fn merge_spec_order_2_exact_outranks_match_all() {
        for (label, order) in [
            ("star first", ["z-star", "a-exact"]),
            ("exact first", ["a-exact", "z-star"]),
        ] {
            let (store, li) = stores();
            for name in order {
                match name {
                    "z-star" => put_path_config(&store, &li, name, "*", "source-wins"),
                    _ => put_path_config(&store, &li, name, "a", "target-wins"),
                }
            }
            assert_eq!(
                strategy_for(&li, &store, "a"),
                MergeStrategy::TargetWins,
                "insertion order: {label}"
            );
        }
    }

    /// A `LocationIndex` that hands `list` back **reversed**.
    ///
    /// `MemoryLocationIndex` is `BTreeMap`-backed, so its `list` is sorted by
    /// path — and within one config prefix, path order *is* `{name}` order,
    /// which happens to coincide with key 4. Against that store a
    /// keep-whichever-came-first implementation passes `MERGE-SPEC-TIE-1` by
    /// luck, in **both** insertion orders: re-inserting in the other order
    /// does not change what the store enumerates. §4.4.18's point is that
    /// `list_entities` ordering is *unspecified*, so the vector has to vary
    /// enumeration, not insertion. This double is that variation, and it is
    /// what makes the row fail against rank-only comparison.
    struct ReverseListIndex(MemoryLocationIndex);

    impl LocationIndex for ReverseListIndex {
        fn set(&self, path: &str, hash: Hash) {
            self.0.set(path, hash)
        }
        fn get(&self, path: &str) -> Option<Hash> {
            self.0.get(path)
        }
        fn has(&self, path: &str) -> bool {
            self.0.has(path)
        }
        fn remove(&self, path: &str) -> Option<Hash> {
            self.0.remove(path)
        }
        fn len_prefix(&self, prefix: &str) -> usize {
            self.0.len_prefix(prefix)
        }
        fn list(&self, prefix: &str) -> Vec<entity_store::LocationEntry> {
            let mut entries = self.0.list(prefix);
            entries.reverse();
            entries
        }
    }

    /// `MERGE-SPEC-TIE-1` — **the row that catches a peer that kept
    /// rank-only comparison.** Two configs, the *same* `pattern`, different
    /// `{name}`; lexicographic `{name}` breaks the tie, so the result does
    /// not depend on enumeration order.
    ///
    /// Run against both a forward- and a reverse-enumerating store, because
    /// the sorted store alone cannot discriminate (see [`ReverseListIndex`]).
    #[test]
    fn merge_spec_tie_1_same_pattern_resolves_by_config_name() {
        for (label, reverse) in [("sorted store", false), ("reversed store", true)] {
            let store = MemoryContentStore::new();
            let li: Box<dyn LocationIndex> = if reverse {
                Box::new(ReverseListIndex(MemoryLocationIndex::new()))
            } else {
                Box::new(MemoryLocationIndex::new())
            };
            put_path_config(&store, li.as_ref(), "z-cfg", "docs/*", "source-wins");
            put_path_config(&store, li.as_ref(), "a-cfg", "docs/*", "target-wins");
            assert_eq!(
                strategy_for(li.as_ref(), &store, "docs/readme"),
                MergeStrategy::TargetWins,
                "enumeration: {label}"
            );
        }
    }

    /// §4.4.18's **key 3 — lexicographic byte order on `pattern`— is
    /// unreachable, and we say so at the code rather than leave an
    /// unexercised branch reading as covered.**
    ///
    /// Key 3 only runs when two *distinct* patterns tie on rank and literal
    /// length **and both match the same subject**. Under §2.4's four forms no
    /// such pair exists: rank 3 is exact (two exacts matching one subject are
    /// the same string), rank 2 patterns of equal literal length are distinct
    /// prefixes and therefore disjoint, rank 1 likewise for suffixes, and
    /// rank 0 has exactly one member (`*`). So the only reachable tie is the
    /// same-pattern one, which key 4 (`{name}`) decides — which is exactly
    /// the case `MERGE-SPEC-TIE-1` describes.
    ///
    /// Proven by enumeration over the forms rather than asserted: for each
    /// rank, a same-length distinct pair, shown to have no common subject.
    #[test]
    fn merge_spec_key_3_pattern_order_is_unreachable_by_construction() {
        // Rank 2 — equal literal length, distinct prefixes.
        for subject in ["docs/x", "abcd/x", "docs/abcd/x", "x"] {
            assert!(
                !(path_pattern_matches("docs/*", subject)
                    && path_pattern_matches("abcd/*", subject)),
                "no subject may match both rank-2 patterns: {subject}"
            );
        }
        // Rank 1 — equal literal length, distinct suffixes.
        for subject in ["a.lock", "a.mock", "a.lock.mock", "x"] {
            assert!(
                !(path_pattern_matches("*.lock", subject)
                    && path_pattern_matches("*.mock", subject)),
                "no subject may match both rank-1 patterns: {subject}"
            );
        }
        // Rank 3 — two exacts matching one subject are the same pattern, so
        // the tie is key 4's, not key 3's.
        assert!(path_pattern_matches("docs/a", "docs/a"));
        assert!(!path_pattern_matches("docs/b", "docs/a"));
        // Rank 0 has one member.
        assert_eq!(pattern_specificity("*"), (0, 0));
    }

    /// The sibling site: `deletion_resolution` selection reads the same
    /// namespace with the same order, and §4.4.18's pseudocode names only the
    /// strategy half. A fix at one site and not the other leaves half the
    /// merge outcome resolved by store enumeration.
    ///
    /// Uses `MERGE-SPEC-ORDER-2`'s one-character pair for the same reason
    /// that row does — `*` and `a` tie under any length-based scorer — and
    /// runs it against a reverse-enumerating store so a keep-whichever-came-
    /// first implementation cannot pass on the sorted store's luck.
    #[test]
    fn merge_spec_order_binds_deletion_resolution_too() {
        let put_dr = |store: &dyn ContentStore,
                      li: &dyn LocationIndex,
                      name: &str,
                      pattern: &str,
                      dr: &str| {
            let data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
                "pattern" => entity_ecf::text(pattern),
                "deletion_resolution" => entity_ecf::text(dr)
            });
            let hash = store
                .put(Entity::new("system/revision/merge-config", data).unwrap())
                .unwrap();
            li.set(
                &format!("/test-peer/system/revision/config/merge/path/{}", name),
                hash,
            );
        };

        for (label, reverse) in [("sorted store", false), ("reversed store", true)] {
            let store = MemoryContentStore::new();
            let li: Box<dyn LocationIndex> = if reverse {
                Box::new(ReverseListIndex(MemoryLocationIndex::new()))
            } else {
                Box::new(MemoryLocationIndex::new())
            };
            // `*` is rank 0 and `a` is rank 3; both match the path `a`, and
            // both are one byte, so only the rank separates them.
            put_dr(&store, li.as_ref(), "z-star", "*", "deletion-wins");
            put_dr(&store, li.as_ref(), "a-exact", "a", "preserve-on-conflict");
            assert_eq!(
                find_deletion_resolution("a", li.as_ref(), &store, "test-peer"),
                DeletionResolution::PreserveOnConflict,
                "enumeration: {label}"
            );
        }
    }

    /// The rank table itself, since every vector above depends on it and
    /// each row is one comparison.
    #[test]
    fn merge_pattern_specificity_rank_table() {
        assert_eq!(pattern_specificity("*"), (0, 0));
        assert_eq!(pattern_specificity("*.lock"), (1, 5));
        assert_eq!(pattern_specificity("docs/*"), (2, 5));
        assert_eq!(pattern_specificity("docs/readme"), (3, 11));
        // Rank is primary: a one-byte exact outranks a long prefix.
        assert!(pattern_specificity("a") > pattern_specificity("very/long/prefix/*"));
        // Within a rank, the longer literal wins.
        assert!(pattern_specificity("docs/deep/*") > pattern_specificity("docs/*"));
        assert!(pattern_specificity("*.lockfile") > pattern_specificity("*.lock"));
    }
}
