//! system/tree handler: get, put, snapshot, diff, merge, extract.
//!
//! Per spec §6.3: the tree handler manages entity storage through
//! the content store (Hash → Entity) and location index (Path → Hash).
//!
//! Operations:
//! - `get`: retrieve an entity by path (or listing for prefix)
//! - `put`: store/remove an entity at a path
//! - `snapshot`: capture all bindings under a prefix (returns trie root)
//! - `diff`: compare two snapshots
//! - `merge`: apply source snapshot bindings into the live tree
//! - `extract`: build an envelope with snapshot + referenced entities

pub mod root_tracker;
pub mod trie;

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use entity_entity::{Entity, EntityError, Envelope, TYPE_DELETION_MARKER};
use entity_handler::{
    Handler, HandlerContext, HandlerError, HandlerResult, STATUS_BAD_REQUEST, STATUS_CONFLICT,
    STATUS_FORBIDDEN, STATUS_MULTI_STATUS, STATUS_NOT_FOUND, STATUS_NOT_SUPPORTED,
};
use entity_hash::{Hash, HashError as EntityHashError};
use entity_store::{
    CasError, CascadeResult, ContentStore, ExecutionContext, LocationEntry, LocationIndex,
};
use thiserror::Error;

/// The tree handler implementing get, put, snapshot, diff, merge, extract.
pub struct TreeHandler {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    local_peer_id: String,
    qualified_pattern: String,
}

impl TreeHandler {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
    ) -> Self {
        let qualified_pattern = format!("/{}/system/tree", local_peer_id);
        Self {
            content_store,
            location_index,
            local_peer_id,
            qualified_pattern,
        }
    }

    /// Build an ExecutionContext from a HandlerContext (SYSTEM-COMPOSITION §1.4).
    fn build_execution_context(ctx: &HandlerContext) -> ExecutionContext {
        // Record bare handler pattern (e.g., "system/tree") not absolute
        // (e.g., "/{peerID}/system/tree") — matches manifest and interop convention (W7).
        let bare_pattern = entity_entity::EntityUri::strip_peer_prefix(&ctx.pattern);
        ExecutionContext {
            // Immutable through cascade
            chain_id: ctx.bounds.as_ref().and_then(|b| b.chain_id.clone()),
            parent_chain_id: ctx.bounds.as_ref().and_then(|b| b.parent_chain_id.clone()),
            author: ctx.author,
            caller_capability: ctx.capability_hash,
            request_id: Some(ctx.request_id.clone()),
            // Per-write fields (tree handler is caller-authorized: capability = caller's)
            capability: ctx.capability_hash,
            handler_grant: ctx.handler_grant_hash,
            handler_pattern: Some(bare_pattern.to_string()),
            operation: Some(ctx.operation.clone()),
            // Managed by emit pathway (initial: depth 0)
            cascade_depth: 0,
            // Extension-contributed (set by clock hook)
            clock: None,
        }
    }

    /// Handler-level path authorization (§6.3 `check_path_permission`) for the
    /// path this handler is **about to touch**. `Ok(())` when allowed;
    /// `Err(403 capability_denied)` when not.
    ///
    /// ⛔ **`base_permission` is the MAPPED permission, never the extension
    /// operation name — `EXTENSION-TREE` §11 does the mapping and says whose job
    /// it is.** `map_operation` there is closed: `get`/`snapshot`/`extract` →
    /// **`get`**, `put`/`merge` → **`put`**, `diff`/`create`/`destroy` → no
    /// path-level check at all. The section states the division in as many words
    /// — *"this mapping is performed by the handler, not by `check_permission` or
    /// `check_path_permission` — those functions receive the already-mapped
    /// permission name."*
    ///
    /// This function passed `ctx.operation` through unmapped at
    /// `handle_snapshot` and `handle_extract`, which is a fail-OPEN and the
    /// direction is not obvious. The dispatch check asks the grant's
    /// `operations` about the **literal** name (`"extract"`), as §11 item 1
    /// requires; the path check must then ask about **`get`**. Feed it
    /// `"extract"` and a grant of `{operations: {include: ["*"], exclude:
    /// ["get"]}}` sails through both: the dispatch check because the exclude
    /// does not name `extract`, and the path check because it was asked the
    /// wrong question — and what leaves `handle_extract` is an envelope of every
    /// bound entity under the prefix. `snapshot` is the same shape with a trie
    /// root instead of the entities. Both seats that map (go's `checkPathPerm`
    /// is called with a literal `"get"`/`"put"` at all seven of its sites, py's
    /// `check_caller_permission("get", …)`) were already conformant here.
    ///
    /// The enforcement point is the *parameter name*: there is no `operation` in
    /// this signature to fill from `ctx.operation`, and each caller names the
    /// §11 row it is applying. A mapping function taking the extension name
    /// would need a `_ =>` arm, and either answer to that arm is a defect
    /// waiting for the next operation.
    ///
    /// **This is not a secondary check `[MUST]` (§5.2, §6.3, §6.7 — 0.8.2.20.)**
    /// The *"defense-in-depth when `resource` is present"* characterization was
    /// withdrawn at seven sites in the corpus, because its premise — that the
    /// dispatch-level check handles the primary resource check — is false in
    /// every case where the subject is derived **after** dispatch, and this
    /// handler is where all four of those cases live:
    ///
    /// 1. **`resource` absent.** §3.2 runs no dispatch-level resource check at
    ///    all, so this is the SOLE resource enforcement. `handle_get` falls back
    ///    to `pattern + suffix` and `handle_snapshot`/`handle_extract` to
    ///    `params.prefix` — paths no capability check had ever seen.
    /// 2. **A path resolved at handler time** — `merge` turning a snapshot into
    ///    individual writes under `params.target_prefix`.
    /// 3. **A listing expanded per entry** (`CP-12a`'s wider class): the
    ///    authorizer evaluated a prefix *string* and the handler enumerates a
    ///    *set*, so a grant `{include:[app/*], exclude:[app/secret]}` authorizes
    ///    `get` on `/{p}/app/` — the exclude does not match the prefix string —
    ///    and the listing then hands back `secret`. See `handle_listing`.
    /// 4. **`F68`/`CP-12a`** — the dispatch-level check made vacuous by a caller
    ///    exclude covering the caller's own target.
    ///
    /// §6.7 is **act-neutral**: reads or writes. It used to be scoped to writes;
    /// the measured harm was a `get`, and disclosure is the same defect with the
    /// same cause and a different verb.
    ///
    /// **Two frames (PR-8).** `path` is a request path and canonicalizes against
    /// the local peer; the cap's `resources` patterns canonicalize against the
    /// cap's own granter, resolved here from `ctx.included`. §6.3's pseudocode
    /// passes one peer id and predates PR-8; taking it literally would let a
    /// foreign-granted bare `*` reach our namespace, and that matters most
    /// precisely in case 1, where nothing ran the right frame first.
    ///
    /// ⚠ **No caller capability means no check, and that is a decision.** A
    /// `None` `caller_capability` is a dispatch the peer itself originated
    /// (`DispatchCeiling::PeerRoot`, the SDK entry points) — §6.8's *"peer-level
    /// writes: the peer is operating as the tree owner"*. It is NOT an absent
    /// credential on a caller's request: wire dispatch cannot reach a handler
    /// without a verified capability, and a handler's sub-dispatch inherits its
    /// caller's. So the `None` arm is the peer-root arm, and the thing that
    /// makes that safe is that `PeerRoot` is constructed in exactly three places
    /// (`grep -rn 'DispatchCeiling::PeerRoot'`), each of which says which side of
    /// the §1.4 provenance test it falls on.
    // A §3.3/§6.3 refusal is a RESPONSE, not a transport error — see
    // `entity_handler::require_single_resource_path`.
    #[allow(clippy::result_large_err)]
    fn authorize_path(
        &self,
        ctx: &HandlerContext,
        base_permission: &str,
        path: &str,
    ) -> Result<(), HandlerResult> {
        // ⛔ **Scoped to an EXTERNAL dispatch, and the scope is the
        // load-bearing decision in this function.** §6.3 authorizes the path
        // against *"the request's capability"* — the one §5.2's
        // `check_permission` authorized the dispatch with. In this tree that is
        // `ctx.caller_capability` for exactly one kind of dispatch: an inbound
        // wire EXECUTE, where it is the verified caller capability and
        // `is_external` is set (one construction site,
        // `connection.rs`'s `dispatch_request`).
        //
        // For the other two kinds it is **not** an authorization input, and
        // treating it as one is a defect in the direction that refuses
        // legitimate traffic:
        //
        // - **In-process sub-dispatch.** `make_execute_fn` propagates
        //   `caller_capability` *unchanged* down the whole chain — its own
        //   comment says why: *"so history transitions record the original
        //   external caller, not the intermediate handler."* It is attribution.
        //   The authority §5.2 actually checks for a sub-dispatch is the
        //   dispatching handler's grant (`DispatchCeiling::Handler`), which this
        //   context does not carry. Measured: `follow(Continuation)`'s standing
        //   leg arrives at `tree:put` carrying the **inbox deliver token**
        //   (`handlers:[system/inbox]`, `operations:[receive]`) four hops after
        //   the delivery that minted it, because that is the token that
        //   authorized the hop at the top of the chain.
        // - **Peer-root dispatch.** §6.8: a peer-level write *"bypasses
        //   capability verification — the peer is operating as the tree
        //   owner"*, and the capability such a dispatch carries is explicitly
        //   *"informational, not a security assertion."* `check_permission`'s
        //   resource dimension already short-circuits on
        //   `DispatchCeiling::PeerRoot`, so checking here would make the
        //   handler-level check STRICTER than the dispatch-level one for the
        //   same dispatch.
        //
        // **What this leaves open, stated rather than implied:** a sub-dispatch's
        // handler-time-derived paths (merge's expansion) are bounded only by the
        // dispatcher's ceiling at §5.2, and where that dispatch carries no
        // `resource` they are bounded by nothing. Closing it needs the ceiling
        // grant in `HandlerContext`, which is a design question about what a
        // deputy's Level-2 authority *is* — routed, not silently left to the
        // attribution field. Every instance `F68`/`CP-12a` measured, and every
        // arm of `CORE-RESOURCE-EFFECTIVE-1`, is an external dispatch.
        if !ctx.is_external {
            return Ok(());
        }
        let Some(cap) = ctx.caller_capability.as_ref() else {
            return Ok(());
        };
        let granter_peer_id = match entity_capability::resolve_granter_peer_id(
            &cap.granter,
            &self.local_peer_id,
            |h| ctx.included.get(h),
        ) {
            Some(g) => g,
            // Fail-closed (§1.11): a granter we cannot resolve is a frame we
            // cannot compute, and guessing `local` here is the V1' escalation.
            None => {
                return Err(HandlerResult::error(
                    STATUS_FORBIDDEN,
                    entity_handler::error_entity(
                        "capability_denied",
                        "capability granter is unresolvable — cannot evaluate path scope",
                    ),
                ))
            }
        };
        if entity_capability::check_path_permission(
            base_permission,
            path,
            cap,
            &ctx.pattern,
            &self.local_peer_id,
            &granter_peer_id,
        ) {
            return Ok(());
        }
        tracing::warn!(
            request_id = %ctx.request_id,
            operation = %ctx.operation,
            base_permission = %base_permission,
            path = %path,
            "tree: handler-level path check denied (§6.3)"
        );
        Err(HandlerResult::error(
            STATUS_FORBIDDEN,
            entity_handler::error_entity(
                "capability_denied",
                &format!("insufficient capability for path: {}", path),
            ),
        ))
    }

    /// [`Self::authorize_path`] as a boolean, for the per-entry listing filter
    /// and the per-path merge loop, where a denial is a *skip* or an abort
    /// rather than a response. `base_permission` carries the same §11
    /// obligation as there.
    fn path_allowed(&self, ctx: &HandlerContext, base_permission: &str, path: &str) -> bool {
        self.authorize_path(ctx, base_permission, path).is_ok()
    }

    /// Does [`Self::path_allowed`] *decide* anything on this dispatch, or is it
    /// the identity function?
    ///
    /// ⛔ **This exists so a fast path and the filter it skips cannot disagree.**
    /// `authorize_path` returns `Ok(())` unconditionally for a non-external or
    /// capability-free dispatch — the two early returns at the top of it, each
    /// of which is a deliberate decision documented there. Any caller that
    /// *bypasses* an optimization in order to run the filter has to bypass it on
    /// exactly that condition: bypass on a narrower one and the filter is
    /// skipped through the optimization (the shape this predicate was extracted
    /// for — a snapshot's tracked-root short-circuit returning a root over
    /// unfiltered bindings); bypass on a wider one and every peer-root dispatch
    /// pays an O(N) rebuild to run a filter that cannot remove anything.
    ///
    /// So the condition is not re-spelled at the call site. If the early returns
    /// in `authorize_path` ever change, this changes with them, and
    /// `snapshot_under_a_scoped_cap_does_not_take_the_tracked_root_fast_path`
    /// is the row that fails if they drift apart.
    fn cap_filter_active(ctx: &HandlerContext) -> bool {
        ctx.is_external && ctx.caller_capability.is_some()
    }

    /// Get an entity by path.
    pub fn get(&self, path: &str) -> Option<Entity> {
        let hash = self.location_index.get(path)?;
        self.content_store.get(&hash)
    }

    /// Look up a tracked trie root for `qualified_prefix` (e.g.
    /// `/{peer}/project/`). The binding at `system/tree/root/{bare_prefix}`
    /// points directly at the trie root node's content hash
    /// (EXTENSION-TREE §3.4.1, direct-binding reading).
    fn lookup_tracked_root(&self, qualified_prefix: &str) -> Option<Hash> {
        let peer_qualifier = format!("/{}/", self.local_peer_id);
        let bare = qualified_prefix.strip_prefix(&peer_qualifier)?;
        let key = bare.trim_end_matches('/');
        let root_path = format!("/{}/system/tree/root/{}", self.local_peer_id, key);
        self.location_index.get(&root_path)
    }

    /// Get an entity by hash.
    pub fn get_by_hash(&self, hash: &Hash) -> Option<Entity> {
        self.content_store.get(hash)
    }

    /// Put an entity at a path. Returns the content hash.
    pub fn put(&self, path: &str, entity: Entity) -> Result<Hash, TreeError> {
        let hash = self
            .content_store
            .put(entity)
            .map_err(|e| TreeError::StoreError(e.to_string()))?;
        self.location_index.set(path, hash);
        Ok(hash)
    }

    /// List entries under a prefix.
    pub fn list(&self, prefix: &str) -> Vec<LocationEntry> {
        self.location_index.list(prefix)
    }

    /// Handle a listing request for the given prefix.
    /// Groups entries by immediate child name, producing a single-level listing.
    /// [`Self::handle_listing`] with §6.3's **per-entry** filter applied.
    ///
    /// > *"When the tree handler returns a listing, each entry MUST be
    /// > individually checked against the request's capability using
    /// > `check_path_permission`. Entries for which `check_path_permission`
    /// > returns DENY MUST be omitted. The listing's `count` field MUST reflect
    /// > the filtered entry count, not the source tree's total count."* (§6.3)
    ///
    /// ⛔ **This is the wider class `CP-12a` names and its own fix does not
    /// reach.** An authorization check evaluates the target it was *given*; a
    /// listing handler acts on the set that target *derives*. Measured at this
    /// line: a grant `{include:[app/*], exclude:[app/secret]}` **authorizes**
    /// `system/tree:get` on `/{p}/app/` — the exclude does not match the prefix
    /// *string*, so §5.2's concrete arm compares one path and passes — and the
    /// unfiltered listing then returned `secret` and its hash. The child's own
    /// path is correctly refused, which is precisely what made the leak
    /// invisible: the direct read is denied and the enumeration is not.
    /// `effective_targets` removes nothing here, because the arity is one and
    /// the caller supplied no exclude at all.
    ///
    /// The filter is per **immediate child**, on the child's own absolute path,
    /// because that is what the listing discloses: a name, and a content hash.
    fn handle_listing_filtered(
        &self,
        ctx: &HandlerContext,
        prefix: &str,
    ) -> Result<HandlerResult, HandlerError> {
        self.listing_inner(prefix, Some(ctx))
    }

    pub fn handle_listing(&self, prefix: &str) -> Result<HandlerResult, HandlerError> {
        self.listing_inner(prefix, None)
    }

    fn listing_inner(
        &self,
        prefix: &str,
        ctx: Option<&HandlerContext>,
    ) -> Result<HandlerResult, HandlerError> {
        let entries = self.location_index.list(prefix);

        // Group by immediate child name (matching Go handler.go:192-227)
        struct ChildInfo {
            hash: Option<Hash>,
            has_children: bool,
        }
        let mut children: BTreeMap<String, ChildInfo> = BTreeMap::new();

        for entry in &entries {
            let rel = entry.path.strip_prefix(prefix).unwrap_or(&entry.path);
            if rel.is_empty() {
                continue;
            }
            if let Some(slash_idx) = rel.find('/') {
                // Nested path → parent directory has children
                let name = &rel[..slash_idx];
                children
                    .entry(name.to_string())
                    .or_insert(ChildInfo {
                        hash: None,
                        has_children: false,
                    })
                    .has_children = true;
            } else {
                // Direct child
                let info = children.entry(rel.to_string()).or_insert(ChildInfo {
                    hash: None,
                    has_children: false,
                });
                info.hash = Some(entry.hash);
            }
        }

        // V7 §1.2a + §6.3 / v7.72 §9.5a CORE-TREE-DELETE-1: a path whose direct
        // binding is a `system/deletion-marker` is suppressed from listings.
        // A marker-bound leaf with no nested children drops entirely; one that
        // still has nested descendants stays as a directory-only entry (its
        // leaf binding is hidden, its children remain visible). Resolving the
        // bound entity and comparing its type is format-agnostic — it works
        // regardless of the peer's home content_hash_format (v7.70).
        for info in children.values_mut() {
            if let Some(h) = info.hash {
                if self
                    .content_store
                    .get(&h)
                    .is_some_and(|e| e.entity_type == TYPE_DELETION_MARKER)
                {
                    info.hash = None;
                }
            }
        }
        children.retain(|_name, info| info.hash.is_some() || info.has_children);

        // §6.3's per-entry filter. Applied AFTER the deletion-marker
        // suppression and BEFORE `count`, so the count is the filtered count as
        // the MUST requires. `ctx` is `None` only for the direct
        // `handle_listing` entry point — peer-internal callers and unit tests,
        // which carry no caller capability and for which `authorize_path` would
        // be a no-op anyway.
        if let Some(ctx) = ctx {
            children.retain(|name, _info| {
                self.path_allowed(ctx, "get", &format!("{}{}", prefix, name))
            });
        }

        let count = children.len();

        // Build entries map: {name: {hash: bytes|null, has_children: bool}}
        let entry_pairs: Vec<(entity_ecf::Value, entity_ecf::Value)> = children
            .iter()
            .map(|(name, info)| {
                let hash_val = match info.hash {
                    Some(h) => entity_ecf::Value::Bytes(h.to_bytes().to_vec()),
                    None => entity_ecf::Value::Null,
                };
                let entry_map = entity_ecf::Value::Map(vec![
                    (
                        entity_ecf::text("has_children"),
                        entity_ecf::bool_val(info.has_children),
                    ),
                    (entity_ecf::text("hash"), hash_val),
                ]);
                (entity_ecf::text(name), entry_map)
            })
            .collect();

        let listing_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("count"), entity_ecf::integer(count as i64)),
            (
                entity_ecf::text("entries"),
                entity_ecf::Value::Map(entry_pairs),
            ),
            (entity_ecf::text("offset"), entity_ecf::integer(0)),
            (entity_ecf::text("path"), entity_ecf::text(prefix)),
        ]));

        let listing_entity = Entity::new(entity_types::TYPE_TREE_LISTING, listing_data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        Ok(HandlerResult::ok(listing_entity))
    }

    /// Check if a path exists.
    pub fn has(&self, path: &str) -> bool {
        self.location_index.has(path)
    }

    /// Remove a path. Returns the removed entity if it existed.
    pub fn remove(&self, path: &str) -> Option<Entity> {
        let hash = self.location_index.remove(path)?;
        self.content_store.get(&hash)
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Decode params data from ctx.params (pre-extracted by dispatch layer).
fn decode_params(ctx: &HandlerContext) -> Option<ciborium::Value> {
    ciborium::from_reader(ctx.params.data.as_slice()).ok()
}

/// Get a string field from a CBOR map value.
/// Get a value by key from a CBOR map.
fn cbor_map_get<'a>(
    map: &'a [(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Option<&'a ciborium::Value> {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
}

fn map_get_text(map: &[(ciborium::Value, ciborium::Value)], key: &str) -> Option<String> {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .and_then(|(_, v)| v.as_text().map(|s| s.to_string()))
}

/// Get a bool field from a CBOR map value.
fn map_get_bool(map: &[(ciborium::Value, ciborium::Value)], key: &str) -> Option<bool> {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .and_then(|(_, v)| v.as_bool())
}

/// Get a bytes field from a CBOR map value.
fn map_get_bytes<'a>(map: &'a [(ciborium::Value, ciborium::Value)], key: &str) -> Option<&'a [u8]> {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .and_then(|(_, v)| v.as_bytes())
        .map(|v| v.as_slice())
}

/// Get an array field from a CBOR map value.
fn map_get_array<'a>(
    map: &'a [(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Option<&'a [ciborium::Value]> {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .and_then(|(_, v)| v.as_array())
        .map(|a| a.as_slice())
}

/// Validate that a non-empty prefix ends with "/".
fn validate_prefix(prefix: &str) -> bool {
    prefix.is_empty() || prefix.ends_with('/')
}

/// An `extract.paths[]` entry is a **relative** path under the request's
/// `prefix` (EXTENSION-TREE v4.9 §6.1). `Err(message)` is `400 invalid_path`
/// for the whole request.
///
/// The four malformed shapes v4.9 names, and why each is here rather than
/// somewhere upstream:
///
/// - a **control character** — `\x01` is the vector's own probe value
///   (`CORE-PARAMS-PATH-TOTAL-1`), and §1.4 forbids it in any tree path;
/// - an **empty segment** (`//`) and the reserved **`./` / `../`** prefixes —
///   [`EntityUri::validate_path_input`], the same predicate the resource-target
///   channel gets at admission, applied to the channel that never had one;
/// - a **leading `/`** — an entry is relative to `prefix`, so an absolute entry
///   is not "a path somewhere else", it is a caller that has misread the
///   parameter, and concatenating it would produce `…prefix//peer/x`;
/// - an **empty** entry, which concatenates to the prefix itself.
///
/// Deliberately NOT [`EntityUri::validate_absolute_path`]: an entry is relative
/// and its first segment is a binding name, not a peer id. The absolute form is
/// checked where it is built — the per-entry authorization filter below runs on
/// `prefix + entry`.
fn validate_extract_subpath(entry: &str) -> Result<(), String> {
    if entry.is_empty() {
        return Err("extract paths[] entry is empty".into());
    }
    if entry.starts_with('/') {
        return Err(format!(
            "extract paths[] entry is relative to `prefix`, not absolute: {:?}",
            entry
        ));
    }
    if let Some(c) = entry.chars().find(|c| c.is_control()) {
        return Err(format!(
            "extract paths[] entry contains a control character (U+{:04X})",
            c as u32
        ));
    }
    entity_entity::EntityUri::validate_path_input(entry)
        .map_err(|e| format!("extract paths[] entry is not a valid relative path: {}", e))
}

/// A tree path is about to be **written** or **read** at the store boundary —
/// `Err(message)` is `400 invalid_path` (§5.4, 0.8.2.21).
///
/// > *"Every path that reaches the location index, the content store, or the
/// > tree is validated at that boundary — whatever carried it. A resource
/// > target, a URI suffix, a `params` field, an entry of a caller-supplied
/// > array, or a path the handler built by concatenation are all the same kind
/// > of input at the point of use."*
///
/// This is the check `merge` never had: its write paths are
/// `params.target_prefix` concatenated with the source snapshot's binding
/// names, and **no resource target is read at all**, so nothing upstream —
/// neither `connection.rs`'s admission nor `check_resource_scope` — has ever
/// seen them. A control character in `target_prefix` was written into the
/// location index verbatim.
fn validate_tree_boundary_path(path: &str) -> Result<(), String> {
    if let Some(c) = path.chars().find(|c| c.is_control()) {
        return Err(format!(
            "path contains a control character (U+{:04X})",
            c as u32
        ));
    }
    entity_entity::EntityUri::validate_absolute_path(path)
}

/// Remap a path from source_prefix to target_prefix.
/// Build a system/protocol/error entity.
fn error_entity(code: &str, message: &str) -> Result<Entity, HandlerError> {
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (entity_ecf::text("code"), entity_ecf::text(code)),
        (entity_ecf::text("message"), entity_ecf::text(message)),
    ]));
    Entity::new(entity_types::TYPE_ERROR, data).map_err(|e| HandlerError::Internal(e.to_string()))
}

/// Build a HandlerResult with an error status.
fn error_result(status: u32, code: &str, message: &str) -> Result<HandlerResult, HandlerError> {
    Ok(HandlerResult::error(status, error_entity(code, message)?))
}

/// First illegal control byte in a tree path, if any (V7 §1.4 / v7.72 §9.5a
/// CORE-TREE-PATH-FLEX-1). §1.4 mandates rejecting null bytes; the cohort floor
/// rejects the full C0 control range (`0x00`–`0x1F`) plus DEL (`0x7F`), matching
/// Go's `ValidatePathChars`, so a path one peer binds is bindable on every peer
/// sharing the tree. Operates on the UTF-8 bytes — format-agnostic. (Multi-byte
/// UTF-8 continuation bytes are ≥ `0x80`, so legitimate Unicode segments pass.)
fn first_illegal_path_byte(path: &str) -> Option<u8> {
    path.bytes().find(|&b| b < 0x20 || b == 0x7F)
}

// (Tree snapshot read removed — PROPOSAL-REVERT-TREE-SNAPSHOT-READ.
// Trie traversal logic will move to the transaction handler.
// Snapshot reads are handled by domain handlers (transaction, revision)
// that have prefix context for correct capability checking.)

fn build_partial_result(cr: CascadeResult) -> HandlerResult {
    use entity_ecf::{bool_val, text, Value};
    let halted_entries: Vec<Value> = cr
        .consumers_halted
        .iter()
        .map(|h| {
            Value::Map(vec![
                (text("name"), text(&h.consumer_name)),
                (
                    text("error"),
                    Value::Map(vec![
                        (text("code"), text(&h.error_message)),
                        (text("status"), Value::Integer(h.error_code.into())),
                    ]),
                ),
            ])
        })
        .collect();
    let data = entity_ecf::to_ecf(&Value::Map(vec![
        (text("binding_committed"), bool_val(cr.binding_committed)),
        (
            text("cascade_depth"),
            Value::Integer(cr.cascade_depth.into()),
        ),
        (
            text("consumers_completed"),
            Value::Array(cr.consumers_completed.iter().map(text).collect()),
        ),
        (text("consumers_halted"), Value::Array(halted_entries)),
        (
            text("consumers_skipped"),
            Value::Array(cr.consumers_skipped.iter().map(text).collect()),
        ),
    ]));
    let entity = Entity::new(entity_types::TYPE_TREE_PARTIAL_RESULT, data)
        .expect("partial-result entity construction cannot fail");
    HandlerResult::error(STATUS_MULTI_STATUS, entity)
}

/// Why a submitted `put` entity failed admission. Two *different* wire codes,
/// which is the whole reason this is an enum and not a `String`.
///
/// `EXTENSION-TREE` Appendix A **v4.5** tabulates them as separate rows and
/// says so in the row text: an unsupported format code is *"**Not** the
/// `invalid_request` row — the value is a structurally valid hash and the peer
/// simply cannot verify it."* Collapsing the two costs a caller the branch that
/// distinguishes *"your submission is malformed, fix it"* from *"your hash is
/// fine and this peer cannot speak your algorithm, try a peer that can"* — and
/// answering `invalid_request` for the second is a **wrong-but-legal** code,
/// the class `AGENTS.md` records as the expensive half: it reads as conformant
/// at every seat and no token census can see it.
enum PutAdmission {
    /// 400 `invalid_request` — the value is not a `core/entity` at all.
    NotAnEntity(String),
    /// 400 `unsupported_content_hash_format` — a well-formed `system/hash`
    /// naming a format code this build cannot verify. `ENTITY-CORE-PROTOCOL`
    /// §4.7 row 5 is the authority; `EXTENSION-TREE` Appendix A restates it on
    /// `put` because `put` is one of that code's ingest surfaces.
    UnsupportedContentHashFormat(String),
}

/// Decode an inline entity from CBOR `{type, data, content_hash}` — the
/// **structural** step of `ENTITY-CORE-PROTOCOL` §6.3's two-step `put`
/// admission ladder (0.8.2.11).
///
/// **All three keys are required.** `put-request.entity` is typed `core/entity`
/// (§3.9), and `ENTITY-NATIVE-TYPE-SYSTEM` §8.1 declares its three fields with
/// no `optional` marker on any of them. The value is an entity only when it is
/// a **map** carrying a **non-empty text-string `type`**, a **present `data`**
/// (any CBOR value — `primitive/any` is unconstrained, so `null` is a legal
/// payload and must not be confused with absence), and a **well-formed
/// `system/hash` `content_hash`** whose total byte length matches its format
/// code (§1.2). Failing any clause, it is not an entity and `put` refuses it
/// `400 invalid_request`.
///
/// **`put` is a receipt path, and this function is where that is enforced.**
/// Until 0.8.2.11 the `None` arm here called `Entity::new`, which *computes* a
/// hash — so a two-key `{type, data}` submission was accepted `200` and the
/// peer authored an address the submitter never chose. That is an authorship
/// the protocol assigns to the submitter (§1.8 item 1), and the SDK is where it
/// belongs: `SDK-OPERATIONS` §3.2's `put(path, type, data) → hash` cannot
/// return a hash it did not compute. The defect was invisible in-tree because
/// our own SDK stripped the field this decoder then restored — a compensating
/// pair inside one tree, perfect on its own round-trip and wrong the moment a
/// strict peer was on the other end, which is exactly how core-go measured it.
///
/// **The authored `content_hash` is preserved, never re-derived** (V7 §1.8 /
/// v7.69 §4.5a). A reference belongs to whoever authored it and carries
/// *their* `content_hash_format`; a peer holding it MUST use it verbatim and
/// MUST NOT re-derive it under its own home format
/// (SPECIFICATION-FORMAT §8.4.6 calls this disposition *hold-and-fetch*).
/// Rebuilding via `Entity::new` discarded the field and recomputed under the
/// local default, so a SHA-384-authored entity `put` to a SHA-256-home peer
/// came back at a different address than it was published to — and every
/// reference anyone else held to it stopped resolving. It was invisible while
/// one format shipped, because then the re-derived hash and the authored one
/// are the same bytes.
///
/// Trusting the caller's hash is not a forgery vector: the put path calls
/// `Entity::validate` immediately after — §6.3 step **2** — which recomputes
/// under the claimed hash's OWN algorithm and rejects any mismatch. A caller
/// can choose the format its entity is addressed under, which is exactly the
/// authoring right §4.5a gives it, but cannot claim a hash its bytes do not
/// produce.
fn decode_entity_from_cbor(raw: &[u8]) -> Result<Entity, PutAdmission> {
    use PutAdmission::{NotAnEntity, UnsupportedContentHashFormat};

    let value: ciborium::Value =
        ciborium::from_reader(raw).map_err(|e| NotAnEntity(format!("cbor decode: {}", e)))?;
    let map = value
        .as_map()
        .ok_or_else(|| NotAnEntity("entity must be a CBOR map".to_string()))?;

    let mut entity_type = None;
    let mut entity_data = None;
    let mut authored_hash = None;

    for (k, v) in map {
        match k.as_text() {
            // Present-but-not-text and present-but-empty are both refusals,
            // and neither may fall through to "absent": §8.1's `type` is
            // `primitive/string` and Appendix A names *"absent / empty / not a
            // text string"* as three spellings of one structural failure.
            Some("type") => {
                let s = v.as_text().ok_or_else(|| {
                    NotAnEntity("'type' is present but is not a text string".to_string())
                })?;
                if s.is_empty() {
                    return Err(NotAnEntity("'type' is present but empty".to_string()));
                }
                entity_type = Some(s.to_string());
            }
            Some("data") => {
                // data is raw CBOR — re-encode it. Any value is legal here,
                // `null` included: `data` is `primitive/any`, so presence is
                // the whole test and absence is the only failure.
                let mut buf = Vec::new();
                ciborium::into_writer(v, &mut buf)
                    .map_err(|e| NotAnEntity(format!("re-encode data: {}", e)))?;
                entity_data = Some(buf);
            }
            Some("content_hash") => {
                // A present-but-wrong-typed `content_hash` (null, a text
                // string, a map) previously fell through this `if let` and
                // left `authored_hash` at `None` — i.e. it took the authoring
                // arm, indistinguishable from absence. It is a refusal.
                let bytes = v.as_bytes().ok_or_else(|| {
                    NotAnEntity("'content_hash' is present but is not a byte string".to_string())
                })?;
                authored_hash = Some(Hash::from_bytes(bytes).map_err(|e| match e {
                    // A code this build does not implement — including the
                    // §5.3 `0xFF` reservation — is the §4.7 row 5 case: the
                    // hash is well-formed, we just cannot verify it.
                    EntityHashError::UnsupportedAlgorithm(_)
                    | EntityHashError::ReservedFormat(_) => {
                        UnsupportedContentHashFormat(format!("content_hash: {e}"))
                    }
                    // A length that does not match the format code, or a
                    // malformed leading varint, is a structural fault in the
                    // submitted value — Appendix A's `invalid_request` row
                    // names it verbatim.
                    _ => NotAnEntity(format!("content_hash: {e}")),
                })?);
            }
            _ => {}
        }
    }

    let entity_type = entity_type.ok_or_else(|| NotAnEntity("missing 'type' field".to_string()))?;
    let data = entity_data.ok_or_else(|| NotAnEntity("missing 'data' field".to_string()))?;
    let content_hash = authored_hash.ok_or_else(|| {
        NotAnEntity(
            "missing 'content_hash' field — `put` is a receipt path and does not author \
             a hash on the submitter's behalf (ENTITY-CORE-PROTOCOL §6.3; the SDK's \
             construction step is SDK-OPERATIONS §3.2)"
                .to_string(),
        )
    })?;

    Ok(Entity {
        entity_type,
        data,
        content_hash,
    })
}

/// Decode bindings from a snapshot entity's data.
///
/// Supports the trie-based format `{root}` (I3 amendment: prefix removed),
/// the legacy `{prefix, root}` format, and the legacy flat `{prefix, bindings}` format.
fn decode_snapshot_bindings_with_store(
    data: &[u8],
    store: &dyn ContentStore,
) -> Option<BTreeMap<String, Hash>> {
    let value: ciborium::Value = ciborium::from_reader(data).ok()?;
    let map = value.as_map()?;

    // Try trie-based format: {root} (or legacy {prefix, root})
    let root_entry = map.iter().find(|(k, _)| k.as_text() == Some("root"));
    if let Some((_, root_val)) = root_entry {
        if let Some(root_bytes) = root_val.as_bytes() {
            if let Ok(root_hash) = Hash::from_bytes(root_bytes) {
                return Some(trie::collect_all_bindings(store, root_hash, ""));
            }
        }
    }

    // Fall back to legacy flat format: {prefix, bindings}
    let bindings_entry = map.iter().find(|(k, _)| k.as_text() == Some("bindings"));
    if let Some((_, bindings_val)) = bindings_entry {
        if let Some(bindings_map) = bindings_val.as_map() {
            let mut result = BTreeMap::new();
            for (k, v) in bindings_map {
                let path = k.as_text()?;
                let hash_bytes = v.as_bytes()?;
                let hash = Hash::from_bytes(hash_bytes).ok()?;
                result.insert(path.to_string(), hash);
            }
            return Some(result);
        }
    }

    None
}

// build_snapshot_entity removed — snapshots now use trie-based {root} format (I3 amendment).

// ---------------------------------------------------------------------------
// Handler trait implementation
// ---------------------------------------------------------------------------

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for TreeHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        match ctx.operation.as_str() {
            "get" => self.handle_get(ctx),
            "put" => self.handle_put(ctx),
            "snapshot" => self.handle_snapshot(ctx),
            "diff" => self.handle_diff(ctx),
            "merge" => self.handle_merge(ctx),
            "extract" => self.handle_extract(ctx),
            // Advertised but unbuilt. Same code SLOT as the fall-through
            // below and therefore the same spelling: §3.3's 501 row says the
            // unit of conformance is the slot, never a token, so "we know this
            // verb and have not written it" and "we do not know this verb" are
            // one row (0.8.2.7). `not_implemented` is named non-conformant at
            // §9.1. The distinction survives in the MESSAGE, which is where a
            // human-readable difference belongs.
            "create" | "destroy" => error_result(
                STATUS_NOT_SUPPORTED,
                "unsupported_operation",
                &format!("{} is not yet implemented", ctx.operation),
            ),
            _ => error_result(
                STATUS_NOT_SUPPORTED,
                "unsupported_operation",
                &format!("unknown operation: {}", ctx.operation),
            ),
        }
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "tree"
    }

    fn operations(&self) -> &[&str] {
        &[
            "get", "put", "snapshot", "diff", "merge", "extract", "create", "destroy",
        ]
    }
}

// ---------------------------------------------------------------------------
// Operation implementations
// ---------------------------------------------------------------------------

impl TreeHandler {
    fn handle_get(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        // §5.2's subject rule (0.8.2.20): the subject is `effective_targets[0]`,
        // never `resource.targets[0]`.
        //
        // `single_effective_target` and not `require_single_resource_path`,
        // deliberately: `get` does **not** require a resource — EXTENSION-TREE
        // §4.10's own operation row is its specification and reads *"Path ending
        // with `/` **or empty**: listing"*, which is the omitted-resource case —
        // and a `tree:get` subject MAY be a prefix, so §3.3's "a
        // resource-requiring operation takes a concrete path" clause does not
        // bind here either. The arity arm does: two targets is
        // `ambiguous_resource`, which this function once answered by silently
        // using the first.
        //
        // ⛔ **The two empties are NOT the same request `[MUST]` (§3.3 +
        // EXTENSION-TREE §4.10, 0.8.2.24), and that is the whole of N6.** This
        // arm read a single `None` and fell through to the URI-suffix form for
        // both of them, so `targets:[qA] exclude:[qA]` — a request for **one**
        // path, which the caller then excluded — was answered with a **listing
        // of the tree**. §5.2's subject rule forbids a handler widening the set;
        // the unqualified "empty effective list IS the absent case" sentence
        // licensed exactly that widening through the front door, and `get`'s own
        // "empty → listing" grammar is what made it land somewhere expensive.
        // The absent case still gets the listing — that half was always right,
        // and refusing it would break every legitimate root listing.
        let target_path = match entity_handler::single_effective_target(
            ctx.resource_target.as_ref(),
            &self.local_peer_id,
            "system/tree:get",
        ) {
            Err(e) => return Ok(e),
            Ok(entity_handler::ResourceSubject::One(p)) => p,
            Ok(entity_handler::ResourceSubject::SelfExcluded) => {
                return Ok(entity_handler::self_excluded_refusal("system/tree:get"))
            }
            // Genuinely absent — §4.10's own absent-case behaviour. That is
            // exactly why §6.3's handler-level check below is the enforcement
            // rather than a second opinion: on this arm no dispatch-level
            // resource check ran at all.
            Ok(entity_handler::ResourceSubject::Absent) if ctx.suffix.is_empty() => {
                ctx.pattern.clone()
            }
            Ok(entity_handler::ResourceSubject::Absent) => {
                format!("{}{}", ctx.pattern, ctx.suffix)
            }
        };

        // §6.3 / §6.7 (act-neutral, 0.8.2.20) — authorize the path we are about
        // to READ. For the suffix form above this is the only resource check
        // that runs anywhere.
        if let Err(e) = self.authorize_path(ctx, "get", &target_path) {
            return Ok(e);
        }

        // Trailing slash or empty path → listing
        if target_path.is_empty() || target_path.ends_with('/') {
            tracing::debug!(path = %target_path, "tree get: listing");
            return self.handle_listing_filtered(ctx, &target_path);
        }

        match self.get(&target_path) {
            Some(entity) => {
                tracing::debug!(
                    path = %target_path,
                    entity_type = %entity.entity_type,
                    hash = %entity.content_hash,
                    "tree get: found"
                );
                Ok(HandlerResult::ok(entity))
            }
            None => {
                tracing::debug!(path = %target_path, "tree get: not found");
                error_result(
                    STATUS_NOT_FOUND,
                    "not_found",
                    &format!("path not found: {}", target_path),
                )
            }
        }
    }

    fn handle_put(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        // §3.3 + §5.2's subject rule (0.8.2.20). `targets.first()` here was the
        // WRITE half of `F68`/`CP-12a` and the most expensive instance of it:
        // `targets:[P] exclude:[P]` reaches `ALLOW` with the resource dimension
        // having checked nothing, and this function then bound `P`.
        let path = match entity_handler::require_single_resource_path(
            ctx.resource_target.as_ref(),
            &self.local_peer_id,
            "system/tree:put (the bind path)",
        ) {
            Ok(p) => p,
            Err(e) => return Ok(e),
        };

        // §6.3 / §6.7 — authorize the path we are about to WRITE.
        if let Err(e) = self.authorize_path(ctx, "put", &path) {
            return Ok(e);
        }

        // V7 §1.4 / v7.72 §9.5a CORE-TREE-PATH-FLEX-1: reject control bytes in
        // the bind path before any binding. The resource-target path bypasses
        // URI canonicalization (which already rejects leading-slash / ./ / ../
        // / empty segments), so this is the surface where a NUL would slip
        // through to a binding.
        if let Some(bad) = first_illegal_path_byte(&path) {
            return error_result(
                STATUS_BAD_REQUEST,
                "invalid_path",
                &format!("path contains illegal control byte {bad:#04x} (V7 §1.4)"),
            );
        }

        let params = decode_params(ctx);

        // Check if entity field is present
        let entity_value = params.as_ref().and_then(|p| {
            let map = p.as_map()?;
            map.iter()
                .find(|(k, _)| k.as_text() == Some("entity"))
                .map(|(_, v)| v)
        });

        // Decode optional expected_hash (ENTITY-CORE-PROTOCOL §3.9).
        let expected_hash =
            match params.as_ref().and_then(|p| {
                let map = p.as_map()?;
                map.iter()
                    .find(|(k, _)| k.as_text() == Some("expected_hash"))
                    .map(|(_, v)| v)
            }) {
                None => None,
                Some(v) if v.is_null() => None,
                Some(v) => match v.as_bytes() {
                    Some(bytes) => Some(Hash::from_bytes(bytes).map_err(|e| {
                        HandlerError::InvalidParams(format!("expected_hash: {}", e))
                    })?),
                    None => {
                        return error_result(
                            STATUS_BAD_REQUEST,
                            "invalid_params",
                            "expected_hash must be bytes",
                        );
                    }
                },
            };

        let is_remove = match entity_value {
            None => true,
            Some(v) if v.is_null() => true,
            Some(v) if v.as_bytes().is_some_and(|b| b.is_empty()) => true,
            _ => false,
        };

        if is_remove {
            tracing::debug!(path = %path, "tree put: removing binding");
            let emit_ctx = Self::build_execution_context(ctx);
            // V7 §3.9 v7.50: zero expected_hash on remove means "expect absent"
            // — an idempotent no-op when the path is already unbound, else 409.
            // The spec ("applies to both write and remove") makes the zero-hash
            // case symmetric with CAS-create on write.
            if let Some(expected) = expected_hash {
                if expected.is_zero() {
                    match self.location_index.get(&path) {
                        None => {
                            let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                                entity_ecf::text("removed"),
                                entity_ecf::bool_val(false),
                            )]));
                            let result = Entity::new(entity_types::TYPE_TREE_PUT_RESULT, data)
                                .map_err(|e| HandlerError::Internal(e.to_string()))?;
                            return Ok(HandlerResult::ok(result));
                        }
                        Some(actual) => {
                            return error_result(
                                STATUS_CONFLICT,
                                "hash_mismatch",
                                &format!("expected_hash zero (expect absent) but binding present at {}: actual {}", path, actual),
                            );
                        }
                    }
                }
            }
            let outcome: Result<(Option<Hash>, CascadeResult), CasError> = match expected_hash {
                Some(expected) => self
                    .location_index
                    .compare_and_remove_with_context(&path, expected, emit_ctx)
                    .map(|(h, c)| (Some(h), c)),
                None => {
                    let (removed, cascade) =
                        self.location_index.remove_with_context(&path, emit_ctx);
                    Ok((removed, cascade))
                }
            };

            match outcome {
                Ok((Some(old_hash), cascade)) => {
                    tracing::debug!(path = %path, old_hash = %old_hash, "tree put: binding removed");
                    if !cascade.is_complete() {
                        return Ok(build_partial_result(cascade));
                    }
                    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                        entity_ecf::text("removed"),
                        entity_ecf::bool_val(true),
                    )]));
                    let result = Entity::new(entity_types::TYPE_TREE_PUT_RESULT, data)
                        .map_err(|e| HandlerError::Internal(e.to_string()))?;
                    Ok(HandlerResult::ok(result))
                }
                Ok((None, _)) => {
                    tracing::debug!(path = %path, "tree put: path not bound for removal");
                    error_result(
                        STATUS_NOT_FOUND,
                        "not_found",
                        &format!("path not bound: {}", path),
                    )
                }
                Err(CasError::NotFound) => error_result(
                    STATUS_CONFLICT,
                    "hash_mismatch",
                    &format!("no binding at {} for expected_hash", path),
                ),
                Err(CasError::Mismatch(actual)) => error_result(
                    STATUS_CONFLICT,
                    "hash_mismatch",
                    &format!("expected_hash mismatch at {}: actual {}", path, actual),
                ),
            }
        } else {
            // Store entity
            let entity_bytes = entity_value.unwrap();

            // Re-encode the CBOR value to bytes for decode_entity_from_cbor
            let mut raw = Vec::new();
            ciborium::into_writer(entity_bytes, &mut raw)
                .map_err(|e| HandlerError::Internal(format!("encode entity bytes: {}", e)))?;

            // EXTENSION-TREE Appendix A `put` rows (v4.4 tabulated; v4.5 stated
            // the predicate and added the format row), over ENTITY-CORE-PROTOCOL
            // §6.3's two-step admission ladder.
            //
            // STEP 1 — structure. `decode_entity_from_cbor` asks *is this a
            // `core/entity`*: a map, non-empty text `type`, present `data`,
            // well-formed `content_hash`. Two codes come back out of it, and
            // they are different rows: `invalid_request` is §3.3's generic
            // structurally-invalid case, while `unsupported_content_hash_format`
            // (§4.7 row 5) says the hash is *fine* and this build cannot verify
            // its algorithm. Appendix A v4.5 says explicitly that the second is
            // "**Not** the `invalid_request` row".
            //
            // STEP 2 — hash, below. `hash_mismatch` says *this entity is not what
            // it claims to be* (EXTENSION-CONTENT §923's code for the same
            // failure). It is reached only if step 1 passed, and that ordering is
            // a data dependency rather than a convention: step 2's inputs are
            // exactly what step 1 establishes. A submission that is BOTH
            // malformed and mis-hashed is step 1's, and it is the only input that
            // discriminates the ladder — which is why §9.1's conformance row
            // names it. Pinned by `put_admission_is_structure_then_hash`.
            //
            // None of these is the 409 `hash_mismatch` further down: that one is
            // nobody's defect and is retryable.
            //
            // These are `error_result` (completed dispatch), not `Err(..)`: the
            // dispatcher maps every `HandlerError::InvalidParams` to the single
            // slot `400 invalid_params` (`connection::handler_error_slot`), which
            // cannot express a per-operation code from a spec code set.
            let entity = match decode_entity_from_cbor(&raw) {
                Ok(e) => e,
                Err(PutAdmission::NotAnEntity(msg)) => {
                    return error_result(
                        STATUS_BAD_REQUEST,
                        "invalid_request",
                        &format!("submitted entity is not a core/entity: {}", msg),
                    );
                }
                Err(PutAdmission::UnsupportedContentHashFormat(msg)) => {
                    return error_result(
                        STATUS_BAD_REQUEST,
                        "unsupported_content_hash_format",
                        &format!("cannot verify the submitted content hash: {}", msg),
                    );
                }
            };

            // Validate hash — §6.3 step 2. `Entity::validate` recomputes under the
            // entity's own claimed format and can only report `HashMismatch` on
            // this path: step 1 already refused an unsupported format code at
            // `Hash::from_bytes`, and since 0.8.2.11 there is no arm that reaches
            // here without a carried hash. The non-mismatch arm is therefore
            // unreachable by construction today and is kept because it is a
            // *different row*, not a fallback; it goes live the moment
            // `digest_len_for_format` and `Hash::compute_format` stop agreeing on
            // the supported set. That containment is pinned by
            // `validate_on_the_put_path_can_only_fail_with_hash_mismatch`.
            if let Err(e) = entity.validate() {
                let (code, what) = match e {
                    EntityError::HashMismatch { .. } => (
                        "hash_mismatch",
                        "content hash does not match the entity it addresses",
                    ),
                    _ => ("invalid_request", "entity is structurally invalid"),
                };
                return error_result(STATUS_BAD_REQUEST, code, &format!("{}: {}", what, e));
            }

            // Store and bind
            let stored_hash = self
                .content_store
                .put(entity.clone())
                .map_err(|e| HandlerError::Internal(e.to_string()))?;
            let emit_ctx = Self::build_execution_context(ctx);

            let cascade = if let Some(expected) = expected_hash {
                // V7 §3.9 v7.50: zero expected_hash means CAS-create — succeed
                // only if the path is currently unbound; non-zero retains the
                // existing compare-and-swap semantics.
                let cas_result = if expected.is_zero() {
                    self.location_index.compare_and_create_with_context(
                        &path,
                        stored_hash,
                        emit_ctx,
                    )
                } else {
                    self.location_index.compare_and_swap_with_context(
                        &path,
                        expected,
                        stored_hash,
                        emit_ctx,
                    )
                };
                match cas_result {
                    Ok(c) => c,
                    Err(CasError::NotFound) => {
                        return error_result(
                            STATUS_CONFLICT,
                            "hash_mismatch",
                            &format!("no binding at {} for expected_hash", path),
                        );
                    }
                    Err(CasError::Mismatch(actual)) => {
                        return error_result(
                            STATUS_CONFLICT,
                            "hash_mismatch",
                            &format!("expected_hash mismatch at {}: actual {}", path, actual),
                        );
                    }
                }
            } else {
                self.location_index
                    .set_with_context(&path, stored_hash, emit_ctx)
            };

            if !cascade.is_complete() {
                return Ok(build_partial_result(cascade));
            }

            tracing::debug!(
                path = %path,
                entity_type = %entity.entity_type,
                hash = %stored_hash,
                "tree put: stored"
            );

            let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                entity_ecf::text("content_hash"),
                entity_ecf::Value::Bytes(stored_hash.to_bytes().to_vec()),
            )]));
            let result = Entity::new(entity_types::TYPE_TREE_PUT_RESULT, data)
                .map_err(|e| HandlerError::Internal(e.to_string()))?;
            Ok(HandlerResult::ok(result))
        }
    }

    fn handle_snapshot(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        let params = decode_params(ctx);

        // V7 §3.2: prefer resource_target (dispatch-layer auth covers it).
        // Sanctioned fallback to params.prefix carries a handler-side auth
        // obligation — see the explicit check below.
        // §5.2's subject rule (0.8.2.20) — the effective set. `single_effective_target`
        // rather than `require_single_resource_path` because a snapshot prefix is
        // a prefix, and because the empty case has a legitimate `params.prefix`
        // fallback below.
        //
        // §3.3's two empties (0.8.2.24), same rule as `handle_get`: the
        // `params.prefix` fallback IS this operation's absent-case behaviour, so
        // a caller who named a target and excluded it must not be handed it.
        // Routed as wider than N6's own worklist, which names `get` only — the
        // normative sentence is §3.3's and it binds *"an operation that does NOT
        // require"* a resource, which is the whole of this file's optional-
        // resource set.
        let prefix = match entity_handler::single_effective_target(
            ctx.resource_target.as_ref(),
            &self.local_peer_id,
            "system/tree:snapshot",
        ) {
            Err(e) => return Ok(e),
            Ok(entity_handler::ResourceSubject::One(p)) => p,
            Ok(entity_handler::ResourceSubject::SelfExcluded) => {
                return Ok(entity_handler::self_excluded_refusal(
                    "system/tree:snapshot",
                ))
            }
            Ok(entity_handler::ResourceSubject::Absent) => params
                .as_ref()
                .and_then(|p| {
                    let map = p.as_map()?;
                    map_get_text(map, "prefix")
                })
                .unwrap_or_default(),
        };

        if !validate_prefix(&prefix) {
            return error_result(
                STATUS_BAD_REQUEST,
                "invalid_prefix",
                "non-empty prefix must end with '/'",
            );
        }

        // §6.3 / §6.7 — UNCONDITIONALLY, not only on the `params.prefix` arm.
        //
        // This check used to be gated on `from_params`, under a comment reading
        // *"when the path came from params the dispatch-layer capability check
        // did not see this path"* — true, and an incomplete statement of when
        // the two layers disagree. `F68`/`CP-12a` is the case where the path
        // came from `resource_target` and the dispatch-layer check **still** did
        // not see it, because the caller excluded its own target; 0.8.2.20
        // withdraws the secondary-check characterization for exactly that
        // reason. The `from_params` distinction is gone rather than widened:
        // there is no path into this function on which the handler-level check
        // is redundant.
        // `"get"`, not `"snapshot"` — EXTENSION-TREE §11's `map_operation` row.
        // See `authorize_path` for why the unmapped name is a fail-open.
        if let Err(e) = self.authorize_path(ctx, "get", &prefix) {
            return Ok(e);
        }

        // ⛔ **A snapshot is a COMMITMENT, and §11's `diff` exemption is a claim
        // about this function.** (V7 §6.3, EXTENSION-TREE §11 — the row go drove
        // against us at `exclude_matrix.snapshot_diff_no_leak`, 2026-09-12.)
        //
        // The prefix check above authorizes the prefix *string*; what leaves
        // here is a trie root committing to the *set* underneath it — `CP-12a`'s
        // wider class again, one surface past the listing and extract filters.
        // What makes it worse than either is the second half: §11 exempts `diff`
        // from path checks, and that exemption is sound **only** while a
        // snapshot cannot commit to bindings the caller may not see. Compose the
        // two and the excluded key and its content hash fall out of
        // `diff(empty, scoped).added` — through the one operation the spec says
        // needs no authority. Measured against us: `secret` present in `added`
        // under a cap whose `resources.exclude` names it, with the direct
        // `get` on that same path correctly `403`.
        //
        // **A path-check EXEMPTION is a claim about the exempt operation's
        // upstream PRODUCER.** `diff` reads two roots and authorizes neither, so
        // the authority that governs its output was spent when the root was
        // minted. Nothing about `handle_diff` is wrong; the entire fix is here.
        //
        // Filtering *before* `build_trie` is re-rooting, not redaction: the root
        // is the canonical trie over what the caller may see, so it is internally
        // complete, verifiable, and diffable — as opposed to handing back the
        // full root and filtering the diff, which would leave the excluded hash
        // reachable to anyone who walks the root's nodes directly.
        let cap_scoped = Self::cap_filter_active(ctx);

        // Fast path: EXTENSION-TREE §3.4 — if an incremental trie root is
        // being maintained for this prefix, return it directly.
        //
        // ⚠ **Bypassed under a scoped cap, and that is the load-bearing half of
        // the fix.** The tracked root is maintained by `RootTrackerEngine` over
        // *every* binding under the prefix — it is a peer-level artifact with no
        // caller in scope when it is built. A filter added only to the rebuild
        // branch below would therefore be skipped whenever a root happened to be
        // tracked for the prefix: same request, same cap, and the leak present or
        // absent depending on whether a `system/tree/root/{prefix}` binding
        // exists. That is the worst available failure mode, because the surviving
        // test would pass on an untracked fixture.
        if !cap_scoped {
            if let Some(tracked) = self.lookup_tracked_root(&prefix) {
                tracing::debug!(prefix = %prefix, root = %tracked, "tree snapshot: tracked root");
                let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                    entity_ecf::text("root"),
                    entity_ecf::Value::Bytes(tracked.to_bytes().to_vec()),
                )]));
                let snapshot = Entity::new(entity_types::TYPE_TREE_SNAPSHOT, data)
                    .map_err(|e| HandlerError::Internal(e.to_string()))?;
                return Ok(HandlerResult::ok(snapshot));
            }
        }

        // Collect all bindings under prefix, per-binding filtered against the
        // caller capability exactly as `handle_extract` and the listing are.
        // `"get"` per EXTENSION-TREE §11's `map_operation` row — see
        // `authorize_path` for why the unmapped name is a fail-open — and the
        // filter runs on the entry's own ABSOLUTE path, which is the frame
        // `check_path_permission` canonicalizes in.
        let entries = self.location_index.list(&prefix);
        let mut bindings = BTreeMap::new();
        for entry in &entries {
            if cap_scoped && !self.path_allowed(ctx, "get", &entry.path) {
                continue;
            }
            let rel = entry.path.strip_prefix(&prefix).unwrap_or(&entry.path);
            bindings.insert(rel.to_string(), entry.hash);
        }

        tracing::debug!(prefix = %prefix, bindings = bindings.len(), "tree snapshot: building trie");

        // Build content-addressed trie per EXTENSION-TREE v3.2 §3.3
        let root_hash = trie::build_trie(self.content_store.as_ref(), &bindings)
            .map_err(|e| HandlerError::Internal(format!("trie build: {}", e)))?;

        tracing::debug!(prefix = %prefix, root = %root_hash, bindings = bindings.len(), "tree snapshot: built");

        // Return {root} per spec (I3 amendment: prefix removed from snapshot)
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("root"),
            entity_ecf::Value::Bytes(root_hash.to_bytes().to_vec()),
        )]));
        let snapshot = Entity::new(entity_types::TYPE_TREE_SNAPSHOT, data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        Ok(HandlerResult::ok(snapshot))
    }

    fn handle_diff(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        let params = decode_params(ctx)
            .ok_or_else(|| HandlerError::InvalidParams("params required for diff".into()))?;
        let params_map = params
            .as_map()
            .ok_or_else(|| HandlerError::InvalidParams("params must be a map".into()))?;

        let base_bytes = map_get_bytes(params_map, "base")
            .ok_or_else(|| HandlerError::InvalidParams("base hash required".into()))?;
        let target_bytes = map_get_bytes(params_map, "target")
            .ok_or_else(|| HandlerError::InvalidParams("target hash required".into()))?;

        let base_hash =
            Hash::from_bytes(base_bytes).map_err(|e| HandlerError::InvalidParams(e.to_string()))?;
        let target_hash = Hash::from_bytes(target_bytes)
            .map_err(|e| HandlerError::InvalidParams(e.to_string()))?;

        // Resolve snapshots (content store first, then included)
        let base_entity = match self
            .content_store
            .get(&base_hash)
            .or_else(|| ctx.included.get(&base_hash).cloned())
        {
            Some(e) => e,
            None => {
                return error_result(
                    STATUS_NOT_FOUND,
                    "snapshot_not_found",
                    "base snapshot not found",
                )
            }
        };
        let target_entity = match self
            .content_store
            .get(&target_hash)
            .or_else(|| ctx.included.get(&target_hash).cloned())
        {
            Some(e) => e,
            None => {
                return error_result(
                    STATUS_NOT_FOUND,
                    "snapshot_not_found",
                    "target snapshot not found",
                )
            }
        };

        let base_bindings =
            decode_snapshot_bindings_with_store(&base_entity.data, self.content_store.as_ref())
                .ok_or_else(|| {
                    HandlerError::InvalidParams("failed to decode base snapshot bindings".into())
                })?;
        let target_bindings =
            decode_snapshot_bindings_with_store(&target_entity.data, self.content_store.as_ref())
                .ok_or_else(|| {
                HandlerError::InvalidParams("failed to decode target snapshot bindings".into())
            })?;

        // Compare
        let mut added: BTreeMap<String, Hash> = BTreeMap::new();
        let mut removed: BTreeMap<String, Hash> = BTreeMap::new();
        let mut changed: BTreeMap<String, (Hash, Hash)> = BTreeMap::new();
        let mut unchanged: u64 = 0;

        // Check target for added/changed
        for (path, target_h) in &target_bindings {
            match base_bindings.get(path) {
                None => {
                    added.insert(path.clone(), *target_h);
                }
                Some(base_h) if base_h != target_h => {
                    changed.insert(path.clone(), (*base_h, *target_h));
                }
                Some(_) => {
                    unchanged += 1;
                }
            }
        }
        // Check base for removed
        for (path, base_h) in &base_bindings {
            if !target_bindings.contains_key(path) {
                removed.insert(path.clone(), *base_h);
            }
        }

        // Build diff entity
        let added_pairs: Vec<(entity_ecf::Value, entity_ecf::Value)> = added
            .iter()
            .map(|(p, h)| {
                (
                    entity_ecf::text(p),
                    entity_ecf::Value::Bytes(h.to_bytes().to_vec()),
                )
            })
            .collect();

        let changed_pairs: Vec<(entity_ecf::Value, entity_ecf::Value)> = changed
            .iter()
            .map(|(p, (bh, th))| {
                (
                    entity_ecf::text(p),
                    entity_ecf::Value::Map(vec![
                        (
                            entity_ecf::text("base_hash"),
                            entity_ecf::Value::Bytes(bh.to_bytes().to_vec()),
                        ),
                        (
                            entity_ecf::text("target_hash"),
                            entity_ecf::Value::Bytes(th.to_bytes().to_vec()),
                        ),
                    ]),
                )
            })
            .collect();

        let removed_pairs: Vec<(entity_ecf::Value, entity_ecf::Value)> = removed
            .iter()
            .map(|(p, h)| {
                (
                    entity_ecf::text(p),
                    entity_ecf::Value::Bytes(h.to_bytes().to_vec()),
                )
            })
            .collect();

        let diff_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("added"),
                entity_ecf::Value::Map(added_pairs),
            ),
            (
                entity_ecf::text("base"),
                entity_ecf::Value::Bytes(base_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("changed"),
                entity_ecf::Value::Map(changed_pairs),
            ),
            (
                entity_ecf::text("removed"),
                entity_ecf::Value::Map(removed_pairs),
            ),
            (
                entity_ecf::text("target"),
                entity_ecf::Value::Bytes(target_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("unchanged"),
                entity_ecf::integer(unchanged as i64),
            ),
        ]));

        let diff_entity = Entity::new(entity_types::TYPE_TREE_DIFF, diff_data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        Ok(HandlerResult::ok(diff_entity))
    }

    /// Ingest `params.source_envelope` (EXTENSION-TREE §5.2) into the content
    /// store and return the root snapshot's hash.
    ///
    /// ⛔ **Read from `ctx.params.data` as a RAW BYTE SLICE, never from the
    /// decoded params `Value`.** `params.data` is the entity's on-wire CBOR
    /// (`decode_entity` captures it as a slice for exactly this reason), and an
    /// envelope's entities are entities: §5.4 forbids a decode+re-encode of
    /// `data`, so the only conformant way to reach them is to keep the bytes.
    /// The previous implementation walked the decoded `ciborium::Value` and
    /// rebuilt each entity with `ciborium::into_writer` — which normalizes
    /// non-minimal integer and length encodings and folds indefinite-length
    /// items to definite. For an ECF-canonical entity that is the identity, so
    /// every fixture in this tree and every cross-impl vector passed; for an
    /// entity authored anywhere else the rebuilt bytes hash to a **different**
    /// address, the entity landed at a hash the source trie does not name, and
    /// the merge reported `200 applied:N` over bindings that resolve to
    /// nothing. Silent partial data loss with a success report.
    ///
    /// ⚠ The far more damaging case is a re-addressed **trie node**:
    /// `trie::collect_bindings_into` skips a `Link` it cannot load, so one lost
    /// node drops an entire subtree from the merge — still `200`, still a
    /// plausible `applied` count.
    ///
    /// Routing this through [`entity_wire::decode_envelope`] also closes a
    /// second gap, and it is the one our own charter predicts: `source_envelope`
    /// is **an envelope built from received bytes at a site that is not
    /// `decode_envelope`**, so §3.1's key-binds-value check — the guard against
    /// filing an entity under a hash it does not hash to — never ran on it.
    /// It runs now, and a mis-keyed entry is `400 hash_mismatch` rather than a
    /// silent re-address.
    ///
    /// Returns `Ok(Ok(hash))` on success and `Ok(Err(response))` for a coded
    /// refusal the caller should return verbatim.
    fn ingest_source_envelope(
        &self,
        ctx: &HandlerContext,
    ) -> Result<Result<Hash, HandlerResult>, HandlerError> {
        let raw = entity_wire::cbor_map_field_raw(&ctx.params.data, "source_envelope").ok_or_else(
            || {
                HandlerError::InvalidParams(
                    "source_envelope is not addressable in the params CBOR".into(),
                )
            },
        )?;

        // Unwrap the `{type, data}` entity wrapper the continuation inject mode
        // and both SDK producers use — by raw slice, so the envelope inside it
        // is still its own on-wire bytes. A bare envelope (no `type`) is
        // accepted as-is, which is the other shape §5.2 admits.
        let envelope_bytes = match (
            entity_wire::cbor_map_field_raw(raw, "type"),
            entity_wire::cbor_map_field_raw(raw, "data"),
        ) {
            (Some(_), Some(data)) => data,
            _ => raw,
        };

        let envelope = match entity_wire::decode_envelope(envelope_bytes) {
            Ok(e) => e,
            Err(entity_wire::WireError::IncludedKeyMismatch { key, actual }) => {
                // §3.1 / §5.2a — the same disposition `decode_envelope` earns at
                // the connection boundary, answered here because this envelope
                // arrived inside a params field and never crossed that boundary.
                return Ok(Err(error_result(
                    STATUS_BAD_REQUEST,
                    "hash_mismatch",
                    &format!(
                        "source_envelope.included entry keyed {key} holds an entity that \
                         hashes to {actual}"
                    ),
                )?));
            }
            Err(e) => {
                return Ok(Err(error_result(
                    STATUS_BAD_REQUEST,
                    "invalid_params",
                    &format!("source_envelope is not a decodable envelope: {e}"),
                )?));
            }
        };

        // §1.8 item 1 on every entity before it enters the store: `content_hash`
        // rides the wire and is caller-controlled, so a self-inconsistent entity
        // is refused rather than silently re-stamped. `decode_envelope` has
        // already bound each included KEY to its entity; this is the other half.
        for entity in envelope.included.values() {
            if let Err(e) = entity.validate() {
                return Ok(Err(error_result(
                    STATUS_BAD_REQUEST,
                    "hash_mismatch",
                    &format!("source_envelope carries a self-inconsistent entity: {e}"),
                )?));
            }
            self.content_store
                .put(entity.clone())
                .map_err(|e| HandlerError::Internal(format!("store included entity: {e}")))?;
        }

        // The root is validated the same way. `decode_envelope` admits a
        // mis-stamped root by design (it has no key to bind it against), so the
        // check belongs here — and it must happen before the `put`, because
        // `ContentStore::put` keys by the stamped field.
        if let Err(e) = envelope.root.validate() {
            return Ok(Err(error_result(
                STATUS_BAD_REQUEST,
                "hash_mismatch",
                &format!("source_envelope root is self-inconsistent: {e}"),
            )?));
        }
        let root_hash = self
            .content_store
            .put(envelope.root)
            .map_err(|e| HandlerError::Internal(format!("store root entity: {e}")))?;
        Ok(Ok(root_hash))
    }

    fn handle_merge(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        let params = decode_params(ctx)
            .ok_or_else(|| HandlerError::InvalidParams("params required for merge".into()))?;
        let params_map = params
            .as_map()
            .ok_or_else(|| HandlerError::InvalidParams("params must be a map".into()))?;

        // Resolve source snapshot hash: either from `source` (direct hash) or
        // from `source_envelope` (inline envelope entity from continuation chains).
        // source_envelope accepts the extract result directly — the merge handler
        // ingests the envelope's entities and uses the root snapshot as source.
        let source_hash = if let Some(source_bytes) = map_get_bytes(params_map, "source") {
            let h = Hash::from_bytes(source_bytes)
                .map_err(|e| HandlerError::InvalidParams(e.to_string()))?;
            // Skip zero hashes — fall through to source_envelope if present.
            if h.is_zero() {
                None
            } else {
                Some(h)
            }
        } else {
            None
        };
        let source_hash = if let Some(h) = source_hash {
            h
        } else if cbor_map_get(params_map, "source_envelope").is_some() {
            match self.ingest_source_envelope(ctx)? {
                Ok(h) => h,
                Err(refusal) => return Ok(refusal),
            }
        } else {
            return Err(HandlerError::InvalidParams(
                "source snapshot hash or source_envelope required".into(),
            ));
        };

        let strategy =
            map_get_text(params_map, "strategy").unwrap_or_else(|| "no-overwrite".to_string());

        // Validate strategy
        match strategy.as_str() {
            "no-overwrite" | "source-wins" | "target-wins" => {}
            _ => {
                return error_result(
                    STATUS_BAD_REQUEST,
                    "invalid_params",
                    &format!("invalid merge strategy: {}", strategy),
                );
            }
        }

        let source_prefix = map_get_text(params_map, "source_prefix").unwrap_or_default();
        let target_prefix = map_get_text(params_map, "target_prefix").unwrap_or_default();
        let dry_run = map_get_bool(params_map, "dry_run").unwrap_or(false);

        // Extract peer-id namespace from the handler pattern (e.g., "/{peer_id}/system/tree").
        // The pattern is absolute — first segment after "/" is the peer_id.
        // Only qualifies bare prefixes when the namespace is actually a peer ID,
        // not when running in tests with unqualified patterns like "system/tree".
        let pattern_path = ctx.pattern.strip_prefix('/').unwrap_or(&ctx.pattern);
        let namespace = pattern_path.split('/').next().unwrap_or("");
        let namespace_is_peer_id = entity_entity::EntityUri::is_peer_id(namespace);

        // Resolve source snapshot (content store — already ingested above if from envelope)
        let source_entity = match self
            .content_store
            .get(&source_hash)
            .or_else(|| ctx.included.get(&source_hash).cloned())
        {
            Some(e) => e,
            None => {
                return error_result(
                    STATUS_NOT_FOUND,
                    "snapshot_not_found",
                    "source snapshot not found",
                )
            }
        };

        let source_bindings =
            decode_snapshot_bindings_with_store(&source_entity.data, self.content_store.as_ref())
                .ok_or_else(|| {
                HandlerError::InvalidParams("failed to decode source snapshot".into())
            })?;

        // I3 amendment: prefix removed from snapshot entity.
        // Use source_prefix/target_prefix from merge params to compute target path.
        // Qualify bare prefixes with the local peer namespace when the handler is
        // registered under a peer-id-qualified pattern. Bare paths from continuation
        // params need the peer ID prefix that Go's NamespacedIndex would normally provide.
        let qualify = |p: &str| -> String {
            if p.is_empty() || !namespace_is_peer_id {
                return p.to_string();
            }
            // Already absolute or URI — pass through
            if p.starts_with('/') || p.starts_with("entity://") {
                return p.to_string();
            }
            format!("/{}/{}", namespace, p)
        };

        let apply_prefix = if !target_prefix.is_empty() {
            qualify(&target_prefix)
        } else if !source_prefix.is_empty() {
            qualify(&source_prefix)
        } else {
            // EXTENSION-TREE §5.2: "When neither [source_prefix nor
            // target_prefix] is provided, bindings use relative paths as-is."
            // The validator's `merge_dry_run_no_apply` WARN (Applied=1 vs 0)
            // stems from this spec'd behavior — TreeMerge with no prefix
            // can't recover the snapshot's original prefix, so target_path
            // = bare rel_path which never matches the qualified live entry.
            // Matches Go's behavior; cross-impl WARN is observation-level,
            // not a spec violation.
            String::new()
        };

        // EXTENSION-TREE §11 + §12.1 — **authorize every path before applying
        // any write, and fail the whole merge on the first denial.**
        //
        // > *"Merge requires `put` authorization on every path it writes. The
        // > handler MUST verify authorization before applying any writes."*
        //
        // This function carried **zero** authorization symbols. It reads no
        // resource target at all: the write prefix comes from
        // `params.target_prefix`, so the dispatch-level check never saw a single
        // one of these paths — §6.3 case 2, *a path resolved at handler time*,
        // and the most complete form of it in the tree, because one
        // caller-supplied string expands into N writes. `handle_snapshot` one
        // function up has carried a documented confused-deputy check for its own
        // `params` fallback since the proposal that introduced it; the two arms
        // beside it (`merge`, `extract`) were never swept, which is the
        // *sibling arms* miss our charter already names. `entity-core-go`
        // implements all three (`core/tree/operations.go`, per-path inside the
        // merge loop) and is the reference.
        //
        // Checked in a PRE-PASS rather than inside the apply loop, because
        // §12.1's MUST is atomicity: a denial on binding 40 of 50 must leave
        // zero writes, not 39. `dry_run` is checked too — a dry run discloses
        // which paths would conflict, which is the §6.7 read half.
        let merge_targets: Vec<String> = source_bindings
            .keys()
            .map(|rel_path| format!("{}{}", apply_prefix, rel_path))
            .collect();
        // ⛔ **Path validation is a property of the BOUNDARY, not of the
        // channel** (§5.4 — 0.8.2.21). These write paths are built by
        // concatenation from `params.target_prefix` — a channel no
        // resource-target pre-validator sees, and `merge` reads no resource
        // target at all — so this function IS the admission step for them.
        // Before the authorization pre-pass, because a malformed path is not a
        // permission question: `403` on garbage tells the caller to go get a
        // capability for a path that cannot exist.
        //
        // In the same pre-pass as the §11/§12.1 authorization sweep, and for
        // the same reason: a refusal on binding 40 of 50 must leave zero
        // writes, not 39.
        //
        // ⚠ Bare `apply_prefix` — the `namespace_is_peer_id` false arm, which
        // only the unqualified-pattern unit fixtures take — yields a relative
        // target that `validate_absolute_path` correctly refuses. The check is
        // therefore scoped to the qualified case, which is every path a peer
        // actually serves; see `namespace_is_peer_id`.
        if namespace_is_peer_id {
            for target_path in &merge_targets {
                if let Err(msg) = validate_tree_boundary_path(target_path) {
                    return error_result(
                        STATUS_BAD_REQUEST,
                        "invalid_path",
                        &format!("merge target path is not a valid tree path: {}", msg),
                    );
                }
            }
        }
        for target_path in &merge_targets {
            if let Err(e) = self.authorize_path(ctx, "put", target_path) {
                tracing::warn!(
                    request_id = %ctx.request_id,
                    path = %target_path,
                    bindings = merge_targets.len(),
                    "tree merge: refused before any write (§11 / §12.1 atomic 403)"
                );
                return Ok(e);
            }
        }

        let mut applied: u64 = 0;
        let mut skipped: u64 = 0;
        let mut conflicts: BTreeMap<String, (Hash, Hash, String)> = BTreeMap::new();
        let merge_emit_ctx = Self::build_execution_context(ctx);

        for (rel_path, source_h) in &source_bindings {
            let target_path = format!("{}{}", apply_prefix, rel_path);

            let existing = self.location_index.get(&target_path);

            match existing {
                None => {
                    if !dry_run {
                        let _cascade = self.location_index.set_with_context(
                            &target_path,
                            *source_h,
                            merge_emit_ctx.clone(),
                        );
                    }
                    applied += 1;
                }
                Some(existing_h) if existing_h == *source_h => {
                    skipped += 1;
                }
                Some(existing_h) => {
                    match strategy.as_str() {
                        "source-wins" => {
                            if !dry_run {
                                let _cascade = self.location_index.set_with_context(
                                    &target_path,
                                    *source_h,
                                    merge_emit_ctx.clone(),
                                );
                            }
                            conflicts.insert(
                                target_path,
                                (existing_h, *source_h, "used-incoming".to_string()),
                            );
                            applied += 1;
                        }
                        "target-wins" => {
                            conflicts.insert(
                                target_path,
                                (existing_h, *source_h, "kept-existing".to_string()),
                            );
                            skipped += 1;
                        }
                        _ => {
                            // no-overwrite
                            conflicts.insert(
                                target_path,
                                (existing_h, *source_h, "unresolved".to_string()),
                            );
                            skipped += 1;
                        }
                    }
                }
            }
        }

        // Build merge result
        let conflict_pairs: Vec<(entity_ecf::Value, entity_ecf::Value)> = conflicts
            .iter()
            .map(|(path, (existing_h, incoming_h, resolution))| {
                (
                    entity_ecf::text(path),
                    entity_ecf::Value::Map(vec![
                        (
                            entity_ecf::text("existing_hash"),
                            entity_ecf::Value::Bytes(existing_h.to_bytes().to_vec()),
                        ),
                        (
                            entity_ecf::text("incoming_hash"),
                            entity_ecf::Value::Bytes(incoming_h.to_bytes().to_vec()),
                        ),
                        (entity_ecf::text("resolution"), entity_ecf::text(resolution)),
                    ]),
                )
            })
            .collect();

        let result_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("applied"),
                entity_ecf::integer(applied as i64),
            ),
            (
                entity_ecf::text("conflicts"),
                entity_ecf::Value::Map(conflict_pairs),
            ),
            (
                entity_ecf::text("skipped"),
                entity_ecf::integer(skipped as i64),
            ),
            (entity_ecf::text("strategy"), entity_ecf::text(&strategy)),
        ]));

        let result_entity = Entity::new(entity_types::TYPE_TREE_MERGE_RESULT, result_data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        Ok(HandlerResult::ok(result_entity))
    }

    fn handle_extract(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        let params = decode_params(ctx);

        // Prefix from resource_target (priority) or params. The protocol
        // layer (`core/peer/src/connection.rs`) qualifies resource-target
        // paths via `EntityUri::qualify_path` before they arrive here, so
        // the resource-target branch is already absolute. The `params.prefix`
        // fallback comes through *un-qualified* — we absolutize it here so
        // that bare prefixes (e.g. `foo/`) resolve against the LI's absolute
        // bindings.
        // §5.2's subject rule (0.8.2.20) — the effective set, and §3.3's two
        // empties (0.8.2.24) exactly as `handle_snapshot` above. `extract`
        // returns an ENVELOPE OF EVERY BOUND ENTITY under the prefix, so serving
        // the `params.prefix` fallback to a self-excluded request is the widest
        // instance of the class in this file.
        let prefix = match entity_handler::single_effective_target(
            ctx.resource_target.as_ref(),
            &self.local_peer_id,
            "system/tree:extract",
        ) {
            Err(e) => return Ok(e),
            Ok(entity_handler::ResourceSubject::One(p)) => p,
            Ok(entity_handler::ResourceSubject::SelfExcluded) => {
                return Ok(entity_handler::self_excluded_refusal("system/tree:extract"))
            }
            Ok(entity_handler::ResourceSubject::Absent) => params
                .as_ref()
                .and_then(|p| {
                    let map = p.as_map()?;
                    map_get_text(map, "prefix").map(|raw| {
                        entity_entity::EntityUri::qualify_path(&raw, &self.local_peer_id)
                    })
                })
                .unwrap_or_default(),
        };

        if !validate_prefix(&prefix) {
            return error_result(
                STATUS_BAD_REQUEST,
                "invalid_prefix",
                "non-empty prefix must end with '/'",
            );
        }

        // §6.3 / §6.7 — `extract` takes `params.prefix` with the same fallback
        // `handle_snapshot` documents an auth obligation for, and performed
        // none. It is a READ that returns an envelope of every binding under
        // the prefix, so §6.7's act-neutral reading (0.8.2.20) is the whole
        // point: the harm is disclosure.
        // `"get"`, not `"extract"` — EXTENSION-TREE §11's `map_operation` row,
        // and the site where the unmapped name cost the most: what this function
        // returns is the bound entities themselves.
        if let Err(e) = self.authorize_path(ctx, "get", &prefix) {
            return Ok(e);
        }

        // Optional paths filter
        let paths_filter: Option<Vec<String>> = params.as_ref().and_then(|p| {
            let map = p.as_map()?;
            let arr = map_get_array(map, "paths")?;
            let paths: Vec<String> = arr
                .iter()
                .filter_map(|v| v.as_text().map(String::from))
                .collect();
            if paths.is_empty() {
                None
            } else {
                Some(paths)
            }
        });

        // ⛔ **Validate EVERY entry before reading ANY** (EXTENSION-TREE v4.9
        // §6.1/§6.2, ENTITY-CORE-PROTOCOL §5.4 — 0.8.2.21).
        //
        // `paths[]` is a caller-controlled array that reaches a tree-path
        // boundary through `params` — a channel the resource-target
        // pre-validator in `connection.rs` never sees. That asymmetry is the
        // whole of `CORE-PARAMS-PATH-TOTAL-1`: a peer that pre-validates only
        // the resource target answers `200` (or, in one sibling, crashed the
        // connection task) where a peer validating at the boundary answers
        // `400`.
        //
        // The disposition is `400 invalid_path` for the WHOLE request, no
        // partial result — and the deciding argument is the one this function's
        // own filter already makes. A well-formed path that binds nothing is
        // *absent* and is silently omitted, because that is what the filter is
        // FOR. So the question was never reject-vs-omit; it was whether
        // **malformed** and **absent** get the same answer. They must not: a
        // caller asking for ten paths and getting seven cannot tell garbage
        // from a missing binding, and *"fix your path"* is a different
        // instruction from *"that binding does not exist"*.
        //
        // Before reading any, not per-entry inside the loop, so the answer does
        // not depend on array order — and the sweep is `validate_path_input`
        // (the reserved dot prefixes, empty segments) plus the control-character
        // and absolute-path rules that make an entry not a *relative* path.
        if let Some(ref paths) = paths_filter {
            for rel_path in paths {
                if let Err(msg) = validate_extract_subpath(rel_path) {
                    return error_result(STATUS_BAD_REQUEST, "invalid_path", &msg);
                }
            }
        }

        // Collect bindings.
        //
        // §6.3's per-entry rule applies here for the same reason it applies to
        // a listing: the authorizer evaluated the prefix *string*, and what
        // leaves this function is the expanded *set* — with the bound entities
        // themselves in the envelope, so the disclosure is strictly wider than a
        // listing's name+hash. A per-entry filter rather than a refusal, matching
        // §6.3's listing MUST and `extensions/query`'s post-filter, which is the
        // in-tree model for an enumerating consumer.
        let mut bindings: BTreeMap<String, Hash> = if let Some(ref paths) = paths_filter {
            // Look up specific paths
            let mut map = BTreeMap::new();
            for rel_path in paths {
                let full_path = format!("{}{}", prefix, rel_path);
                if let Some(hash) = self.location_index.get(&full_path) {
                    map.insert(rel_path.clone(), hash);
                }
            }
            map
        } else {
            // List all under prefix
            let entries = self.location_index.list(&prefix);
            entries
                .iter()
                .map(|e| {
                    let rel = e.path.strip_prefix(&prefix).unwrap_or(&e.path);
                    (rel.to_string(), e.hash)
                })
                .collect()
        };
        // `"get"` per §11, as at the prefix check above — and it is the same
        // base permission the listing filter uses, which is what §8.2's
        // *"entries the capability grants `get` access to"* and §6.3's
        // `filter_listing` both name. go filters extract entries with a literal
        // `"get"` at `operations.go:436`/`:457`; this row was `"extract"` here.
        bindings.retain(|rel_path, _| {
            self.path_allowed(ctx, "get", &format!("{}{}", prefix, rel_path))
        });

        // Build trie and snapshot entity as root
        let root_hash = trie::build_trie(self.content_store.as_ref(), &bindings)
            .map_err(|e| HandlerError::Internal(format!("trie build: {}", e)))?;
        let snap_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("root"),
            entity_ecf::Value::Bytes(root_hash.to_bytes().to_vec()),
        )]));
        let snapshot = Entity::new(entity_types::TYPE_TREE_SNAPSHOT, snap_data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        // ⛔ **Every entity here is spliced by its RAW `data` bytes** — built
        // through `entity_entity::Envelope` + `entity_wire::encode_envelope`,
        // never by decoding `data` into a `Value` and letting `to_ecf` write
        // it back (ENTITY-CORE-PROTOCOL §5.4 byte fidelity; §3.1's *"keyed by
        // its own content hash"*, normative in the SENDER direction since
        // 0.8.2.23).
        //
        // What this used to be — `raw_cbor_value(&entity.data)` into an
        // `entity_ecf::Value::Map` — is a decode+re-encode, and `to_ecf`
        // normalizes non-minimal integer and length encodings, folds
        // indefinite-length items to definite, sorts map keys, and **drops
        // tags** (`encode_value`'s `Value::Tag(_, inner)` arm). For every
        // entity our own codec authored those are all no-ops, which is
        // precisely why no in-tree test and no cross-impl vector could see it:
        // the transform is the identity on every value the fixture set can
        // produce. For an entity authored anywhere else, the re-encoded bytes
        // hash to something else — so this map's KEY (the true hash, taken
        // from the store) stopped addressing its own VALUE, and the receiver
        // stored the entity at a hash the trie does not name. Measured end to
        // end at `merge_from_an_envelope_preserves_entity_bytes`.
        //
        // go is immune by construction here: `entity.Entity.Data` is
        // `cbor.RawMessage`, so its encoder splices. This is the rust-shaped
        // half of the same rule.
        // `include`, not `included.insert` — it keys by the RECOMPUTED content
        // hash (§3.1, 0.8.2.23), which is what makes the map content-addressed
        // rather than stamp-addressed. With raw `data` now surviving the trip,
        // the two agree for every honestly-built entity and disagree exactly
        // where the receiver should refuse.
        let mut envelope = Envelope::new(snapshot.clone());
        // The snapshot rides in `included` as well as in `root` — the
        // receiver's `ContentStore::put` round-trip wants it addressable.
        envelope.include(snapshot.clone());

        // All trie node entities (per TREE §6.2 — MUST include all reachable nodes)
        let trie_hashes = trie::collect_all_hashes(self.content_store.as_ref(), root_hash);
        for h in &trie_hashes {
            // Skip binding hashes (data entities are added below) and the snapshot itself
            if bindings.values().any(|bh| bh == h) || *h == snapshot.content_hash {
                continue;
            }
            if let Some(entity) = self.content_store.get(h) {
                envelope.include(entity);
            }
        }

        // Data entities referenced by bindings
        for hash in bindings.values() {
            if let Some(entity) = self.content_store.get(hash) {
                envelope.include(entity);
            }
        }

        let envelope_data = entity_wire::encode_envelope(&envelope);

        // EXTENSION-TREE §6 + PROPOSAL-CONTINUATION-TRANSFORM-AND-ENVELOPE-AMENDMENTS S3:
        // extract returns `system/envelope` (data bundle), NOT
        // `system/protocol/envelope` (a distinct protocol-message type).
        let envelope_entity = Entity::new(entity_types::TYPE_ENVELOPE, envelope_data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        Ok(HandlerResult::ok(envelope_entity))
    }
}

// `raw_cbor_value` — *"parse raw CBOR bytes back into a ciborium::Value for
// embedding in ECF output"* — is deliberately gone rather than left unused.
// It was the one helper in this file whose whole purpose was to carry an
// entity's `data` across a decode+re-encode, which §5.4 forbids; `extract`
// and `merge` were its only callers and both splice raw bytes now. A helper
// that exists is a helper the next inline-an-entity site will reach for.

#[derive(Debug, Error)]
pub enum TreeError {
    #[error("store error: {0}")]
    StoreError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use entity_capability::ResourceTarget;
    use entity_handler::STATUS_OK;
    use entity_store::{MemoryContentStore, MemoryLocationIndex};

    fn test_peer_id() -> String {
        entity_crypto::Keypair::from_seed([42u8; 32])
            .peer_id()
            .to_string()
    }

    /// Qualify a bare test path to the shape the WIRE produces.
    ///
    /// Every test in this module used to bind and address bare paths
    /// (`docs/readme`). Since 0.8.2.20 the handler draws its subject from
    /// `effective_targets`, which **canonicalizes** (§5.2) — so a bare target
    /// arrives as `/{peer}/docs/readme`, which is also the only shape
    /// `validate_absolute_path` accepts and the only shape `connection.rs`
    /// ever hands a handler. The bare form was modelling a tree state this
    /// peer cannot produce; `qp` makes the fixtures match the wire.
    fn qp(path: &str) -> String {
        format!("/{}/{}", test_peer_id(), path)
    }

    fn make_tree() -> TreeHandler {
        TreeHandler::new(
            Arc::new(MemoryContentStore::new()),
            Arc::new(MemoryLocationIndex::new()),
            test_peer_id(),
        )
    }

    fn make_entity(type_str: &str, data_str: &str) -> Entity {
        let data = entity_ecf::to_ecf(&entity_ecf::text(data_str));
        Entity::new(type_str, data).unwrap()
    }

    /// Build a HandlerContext for testing tree operations.
    fn make_handler_context(
        operation: &str,
        params_value: Option<entity_ecf::Value>,
        resource_targets: Option<Vec<String>>,
    ) -> HandlerContext {
        // Build params entity from the data value
        let params_data_val = params_value.unwrap_or(entity_ecf::Value::Null);
        let params_data_bytes = entity_ecf::to_ecf(&params_data_val);
        let params_type = format!("system/tree/{}-params", operation);
        let params = Entity::new(&params_type, params_data_bytes).unwrap();

        // Build EXECUTE entity (still needed for ctx.execute)
        let execute_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("operation"), entity_ecf::text(operation)),
            (
                entity_ecf::text("request_id"),
                entity_ecf::text("test-req-1"),
            ),
            (entity_ecf::text("uri"), entity_ecf::text("system/tree")),
        ]));
        let execute = Entity::new(entity_types::TYPE_EXECUTE, execute_data).unwrap();

        let resource_target = resource_targets.map(|targets| ResourceTarget {
            targets,
            exclude: vec![],
        });

        HandlerContext {
            handler_grant: None,
            caller_capability: None,
            execute,
            params,
            // The QUALIFIED pattern, as `connection.rs` sets it. The bare form
            // made `handle_merge`'s `namespace_is_peer_id` test false, so bare
            // merge prefixes were never qualified and the fixtures were
            // exercising an unqualified write path production cannot reach.
            pattern: qp("system/tree"),
            suffix: String::new(),
            resource_target,
            author: None,
            session_peer_id: None,
            request_id: "test-req-1".to_string(),
            operation: operation.to_string(),
            execute_fn: None,
            included: std::collections::HashMap::new(),
            matching_grant: None,
            capability_hash: None,
            handler_grant_hash: None,
            bounds: None,
            is_external: false,
            reactive_trigger: false,
        }
    }

    fn decode_cbor(data: &[u8]) -> ciborium::Value {
        ciborium::from_reader(data).unwrap()
    }

    fn cbor_map_get<'a>(
        map: &'a [(ciborium::Value, ciborium::Value)],
        key: &str,
    ) -> &'a ciborium::Value {
        &map.iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .unwrap_or_else(|| panic!("key '{}' not found", key))
            .1
    }

    // -----------------------------------------------------------------------
    // Direct API tests (existing)
    // -----------------------------------------------------------------------

    #[test]
    fn test_put_get() {
        let tree = make_tree();
        let entity = make_entity("test/type", "hello");
        let hash = tree.put(&qp("test/path"), entity.clone()).unwrap();
        let got = tree.get(&qp("test/path")).unwrap();
        assert_eq!(got.content_hash, entity.content_hash);
        assert_eq!(got.content_hash, hash);
    }

    #[test]
    fn test_get_missing() {
        let tree = make_tree();
        assert!(tree.get(&qp("nonexistent")).is_none());
    }

    #[test]
    fn test_get_by_hash() {
        let tree = make_tree();
        let entity = make_entity("test/type", "hello");
        let hash = tree.put(&qp("test/path"), entity).unwrap();
        assert!(tree.get_by_hash(&hash).is_some());
        assert!(tree.get_by_hash(&Hash::zero()).is_none());
    }

    #[test]
    fn test_has() {
        let tree = make_tree();
        assert!(!tree.has(&qp("test/path")));
        tree.put(&qp("test/path"), make_entity("test", "data"))
            .unwrap();
        assert!(tree.has(&qp("test/path")));
    }

    #[test]
    fn test_remove() {
        let tree = make_tree();
        let entity = make_entity("test/type", "hello");
        tree.put(&qp("test/path"), entity.clone()).unwrap();
        let removed = tree.remove(&qp("test/path"));
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().content_hash, entity.content_hash);
        assert!(!tree.has(&qp("test/path")));
    }

    #[test]
    fn test_remove_missing() {
        let tree = make_tree();
        assert!(tree.remove(&qp("nonexistent")).is_none());
    }

    #[test]
    fn test_list() {
        let tree = make_tree();
        tree.put(&qp("system/handler/a"), make_entity("test", "a"))
            .unwrap();
        tree.put(&qp("system/handler/b"), make_entity("test", "b"))
            .unwrap();
        tree.put(&qp("system/tree"), make_entity("test", "c"))
            .unwrap();

        let entries = tree.list(&qp("system/handler/"));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, qp("system/handler/a"));
        assert_eq!(entries[1].path, qp("system/handler/b"));
    }

    #[test]
    fn test_put_overwrite() {
        let tree = make_tree();
        let e1 = make_entity("test", "first");
        let e2 = make_entity("test", "second");
        tree.put(&qp("path"), e1).unwrap();
        tree.put(&qp("path"), e2.clone()).unwrap();
        let got = tree.get(&qp("path")).unwrap();
        assert_eq!(got.content_hash, e2.content_hash);
    }

    #[test]
    fn test_handler_pattern() {
        let tree = make_tree();
        assert_eq!(tree.pattern(), format!("/{}/system/tree", test_peer_id()));
        assert_eq!(tree.name(), "tree");
        assert_eq!(
            tree.operations(),
            &["get", "put", "snapshot", "diff", "merge", "extract", "create", "destroy"]
        );
    }

    // -----------------------------------------------------------------------
    // Listing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_listing_basic() {
        let tree = make_tree();
        tree.put(&qp("local/files/a.txt"), make_entity("test", "a"))
            .unwrap();
        tree.put(&qp("local/files/b.txt"), make_entity("test", "b"))
            .unwrap();

        let result = tree.handle_listing(&qp("local/files/")).unwrap();
        assert_eq!(result.status, 200);
        assert_eq!(result.result.entity_type, entity_types::TYPE_TREE_LISTING);

        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();
        let count = cbor_map_get(map, "count").as_integer().unwrap();
        assert_eq!(i128::from(count), 2);
    }

    #[test]
    fn test_listing_groups_children() {
        let tree = make_tree();
        tree.put(&qp("dir/a"), make_entity("test", "a")).unwrap();
        tree.put(&qp("dir/sub/b"), make_entity("test", "b"))
            .unwrap();
        tree.put(&qp("dir/sub/c"), make_entity("test", "c"))
            .unwrap();

        let result = tree.handle_listing(&qp("dir/")).unwrap();
        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();

        let count = cbor_map_get(map, "count").as_integer().unwrap();
        assert_eq!(i128::from(count), 2);

        let entries = cbor_map_get(map, "entries").as_map().unwrap();

        let a_entry = cbor_map_get(entries, "a").as_map().unwrap();
        let a_hash = cbor_map_get(a_entry, "hash");
        assert!(a_hash.as_bytes().is_some(), "direct child should have hash");

        let sub_entry = cbor_map_get(entries, "sub").as_map().unwrap();
        let sub_hash = cbor_map_get(sub_entry, "hash");
        assert!(sub_hash.is_null(), "directory should have null hash");
        let sub_children = cbor_map_get(sub_entry, "has_children");
        assert_eq!(sub_children.as_bool(), Some(true));
    }

    #[test]
    fn test_listing_empty_prefix() {
        let tree = make_tree();
        let result = tree.handle_listing(&qp("nonexistent/")).unwrap();
        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();
        let count = cbor_map_get(map, "count").as_integer().unwrap();
        assert_eq!(i128::from(count), 0);
    }

    // -----------------------------------------------------------------------
    // Handler dispatch tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_handler_get_entity() {
        let tree = make_tree();
        let entity = make_entity("test/type", "hello");
        tree.put(&qp("docs/readme"), entity.clone()).unwrap();

        let ctx = make_handler_context("get", None, Some(vec![qp("docs/readme")]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(result.result.content_hash, entity.content_hash);
    }

    #[tokio::test]
    async fn test_handler_get_not_found() {
        let tree = make_tree();
        let ctx = make_handler_context("get", None, Some(vec![qp("missing/path")]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_NOT_FOUND);
    }

    #[tokio::test]
    async fn test_handler_get_listing() {
        let tree = make_tree();
        tree.put(&qp("docs/a"), make_entity("test", "a")).unwrap();
        let ctx = make_handler_context("get", None, Some(vec![qp("docs/")]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(result.result.entity_type, entity_types::TYPE_TREE_LISTING);
    }

    #[tokio::test]
    async fn test_handler_unknown_operation() {
        let tree = make_tree();
        let ctx = make_handler_context("frobnicate", None, None);
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_NOT_SUPPORTED);
        // §3.3's 501 row (0.8.2.7): the unit of conformance is the code SLOT,
        // so the pair is pinned, not just the status. Asserting the status
        // alone is what let five synonyms share this slot.
        assert!(
            result
                .result
                .data
                .windows(21)
                .any(|w| w == b"unsupported_operation"),
            "the 501 slot carries exactly one spelling"
        );
    }

    // -----------------------------------------------------------------------
    // PUT operation tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_handler_put_store_entity() {
        let tree = make_tree();

        // Build an inline entity in params
        let inner = make_entity("test/doc", "my document");
        let inner_data_val: ciborium::Value = ciborium::from_reader(inner.data.as_slice()).unwrap();

        let params = entity_ecf::Value::Map(vec![(
            entity_ecf::text("entity"),
            entity_ecf::Value::Map(vec![
                (
                    entity_ecf::text("content_hash"),
                    entity_ecf::Value::Bytes(inner.content_hash.to_bytes()),
                ),
                (entity_ecf::text("data"), inner_data_val),
                (
                    entity_ecf::text("type"),
                    entity_ecf::text(&inner.entity_type),
                ),
            ]),
        )]);

        let ctx = make_handler_context("put", Some(params), Some(vec![qp("docs/readme")]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(
            result.result.entity_type,
            entity_types::TYPE_TREE_PUT_RESULT
        );

        // Verify entity was stored
        let stored = tree.get(&qp("docs/readme")).unwrap();
        assert_eq!(stored.content_hash, inner.content_hash);

        // Verify response contains content_hash
        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();
        let hash_bytes = cbor_map_get(map, "content_hash").as_bytes().unwrap();
        let returned_hash = Hash::from_bytes(hash_bytes).unwrap();
        assert_eq!(returned_hash, inner.content_hash);
    }

    #[tokio::test]
    async fn test_handler_put_remove_binding() {
        let tree = make_tree();
        tree.put(&qp("docs/readme"), make_entity("test", "data"))
            .unwrap();

        // Put with null entity → remove
        let params =
            entity_ecf::Value::Map(vec![(entity_ecf::text("entity"), entity_ecf::Value::Null)]);

        let ctx = make_handler_context("put", Some(params), Some(vec![qp("docs/readme")]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();
        assert_eq!(cbor_map_get(map, "removed").as_bool(), Some(true));

        // Verify binding is gone
        assert!(!tree.has(&qp("docs/readme")));
    }

    #[tokio::test]
    async fn test_handler_put_remove_not_found() {
        let tree = make_tree();

        let params =
            entity_ecf::Value::Map(vec![(entity_ecf::text("entity"), entity_ecf::Value::Null)]);

        let ctx = make_handler_context("put", Some(params), Some(vec![qp("missing/path")]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_NOT_FOUND);
    }

    /// §3.3 (0.8.2.20): `put` with no resource is the ABSENT case and answers
    /// **400 `path_required`** as a value, not a transport-level `Err`. The old
    /// shape was `Err(HandlerError::InvalidParams)`, which collapses the two
    /// §3.3 inputs into one generic refusal — the thing §3.3 names
    /// non-conformant — and gives the caller no code to branch on.
    #[tokio::test]
    async fn test_handler_put_missing_path() {
        let tree = make_tree();
        let ctx = make_handler_context("put", None, None);
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_BAD_REQUEST);
        assert_eq!(error_code(&result), "path_required");
    }

    /// Decode the `code` field of a `system/protocol/error` result.
    ///
    /// Reads the decoded **key**, never a substring of the body: a code is
    /// `(status, field, spelling)` and a byte scan measures only the spelling.
    fn error_code(result: &HandlerResult) -> String {
        let v = decode_cbor(&result.result.data);
        let map = v.as_map().expect("error body is a map");
        cbor_map_get(map, "code")
            .as_text()
            .unwrap_or_default()
            .to_string()
    }

    /// [`error_code`] made **total**, for a row that collects rather than
    /// asserts. `error_code` panics on a non-error body, and a collecting row's
    /// whole job is to survive the answer it did not expect and report it — a
    /// mutation that turns a 400 into a 200 would otherwise die inside the
    /// helper and name no row at all (measured: it did, on the first run of
    /// `the_two_empties_split_on_every_resource_optional_tree_op`).
    fn describe_outcome(result: &HandlerResult) -> String {
        if result.result.entity_type != entity_types::TYPE_ERROR {
            return format!("(non-error body: {})", result.result.entity_type);
        }
        error_code(result)
    }

    // -----------------------------------------------------------------------
    // PUT expected_hash / CAS tests (ENTITY-CORE-PROTOCOL §3.9)
    // -----------------------------------------------------------------------

    /// Build `put` params for a CAS test: optional inline entity + optional expected_hash.
    fn put_params_with_expected(
        entity: Option<&Entity>,
        expected: Option<Hash>,
    ) -> entity_ecf::Value {
        let mut fields: Vec<(entity_ecf::Value, entity_ecf::Value)> = Vec::new();
        if let Some(e) = entity {
            let inner_data_val: ciborium::Value = ciborium::from_reader(e.data.as_slice()).unwrap();
            // All three keys — §6.3 step 1 admits the value as a `core/entity`
            // before anything else looks at it, so a two-key fixture never
            // reaches the CAS behaviour these callers exist to exercise.
            fields.push((
                entity_ecf::text("entity"),
                entity_ecf::Value::Map(vec![
                    (
                        entity_ecf::text("content_hash"),
                        entity_ecf::Value::Bytes(e.content_hash.to_bytes()),
                    ),
                    (entity_ecf::text("data"), inner_data_val),
                    (entity_ecf::text("type"), entity_ecf::text(&e.entity_type)),
                ]),
            ));
        } else {
            fields.push((entity_ecf::text("entity"), entity_ecf::Value::Null));
        }
        if let Some(h) = expected {
            fields.push((
                entity_ecf::text("expected_hash"),
                entity_ecf::Value::Bytes(h.to_bytes().to_vec()),
            ));
        }
        entity_ecf::Value::Map(fields)
    }

    #[tokio::test]
    async fn test_handler_put_cas_match_succeeds() {
        let tree = make_tree();
        let e1 = make_entity("test", "v1");
        let h1 = tree.put(&qp("cas/path"), e1.clone()).unwrap();

        let e2 = make_entity("test", "v2");
        let params = put_params_with_expected(Some(&e2), Some(h1));
        let ctx = make_handler_context("put", Some(params), Some(vec![qp("cas/path")]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(
            tree.get(&qp("cas/path")).unwrap().content_hash,
            e2.content_hash
        );
    }

    /// EXTENSION-TREE v4.4 Appendix A — all three `put` rows in one place, so
    /// the two `hash_mismatch` rows sit beside the `invalid_request` row they
    /// are most likely to be collapsed into.
    ///
    /// Mutation witnesses, each run and confirmed RED **at the row it is
    /// scoped to** — the two 400 rows take different code paths, so a mutation
    /// of one says nothing about the other:
    ///
    /// - decode site → `"hash_mismatch"` (the wholesale flip the routed
    ///   worklist would have produced) reddens **row 1** at the
    ///   `invalid_request` assertion.
    /// - validate site → `"invalid_request"` (the collapse in the other
    ///   direction) reddens **row 2**.
    /// - restoring the pre-v4.4 `HandlerError::InvalidParams("invalid_entity:
    ///   …")` at both sites reddens **row 1** at the `.unwrap()`, because the
    ///   handler goes back to a propagated `Err`.
    ///
    /// One mutation deliberately does **not** bite and is recorded so nobody
    /// re-derives it as a defect: collapsing only the *validate* branch's
    /// `match` to a bare `"hash_mismatch"` leaves all three rows green. That is
    /// correct — the non-mismatch arm is unreachable by construction, which is
    /// what `validate_on_the_put_path_can_only_fail_with_hash_mismatch` exists
    /// to keep true. It is not evidence that this test is toothless; the first
    /// two mutations are.
    #[tokio::test]
    async fn put_error_codes_are_the_three_appendix_a_rows() {
        // Row 1 — the submitted entity does not decode: 400 invalid_request.
        // `entity` is present and is not a map, so `decode_entity_from_cbor`
        // fails at `as_map` rather than at any hash check.
        {
            let tree = make_tree();
            let params = entity_ecf::Value::Map(vec![(
                entity_ecf::text("entity"),
                entity_ecf::text("not a map"),
            )]);
            let ctx = make_handler_context("put", Some(params), Some(vec![qp("bad/decode")]));
            let result = tree.handle(&ctx).await.unwrap();
            assert_eq!(result.status, STATUS_BAD_REQUEST);
            let val = decode_cbor(&result.result.data);
            let map = val.as_map().unwrap();
            assert_eq!(
                cbor_map_get(map, "code").as_text(),
                Some("invalid_request"),
                "a non-decoding entity is the generic structurally-invalid case"
            );
            assert!(!tree.has(&qp("bad/decode")));
        }

        // Row 2 — the entity is well-formed and its content hash addresses
        // something else: 400 hash_mismatch. This is the row that carries the
        // information; it is what a caller branches on.
        {
            let tree = make_tree();
            let e = make_entity("test", "the real payload");
            let wrong = Hash::compute(
                "test",
                &entity_ecf::to_ecf(&entity_ecf::text("something else")),
            );
            assert_ne!(wrong, e.content_hash);
            let inner: ciborium::Value = ciborium::from_reader(e.data.as_slice()).unwrap();
            let params = entity_ecf::Value::Map(vec![(
                entity_ecf::text("entity"),
                entity_ecf::Value::Map(vec![
                    (
                        entity_ecf::text("content_hash"),
                        entity_ecf::Value::Bytes(wrong.to_bytes().to_vec()),
                    ),
                    (entity_ecf::text("data"), inner),
                    (entity_ecf::text("type"), entity_ecf::text(&e.entity_type)),
                ]),
            )]);
            let ctx = make_handler_context("put", Some(params), Some(vec![qp("bad/hash")]));
            let result = tree.handle(&ctx).await.unwrap();
            assert_eq!(
                result.status,
                STATUS_BAD_REQUEST,
                "a tampered content hash is a defect in the submission (400), not a lost race (409)"
            );
            let val = decode_cbor(&result.result.data);
            let map = val.as_map().unwrap();
            assert_eq!(cbor_map_get(map, "code").as_text(), Some("hash_mismatch"));
            assert!(!tree.has(&qp("bad/hash")));
        }

        // Row 3 — the CAS race. Same token, different status, different
        // failure: nobody's defect and retryable. Covered in full by
        // `test_handler_put_cas_mismatch_returns_409`; asserted here only so
        // the pair is visible as a pair.
        {
            let tree = make_tree();
            tree.put(&qp("cas/pair"), make_entity("test", "v1"))
                .unwrap();
            let wrong = Hash::compute("test", &entity_ecf::to_ecf(&entity_ecf::text("stale")));
            let params = put_params_with_expected(Some(&make_entity("test", "v2")), Some(wrong));
            let ctx = make_handler_context("put", Some(params), Some(vec![qp("cas/pair")]));
            let result = tree.handle(&ctx).await.unwrap();
            assert_eq!(result.status, STATUS_CONFLICT);
            let val = decode_cbor(&result.result.data);
            let map = val.as_map().unwrap();
            assert_eq!(cbor_map_get(map, "code").as_text(), Some("hash_mismatch"));
        }
    }

    /// `ENTITY-CORE-PROTOCOL` §6.3 step 1 in full — the **predicate**, not the
    /// one clause that was routed. `EXTENSION-TREE` Appendix A v4.5 spells it
    /// out: the value is not an entity when it is *"not a map, or `type` is
    /// absent / empty / not a text string, or `data` is absent, or
    /// `content_hash` is absent or its length does not match its format code"*.
    /// core-go's routing named only absent `content_hash`, because that is the
    /// clause their check drove; the sentence binds all of them, so the
    /// boundary is the clause list and not the pointer (`AGENTS.md`: a routed
    /// pointer is a starting point, not the boundary).
    ///
    /// Two clauses were already right here before this change and are asserted
    /// rather than "fixed": a non-map, and a `data` that is absent. Two were
    /// not: an **empty** `type` was accepted, and a **non-text** `type` reached
    /// the right code by accident — it fell through `as_text()` into the
    /// *"missing 'type'"* arm, so the wire answer was correct while the reason
    /// was wrong and one refactor away from silently becoming an empty type.
    ///
    /// `data: null` is deliberately in the PASS column: `data` is
    /// `primitive/any`, so §6.3 asks only that it be **present**. Reading
    /// absent and null as one fact here would refuse a legal payload.
    #[tokio::test]
    async fn put_admission_predicate_is_every_clause_of_the_entity_shape() {
        let good = make_entity("test/type", "payload");
        let good_data: ciborium::Value = ciborium::from_reader(good.data.as_slice()).unwrap();
        let ch = || {
            (
                entity_ecf::text("content_hash"),
                entity_ecf::Value::Bytes(good.content_hash.to_bytes()),
            )
        };

        // Each row: (label, the `entity` value, refused?)
        let rows: Vec<(&str, entity_ecf::Value, bool)> = vec![
            ("not a map", entity_ecf::text("not a map"), true),
            (
                "type absent",
                entity_ecf::Value::Map(vec![ch(), (entity_ecf::text("data"), good_data.clone())]),
                true,
            ),
            (
                "type empty",
                entity_ecf::Value::Map(vec![
                    ch(),
                    (entity_ecf::text("data"), good_data.clone()),
                    (entity_ecf::text("type"), entity_ecf::text("")),
                ]),
                true,
            ),
            (
                "type not a text string",
                entity_ecf::Value::Map(vec![
                    ch(),
                    (entity_ecf::text("data"), good_data.clone()),
                    (entity_ecf::text("type"), entity_ecf::integer(7)),
                ]),
                true,
            ),
            (
                "data absent",
                entity_ecf::Value::Map(vec![
                    ch(),
                    (entity_ecf::text("type"), entity_ecf::text("test/type")),
                ]),
                true,
            ),
            (
                "content_hash absent",
                entity_ecf::Value::Map(vec![
                    (entity_ecf::text("data"), good_data.clone()),
                    (entity_ecf::text("type"), entity_ecf::text("test/type")),
                ]),
                true,
            ),
            (
                "content_hash mis-sized for its format code",
                entity_ecf::Value::Map(vec![
                    (
                        entity_ecf::text("content_hash"),
                        // format 0x00 (SHA-256) declares 32 digest bytes; 8 is
                        // a length that does not match the code it names.
                        entity_ecf::Value::Bytes(vec![0x00; 9]),
                    ),
                    (entity_ecf::text("data"), good_data.clone()),
                    (entity_ecf::text("type"), entity_ecf::text("test/type")),
                ]),
                true,
            ),
            // --- the control: the same shape, complete, is admitted. Without
            // it every row above is satisfied by a `put` that refuses
            // everything, which is the one-edit-away wrong fix.
            (
                "all three fields present and well-formed",
                entity_ecf::Value::Map(vec![
                    ch(),
                    (entity_ecf::text("data"), good_data.clone()),
                    (entity_ecf::text("type"), entity_ecf::text("test/type")),
                ]),
                false,
            ),
        ];

        for (label, entity_val, refused) in rows {
            let tree = make_tree();
            let params = entity_ecf::Value::Map(vec![(entity_ecf::text("entity"), entity_val)]);
            let ctx = make_handler_context("put", Some(params), Some(vec![qp("p/x")]));
            let result = tree.handle(&ctx).await.unwrap();
            if refused {
                assert_eq!(
                    result.status, STATUS_BAD_REQUEST,
                    "clause `{label}` must be refused"
                );
                let val = decode_cbor(&result.result.data);
                assert_eq!(
                    cbor_map_get(val.as_map().unwrap(), "code").as_text(),
                    Some("invalid_request"),
                    "clause `{label}` is the structural row"
                );
                assert!(!tree.has(&qp("p/x")), "clause `{label}` stored something");
            } else {
                assert_eq!(result.status, STATUS_OK, "row `{label}` must be admitted");
                assert!(tree.has(&qp("p/x")), "row `{label}` must bind");
            }
        }

        // `data: null` is PRESENT, and presence is the whole test.
        let null_body =
            Entity::new("test/type", entity_ecf::to_ecf(&entity_ecf::Value::Null)).unwrap();
        let tree = make_tree();
        let params = entity_ecf::Value::Map(vec![(
            entity_ecf::text("entity"),
            entity_ecf::Value::Map(vec![
                (
                    entity_ecf::text("content_hash"),
                    entity_ecf::Value::Bytes(null_body.content_hash.to_bytes()),
                ),
                (entity_ecf::text("data"), entity_ecf::Value::Null),
                (entity_ecf::text("type"), entity_ecf::text("test/type")),
            ]),
        )]);
        let ctx = make_handler_context("put", Some(params), Some(vec![qp("p/null")]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(
            result.status, STATUS_OK,
            "`data` is primitive/any — null is a legal payload, not an absence"
        );
    }

    /// `EXTENSION-TREE` Appendix A **v4.5**'s fourth `put` row, and it is a
    /// **wrong-but-legal code** we were shipping until now: a `content_hash`
    /// that is a well-formed `system/hash` naming a format code this build
    /// cannot verify is `400 unsupported_content_hash_format`
    /// (`ENTITY-CORE-PROTOCOL` §4.7 row 5), **not** `invalid_request`. The row
    /// says so in its own text — *"Not the `invalid_request` row — the value is
    /// a structurally valid hash and the peer simply cannot verify it."*
    ///
    /// This clause was **not** in core-go's relay section for us; it was item 3
    /// of go's own worklist, because go is where the row was noticed. The row
    /// binds every seat that ingests a `put`, so it is ours too — the sweep
    /// found it, not the routing.
    ///
    /// It is the expensive kind of defect precisely because the old answer was
    /// *legal*: `invalid_request` is a real §3.3 400 code, so no token census
    /// anywhere can see the mistake. Only a caller trying to decide *"re-encode
    /// my submission"* versus *"find a peer that speaks SHA-512"* pays for it.
    ///
    /// Mutation verified: routing `UnsupportedAlgorithm` / `ReservedFormat`
    /// back into `PutAdmission::NotAnEntity` reddens both rows below at the
    /// `code` assertion, and leaves
    /// `put_admission_predicate_is_every_clause_of_the_entity_shape` green —
    /// which is why this needs its own rows rather than one more clause there.
    #[tokio::test]
    async fn put_unsupported_content_hash_format_is_its_own_row_not_invalid_request() {
        // 0x02 is unallocated; 0xFF is the v7.67 §5.3 reservation, encoded as
        // the two-byte varint [0xFF, 0x01]. Both are "well-formed hash, format
        // this peer cannot verify" and both take the §4.7 row 5 exit.
        let mut reserved = vec![0xFF, 0x01];
        reserved.extend_from_slice(&[0u8; 32]);
        let unallocated = {
            let mut v = vec![0x02];
            v.extend_from_slice(&[0u8; 32]);
            v
        };

        for (label, wire) in [
            ("unallocated 0x02", unallocated),
            ("reserved 0xFF", reserved),
        ] {
            let tree = make_tree();
            let good = make_entity("test/type", "payload");
            let inner: ciborium::Value = ciborium::from_reader(good.data.as_slice()).unwrap();
            let params = entity_ecf::Value::Map(vec![(
                entity_ecf::text("entity"),
                entity_ecf::Value::Map(vec![
                    (
                        entity_ecf::text("content_hash"),
                        entity_ecf::Value::Bytes(wire),
                    ),
                    (entity_ecf::text("data"), inner),
                    (entity_ecf::text("type"), entity_ecf::text("test/type")),
                ]),
            )]);
            let ctx = make_handler_context("put", Some(params), Some(vec![qp("fmt/x")]));
            let result = tree.handle(&ctx).await.unwrap();
            assert_eq!(result.status, STATUS_BAD_REQUEST, "{label}");
            let val = decode_cbor(&result.result.data);
            assert_eq!(
                cbor_map_get(val.as_map().unwrap(), "code").as_text(),
                Some("unsupported_content_hash_format"),
                "{label}: a well-formed hash we cannot verify is §4.7 row 5, \
                 not the structural row"
            );
            assert!(!tree.has(&qp("fmt/x")));
        }
    }

    /// §6.3's ordering, and the **only input that can measure it**: a
    /// submission carrying *both* faults at once. Each single-fault row reaches
    /// its own branch under either ordering, so no vector carrying one fault
    /// discriminates — 0.8.2.11 says this in the spec text and §9.1's
    /// conformance row names the both-faults input for exactly that reason.
    ///
    /// Structure strictly precedes hash, and the ordering is a data dependency
    /// rather than a convention: step 2 compares against `content_hash({type,
    /// data})`, which are precisely the fields step 1 establishes exist.
    ///
    /// Mutation verified: deleting the empty-`type` clause from
    /// `decode_entity_from_cbor` lets this input pass step 1, so step 2 speaks
    /// instead and the row reddens with **`Some("hash_mismatch")` vs
    /// `Some("invalid_request")`** — the ladder running backwards, which is
    /// exactly what the assertion message names. (It also reddens the
    /// `type empty` row of `put_admission_predicate_is_every_clause_of_the_
    /// entity_shape`; that neighbour going red is expected and is not what
    /// this row is measuring.)
    #[tokio::test]
    async fn put_admission_is_structure_then_hash() {
        let tree = make_tree();
        // Both faults: `type` is empty (structural), AND the carried hash
        // addresses something else entirely (hash fault).
        let other = make_entity("test/type", "a different payload");
        let good = make_entity("test/type", "payload");
        let inner: ciborium::Value = ciborium::from_reader(good.data.as_slice()).unwrap();
        let params = entity_ecf::Value::Map(vec![(
            entity_ecf::text("entity"),
            entity_ecf::Value::Map(vec![
                (
                    entity_ecf::text("content_hash"),
                    entity_ecf::Value::Bytes(other.content_hash.to_bytes()),
                ),
                (entity_ecf::text("data"), inner),
                (entity_ecf::text("type"), entity_ecf::text("")),
            ]),
        )]);
        let ctx = make_handler_context("put", Some(params), Some(vec![qp("both/faults")]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_BAD_REQUEST);
        let val = decode_cbor(&result.result.data);
        assert_eq!(
            cbor_map_get(val.as_map().unwrap(), "code").as_text(),
            Some("invalid_request"),
            "a submission that is both malformed and mis-hashed is the STRUCTURAL row; \
             answering hash_mismatch means the ladder is running backwards"
        );
        assert!(!tree.has(&qp("both/faults")));
    }

    /// The containment that makes the `put` validate branch's non-mismatch arm
    /// unreachable, asserted rather than assumed. `decode_entity_from_cbor`
    /// admits a `content_hash` only through `Hash::from_bytes`, which refuses
    /// any format `digest_len_for_format` does not know; `Entity::validate`
    /// then recomputes through `Hash::compute_format`. While those two agree on
    /// the supported set, the only reachable failure is `HashMismatch`. If a
    /// format is ever added to one and not the other this goes red, and the
    /// `invalid_request` arm in `handle_put` becomes live code rather than a
    /// documented dead row.
    #[test]
    fn validate_on_the_put_path_can_only_fail_with_hash_mismatch() {
        for format_code in 0u8..=u8::MAX {
            let known_to_decoder = entity_hash::digest_len_for_format(format_code).is_some();
            let known_to_hasher = Hash::compute_format("test", b"\x60", format_code).is_ok();
            assert_eq!(
                known_to_decoder, known_to_hasher,
                "format {:#04x} is known to one of the two hash tables and not the other; \
                 the put validate branch's non-mismatch arm is now reachable",
                format_code
            );
        }
    }

    #[tokio::test]
    async fn test_handler_put_cas_mismatch_returns_409() {
        let tree = make_tree();
        let e1 = make_entity("test", "v1");
        tree.put(&qp("cas/path"), e1).unwrap();

        let wrong = Hash::compute("test", &entity_ecf::to_ecf(&entity_ecf::text("wrong")));
        let e2 = make_entity("test", "v2");
        let params = put_params_with_expected(Some(&e2), Some(wrong));
        let ctx = make_handler_context("put", Some(params), Some(vec![qp("cas/path")]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_CONFLICT);
        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();
        assert_eq!(cbor_map_get(map, "code").as_text(), Some("hash_mismatch"));
    }

    #[tokio::test]
    async fn test_handler_put_cas_missing_binding_returns_409() {
        let tree = make_tree();
        let expected = Hash::compute("test", &entity_ecf::to_ecf(&entity_ecf::text("x")));
        let e = make_entity("test", "new");
        let params = put_params_with_expected(Some(&e), Some(expected));
        let ctx = make_handler_context("put", Some(params), Some(vec![qp("cas/missing")]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_CONFLICT);
        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();
        assert_eq!(cbor_map_get(map, "code").as_text(), Some("hash_mismatch"));
        assert!(!tree.has(&qp("cas/missing")));
    }

    #[tokio::test]
    async fn test_handler_put_cas_absent_is_unconditional() {
        // Backward compat: no expected_hash → unconditional put.
        let tree = make_tree();
        let e1 = make_entity("test", "v1");
        tree.put(&qp("cas/path"), e1).unwrap();

        let e2 = make_entity("test", "v2");
        let params = put_params_with_expected(Some(&e2), None);
        let ctx = make_handler_context("put", Some(params), Some(vec![qp("cas/path")]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(
            tree.get(&qp("cas/path")).unwrap().content_hash,
            e2.content_hash
        );
    }

    #[tokio::test]
    async fn test_handler_put_cas_remove_match_succeeds() {
        let tree = make_tree();
        let e1 = make_entity("test", "v1");
        let h1 = tree.put(&qp("cas/path"), e1).unwrap();

        let params = put_params_with_expected(None, Some(h1));
        let ctx = make_handler_context("put", Some(params), Some(vec![qp("cas/path")]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert!(!tree.has(&qp("cas/path")));
    }

    #[tokio::test]
    async fn test_handler_put_cas_remove_mismatch_returns_409() {
        let tree = make_tree();
        let e1 = make_entity("test", "v1");
        tree.put(&qp("cas/path"), e1).unwrap();

        let wrong = Hash::compute("test", &entity_ecf::to_ecf(&entity_ecf::text("wrong")));
        let params = put_params_with_expected(None, Some(wrong));
        let ctx = make_handler_context("put", Some(params), Some(vec![qp("cas/path")]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_CONFLICT);
        // Binding still present
        assert!(tree.has(&qp("cas/path")));
    }

    #[tokio::test]
    async fn test_handler_put_cas_create_zero_hash_unbound_succeeds() {
        // V7 §3.9 v7.50: expected_hash = zero on an unbound path → CAS-create
        // succeeds and binds the entity.
        let tree = make_tree();
        let e = make_entity("test", "first");
        let params = put_params_with_expected(Some(&e), Some(Hash::zero()));
        let ctx = make_handler_context("put", Some(params), Some(vec![qp("cas/fresh")]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(
            tree.get(&qp("cas/fresh")).unwrap().content_hash,
            e.content_hash
        );
    }

    #[tokio::test]
    async fn test_handler_put_cas_create_zero_hash_bound_returns_409() {
        // V7 §3.9 v7.50: expected_hash = zero on a bound path → 409
        // hash_mismatch (the create precondition is "path is unbound").
        let tree = make_tree();
        let e1 = make_entity("test", "first");
        let h1 = tree.put(&qp("cas/taken"), e1.clone()).unwrap();

        let e2 = make_entity("test", "second");
        let params = put_params_with_expected(Some(&e2), Some(Hash::zero()));
        let ctx = make_handler_context("put", Some(params), Some(vec![qp("cas/taken")]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_CONFLICT);
        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();
        assert_eq!(cbor_map_get(map, "code").as_text(), Some("hash_mismatch"));
        // Binding unchanged.
        assert_eq!(tree.get(&qp("cas/taken")).unwrap().content_hash, h1);
    }

    #[tokio::test]
    async fn test_handler_put_cas_create_remove_zero_hash_unbound_noop_ok() {
        // V7 §3.9 v7.50: remove with expected_hash = zero on an unbound path
        // → idempotent no-op (200, removed: false). "Applies to both write and
        // remove".
        let tree = make_tree();
        let params = put_params_with_expected(None, Some(Hash::zero()));
        let ctx = make_handler_context("put", Some(params), Some(vec![qp("cas/never")]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert!(!tree.has(&qp("cas/never")));
    }

    #[tokio::test]
    async fn test_handler_put_cas_create_remove_zero_hash_bound_returns_409() {
        // V7 §3.9 v7.50: remove with expected_hash = zero on a bound path
        // → 409 (you expected absent but the path has a binding).
        let tree = make_tree();
        let e1 = make_entity("test", "v1");
        tree.put(&qp("cas/exists"), e1).unwrap();

        let params = put_params_with_expected(None, Some(Hash::zero()));
        let ctx = make_handler_context("put", Some(params), Some(vec![qp("cas/exists")]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_CONFLICT);
        // Binding still present.
        assert!(tree.has(&qp("cas/exists")));
    }

    // -----------------------------------------------------------------------
    // SNAPSHOT operation tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_handler_snapshot_uses_tracked_root_when_present() {
        // Seed a tracked root binding directly (no wrapper entity) —
        // handle_snapshot must return it verbatim (EXTENSION-TREE §3.4.1).
        let tree = make_tree();
        let pid = test_peer_id();

        let fake_root = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("fake-root")));
        tree.location_index
            .set(&format!("/{}/system/tree/root/project", pid), fake_root);
        // Also seed real bindings — the fast path should still win.
        tree.put(&format!("/{}/project/a", pid), make_entity("t", "a"))
            .unwrap();

        let ctx = make_handler_context("snapshot", None, Some(vec![format!("/{}/project/", pid)]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();
        let root_bytes = cbor_map_get(map, "root").as_bytes().unwrap();
        let got_root = Hash::from_bytes(root_bytes).unwrap();
        assert_eq!(
            got_root, fake_root,
            "snapshot fast path must return the tracked root"
        );
    }

    #[tokio::test]
    async fn test_handler_snapshot_empty_tree() {
        let tree = make_tree();
        let ctx = make_handler_context("snapshot", None, Some(vec![qp("docs/")]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(result.result.entity_type, entity_types::TYPE_TREE_SNAPSHOT);

        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();
        let root_bytes = cbor_map_get(map, "root").as_bytes().unwrap();
        assert_eq!(root_bytes.len(), 33, "root should be a 33-byte hash");
        let root_hash = Hash::from_bytes(root_bytes).unwrap();
        let bindings = trie::collect_all_bindings(tree.content_store.as_ref(), root_hash, "");
        assert!(bindings.is_empty());
    }

    #[tokio::test]
    async fn test_handler_snapshot_populated() {
        let tree = make_tree();
        let e1 = make_entity("test", "alpha");
        let e2 = make_entity("test", "beta");
        tree.put(&qp("docs/a"), e1.clone()).unwrap();
        tree.put(&qp("docs/b"), e2.clone()).unwrap();
        tree.put(&qp("other/c"), make_entity("test", "gamma"))
            .unwrap();

        let ctx = make_handler_context("snapshot", None, Some(vec![qp("docs/")]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();
        let root_bytes = cbor_map_get(map, "root").as_bytes().unwrap();
        assert_eq!(root_bytes.len(), 33, "root should be a 33-byte hash");
        let root_hash = Hash::from_bytes(root_bytes).unwrap();
        let bindings = trie::collect_all_bindings(tree.content_store.as_ref(), root_hash, "");
        assert_eq!(bindings.len(), 2);

        // Verify relative paths
        let a_hash = bindings.get("a").expect("binding 'a' should exist");
        assert_eq!(*a_hash, e1.content_hash);
    }

    #[tokio::test]
    async fn test_handler_snapshot_invalid_prefix() {
        let tree = make_tree();
        let ctx = make_handler_context("snapshot", None, Some(vec![qp("docs")]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_BAD_REQUEST);
    }

    /// V7 §3.2 confused-deputy regression — PROPOSAL-CROSS-IMPL-STANDARDIZATION-
    /// CATCHUP §3. When tree:snapshot reads its prefix from params (not
    /// resource_target), the dispatch-layer auth check did not see that path,
    /// so the handler MUST perform its own check. Without the fix, a caller
    /// authorized for one prefix could snapshot a different one.
    #[tokio::test]
    async fn test_handler_snapshot_params_prefix_auth_checked() {
        use entity_capability::{
            check_permission, CapabilityToken, GrantEntry, Granter, IdScope, PathScope,
            ResourceTarget,
        };

        let tree = make_tree();
        let peer = test_peer_id();

        // Build a cap granting snapshot on `/peer/system/tree` ONLY for the
        // `docs/` prefix.
        let allowed_prefix = format!("/{}/docs/", peer);
        let attempted_prefix = format!("/{}/secret/", peer);
        let grant = GrantEntry {
            handlers: PathScope::new(vec!["system/tree".into()]),
            resources: PathScope::new(vec![allowed_prefix.clone()]),
            operations: IdScope::new(vec!["snapshot".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        };
        let cap = CapabilityToken {
            grants: vec![grant],
            granter: Granter::Single(Hash::zero()),
            grantee: Hash::zero(),
            parent: None,
            created_at: 0,
            expires_at: None,
            not_before: None,
            delegation_caveats: None,
        };

        // Sanity: dispatch-layer check would PASS for allowed, FAIL for
        // attempted (proves the cap shape is correct).
        let allowed_target = ResourceTarget {
            targets: vec![allowed_prefix.clone()],
            exclude: vec![],
        };
        let attempted_target = ResourceTarget {
            targets: vec![attempted_prefix.clone()],
            exclude: vec![],
        };
        let pattern = format!("/{}/system/tree", peer);
        assert!(check_permission(
            "snapshot",
            &pattern,
            &peer,
            Some(&allowed_target),
            &cap,
            &peer
        ));
        assert!(!check_permission(
            "snapshot",
            &pattern,
            &peer,
            Some(&attempted_target),
            &cap,
            &peer
        ));

        // Build a context: NO resource_target, params carries the attempted
        // prefix. Without the §3.2 handler-side check this would silently
        // return a snapshot of `/peer/secret/`.
        let params_val = entity_ecf::Value::Map(vec![(
            entity_ecf::text("prefix"),
            entity_ecf::text(&attempted_prefix),
        )]);
        let mut ctx = make_handler_context("snapshot", Some(params_val.clone()), None);
        ctx.caller_capability = Some(cap.clone());
        // The fixture now declares the dispatch EXTERNAL, because that is the
        // only kind for which `caller_capability` is an authorization input
        // rather than attribution — see `TreeHandler::authorize_path`. It was
        // implicitly external all along (the scenario is *"a caller authorized
        // for one prefix"*); nothing said so, and the check it drives used to
        // run on every dispatch.
        ctx.is_external = true;

        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(
            result.status, STATUS_FORBIDDEN,
            "snapshot with params.prefix MUST be auth-checked when not in resource_target"
        );
    }

    /// The narrowing that landed with §6.3's handler-level check, pinned so it
    /// is visible rather than rediscovered as a defect.
    ///
    /// The same request on an **internal** dispatch is NOT refused. That is a
    /// reduction against the previous `from_params` check, which ran on every
    /// dispatch, and it is deliberate: for an in-process dispatch
    /// `caller_capability` is the *propagated* original caller's token —
    /// attribution, per `make_execute_fn`'s own comment — not the authority
    /// §5.2 checked, which is the dispatcher's `DispatchCeiling`. Measured
    /// consequence of the old reading: `follow(Continuation)`'s standing leg
    /// reached `tree:put` carrying the inbox deliver token four hops later.
    ///
    /// What this row does NOT say is that the internal case is safe. It is
    /// bounded by the dispatcher's ceiling at §5.2 and, where that dispatch
    /// carries no `resource`, by nothing — the gap named at `authorize_path`
    /// and routed. Flip this assertion when the ceiling grant reaches the
    /// handler context.
    #[tokio::test]
    async fn snapshot_params_prefix_is_not_checked_on_an_internal_dispatch() {
        let tree = make_tree();
        let peer = test_peer_id();
        let attempted_prefix = format!("/{}/secret/", peer);
        let cap = entity_capability::CapabilityToken {
            grants: vec![entity_capability::GrantEntry {
                handlers: entity_capability::PathScope::new(vec![format!("/{}/system/tree", peer)]),
                resources: entity_capability::PathScope::new(vec![format!("/{}/allowed/*", peer)]),
                operations: entity_capability::IdScope::new(vec!["snapshot".into()]),
                peers: None,
                constraints: None,
                allowances: None,
            }],
            granter: entity_capability::Granter::Single(Hash::zero()),
            grantee: Hash::zero(),
            parent: None,
            created_at: 0,
            expires_at: None,
            not_before: None,
            delegation_caveats: None,
        };
        let params_val = entity_ecf::Value::Map(vec![(
            entity_ecf::text("prefix"),
            entity_ecf::text(&attempted_prefix),
        )]);
        let mut ctx = make_handler_context("snapshot", Some(params_val), None);
        ctx.caller_capability = Some(cap);
        ctx.is_external = false;

        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
    }

    // -----------------------------------------------------------------------
    // §6.3 / §6.7 handler-level path authorization (0.8.2.20)
    //
    // `CORE-RESOURCE-EFFECTIVE-1`'s six arms are driven CROSS-IMPL against a
    // live peer by core-go's `resource_effective` oracle (6P/0F, mutation
    // M3-verified: disabling both the boundary narrowing and the handler
    // selection reddens `case_d_witness` 5P/1F). The rows below are the ones
    // that oracle does NOT reach — the wider class `CP-12a` names and its own
    // fix does not touch, where the authorizer evaluated a path STRING and the
    // handler acts on the SET that string derives.
    // -----------------------------------------------------------------------

    /// A capability granting `app/*` with `app/secret` excluded, for `tree:get`.
    fn prefix_cap_excluding_secret(peer: &str) -> entity_capability::CapabilityToken {
        entity_capability::CapabilityToken {
            grants: vec![entity_capability::GrantEntry {
                handlers: entity_capability::PathScope::new(vec![format!("/{}/system/tree", peer)]),
                resources: entity_capability::PathScope::with_exclude(
                    vec![format!("/{}/app/*", peer)],
                    vec![format!("/{}/app/secret", peer)],
                ),
                operations: entity_capability::IdScope::new(vec![
                    "get".into(),
                    "put".into(),
                    "extract".into(),
                ]),
                peers: None,
                constraints: None,
                allowances: None,
            }],
            granter: entity_capability::Granter::Single(Hash::zero()),
            grantee: Hash::zero(),
            parent: None,
            created_at: 0,
            expires_at: None,
            not_before: None,
            delegation_caveats: None,
        }
    }

    /// The local peer's own `system/peer` identity entity and its hash.
    ///
    /// Needed because `authorize_path` resolves the cap's PR-8 granter frame
    /// from `ctx.included` and **fails closed** when it cannot — and a fixture
    /// whose granter is `Hash::zero()` with an empty `included` map is exactly
    /// that case. On the wire this never arises: §5.2's `check_permission` has
    /// already resolved the same granter out of `envelope.included` and refused
    /// the dispatch if it could not, so an unresolvable granter cannot reach a
    /// handler. The fixture has to carry what the wire carries.
    fn test_peer_entity() -> (Hash, Entity) {
        let kp = entity_crypto::Keypair::from_seed([42u8; 32]);
        let ent = entity_crypto::peer_entity_from_components(&kp.public_key_bytes())
            .expect("peer entity");
        (ent.content_hash, ent)
    }

    fn external_ctx(
        operation: &str,
        params: Option<entity_ecf::Value>,
        targets: Option<Vec<String>>,
        cap: entity_capability::CapabilityToken,
    ) -> HandlerContext {
        let mut ctx = make_handler_context(operation, params, targets);
        let (granter_hash, granter_entity) = test_peer_entity();
        let mut cap = cap;
        cap.granter = entity_capability::Granter::Single(granter_hash);
        ctx.included.insert(granter_hash, granter_entity);
        ctx.caller_capability = Some(cap);
        // `authorize_path` only treats `caller_capability` as an authorization
        // input on an EXTERNAL dispatch — see its doc comment. Every row here is
        // a wire caller, which is what `CP-12a` measured.
        ctx.is_external = true;
        ctx
    }

    /// ⛔ **`CP-12a`'s wider class, measured at this line and fixed here.**
    ///
    /// The grant authorizes `app/*` and excludes `app/secret`. `tree:get` on the
    /// PARENT PREFIX `/{p}/app/` is authorized by §5.2 — the exclude does not
    /// match the prefix *string*, so the concrete arm compares one path and
    /// passes — and the unfiltered listing then returned `secret` AND ITS
    /// CONTENT HASH. `effective_targets` removes nothing: the arity is one and
    /// the caller supplied no exclude at all, so `CP-12a`'s own fix does not
    /// reach this.
    ///
    /// The NEGATIVE CONTROL is the non-obvious half and it is why the leak read
    /// as a working guard: the child's own path is still refused. A reader
    /// checking `get /{p}/app/secret` sees a correct 403 and concludes the
    /// dimension binds.
    #[tokio::test]
    async fn a_listing_omits_a_child_the_callers_grant_excludes() {
        let tree = make_tree();
        let peer = test_peer_id();
        tree.put(&qp("app/public"), make_entity("t", "public"))
            .unwrap();
        tree.put(&qp("app/secret"), make_entity("t", "secret"))
            .unwrap();
        let cap = prefix_cap_excluding_secret(&peer);

        let ctx = external_ctx("get", None, Some(vec![qp("app/")]), cap.clone());
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(
            result.status, STATUS_OK,
            "the prefix read itself is authorized"
        );

        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();
        let entries = cbor_map_get(map, "entries").as_map().unwrap();
        let names: Vec<&str> = entries.iter().filter_map(|(k, _)| k.as_text()).collect();
        assert!(names.contains(&"public"), "the in-grant child is listed");
        assert!(
            !names.contains(&"secret"),
            "§6.3: an entry whose path the caller's grant excludes MUST be omitted \
             — it was returned with its content hash"
        );
        // §6.3: "`count` MUST reflect the filtered entry count."
        let count = cbor_map_get(map, "count").as_integer().unwrap();
        assert_eq!(
            i128::from(count),
            1,
            "count is the FILTERED count, not the source total"
        );

        // NEGATIVE CONTROL — the direct read of the same child is refused, which
        // is what made the enumeration leak invisible from either side.
        let direct = external_ctx("get", None, Some(vec![qp("app/secret")]), cap.clone());
        assert_eq!(
            tree.handle(&direct).await.unwrap().status,
            STATUS_FORBIDDEN,
            "the child's OWN path must still be refused — this row passing is \
             exactly what let the listing leak read as a working guard"
        );
        // CONTROL — an in-grant direct read still works, so the 403 above is
        // attributable to the exclude and not to a deny-everything peer.
        let allowed = external_ctx("get", None, Some(vec![qp("app/public")]), cap);
        assert_eq!(tree.handle(&allowed).await.unwrap().status, STATUS_OK);
    }

    /// §6.7 is ACT-NEUTRAL (0.8.2.20): `extract` is a read that returns every
    /// binding under a prefix *with the entities themselves*, so it is a strictly
    /// wider disclosure than a listing's name+hash. Same per-entry filter.
    #[tokio::test]
    async fn an_extract_omits_a_binding_the_callers_grant_excludes() {
        let tree = make_tree();
        let peer = test_peer_id();
        tree.put(&qp("app/public"), make_entity("t", "public"))
            .unwrap();
        tree.put(&qp("app/secret"), make_entity("t", "secret"))
            .unwrap();
        let cap = prefix_cap_excluding_secret(&peer);

        let ctx = external_ctx("extract", None, Some(vec![qp("app/")]), cap);
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        // The excluded entity's bytes must not appear anywhere in the envelope.
        let secret_hash = make_entity("t", "secret").content_hash;
        let public_hash = make_entity("t", "public").content_hash;
        let body = &result.result.data;
        assert!(
            !contains_subslice(body, &secret_hash.to_bytes()),
            "§6.3/§6.7: extract disclosed the excluded binding's entity"
        );
        assert!(
            contains_subslice(body, &public_hash.to_bytes()),
            "CONTROL: the in-grant binding IS in the envelope — without this the \
             row above passes against an extract that returns nothing"
        );
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Decode a `system/tree/snapshot` result and walk its trie root back into
    /// the binding set it commits to.
    ///
    /// ⚠ The assertion has to be made on the WALKED SET, not on the response
    /// bytes. A snapshot response is `{root: <33 bytes>}` and nothing else — the
    /// excluded key and its content hash are not *in* it under either
    /// implementation, so `contains_subslice` over the body (which is what the
    /// extract row two functions up can legitimately use) is green against the
    /// leak. That is the whole reason this class needed a cross-impl drive
    /// composing two operations to surface: the disclosure is one dereference
    /// away from the response, and an assertion that stops at the response
    /// cannot see it.
    fn snapshot_bindings(tree: &TreeHandler, result: &HandlerResult) -> BTreeMap<String, Hash> {
        let val = decode_cbor(&result.result.data);
        let map = val.as_map().expect("snapshot result is a map");
        let root_bytes = cbor_map_get(map, "root").as_bytes().expect("root is bstr");
        let root = Hash::from_bytes(root_bytes).expect("root hash");
        trie::collect_all_bindings(tree.content_store.as_ref(), root, "")
    }

    /// ⛔ **The composed leak: `snapshot` under an excluding cap + the §11
    /// `diff` exemption.** (V7 §6.3, EXTENSION-TREE §11 — core-go's
    /// `exclude_matrix.snapshot_diff_no_leak`, which scored us `1F` at
    /// `74e2afb` and is the cohort's only scored FAIL that round.)
    ///
    /// `snapshot` is the third member of the enumerating-consumer family
    /// (`listing`, `extract`, `snapshot`) and was the one left unfiltered. It
    /// reads worse than the other two on the wire because the disclosure is
    /// **deferred**: the response is a single 33-byte root and discloses
    /// nothing by itself, so the caller spends it at `diff`, which §11 exempts
    /// from path checks entirely. `diff(empty_baseline, scoped_snapshot).added`
    /// then hands back `secret` **and its content hash** — with no
    /// authorization run anywhere in the composition, because `snapshot`
    /// authorized the prefix string and `diff` is exempt by construction.
    ///
    /// **A path-check EXEMPTION is a claim about the exempt operation's
    /// upstream producer.** §11 is not wrong and `handle_diff` needs no change;
    /// the exemption's premise — that a root cannot commit to what the caller
    /// may not see — is what this function has to make true.
    ///
    /// **Mutation-verified (M1, run):** dropping the
    /// `cap_scoped && !path_allowed(…)` `continue` from the collection loop puts
    /// `secret` back in the walked set — RED here and on
    /// `snapshot_under_a_scoped_cap_does_not_take_the_tracked_root_fast_path`,
    /// with `a_listing_omits_…` and `an_extract_omits_…` green, which is what
    /// says the three filters are three call sites and not one. The `public`
    /// assertion is the control that separates *"filters correctly"* from
    /// *"returns an empty trie"*, and the direct-`get` 403 is the one that
    /// separates it from *"denies this caller everything"*.
    #[tokio::test]
    async fn a_snapshot_root_omits_a_binding_the_callers_grant_excludes() {
        let tree = make_tree();
        let peer = test_peer_id();
        tree.put(&qp("app/public"), make_entity("t", "public"))
            .unwrap();
        tree.put(&qp("app/secret"), make_entity("t", "secret"))
            .unwrap();
        let cap = prefix_cap_excluding_secret(&peer);

        let ctx = external_ctx("snapshot", None, Some(vec![qp("app/")]), cap.clone());
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(
            result.status, STATUS_OK,
            "the prefix snapshot is authorized"
        );

        let committed = snapshot_bindings(&tree, &result);
        assert!(
            !committed.contains_key("secret"),
            "§6.3: the snapshot committed to a binding the caller's grant excludes \
             — `diff` against an empty snapshot returns the key and its content \
             hash through the §11 path-check exemption (committed: {:?})",
            committed.keys().collect::<Vec<_>>()
        );
        // CONTROL — without this the row above passes against a snapshot that
        // commits to nothing at all, which is the other way to be "secure".
        assert_eq!(
            committed.get("public"),
            Some(&make_entity("t", "public").content_hash),
            "CONTROL: the in-grant binding IS committed, at its real hash"
        );

        // CONTROL — the same caller reading the excluded child directly is still
        // refused. This row passing is what made the leak read as a working
        // guard: the direct read is denied and the commitment is not.
        let direct = external_ctx("get", None, Some(vec![qp("app/secret")]), cap);
        assert_eq!(tree.handle(&direct).await.unwrap().status, STATUS_FORBIDDEN);
    }

    /// ⛔ **The filter has to survive the O(1) fast path, and that is a separate
    /// claim from "the filter exists".**
    ///
    /// `handle_snapshot` short-circuits on a tracked trie root
    /// (EXTENSION-TREE §3.4) when `RootTrackerEngine` maintains one for the
    /// prefix. That root is a **peer-level** artifact built over every binding,
    /// with no caller in scope at the time it is built — so a filter placed only
    /// on the rebuild branch is skipped whenever a root happens to be tracked.
    /// The failure mode that makes this worth its own row: the same request
    /// under the same cap leaks or does not leak depending on whether a
    /// `system/tree/root/{prefix}` binding exists, and the row above — which
    /// builds no tracker — would stay green through it.
    ///
    /// Row 1 drives the fast-path-armed tree under a scoped cap and asserts the
    /// answer is the FILTERED root, not the tracked one. Row 2 is the control
    /// that keeps the bypass honest in the other direction: cap-free, the
    /// tracked root is still returned verbatim, so "bypass under a scoped cap"
    /// cannot be satisfied by deleting the fast path.
    ///
    /// **Mutation-verified, both run, and the disjointness is the result worth
    /// recording:**
    ///
    /// | mutation | this row | `a_snapshot_root_omits_…` | pre-existing `…uses_tracked_root_…` |
    /// |---|---|---|---|
    /// | M2 — `if !cap_scoped` → `if true` (fast path not bypassed) | **RED** | green | green |
    /// | M3 — `if !cap_scoped` → `if false` (fast path deleted) | **RED** | green | **RED** |
    ///
    /// M2 is the one that earns this row its existence: the plain filter row
    /// **cannot see** the fast-path skip, because it builds no tracker, so
    /// without this fixture a peer that filters the rebuild branch and
    /// short-circuits past it is green on every row in the file. M3 reddening
    /// the §3.4 row as well is the fast path's own pin, and it reddens *here*
    /// through the sentinel rather than through a root comparison.
    #[tokio::test]
    async fn snapshot_under_a_scoped_cap_does_not_take_the_tracked_root_fast_path() {
        let tree = make_tree();
        let peer = test_peer_id();
        tree.put(&qp("app/public"), make_entity("t", "public"))
            .unwrap();
        tree.put(&qp("app/secret"), make_entity("t", "secret"))
            .unwrap();

        // Arm the fast path as `RootTrackerEngine` does — the UNFILTERED root
        // over the prefix, bound at `system/tree/root/{bare_prefix}` — plus one
        // SENTINEL key that exists only inside the tracked root and has no
        // binding in the location index.
        //
        // ⚠ The sentinel is what makes row 2 a control at all, and the first
        // draft of this fixture did without it and was a **tautology**: a
        // tracked root built as the canonical trie over exactly the indexed
        // bindings is *equal to* what the rebuild branch produces, so `== root`
        // is satisfied whether the fast path fired or not. Measured — deleting
        // the fast path outright left that version GREEN and reddened only the
        // pre-existing `test_handler_snapshot_uses_tracked_root_when_present`,
        // which uses a fabricated root for this same reason. A root no rebuild
        // can produce is the only thing that observes which branch ran.
        let mut all = BTreeMap::new();
        all.insert(
            "public".to_string(),
            tree.location_index.get(&qp("app/public")).unwrap(),
        );
        all.insert(
            "secret".to_string(),
            tree.location_index.get(&qp("app/secret")).unwrap(),
        );
        all.insert(
            "tracked-sentinel".to_string(),
            make_entity("t", "sentinel").content_hash,
        );
        let tracked_root = trie::build_trie(tree.content_store.as_ref(), &all).unwrap();
        tree.location_index
            .set(&qp("system/tree/root/app"), tracked_root);
        // The fixture is only meaningful if the fast path would actually fire.
        assert_eq!(
            tree.lookup_tracked_root(&qp("app/")),
            Some(tracked_root),
            "fixture: the tracked root must be reachable, or row 1 passes vacuously"
        );

        // Row 1 — scoped cap: the tracked root is bypassed and the answer is the
        // re-rooted, filtered trie.
        let cap = prefix_cap_excluding_secret(&peer);
        let ctx = external_ctx("snapshot", None, Some(vec![qp("app/")]), cap);
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        let committed = snapshot_bindings(&tree, &result);
        assert!(
            !committed.contains_key("tracked-sentinel"),
            "the tracked-root fast path FIRED under a scoped cap — it returns a \
             root over bindings nothing filtered (committed: {:?})",
            committed.keys().collect::<Vec<_>>()
        );
        assert!(
            !committed.contains_key("secret"),
            "the excluded binding is committed to — the filter on the rebuild \
             branch was skipped through the fast path"
        );
        assert!(committed.contains_key("public"), "CONTROL: still re-rooted");

        // Row 2 — CONTROL, cap-free (a peer-root dispatch): the O(1) fast path
        // is still taken, so the bypass is scoped to the case that needs it and
        // not a deletion of §3.4.
        let internal = make_handler_context("snapshot", None, Some(vec![qp("app/")]));
        // Stated rather than implied by an absent line: this fixture's claim is
        // that the dispatch is the kind on which the filter decides nothing.
        assert!(!TreeHandler::cap_filter_active(&internal));
        let result = tree.handle(&internal).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        let val = decode_cbor(&result.result.data);
        let root_bytes = cbor_map_get(val.as_map().unwrap(), "root")
            .as_bytes()
            .unwrap();
        assert_eq!(
            Hash::from_bytes(root_bytes).unwrap(),
            tracked_root,
            "CONTROL: cap-free, EXTENSION-TREE §3.4's tracked root is returned \
             verbatim — the bypass must not have deleted the fast path"
        );
        assert!(
            snapshot_bindings(&tree, &result).contains_key("tracked-sentinel"),
            "CONTROL: and the answer is the TRACKED root specifically — the \
             sentinel has no binding in the index, so no rebuild can mint it"
        );
    }

    /// ⛔ **`EXTENSION-TREE` §11: the path-level check is asked about the MAPPED
    /// base permission (`get`), never about the extension operation name.**
    ///
    /// The discriminating grant is the one where the two disagree:
    /// `operations: {include: ["*"], exclude: ["get"]}`. The **dispatch** check
    /// asks about the literal name and allows — `extract` is not `get`, which is
    /// §11 item 1 working as written. The **path** check must then ask about
    /// `get` and refuse. Handed `"extract"` instead it agreed with the dispatch
    /// check, so §6.3 answered a question nobody asked and `handle_extract`
    /// returned an envelope of every bound entity under the prefix. `snapshot`
    /// is the same row with a trie root in place of the entities.
    ///
    /// Note which way a mis-mapping fails and why no green suite could see it:
    /// every ordinary cap lists `get` alongside `extract` (§11's own example
    /// does), and for those two the mapped and unmapped questions have the same
    /// answer. Only a cap that grants the operation while withholding the base
    /// permission separates them.
    ///
    /// **Mutation-verified**, both directions, both sites: restoring
    /// `authorize_path(ctx, "extract", …)` / `(ctx, "snapshot", …)` turns rows 1
    /// and 2 from `403` to `200` — RED — and leaves the control green, because
    /// the control's cap satisfies both readings. The control is the half that
    /// matters here: "asks about `get`" and "denies everything" are one edit
    /// apart, and only the control tells them apart.
    #[tokio::test]
    async fn extract_and_snapshot_authorize_the_mapped_get_not_the_operation_name() {
        let peer = test_peer_id();
        let grant_without_get =
            |ops: entity_capability::IdScope| entity_capability::CapabilityToken {
                grants: vec![entity_capability::GrantEntry {
                    handlers: entity_capability::PathScope::new(vec![format!(
                        "/{}/system/tree",
                        peer
                    )]),
                    resources: entity_capability::PathScope::new(vec![format!("/{}/app/*", peer)]),
                    operations: ops,
                    peers: None,
                    constraints: None,
                    allowances: None,
                }],
                granter: entity_capability::Granter::Single(Hash::zero()),
                grantee: Hash::zero(),
                parent: None,
                created_at: 0,
                expires_at: None,
                not_before: None,
                delegation_caveats: None,
            };

        // The cap that separates the two readings: every operation EXCEPT the
        // base permission the §11 table maps `extract`/`snapshot` onto.
        let all_but_get = entity_capability::IdScope::with_exclude(
            vec!["*".to_string()],
            vec!["get".to_string()],
        );

        // Row 1 — extract.
        let tree = make_tree();
        tree.put(&qp("app/public"), make_entity("t", "public"))
            .unwrap();
        let ctx = external_ctx(
            "extract",
            None,
            Some(vec![qp("app/")]),
            grant_without_get(all_but_get.clone()),
        );
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(
            result.status, STATUS_FORBIDDEN,
            "§11 map_operation: extract → get, and this grant excludes get"
        );

        // Row 2 — snapshot, same grant, same mapping row.
        let ctx = external_ctx(
            "snapshot",
            None,
            Some(vec![qp("app/")]),
            grant_without_get(all_but_get),
        );
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(
            result.status, STATUS_FORBIDDEN,
            "§11 map_operation: snapshot → get, and this grant excludes get"
        );

        // CONTROL — the ordinary shape §11's own example grant uses. Both
        // readings allow it, so a "deny extract outright" mutation reddens here
        // and nowhere else.
        let ctx = external_ctx(
            "extract",
            None,
            Some(vec![qp("app/")]),
            grant_without_get(entity_capability::IdScope::new(vec![
                "get".to_string(),
                "snapshot".to_string(),
                "extract".to_string(),
            ])),
        );
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(
            result.status, STATUS_OK,
            "CONTROL: a cap listing get alongside extract still extracts"
        );
        let public_hash = make_entity("t", "public").content_hash;
        assert!(
            contains_subslice(&result.result.data, &public_hash.to_bytes()),
            "CONTROL: the in-grant binding IS in the envelope"
        );
    }

    /// The §11 mapping binds the **per-entry** extract filter as well as the
    /// prefix check, and that site needs its own row — *"the feature is mapped"*
    /// and *"this call site is mapped"* are different claims, and a mutation
    /// only measures the second.
    ///
    /// The shape that separates them is two grants whose dimensions cross, which
    /// is also §5.2's *all dimensions from ONE grant entry* rule:
    ///
    /// | grant | resources | operations |
    /// |---|---|---|
    /// | G1 | `/{p}/app/` — the prefix string, EXACT | `get` |
    /// | G2 | `/{p}/app/*` — the children | `extract`, no `get` |
    ///
    /// The prefix check (`get` on `/{p}/app/`) is satisfied by G1, so the
    /// request is not refused and the filter is actually reached. Each child
    /// then needs `get` on `/{p}/app/{name}`, which G1's exact include does not
    /// cover and G2's operations do not grant — so nothing is extractable.
    /// Ask the filter about `"extract"` instead and G2 answers yes, and the
    /// envelope ships the entity.
    ///
    /// **Mutation-verified:** `path_allowed(ctx, "extract", …)` on the
    /// `bindings.retain` line turns the first assertion RED (the entity appears)
    /// while the prefix-level rows above stay green.
    #[tokio::test]
    async fn the_per_entry_extract_filter_asks_about_get_too() {
        let tree = make_tree();
        let peer = test_peer_id();
        tree.put(&qp("app/public"), make_entity("t", "public"))
            .unwrap();
        let cap = entity_capability::CapabilityToken {
            grants: vec![
                entity_capability::GrantEntry {
                    handlers: entity_capability::PathScope::new(vec![format!(
                        "/{}/system/tree",
                        peer
                    )]),
                    resources: entity_capability::PathScope::new(vec![format!("/{}/app/", peer)]),
                    operations: entity_capability::IdScope::new(vec!["get".into()]),
                    peers: None,
                    constraints: None,
                    allowances: None,
                },
                entity_capability::GrantEntry {
                    handlers: entity_capability::PathScope::new(vec![format!(
                        "/{}/system/tree",
                        peer
                    )]),
                    resources: entity_capability::PathScope::new(vec![format!("/{}/app/*", peer)]),
                    operations: entity_capability::IdScope::new(vec!["extract".into()]),
                    peers: None,
                    constraints: None,
                    allowances: None,
                },
            ],
            granter: entity_capability::Granter::Single(Hash::zero()),
            grantee: Hash::zero(),
            parent: None,
            created_at: 0,
            expires_at: None,
            not_before: None,
            delegation_caveats: None,
        };

        let ctx = external_ctx("extract", None, Some(vec![qp("app/")]), cap);
        let result = tree.handle(&ctx).await.unwrap();
        // Reached the filter, not refused at the prefix — that is what G1 is for.
        assert_eq!(result.status, STATUS_OK);
        let public_hash = make_entity("t", "public").content_hash;
        assert!(
            !contains_subslice(&result.result.data, &public_hash.to_bytes()),
            "§11: the per-entry filter asks about `get`, which no single grant \
             here answers for a child path"
        );
    }

    /// `EXTENSION-TREE` §11 + §12.1: *"Merge requires `put` authorization on
    /// every path it writes. The handler MUST verify authorization before
    /// applying any writes."* — and §12.1 makes the failure ATOMIC.
    ///
    /// `handle_merge` carried zero authorization symbols: it reads no resource
    /// target at all, its write prefix comes from `params.target_prefix`, so the
    /// dispatch-level check never saw a single one of these paths.
    #[tokio::test]
    async fn a_merge_touching_one_forbidden_path_writes_nothing_at_all() {
        let tree = make_tree();
        let peer = test_peer_id();
        // Source: two bindings, which will land at app/public and app/secret.
        tree.put(&qp("src/public"), make_entity("t", "p")).unwrap();
        tree.put(&qp("src/secret"), make_entity("t", "s")).unwrap();
        let snap_ctx = make_handler_context("snapshot", None, Some(vec![qp("src/")]));
        let snap = tree.handle(&snap_ctx).await.unwrap();
        let snap_hash = tree.content_store.put(snap.result).unwrap();

        let params = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("source"),
                entity_ecf::Value::Bytes(snap_hash.to_bytes().to_vec()),
            ),
            (entity_ecf::text("source_prefix"), entity_ecf::text("src/")),
            (entity_ecf::text("target_prefix"), entity_ecf::text("app/")),
        ]);
        let ctx = external_ctx(
            "merge",
            Some(params),
            None,
            prefix_cap_excluding_secret(&peer),
        );
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(
            result.status, STATUS_FORBIDDEN,
            "§11: merge MUST verify authorization before applying any writes"
        );
        // §12.1 ATOMIC — the AUTHORIZED sibling must not have landed either.
        // This is the assertion a per-path check inside the apply loop fails:
        // it would write `app/public`, then refuse at `app/secret`, and report a
        // 403 over a half-applied tree.
        assert!(
            !tree.has(&qp("app/public")),
            "§12.1: a refused merge is atomic — the in-grant sibling must not be written"
        );
        assert!(!tree.has(&qp("app/secret")));
    }

    /// CONTROL for the row above: the same merge with every target in grant
    /// applies. Without this, refusing every merge scores identically.
    #[tokio::test]
    async fn a_fully_in_grant_merge_still_applies() {
        let tree = make_tree();
        let peer = test_peer_id();
        tree.put(&qp("src/public"), make_entity("t", "p")).unwrap();
        let snap_ctx = make_handler_context("snapshot", None, Some(vec![qp("src/")]));
        let snap = tree.handle(&snap_ctx).await.unwrap();
        let snap_hash = tree.content_store.put(snap.result).unwrap();

        let params = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("source"),
                entity_ecf::Value::Bytes(snap_hash.to_bytes().to_vec()),
            ),
            (entity_ecf::text("source_prefix"), entity_ecf::text("src/")),
            (entity_ecf::text("target_prefix"), entity_ecf::text("app/")),
        ]);
        let ctx = external_ctx(
            "merge",
            Some(params),
            None,
            prefix_cap_excluding_secret(&peer),
        );
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert!(tree.has(&qp("app/public")));
    }

    /// §5.2's subject rule at the `put` half — the WRITE form of `F68`/`CP-12a`,
    /// and the most expensive instance of it.
    ///
    /// `targets:[P] exclude:[P]` makes the dispatch-level resource check vacuous
    /// (it skips the target, correctly — a caller that excludes a target is not
    /// asking for it), and `handle_put` used to bind `targets[0]` anyway. The
    /// effective list is empty, which §3.3 says IS the absent case.
    #[tokio::test]
    async fn a_self_excluded_put_target_is_the_absent_case_and_binds_nothing() {
        let tree = make_tree();
        let peer = test_peer_id();
        let body = make_entity("t", "payload");
        let params = put_params_with_expected(Some(&body), None);
        let mut ctx = external_ctx(
            "put",
            Some(params),
            Some(vec![qp("app/secret")]),
            prefix_cap_excluding_secret(&peer),
        );
        // The boundary narrowing is what a wire request gets; here the handler's
        // own `effective_targets` call is the one under test, so the raw target
        // plus its self-exclusion is passed through deliberately.
        if let Some(rt) = ctx.resource_target.as_mut() {
            rt.exclude = vec![qp("app/secret")];
        }
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_BAD_REQUEST);
        assert_eq!(error_code(&result), "path_required");
        assert!(
            !tree.has(&qp("app/secret")),
            "nothing may be bound at a path the authorizer never evaluated"
        );
    }

    /// ⛔ **N6 — THE TWO EMPTIES ARE NOT THE SAME REQUEST `[MUST]`** (§3.3 +
    /// `EXTENSION-TREE` §4.10, 0.8.2.24), across all three of this handler's
    /// resource-optional operations.
    ///
    /// The row above pins the **resource-REQUIRING** half (`put`), where §3.3's
    /// *"an empty effective list IS the absent case"* is untouched and both
    /// empties answer `path_required`. This is the other half, and it is where
    /// that same sentence, read unqualified, did damage: `get` does not require
    /// a resource, its absent case is a **listing**, and so
    /// `targets:[qA] exclude:[qA]` — a request for exactly one path, which the
    /// caller then excluded — was answered with **a listing of the tree**. The
    /// caller named a target; the exclusion removed it; answering the wider
    /// thing is §5.2's subject rule (*a handler MUST NOT widen the set*) reached
    /// through the front door.
    ///
    /// **Rows collected, not asserted inline**, because they fail in opposite
    /// directions: the refusal rows fail if the split is missing, and the
    /// control rows fail if the split swallowed the absent case too. An inline
    /// first row short-circuits and reports nothing about the second.
    ///
    /// **Mutations RUN, and which rows reddened is the record — all three at
    /// the one derivation point in `entity_handler::single_effective_target`,
    /// because that is the site the rule lives at and mutating a caller would
    /// make a per-site claim this test does not support:**
    /// - **restore the collapse** (`SelfExcluded` → the absent arm) → the three
    ///   refusal rows redden as `200`: `get` → `system/tree/listing`,
    ///   `snapshot` → `system/tree/snapshot`, `extract` → `system/envelope`.
    ///   The three controls stay **green**, and that green is the point — an
    ///   implementation that refuses *every* empty scores identically to a
    ///   correct one on the refusal rows alone, and the root listing is not an
    ///   edge case, it is how a peer is browsed.
    /// - **invert it** (`Absent` → refuse) → the three controls redden with
    ///   `400 path_required` and the three refusal rows stay green — disjoint
    ///   from the first, which is what separates *split the empties* from
    ///   *refuse more*. It additionally reddens
    ///   `a_resource_naming_no_targets_is_the_absent_case` and the untouched
    ///   neighbour `test_handler_snapshot_full_tree`, which is worth recording:
    ///   the absent case is load-bearing well beyond the rows written for it.
    /// - **key `SelfExcluded` on `resource_target.is_some()`** instead of on the
    ///   raw target list → **nothing in THIS row reddens.** That is not a
    ///   toothless test, it is the wrong observer: the state only differs for a
    ///   resource present with `targets: []`, which no fixture here builds. The
    ///   row that observes it is
    ///   `a_resource_naming_no_targets_is_the_absent_case`, which reddens alone.
    ///   Recorded here so the next reader does not re-derive this greenness as a
    ///   defect.
    #[tokio::test]
    async fn the_two_empties_split_on_every_resource_optional_tree_op() {
        let peer = test_peer_id();
        let mut failures: Vec<String> = Vec::new();

        for op in ["get", "snapshot", "extract"] {
            // --- the discriminator: a resource that NAMED a target and excluded it
            let tree = make_tree();
            tree.put(&qp("app/a"), make_entity("t", "a")).unwrap();
            tree.put(&qp("app/b"), make_entity("t", "b")).unwrap();
            let mut ctx = make_handler_context(op, None, Some(vec![qp("app/a")]));
            if let Some(rt) = ctx.resource_target.as_mut() {
                rt.exclude = vec![qp("app/a")];
            }
            // The suffix is what makes `get`'s pre-fix answer the DISCLOSURE
            // rather than a miss, and the fixture has to carry it or the row
            // measures something milder than the defect. Without it the
            // collapsed form fell through to `pattern` — a point read at
            // `/{p}/system/tree` — and answered `404 not_found`, which reddens
            // the row and understates it by a lot. With it the fall-through is
            // `/{p}/system/tree/`, §4.10's listing arm, and the mutation shows
            // the actual harm: a request for ONE excluded path answered with an
            // enumeration. (Measured both ways; this is the first run's finding.)
            ctx.suffix = "/".to_string();
            let result = tree.handle(&ctx).await.unwrap();
            // `error_code` panics on a non-error body, and the whole point of
            // the mutation is that this row comes back a 200 — so the row must
            // report the answer it got, not die inside a helper on the way.
            let code = describe_outcome(&result);
            if result.status != STATUS_BAD_REQUEST || code != "path_required" {
                failures.push(format!(
                    "{op}: a self-excluded resource must be 400 path_required, got {} {code}",
                    result.status,
                ));
            }

            // --- the control: a GENUINELY absent resource still takes the
            // operation's own absent-case behaviour. `get` falls through to the
            // URI-suffix form — `entity://{p}/system/tree/`, §4.10's
            // "path ending with `/` → listing"; `snapshot`/`extract` fall back
            // to `params.prefix`, absent here, so they cover the whole tree.
            // All three answer 200.
            let mut ctx = make_handler_context(op, None, None);
            ctx.suffix = "/".to_string();
            let result = tree.handle(&ctx).await.unwrap();
            if result.status != STATUS_OK {
                failures.push(format!(
                    "{op}: an ABSENT resource must still take the absent-case behaviour, got {} {}",
                    result.status,
                    describe_outcome(&result)
                ));
            }
        }

        // `get`'s absent case specifically, because it is the one the collapse
        // turned into a disclosure: assert it is the LISTING, not merely a 200.
        let tree = make_tree();
        tree.put(&qp("app/a"), make_entity("t", "a")).unwrap();
        let mut listing_ctx = make_handler_context("get", None, None);
        listing_ctx.suffix = "/".to_string();
        let listing = tree.handle(&listing_ctx).await.unwrap();
        if listing.result.entity_type != entity_types::TYPE_TREE_LISTING {
            failures.push(format!(
                "get: the absent case is §4.10's root listing, got {}",
                listing.result.entity_type
            ));
        }

        let _ = peer;
        assert!(
            failures.is_empty(),
            "N6 rows failed:\n{}",
            failures.join("\n")
        );
    }

    /// The third state the wire cannot carry, pinned so the choice is measured
    /// rather than inherited from a decoder.
    ///
    /// `SelfExcluded` is keyed on the **raw target list**, not on
    /// `resource_target.is_some()`. A `resource` present with `targets: []`
    /// named nothing, so it is the ABSENT case — the same already-ratified rule
    /// that makes an optional array's absent and empty one fact.
    /// `connection::extract_resource_target` enforces that at the wire boundary
    /// by returning `None` for an empty target list, so this state is
    /// unreachable from outside; it IS reachable in-process, and keying on the
    /// list rather than on the `Option` is what makes the two seams agree
    /// instead of one depending on the other's choice.
    ///
    /// **Mutation RUN:** key on `resource_target.is_some()` → this row reddens
    /// (400 `path_required` where a 200 listing is owed) and every row of
    /// `the_two_empties_split_on_every_resource_optional_tree_op` stays green.
    #[tokio::test]
    async fn a_resource_naming_no_targets_is_the_absent_case() {
        let tree = make_tree();
        tree.put(&qp("app/a"), make_entity("t", "a")).unwrap();
        let mut ctx = make_handler_context("get", None, Some(vec![]));
        ctx.suffix = "/".to_string();
        // `make_handler_context` builds `Some(rt)` from `Some(vec![])`, which is
        // exactly the shape under test: present, naming nothing.
        assert!(
            ctx.resource_target.is_some(),
            "fixture must carry a PRESENT resource, or this row measures nothing"
        );
        if let Some(rt) = ctx.resource_target.as_mut() {
            rt.exclude = vec![qp("app/a")];
        }
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(
            result.status, STATUS_OK,
            "a resource naming no targets is the absent case, not a self-exclusion"
        );
        assert_eq!(result.result.entity_type, entity_types::TYPE_TREE_LISTING);
    }

    /// §3.3's arity arm on `get`, which this handler answered by silently using
    /// the first of two targets.
    #[tokio::test]
    async fn two_effective_get_targets_are_ambiguous_resource() {
        let tree = make_tree();
        tree.put(&qp("app/a"), make_entity("t", "a")).unwrap();
        tree.put(&qp("app/b"), make_entity("t", "b")).unwrap();
        let ctx = make_handler_context("get", None, Some(vec![qp("app/a"), qp("app/b")]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_BAD_REQUEST);
        assert_eq!(error_code(&result), "ambiguous_resource");
    }

    #[tokio::test]
    async fn test_handler_snapshot_determinism() {
        let tree = make_tree();
        tree.put(&qp("data/x"), make_entity("test", "x")).unwrap();
        tree.put(&qp("data/y"), make_entity("test", "y")).unwrap();

        let ctx1 = make_handler_context("snapshot", None, Some(vec![qp("data/")]));
        let r1 = tree.handle(&ctx1).await.unwrap();

        let ctx2 = make_handler_context("snapshot", None, Some(vec![qp("data/")]));
        let r2 = tree.handle(&ctx2).await.unwrap();

        assert_eq!(r1.result.content_hash, r2.result.content_hash);
    }

    #[tokio::test]
    async fn test_handler_snapshot_full_tree() {
        let tree = make_tree();
        tree.put(&qp("a"), make_entity("test", "a")).unwrap();
        tree.put(&qp("b"), make_entity("test", "b")).unwrap();

        // Empty prefix = full tree
        let params =
            entity_ecf::Value::Map(vec![(entity_ecf::text("prefix"), entity_ecf::text(""))]);
        let ctx = make_handler_context("snapshot", Some(params), None);
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();
        let root_bytes = cbor_map_get(map, "root").as_bytes().unwrap();
        assert_eq!(root_bytes.len(), 33, "root should be a 33-byte hash");
        let root_hash = Hash::from_bytes(root_bytes).unwrap();
        let bindings = trie::collect_all_bindings(tree.content_store.as_ref(), root_hash, "");
        assert_eq!(bindings.len(), 2);
    }

    // -----------------------------------------------------------------------
    // DIFF operation tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_handler_diff_added_removed_changed() {
        let tree = make_tree();

        // Create base snapshot: a, b, c
        tree.put(&qp("data/a"), make_entity("test", "a1")).unwrap();
        tree.put(&qp("data/b"), make_entity("test", "b1")).unwrap();
        tree.put(&qp("data/c"), make_entity("test", "c1")).unwrap();

        let snap1_ctx = make_handler_context("snapshot", None, Some(vec![qp("data/")]));
        let snap1 = tree.handle(&snap1_ctx).await.unwrap();
        // Store snapshot in content store
        let snap1_hash = tree.content_store.put(snap1.result.clone()).unwrap();

        // Modify tree: remove b, change c, add d
        tree.remove(&qp("data/b"));
        tree.put(&qp("data/c"), make_entity("test", "c2")).unwrap();
        tree.put(&qp("data/d"), make_entity("test", "d1")).unwrap();

        let snap2_ctx = make_handler_context("snapshot", None, Some(vec![qp("data/")]));
        let snap2 = tree.handle(&snap2_ctx).await.unwrap();
        let snap2_hash = tree.content_store.put(snap2.result.clone()).unwrap();

        // Diff
        let params = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("base"),
                entity_ecf::Value::Bytes(snap1_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("target"),
                entity_ecf::Value::Bytes(snap2_hash.to_bytes().to_vec()),
            ),
        ]);
        let diff_ctx = make_handler_context("diff", Some(params), None);
        let diff_result = tree.handle(&diff_ctx).await.unwrap();
        assert_eq!(diff_result.status, STATUS_OK);
        assert_eq!(diff_result.result.entity_type, entity_types::TYPE_TREE_DIFF);

        let val = decode_cbor(&diff_result.result.data);
        let map = val.as_map().unwrap();

        let added = cbor_map_get(map, "added").as_map().unwrap();
        assert_eq!(added.len(), 1); // d
        assert!(added.iter().any(|(k, _)| k.as_text() == Some("d")));

        let removed = cbor_map_get(map, "removed").as_map().unwrap();
        assert_eq!(removed.len(), 1); // b
        assert!(removed.iter().any(|(k, _)| k.as_text() == Some("b")));

        let changed = cbor_map_get(map, "changed").as_map().unwrap();
        assert_eq!(changed.len(), 1); // c
        assert!(changed.iter().any(|(k, _)| k.as_text() == Some("c")));

        let unchanged = cbor_map_get(map, "unchanged").as_integer().unwrap();
        assert_eq!(i128::from(unchanged), 1); // a
    }

    #[tokio::test]
    async fn test_handler_diff_snapshot_not_found() {
        let tree = make_tree();
        let fake_hash = Hash::compute("fake", &[1, 2, 3]);
        let params = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("base"),
                entity_ecf::Value::Bytes(fake_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("target"),
                entity_ecf::Value::Bytes(fake_hash.to_bytes().to_vec()),
            ),
        ]);
        let ctx = make_handler_context("diff", Some(params), None);
        let result = tree.handle(&ctx).await;
        let result = result.unwrap();
        assert_eq!(result.status, STATUS_NOT_FOUND);
    }

    // -----------------------------------------------------------------------
    // MERGE operation tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_handler_merge_new_paths() {
        let tree = make_tree();

        // Create source snapshot with entries
        tree.put(&qp("src/a"), make_entity("test", "a")).unwrap();
        tree.put(&qp("src/b"), make_entity("test", "b")).unwrap();

        let snap_ctx = make_handler_context("snapshot", None, Some(vec![qp("src/")]));
        let snap = tree.handle(&snap_ctx).await.unwrap();
        let snap_hash = tree.content_store.put(snap.result).unwrap();

        // Merge into empty target (no prefix remap)
        let params = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("source"),
                entity_ecf::Value::Bytes(snap_hash.to_bytes().to_vec()),
            ),
            (entity_ecf::text("source_prefix"), entity_ecf::text("src/")),
            (entity_ecf::text("target_prefix"), entity_ecf::text("dest/")),
        ]);

        let ctx = make_handler_context("merge", Some(params), None);
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();

        let applied = cbor_map_get(map, "applied").as_integer().unwrap();
        assert_eq!(i128::from(applied), 2);

        let skipped = cbor_map_get(map, "skipped").as_integer().unwrap();
        assert_eq!(i128::from(skipped), 0);

        // Verify paths were written
        assert!(tree.has(&qp("dest/a")));
        assert!(tree.has(&qp("dest/b")));
    }

    #[tokio::test]
    async fn test_handler_merge_no_overwrite_conflict() {
        let tree = make_tree();

        // Pre-existing entry
        tree.put(&qp("data/x"), make_entity("test", "existing"))
            .unwrap();

        // Source snapshot with conflicting entry
        tree.put(&qp("snap/x"), make_entity("test", "incoming"))
            .unwrap();
        let snap_ctx = make_handler_context("snapshot", None, Some(vec![qp("snap/")]));
        let snap = tree.handle(&snap_ctx).await.unwrap();
        let snap_hash = tree.content_store.put(snap.result).unwrap();

        let params = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("source"),
                entity_ecf::Value::Bytes(snap_hash.to_bytes().to_vec()),
            ),
            (entity_ecf::text("source_prefix"), entity_ecf::text("snap/")),
            (entity_ecf::text("target_prefix"), entity_ecf::text("data/")),
            (
                entity_ecf::text("strategy"),
                entity_ecf::text("no-overwrite"),
            ),
        ]);

        let ctx = make_handler_context("merge", Some(params), None);
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();

        let conflicts = cbor_map_get(map, "conflicts").as_map().unwrap();
        assert_eq!(conflicts.len(), 1);

        // Existing value should not be overwritten
        let existing = tree.get(&qp("data/x")).unwrap();
        assert_eq!(existing, make_entity("test", "existing"));
    }

    #[tokio::test]
    async fn test_handler_merge_source_wins() {
        let tree = make_tree();
        let existing = make_entity("test", "existing");
        let incoming = make_entity("test", "incoming");
        tree.put(&qp("data/x"), existing).unwrap();

        tree.put(&qp("snap/x"), incoming.clone()).unwrap();
        let snap_ctx = make_handler_context("snapshot", None, Some(vec![qp("snap/")]));
        let snap = tree.handle(&snap_ctx).await.unwrap();
        let snap_hash = tree.content_store.put(snap.result).unwrap();

        let params = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("source"),
                entity_ecf::Value::Bytes(snap_hash.to_bytes().to_vec()),
            ),
            (entity_ecf::text("source_prefix"), entity_ecf::text("snap/")),
            (entity_ecf::text("target_prefix"), entity_ecf::text("data/")),
            (
                entity_ecf::text("strategy"),
                entity_ecf::text("source-wins"),
            ),
        ]);

        let ctx = make_handler_context("merge", Some(params), None);
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();

        let applied = cbor_map_get(map, "applied").as_integer().unwrap();
        assert_eq!(i128::from(applied), 1);

        // Source should win
        let stored = tree.get(&qp("data/x")).unwrap();
        assert_eq!(stored.content_hash, incoming.content_hash);

        let conflicts = cbor_map_get(map, "conflicts").as_map().unwrap();
        assert_eq!(conflicts.len(), 1);
        // The conflict key is the qualified target path, as the merge writes it.
        let conflict = cbor_map_get(conflicts, &qp("data/x")).as_map().unwrap();
        let resolution = cbor_map_get(conflict, "resolution").as_text().unwrap();
        assert_eq!(resolution, "used-incoming");
    }

    #[tokio::test]
    async fn test_handler_merge_target_wins() {
        let tree = make_tree();
        let existing = make_entity("test", "existing");
        tree.put(&qp("data/x"), existing.clone()).unwrap();

        tree.put(&qp("snap/x"), make_entity("test", "incoming"))
            .unwrap();
        let snap_ctx = make_handler_context("snapshot", None, Some(vec![qp("snap/")]));
        let snap = tree.handle(&snap_ctx).await.unwrap();
        let snap_hash = tree.content_store.put(snap.result).unwrap();

        let params = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("source"),
                entity_ecf::Value::Bytes(snap_hash.to_bytes().to_vec()),
            ),
            (entity_ecf::text("source_prefix"), entity_ecf::text("snap/")),
            (entity_ecf::text("target_prefix"), entity_ecf::text("data/")),
            (
                entity_ecf::text("strategy"),
                entity_ecf::text("target-wins"),
            ),
        ]);

        let ctx = make_handler_context("merge", Some(params), None);
        let result = tree.handle(&ctx).await.unwrap();

        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();

        let skipped = cbor_map_get(map, "skipped").as_integer().unwrap();
        assert_eq!(i128::from(skipped), 1);

        // Existing should remain
        let stored = tree.get(&qp("data/x")).unwrap();
        assert_eq!(stored.content_hash, existing.content_hash);
    }

    #[tokio::test]
    async fn test_handler_merge_dry_run() {
        let tree = make_tree();

        tree.put(&qp("src/a"), make_entity("test", "a")).unwrap();
        let snap_ctx = make_handler_context("snapshot", None, Some(vec![qp("src/")]));
        let snap = tree.handle(&snap_ctx).await.unwrap();
        let snap_hash = tree.content_store.put(snap.result).unwrap();

        let params = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("source"),
                entity_ecf::Value::Bytes(snap_hash.to_bytes().to_vec()),
            ),
            (entity_ecf::text("source_prefix"), entity_ecf::text("src/")),
            (entity_ecf::text("target_prefix"), entity_ecf::text("dest/")),
            (entity_ecf::text("dry_run"), entity_ecf::bool_val(true)),
        ]);

        let ctx = make_handler_context("merge", Some(params), None);
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();

        let applied = cbor_map_get(map, "applied").as_integer().unwrap();
        assert_eq!(i128::from(applied), 1);

        // But no actual write
        assert!(!tree.has(&qp("dest/a")));
    }

    // -----------------------------------------------------------------------
    // §5.4 byte fidelity across extract → merge
    // -----------------------------------------------------------------------

    /// An entity whose `data` is valid CBOR that **no ECF encoder emits**:
    /// `{"v": 1}` with the `1` written non-minimally (`0x18 0x01`). It is
    /// self-consistent — `content_hash` is computed over these exact bytes —
    /// so §1.8 item-1 validation passes and `ContentStore::put` keys it at the
    /// recomputed hash, which for this entity is the same one.
    ///
    /// ⛔ **This fixture is the whole test.** The transform under scrutiny —
    /// decode `data` into a `Value`, write it back with `to_ecf` /
    /// `ciborium::into_writer` — is the **identity** on every value our own
    /// codec authors, so a fixture built the usual way (`make_entity`, which
    /// goes through `to_ecf`) passes under both the broken and the fixed
    /// implementation and measures nothing. Same rule as
    /// `set_resolver_config_stores_the_submitted_bytes…`, one level down: there
    /// the fixture needed a **field** the codec cannot emit, here it needs
    /// **bytes** it cannot emit. Measured against ciborium 0.2.2: non-minimal
    /// uint, non-minimal bstr/tstr length, and indefinite-length text / array /
    /// map all change under the round trip; `to_ecf` additionally sorts map
    /// keys and drops tags.
    fn noncanonical_entity() -> Entity {
        Entity::new("test/noncanon", vec![0xa1, 0x61, 0x76, 0x18, 0x01]).unwrap()
    }

    /// Wrap an extract result as `source_envelope` and build merge params —
    /// **splicing the envelope's raw bytes**, the way both SDK producers
    /// (`follow::bootstrap_merge_params`, `reconcile::build_tree_merge_params`)
    /// and the continuation's `result_field` injection now do.
    fn merge_params_raw(envelope: &Entity, source_prefix: &str, target_prefix: &str) -> Vec<u8> {
        let wrapper = entity_wire::cbor_map_set_raw(
            &entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                entity_ecf::text("type"),
                entity_ecf::text(&envelope.entity_type),
            )])),
            "data",
            &envelope.data,
        )
        .unwrap();
        entity_wire::cbor_map_set_raw(
            &entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
                (
                    entity_ecf::text("source_prefix"),
                    entity_ecf::text(source_prefix),
                ),
                (
                    entity_ecf::text("target_prefix"),
                    entity_ecf::text(target_prefix),
                ),
            ])),
            "source_envelope",
            &wrapper,
        )
        .unwrap()
    }

    /// A `HandlerContext` whose `params.data` is exactly the bytes given — no
    /// `to_ecf` pass, so a deliberately non-canonical byte sequence reaches the
    /// handler the way the wire delivers it. `make_handler_context` cannot be
    /// used for these rows: it re-encodes the params `Value`, which is itself
    /// one of the transforms under test.
    fn make_handler_context_raw_params(operation: &str, params_data: Vec<u8>) -> HandlerContext {
        let mut ctx = make_handler_context(operation, None, None);
        ctx.params =
            Entity::new(&format!("system/tree/{}-params", operation), params_data).unwrap();
        ctx
    }

    /// Put an entity, `extract` it, `merge` the envelope into a peer that has
    /// **never seen it**, and check the merged path resolves to content.
    ///
    /// Both halves of that sentence are load-bearing and each is, on its own,
    /// enough to make the row blind — which is why core-go's
    /// `roundtrip_verify_entity` scored us PASS through the whole defect:
    ///
    /// 1. **Its fixture is ECF-canonical** (`ecf.Encode` in `put_entity`), so
    ///    the re-encode is the identity.
    /// 2. **Its round trip is same-peer** — `system/validate/tree-ops/` to
    ///    `…/tree-ops-mirror/` on one peer — so the target already holds every
    ///    entity from the original `put`, and the binding resolves whether or
    ///    not the envelope ingest did anything at all.
    ///
    /// Measured here: driving the same fixture into a target that **shares**
    /// the source's store passed against the pre-fix code, i.e. fixing only (1)
    /// would not have reddened it. Both axes have to move.
    ///
    /// **Mutations RUN** (not predicted — the first prediction about which row
    /// each would redden was wrong once already):
    /// - *M1, re-encode on the receive side* (`ingest_source_envelope` rebuilds
    ///   `data` through `ciborium::into_writer`): **this row reddens**,
    ///   `a_miskeyed_source_envelope_is_refused…` stays **green** — M1 is
    ///   downstream of the key check and cannot reach it.
    /// - *M2, re-encode on the emit side* (`handle_extract` re-encodes each
    ///   entity and keys it by the store hash, the literal pre-fix code):
    ///   **this row reddens**. Note what stays green — all three pre-existing
    ///   `test_handler_extract_*` rows — which is the finding, not a detail:
    ///   the extract suite asserts the envelope's *shape*, and the shape is
    ///   identical under both implementations.
    /// - *M5, drop §3.1's key-binds-value refusal in `decode_envelope`*: this
    ///   row stays **green** (M2 is not active, so the keys are honest) and
    ///   only `a_miskeyed_source_envelope_is_refused…` reddens. The two rows
    ///   are **disjoint discriminators**: one measures the bytes, the other
    ///   measures the addressing, and neither can stand in for the other.
    ///
    /// The canonical row in the loop is the control. It passes under every
    /// mutation above, which is the point: it is what a reader would have
    /// written, and it is why this shipped.
    #[tokio::test]
    async fn merge_from_an_envelope_preserves_entity_bytes() {
        for (label, ent) in [
            ("non-canonical", noncanonical_entity()),
            ("canonical control", make_entity("test/canon", "a")),
        ] {
            let source = make_tree();
            let true_hash = source.put(&qp("src/a"), ent.clone()).unwrap();
            assert_eq!(
                true_hash, ent.content_hash,
                "{label}: fixture is self-consistent"
            );

            let ex = source
                .handle(&make_handler_context(
                    "extract",
                    None,
                    Some(vec![qp("src/")]),
                ))
                .await
                .unwrap();
            assert_eq!(ex.status, STATUS_OK, "{label}: extract");

            // A peer that has never seen this entity.
            let target = make_tree();
            let res = target
                .handle(&make_handler_context_raw_params(
                    "merge",
                    merge_params_raw(&ex.result, "src/", "dest/"),
                ))
                .await
                .unwrap();
            assert_eq!(res.status, STATUS_OK, "{label}: merge status");

            assert_eq!(
                target.location_index.get(&qp("dest/a")),
                Some(true_hash),
                "{label}: the binding names the source hash"
            );
            let got = target
                .get(&qp("dest/a"))
                .unwrap_or_else(|| panic!("{label}: merged path resolves to content"));
            assert_eq!(got.content_hash, true_hash, "{label}: same entity");
            assert_eq!(
                got.data, ent.data,
                "{label}: §5.4 — the bytes crossed the merge unchanged"
            );
        }
    }

    /// The other half of routing `source_envelope` through
    /// [`entity_wire::decode_envelope`]: §3.1's key-binds-value check now runs
    /// on it. It never did before, because `source_envelope` is **an envelope
    /// built from received bytes at a site that is not `decode_envelope`** —
    /// the exact gap our charter's *"enforce it at the constructor"* entry
    /// predicts, one params field away from the constructor that enforces it.
    #[tokio::test]
    async fn a_miskeyed_source_envelope_is_refused_not_silently_re_addressed() {
        let source = make_tree();
        let ent = make_entity("test/canon", "a");
        source.put(&qp("src/a"), ent.clone()).unwrap();
        let ex = source
            .handle(&make_handler_context(
                "extract",
                None,
                Some(vec![qp("src/")]),
            ))
            .await
            .unwrap();

        // Re-key one included entry under a hash it does not hash to, leaving
        // the entity itself untouched and self-consistent — `validate()` alone
        // cannot see this, which is why the KEY check has to be its own.
        let env_val = decode_cbor(&ex.result.data);
        let mut env_map = env_val.as_map().unwrap().clone();
        let wrong = Hash::compute("test/canon", b"\x61z");
        for (k, v) in env_map.iter_mut() {
            if k.as_text() == Some("included") {
                let mut inc = v.as_map().unwrap().clone();
                let bad = entity_ecf::Value::Bytes(wrong.to_bytes().to_vec());
                let last = inc.len() - 1;
                inc[last].0 = bad;
                *v = entity_ecf::Value::Map(inc);
            }
        }
        let forged = Entity::new(
            &ex.result.entity_type,
            entity_ecf::to_ecf(&entity_ecf::Value::Map(env_map)),
        )
        .unwrap();

        let target = make_tree();
        let res = target
            .handle(&make_handler_context_raw_params(
                "merge",
                merge_params_raw(&forged, "src/", "dest/"),
            ))
            .await
            .unwrap();
        assert_eq!(res.status, STATUS_BAD_REQUEST);
        let (code, _) = entity_handler::decode_error_entity(&res.result).unwrap();
        assert_eq!(code.as_deref(), Some("hash_mismatch"));
        assert!(
            !target.has(&qp("dest/a")),
            "a refused envelope writes nothing"
        );
    }

    // -----------------------------------------------------------------------
    // EXTRACT operation tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_handler_extract_full_subtree() {
        let tree = make_tree();
        let e1 = make_entity("test", "alpha");
        let e2 = make_entity("test", "beta");
        tree.put(&qp("data/a"), e1).unwrap();
        tree.put(&qp("data/b"), e2).unwrap();

        let ctx = make_handler_context("extract", None, Some(vec![qp("data/")]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(result.result.entity_type, entity_types::TYPE_ENVELOPE);

        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();

        // Root should be a snapshot
        let root = cbor_map_get(map, "root").as_map().unwrap();
        let root_type = cbor_map_get(root, "type").as_text().unwrap();
        assert_eq!(root_type, entity_types::TYPE_TREE_SNAPSHOT);

        // Included should have the snapshot + trie nodes + 2 data entities
        // (snapshot + root trie node + 2 leaf trie nodes + 2 data entities = 6,
        // or fewer if trie compresses paths)
        let included = cbor_map_get(map, "included").as_map().unwrap();
        assert!(
            included.len() >= 3,
            "expected at least 3 included entities, got {}",
            included.len()
        );
    }

    #[tokio::test]
    async fn test_handler_extract_with_paths_filter() {
        let tree = make_tree();
        tree.put(&qp("data/a"), make_entity("test", "alpha"))
            .unwrap();
        tree.put(&qp("data/b"), make_entity("test", "beta"))
            .unwrap();
        tree.put(&qp("data/c"), make_entity("test", "gamma"))
            .unwrap();

        let params = entity_ecf::Value::Map(vec![(
            entity_ecf::text("paths"),
            entity_ecf::array(vec![entity_ecf::text("a"), entity_ecf::text("c")]),
        )]);

        let ctx = make_handler_context("extract", Some(params), Some(vec![qp("data/")]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();

        // Root snapshot should have only 2 bindings (a, c)
        let root = cbor_map_get(map, "root").as_map().unwrap();
        let root_data_val = cbor_map_get(root, "data");
        let mut root_data_bytes = Vec::new();
        ciborium::into_writer(root_data_val, &mut root_data_bytes).unwrap();
        let root_data: ciborium::Value = ciborium::from_reader(root_data_bytes.as_slice()).unwrap();
        let root_map = root_data.as_map().unwrap();
        let trie_root_bytes = cbor_map_get(root_map, "root").as_bytes().unwrap();
        let trie_root_hash = Hash::from_bytes(trie_root_bytes).unwrap();
        let bindings = trie::collect_all_bindings(tree.content_store.as_ref(), trie_root_hash, "");
        assert_eq!(bindings.len(), 2);
    }

    /// ⛔ **`CORE-PARAMS-PATH-TOTAL-1` (§5.4 — 0.8.2.21) and EXTENSION-TREE v4.9
    /// §6.1 in one row: a malformed `paths[]` entry is `400 invalid_path` for
    /// the whole request, and an ABSENT well-formed one is silently omitted.**
    ///
    /// The two are different inputs with different remedies and collapsing them
    /// is the defect: a caller asking for ten paths and getting seven cannot
    /// tell garbage from a missing binding. *"Fix your path"* is a different
    /// instruction from *"that binding does not exist"*, and the code is what
    /// selects the remedy.
    ///
    /// **This cannot be a false pass** — that is the vector's own claim and it
    /// is why the absent row below is mandatory. `paths[]` reaches a tree-path
    /// boundary through `params`, a channel `connection.rs`'s resource-target
    /// pre-validator never sees, so a peer that validates only the resource
    /// target answers `200` with a short result (ours did) or crashes the
    /// connection task (one sibling's did). Only a peer validating at the
    /// boundary answers `400`.
    ///
    /// Mutation-verified: deleting the `validate_extract_subpath` pre-pass in
    /// `handle_extract` reddens every malformed row here and leaves the two
    /// well-formed rows green.
    #[tokio::test]
    async fn a_malformed_extract_subpath_is_400_and_an_absent_one_is_omitted() {
        let tree = make_tree();
        tree.put(&qp("data/a"), make_entity("test", "alpha"))
            .unwrap();

        let drive = |paths: Vec<&str>| {
            let params = entity_ecf::Value::Map(vec![(
                entity_ecf::text("paths"),
                entity_ecf::array(paths.iter().map(|p| entity_ecf::text(*p)).collect()),
            )]);
            make_handler_context("extract", Some(params), Some(vec![qp("data/")]))
        };

        // The vector's own probe value, and the other three shapes v4.9 names.
        for bad in ["\u{1}x", "a//b", "./a", "../a", "/a", ""] {
            let result = tree.handle(&drive(vec![bad])).await.unwrap();
            assert_eq!(
                result.status, STATUS_BAD_REQUEST,
                "a malformed paths[] entry {bad:?} is 400, not a short 200"
            );
            let (code, _) = entity_handler::decode_error_entity(&result.result)
                .expect("400 carries a system/protocol/error");
            assert_eq!(
                code.as_deref(),
                Some("invalid_path"),
                "the code is what selects the remedy — read the decoded `code` \
                 key, never a substring of the body"
            );
        }

        // BEFORE reading any: one good entry beside one malformed entry is
        // still 400 for the whole request, and the answer does not depend on
        // array order.
        for pair in [vec!["a", "\u{1}x"], vec!["\u{1}x", "a"]] {
            let result = tree.handle(&drive(pair.clone())).await.unwrap();
            assert_eq!(
                result.status, STATUS_BAD_REQUEST,
                "no partial result, in either array order: {pair:?}"
            );
        }

        // CONTROL 1 — a well-formed entry that BINDS NOTHING is absent, and
        // absent is silently omitted. This is what the filter is FOR, and
        // without this row the rows above are satisfied by a handler that
        // refuses every `paths` filter.
        let result = tree.handle(&drive(vec!["a", "nonexistent"])).await.unwrap();
        assert_eq!(
            result.status, STATUS_OK,
            "a well-formed path that binds nothing is ABSENT, not malformed"
        );

        // CONTROL 2 — the ordinary filtered extract still works.
        let result = tree.handle(&drive(vec!["a"])).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
    }

    /// ⛔ **The other half of `CORE-PARAMS-PATH-TOTAL-1`: `:merge`'s
    /// `target_prefix`, which is the sharper one, because `merge` reads NO
    /// resource target at all.**
    ///
    /// Nothing upstream has ever seen these paths — not `connection.rs`'s
    /// admission, not `check_resource_scope` — so a control character in
    /// `target_prefix` was concatenated with every binding name in the source
    /// snapshot and written into the location index verbatim. The boundary is
    /// where it has to be caught, *"whatever carried it"*.
    ///
    /// Before the §11/§12.1 authorization pre-pass, deliberately: `403` on a
    /// path that cannot exist tells the caller to go get a capability for it.
    #[tokio::test]
    async fn a_malformed_merge_target_prefix_is_400_and_writes_nothing() {
        let source = make_tree();
        source
            .put(&qp("src/a"), make_entity("test", "alpha"))
            .unwrap();
        let snap = source
            .handle(&make_handler_context(
                "snapshot",
                None,
                Some(vec![qp("src/")]),
            ))
            .await
            .unwrap();
        let snapshot_hash = source.content_store.put(snap.result).unwrap();

        let drive = |target_prefix: &str| {
            entity_ecf::Value::Map(vec![
                (
                    entity_ecf::text("source"),
                    entity_ecf::Value::Bytes(snapshot_hash.to_bytes().to_vec()),
                ),
                (
                    entity_ecf::text("target_prefix"),
                    entity_ecf::text(target_prefix),
                ),
            ])
        };

        let result = source
            .handle(&make_handler_context(
                "merge",
                Some(drive("\u{1}evil/")),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(result.status, STATUS_BAD_REQUEST);
        let (code, _) = entity_handler::decode_error_entity(&result.result).unwrap();
        assert_eq!(code.as_deref(), Some("invalid_path"));
        assert!(
            source
                .location_index
                .list(&format!("/{}/", test_peer_id()))
                .iter()
                .all(|e| !e.path.contains('\u{1}')),
            "§12.1 is atomic: a refused merge leaves ZERO writes, not some"
        );

        // CONTROL — the same merge at a well-formed target prefix applies.
        let result = source
            .handle(&make_handler_context("merge", Some(drive("dest/")), None))
            .await
            .unwrap();
        assert_eq!(
            result.status, STATUS_OK,
            "without this row the refusal above is a handler that refuses every merge"
        );
    }

    #[tokio::test]
    async fn test_handler_extract_invalid_prefix() {
        let tree = make_tree();
        let ctx = make_handler_context("extract", None, Some(vec![qp("data")]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_BAD_REQUEST);
    }

    // -----------------------------------------------------------------------
    // Round-trip: snapshot → diff → merge → extract
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_round_trip() {
        let tree = make_tree();

        // Set up initial data
        tree.put(&qp("app/config"), make_entity("test", "config-v1"))
            .unwrap();
        tree.put(&qp("app/data"), make_entity("test", "data-v1"))
            .unwrap();

        // Snapshot before
        let snap1_ctx = make_handler_context("snapshot", None, Some(vec![qp("app/")]));
        let snap1 = tree.handle(&snap1_ctx).await.unwrap();
        let snap1_hash = tree.content_store.put(snap1.result).unwrap();

        // Modify
        tree.put(&qp("app/data"), make_entity("test", "data-v2"))
            .unwrap();
        tree.put(&qp("app/new"), make_entity("test", "new-entry"))
            .unwrap();

        // Snapshot after
        let snap2_ctx = make_handler_context("snapshot", None, Some(vec![qp("app/")]));
        let snap2 = tree.handle(&snap2_ctx).await.unwrap();
        let snap2_hash = tree.content_store.put(snap2.result).unwrap();

        // Diff should show 1 changed (data), 1 added (new), 1 unchanged (config)
        let diff_params = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("base"),
                entity_ecf::Value::Bytes(snap1_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("target"),
                entity_ecf::Value::Bytes(snap2_hash.to_bytes().to_vec()),
            ),
        ]);
        let diff_ctx = make_handler_context("diff", Some(diff_params), None);
        let diff = tree.handle(&diff_ctx).await.unwrap();
        assert_eq!(diff.status, STATUS_OK);

        let val = decode_cbor(&diff.result.data);
        let map = val.as_map().unwrap();
        let added = cbor_map_get(map, "added").as_map().unwrap();
        let changed = cbor_map_get(map, "changed").as_map().unwrap();
        let unchanged = cbor_map_get(map, "unchanged").as_integer().unwrap();
        assert_eq!(added.len(), 1);
        assert_eq!(changed.len(), 1);
        assert_eq!(i128::from(unchanged), 1);

        // Extract subtree
        let extract_ctx = make_handler_context("extract", None, Some(vec![qp("app/")]));
        let extract = tree.handle(&extract_ctx).await.unwrap();
        assert_eq!(extract.status, STATUS_OK);
        assert_eq!(extract.result.entity_type, entity_types::TYPE_ENVELOPE);
    }

    /// V7 §1.8 / v7.69 §4.5a — a `put` of an entity authored under a
    /// **foreign** `content_hash_format` MUST store and serve it at the
    /// address its author gave it, not re-derive it under the peer's home
    /// format. SPECIFICATION-FORMAT §8.4.6 calls this *hold-and-fetch*: the
    /// reference travelled here, so it is used verbatim.
    ///
    /// The test peer's home format is SHA-256; the entity is authored under
    /// SHA-384. Before this was fixed the put path rebuilt the entity from
    /// `{type, data}` alone and recomputed the hash, so the entity came back
    /// at a 33-byte SHA-256 address after being published at a 49-byte
    /// SHA-384 one — and every reference held to it elsewhere stopped
    /// resolving. Invisible while a single format ships, because then the
    /// re-derived hash and the authored one are the same bytes.
    #[tokio::test]
    async fn test_handler_put_preserves_a_foreign_format_content_hash() {
        let tree = make_tree();
        let data = entity_ecf::to_ecf(&entity_ecf::text("authored elsewhere"));
        let foreign =
            Entity::new_with_format("test/type", data, entity_hash::HASH_ALGORITHM_SHA384).unwrap();
        assert_eq!(
            foreign.content_hash.algorithm,
            entity_hash::HASH_ALGORITHM_SHA384
        );
        assert_eq!(foreign.content_hash.to_bytes().len(), 49);

        let inner_data_val: ciborium::Value =
            ciborium::from_reader(foreign.data.as_slice()).unwrap();
        let params = entity_ecf::Value::Map(vec![(
            entity_ecf::text("entity"),
            entity_ecf::Value::Map(vec![
                (
                    entity_ecf::text("content_hash"),
                    entity_ecf::Value::Bytes(foreign.content_hash.to_bytes().to_vec()),
                ),
                (entity_ecf::text("data"), inner_data_val),
                (
                    entity_ecf::text("type"),
                    entity_ecf::text(&foreign.entity_type),
                ),
            ]),
        )]);
        let ctx = make_handler_context("put", Some(params), Some(vec![qp("foreign/fmt")]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let got = tree.get(&qp("foreign/fmt")).expect("bound");
        assert_eq!(
            got.content_hash, foreign.content_hash,
            "the peer re-derived a reference it did not author"
        );
        assert_eq!(
            got.content_hash.algorithm,
            entity_hash::HASH_ALGORITHM_SHA384
        );
        // And what it serves still verifies against the hash it serves it at.
        got.validate().expect("served entity must validate");
    }

    /// The other half, **inverted at 0.8.2.11 — and this test previously
    /// asserted the defect.** It read
    /// `test_handler_put_without_content_hash_authors_under_home_format` and
    /// said *"preserving a supplied hash must not turn the field into a
    /// requirement"*, asserting `STATUS_OK` for a two-key submission. §8.1
    /// declares `core/entity`'s three fields with no `optional` marker and
    /// `ENTITY-CORE-PROTOCOL` §6.3 now states the ladder outright: `put` is a
    /// **receipt** path and MUST NOT author a hash on the submitter's behalf.
    /// The field always was a requirement; the old test was written from the
    /// `content_hash?` spelling `ENTITY-NATIVE-TYPE-SYSTEM` §2.8 carried until
    /// 0.8.2.11 corrected it.
    ///
    /// **Because this rewrites what a test asserts rather than whether it
    /// passes, it witnesses nothing on its own** (`AGENTS.md`: a test edited in
    /// the same commit as the behaviour is not an independent witness). The two
    /// things that do witness it are both outside this file:
    ///   - the **untouched** control one function up,
    ///     `test_handler_put_preserves_foreign_content_hash_format`, which
    ///     drives a three-key SHA-384 submission and must stay green — it fails
    ///     if this change made `put` refuse carried hashes rather than absent
    ///     ones, which is the one-edit-away way to "fix" this wrong;
    ///   - the cross-impl drive, `validate-peer -category tree_operations`,
    ///     row `put_absent_content_hash_400_invalid_request`, which scored us
    ///     **FAIL — 200** at `06404cb` and is the measurement that found this.
    #[tokio::test]
    async fn put_without_content_hash_is_refused_and_never_authored() {
        let tree = make_tree();
        let entity = make_entity("test/type", "authored here");
        let inner: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).unwrap();
        let params = entity_ecf::Value::Map(vec![(
            entity_ecf::text("entity"),
            entity_ecf::Value::Map(vec![
                (entity_ecf::text("data"), inner),
                (entity_ecf::text("type"), entity_ecf::text("test/type")),
            ]),
        )]);
        let ctx = make_handler_context("put", Some(params), Some(vec![qp("local/fmt")]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(
            result.status, STATUS_BAD_REQUEST,
            "a two-key submission is not a core/entity; put must refuse it"
        );
        let val = decode_cbor(&result.result.data);
        assert_eq!(
            cbor_map_get(val.as_map().unwrap(), "code").as_text(),
            Some("invalid_request"),
            "absence of a required field is the structural row, not hash_mismatch"
        );
        // The half that makes it a *receipt* claim rather than a status claim:
        // nothing was stored and nothing was bound, so no address the
        // submitter did not choose came into existence.
        assert!(
            !tree.has(&qp("local/fmt")),
            "the peer authored a hash the submitter did not provide"
        );
    }

    /// A `content_hash` that is *present but not a byte string* — `null`, a
    /// text string, a map — is the same structural refusal as absence, and it
    /// is the input the routed worklist did not name. It matters because the
    /// pre-0.8.2.11 decoder read it through `if let Some(bytes) = v.as_bytes()`
    /// and simply **fell through**, leaving the authored-hash slot empty: a
    /// mis-typed field took the authoring arm, indistinguishable from a field
    /// that was never sent.
    ///
    /// **Mutation, stated as measured rather than as expected — the first
    /// version of this comment was wrong and the run is what corrected it.**
    /// Removing the `else` *alone* leaves both rows below **green**: the
    /// `ok_or_else` at the end of `decode_entity_from_cbor` catches the empty
    /// slot and answers the same `invalid_request`, so the two spellings are
    /// behaviourally equivalent on the wire today. The mutation that reddens
    /// these rows is the **combination** — remove the `else` *and* restore the
    /// authoring arm — because it takes both for a mis-typed field to reach a
    /// peer-authored hash. So the `else` is defence in depth, not the load-
    /// bearing check, and the honest reading of these rows is that they pin the
    /// *wire answer* for a shape core-go's routing did not name, while
    /// `put_without_content_hash_is_refused_and_never_authored` is the row that
    /// discriminates the authoring arm on its own (verified: authoring arm
    /// alone reddens that row and
    /// `put_admission_predicate_is_every_clause_of_the_entity_shape`, and
    /// leaves these two green).
    #[tokio::test]
    async fn put_content_hash_present_but_not_a_bstr_is_refused_not_authored() {
        for (label, bad) in [
            ("null", entity_ecf::Value::Null),
            ("text", entity_ecf::text("not a hash")),
        ] {
            let tree = make_tree();
            let entity = make_entity("test/type", "payload");
            let inner: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).unwrap();
            let params = entity_ecf::Value::Map(vec![(
                entity_ecf::text("entity"),
                entity_ecf::Value::Map(vec![
                    (entity_ecf::text("content_hash"), bad),
                    (entity_ecf::text("data"), inner),
                    (entity_ecf::text("type"), entity_ecf::text("test/type")),
                ]),
            )]);
            let ctx = make_handler_context("put", Some(params), Some(vec![qp("bad/ch")]));
            let result = tree.handle(&ctx).await.unwrap();
            assert_eq!(
                result.status, STATUS_BAD_REQUEST,
                "content_hash as {label} is not a system/hash"
            );
            let val = decode_cbor(&result.result.data);
            assert_eq!(
                cbor_map_get(val.as_map().unwrap(), "code").as_text(),
                Some("invalid_request"),
                "content_hash as {label} is the structural row"
            );
            assert!(
                !tree.has(&qp("bad/ch")),
                "nothing may be stored for {label}"
            );
        }
    }

    /// Preserving the authored hash is not a forgery vector: `validate` runs
    /// on the put path and recomputes under the CLAIMED hash's own algorithm,
    /// so a caller may choose the format its entity is addressed under — the
    /// authoring right §4.5a gives it — but cannot claim a hash its bytes do
    /// not produce.
    #[tokio::test]
    async fn test_handler_put_rejects_a_claimed_hash_that_does_not_verify() {
        let tree = make_tree();
        let data = entity_ecf::to_ecf(&entity_ecf::text("real bytes"));
        let lie = Entity::new_with_format(
            "test/type",
            entity_ecf::to_ecf(&entity_ecf::text("other")),
            entity_hash::HASH_ALGORITHM_SHA384,
        )
        .unwrap();

        let inner_data_val: ciborium::Value = ciborium::from_reader(data.as_slice()).unwrap();
        let params = entity_ecf::Value::Map(vec![(
            entity_ecf::text("entity"),
            entity_ecf::Value::Map(vec![
                (
                    entity_ecf::text("content_hash"),
                    entity_ecf::Value::Bytes(lie.content_hash.to_bytes().to_vec()),
                ),
                (entity_ecf::text("data"), inner_data_val),
                (entity_ecf::text("type"), entity_ecf::text("test/type")),
            ]),
        )]);
        let ctx = make_handler_context("put", Some(params), Some(vec![qp("forged/fmt")]));
        let result = tree.handle(&ctx).await;
        assert!(
            result.is_err() || result.as_ref().unwrap().status >= 400,
            "a content_hash that does not match the bytes must be refused"
        );
        assert!(
            tree.get(&qp("forged/fmt")).is_none(),
            "nothing may be bound"
        );
    }
}
