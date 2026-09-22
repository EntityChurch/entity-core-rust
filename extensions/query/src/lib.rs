//! Query extension — secondary indexes and find/count operations.
//!
//! Implements EXTENSION-QUERY.md Level 1:
//! - Type index, reverse hash index, path link index
//! - Query handler at `system/query` with `find` and `count` operations
//! - Capability-filtered results, cursor-based pagination

pub mod cursor;
pub mod index;
pub mod indexing;
#[cfg(feature = "sqlite")]
pub mod sqlite_index;
pub mod walker;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use entity_capability::GrantEntry;
use entity_ecf::Value;
use entity_entity::Entity;
use entity_handler::{
    Handler, HandlerContext, HandlerError, HandlerResult, STATUS_BAD_REQUEST, STATUS_FORBIDDEN,
    STATUS_NOT_SUPPORTED,
};
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};

/// Default limit when not specified in expression (spec §8).
const DEFAULT_QUERY_LIMIT: u64 = 100;
/// Maximum limit value (spec §8).
const MAX_QUERY_LIMIT: u64 = 10_000;

// Re-exports
pub use index::{QueryIndexStore, QueryIndexes};
pub use indexing::IndexingLocationIndex;
#[cfg(feature = "sqlite")]
pub use sqlite_index::SqliteQueryIndexes;

// ---------------------------------------------------------------------------
// Query expression (parsed from params)
// ---------------------------------------------------------------------------

struct QueryExpression {
    type_filter: Option<String>,
    ref_filter: Option<Hash>,
    path_filter: Option<String>,
    path_prefix: Option<String>,
    limit: Option<u64>,
    cursor: Option<String>,
    include_entities: bool,
}

/// A single query match result.
#[derive(Debug, Clone)]
struct QueryMatch {
    path: String,
    hash: Hash,
    entity_type: String,
}

// ---------------------------------------------------------------------------
// Constraints decoded from matching grant
// ---------------------------------------------------------------------------

struct QueryConstraints {
    scope: String, // "tree" or "content_store"
    max_results: Option<u64>,
    type_scope_include: Option<Vec<String>>,
    type_scope_exclude: Option<Vec<String>>,
}

impl Default for QueryConstraints {
    fn default() -> Self {
        Self {
            scope: "tree".to_string(),
            max_results: None,
            type_scope_include: None,
            type_scope_exclude: None,
        }
    }
}

fn parse_constraints(grant: &Option<GrantEntry>) -> QueryConstraints {
    let grant = match grant {
        Some(g) => g,
        None => return QueryConstraints::default(),
    };

    let mut result = QueryConstraints::default();

    // Read scope from allowances (expanding field — absent = tree-only)
    if let Some(ref allowances) = grant.allowances {
        if let Some(scope_val) = allowances.get("scope") {
            if let Some(s) = scope_val.as_text() {
                result.scope = s.to_string();
            }
        }
    }

    // Read max_results and type_scope from constraints (narrowing fields)
    if let Some(ref constraints) = grant.constraints {
        if let Some(max_val) = constraints.get("max_results") {
            if let Some(ciborium::Value::Integer(i)) = Some(max_val) {
                let n: i128 = (*i).into();
                if n > 0 {
                    result.max_results = Some(n as u64);
                }
            }
        }
        if let Some(type_scope_val) = constraints.get("type_scope") {
            if let Some(scope_map) = type_scope_val.as_map() {
                for (sk, sv) in scope_map {
                    match sk.as_text() {
                        Some("include") => {
                            if let Some(arr) = sv.as_array() {
                                result.type_scope_include = Some(
                                    arr.iter()
                                        .filter_map(|v| v.as_text().map(String::from))
                                        .collect(),
                                );
                            }
                        }
                        Some("exclude") => {
                            if let Some(arr) = sv.as_array() {
                                result.type_scope_exclude = Some(
                                    arr.iter()
                                        .filter_map(|v| v.as_text().map(String::from))
                                        .collect(),
                                );
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    result
}

// ---------------------------------------------------------------------------
// QueryHandler
// ---------------------------------------------------------------------------

pub struct QueryHandler {
    indexes: Arc<dyn QueryIndexStore>,
    content_store: Arc<dyn ContentStore>,
    #[allow(dead_code)]
    location_index: Arc<dyn LocationIndex>,
    local_peer_id: String,
    qualified_pattern: String,
}

impl QueryHandler {
    pub fn new(
        indexes: Arc<dyn QueryIndexStore>,
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
    ) -> Self {
        let qualified_pattern = format!("/{}/system/query", local_peer_id);
        Self {
            indexes,
            content_store,
            location_index,
            local_peer_id,
            qualified_pattern,
        }
    }

    fn handle_find(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        let expr = parse_expression(&ctx.params)?;
        let constraints = parse_constraints(&ctx.matching_grant);

        // Validate content_store scope requires type_scope (spec §5.5.2)
        if constraints.scope == "content_store" && constraints.type_scope_include.is_none() {
            return Ok(HandlerResult::error(
                STATUS_FORBIDDEN,
                make_error_entity(
                    "content_store_requires_type_scope",
                    "content_store scope requires type_scope on grant constraints",
                ),
            ));
        }

        // Validate type_filter against type_scope (spec §5.2 step 3).
        // `matches_id_scope`, not `matches_scope`: the subject is a TYPE NAME and
        // `type_scope` is a `system/capability/id-scope` (§5.5.1), so it matches
        // literally with the two id wildcards and carries no peer-id frame — see
        // `filter_by_capability`, which had the same confusion at step 6a.
        if let (Some(ref type_filter), Some(ref type_scope)) =
            (&expr.type_filter, &constraints.type_scope_include)
        {
            let exclude = constraints.type_scope_exclude.as_deref().unwrap_or(&[]);
            if !entity_capability::matches_id_scope(type_filter, type_scope, exclude) {
                return Ok(HandlerResult::error(
                    STATUS_FORBIDDEN,
                    make_error_entity("type_not_authorized", "type_filter not in type_scope"),
                ));
            }
        }

        // Validate: empty query → 400
        if expr.type_filter.is_none()
            && expr.ref_filter.is_none()
            && expr.path_filter.is_none()
            && expr.path_prefix.is_none()
        {
            return Ok(HandlerResult::error(
                STATUS_BAD_REQUEST,
                make_error_entity("empty_query", "at least one filter is required"),
            ));
        }

        // Execute index lookups and intersect
        let candidates = self.execute_query(&expr);

        // Capability filter
        let filtered = self.filter_by_capability(candidates, &constraints, ctx);

        // Sort by path ascending
        let mut sorted = filtered;
        sorted.sort_by(|a, b| a.path.cmp(&b.path));

        // Effective limit
        let effective_limit = std::cmp::min(
            expr.limit.unwrap_or(DEFAULT_QUERY_LIMIT),
            constraints.max_results.unwrap_or(MAX_QUERY_LIMIT),
        );

        // Pagination
        let total = sorted.len() as u64;
        let start = if let Some(ref cursor_str) = expr.cursor {
            let last_path = cursor::decode_cursor(cursor_str)?;
            sorted
                .iter()
                .position(|m| m.path > last_path)
                .unwrap_or(sorted.len())
        } else {
            0
        };

        let page: Vec<&QueryMatch> = sorted
            .iter()
            .skip(start)
            .take(effective_limit as usize)
            .collect();

        let has_more = start + page.len() < sorted.len();
        let next_cursor = if has_more {
            page.last().map(|m| cursor::encode_cursor(&m.path))
        } else {
            None
        };

        // Build result entity
        let matches: Vec<Value> = page
            .iter()
            .map(|m| {
                Value::Map(vec![
                    (
                        entity_ecf::text("hash"),
                        Value::Bytes(m.hash.to_bytes().to_vec()),
                    ),
                    (entity_ecf::text("path"), entity_ecf::text(&m.path)),
                    (entity_ecf::text("type"), entity_ecf::text(&m.entity_type)),
                ])
            })
            .collect();

        let mut result_entries = vec![
            (entity_ecf::text("has_more"), entity_ecf::bool_val(has_more)),
            (entity_ecf::text("matches"), Value::Array(matches)),
            (entity_ecf::text("total"), entity_ecf::integer(total as i64)),
        ];
        if let Some(ref cursor_val) = next_cursor {
            result_entries.push((entity_ecf::text("cursor"), entity_ecf::text(cursor_val)));
        }

        let result_data = entity_ecf::to_ecf(&Value::Map(result_entries));
        let result_entity = Entity::new("system/query/result", result_data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        if expr.include_entities {
            let mut included = HashMap::new();
            for m in &page {
                if let Some(entity) = self.content_store.get(&m.hash) {
                    included.insert(m.hash, entity);
                }
            }
            Ok(HandlerResult::ok(build_envelope_result(
                result_entity,
                included,
            )))
        } else {
            Ok(HandlerResult::ok(result_entity))
        }
    }

    fn handle_count(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        let expr = parse_expression(&ctx.params)?;
        let constraints = parse_constraints(&ctx.matching_grant);

        if constraints.scope == "content_store" && constraints.type_scope_include.is_none() {
            return Ok(HandlerResult::error(
                STATUS_FORBIDDEN,
                make_error_entity(
                    "content_store_requires_type_scope",
                    "content_store scope requires type_scope on grant constraints",
                ),
            ));
        }

        if expr.type_filter.is_none()
            && expr.ref_filter.is_none()
            && expr.path_filter.is_none()
            && expr.path_prefix.is_none()
        {
            return Ok(HandlerResult::error(
                STATUS_BAD_REQUEST,
                make_error_entity("empty_query", "at least one filter is required"),
            ));
        }

        let candidates = self.execute_query(&expr);
        let filtered = self.filter_by_capability(candidates, &constraints, ctx);
        let count = filtered.len() as i64;

        let result_data = entity_ecf::to_ecf(&entity_ecf::integer(count));
        let result_entity = Entity::new("primitive/uint", result_data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        Ok(HandlerResult::ok(result_entity))
    }

    fn execute_query(&self, expr: &QueryExpression) -> Vec<QueryMatch> {
        let mut result_sets: Vec<Vec<QueryMatch>> = Vec::new();

        // Type index lookup
        if let Some(ref type_filter) = expr.type_filter {
            let type_entries = self.indexes.query_type_index(type_filter);
            result_sets.push(
                type_entries
                    .into_iter()
                    .map(|e| {
                        // Get entity type from the cache via content store lookup
                        let entity_type = self
                            .content_store
                            .get(&e.hash)
                            .map(|ent| ent.entity_type)
                            .unwrap_or_default();
                        QueryMatch {
                            path: e.path,
                            hash: e.hash,
                            entity_type,
                        }
                    })
                    .collect(),
            );
        }

        // Reverse hash index lookup
        if let Some(ref ref_hash) = expr.ref_filter {
            let ref_entries = self.indexes.query_reverse_index(ref_hash);
            result_sets.push(
                ref_entries
                    .into_iter()
                    .map(|e| {
                        let hash = self
                            .indexes
                            .query_type_index(&e.source_type)
                            .into_iter()
                            .find(|t| t.path == e.source_path)
                            .map(|t| t.hash)
                            .unwrap_or(Hash::zero());
                        QueryMatch {
                            path: e.source_path,
                            hash,
                            entity_type: e.source_type,
                        }
                    })
                    .collect(),
            );
        }

        // Path link index lookup
        if let Some(ref path_filter) = expr.path_filter {
            let link_entries = self.indexes.query_path_link_index(path_filter);
            result_sets.push(
                link_entries
                    .into_iter()
                    .map(|e| {
                        let hash = self
                            .indexes
                            .query_type_index(&e.source_type)
                            .into_iter()
                            .find(|t| t.path == e.source_path)
                            .map(|t| t.hash)
                            .unwrap_or(Hash::zero());
                        QueryMatch {
                            path: e.source_path,
                            hash,
                            entity_type: e.source_type,
                        }
                    })
                    .collect(),
            );
        }

        // If no index was queried but path_prefix is present, scan type index
        if result_sets.is_empty() {
            if let Some(ref _prefix) = expr.path_prefix {
                let all = self.indexes.query_type_index("*");
                result_sets.push(
                    all.into_iter()
                        .map(|e| {
                            let entity_type = self
                                .content_store
                                .get(&e.hash)
                                .map(|ent| ent.entity_type)
                                .unwrap_or_default();
                            QueryMatch {
                                path: e.path,
                                hash: e.hash,
                                entity_type,
                            }
                        })
                        .collect(),
                );
            }
        }

        // Intersect result sets
        let mut candidates = match result_sets.len() {
            0 => return Vec::new(),
            1 => result_sets.into_iter().next().unwrap(),
            _ => {
                let mut iter = result_sets.into_iter();
                let first = iter.next().unwrap();
                let first_paths: std::collections::HashSet<String> =
                    first.iter().map(|m| m.path.clone()).collect();
                let mut intersection = first;

                for set in iter {
                    let paths: std::collections::HashSet<String> =
                        set.iter().map(|m| m.path.clone()).collect();
                    let common: std::collections::HashSet<&String> =
                        first_paths.intersection(&paths).collect();
                    intersection.retain(|m| common.contains(&m.path));
                }
                intersection
            }
        };

        // Apply path_prefix filter.
        // Paths in the index are peer-qualified ({peer_id}/path). The expression's
        // path_prefix is a bare path. We qualify it so it matches indexed paths.
        if let Some(ref prefix) = expr.path_prefix {
            let qualified_prefix =
                entity_entity::EntityUri::qualify_path(prefix, &self.local_peer_id);
            candidates.retain(|m| m.path.starts_with(&qualified_prefix));
        }

        candidates
    }

    /// `EXTENSION-QUERY` §5.2 steps **6a** (type scope) and **6b** (per-result
    /// path permission), and the two steps do not share an authority.
    ///
    /// ⛔ **6b is `check_path_permission`, and the reason is the sentence §5.5.2
    /// uses to describe it: *"capability filtering uses `check_path_permission`
    /// per result — same pattern as tree listing."*** `find` is the widest
    /// enumerating consumer in the corpus: the dispatch check saw a handler, an
    /// operation and — only if the EXECUTE carried a `resource` — a target
    /// *string*; what leaves this function is a **set** drawn straight off the
    /// indexes. That is `CP-12a`/`F71`'s class, and §6.3's listing MUST is the
    /// same rule one handler over.
    ///
    /// This ran a hand-rolled predicate instead, and it was wrong in three
    /// independent ways:
    ///
    /// 1. **Resources only, so the dimensions came apart.** It looped *every*
    ///    grant asking only about `resources`, so a path covered by grant B was
    ///    admitted for a query authorized by grant A — a cap holding
    ///    `{handlers:[system/inbox], resources:[/{p}/secret/*]}` beside a narrow
    ///    query grant enumerated `/{p}/secret/*`. §5.2 answers all dimensions
    ///    **from one grant entry**; splitting them across entries is the same
    ///    defect `F67` was, reached from a filter instead of a bypass.
    /// 2. **The wrong PR-8 frame.** Grant patterns canonicalized against
    ///    `local_peer_id`, so a foreign-granted bare `*` in `resources` landed in
    ///    *our* namespace — the V1' escalation, and this is a path with no
    ///    dispatch-level resource check behind it whenever `resource` is absent.
    /// 3. **`content_store` scope skipped the path check entirely.** §5.5.2's own
    ///    table says the filter is *"applied to entities with paths"* there;
    ///    only **pathless** results are authorized by `type_scope` alone.
    ///
    /// **The authority for 6b is the caller's capability and therefore EXTERNAL
    /// dispatch only** — the same scope, for the same measured reason, as
    /// `TreeHandler::authorize_path`: on an in-process sub-dispatch
    /// `caller_capability` is propagated *for attribution* (`make_execute_fn`
    /// says so at the site that writes it), so reading it as an authorization
    /// input refuses legitimate traffic. That gate is new here and it is a
    /// widening; it is stated because the previous code gated on the capability
    /// being *present*, which is the shape that cost us five days at `tree:put`.
    ///
    /// **6a is not gated, and that is deliberate.** `type_scope` is a
    /// *constraint* carried by `ctx.matching_grant` — the grant that authorized
    /// **this** dispatch, whichever kind it is — so it binds an internal caller
    /// exactly as it binds a wire caller. It is also an **id-scope** of type
    /// names (§5.5.1: `{type_ref: "system/capability/id-scope"}`), so it matches
    /// literally with the two id wildcards and takes no `local_peer_id`:
    /// `matches_scope` was canonicalizing a *type name* as though it were a
    /// path, which made a `*/`-leading pattern NEVER_MATCH and diverged from
    /// both sibling seats (go's `matchesScope` and py's `_type_authorized_by_scope`
    /// both match the raw name).
    fn filter_by_capability(
        &self,
        candidates: Vec<QueryMatch>,
        constraints: &QueryConstraints,
        ctx: &HandlerContext,
    ) -> Vec<QueryMatch> {
        // Step 6b's authority. `None` = no path check: a peer-root or in-process
        // dispatch, bounded by §5.2's `DispatchCeiling` rather than by this.
        let path_authority = if ctx.is_external {
            ctx.caller_capability.as_ref()
        } else {
            None
        };

        // The cap's own granter frame (PR-8). Fail CLOSED when it cannot be
        // resolved (§1.11) — a frame we cannot compute is not a frame we may
        // guess at, and §5.5.3 requires an out-of-scope entity to be
        // indistinguishable from a non-existent one, so the answer is an empty
        // result rather than an error.
        let granter_peer_id = match path_authority {
            Some(cap) => {
                match entity_capability::resolve_granter_peer_id(
                    &cap.granter,
                    &self.local_peer_id,
                    |h| ctx.included.get(h),
                ) {
                    Some(g) => Some(g),
                    None => return Vec::new(),
                }
            }
            None => None,
        };

        candidates
            .into_iter()
            .filter(|candidate| {
                // 6a — type scope (id-scope, literal; see the doc comment).
                if let Some(ref type_include) = constraints.type_scope_include {
                    let type_exclude = constraints.type_scope_exclude.as_deref().unwrap_or(&[]);
                    if !entity_capability::matches_id_scope(
                        &candidate.entity_type,
                        type_include,
                        type_exclude,
                    ) {
                        return false;
                    }
                }

                // 6b — per-result path permission (§6.3).
                if candidate.path.is_empty() {
                    // Pathless: reachable only under the `content_store`
                    // allowance, where §5.2's algorithm authorizes it by
                    // `type_scope` above. Under tree scope every result MUST
                    // have a path, so a pathless one is dropped.
                    return constraints.scope == "content_store";
                }
                match (path_authority, granter_peer_id.as_deref()) {
                    (Some(cap), Some(granter)) => entity_capability::check_path_permission(
                        "get",
                        &candidate.path,
                        cap,
                        // ⛔ **The frame is the handler that OWNS the operation,
                        // never the handler running the check `[MUST]` (§6.3,
                        // 0.8.2.23 — K4/K5).** This line passed `ctx.pattern`,
                        // which is `system/query`: the running handler. What is
                        // being authorized is a **tree read** — `get` on a tree
                        // path — so the authority being spent is `system/tree`,
                        // and whether the caller reaches it through the query
                        // surface is their route, not a second grant they must
                        // separately hold.
                        //
                        // The frame runs UPSTREAM of every dimension, so a wrong
                        // one is indistinguishable from a broken matcher, and it
                        // was wrong in **both** directions here:
                        //
                        // - it **refused** a conformant caller — a capability
                        //   split `{system/query: find}` + `{system/tree: get}`
                        //   had the `get` grant discarded unread, because no
                        //   grant naming `system/tree` survives a `handlers`
                        //   test against `system/query`, and the surviving
                        //   `{system/query: find}` grant then fails `operations`
                        //   on `get`. Every result was dropped.
                        // - it **admitted** one it should not — a caller holding
                        //   `{handlers:[system/query], operations:[find, get],
                        //   resources:[/{p}/*]}` was authorized for tree reads
                        //   through this surface while holding no tree grant at
                        //   all.
                        //
                        // `system/tree` is the literal every worked example in
                        // the corpus passes (`EXTENSION-QUERY` §5.5 step 6b's own
                        // pseudocode, `EXTENSION-HISTORY` §4.2,
                        // `EXTENSION-COMPUTE` §7.2, `EXTENSION-SUBSCRIPTION`
                        // §2.3) and the literal core-go passes at the same site
                        // (`ext/query/handler.go:605`). The other three
                        // frame-bearing sites in this tree were already correct:
                        // `core/tree` passes `ctx.pattern` and is conformant
                        // because there owner **is** runner — which §6.3 names
                        // explicitly, so a literal here and `ctx.pattern` there
                        // are the same rule, not two.
                        "system/tree",
                        &self.local_peer_id,
                        granter,
                    ),
                    _ => true,
                }
            })
            .collect()
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for QueryHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        match ctx.operation.as_str() {
            "find" => self.handle_find(ctx),
            "count" => self.handle_count(ctx),
            _ => Ok(HandlerResult::error(
                STATUS_NOT_SUPPORTED,
                make_error_entity(
                    "unsupported_operation",
                    &format!("unknown operation: {}", ctx.operation),
                ),
            )),
        }
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "query"
    }

    fn operations(&self) -> &[&str] {
        &["find", "count"]
    }
}

// ---------------------------------------------------------------------------
// Expression parsing
// ---------------------------------------------------------------------------

fn parse_expression(params: &Entity) -> Result<QueryExpression, HandlerError> {
    let value: ciborium::Value = ciborium::from_reader(params.data.as_slice())
        .map_err(|e| HandlerError::InvalidParams(format!("invalid expression: {e}")))?;

    let map = value
        .as_map()
        .ok_or_else(|| HandlerError::InvalidParams("expression must be a map".into()))?;

    let mut expr = QueryExpression {
        type_filter: None,
        ref_filter: None,
        path_filter: None,
        path_prefix: None,
        limit: None,
        cursor: None,
        include_entities: false,
    };

    for (k, v) in map {
        match k.as_text() {
            Some("type_filter") => {
                expr.type_filter = v.as_text().map(String::from);
            }
            Some("ref_filter") => {
                if let Some(bytes) = v.as_bytes() {
                    expr.ref_filter = Hash::from_bytes(bytes).ok();
                }
            }
            Some("path_filter") => {
                expr.path_filter = v.as_text().map(String::from);
            }
            Some("path_prefix") => {
                expr.path_prefix = v.as_text().map(String::from);
            }
            Some("limit") => {
                if let Some(ciborium::Value::Integer(i)) = Some(v) {
                    let n: i128 = (*i).into();
                    if n > 0 {
                        expr.limit = Some(n as u64);
                    }
                }
            }
            Some("cursor") => {
                expr.cursor = v.as_text().map(String::from);
            }
            Some("include_entities") => {
                expr.include_entities = v.as_bool().unwrap_or(false);
            }
            // Silently ignore Level 2 fields (field_filters, order_by, descending)
            _ => {}
        }
    }

    // Validate: field_filters requires type_filter (Level 2, but validate anyway)
    // (silently ignored at Level 1 per spec §5.2)

    Ok(expr)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_error_entity(code: &str, message: &str) -> Entity {
    let data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
        "code" => entity_ecf::text(code),
        "message" => entity_ecf::text(message)
    });
    Entity::new(entity_types::TYPE_ERROR, data).unwrap()
}

fn entity_to_inline(entity: &Entity) -> Value {
    let data_value: Value = ciborium::from_reader(entity.data.as_slice()).unwrap_or(Value::Null);
    Value::Map(vec![
        (
            entity_ecf::text("content_hash"),
            Value::Bytes(entity.content_hash.to_bytes().to_vec()),
        ),
        (entity_ecf::text("data"), data_value),
        (
            entity_ecf::text("type"),
            entity_ecf::text(&entity.entity_type),
        ),
    ])
}

fn build_envelope_result(root: Entity, included: HashMap<Hash, Entity>) -> Entity {
    let included_entries: Vec<_> = included
        .iter()
        .map(|(hash, entity)| {
            (
                Value::Bytes(hash.to_bytes().to_vec()),
                entity_to_inline(entity),
            )
        })
        .collect();

    let mut envelope_fields = vec![(entity_ecf::text("root"), entity_to_inline(&root))];
    if !included_entries.is_empty() {
        envelope_fields.push((entity_ecf::text("included"), Value::Map(included_entries)));
    }

    let data = entity_ecf::to_ecf(&Value::Map(envelope_fields));
    Entity::new(entity_types::TYPE_ENVELOPE, data)
        .expect("envelope entity creation should not fail")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use entity_handler::STATUS_OK;
    use entity_store::{MemoryContentStore, MemoryLocationIndex};

    fn setup() -> (
        Arc<QueryIndexes>,
        Arc<MemoryContentStore>,
        Arc<MemoryLocationIndex>,
        QueryHandler,
    ) {
        let content_store = Arc::new(MemoryContentStore::new());
        let location_index = Arc::new(MemoryLocationIndex::new());
        let indexes = Arc::new(QueryIndexes::new());
        let indexing = Arc::new(indexing::IndexingLocationIndex::new(
            location_index.clone() as Arc<dyn LocationIndex>,
            content_store.clone() as Arc<dyn ContentStore>,
            indexes.clone(),
        ));
        let handler = QueryHandler::new(
            indexes.clone(),
            content_store.clone() as Arc<dyn ContentStore>,
            indexing as Arc<dyn LocationIndex>,
            "test_peer".to_string(),
        );
        (indexes, content_store, location_index, handler)
    }

    fn put_entity(
        cs: &Arc<MemoryContentStore>,
        li: &Arc<MemoryLocationIndex>,
        indexes: &Arc<QueryIndexes>,
        path: &str,
        entity_type: &str,
        data_val: &str,
    ) -> Hash {
        let entity =
            Entity::new(entity_type, entity_ecf::to_ecf(&entity_ecf::text(data_val))).unwrap();
        let hash = cs.put(entity.clone()).unwrap();
        li.set(path, hash);
        indexes.add_entries_for_entity(path, &entity);
        hash
    }

    fn make_find_ctx(expr_data: Value) -> HandlerContext {
        let params =
            Entity::new("system/query/expression", entity_ecf::to_ecf(&expr_data)).unwrap();
        HandlerContext {
            handler_grant: None,
            caller_capability: None,
            execute: params.clone(),
            params,
            pattern: "test_peer/system/query".to_string(),
            suffix: String::new(),
            resource_target: None,
            author: None,
            request_id: "test".to_string(),
            operation: "find".to_string(),
            execute_fn: None,
            included: HashMap::new(),
            matching_grant: None,
            capability_hash: None,
            handler_grant_hash: None,
            bounds: None,
            is_external: false,
            reactive_trigger: false,
            session_peer_id: None,
        }
    }

    #[tokio::test]
    async fn test_find_by_type() {
        let (indexes, cs, li, handler) = setup();
        put_entity(&cs, &li, &indexes, "users/alice", "app/user", "alice");
        put_entity(&cs, &li, &indexes, "users/bob", "app/user", "bob");
        put_entity(&cs, &li, &indexes, "orders/o1", "app/order", "order1");

        let ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user")
        });
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let result_val: ciborium::Value =
            ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = result_val.as_map().unwrap();
        let total = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("total"))
            .unwrap()
            .1
            .as_integer()
            .unwrap();
        let total_val: i128 = total.into();
        assert_eq!(total_val, 2);
    }

    #[tokio::test]
    async fn test_find_with_path_prefix() {
        let (indexes, cs, li, handler) = setup();
        put_entity(
            &cs,
            &li,
            &indexes,
            "/test_peer/app/users/alice",
            "app/user",
            "alice",
        );
        put_entity(
            &cs,
            &li,
            &indexes,
            "/test_peer/app/users/bob",
            "app/user",
            "bob",
        );
        put_entity(
            &cs,
            &li,
            &indexes,
            "/test_peer/other/users/carol",
            "app/user",
            "carol",
        );

        let ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user"),
            "path_prefix" => entity_ecf::text("app/users/")
        });
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let result_val: ciborium::Value =
            ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = result_val.as_map().unwrap();
        let total: i128 = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("total"))
            .unwrap()
            .1
            .as_integer()
            .unwrap()
            .into();
        assert_eq!(total, 2);
    }

    #[tokio::test]
    async fn test_find_by_ref() {
        let (indexes, cs, li, handler) = setup();
        let target = Hash::compute("target", b"target_data");
        let ref_entity = Entity::new(
            "app/reference",
            entity_ecf::to_ecf(&entity_ecf::cbor_map! {
                "target" => Value::Bytes(target.to_bytes().to_vec())
            }),
        )
        .unwrap();
        let ref_hash = cs.put(ref_entity.clone()).unwrap();
        li.set("refs/r1", ref_hash);
        indexes.add_entries_for_entity("refs/r1", &ref_entity);

        let ctx = make_find_ctx(entity_ecf::cbor_map! {
            "ref_filter" => Value::Bytes(target.to_bytes().to_vec())
        });
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let result_val: ciborium::Value =
            ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = result_val.as_map().unwrap();
        let total: i128 = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("total"))
            .unwrap()
            .1
            .as_integer()
            .unwrap()
            .into();
        assert_eq!(total, 1);
    }

    #[tokio::test]
    async fn test_count() {
        let (indexes, cs, li, handler) = setup();
        put_entity(&cs, &li, &indexes, "users/alice", "app/user", "alice");
        put_entity(&cs, &li, &indexes, "users/bob", "app/user", "bob");

        let params = Entity::new(
            "system/query/expression",
            entity_ecf::to_ecf(&entity_ecf::cbor_map! {
                "type_filter" => entity_ecf::text("app/user")
            }),
        )
        .unwrap();
        let mut ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user")
        });
        ctx.operation = "count".to_string();
        ctx.params = params;
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let count: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let n: i128 = count.as_integer().unwrap().into();
        assert_eq!(n, 2);
    }

    #[tokio::test]
    async fn test_empty_query_rejected() {
        let (_indexes, _cs, _li, handler) = setup();
        let ctx = make_find_ctx(entity_ecf::cbor_map! {});
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_pagination() {
        let (indexes, cs, li, handler) = setup();
        for i in 0..5 {
            put_entity(
                &cs,
                &li,
                &indexes,
                &format!("users/user_{:02}", i),
                "app/user",
                &format!("user_{}", i),
            );
        }

        // Page 1: limit 2
        let ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user"),
            "limit" => entity_ecf::integer(2)
        });
        let result = handler.handle(&ctx).await.unwrap();
        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let has_more = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("has_more"))
            .unwrap()
            .1
            .as_bool()
            .unwrap();
        assert!(has_more);
        let cursor_val = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("cursor"))
            .unwrap()
            .1
            .as_text()
            .unwrap();
        let matches = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("matches"))
            .unwrap()
            .1
            .as_array()
            .unwrap();
        assert_eq!(matches.len(), 2);

        // Page 2: use cursor
        let ctx2 = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user"),
            "limit" => entity_ecf::integer(2),
            "cursor" => entity_ecf::text(cursor_val)
        });
        let result2 = handler.handle(&ctx2).await.unwrap();
        let val2: ciborium::Value = ciborium::from_reader(result2.result.data.as_slice()).unwrap();
        let map2 = val2.as_map().unwrap();
        let matches2 = map2
            .iter()
            .find(|(k, _)| k.as_text() == Some("matches"))
            .unwrap()
            .1
            .as_array()
            .unwrap();
        assert_eq!(matches2.len(), 2);
        let has_more2 = map2
            .iter()
            .find(|(k, _)| k.as_text() == Some("has_more"))
            .unwrap()
            .1
            .as_bool()
            .unwrap();
        assert!(has_more2);

        // Page 3: last page
        let cursor_val2 = map2
            .iter()
            .find(|(k, _)| k.as_text() == Some("cursor"))
            .unwrap()
            .1
            .as_text()
            .unwrap();
        let ctx3 = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user"),
            "limit" => entity_ecf::integer(2),
            "cursor" => entity_ecf::text(cursor_val2)
        });
        let result3 = handler.handle(&ctx3).await.unwrap();
        let val3: ciborium::Value = ciborium::from_reader(result3.result.data.as_slice()).unwrap();
        let map3 = val3.as_map().unwrap();
        let matches3 = map3
            .iter()
            .find(|(k, _)| k.as_text() == Some("matches"))
            .unwrap()
            .1
            .as_array()
            .unwrap();
        assert_eq!(matches3.len(), 1);
        let has_more3 = map3
            .iter()
            .find(|(k, _)| k.as_text() == Some("has_more"))
            .unwrap()
            .1
            .as_bool()
            .unwrap();
        assert!(!has_more3);
    }

    #[tokio::test]
    async fn test_include_entities() {
        let (indexes, cs, li, handler) = setup();
        put_entity(&cs, &li, &indexes, "users/alice", "app/user", "alice");

        let ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user"),
            "include_entities" => entity_ecf::bool_val(true)
        });
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(result.result.entity_type, entity_types::TYPE_ENVELOPE);
        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let has_included = map.iter().any(|(k, _)| k.as_text() == Some("included"));
        assert!(has_included, "envelope should contain included entities");
    }

    #[tokio::test]
    async fn test_glob_type_filter() {
        let (indexes, cs, li, handler) = setup();
        put_entity(&cs, &li, &indexes, "users/alice", "app/user", "alice");
        put_entity(&cs, &li, &indexes, "orders/o1", "app/order", "order1");
        put_entity(&cs, &li, &indexes, "system/cfg", "system/config", "cfg");

        let ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/*")
        });
        let result = handler.handle(&ctx).await.unwrap();
        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let total: i128 = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("total"))
            .unwrap()
            .1
            .as_integer()
            .unwrap()
            .into();
        assert_eq!(total, 2);
    }

    // --- Capability constraint tests ---

    #[tokio::test]
    async fn test_query_type_scope_filtering() {
        let (indexes, cs, li, handler) = setup();
        put_entity(&cs, &li, &indexes, "users/alice", "app/user", "alice");
        put_entity(&cs, &li, &indexes, "orders/o1", "app/order", "order1");

        // Grant with type_scope only allowing "app/user"
        let grant = entity_capability::GrantEntry {
            handlers: entity_capability::PathScope::new(vec!["*".into()]),
            resources: entity_capability::PathScope::new(vec!["*".into()]),
            operations: entity_capability::IdScope::new(vec!["*".into()]),
            peers: None,
            constraints: Some(std::collections::BTreeMap::from([(
                "type_scope".to_string(),
                ciborium::Value::Map(vec![(
                    ciborium::Value::Text("include".into()),
                    ciborium::Value::Array(vec![ciborium::Value::Text("app/user".into())]),
                )]),
            )])),
            allowances: None,
        };
        let cap = entity_capability::CapabilityToken {
            grants: vec![grant.clone()],
            granter: entity_capability::Granter::Single(entity_hash::Hash::zero()),
            grantee: entity_hash::Hash::zero(),
            parent: None,
            created_at: 0,
            expires_at: None,
            not_before: None,
            delegation_caveats: None,
        };

        // Query for exact type "app/user" — allowed by type_scope
        let mut ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user")
        });
        ctx.matching_grant = Some(grant.clone());
        ctx.caller_capability = Some(cap.clone());

        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let total: i128 = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("total"))
            .unwrap()
            .1
            .as_integer()
            .unwrap()
            .into();
        assert_eq!(total, 1); // only alice (app/user)

        // Query for "app/order" — blocked by type_scope (not in include list)
        let mut ctx2 = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/order")
        });
        ctx2.matching_grant = Some(grant.clone());
        ctx2.caller_capability = Some(cap.clone());
        let result2 = handler.handle(&ctx2).await.unwrap();
        assert_eq!(result2.status, STATUS_FORBIDDEN);

        // Query with glob "app/*" — rejected because glob is wider than type_scope
        let mut ctx3 = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/*")
        });
        ctx3.matching_grant = Some(grant);
        ctx3.caller_capability = Some(cap);
        let result3 = handler.handle(&ctx3).await.unwrap();
        assert_eq!(result3.status, STATUS_FORBIDDEN);
    }

    /// The local peer's own `system/peer` entity, for the cap's PR-8 granter
    /// frame. `filter_by_capability` fails CLOSED when it cannot resolve the
    /// granter, and a fixture whose granter is `Hash::zero()` against an empty
    /// `included` map is exactly that case — on the wire §5.2 has already
    /// resolved the same granter out of `envelope.included` and refused the
    /// dispatch if it could not, so a handler never sees an unresolvable one.
    fn granter_in_included() -> (entity_hash::Hash, Entity) {
        let kp = entity_crypto::Keypair::from_seed([7u8; 32]);
        let ent = entity_crypto::peer_entity_from_components(&kp.public_key_bytes())
            .expect("peer entity");
        (ent.content_hash, ent)
    }

    fn external_find_ctx(
        expr_data: Value,
        grants: Vec<entity_capability::GrantEntry>,
    ) -> HandlerContext {
        let (granter_hash, granter_entity) = granter_in_included();
        let mut ctx = make_find_ctx(expr_data);
        ctx.caller_capability = Some(entity_capability::CapabilityToken {
            grants,
            granter: entity_capability::Granter::Single(granter_hash),
            grantee: entity_hash::Hash::zero(),
            parent: None,
            created_at: 0,
            expires_at: None,
            not_before: None,
            delegation_caveats: None,
        });
        ctx.included.insert(granter_hash, granter_entity);
        // §6.3's authority is the caller's VERIFIED capability, which
        // `caller_capability` is on an inbound wire EXECUTE and nowhere else —
        // see `filter_by_capability`.
        ctx.is_external = true;
        ctx
    }

    fn match_paths(result: &HandlerResult) -> Vec<String> {
        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        map.iter()
            .find(|(k, _)| k.as_text() == Some("matches"))
            .map(|(_, v)| {
                v.as_array()
                    .unwrap()
                    .iter()
                    .map(|m| {
                        m.as_map()
                            .unwrap()
                            .iter()
                            .find(|(k, _)| k.as_text() == Some("path"))
                            .unwrap()
                            .1
                            .as_text()
                            .unwrap()
                            .to_string()
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// ⛔ **`EXTENSION-QUERY` §5.2 step 6b: every result is filtered with
    /// `check_path_permission`, which answers all dimensions from ONE grant
    /// entry — not with a resources-only scan across every grant the cap
    /// holds.**
    ///
    /// `find` is the widest enumerating consumer in the corpus, and the
    /// dimensions coming apart is what made it wide. The discriminating cap
    /// holds two grants that cross:
    ///
    /// | grant | handlers | operations | resources |
    /// |---|---|---|---|
    /// | G1 | `*` | `find` | `/{p}/users/*` |
    /// | G2 | `system/inbox` | `receive` | `/{p}/secret/*` |
    ///
    /// G2 authorizes nothing about a query — wrong handler, wrong operation —
    /// and its `resources` is the only thing the old filter looked at, so
    /// `/{p}/secret/*` was enumerated by a query G1 authorized. That is `F67`'s
    /// shape arrived at from a filter instead of a bypass: **an outcome
    /// reachable from more than one authority source, measured as their union.**
    ///
    /// Note which rows the previous test set could not separate: with a single
    /// broad grant, "any grant's resources" and "the matching grant's
    /// resources" give the same answer. The sources have to DISAGREE.
    ///
    /// **Mutation-verified:** restoring the `for grant in &cap.grants { if
    /// matches_scope(path, grant.resources…) { return true } }` loop puts
    /// `secret/s` back in the result — `["secret/s", "users/alice"]` against the
    /// expected `["users/alice"]` — with the control row green.
    #[tokio::test]
    async fn a_query_result_is_filtered_by_one_grant_not_the_union_of_all_grants() {
        let (indexes, cs, li, handler) = setup();
        put_entity(&cs, &li, &indexes, "users/alice", "app/user", "alice");
        put_entity(&cs, &li, &indexes, "secret/s", "app/user", "secret");

        let g1 = entity_capability::GrantEntry {
            handlers: entity_capability::PathScope::new(vec!["*".into()]),
            resources: entity_capability::PathScope::new(vec!["/test_peer/users/*".into()]),
            operations: entity_capability::IdScope::new(vec!["find".into(), "get".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        };
        let g2 = entity_capability::GrantEntry {
            handlers: entity_capability::PathScope::new(vec!["system/inbox".into()]),
            resources: entity_capability::PathScope::new(vec!["/test_peer/secret/*".into()]),
            operations: entity_capability::IdScope::new(vec!["receive".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        };

        let ctx = external_find_ctx(
            entity_ecf::cbor_map! { "type_filter" => entity_ecf::text("app/user") },
            vec![g1.clone(), g2],
        );
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(
            match_paths(&result),
            vec!["users/alice".to_string()],
            "§5.2 step 6b: only the path G1 covers — G2 authorizes no query"
        );

        // CONTROL: G1 alone still returns its own path. Without this the row
        // above passes against a filter that drops everything.
        let ctx = external_find_ctx(
            entity_ecf::cbor_map! { "type_filter" => entity_ecf::text("app/user") },
            vec![g1],
        );
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(
            match_paths(&result),
            vec!["users/alice".to_string()],
            "CONTROL: the in-grant path IS returned"
        );
    }

    /// The payoff of routing step 6b through `check_path_permission`: the
    /// `resources.exclude` arm and `0.8.2.21`'s **H1** arm arrive for free,
    /// because there is one implementation of the rule rather than a copy here.
    ///
    /// Row 1 is `CP-12a`'s class at `find` — the grant covers `users/*` and
    /// excludes one child; the query enumerates the subtree and must omit it.
    /// Row 2 is H1: an **unmatchable** exclude (`*/secret`, the plausible
    /// misspelling of `/*/secret`) excludes EVERYTHING, so the result is empty
    /// rather than silently unfiltered. Row 3 is the control the H1 vector
    /// demands — a well-formed exclude that still ALLOWS its sibling — because
    /// every row here is a denial and a filter that returns nothing passes both
    /// of the first two.
    ///
    /// ⚠ **Recorded because an unreachable-by-construction row looks identical
    /// to a toothless one from outside: this test stays GREEN under the
    /// union-scan mutation** that reddens its neighbour. With a single grant,
    /// *"any grant's resources"* and *"the matching grant, all dimensions"*
    /// return the same answer — which is exactly why the neighbour needs two
    /// grants that disagree. These rows are a **containment** pin: they fail if
    /// step 6b ever stops going through `check_path_permission` and starts
    /// re-implementing the exclude arms locally, which is the drift the one-call
    /// shape exists to prevent. The arms themselves have their teeth in
    /// `core/capability`.
    #[tokio::test]
    async fn the_query_filter_inherits_the_exclude_arms_including_h1() {
        let (indexes, cs, li, handler) = setup();
        put_entity(&cs, &li, &indexes, "users/alice", "app/user", "alice");
        put_entity(&cs, &li, &indexes, "users/secret", "app/user", "secret");

        let grant_with_exclude = |exclude: Vec<String>| entity_capability::GrantEntry {
            handlers: entity_capability::PathScope::new(vec!["*".into()]),
            resources: entity_capability::PathScope::with_exclude(
                vec!["/test_peer/users/*".into()],
                exclude,
            ),
            operations: entity_capability::IdScope::new(vec!["find".into(), "get".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        };

        let rows: Vec<(&str, Vec<String>, Vec<String>)> = vec![
            (
                "a well-formed exclude omits its own child (CP-12a at find)",
                vec!["/test_peer/users/secret".into()],
                vec!["users/alice".into()],
            ),
            (
                "an UNMATCHABLE exclude excludes everything (H1)",
                vec!["*/secret".into()],
                vec![],
            ),
            (
                "CONTROL: a well-formed exclude that matches nothing here still ALLOWS",
                vec!["/test_peer/users/nobody".into()],
                vec!["users/alice".into(), "users/secret".into()],
            ),
        ];

        let mut mismatches: Vec<String> = Vec::new();
        for (label, exclude, expected) in rows {
            let ctx = external_find_ctx(
                entity_ecf::cbor_map! { "type_filter" => entity_ecf::text("app/user") },
                vec![grant_with_exclude(exclude)],
            );
            let result = handler.handle(&ctx).await.unwrap();
            let got = match_paths(&result);
            if got != expected {
                mismatches.push(format!(
                    "[{}]: got {:?}, expected {:?}",
                    label, got, expected
                ));
            }
        }
        assert!(
            mismatches.is_empty(),
            "§5.2 step 6b + 0.8.2.21 H1:\n  {}",
            mismatches.join("\n  ")
        );
    }

    /// ⛔ **§6.3's handler FRAME (0.8.2.23 — K4/K5): `handler_pattern` is the
    /// handler that OWNS the operation, never the handler running the check.**
    ///
    /// Step 6b authorizes a **tree read**, so the frame is `system/tree`. This
    /// line passed `ctx.pattern` — `system/query`, the running handler — and the
    /// frame is tested UPSTREAM of every other dimension, so a wrong one is
    /// indistinguishable from a broken matcher. Both directions are driven here
    /// because it was wrong in both:
    ///
    /// - **row 1 — the wrong frame REFUSED a conformant caller.** A capability
    ///   split across `{system/query: find}` + `{system/tree: get}` is the exact
    ///   shape §6.3's own note measured: the `get` grant is discarded unread
    ///   (its `handlers` names `system/tree`, which no `system/query` frame
    ///   matches), and the surviving query grant then fails `operations` on
    ///   `get`. Every result dropped, with no dimension to attribute it to.
    /// - **row 2 — the wrong frame ADMITTED one it should not.** A caller whose
    ///   only grant names `system/query` — holding no tree grant at all — was
    ///   authorized for tree reads through this surface.
    ///
    /// **Why the pre-existing rows could not see it:** every other capability
    /// test in this module grants `handlers: ["*"]`, which covers `system/query`
    /// and `system/tree` alike. The two frames only disagree when the grant
    /// **names** a handler, which is why both rows below spell one out.
    ///
    /// **Mutation-verified, three mutations RUN, and the two rows are disjoint:**
    ///
    /// | mutation | row 1 | row 2 |
    /// |---|---|---|
    /// | `&ctx.pattern` (the defect) | RED — `[]` vs `["users/alice"]` | RED — `["users/alice"]` vs `[]` |
    /// | `"*"` (§6.3's forbidden permissive default) | RED — `[]` vs `["users/alice"]` | green |
    /// | — (the fix) | green | green |
    ///
    /// The defect's two rows redden in **opposite directions**, which is what
    /// says the fix discriminates rather than widens — a frame that merely
    /// widened would redden row 2 alone.
    ///
    /// ⚠ The `"*"` row is recorded because the prediction written here before it
    /// was run said the opposite (*"passes row 1 and fails row 2"*). It is wrong
    /// for a reason worth keeping: `"*"` is not a permissive frame at this
    /// matcher at all — `canonicalize("*")` is `/{local}/*`, and `matches_scope`
    /// compares it as a **value** against each grant's include patterns, so it
    /// matches a grant whose `handlers` is `*` and NO grant that names a handler.
    /// It fails closed here, not open. §6.3's "MUST NOT treat an absent or empty
    /// `handler_pattern` as match-all" is therefore a rule about a matcher that
    /// special-cases the value, which this one does not — stated so the next
    /// reader does not add a special case in order to have something to forbid.
    ///
    /// The rows are collected rather than asserted inline for the same reason a
    /// multi-row mutation is scoped: an inline row 1 short-circuits and reports
    /// nothing about row 2.
    #[tokio::test]
    async fn the_tree_read_filter_is_framed_by_the_owning_handler_not_the_running_one() {
        let (indexes, cs, li, handler) = setup();
        put_entity(&cs, &li, &indexes, "users/alice", "app/user", "alice");

        // The frame the running handler would supply, in the canonical form the
        // dispatcher resolves it to. Spelled absolutely so the two candidate
        // frames differ only in their last segment.
        const RUNNING: &str = "/test_peer/system/query";

        let grant = |handlers: &str, ops: Vec<&str>| entity_capability::GrantEntry {
            handlers: entity_capability::PathScope::new(vec![handlers.into()]),
            resources: entity_capability::PathScope::new(vec!["/test_peer/users/*".into()]),
            operations: entity_capability::IdScope::new(
                ops.into_iter().map(String::from).collect(),
            ),
            peers: None,
            constraints: None,
            allowances: None,
        };

        let drive = |grants: Vec<entity_capability::GrantEntry>| {
            let mut ctx = external_find_ctx(
                entity_ecf::cbor_map! { "type_filter" => entity_ecf::text("app/user") },
                grants,
            );
            ctx.pattern = RUNNING.to_string();
            ctx
        };

        // Both rows are collected rather than asserted in place: a multi-row
        // test short-circuits at its first failing assertion, and these two
        // redden in OPPOSITE directions under the same mutation. Asserting
        // inline would make the run report row 1 and stay silent about row 2,
        // which is the half that says the fix discriminates rather than widens.
        let rows: Vec<(&str, Vec<entity_capability::GrantEntry>, Vec<String>)> = vec![
            (
                // The caller holds the tree read in a SEPARATE grant, which is
                // the conformant way to hold it. Only the owning-handler frame
                // reaches it.
                "row 1 — `{system/query: find}` + `{system/tree: get}` is a conformant \
                 split and the `system/tree` grant MUST be the one consulted; under \
                 the running-handler frame it is discarded unread",
                vec![
                    grant(RUNNING, vec!["find"]),
                    grant("system/tree", vec!["get"]),
                ],
                vec!["users/alice".to_string()],
            ),
            (
                // The caller holds NO tree grant. The running-handler frame lets
                // a query-only grant authorize a tree read; the owning frame refuses.
                "row 2 — a grant naming only `system/query` authorizes no tree read, \
                 however wide its `resources`; under the running-handler frame it did",
                vec![grant(RUNNING, vec!["find", "get"])],
                Vec::new(),
            ),
        ];

        let mut mismatches: Vec<String> = Vec::new();
        for (label, grants, expected) in rows {
            let result = handler.handle(&drive(grants)).await.unwrap();
            let got = match_paths(&result);
            if got != expected {
                mismatches.push(format!("[{label}]: got {got:?}, expected {expected:?}"));
            }
        }
        assert!(
            mismatches.is_empty(),
            "§6.3 handler frame (0.8.2.23):\n  {}",
            mismatches.join("\n  ")
        );
    }

    #[tokio::test]
    async fn test_query_max_results_constraint() {
        let (indexes, cs, li, handler) = setup();
        for i in 0..10 {
            put_entity(
                &cs,
                &li,
                &indexes,
                &format!("users/u{:02}", i),
                "app/user",
                &format!("user{}", i),
            );
        }

        // Grant with max_results: 3
        let grant = entity_capability::GrantEntry {
            handlers: entity_capability::PathScope::new(vec!["*".into()]),
            resources: entity_capability::PathScope::new(vec!["*".into()]),
            operations: entity_capability::IdScope::new(vec!["*".into()]),
            peers: None,
            constraints: Some(std::collections::BTreeMap::from([(
                "max_results".to_string(),
                ciborium::Value::Integer(3.into()),
            )])),
            allowances: None,
        };

        let mut ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user")
        });
        ctx.matching_grant = Some(grant);

        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let matches = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("matches"))
            .unwrap()
            .1
            .as_array()
            .unwrap();
        assert_eq!(matches.len(), 3); // limited by max_results
        let has_more = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("has_more"))
            .unwrap()
            .1
            .as_bool()
            .unwrap();
        assert!(has_more);
    }

    #[tokio::test]
    async fn test_query_content_store_scope_requires_type_scope() {
        let (_indexes, _cs, _li, handler) = setup();

        // Grant with content_store scope (allowance) but no type_scope → should be 403
        let grant = entity_capability::GrantEntry {
            handlers: entity_capability::PathScope::new(vec!["*".into()]),
            resources: entity_capability::PathScope::new(vec!["*".into()]),
            operations: entity_capability::IdScope::new(vec!["*".into()]),
            peers: None,
            constraints: None,
            allowances: Some(std::collections::BTreeMap::from([(
                "scope".to_string(),
                ciborium::Value::Text("content_store".into()),
            )])),
        };

        let mut ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user")
        });
        ctx.matching_grant = Some(grant);

        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_FORBIDDEN);
    }

    // --- Multi-filter intersection tests ---

    #[tokio::test]
    async fn test_find_type_and_ref_intersection() {
        let (indexes, cs, li, handler) = setup();
        let target = entity_hash::Hash::compute("target", b"target_data");

        // Entity A: app/user, references target
        let e_a = Entity::new(
            "app/user",
            entity_ecf::to_ecf(&entity_ecf::cbor_map! {
                "name" => entity_ecf::text("alice"),
                "ref" => Value::Bytes(target.to_bytes().to_vec())
            }),
        )
        .unwrap();
        let h_a = cs.put(e_a.clone()).unwrap();
        li.set("users/alice", h_a);
        indexes.add_entries_for_entity("users/alice", &e_a);

        // Entity B: app/order, also references target
        let e_b = Entity::new(
            "app/order",
            entity_ecf::to_ecf(&entity_ecf::cbor_map! {
                "id" => entity_ecf::text("o1"),
                "user_ref" => Value::Bytes(target.to_bytes().to_vec())
            }),
        )
        .unwrap();
        let h_b = cs.put(e_b.clone()).unwrap();
        li.set("orders/o1", h_b);
        indexes.add_entries_for_entity("orders/o1", &e_b);

        // Query: type=app/user AND ref_filter=target → should only return alice
        let ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user"),
            "ref_filter" => Value::Bytes(target.to_bytes().to_vec())
        });
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let total: i128 = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("total"))
            .unwrap()
            .1
            .as_integer()
            .unwrap()
            .into();
        assert_eq!(total, 1);
    }

    #[tokio::test]
    async fn test_find_type_and_path_prefix_intersection() {
        let (indexes, cs, li, handler) = setup();
        put_entity(
            &cs,
            &li,
            &indexes,
            "/test_peer/team/eng/alice",
            "app/user",
            "alice",
        );
        put_entity(
            &cs,
            &li,
            &indexes,
            "/test_peer/team/sales/bob",
            "app/user",
            "bob",
        );
        put_entity(
            &cs,
            &li,
            &indexes,
            "/test_peer/team/eng/carol",
            "app/user",
            "carol",
        );

        // Query: type=app/user AND path_prefix=team/eng/
        let ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user"),
            "path_prefix" => entity_ecf::text("team/eng/")
        });
        let result = handler.handle(&ctx).await.unwrap();
        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let total: i128 = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("total"))
            .unwrap()
            .1
            .as_integer()
            .unwrap()
            .into();
        assert_eq!(total, 2); // alice and carol, not bob
    }

    // --- Edge cases ---

    #[tokio::test]
    async fn test_find_no_results() {
        let (_indexes, _cs, _li, handler) = setup();
        let ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/nonexistent")
        });
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let total: i128 = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("total"))
            .unwrap()
            .1
            .as_integer()
            .unwrap()
            .into();
        assert_eq!(total, 0);
        let has_more = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("has_more"))
            .unwrap()
            .1
            .as_bool()
            .unwrap();
        assert!(!has_more);
    }

    #[tokio::test]
    async fn test_unknown_operation() {
        let (_indexes, _cs, _li, handler) = setup();
        let mut ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user")
        });
        ctx.operation = "delete_all".to_string();
        let result = handler.handle(&ctx).await.unwrap();
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
}

// ---------------------------------------------------------------------------
// SQLite backend handler tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg(feature = "sqlite")]
mod sqlite_handler_tests {
    use super::*;
    use entity_handler::STATUS_OK;
    use entity_store::sqlite::SqliteStore;

    #[allow(clippy::type_complexity)] // test fixture tuple; naming it adds nothing
    fn setup_sqlite() -> (
        Arc<dyn QueryIndexStore>,
        Arc<dyn ContentStore>,
        Arc<dyn LocationIndex>,
        QueryHandler,
    ) {
        let store = SqliteStore::open_in_memory().unwrap();
        let content_store: Arc<dyn ContentStore> = Arc::new(store.content_store());
        let location_index: Arc<dyn LocationIndex> = Arc::new(store.location_index());
        let indexes: Arc<dyn QueryIndexStore> =
            Arc::new(crate::sqlite_index::SqliteQueryIndexes::new(store.connection()).unwrap());
        let indexing: Arc<dyn LocationIndex> = Arc::new(indexing::IndexingLocationIndex::new(
            location_index.clone(),
            content_store.clone(),
            indexes.clone(),
        ));
        let handler = QueryHandler::new(
            indexes.clone(),
            content_store.clone(),
            indexing,
            "test_peer".to_string(),
        );
        (indexes, content_store, location_index, handler)
    }

    fn put_entity_sqlite(
        cs: &Arc<dyn ContentStore>,
        li: &Arc<dyn LocationIndex>,
        indexes: &Arc<dyn QueryIndexStore>,
        path: &str,
        entity_type: &str,
        data_val: &str,
    ) {
        let entity =
            Entity::new(entity_type, entity_ecf::to_ecf(&entity_ecf::text(data_val))).unwrap();
        let hash = cs.put(entity.clone()).unwrap();
        li.set(path, hash);
        indexes.add_entries_for_entity(path, &entity);
    }

    fn make_find_ctx(expr_data: Value) -> HandlerContext {
        let params =
            Entity::new("system/query/expression", entity_ecf::to_ecf(&expr_data)).unwrap();
        HandlerContext {
            handler_grant: None,
            caller_capability: None,
            execute: params.clone(),
            params,
            pattern: "test_peer/system/query".to_string(),
            suffix: String::new(),
            resource_target: None,
            author: None,
            request_id: "test".to_string(),
            operation: "find".to_string(),
            execute_fn: None,
            included: HashMap::new(),
            matching_grant: None,
            capability_hash: None,
            handler_grant_hash: None,
            bounds: None,
            is_external: false,
            reactive_trigger: false,
            session_peer_id: None,
        }
    }

    fn extract_total(result: &HandlerResult) -> i128 {
        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        map.iter()
            .find(|(k, _)| k.as_text() == Some("total"))
            .unwrap()
            .1
            .as_integer()
            .unwrap()
            .into()
    }

    #[tokio::test]
    async fn test_sqlite_find_by_type() {
        let (indexes, cs, li, handler) = setup_sqlite();
        put_entity_sqlite(&cs, &li, &indexes, "users/alice", "app/user", "alice");
        put_entity_sqlite(&cs, &li, &indexes, "users/bob", "app/user", "bob");
        put_entity_sqlite(&cs, &li, &indexes, "orders/o1", "app/order", "order1");

        let ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user")
        });
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(extract_total(&result), 2);
    }

    #[tokio::test]
    async fn test_sqlite_find_glob() {
        let (indexes, cs, li, handler) = setup_sqlite();
        put_entity_sqlite(&cs, &li, &indexes, "users/alice", "app/user", "alice");
        put_entity_sqlite(&cs, &li, &indexes, "orders/o1", "app/order", "order1");
        put_entity_sqlite(&cs, &li, &indexes, "cfg/x", "system/config", "x");

        let ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/*")
        });
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(extract_total(&result), 2);
    }

    #[tokio::test]
    async fn test_sqlite_count() {
        let (indexes, cs, li, handler) = setup_sqlite();
        put_entity_sqlite(&cs, &li, &indexes, "users/a", "app/user", "a");
        put_entity_sqlite(&cs, &li, &indexes, "users/b", "app/user", "b");
        put_entity_sqlite(&cs, &li, &indexes, "users/c", "app/user", "c");

        let mut ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user")
        });
        ctx.operation = "count".to_string();
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        let count: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let n: i128 = count.as_integer().unwrap().into();
        assert_eq!(n, 3);
    }

    #[tokio::test]
    async fn test_sqlite_pagination() {
        let (indexes, cs, li, handler) = setup_sqlite();
        for i in 0..5 {
            put_entity_sqlite(
                &cs,
                &li,
                &indexes,
                &format!("u/u{:02}", i),
                "app/user",
                &format!("u{}", i),
            );
        }

        let ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user"),
            "limit" => entity_ecf::integer(2)
        });
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let matches = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("matches"))
            .unwrap()
            .1
            .as_array()
            .unwrap();
        assert_eq!(matches.len(), 2);
        let has_more = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("has_more"))
            .unwrap()
            .1
            .as_bool()
            .unwrap();
        assert!(has_more);
        assert_eq!(extract_total(&result), 5);
    }

    #[tokio::test]
    async fn test_sqlite_find_by_ref() {
        let (indexes, cs, li, handler) = setup_sqlite();
        let target = entity_hash::Hash::compute("target", b"target_data");
        let entity = Entity::new(
            "app/reference",
            entity_ecf::to_ecf(&entity_ecf::cbor_map! {
                "target" => Value::Bytes(target.to_bytes().to_vec())
            }),
        )
        .unwrap();
        let hash = cs.put(entity.clone()).unwrap();
        li.set("refs/r1", hash);
        indexes.add_entries_for_entity("refs/r1", &entity);

        let ctx = make_find_ctx(entity_ecf::cbor_map! {
            "ref_filter" => Value::Bytes(target.to_bytes().to_vec())
        });
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(extract_total(&result), 1);
    }

    #[tokio::test]
    async fn test_sqlite_include_entities() {
        let (indexes, cs, li, handler) = setup_sqlite();
        put_entity_sqlite(&cs, &li, &indexes, "users/alice", "app/user", "alice");

        let ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user"),
            "include_entities" => entity_ecf::bool_val(true)
        });
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(result.result.entity_type, entity_types::TYPE_ENVELOPE);
        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let has_included = map.iter().any(|(k, _)| k.as_text() == Some("included"));
        assert!(has_included, "envelope should contain included entities");
    }
}
