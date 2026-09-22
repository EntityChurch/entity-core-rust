//! Serving-side scope predicates for the `http-poll` content-by-hash
//! route.
//!
//! Per the serving-mode content-scope ruling
//! §1.2: the route's `in_scope(H)` predicate is **the lever** —
//! request-side auth is always hash-knowledge, serving-side scope is
//! where the operator decides which hashes the route answers for. The
//! handler shape is identical across predicates; only the predicate
//! swaps. v1 ships [`NamespaceScope`] (the recommended default per
//! §1.2 — "content-namespace, ship-first"); closure-scope and
//! whole-store land as additional impls without touching the handler.
//!
//! **T4 mitigation (ruling §1.3):** the route returns an identical
//! `404` for both "out of scope" and "not held," so the predicate
//! result is never directly observable as a presence oracle. Honor
//! that contract in any new predicate impl: return `Ok(false)` for
//! anything you don't want to serve, never return an error that the
//! caller might leak as 4xx vs 5xx.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use entity_capability::CapabilityToken;
use entity_hash::Hash;

use crate::PeerShared;

/// The serving-side scope contract. Implementations decide which
/// hashes the content-by-hash route serves **and** which paths the
/// tree-get route serves. Same scope object, two faces — per arch
/// ruling F-PY-12: "the published set has a tree-face
/// (which paths resolve) and a content-face (which hashes resolve),
/// same serve_scope." At the poll boundary there's no protocol cap,
/// so the served scope IS the auth on both faces.
///
/// **Amendment 5 (§6.5.6) — `serve_scope` is a capability token.**
/// The spec normative posture is that `serve_scope` is a literal
/// `system/capability` token evaluated by the same cap evaluator the
/// live-EXECUTE surface uses (`check_permission` / `check_path_permission`)
/// — one ACL machinery, structurally no drift. [`CapTokenScope`] is
/// the recommended-default impl that wraps a `CapabilityToken` and
/// satisfies this contract by construction.
///
/// **Non-`CapTokenScope` impls are a SECOND ACL machinery.** Other
/// `ScopePredicate` impls (closure-walk, federated lookups,
/// whole-store) are valid as implementation extension points BUT MUST
/// be kept in sync with the operator's live-EXECUTE cap set by
/// hand. Use them only when the cap-token shape genuinely cannot
/// express the desired scope; for ordinary published-set serving, use
/// [`CapTokenScope`] and let the cap be the audit log.
///
/// The trait is async because some predicate impls (closure-walk,
/// federated lookups) may need to traverse tree state that isn't
/// strictly synchronous — though the v1 [`NamespaceScope`] is a
/// trivial string-prefix / single-LocationIndex-lookup check.
#[async_trait]
pub trait ScopePredicate: Send + Sync {
    /// **Content-face.** Return `Ok(true)` iff `hash` is in the
    /// published set the operator configured for this listener.
    /// `Ok(false)` for out-of-scope (the canonical "no, don't serve
    /// this" answer). `Err` is reserved for genuine infrastructure
    /// failures (storage errors, lock poison) — never use it for
    /// "this hash isn't served," which is `Ok(false)` per T4.
    async fn in_scope(&self, hash: &Hash, shared: &Arc<PeerShared>) -> Result<bool, ScopeError>;

    /// **Tree-face.** Return `Ok(true)` iff `absolute_path` is
    /// within the published set's tree footprint. Used by the
    /// `GET /tree/{path}` poll route. Per F-PY-12: published-scope-
    /// gated, NOT "always 501." Default impl returns `Ok(false)`
    /// (no tree-face by default) — predicate impls that have a
    /// natural path-domain answer override.
    ///
    /// Same T4 contract as `in_scope`: `Ok(false)` for out-of-scope;
    /// `Err` only for infrastructure failures. The caller maps both
    /// `Ok(false)` and not-held into an identical 404.
    async fn in_scope_path(
        &self,
        _absolute_path: &str,
        _shared: &Arc<PeerShared>,
    ) -> Result<bool, ScopeError> {
        Ok(false)
    }

    /// Short human-readable identifier for logging / profile-entity
    /// metadata. e.g. `"namespace(system/content/public)"` or
    /// `"whole-store"`.
    fn describe(&self) -> String;
}

/// Errors a [`ScopePredicate`] may return. Kept intentionally small;
/// per T4 a normal "this hash isn't served" answer is `Ok(false)`,
/// not an error.
#[derive(Debug, thiserror::Error)]
pub enum ScopeError {
    #[error("scope storage error: {0}")]
    Storage(String),
}

/// Content-mount scope — serves any hash bound at the EXTENSION-
/// CONTENT mount label under any peer-id top-level in **this local
/// view** of the universal address space (V7 §1.4).
///
/// **The universal-tree model this implements.** Every peer holds a
/// complete local-scoped view of the universal tree. A peer may
/// write into ANY `/{pid}/...` path in their own local view — that's
/// a cache of what they hold about each peer-id's subtree. The
/// keyholder for `{pid}` is the only authority for what's TRUE about
/// `{pid}`; the local peer is the authority for what they choose to
/// CACHE in their own view. The content store is universal (just
/// `hash → bytes`, no namespaces); content-mount labels like
/// `system/content/{ns}` exist only so that cap grants — which are
/// tree-path-keyed — can cover content-store access.
///
/// **What `NamespaceScope("system/content/public")` means at this
/// serving listener.** "Expose any hash bound at
/// `/{any_pid}/system/content/public/{hex(H)}` in my local view."
/// Peer-wildcard *over what I locally hold*, not a claim that the
/// mount label is symmetric across peers — each peer's `public`
/// subtree is their own. If the local view caches a foreign peer's
/// public-namespace binding (e.g. because the operator runs as a
/// mirror), this scope surfaces it; if it doesn't, it doesn't.
/// Authority for content remains the hash itself (content-addressed
/// verify-by-rehash) plus whatever signed manifest is published.
///
/// **For the "serve any stored hash regardless of tree placement"
/// case**, use [`CapTokenScope`] with a wide cap or wait on the
/// `whole-store` explicit-opt-in shape (§6.5.6).
pub struct NamespaceScope {
    /// Content-mount path WITHOUT a leading `/` or trailing `/` —
    /// e.g., `"system/content/public"`. At check time the full
    /// binding path scanned is `/{any_pid}/{namespace}/{hex(H)}`
    /// across the LocationIndex.
    namespace: String,
}

impl NamespaceScope {
    /// Construct a namespace-scope predicate. `namespace` is the
    /// content namespace path (e.g., `"system/content/public"`); it
    /// MUST NOT include a leading `/` or a trailing `/`. The
    /// LocationIndex lookup uses the local peer's ID as the
    /// top-level segment.
    pub fn new(namespace: impl Into<String>) -> Self {
        let mut ns = namespace.into();
        // Tolerate operator-provided leading/trailing slashes; the
        // path we BUILD at check time is precise.
        ns = ns.trim_matches('/').to_string();
        Self { namespace: ns }
    }

    /// The configured namespace (without slashes).
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
}

#[async_trait]
impl ScopePredicate for NamespaceScope {
    /// Content-face per universal-tree-semantics: `H` is in scope iff
    /// **any** peer-id has a binding at `/{pid}/{namespace}/{hex(H)}`.
    /// Walks `location_index.list("/")` once per query; acceptable for
    /// in-memory stores at any plausible scale. A reverse hash→paths
    /// index would make this O(1) but is not load-bearing.
    async fn in_scope(&self, hash: &Hash, shared: &Arc<PeerShared>) -> Result<bool, ScopeError> {
        let hex_h = super::hex_encode(&hash.to_bytes());
        // Universal-tree reading: ANY peer's `/{pid}/{namespace}/{hex(H)}`
        // satisfies. We can't enumerate peer-ids without walking the
        // store, but the suffix is invariant — scan for any binding
        // whose path ends with `/{namespace}/{hex_h}` and starts with
        // `/{some_pid}/` followed by `{namespace}/`.
        let suffix = format!("/{}/{}", self.namespace, hex_h);
        for entry in shared.location_index.list("/") {
            if !entry.path.ends_with(&suffix) {
                continue;
            }
            // Confirm the structure is `/{pid}/{namespace}/{hex_h}`:
            // the part before the suffix MUST be just `/{pid}` (no
            // extra segments). This rejects e.g.
            // `/{pid}/something/system/content/public/{hex_h}` where
            // the binding is deeper than the namespace anchor.
            let head = &entry.path[..entry.path.len() - suffix.len()];
            // `head` is `/{pid}`. It must start with `/`, have no
            // further `/`, and be non-empty.
            if !head.starts_with('/') {
                continue;
            }
            if head[1..].contains('/') {
                continue;
            }
            if head.len() <= 1 {
                continue;
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// Tree-face per universal-tree-semantics: a path `p` is
    /// reachable iff it matches the pattern `/*/{namespace}/...` OR
    /// is an ancestor of any such pattern (so a listing walk from
    /// `/` down to in-scope content surfaces correctly).
    ///
    /// Reading B fix (per audit): foreign peer-ids' subtrees
    /// surface in `peers.list` when they contain in-scope content,
    /// matching the cohort `multi_peer_publish_via_tree_put` test.
    ///
    /// Strict leaf-vs-ancestor disambiguation falls out at the
    /// LocationIndex lookup in `render_leaf` — unbound ancestors
    /// return `None` and yield identical 404 to not-held (T4).
    async fn in_scope_path(
        &self,
        absolute_path: &str,
        _shared: &Arc<PeerShared>,
    ) -> Result<bool, ScopeError> {
        // Universal root is always reachable if anything is published.
        if absolute_path == "/" {
            return Ok(true);
        }

        // Split `absolute_path` into `["", pid_or_anchor, rest...]`.
        // Reject if it doesn't start with `/`.
        let trimmed = match absolute_path.strip_prefix('/') {
            Some(t) => t,
            None => return Ok(false),
        };

        // Segment 0 is the peer-id (or another reserved top-level
        // word; for the purposes of scope, anything in segment 0
        // *could* be a peer-id holding in-scope namespace). Reject
        // empty (which would mean `absolute_path == "/"`, already
        // handled).
        let (seg0, tail) = match trimmed.find('/') {
            Some(i) => (&trimmed[..i], &trimmed[i + 1..]),
            None => (trimmed, ""),
        };
        if seg0.is_empty() {
            return Ok(false);
        }

        // Ancestor case: `p` is `/{pid}` (no namespace suffix yet).
        // Any peer-id is potentially in scope under the universal
        // reading; surface so that descending walks can reach in-
        // scope content.
        if tail.is_empty() {
            return Ok(true);
        }

        // Compare `tail` against the configured namespace.
        if tail == self.namespace {
            // Exact anchor: `/{pid}/{namespace}` → in scope.
            return Ok(true);
        }
        if tail.starts_with(&format!("{}/", self.namespace)) {
            // Descendant of the namespace anchor.
            return Ok(true);
        }
        if self.namespace.starts_with(&format!("{}/", tail)) {
            // Ancestor of the namespace (tail is a path-prefix-of-
            // namespace, e.g. tail = "system" when namespace =
            // "system/content/public"). Surfaces intermediate
            // listings on the walk from `/{pid}` down to the
            // namespace anchor.
            return Ok(true);
        }
        Ok(false)
    }

    fn describe(&self) -> String {
        format!("namespace(/*/{})", self.namespace)
    }
}

// ===========================================================================
// CapTokenScope — Amendment-5 recommended default
// ===========================================================================

/// `serve_scope` as a capability token (EXTENSION-NETWORK §6.5.6
/// Amendment 5). Wraps a [`CapabilityToken`] and routes BOTH faces
/// through `entity_capability::check_permission` — the same evaluator
/// the live-EXECUTE surface uses for `system/tree:get`. This is the
/// **one-ACL-machinery** posture the spec mandates as normative.
///
/// **Tree-face.** `in_scope_path(p)` ⇔ the cap permits
/// `get` on resource `p` against handler `system/tree`. Out-of-scope
/// paths receive identical 404 to not-held (T4).
///
/// **Content-face.** `in_scope(H)` walks the cap's resource includes
/// and asks "does any include namespace bind H?" — i.e., §6.4.2 Hash
/// Tree Presence within the cap's reach. For each include pattern
/// shaped like `/{pid}/{ns}/*`, derive `{ns}` and check
/// LocationIndex for `/{pid}/{ns}/{hex33(H)}`.
///
/// **The cap IS the publish contract.** What you put in the cap is
/// what gets served; nothing else. Audit by inspecting the cap;
/// revoke by re-rendering against a smaller one.
pub struct CapTokenScope {
    cap: CapabilityToken,
}

impl CapTokenScope {
    /// Wrap a published-set capability token. The token's resource
    /// includes are the authoritative published-set membership.
    pub fn new(cap: CapabilityToken) -> Self {
        Self { cap }
    }

    /// The wrapped cap token (for inspection / audit).
    pub fn cap(&self) -> &CapabilityToken {
        &self.cap
    }

    /// Does the published cap permit `system/tree:get` on this **concrete**
    /// path? One evaluator for both faces — the content face resolves a hash to
    /// a candidate bind path and asks this; the tree face asks it directly.
    ///
    /// Everything the decision needs is in `check_permission`: all four
    /// dimensions from one grant entry (§5.2), both `exclude` arrays, and
    /// 0.8.2.21's H1 arm on each. A hand-written predicate over
    /// `handlers.include` is how the content face came to serve a namespace the
    /// cap excluded — see `in_scope`.
    ///
    /// `granter == local` here by construction: a published-set cap is minted by
    /// the publishing peer for its own surface, so the two PR-8 frames coincide
    /// and passing `local_peer_id` twice is the honest call, not a shortcut.
    fn permits_tree_get(&self, absolute_path: &str, local_peer_id: &str) -> bool {
        let target = entity_capability::ResourceTarget {
            targets: vec![absolute_path.to_string()],
            exclude: vec![],
        };
        entity_capability::check_permission(
            "get",
            "system/tree",
            local_peer_id,
            Some(&target),
            &self.cap,
            local_peer_id,
        )
    }
}

#[async_trait]
impl ScopePredicate for CapTokenScope {
    /// Content-face per §6.5.6: §6.4.2 Hash Tree Presence within the
    /// cap's reach. For each include namespace, check if there's a
    /// binding at `/{ns}/{hex33(H)}`.
    async fn in_scope(&self, hash: &Hash, shared: &Arc<PeerShared>) -> Result<bool, ScopeError> {
        let local_pid = shared.keypair.peer_id();
        let hex_h = super::hex_encode(&hash.to_bytes());

        for grant in &self.cap.grants {
            for pat in &grant.resources.include {
                // A malformed pattern can't project to a namespace — it
                // canonicalizes to NEVER_MATCH (§5.4), which has no `/*`
                // suffix and so falls out at the `strip_suffix` below.
                let canon = entity_capability::canonicalize(pat, local_pid.as_str());
                // Derive the namespace prefix from a `prefix/*`
                // pattern; exact patterns aren't a content-namespace.
                let ns_prefix = match canon.strip_suffix("/*") {
                    Some(p) => p.to_string(),
                    None => continue,
                };
                let bind_path = format!("{}/{}", ns_prefix, hex_h);
                if shared.location_index.get(&bind_path).is_none() {
                    continue;
                }
                // ⛔ **The grant loop ENUMERATES candidate namespaces; the
                // decision is the real evaluator's.** This arm used to decide
                // membership from `grant_allows_tree_get` — an open-coded
                // handler/operation scope test comparing `h == "*" || h ==
                // "system/tree"` — with `resources.exclude` never read at all.
                // Both halves were fail-open on the content face, which has no
                // second layer behind it: a published cap whose handlers
                // `exclude` was *patterned* (`system/*`) or **unmatchable**
                // (`*/tree`, which 0.8.2.21 H1 makes exclude EVERYTHING) passed
                // the literal test and served the namespace anyway. Asking
                // `check_permission` about the concrete `bind_path` answers all
                // four dimensions from one grant entry (§5.2) and carries the H1
                // arms, and it is the same evaluator the tree face and the live
                // EXECUTE surface use — so the three cannot drift.
                if self.permits_tree_get(&bind_path, local_pid.as_str()) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Tree-face per §6.5.6: cap permits `system/tree:get` on the
    /// concrete path. Drift impossible — same evaluator the live
    /// surface uses.
    ///
    /// Amendment-5 listing-discovery: a path is also reachable if
    /// it is an **ancestor** of any cap-include pattern (so a
    /// consumer can list from the universal-tree root down to
    /// in-scope content). The strict leaf-vs-ancestor distinction
    /// falls out at the LocationIndex lookup in `render_leaf`.
    async fn in_scope_path(
        &self,
        absolute_path: &str,
        shared: &Arc<PeerShared>,
    ) -> Result<bool, ScopeError> {
        let local_pid = shared.keypair.peer_id();

        // Direct cap eval — same evaluator the live surface uses.
        if self.permits_tree_get(absolute_path, local_pid.as_str()) {
            return Ok(true);
        }

        // Ancestor check: any cap include whose prefix sits under
        // `absolute_path/`? Universal root `/` is reachable as long
        // as any include exists.
        for grant in &self.cap.grants {
            if !grant_allows_tree_get(grant, local_pid.as_str()) {
                continue;
            }
            for pat in &grant.resources.include {
                // A malformed pattern can't extend reachability: NEVER_MATCH
                // (§5.4) is a single segment that is nobody's ancestor, so the
                // two prefix tests below both fail on it.
                let canon = entity_capability::canonicalize(pat, local_pid.as_str());
                if canon == entity_capability::NEVER_MATCH {
                    continue;
                }
                let inc_prefix = canon.strip_suffix("/*").unwrap_or(&canon).to_string();
                if absolute_path == "/" && !inc_prefix.is_empty() {
                    return Ok(true);
                }
                if !absolute_path.is_empty()
                    && inc_prefix.starts_with(&format!("{}/", absolute_path))
                {
                    return Ok(true);
                }
            }
        }

        // Universal-tree top-level arm — the same convention [`NamespaceScope`]
        // and [`ClosureScope`] carry, and Go's `serveAllPeersListing` hardcodes:
        // a bare `/{peer_id}` is reachable whatever the cap holds, so
        // `peers.list` enumerates every peer-id the local view binds under. The
        // ancestor arm above only reaches the *local* peer-id (includes
        // canonicalize against `local_pid`), so without this a foreign peer-id
        // vanished from `peers.list` under cap scope alone — exactly the
        // divergence `peers_list_surfaces_other_peer` caught between the other
        // two predicates. The cap still governs everything below: each child
        // goes back through this predicate and `render_leaf` resolves the
        // binding, so an out-of-cap leaf 404s identically to not-held (T4).
        Ok(is_bare_top_level_segment(absolute_path))
    }

    fn describe(&self) -> String {
        format!(
            "cap-token({} grants, grantee={})",
            self.cap.grants.len(),
            // Render grantee as a short hash hex prefix for logs.
            &super::hex_encode(&self.cap.grantee.to_bytes())[..16],
        )
    }
}

/// Is `path` exactly one non-empty top-level segment — `/{peer_id}`, with no
/// trailing slash and no further segments?
fn is_bare_top_level_segment(path: &str) -> bool {
    match path.strip_prefix('/') {
        Some(rest) => !rest.is_empty() && !rest.contains('/'),
        None => false,
    }
}

/// Does this grant entry admit `system/tree:get` at all? Used **only** to skip
/// grants that cannot contribute an ancestor for listing-descent — the reachable
/// decision itself is [`CapTokenScope::permits_tree_get`].
///
/// ⛔ **Call the scope matchers; do not re-spell them.** This was an open-coded
/// literal test (`h == "*" || h == "system/tree"`, and an `exclude` scan for the
/// same two spellings), which is the §6.3/G-3 shape both our sibling seats swept
/// on 2026-09-11: a *patterned* exclude (`system/*`) was invisible to it, and so
/// was an **unmatchable** one, which 0.8.2.21's H1 makes exclude EVERYTHING. It
/// also read `include` too narrowly in the other direction — a grant of
/// `handlers: {include: ["system/*"]}` does grant `system/tree` and was being
/// skipped. `matches_scope` (path-scope, §5.4 — handlers) and `matches_id_scope`
/// (id-scope, §5.2 — operations) are the one implementation of each rule.
fn grant_allows_tree_get(grant: &entity_capability::GrantEntry, local_peer_id: &str) -> bool {
    entity_capability::matches_scope(
        "system/tree",
        &grant.handlers.include,
        &grant.handlers.exclude,
        local_peer_id,
    ) && entity_capability::matches_id_scope(
        "get",
        &grant.operations.include,
        &grant.operations.exclude,
    )
}

// ===========================================================================
// ClosureScope — closure-of-signed-root (NETWORK §6.5.6 Amendment 10)
// ===========================================================================

/// Serving scope for a publisher that advertises `signed_pointer`
/// (PROPOSAL-PEER-MANIFEST-STATIC-HANDSHAKE). Amendment 10 (NETWORK §6.5.6):
/// when a signed root is published, the served set MUST cover the **transitive
/// trie-node closure reachable from `published-root.root_hash`** — the root
/// node, every interior sub-node, every leaf-bound value, plus the
/// `published-root` entity itself and its authenticating signature.
///
/// Why this is the floor and namespace-scope is not: CHAMP trie interior nodes
/// are hash-linked, not path-bound (V7 §1.7). A `NamespaceScope` only serves
/// hashes bound under a content path, so `CONTENT_GET(root_hash)` 404s and a
/// consumer's §1.1 walk-from-signed-root halts before the first node. This
/// predicate derives its membership from the live published-root head, so it
/// tracks the publisher automatically with no operator-maintained cap set.
///
/// **Content-face** (`in_scope`): hash ∈ {head, signature, trie-closure}.
///
/// **Tree-face** (`in_scope_path`): a path is served iff the host's binding at
/// that path resolves to a closure hash — which is exactly the signature
/// invariant-pointer leaf (`system/signature/{hex(head)}`, the surface the
/// outbound dialer resolves per V7 §5.2) and the published tree's path
/// bindings — **or** it is an ancestor of such a path. The ancestor arm is
/// what the §6.5.3.1 listing routes stand on: `{prefix}.list`, `{peer_id}.list`
/// and `peers.list` all address prefixes that carry no binding of their own, so
/// a leaf-only predicate 404s every listing under closure scope. (It did:
/// `serving_mode`'s eleven listing checks were `SKIP`ped behind
/// `seed_republished` and only became reachable once the republish landed.)
/// Same convention as [`NamespaceScope`] and Go's `ClosureScope.InScopePath`.
/// Leaf-vs-ancestor stays strict at the request: `render_leaf` looks the
/// binding up and an unbound ancestor 404s identically to not-held (T4).
///
/// The consumer re-verifies every fetched body by hash regardless (§1.1), so a
/// host binding an extra path to a closure hash gains nothing.
///
/// Membership is memoized and keyed by the head hash, so the trie is re-walked
/// only when the publisher advances the head. The ancestor set is built in the
/// same pass — one index scan — because the listing route asks the tree-face
/// once per candidate child, and re-deriving it per query would make a single
/// listing O(children × tree).
pub struct ClosureScope {
    cache: Mutex<ClosureCache>,
}

/// How many superseded heads keep their §1.1 verify-cycle anchors in scope.
///
/// A serving-window policy, not a wire value — core-go retains 16 and
/// core-py 64, and the cohort deliberately did not converge them. 16 is taken
/// here for go's reason: a head advance retains two hashes, so the whole ring is
/// 32 anchors, and a consumer that has not finished a two-fetch cycle across 16
/// republishes is not in a race, it is stalled.
const RETAINED_HEADS: usize = 16;

#[derive(Default)]
struct ClosureCache {
    current: Option<ClosureSnapshot>,
    /// Superseded head hashes, oldest first, bounded by [`RETAINED_HEADS`].
    /// See [`ClosureScope::refresh`] for what this is defending.
    retired_heads: VecDeque<Hash>,
}

struct ClosureSnapshot {
    head: Hash,
    members: HashSet<Hash>,
    /// Every path whose binding is a closure member, plus every ancestor of
    /// one, plus the universal root `/` when the set is non-empty.
    paths: HashSet<String>,
}

impl ClosureScope {
    /// A closure scope tracking this listener's published-root head.
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(ClosureCache::default()),
        }
    }

    /// Bring `self.cache` into agreement with the current published-root head.
    /// Cheap when the head is unchanged (one LocationIndex lookup + a compare);
    /// re-walks the trie only on head advance. Clears the cache when nothing is
    /// published (the route then serves nothing — identical 404, T4).
    ///
    /// ⛔ **A head advance must not evict the anchors of the head a consumer is
    /// mid-cycle on (NETWORK §1.1 — the CONSUMER-SIDE window of the
    /// published-root verify race).** A consumer's verify cycle is **two**
    /// fetches: `MANIFEST_GET` returns head *N*, then it fetches *N*'s signature
    /// and verifies before walking anything. Recomputing this closure on root
    /// change (Amendment 10) used to replace the snapshot wholesale, so a
    /// republish landing between those two fetches dropped *N*'s signature —
    /// and *N* itself — out of scope and the second fetch 404'd. The consumer
    /// cannot distinguish that from a publisher serving an unsigned root, which
    /// is the one thing the signature exists to rule out, so it fails the cycle
    /// rather than retrying.
    ///
    /// The defence is a bounded ring of superseded heads whose two anchors stay
    /// in `members`. Because `paths` is *projected* from `members` by the index
    /// scan below, this covers **both faces** in one place — the content face
    /// (`content/{hex}`) and the tree-path face, which is the one that actually
    /// bites here: `signature_url` addresses the signature at the invariant
    /// pointer path `/{peer}/system/signature/{hex}`, not by content hash.
    ///
    /// ⚠ **What this does NOT retain, stated rather than left to be
    /// rediscovered:** the superseded head's *trie closure*. Structural sharing
    /// means the great majority of a previous root's nodes are still members of
    /// the new one, so a consumer walking the HAMT is very unlikely to miss —
    /// but "unlikely" is not "cannot," and retaining whole closures is unbounded
    /// memory for a serving window. core-go's `recentSigs` carries the same
    /// residual; it is the anchors that are the measured failure, and this is
    /// the same shape both other seats ship.
    fn refresh(&self, shared: &Arc<PeerShared>) {
        let peer_id = shared.peer_id.as_str();
        let head = shared
            .location_index
            .get(&crate::published_root::published_root_head_path(peer_id));
        let mut cache = self.cache.lock().unwrap();
        let head = match head {
            Some(h) => h,
            None => {
                // The retired ring is deliberately KEPT. Nothing published is a
                // reason to serve no *current* root; it is not a reason to
                // strand a consumer who is mid-cycle on the head that was there
                // a moment ago.
                cache.current = None;
                return;
            }
        };
        if cache.current.as_ref().map(|s| s.head) == Some(head) {
            return;
        }
        if let Some(previous) = cache.current.as_ref().map(|s| s.head) {
            if !cache.retired_heads.contains(&previous) {
                cache.retired_heads.push_back(previous);
                while cache.retired_heads.len() > RETAINED_HEADS {
                    cache.retired_heads.pop_front();
                }
            }
        }
        let mut members = HashSet::new();
        members.insert(head); // the published-root entity itself
        if let Some(entity) = shared.content_store.get(&head) {
            if let Ok(data) = entity_types::PublishedRootData::from_entity(&entity) {
                members.extend(entity_tree::trie::collect_node_closure(
                    shared.content_store.as_ref(),
                    data.root_hash,
                ));
            }
        }
        // The authenticating signature, carried at the §5.2 invariant pointer.
        // The current head and every retired one: the two fetches of one verify
        // cycle are what the ring exists to keep together.
        for anchor in std::iter::once(&head).chain(cache.retired_heads.iter()) {
            members.insert(*anchor);
            if let Some(sig_hash) = shared
                .location_index
                .get(&entity_hash::invariant_signature_path(peer_id, anchor))
            {
                members.insert(sig_hash);
            }
        }

        // Project the content-face onto the path space: every binding that
        // resolves to a closure member, and every ancestor of one.
        let mut paths: HashSet<String> = HashSet::new();
        for entry in shared.location_index.list("/") {
            if !members.contains(&entry.hash) {
                continue;
            }
            let mut p = entry.path.as_str();
            loop {
                paths.insert(p.to_string());
                match p.rfind('/') {
                    // `Some(0)` is the last cut before the universal root, which
                    // is added below; `None` cannot occur on an absolute path.
                    Some(0) | None => break,
                    Some(i) => p = &p[..i],
                }
            }
        }
        if !paths.is_empty() {
            paths.insert("/".to_string());
        }

        cache.current = Some(ClosureSnapshot {
            head,
            members,
            paths,
        });
    }
}

impl Default for ClosureScope {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScopePredicate for ClosureScope {
    async fn in_scope(&self, hash: &Hash, shared: &Arc<PeerShared>) -> Result<bool, ScopeError> {
        self.refresh(shared);
        let cache = self.cache.lock().unwrap();
        Ok(cache
            .current
            .as_ref()
            .map(|s| s.members.contains(hash))
            .unwrap_or(false))
    }

    async fn in_scope_path(
        &self,
        absolute_path: &str,
        shared: &Arc<PeerShared>,
    ) -> Result<bool, ScopeError> {
        self.refresh(shared);
        let cache = self.cache.lock().unwrap();
        let snapshot = match cache.current.as_ref() {
            Some(s) => s,
            None => return Ok(false),
        };
        if snapshot.paths.contains(absolute_path) {
            return Ok(true);
        }
        // Universal-tree ancestor case: a bare `/{peer_id}` top-level segment
        // is reachable whatever the closure holds, so a descending walk can
        // find in-scope content and `peers.list` enumerates every peer-id the
        // local view holds bindings for (§6.5.6 universal-tree-root listing).
        // `NamespaceScope::in_scope_path` already reads it this way; the two
        // predicates diverging here is what made `peers_list_surfaces_other_peer`
        // pass under namespace scope and fail under closure scope. Enumeration
        // is still bounded by the index — `render_listing` only emits children
        // that actually carry bindings — and every child below this level goes
        // back through the closure filter.
        Ok(is_bare_top_level_segment(absolute_path))
    }

    fn describe(&self) -> String {
        "closure-of-signed-root".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_scope_trims_slashes() {
        assert_eq!(
            NamespaceScope::new("system/content/public").namespace(),
            "system/content/public"
        );
        assert_eq!(
            NamespaceScope::new("/system/content/public/").namespace(),
            "system/content/public"
        );
    }

    #[test]
    fn bare_top_level_segment_recognition() {
        assert!(is_bare_top_level_segment("/2KCFip6Zz4R5Ynn"));
        // A trailing slash makes it a prefix form, not the bare segment; the
        // universal root and any deeper path are handled by the closure set.
        assert!(!is_bare_top_level_segment("/2KCFip6Zz4R5Ynn/"));
        assert!(!is_bare_top_level_segment("/2KCFip6Zz4R5Ynn/system"));
        assert!(!is_bare_top_level_segment("/"));
        assert!(!is_bare_top_level_segment(""));
        assert!(!is_bare_top_level_segment("no-leading-slash"));
    }
}
