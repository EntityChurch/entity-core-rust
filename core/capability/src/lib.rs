//! Capability tokens, grants, pattern matching, scope checking.
//!
//! Implements the 4D grant model from Entity Core Protocol v7.9 §3.6, §5.4:
//! - handlers (path-scope): which handlers can be called
//! - resources (path-scope): which data paths can be accessed
//! - operations (id-scope): which operations are authorized
//! - peers (id-scope, optional): which peers the grant applies to
//!
//! Pattern matching follows §5.4: `*` matches everything, `prefix/*` matches
//! subtrees, `/*/pattern` is a peer wildcard. All paths are absolute after
//! canonicalization (leading `/`).

use entity_hash::Hash;
use thiserror::Error;

mod mint;
pub use mint::{mint_reattenuated, MintError};

/// Policy-table fallback segment (V7.62 §6.2 closeout F8 — was `*` in
/// v7.62; renamed to the literal `default` to remove the glyph collision
/// with `*`-as-glob everywhere else in V7). Lives in `core/capability`
/// (not the optional handler crate) so the §4.4 connection-time policy
/// reader in `core/peer` can share the same constant without taking on a
/// feature-gated dependency.
pub const POLICY_FALLBACK_SEGMENT: &str = "default";

// ---------------------------------------------------------------------------
// Scope types (§3.6)
// ---------------------------------------------------------------------------

/// Path-based scope for handlers and resources.
///
/// `include` patterns define what's allowed, `exclude` patterns carve out exceptions.
/// Pattern syntax: `*` = all, `prefix/*` = subtree, `*/rest` = any peer.
#[derive(Debug, Clone, PartialEq)]
pub struct PathScope {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

impl PathScope {
    pub fn new(include: Vec<String>) -> Self {
        Self {
            include,
            exclude: Vec::new(),
        }
    }

    pub fn with_exclude(include: Vec<String>, exclude: Vec<String>) -> Self {
        Self { include, exclude }
    }

    /// Wildcard scope matching everything.
    pub fn all() -> Self {
        Self::new(vec!["*".into()])
    }

    /// Empty scope matching nothing (valid for resource-less handlers).
    pub fn none() -> Self {
        Self::new(vec![])
    }
}

/// Identifier-based scope for operations and peers.
///
/// Unlike `PathScope`, id-scope patterns match the raw value as a **literal
/// string** (§5.2) — no §5.4 path canonicalization. Exactly two wildcards:
/// bare `*` (any) and a trailing `/*` (literal segment-prefix).
#[derive(Debug, Clone, PartialEq)]
pub struct IdScope {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

impl IdScope {
    pub fn new(include: Vec<String>) -> Self {
        Self {
            include,
            exclude: Vec::new(),
        }
    }

    pub fn with_exclude(include: Vec<String>, exclude: Vec<String>) -> Self {
        Self { include, exclude }
    }

    pub fn all() -> Self {
        Self::new(vec!["*".into()])
    }
}

/// A single grant entry covering all four dimensions (§3.6).
///
/// All four dimensions must match simultaneously within the same grant entry
/// for authorization to succeed.
#[derive(Debug, Clone, PartialEq)]
pub struct GrantEntry {
    pub handlers: PathScope,
    pub resources: PathScope,
    pub operations: IdScope,
    /// When None, defaults to `{include: [local_peer_id]}` — local peer only.
    pub peers: Option<IdScope>,
    /// Domain-specific narrowing fields (map_of: primitive/any).
    /// Each key is a named restriction. Absent = unconstrained.
    /// During delegation: child MUST retain all parent constraint keys (§5.6).
    pub constraints: Option<std::collections::BTreeMap<String, ciborium::Value>>,
    /// Domain-specific expanding fields (map_of: primitive/any).
    /// Each key is a named privilege. Absent = most restricted.
    /// During delegation: child MUST NOT add keys parent doesn't have (§5.6).
    pub allowances: Option<std::collections::BTreeMap<String, ciborium::Value>>,
}

/// Default connection grants per §4.4.
///
/// Three grants:
/// 1. Tree handler: read type definitions and handler manifests.
/// 2. Capability handler: request capabilities (V7 §6.2).
/// 3. Network handler: `observe-address` only — `EXTENSION-NETWORK` §6.7.4's
///    `system/capability/network-reflect`, which that section makes a **broad
///    default grant** on the reasoning that reflection is a mirror: it returns
///    the caller's own transport source and leaks nothing the caller did not
///    reveal by connecting. Deliberately *only* `observe-address` — §6.7.2's
///    `check-reachability` is the restricted one (`network-dialback`), because
///    it causes this peer to **emit traffic at an address**, and a broad grant
///    there would make every peer a DDoS reflector.
///
/// > **Found by the cross-impl matrix, not by review.** Rust shipped the
/// > §6.7.1 responder reachable only to a caller that already held a
/// > `system/network` grant, so Go's client got a 403 where the spec says it
/// > should get a mapping. Neither impl's own suite could see it: Go's client
/// > only ever met Go's responder, whose defaults already covered it, and
/// > Rust had a client and a responder that never spoke to each other.
///
/// Both targets are registered as bootstrap handlers when the matching
/// feature flag is on (default). Per RULING-CAPABILITY-HANDLER-
/// ADVERTISEMENT, an advertised grant SHALL only reference
/// handlers registered on this peer — keep these in sync with the
/// `capability-handler` and `handlers` feature gates in core/peer.
pub fn default_connection_grants() -> Vec<GrantEntry> {
    vec![
        GrantEntry {
            handlers: PathScope::new(vec!["system/tree".into()]),
            resources: PathScope::new(vec!["system/type/*".into(), "system/handler/*".into()]),
            operations: IdScope::new(vec!["get".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        },
        GrantEntry {
            handlers: PathScope::new(vec!["system/capability".into()]),
            resources: PathScope::new(vec![]),
            operations: IdScope::new(vec!["request".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        },
        GrantEntry {
            handlers: PathScope::new(vec!["system/network".into()]),
            // No resource scope: reflection addresses no tree resource, and
            // attaching one reads as "not granted" rather than as the mistake
            // it is.
            resources: PathScope::new(vec![]),
            operations: IdScope::new(vec!["observe-address".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        },
    ]
}

/// Wide-open connection grants for debugging/testing.
///
/// Single grant covering all handlers, all resources, all operations,
/// across any peer namespace. **Never use in production** — bypasses all
/// authorization scoping.
///
/// R-5 (CROSS-IMPL-ACME-RUST): resource patterns use the
/// cross-namespace peer-wildcard form `/*/*` rather than bare `*` so
/// the grant covers paths under any peer namespace within the local
/// tree. The bare `*` resource canonicalizes to `/{local_peer_id}/*`
/// per `canonicalize`, which would reject writes to `/{X}/...` where
/// X is e.g. an ephemeral peer's signature-path namespace per V7 §6.5
/// invariant-pointer semantics. The peer-scope stays `*` (any local-side
/// `target_peer` value satisfies via `IdScope`).
pub fn debug_open_grants() -> Vec<GrantEntry> {
    use std::collections::BTreeMap;

    // Query-specific grant with content_store access + wildcard type_scope
    let type_scope = vec![(
        ciborium::Value::Text("include".into()),
        ciborium::Value::Array(vec![ciborium::Value::Text("*".into())]),
    )];
    let mut constraints = BTreeMap::new();
    constraints.insert("type_scope".to_string(), ciborium::Value::Map(type_scope));
    let mut allowances = BTreeMap::new();
    allowances.insert(
        "scope".to_string(),
        ciborium::Value::Text("content_store".into()),
    );

    vec![
        // Query grant with content_store scope + wildcard type_scope
        GrantEntry {
            handlers: PathScope::new(vec!["system/query".into()]),
            resources: PathScope::new(vec!["/*/*".into()]),
            operations: IdScope::new(vec!["find".into(), "count".into()]),
            peers: None,
            constraints: Some(constraints),
            allowances: Some(allowances),
        },
        // General wildcard grant — resources are cross-namespace.
        GrantEntry {
            handlers: PathScope::new(vec!["*".into()]),
            resources: PathScope::new(vec!["/*/*".into()]),
            operations: IdScope::new(vec!["*".into()]),
            peers: Some(IdScope::new(vec!["*".into()])),
            constraints: None,
            allowances: None,
        },
    ]
}

/// Tree-binding storage path for a multi-sig root capability
/// (PROPOSAL-MULTISIG-CORE-PRIMITIVE M12).
///
/// Multi-sig root caps are stored at
/// `system/capability/grants/multi-sig-root/{cap_hash}`. `is_revoked` checks
/// the tree binding here; removing it revokes the cap.
///
/// `cap_hash` is rendered in the protocol's display form (`ecfv1-sha256:…`,
/// V7 §1.2). The path is bare (peer-relative); callers qualify with the
/// peer ID before tree access (peer-qualified paths convention).
pub fn capability_path_for_multisig_root(cap_hash: &Hash) -> String {
    format!("system/capability/grants/multi-sig-root/{}", cap_hash)
}

/// Principal-level owner-authority scope for a peer over its own namespace
/// `/{peer_id}/*` (F27 §6.9a peer-authority-bootstrap).
///
/// All handlers, all operations, all peers — resources scoped to the peer's
/// own namespace. This is the **principal-level** owner capability the
/// key-holder receives when authenticating as the peer's own identity over
/// the wire. It is distinct from the **handler-level** per-handler
/// self-grants ([`wildcard_handler_grant`] / `internal_scope`) that cover
/// peer-internal dispatch (§6.9a.4 coexistence — both are seeded at
/// peer-init; neither subsumes the other).
pub fn owner_self_grant(peer_id: &str) -> Vec<GrantEntry> {
    vec![GrantEntry {
        handlers: PathScope::all(),
        resources: PathScope::new(vec![format!("/{}/*", peer_id)]),
        operations: IdScope::all(),
        peers: Some(IdScope::all()),
        constraints: None,
        allowances: None,
    }]
}

/// Wildcard handler grant scope: all handlers, all operations, all peers, and
/// all resources **in the local peer's own namespace** — the bare `*` resource
/// canonicalizes to `/{local}/*` (see [`check_resource_scope`] / `canonicalize`).
///
/// **This is the own-namespace form.** For the §6.9 per-handler self-grant the
/// peer seeds at init, use [`default_handler_self_grant`] instead: that one is
/// the ceiling for a handler's in-process sub-dispatches (§5.2 D1), and a peer's
/// own store legitimately holds foreign-namespace subtrees (V7 §1.4 Category A),
/// so confining it to `/{local}/*` forbids the peer's own engine from writing
/// its own mirrors. Kept as-is for the call sites that *want* own-namespace
/// confinement (the SDK owner self-cap builds on it and adds an explicit
/// cross-namespace read grant on top).
pub fn wildcard_handler_grant() -> Vec<GrantEntry> {
    vec![GrantEntry {
        handlers: PathScope::all(),
        resources: PathScope::all(),
        operations: IdScope::all(),
        peers: Some(IdScope::all()),
        constraints: None,
        allowances: None,
    }]
}

/// Default scope for handlers that do not declare `internal_scope` (§6.2, was
/// §6.9): all handlers, **all resources**, all operations, and **the local peer
/// only** — `peers` is deliberately absent.
///
/// Differs from [`wildcard_handler_grant`] in two places. "All resources" is
/// written in the R-5 cross-namespace peer-wildcard form `/*/*` rather than the
/// bare `*` — the same distinction, and for the same reason, as
/// [`debug_open_grants`]. And `peers` is **omitted**, which is not the same as
/// `*`.
///
/// **Why `resources` spans namespaces while `peers` does not.** The two
/// dimensions are orthogonal and bound different things (§6.3). A peer's store
/// is one local address space keyed by peer id (§1.4), so `/{them}/…` names a
/// **local** region holding their cached or mirrored data; writing there is a
/// local write, not a remote reach. The network bound is carried entirely by
/// `peers`, which is absent here and therefore defaults to
/// `{include: [local_peer_id]}` — **and is still checked** (§5.2 Dimension 4).
/// A default-scope handler consequently cannot dispatch at a foreign peer,
/// which is the escalation that matters, while it can still write the mirrors
/// its own store legitimately holds.
///
/// §6.2 names `peers: ["*"]` here as "specifically wrong" and the one direction
/// that must not be widened: it authorizes sub-dispatch at *foreign peers'*
/// handlers under a bootstrap grant nobody minted for that purpose, undoing the
/// dimension §5.2 Dimension 4 exists to close. We shipped `IdScope::all()` until
/// arch ruled the question (go's spec-issue `2026-08-23-a`, ruled absent and
/// folded into §6.2). **This field is now live and it was not when it was
/// written.** The prior sentence here read *"inert in this tree either way today
/// — `make_execute_fn` returns at its `is_remote` branch before the ceiling
/// check, so the path that reaches Dimension 4 always qualifies to the local
/// peer."* True as written, and it stopped being true at 0.8.2.17, which put a
/// four-dimension check on the outbound branch (§1.4 PD-2,
/// `outbound_sub_dispatch_authorized`). So this is the *third* instance of the
/// same shape in one function's doc comment: an unread field spelled correctly
/// on the argument that a reader would one day consult it, and then consulted.
/// The consequence of `peers: None` is now observable — a bootstrap-scope
/// handler cannot sub-dispatch at a foreign peer on ambient authority, which is
/// the escalation §6.2 names, and it reaches such a peer only by presenting a
/// capability that peer minted.
///
/// **Why the form matters here and did not before.** §6.9 describes this default
/// as unrestricted, and until D1 (PROPOSAL-DISPATCH-AUTHORIZATION-FRAME, §5.2
/// resource dimension) nothing read its `resources` field at all on the
/// in-process path — `make_execute_fn` ran no capability check of any dimension.
/// D1 made this grant the **ceiling** for every sub-dispatch a handler performs,
/// at which point the bare `*` silently narrowed "all resources" to
/// `/{local}/*`. A peer's own store legitimately holds OTHER peers' subtrees at
/// their natural universal paths (V7 §1.4 Category A — a cached foreign content
/// site, a `follow` mirror at `/{them}/app/...`), and those writes are dispatched
/// by the peer's own engine handlers. Under the bare-`*` ceiling the engine could
/// not write them: `follow(Continuation)`'s standing leg 403'd at its
/// `system/tree:merge` step, which is what
/// `follow_continuation_standing_leg_fires_cross_peer` measures.
///
/// This does not blunt D1. D1's teeth are handlers that declare a **narrow**
/// `internal_scope` (the confused-deputy shape: a deputy granted `app/*` that
/// sub-dispatches `system/handler:register` at `system/handler/pwn`); those are
/// unaffected. A handler on the default scope was already omnipotent inside
/// `/{local}/*`, so restoring the cross-namespace half returns exactly the
/// authority §6.9 says it has and nothing more — and it is still bounded by the
/// **local** store: a write into `/{them}/...` here touches this peer's tree, not
/// theirs (a foreign peer authorizes its own writes through `dispatch_request`).
pub fn default_handler_self_grant() -> Vec<GrantEntry> {
    vec![GrantEntry {
        handlers: PathScope::all(),
        // R-5 form — see `debug_open_grants`. Bare `*` would canonicalize to
        // `/{local}/*` and exclude the foreign-namespace paths this peer's own
        // store holds.
        resources: PathScope::new(vec!["/*/*".into()]),
        operations: IdScope::all(),
        // ABSENT, not `*` — §6.2. Absent defaults to `{include: [local_peer_id]}`
        // and is still checked; `*` would authorize dispatch at foreign peers'
        // handlers. See the doc comment above before widening this.
        peers: None,
        constraints: None,
        allowances: None,
    }]
}

/// Resource target from an EXECUTE message (§3.2).
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceTarget {
    pub targets: Vec<String>,
    pub exclude: Vec<String>,
}

/// Multi-signature granter (PROPOSAL-MULTISIG-CORE-PRIMITIVE §3.2 / M2).
///
/// `signers` are identity hashes (content hashes of `system/peer` entities,
/// V7 §1.5). `threshold` is K. The validity constraint is K ∈ [2, N], N ≥ 2,
/// no duplicate signers (M3); enforced at chain-walk entry by `validate`.
///
/// Encoded on the wire as a CBOR map with `signers` (array of bstr) and
/// `threshold` (uint). Distinguished from a single-sig granter (CBOR bstr) by
/// CBOR major type — no tag is emitted (M8).
#[derive(Debug, Clone, PartialEq)]
pub struct MultiGranter {
    pub signers: Vec<Hash>,
    pub threshold: u64,
}

impl MultiGranter {
    /// Validate M3 constraints. Called at MUST-level chain-walk entry.
    ///
    /// - N (signers count) ≥ 2 (use single-sig form for N=1)
    /// - K (threshold) ∈ [2, N] (K=0 invalid, K=1 invalid, K>N invalid)
    /// - No duplicate signers
    pub fn validate(&self) -> Result<(), CapabilityError> {
        let n = self.signers.len();
        if n < 2 {
            return Err(CapabilityError::Invalid(format!(
                "multi-granter must have N ≥ 2 signers, got {}",
                n
            )));
        }
        if self.threshold < 2 {
            return Err(CapabilityError::Invalid(format!(
                "multi-granter threshold K must be ≥ 2, got {}",
                self.threshold
            )));
        }
        if self.threshold > n as u64 {
            return Err(CapabilityError::Invalid(format!(
                "multi-granter threshold K ({}) exceeds N ({})",
                self.threshold, n
            )));
        }
        // Duplicate detection — small N (recommended ≤ 32, M9), O(n²) is fine.
        for i in 0..self.signers.len() {
            for j in (i + 1)..self.signers.len() {
                if self.signers[i] == self.signers[j] {
                    return Err(CapabilityError::Invalid(
                        "multi-granter contains duplicate signers".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Polymorphic granter (PROPOSAL-MULTISIG-CORE-PRIMITIVE §3.1 / M1).
///
/// Either a single identity hash (single-sig, identical to today's behavior)
/// or a multi-sig granter (K-of-N). Multi-sig is restricted to root caps
/// (`parent: None`) by validity constraint M3.
#[derive(Debug, Clone, PartialEq)]
pub enum Granter {
    Single(Hash),
    Multi(MultiGranter),
}

impl Granter {
    /// Construct a single-sig granter from a hash.
    pub fn single(hash: Hash) -> Self {
        Granter::Single(hash)
    }

    /// Construct a multi-sig granter from a `MultiGranter` value.
    pub fn multi(multi: MultiGranter) -> Self {
        Granter::Multi(multi)
    }

    /// If single-sig, return the granter hash; otherwise None.
    pub fn as_single(&self) -> Option<&Hash> {
        match self {
            Granter::Single(h) => Some(h),
            Granter::Multi(_) => None,
        }
    }

    /// If multi-sig, return the multi-granter value; otherwise None.
    pub fn as_multi(&self) -> Option<&MultiGranter> {
        match self {
            Granter::Multi(m) => Some(m),
            Granter::Single(_) => None,
        }
    }

    pub fn is_multi(&self) -> bool {
        matches!(self, Granter::Multi(_))
    }
}

impl From<Hash> for Granter {
    fn from(h: Hash) -> Self {
        Granter::Single(h)
    }
}

/// Capability token data (§3.6).
#[derive(Debug, Clone, PartialEq)]
pub struct CapabilityToken {
    pub grants: Vec<GrantEntry>,
    /// Polymorphic granter — single-sig (`Granter::Single`) or multi-sig
    /// (`Granter::Multi`) per PROPOSAL-MULTISIG-CORE-PRIMITIVE M1.
    /// Multi-sig requires `parent: None` (M3).
    pub granter: Granter,
    pub grantee: Hash,
    pub parent: Option<Hash>,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub not_before: Option<u64>,
    pub delegation_caveats: Option<DelegationCaveats>,
}

/// Delegation caveats — flat struct, NOT an array (§5.7).
#[derive(Debug, Clone, PartialEq)]
pub struct DelegationCaveats {
    pub no_delegation: Option<bool>,
    pub max_delegation_depth: Option<u64>,
    pub max_delegation_ttl: Option<u64>,
}

// ---------------------------------------------------------------------------
// Pattern matching (§5.4)
// ---------------------------------------------------------------------------

/// The unmatchable canonical value (§5.4, 0.8.2.20).
///
/// A single-segment absolute path whose first segment cannot be a `peer_id`
/// — [`entity_entity::EntityUri::is_peer_id`] requires ≥ 46 Base58 characters
/// and `-` is outside the Base58 alphabet — so it is unreachable as a real
/// canonical path *by construction*, not by a prohibition somebody has to
/// remember. Star-free, plain ASCII, greppable.
///
/// **Why a sentinel and not `Option`.** Until 0.8.2.20 this module's
/// `canonicalize` returned `Option<String>` and every caller was obliged to
/// read `None` as deny. That is a stronger contract in Rust — the compiler
/// asks the question — and it was the right shape for as long as the rule was
/// *"a malformed pattern denies."* It is the wrong shape for
/// [`effective_targets`], whose defined behaviour is that a malformed target
/// **stays in the effective list** so the arity rule counts it and
/// `validate_absolute_path` refuses it (§5.2). `None` cannot be put in that
/// list; a value that matches nothing can. The sentinel is also the cohort's
/// wire-visible vocabulary, which an `Option` is not.
pub use entity_entity::NEVER_MATCH;

/// Canonicalize a path or pattern to absolute form. **Total** (§5.4,
/// 0.8.2.20): the return domain is *a canonical path or [`NEVER_MATCH`]*, and
/// there is no error channel.
///
/// It became total because every normative call site is a **matcher**, which
/// has nowhere to put an error — `matches_scope` ends in a `matches_pattern`
/// over two canonicalized operands, `is_covered_by` canonicalizes inside a
/// matcher argument. A declared failure mode that every caller structurally
/// discards is not a contract (R11). The diagnostic lives at admission (§6.5),
/// which has a caller to answer; see `connection.rs`'s `invalid_path` refusal.
///
/// Rules:
/// - `"entity://{peer}/{path}"` → `"/{peer}/{path}"` (address, not scheme)
/// - `starts_with("/")` → pass through (already absolute)
/// - `"*"` → `"/{local_peer_id}/*"` (peer-relative wildcard)
/// - `"./..."` / `"../..."` → [`NEVER_MATCH`] (reserved, §1.4)
/// - `"*/..."` → [`NEVER_MATCH`] (ambiguous — use `/*/...`)
/// - bare path → `"/{local_peer_id}/{path}"`
///
/// The three consumers of [`NEVER_MATCH`] are ruled by §5.4 and all three are
/// implemented here or next door: [`matches_pattern`] returns `false` for
/// either operand; [`entity_entity::EntityUri::validate_absolute_path`] errors
/// on it (its first segment is not a `peer_id`); and `core/store` refuses to
/// store or resolve it.
pub fn canonicalize(path: &str, local_peer_id: &str) -> String {
    // Reserved directory-relative prefixes (§1.4).
    if path.starts_with("./") || path.starts_with("../") {
        return NEVER_MATCH.to_string();
    }
    // Ambiguous bare */rest — must use /*/rest. Matches nothing rather than
    // erroring (R11): a `*/`-leading pattern in a grant is admitted and
    // covers no path.
    if path.starts_with("*/") {
        return NEVER_MATCH.to_string();
    }
    // Full entity URI → absolute path (arch ruling 24: `entity://{p}/x` and
    // `/{p}/x` are the same address, and canonicalization is where they
    // converge — dispatch routing already treats them as one).
    //
    // Without this, a cross-peer `deliver_uri`'s `entity://` form (the shape
    // the spec uses, so the shape a deliver_token's `resources` scope
    // carries) fell through to the bare-path arm below and came out as
    // `/{local}/entity://{peer}/x` — which can never match the normalized
    // request target, so every cross-peer delivery 403'd. Rust had this
    // logged as a cross-impl question; the ruling is that it was never one —
    // *cleaning* preserves the scheme (`EntityUri::clean_path`),
    // *canonicalizing* resolves it to the address it names. Two different
    // jobs that Rust had conflated. Mirrors Go's `capability.Canonicalize`.
    if path.starts_with("entity://") {
        if let Ok(uri) = entity_entity::EntityUri::parse(path) {
            if !uri.peer_id.is_empty() {
                return if uri.path.is_empty() {
                    format!("/{}", uri.peer_id)
                } else {
                    format!("/{}/{}", uri.peer_id, uri.path)
                };
            }
        }
    }
    // Already absolute — pass through
    if path.starts_with('/') {
        return path.to_string();
    }
    // Bare wildcard → local peer all paths
    if path == "*" {
        return format!("/{}/*", local_peer_id);
    }
    // Bare path — prepend / + local peer
    format!("/{}/{}", local_peer_id, path)
}

/// Check if a concrete path matches a pattern (§5.4).
///
/// Both `path` and `pattern` should already be canonicalized (absolute).
///
/// Pattern types:
/// - `*` — matches everything (recursive case from `/*/*` decomposition)
/// - `prefix/*` — subtree match (path starts with prefix)
/// - `/*/rest` — peer wildcard (any peer, match rest)
/// - anything else — exact match
pub fn matches_pattern(path: &str, pattern: &str) -> bool {
    // §5.4 (0.8.2.20): NEVER_MATCH never matches, in EITHER operand. This arm
    // is deliberately FIRST and is a *matcher rule*, not a property of the
    // string — the `pattern == "*"` arm immediately below returns true for any
    // path, so safety here MUST NOT rest on the sentinel merely looking
    // unmatchable. Reorder these two and a bare-`*` grant covers every
    // malformed target in the tree.
    if path == NEVER_MATCH || pattern == NEVER_MATCH {
        return false;
    }
    if pattern == "*" {
        return true;
    }

    // Peer wildcard: /*/rest — match any peer's subtree
    if let Some(remainder) = pattern.strip_prefix("/*/") {
        // path is /{peer_id}/rest — extract rest after peer segment
        if let Some(after_slash) = path.strip_prefix('/') {
            if let Some(slash) = after_slash.find('/') {
                let path_rest = &after_slash[slash + 1..];
                // Recurse: both sides are now bare sub-paths
                return matches_pattern(path_rest, remainder);
            }
        }
        return false;
    }

    // Subtree prefix: prefix/*
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return path.starts_with(prefix)
            && path.len() > prefix.len()
            && path.as_bytes()[prefix.len()] == b'/';
    }

    // Exact match
    path == pattern
}

/// Check if a value matches an id-scope pattern (§5.2).
///
/// id-scope (`operations`, `peers`) matches the raw value as a **literal
/// string** — no §5.4 path canonicalization (no leading-`/` universal scope,
/// no `/*/` interior peer-wildcard, no peer-relative→`/{local}/…`
/// qualification). Exactly two wildcards: bare `*` (any) and a trailing `/*`
/// (literal segment-prefix, e.g. `compute/*` matches `compute/apply`).
fn matches_id_pattern(value: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return value.starts_with(prefix)
            && value.len() > prefix.len()
            && value.as_bytes()[prefix.len()] == b'/';
    }
    value == pattern
}

/// Check if a value matches an id-scope (include/exclude) (§5.2).
///
/// The value must match at least one include pattern and must not match any
/// exclude pattern, both compared literally per [`matches_id_pattern`].
pub fn matches_id_scope(value: &str, include: &[String], exclude: &[String]) -> bool {
    if !include
        .iter()
        .any(|pattern| matches_id_pattern(value, pattern))
    {
        return false;
    }
    !exclude
        .iter()
        .any(|pattern| matches_id_pattern(value, pattern))
}

/// Check if a value matches a scope (include/exclude) (§5.4).
///
/// The value must match at least one include pattern and must not
/// match any exclude pattern.
pub fn matches_scope(
    value: &str,
    include: &[String],
    exclude: &[String],
    local_peer_id: &str,
) -> bool {
    // A malformed value canonicalizes to NEVER_MATCH, which the include loop
    // below cannot match (§5.4's matcher rule) — so it falls through to DENY
    // without needing a guard of its own.
    let cv = canonicalize(value, local_peer_id);

    // A malformed include can never grant — it simply doesn't match.
    let matched = include
        .iter()
        .any(|pattern| matches_pattern(&cv, &canonicalize(pattern, local_peer_id)));

    if !matched {
        return false;
    }

    // ⛔ §5.4 (0.8.2.21): AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING.
    //
    // The sentinel's safety is DIRECTIONAL and 0.8.2.20 argued it from the
    // include side only. *Matches nothing* is fail-closed in an include (covers
    // nothing → the grant grants nothing) and fail-OPEN here (carves out
    // nothing → the grant is silently WIDER than its author wrote, with no
    // error anywhere, because the sentinel is designed not to raise). A granter
    // writing `exclude: ["*/secret"]` — a plausible spelling of *not `secret`,
    // in any peer's namespace*, where the intended form is `/*/secret` — got an
    // exclusion that excluded nothing.
    //
    // This is the disposition this line carried BEFORE 0.8.2.20 reversed it;
    // the reversal is corrected at the spec's end and the fail-closed reading
    // is restored. It is stated HERE, at the scope layer, which already knows
    // which array it is reading — `matches_pattern` stays uniform over its
    // operands so it remains transcribable into 46 languages.
    //
    // `check_resource_scope`'s concrete arm carries the same arm; its pattern
    // arm is fail-closed already (see there). The caller's OWN exclude in
    // `effective_targets` deliberately does not: an unmatchable caller exclude
    // carves out nothing, so MORE of the caller's targets face the grant check
    // — that direction narrows, and refusing it would reject a request the
    // caller is entitled to make.
    for pattern in exclude {
        let cp = canonicalize(pattern, local_peer_id);
        if cp == NEVER_MATCH {
            return false;
        }
        if matches_pattern(&cv, &cp) {
            return false;
        }
    }

    true
}

/// The first scope pattern in `grants` that canonicalizes to [`NEVER_MATCH`],
/// if any — §5.4's *"a capability carrying an unmatchable scope pattern is
/// INVALID"* `[MUST]` (0.8.2.21).
///
/// ⛔ **This is the authoring half of the fail-open, and it is a MUST rather
/// than a MAY for a cross-peer reason.** An unmatchable pattern is fail-closed
/// in an `include` and fail-OPEN in an `exclude`; the evaluation-side deny
/// ([`matches_scope`], [`check_resource_scope`]) closes the hole, and this
/// closes it at the only moment the **granter** — the party a silently-wider
/// grant harms — is still present to be told. A peer that refuses the
/// capability and a peer that honours a grant wider than written reach
/// **different authorization decisions on the same capability bytes**, which is
/// the class the specification pins rather than leaves open. Two layers,
/// because a single layer that author input can make vacuous is not a gate.
///
/// **Frame-independent, deliberately, and there is no `local_peer_id`
/// parameter.** [`canonicalize`] yields [`NEVER_MATCH`] for exactly three
/// reserved prefixes — `./`, `../`, `*/` — all decided *before* any peer-id
/// qualification, so the granter frame and the verifier frame give the same
/// answer. Taking a peer id here would invite a call site to pass the wrong one
/// and read as though the verdict depended on it.
///
/// **Path scopes only.** `operations` and `peers` are id-scopes (§5.2): they
/// match literally with no §5.4 canonicalization, so no id-scope pattern can
/// be unmatchable and there is nothing here to check. Stated rather than
/// omitted — an absent check reads the same as an overlooked one.
///
/// Call sites: mint (`system/capability:request`), delegation
/// (`system/capability:delegate`) → `400 invalid_path`; and chain verification
/// (§5.5), where it is an invalid capability.
pub fn unmatchable_scope_pattern(grants: &[GrantEntry]) -> Option<String> {
    // The frame is irrelevant (see the doc comment); this one is named so that
    // nobody "fixes" it by threading a peer id in and making the verdict look
    // frame-dependent. `frame_is_irrelevant_to_the_unmatchable_verdict` fails if
    // that stops being true.
    const ANY_FRAME: &str = "unused-frame-see-doc-comment";
    for grant in grants {
        for scope in [&grant.handlers, &grant.resources] {
            for pattern in scope.include.iter().chain(scope.exclude.iter()) {
                if canonicalize(pattern, ANY_FRAME) == NEVER_MATCH {
                    return Some(pattern.clone());
                }
            }
        }
    }
    None
}

/// Check if a path/pattern is covered by a set of patterns.
fn is_covered_by(path: &str, pattern_set: &[String], local_peer_id: &str) -> bool {
    // A malformed pattern canonicalizes to NEVER_MATCH and covers nothing.
    pattern_set
        .iter()
        .any(|p| matches_pattern(path, &canonicalize(p, local_peer_id)))
}

/// Check if a string contains a wildcard.
fn is_pattern(path: &str) -> bool {
    path.contains('*')
}

/// Strip trailing wildcard for overlap checking.
fn strip_wildcard(pattern: &str) -> &str {
    if let Some(prefix) = pattern.strip_suffix("/*") {
        prefix
    } else if pattern == "*" {
        ""
    } else {
        pattern
    }
}

/// Check if two patterns could match any common concrete path.
fn patterns_overlap(a: &str, b: &str) -> bool {
    let pa = strip_wildcard(a);
    let pb = strip_wildcard(b);
    pa.starts_with(pb) || pb.starts_with(pa)
}

// ---------------------------------------------------------------------------
// Permission checking (§5.4)
// ---------------------------------------------------------------------------

/// Check whether a capability authorizes an operation (§5.4).
///
/// This is the Level 1 "dispatch scope" check, called after handler resolution.
/// All four dimensions must match within the same grant entry.
pub fn check_permission(
    operation: &str,
    handler_pattern: &str,
    target_peer: &str,
    resource_target: Option<&ResourceTarget>,
    capability: &CapabilityToken,
    local_peer_id: &str,
) -> bool {
    check_permission_inner(
        operation,
        handler_pattern,
        target_peer,
        resource_target,
        capability,
        local_peer_id,
        false,
    )
}

/// [`check_permission`] with **Dimension 4 (`peers`) relaxed** — §1.4's one
/// exemption (0.8.2.19).
///
/// The outbound sub-dispatch gate calls this, and only this, when a valid
/// credential minted by the TARGET peer has already answered *where*. The
/// target answers where; this grant still answers *what*, so Dimensions 1–3
/// are checked exactly as [`check_permission`] checks them.
///
/// **It is not dimension-mixing, and the loop shape is what enforces that.**
/// §5.2 requires all applicable dimensions to be satisfied *by a single grant
/// entry*; this skips the peers **test**, it does not let entry A supply
/// `handlers` while entry B supplies `peers`. Written as a flag threaded into
/// one body rather than a second copy of the loop for exactly that reason — a
/// second copy is where the two would drift apart.
///
/// **A credential is not a grant.** There is deliberately no entry point here
/// that authorizes from the credential alone: with no handler grant there is
/// nothing to supply Dimensions 1–3 and the caller must refuse. Reintroducing
/// the pre-0.8.2.19 bypass requires adding a new early return at the gate, not
/// passing a different argument here.
pub fn check_permission_relax_peers(
    operation: &str,
    handler_pattern: &str,
    resource_target: Option<&ResourceTarget>,
    capability: &CapabilityToken,
    local_peer_id: &str,
) -> bool {
    check_permission_inner(
        operation,
        handler_pattern,
        // Unread when `relax_peers` is set; passing the local peer id keeps the
        // argument honest rather than inventing a sentinel.
        local_peer_id,
        resource_target,
        capability,
        local_peer_id,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn check_permission_inner(
    operation: &str,
    handler_pattern: &str,
    target_peer: &str,
    resource_target: Option<&ResourceTarget>,
    capability: &CapabilityToken,
    local_peer_id: &str,
    relax_peers: bool,
) -> bool {
    for grant in &capability.grants {
        // Operations (id-scope, §5.2 — literal match, no canonicalization)
        if !matches_id_scope(
            operation,
            &grant.operations.include,
            &grant.operations.exclude,
        ) {
            continue;
        }

        // Handlers (path-scope, §5.4)
        if !matches_scope(
            handler_pattern,
            &grant.handlers.include,
            &grant.handlers.exclude,
            local_peer_id,
        ) {
            continue;
        }

        // Peers (id-scope, §5.2 — literal match, no canonicalization).
        // Skipped, and ONLY skipped, under §1.4's one exemption — see
        // `check_permission_relax_peers`.
        if !relax_peers {
            let default_peers = IdScope::new(vec![local_peer_id.into()]);
            let peers = grant.peers.as_ref().unwrap_or(&default_peers);
            if !matches_id_scope(target_peer, &peers.include, &peers.exclude) {
                continue;
            }
        }

        // Resources — only checked when resource is present.
        // This entry point keeps the self-issued (granter == local) frame:
        // the dispatch boundary that needs granter-aware canonicalization
        // (PR-8) goes through `check_permission_with_grant`.
        if let Some(rt) = resource_target {
            if !check_resource_scope(rt, &grant.resources, local_peer_id, local_peer_id) {
                continue;
            }
        }

        return true;
    }
    false
}

/// Check permission and return the matching grant entry (§5.4).
///
/// Same logic as `check_permission`, but returns a clone of the first
/// matching grant entry. This is needed by handlers that inspect the
/// grant's `constraints` field (e.g., the query handler).
///
/// `granter_peer_id` is the namespace frame for the cap's peer-relative
/// resource patterns (V7 §5.5 / PR-8) — resolve it from the cap's `granter`
/// via [`resolve_granter_peer_id`]. This is the dispatch-time authorization
/// boundary; pass the real granter so a foreign-granted bare-`*` cap cannot
/// reach the verifier's namespace.
pub fn check_permission_with_grant(
    operation: &str,
    handler_pattern: &str,
    target_peer: &str,
    resource_target: Option<&ResourceTarget>,
    capability: &CapabilityToken,
    local_peer_id: &str,
    granter_peer_id: &str,
) -> Option<GrantEntry> {
    for grant in &capability.grants {
        // Operations (id-scope, §5.2 — literal match, no canonicalization)
        if !matches_id_scope(
            operation,
            &grant.operations.include,
            &grant.operations.exclude,
        ) {
            continue;
        }
        // Handlers (path-scope, §5.4)
        if !matches_scope(
            handler_pattern,
            &grant.handlers.include,
            &grant.handlers.exclude,
            local_peer_id,
        ) {
            continue;
        }
        // Peers (id-scope, §5.2 — literal match, no canonicalization)
        let default_peers = IdScope::new(vec![local_peer_id.into()]);
        let peers = grant.peers.as_ref().unwrap_or(&default_peers);
        if !matches_id_scope(target_peer, &peers.include, &peers.exclude) {
            continue;
        }
        if let Some(rt) = resource_target {
            if !check_resource_scope(rt, &grant.resources, local_peer_id, granter_peer_id) {
                continue;
            }
        }
        return Some(grant.clone());
    }
    None
}

/// Resolve the peer_id whose namespace a capability's peer-relative resource
/// patterns canonicalize against (V7 §5.5 / PR-8).
///
/// Single-sig granters resolve to the granter identity's derived peer_id;
/// multi-sig granters fall back to the local peer (M3 root-only — multi-sig
/// caps are locally rooted, §5.5 root-trust). For a self-issued cap (granter
/// == local peer) the result equals `local_peer_id`.
///
/// `lookup` resolves a granter hash to its `system/peer` entity — pass a
/// closure over the envelope's `included` map (or content store). Returns
/// `None` when a single-sig granter cannot be resolved to a present
/// `system/peer` entity; callers MUST treat `None` as fail-closed (deny, §1.11).
pub fn resolve_granter_peer_id<'a>(
    granter: &Granter,
    local_peer_id: &str,
    lookup: impl FnOnce(&Hash) -> Option<&'a entity_entity::Entity>,
) -> Option<String> {
    let granter_hash = match granter.as_single() {
        Some(h) => h,
        None => return Some(local_peer_id.to_string()), // multi-sig → local
    };
    let granter_entity = lookup(granter_hash)?;
    if granter_entity.entity_type != entity_types::TYPE_PEER {
        return None;
    }
    entity_types::PeerData::from_entity(granter_entity)
        .ok()?
        .canonical_peer_id()
}

/// §5.2's **pattern-subject** exclude rule — the grant-exclude half of
/// `check_resource_scope`'s pattern arm, factored out because §6.3 now routes a
/// second subject through the identical rule `[MUST]` (0.8.2.22).
///
/// A pattern subject cannot be tested against a grant exclude the way a concrete
/// path is: `matches_pattern` is a **literal** comparison, so `/{p}/app/*` does
/// not "match" the exclude `/{p}/app/secret` and re-spells straight past an
/// exclusion it **spans**. The rule is therefore coverage, not matching — every
/// grant exclude that `patterns_overlap`s the subject is uncovered unless the
/// **caller's own** exclude already carves it out, and an uncovered one DENIES.
///
/// `caller_exclude` is the caller's `resource.exclude` at `check_resource_scope`
/// and **empty** at `check_path_permission`, where there is no `resource` in
/// scope — §6.3 says so in as many words. Empty is not a special case: with no
/// caller exclude, `is_covered_by` is false for every overlap, so *every*
/// overlapping grant exclude denies, which is exactly the sentence §6.3 states.
///
/// ⛔ **The sentinel arm is FIRST and that is a control-flow obligation, not a
/// line** (§5.4, 0.8.2.22). `patterns_overlap(subject, NEVER_MATCH)` is `false`
/// for every real pattern — `strip_wildcard` leaves the path-shaped sentinel
/// intact and neither string prefixes the other — so a sentinel check written
/// after the overlap test `continue`s past itself and is never reached. This
/// tree shipped the arm in the right order at `9beb723` as a **routed departure**
/// from `0.8.2.21`, which had called the pattern arm *"fail-closed by accident"*;
/// `0.8.2.22` ratified the departure and now states the ordering rule generally.
/// Keeping it in one function is what stops the two consumers drifting back.
fn pattern_subject_survives_grant_excludes(
    canonical_subject: &str,
    grant_exclude: &[String],
    caller_exclude: &[String],
    local_peer_id: &str,
    granter_peer_id: &str,
) -> bool {
    for ge in grant_exclude {
        let cge = canonicalize(ge, granter_peer_id);
        if cge == NEVER_MATCH {
            return false;
        }
        if !patterns_overlap(canonical_subject, &cge) {
            continue;
        }
        if !is_covered_by(&cge, caller_exclude, local_peer_id) {
            return false;
        }
    }
    true
}

/// Check resource scope — caller's requested targets must fit within grant scope (§5.2).
///
/// Two canonicalization frames (V7 §5.5 / PR-8): the **request target** and the
/// caller's own exclude canonicalize against `local_peer_id` (request-path
/// semantics, §5.4); the **grant's** include/exclude patterns canonicalize
/// against `granter_peer_id` — a bare `*` in a cap resource means
/// `/{granter_peer_id}/*` (the granter's namespace), never the verifier's. For
/// a self-issued cap the two frames coincide (pass `local_peer_id` for both).
pub fn check_resource_scope(
    resource_target: &ResourceTarget,
    grant_resources: &PathScope,
    local_peer_id: &str,
    granter_peer_id: &str,
) -> bool {
    let caller_exclude = &resource_target.exclude;
    let grant_include = &grant_resources.include;
    let grant_exclude = &grant_resources.exclude;

    // §5.2 (0.8.2.20): the authorizer iterates the EFFECTIVE set, named rather
    // than computed inline. The skip loop that used to live here IS
    // `effective_targets`; the handler calls the same function, which is the
    // whole point of the extraction (`F68`/`CP-12a` was two layers deriving one
    // set independently and drifting).
    for target in effective_targets(Some(resource_target), local_peer_id) {
        // `effective_targets` returns the RAW survivors (§5.2, 0.8.2.21), so
        // this scope check canonicalizes for its own matching. Re-canonicalizing
        // is not a second derivation of the effective SET — the set is already
        // decided, and decided canonically inside that function; this is the
        // same total function applied to a member of it.
        let ct = canonicalize(&target, local_peer_id);

        // Validate concrete path targets at the protocol boundary, and CONSUME
        // the verdict (§5.4, 0.8.2.20 — R11/G6). This call did not exist here
        // at all, so a target like `/notapeerid/x` was matched against the
        // grant as an ordinary string and a broad grant (`*`, `/*/*`) covered
        // it. NEVER_MATCH is refused by this arm too, by construction: its
        // first segment is not a peer_id.
        if !is_pattern(&ct) && entity_entity::EntityUri::validate_absolute_path(&ct).is_err() {
            return false;
        }

        // Target must be covered by grant include (granter frame per PR-8)
        if !is_covered_by(&ct, grant_include, granter_peer_id) {
            return false;
        }

        if is_pattern(&ct) {
            // Pattern target: grant excludes must be covered by caller excludes.
            //
            // ⛔ **This arm carries the NEVER_MATCH deny too, and that is a
            // DEPARTURE from 0.8.2.21's pseudocode — routed, with the
            // measurement.** The fold's own ledger calls this arm *"fail-closed
            // BY ACCIDENT, the test is negated for an unrelated reason"* and so
            // adds the arm only to the concrete branch. The accident does not
            // hold: `is_covered_by`'s negated test is never REACHED, because
            // `patterns_overlap(ct, "/never-match")` is false for every real
            // pattern target — `strip_wildcard` leaves the sentinel intact and
            // neither string is a prefix of the other — so the loop `continue`s
            // and the unmatchable grant exclude is skipped exactly as it was in
            // the concrete arm. Measured, not reasoned:
            // `the_pattern_arm_is_not_fail_closed_by_accident` fails against a
            // build of this function without this `if`. Spec-literal here is
            // fail-OPEN on the third of the three sites 0.8.2.21 enumerates.
            //
            // **0.8.2.22 ratified that departure and added a SECOND consumer**
            // (§6.3's pattern subject), so the rule moved into
            // [`pattern_subject_survives_grant_excludes`] rather than being
            // copied. The body is unchanged — sentinel first, then overlap, then
            // caller-exclude coverage — and the only thing this call site still
            // decides is whose exclude set plays the caller's part. Here it is
            // the caller's own; at §6.3 there is none.
            if !pattern_subject_survives_grant_excludes(
                &ct,
                grant_exclude,
                caller_exclude,
                local_peer_id,
                granter_peer_id,
            ) {
                return false;
            }
        } else {
            // Concrete target: must not be in grant exclude (granter frame).
            //
            // ⛔ Unmatchable exclude excludes everything (§5.2, 0.8.2.21) — see
            // `matches_scope` for the direction argument. Without this arm a
            // grant exclude the granter misspelled carves out NOTHING and the
            // grant is wider than written.
            for ge in grant_exclude {
                let cge = canonicalize(ge, granter_peer_id);
                if cge == NEVER_MATCH {
                    return false;
                }
                if matches_pattern(&ct, &cge) {
                    return false;
                }
            }
        }
    }
    true
}

/// The targets a request **actually names**, after the caller's own exclusions
/// (§5.2 `effective_targets`, 0.8.2.20/0.8.2.21).
///
/// **Returns the RAW survivors; decides the skip on the CANONICAL forms
/// (0.8.2.21).** Both halves are load-bearing and they pull in opposite
/// directions. The *skip* MUST be canonical, because two layers have to agree
/// on which targets survive — that agreement is the whole point of the
/// function. The *value handed back* is the target as the caller wrote it,
/// because §6.13 derives a handler's install pattern from this function against
/// the `system/handler/` prefix and its own worked example target is
/// peer-relative, so a canonical return makes the derivation it states not
/// fire. A consumer needing the absolute form calls [`canonicalize`] itself —
/// `entity_handler::single_effective_target` does, which is why no handler in
/// this tree changed shape when the return did.
///
/// The security property is unchanged under either return: the canonical form
/// of a raw survivor is a member of the canonical effective set, so
/// `subject ⊆ effective_targets` holds both ways.
///
/// **The authorizer and every handler MUST derive their subject from this one
/// function.** It is a named function rather than a rule in prose because the
/// defect it closes is two layers computing the same set independently and
/// drifting: [`check_resource_scope`] skipped caller-excluded targets while
/// every handler in the corpus indexed `resource.targets[0]`, and *which*
/// targets differed was the caller's to choose. A third statement of the rule
/// would drift the same way; a function has one definition.
///
/// Its parameters are deliberately only values a handler already holds
/// (`ctx.resource_target`, the local peer id) — no grant, no capability, no
/// dispatch state — so a handler specified in another document can call it.
///
/// ⛔ **The count is not the rule; the selection is.** `targets:[P,Q]
/// exclude:[P]` has an effective list of exactly one, so an arity check
/// *passes* — and `targets[0]` is still `P`. Index the list you counted. Use
/// [`require_single_resource_path`](crate::require_single_resource_path)
/// rather than open-coding the arity arms.
///
/// An absent resource yields the empty list, so callers need no separate null
/// check: *absent* and *present but fully self-excluded* are the same answer to
/// the same question, and §3.3 gives them the same code (`path_required`).
pub fn effective_targets(
    resource_target: Option<&ResourceTarget>,
    local_peer_id: &str,
) -> Vec<String> {
    let Some(rt) = resource_target else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(rt.targets.len());
    for target in &rt.targets {
        let ct = canonicalize(target, local_peer_id);

        // The caller targeted it and then excluded it — redundant but valid,
        // and NOT a subject. The skip is correct and is retained: demanding
        // grant coverage for a path nobody requested would refuse legitimate
        // traffic. The defect was never the skip; it was that only one layer
        // performed it.
        //
        // NEVER_MATCH is deliberately NOT skipped: it cannot be covered by any
        // exclude (§5.4's matcher rule), so it stays in the list, counts toward
        // the arity, and is refused by `validate_absolute_path` downstream.
        if is_covered_by(&ct, &rt.exclude, local_peer_id) {
            continue;
        }
        // The RAW survivor, not `ct` (0.8.2.21). The skip above used `ct`;
        // only the returned value is raw.
        out.push(target.clone());
    }
    out
}

/// Handler-level path authorization (§6.3 `check_path_permission`).
///
/// **This is not a secondary check `[MUST]` (§5.2, 0.8.2.20.)** The
/// dispatch-level [`check_permission`] authorizes the request the caller
/// *made*; this authorizes the path the handler is *about to touch*. The two
/// differ whenever any part of the subject is derived after dispatch:
///
/// - `EXECUTE.resource` absent — then this is the **sole** resource enforcement,
///   because §3.2 runs no dispatch-level resource check at all;
/// - a path resolved at handler time (a `params.prefix` fallback, a merge
///   resolving a snapshot into individual writes);
/// - a listing expanded per entry (`CP-12a`'s wider class — the authorizer
///   evaluated a prefix *string*, the handler enumerates a *set*);
/// - `resource` present but the dispatch-level check made vacuous by a caller
///   exclude covering the caller's own target (`F68`/`CP-12a`).
///
/// §6.7 is **act-neutral** (0.8.2.20): reads or writes. The measured harm was a
/// `get` — disclosure rather than mutation.
///
/// `path` MUST come from [`effective_targets`], never `resource.targets[0]`.
/// Unlike [`check_permission`] this consults three dimensions, not four:
/// `handlers`, `operations`, `resources`. The `peers` dimension is the dispatch
/// boundary's and is not re-asked here (§6.3's pseudocode).
///
/// **Two canonicalization frames, as at §5.2 (PR-8).** §6.3's pseudocode passes
/// one `local_peer_id` and predates PR-8; taking it literally would let a
/// foreign-granted bare `*` in `resources` canonicalize into *our* namespace —
/// the V1' escalation — and that matters here precisely because this check is
/// **sole** enforcement when `resource` is absent, so no dispatch-level check
/// has applied the right frame first. The `path` is a request path and
/// canonicalizes against `local_peer_id`; the grant's `resources` patterns
/// canonicalize against `granter_peer_id`. `handlers` and `operations` carry no
/// peer-id namespace semantics and stay on the local frame. For a self-issued
/// capability the two coincide — pass `local_peer_id` twice.
///
/// ⛔ **The parameter is `authority`, not `capability` (§6.3 — renamed at
/// 0.8.2.21 because the old name is what caused the defect).** It is NOT *"the
/// capability on the request"*. It is the authority that authorized **this
/// dispatch for THIS path**, selected by **who NAMED the path** (§6.8), never
/// by who initiated the chain:
///
/// | the handler is about to touch | the authority is |
/// |---|---|
/// | a path the **caller named** — resource target, URI suffix, a `params` path the caller supplied | the caller's **verified** capability |
/// | a path the **handler derived** that the caller did not name — an autonomous write, a continuation's onward leg | the **executing handler's own grant** |
/// | a **peer-root** dispatch | **no check** — the capability is informational, and checking it would make this check stricter than the dispatch-level one for the same dispatch |
///
/// The two are the same value on the wire and different values everywhere else.
/// **Measured here:** on a continuation's standing leg the value arriving at
/// `system/tree:put` was the **inbox deliver token** (`handlers:[system/inbox]`,
/// `operations:[receive]`), four hops after the delivery that minted it, because
/// `caller_capability` propagates unchanged **for attribution** — its producer's
/// own comment says so. Two independent seats filled a parameter named
/// `capability` from that field.
///
/// ⚠ **Two rows of §6.8's table are NOT applied in this tree, and the reason is
/// a contradiction inside `0.8.2.21` rather than a gap here — routed.** The
/// table classes *"a merge expansion"* and *"a listing entry"* as
/// handler-derived and therefore authorized by the handler's own grant. Both
/// derive from a path the caller **did** name (`params.target_prefix`; the
/// listing prefix), and §6.3's own *"Listing filter"* MUST — unchanged in the
/// same revision — says each entry is checked *"against the **request's**
/// capability"*. Applying the table there would filter the listing against a
/// grant of `/*/*` and hand back exactly the entries `F71`/`CP-12a` closed.
/// This tree keeps §6.3's reading for both.
pub fn check_path_permission(
    operation: &str,
    path: &str,
    authority: &CapabilityToken,
    handler_pattern: &str,
    local_peer_id: &str,
    granter_peer_id: &str,
) -> bool {
    // A malformed path canonicalizes to NEVER_MATCH, which matches no grant
    // (§5.4), so it falls through to DENY below rather than being compared
    // against anything.
    let canonical_path = canonicalize(path, local_peer_id);

    authority.grants.iter().any(|grant| {
        matches_scope(
            handler_pattern,
            &grant.handlers.include,
            &grant.handlers.exclude,
            local_peer_id,
        ) && matches_id_scope(
            operation,
            &grant.operations.include,
            &grant.operations.exclude,
        ) && path_scope_admits_subject(
            // ⛔ **A FOURTH site of 0.8.2.21's fail-open, which the ruling does
            // not enumerate because all three of its sites are in §5.2 — and
            // this one is OURS, not the spec's.** §6.3's own pseudocode reads
            // `matches_scope(canonical_path, grant.resources, …)`; this line
            // open-coded it as `is_covered_by(include) && !is_covered_by(exclude)`,
            // which is `matches_scope`'s body with the 0.8.2.21 arm missing. An
            // unmatchable resource exclude therefore carved out nothing HERE
            // even after the three §5.2 sites were fixed — and this is the check
            // that is SOLE enforcement when `resource` is absent.
            //
            // The enforcement point is the call, not a fourth copy of the arm:
            // one rule, one function. Grep `is_covered_by(` on any path that is
            // implementing a scope rather than asking a containment question.
            //
            // **Frames (PR-8) survive the switch.** `matches_scope` canonicalizes
            // its value with the peer id it is given, and `canonical_path` is
            // already absolute — canonicalizing an absolute path is identity — so
            // passing `granter_peer_id` puts the grant's patterns in the granter
            // frame without moving the path into it.
            //
            // ⛔ **And a fifth shape at the same line: the subject may be a
            // PATTERN, and `matches_scope` answers the wrong question for one**
            // (§6.3, 0.8.2.22 — J3). `matches_scope`'s exclude test is
            // `matches_pattern`, a literal comparison, so a subject of
            // `/{p}/app/*` does not "match" the exclude `/{p}/app/secret` and is
            // ALLOWED — while the set it names plainly contains the excluded
            // path. See [`path_scope_admits_subject`] for the split.
            &canonical_path,
            &grant.resources,
            local_peer_id,
            granter_peer_id,
        )
    })
}

/// The resources dimension of §6.3, which is `matches_scope` for a **concrete**
/// subject and §5.2's pattern-target rule for a **pattern** one `[MUST]`
/// (0.8.2.22).
///
/// Two subjects, two questions that read alike:
///
/// - a **concrete** path asks *is this path in the scope?* — an exclude either
///   matches it or does not, and [`matches_scope`] answers it (with 0.8.2.21's
///   sentinel arm, which is why this function calls it rather than re-deriving);
/// - a **pattern** asks *is every path this could name in the scope?* — and a
///   literal exclude test answers the first question about the second subject,
///   which is a fail-OPEN. `/{p}/app/*` is not literally equal to the exclude
///   `/{p}/app/secret`, so it passes; the set it names contains `secret`.
///
/// §6.3 pins the pattern reading to §5.2's — *"a pattern subject is authorized
/// exactly as §5.2 authorizes a pattern target, with the caller-exclude set
/// empty"* — so this is the same [`pattern_subject_survives_grant_excludes`]
/// that `check_resource_scope`'s pattern arm calls, with `&[]` for the caller
/// exclude because §6.3 has no `resource` in scope to supply one.
///
/// ⚠ **Reachability, stated rather than implied, because an unreachable arm and
/// an overlooked one look identical from outside.** Neither production consumer
/// of [`check_path_permission`] passes a pattern today: `core/tree` passes
/// effective targets and listing/extract entries, `extensions/query` passes a
/// `candidate.path` — all concrete. The arm is written anyway because this is a
/// `pub fn` whose return value is a security verdict, and §6.3 names a
/// caller-facing rule that routes a pattern into it (`EXTENSION-SUBSCRIPTION`
/// §2.3's `include_payload` read check). In this tree that check does not go
/// through here — `extensions/subscription` routes it through
/// [`check_permission`], which reaches `check_resource_scope`'s pattern arm and
/// is therefore already conformant — so the hole was latent rather than live.
/// **An invariant that lives in the callers is one the next caller does not
/// inherit**, and the next caller is the one this arm is for.
fn path_scope_admits_subject(
    canonical_subject: &str,
    scope: &PathScope,
    local_peer_id: &str,
    granter_peer_id: &str,
) -> bool {
    if !is_pattern(canonical_subject) {
        return matches_scope(
            canonical_subject,
            &scope.include,
            &scope.exclude,
            granter_peer_id,
        );
    }
    // The include half is the same coverage test under either subject shape —
    // `matches_scope` runs `matches_pattern(value, include_pattern)` and so does
    // `is_covered_by`. Only the exclude half differs, which is the whole of J3.
    is_covered_by(canonical_subject, &scope.include, granter_peer_id)
        && pattern_subject_survives_grant_excludes(
            canonical_subject,
            &scope.exclude,
            &[],
            local_peer_id,
            granter_peer_id,
        )
}

// ---------------------------------------------------------------------------
// Attenuation (§5.6)
// ---------------------------------------------------------------------------

/// Check that a child capability is a valid attenuation of its parent.
///
/// The child can only restrict, never amplify — every child grant must be
/// covered by some parent grant, and expiration cannot exceed parent's.
///
/// **Self-issued frame:** both caps' peer-relative resource patterns
/// canonicalize against `local_peer_id`. Correct when granter == local peer at
/// every link (the dominant self-issued path: capability/role handlers minting
/// from the caller's own cap). For a delegation **chain** whose links have
/// *different* granters, use [`is_attenuated_framed`] — V7 §5.5a requires each
/// link's resources to canonicalize against its OWN granter's namespace.
pub fn is_attenuated(
    child: &CapabilityToken,
    parent: &CapabilityToken,
    local_peer_id: &str,
) -> bool {
    is_attenuated_inner(child, parent, local_peer_id, local_peer_id, local_peer_id)
}

/// Per-link granter-frame attenuation check (V7 §5.5a / §PR-8 — the chain-walk
/// surface, distinct from the dispatch boundary).
///
/// Identical to [`is_attenuated`] except each cap's **resource** patterns
/// canonicalize against ITS OWN granter's peer_id — `child_granter_peer_id`
/// for the child cap, `parent_granter_peer_id` for the parent. Per V7 §5.5 a
/// bare `*` means `/{granter_peer_id}/*` (the granter's own namespace), so a
/// foreign-granted bare `*` in a parent link no longer silently covers the
/// verifier's namespace — the V1' authority-escalation the cohort confirmed.
/// Handlers, operations, and peers carry no peer-id namespace semantics and
/// stay on `local_peer_id`. `verify_capability_chain` derives both granter
/// peer_ids from the chain's included identities and calls this; self-issued
/// callers use [`is_attenuated`] (granter == local at every link).
pub fn is_attenuated_framed(
    child: &CapabilityToken,
    parent: &CapabilityToken,
    child_granter_peer_id: &str,
    parent_granter_peer_id: &str,
    local_peer_id: &str,
) -> bool {
    is_attenuated_inner(
        child,
        parent,
        child_granter_peer_id,
        parent_granter_peer_id,
        local_peer_id,
    )
}

fn is_attenuated_inner(
    child: &CapabilityToken,
    parent: &CapabilityToken,
    child_granter_peer_id: &str,
    parent_granter_peer_id: &str,
    local_peer_id: &str,
) -> bool {
    // Every child grant must be covered by some parent grant
    for child_grant in &child.grants {
        if !grant_covered_by(
            child_grant,
            &parent.grants,
            child_granter_peer_id,
            parent_granter_peer_id,
            local_peer_id,
        ) {
            return false;
        }
    }

    // Child expiration must not exceed parent's
    if let Some(parent_exp) = parent.expires_at {
        match child.expires_at {
            None => return false, // child infinite, parent finite
            Some(child_exp) if child_exp > parent_exp => return false,
            _ => {}
        }
    }

    true
}

/// Check if a child grant is covered by any parent grant.
fn grant_covered_by(
    child_grant: &GrantEntry,
    parent_grants: &[GrantEntry],
    child_granter_peer_id: &str,
    parent_granter_peer_id: &str,
    local_peer_id: &str,
) -> bool {
    parent_grants.iter().any(|pg| {
        grant_subset(
            child_grant,
            pg,
            child_granter_peer_id,
            parent_granter_peer_id,
            local_peer_id,
        )
    })
}

/// Check if a child grant is a subset of a parent grant (all four dimensions).
///
/// Per V7 §5.5a / §PR-8, only the **resource** dimension is granter-frame-
/// relative: child resources canonicalize against `child_granter_peer_id`,
/// parent resources against `parent_granter_peer_id`. Handlers, operations,
/// and peers have no peer-id namespace semantics and stay on `local_peer_id`
/// for both sides (existing behavior).
fn grant_subset(
    child: &GrantEntry,
    parent: &GrantEntry,
    child_granter_peer_id: &str,
    parent_granter_peer_id: &str,
    local_peer_id: &str,
) -> bool {
    if !grant_axes_subset(
        child,
        parent,
        child_granter_peer_id,
        parent_granter_peer_id,
        local_peer_id,
    ) {
        return false;
    }

    // Constraint attenuation (§5.6): child MUST retain all parent constraint keys
    // with byte-identical values. Child MAY add new constraint keys (narrows).
    let empty_map = std::collections::BTreeMap::new();
    let parent_constraints = parent.constraints.as_ref().unwrap_or(&empty_map);
    let child_constraints = child.constraints.as_ref().unwrap_or(&empty_map);
    for (key, parent_val) in parent_constraints {
        match child_constraints.get(key) {
            None => return false, // Key dropped — escalation
            Some(child_val) if !cbor_bytes_equal(parent_val, child_val) => return false, // Value changed
            _ => {} // Key present, value identical
        }
    }

    // Allowance attenuation (§5.6): child MUST NOT add keys parent doesn't have.
    // Child MAY remove allowance keys (narrows).
    let parent_allowances = parent.allowances.as_ref().unwrap_or(&empty_map);
    let child_allowances = child.allowances.as_ref().unwrap_or(&empty_map);
    for (key, child_val) in child_allowances {
        match parent_allowances.get(key) {
            None => return false, // Key added — escalation
            Some(parent_val) if !cbor_bytes_equal(parent_val, child_val) => return false, // Value changed
            _ => {} // Key present, value identical
        }
    }

    true
}

/// The **four-axis** half of [`grant_subset`] — handlers, operations,
/// resources, peers — without §5.6's constraint/allowance attenuation.
///
/// Split out because the §3 advertisement filter names exactly these four
/// (see [`advertisement_covers`]) while delegation attenuation needs both
/// halves. Delegation's behavior is unchanged: `grant_subset` calls this first
/// and then applies §5.6 as before.
fn grant_axes_subset(
    child: &GrantEntry,
    parent: &GrantEntry,
    child_granter_peer_id: &str,
    parent_granter_peer_id: &str,
    local_peer_id: &str,
) -> bool {
    // Handlers: no §PR-8 frame — both sides canonicalize under local_peer_id.
    if !scope_subset_path(
        &child.handlers,
        &parent.handlers,
        local_peer_id,
        local_peer_id,
    ) {
        return false;
    }
    if !scope_subset_id(&child.operations, &parent.operations) {
        return false;
    }
    // Resources: §PR-8 per-link granter frame (child vs parent granter).
    if !scope_subset_path(
        &child.resources,
        &parent.resources,
        child_granter_peer_id,
        parent_granter_peer_id,
    ) {
        return false;
    }
    let default_peers = IdScope::new(vec![local_peer_id.into()]);
    let child_peers = child.peers.as_ref().unwrap_or(&default_peers);
    let parent_peers = parent.peers.as_ref().unwrap_or(&default_peers);
    scope_subset_id(child_peers, parent_peers)
}

/// Does an advertised served-scope **cover** a grant entry?
///
/// The §4.4 / EXTENSION-SIGNALING §6.5 (b) *advertisement filter* (arch ruling
/// 2026-08-05): an assembled entry is retained iff some advertised entry covers
/// it under the **same four-axis `scope_subset` relation the chain uses for
/// attenuation** — i.e. [`grant_subset`], the one already used for delegation.
/// Exact-op-match and namespace-prefix-match are explicitly non-conformant, so
/// this deliberately reuses the relation rather than re-deriving a filter.
///
/// **Four axes only.** The ruling says *four-axis*, so this uses
/// [`grant_axes_subset`], not `grant_subset` — §5.6's allowance rule ("child
/// MUST NOT add keys the parent lacks") is right for delegation and wrong here:
/// a handler manifest expresses no allowances, so applying it would drop every
/// operator-authored entry carrying one, silently and entry-wide.
///
/// **Entry-level, and drop-not-narrow.** An entry that is only partly covered
/// is dropped whole; rewriting its scope would hand the counterpart a grant no
/// operator authored.
///
/// All three granter frames collapse to `local_peer_id`: the advertised scope
/// and the assembled entry are both authored by *this* peer at the same moment,
/// so §PR-8's per-link granter frame has no two links to distinguish.
pub fn advertisement_covers(
    advertised: &[GrantEntry],
    entry: &GrantEntry,
    local_peer_id: &str,
) -> bool {
    // UNIVERSAL-HANDLER CARVE-OUT — the boundary the ruling does not address.
    //
    // An advertised served-scope is a finite set of registered handlers, so no
    // union of advertised entries can cover a `handlers: ["*"]` claim. Under a
    // literal "uncovered entries drop, not narrow", every open-access grant is
    // deleted and such a peer hands its counterparts exactly nothing.
    //
    // That does not close a divergence — the ruling's worked example is a
    // *narrower* mismatch (`system/tree:put` against an advertised `foo/*`),
    // which is what the four-axis relation genuinely fixes. A `*` grant
    // dispatched at a registered handler works, and at an unregistered one 404s
    // — the same outcome an absent grant reaches one layer later.
    //
    // So bare `*` is retained iff this peer serves anything at all: "backed by
    // whatever we serve", not "always backed". `entity-core-go` reached the same
    // carve-out independently (`advertisedCovers`, `core/protocol/connect.go`)
    // and routed it; this is convergence on their landed shape, not two
    // implementations agreeing by construction. Routed to arch — if the literal
    // reading is ruled, this block deletes and the pin below changes with it.
    if entry.handlers.include.iter().any(|p| p == "*") {
        return !advertised.is_empty();
    }
    advertised
        .iter()
        .any(|a| grant_axes_subset(entry, a, local_peer_id, local_peer_id, local_peer_id))
}

/// Compare two ciborium::Values by their canonical CBOR encoding.
fn cbor_bytes_equal(a: &ciborium::Value, b: &ciborium::Value) -> bool {
    let mut buf_a = Vec::new();
    let mut buf_b = Vec::new();
    if ciborium::into_writer(a, &mut buf_a).is_err() {
        return false;
    }
    if ciborium::into_writer(b, &mut buf_b).is_err() {
        return false;
    }
    buf_a == buf_b
}

/// Check if child PathScope is a subset of parent PathScope (§5.6).
///
/// Each side canonicalizes its peer-relative patterns against its OWN frame
/// (V7 §5.5a / §PR-8): child against `child_canon_peer_id`, parent against
/// `parent_canon_peer_id`. For dimensions where §PR-8 does not apply (handlers),
/// callers pass the same `local_peer_id` for both — one frame, behavior
/// unchanged.
fn scope_subset_path(
    child: &PathScope,
    parent: &PathScope,
    child_canon_peer_id: &str,
    parent_canon_peer_id: &str,
) -> bool {
    // Every child include must be covered by some parent include.
    // An unmatchable child include (NEVER_MATCH) is covered by nothing and
    // denies — the same answer the `Option` form gave, for the same reason.
    for ci in &child.include {
        let cc = canonicalize(ci, child_canon_peer_id);
        if !parent
            .include
            .iter()
            .any(|pi| matches_pattern(&cc, &canonicalize(pi, parent_canon_peer_id)))
        {
            return false;
        }
    }

    // Child must inherit ALL parent excludes. An unmatchable parent exclude is
    // inherited by nothing and denies — again unchanged, and deliberately left
    // strict: §5.6 is not among §5.4's three ruled consumers of NEVER_MATCH,
    // and refusing an attenuation we cannot reason about costs a delegation
    // rather than a grant.
    for pe in &parent.exclude {
        let cp = canonicalize(pe, parent_canon_peer_id);
        let child_has = child
            .exclude
            .iter()
            .any(|ce| matches_pattern(&cp, &canonicalize(ce, child_canon_peer_id)));
        if !child_has {
            return false;
        }
    }

    true
}

/// Check if child IdScope is a subset of parent IdScope (§5.2, §5.6).
///
/// id-scope compares literally — no canonicalization frame, unlike
/// [`scope_subset_path`].
fn scope_subset_id(child: &IdScope, parent: &IdScope) -> bool {
    // Every child include must be covered by some parent include
    for ci in &child.include {
        if !parent.include.iter().any(|pi| matches_id_pattern(ci, pi)) {
            return false;
        }
    }

    // Child must inherit ALL parent excludes
    for pe in &parent.exclude {
        let child_has = child.exclude.iter().any(|ce| matches_id_pattern(pe, ce));
        if !child_has {
            return false;
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Delegation caveats (§5.7)
// ---------------------------------------------------------------------------

/// Check delegation caveats from parent against child capability.
pub fn check_delegation_caveats(
    parent: &CapabilityToken,
    child: &CapabilityToken,
    depth: u64,
) -> bool {
    let caveats = match &parent.delegation_caveats {
        None => return true,
        Some(c) => c,
    };

    if caveats.no_delegation == Some(true) {
        return false;
    }

    if let Some(max_depth) = caveats.max_delegation_depth {
        if depth >= max_depth {
            return false;
        }
    }

    if let Some(max_ttl) = caveats.max_delegation_ttl {
        match child.expires_at {
            None => return false, // infinite lifetime exceeds any finite limit
            Some(exp) => {
                let child_ttl = exp.saturating_sub(child.created_at);
                if child_ttl > max_ttl {
                    return false;
                }
            }
        }
    }

    true
}

// ---------------------------------------------------------------------------
// CBOR encode/decode for CapabilityToken
// ---------------------------------------------------------------------------

impl CapabilityToken {
    /// Validate well-formedness of the cap (SEC-18 / M3 / V7 v7.39 PR-3).
    ///
    /// Defense-in-depth check intended to be called by mint-time call sites
    /// (role assign/delegate, custom cap-issuance handlers). Mirrors Go's
    /// `CapabilityTokenData.ValidateStructure`. Returns:
    /// - `Invalid` for the M3 multi-sig parent constraint
    /// - `Invalid` (with an `unresolvable_grantee` marker in the message)
    ///   for a zero-hash grantee — never resolves to a `system/peer` entity,
    ///   so the cap would fail chain-walk under PR-3 anyway.
    ///
    /// Chain-walk in `core/protocol/verify.rs::verify_capability_chain` is
    /// the load-bearing enforcement; this method just lets issuers fail
    /// fast at mint time instead of leaving a dud cap bound in the tree.
    pub fn validate_structure(&self) -> Result<(), CapabilityError> {
        if let Granter::Multi(multi) = &self.granter {
            if self.parent.is_some() {
                return Err(CapabilityError::Invalid(
                    "multi-sig capability MUST have parent: null (M3)".into(),
                ));
            }
            multi.validate()?;
        }
        if self.grantee.is_zero() {
            return Err(CapabilityError::Invalid(
                "unresolvable_grantee: capability grantee MUST be a non-zero \
                 hash (SEC-18 / V7 v7.39 PR-3)"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Encode to ECF bytes suitable for creating an entity.
    pub fn to_ecf(&self) -> Vec<u8> {
        use entity_ecf::{text, uinteger, Value};

        let mut entries = Vec::new();

        // created_at
        entries.push((text("created_at"), uinteger(self.created_at)));

        // delegation_caveats
        if let Some(ref dc) = self.delegation_caveats {
            entries.push((text("delegation_caveats"), dc.to_value()));
        }

        // expires_at
        if let Some(exp) = self.expires_at {
            entries.push((text("expires_at"), uinteger(exp)));
        }

        // grantee
        entries.push((
            text("grantee"),
            Value::Bytes(self.grantee.to_bytes().to_vec()),
        ));

        // granter — polymorphic per M1/M8: bstr for single-sig, map for multi-sig
        entries.push((text("granter"), encode_granter(&self.granter)));

        // grants
        let grants: Vec<Value> = self.grants.iter().map(|g| g.to_value()).collect();
        entries.push((text("grants"), Value::Array(grants)));

        // not_before
        if let Some(nb) = self.not_before {
            entries.push((text("not_before"), uinteger(nb)));
        }

        // parent
        if let Some(ref p) = self.parent {
            entries.push((text("parent"), Value::Bytes(p.to_bytes().to_vec())));
        }

        entity_ecf::to_ecf(&Value::Map(entries))
    }

    /// Create an entity from this capability token under the process home
    /// `content_hash_format` ([`entity_hash::default_hash_format`] — V7 §1.2).
    /// Connection caps minted under a negotiated active format (§4.5a) use
    /// [`CapabilityToken::to_entity_with_format`] instead.
    pub fn to_entity(&self) -> Result<entity_entity::Entity, CapabilityError> {
        self.to_entity_with_format(entity_hash::default_hash_format())
    }

    /// Create an entity from this capability token under an explicit
    /// `content_hash_format` (V7 §4.5a — mint connection caps under the
    /// negotiated active format). A cap chain has a self-consistent format
    /// (§5.5 freeze), so every link a peer mints for a connection uses the
    /// connection's active format.
    pub fn to_entity_with_format(
        &self,
        format_code: u8,
    ) -> Result<entity_entity::Entity, CapabilityError> {
        let data = self.to_ecf();
        entity_entity::Entity::new_with_format(entity_types::TYPE_CAP_TOKEN, data, format_code)
            .map_err(|e| CapabilityError::EntityError(e.to_string()))
    }

    /// Decode a CapabilityToken from an entity.
    pub fn from_entity(entity: &entity_entity::Entity) -> Result<Self, CapabilityError> {
        if entity.entity_type != entity_types::TYPE_CAP_TOKEN {
            return Err(CapabilityError::Invalid(format!(
                "expected {}, got {}",
                entity_types::TYPE_CAP_TOKEN,
                entity.entity_type
            )));
        }

        let value: ciborium::Value = ciborium::from_reader(entity.data.as_slice())
            .map_err(|e| CapabilityError::Invalid(e.to_string()))?;
        let map = value
            .as_map()
            .ok_or_else(|| CapabilityError::Invalid("capability data must be a map".into()))?;

        let mut grants = None;
        let mut granter = None;
        let mut grantee = None;
        let mut parent = None;
        let mut created_at = None;
        let mut expires_at = None;
        let mut not_before = None;
        let mut delegation_caveats = None;

        for (k, v) in map {
            match k.as_text() {
                Some("grants") => {
                    let arr = v.as_array().ok_or_else(|| {
                        CapabilityError::Invalid("grants must be an array".into())
                    })?;
                    let mut entries = Vec::new();
                    for item in arr {
                        entries.push(decode_grant_entry(item)?);
                    }
                    grants = Some(entries);
                }
                Some("granter") => {
                    granter = Some(decode_granter(v)?);
                }
                Some("grantee") => {
                    if let Some(b) = v.as_bytes() {
                        grantee = Some(
                            Hash::from_bytes(b)
                                .map_err(|e| CapabilityError::Invalid(e.to_string()))?,
                        );
                    }
                }
                Some("parent") => {
                    if let Some(b) = v.as_bytes() {
                        parent = Some(
                            Hash::from_bytes(b)
                                .map_err(|e| CapabilityError::Invalid(e.to_string()))?,
                        );
                    }
                }
                Some("created_at") => {
                    created_at = decode_temporal_field(v, "created_at")?;
                }
                Some("expires_at") => {
                    expires_at = decode_temporal_field(v, "expires_at")?;
                }
                Some("not_before") => {
                    not_before = decode_temporal_field(v, "not_before")?;
                }
                Some("delegation_caveats") => {
                    delegation_caveats = Some(decode_delegation_caveats(v)?);
                }
                _ => {}
            }
        }

        Ok(CapabilityToken {
            grants: grants.ok_or_else(|| CapabilityError::Invalid("missing grants".into()))?,
            granter: granter.ok_or_else(|| CapabilityError::Invalid("missing granter".into()))?,
            grantee: grantee.ok_or_else(|| CapabilityError::Invalid("missing grantee".into()))?,
            parent,
            created_at: created_at
                .ok_or_else(|| CapabilityError::Invalid("missing created_at".into()))?,
            expires_at,
            not_before,
            delegation_caveats,
        })
    }
}

/// Decode one of the token's `primitive/uint` millisecond fields
/// (`created_at` / `expires_at` / `not_before`).
///
/// **A value that does not fit `u64` is malformed, not absent.** Reading it as
/// absent is fail-*open* on the one field that bounds a token's life: an
/// `expires_at` a peer minted at arbitrary precision (`created_at + ttl_ms`
/// with no overflow check — the CAP-6 defect) would land here as "no expiry"
/// and hand the grantee an immortal cap, while a `u64` implementation that
/// refuses to decode it — go does — sees a malformed token. Two peers reading
/// one token two ways is exactly what §5.10 cross-peer determinism forbids, so
/// this refuses too. §5.6's rule is that an unrepresentable term is **absent**
/// on the wire, and only the minter can make it so.
///
/// `null` stays legal: our optional-field convention is *SHOULD be absent, null
/// is valid*, and both spell "no bound".
fn decode_temporal_field(v: &ciborium::Value, field: &str) -> Result<Option<u64>, CapabilityError> {
    if v.is_null() {
        return Ok(None);
    }
    let i = v.as_integer().ok_or_else(|| {
        CapabilityError::Invalid(format!("{field} must be an integer (primitive/uint)"))
    })?;
    u64::try_from(i).map(Some).map_err(|_| {
        CapabilityError::Invalid(format!(
            "{field} does not fit primitive/uint — an unrepresentable temporal value MUST be \
             absent on the wire, never carried at arbitrary precision, wrapped, or saturated"
        ))
    })
}

impl GrantEntry {
    fn to_value(&self) -> entity_ecf::Value {
        encode_grant_entry(self)
    }
}

/// Encode a grant entry to ECF CBOR. Public so consumer extensions
/// (identity peer-config, role) can serialize grants without a full
/// CapabilityToken round-trip.
pub fn encode_grant_entry(g: &GrantEntry) -> entity_ecf::Value {
    use entity_ecf::{text, Value};
    let mut entries = Vec::new();
    if let Some(ref allowances) = g.allowances {
        entries.push((text("allowances"), string_map_to_ecf(allowances)));
    }
    if let Some(ref constraints) = g.constraints {
        entries.push((text("constraints"), string_map_to_ecf(constraints)));
    }
    entries.push((text("handlers"), scope_to_value_path(&g.handlers)));
    entries.push((text("operations"), scope_to_value_id(&g.operations)));
    if let Some(ref peers) = g.peers {
        entries.push((text("peers"), scope_to_value_id(peers)));
    }
    entries.push((text("resources"), scope_to_value_path(&g.resources)));
    Value::Map(entries)
}

/// Convert a BTreeMap<String, ciborium::Value> to entity_ecf::Value for encoding.
fn string_map_to_ecf(
    map: &std::collections::BTreeMap<String, ciborium::Value>,
) -> entity_ecf::Value {
    use entity_ecf::{text, Value};
    Value::Map(
        map.iter()
            .map(|(k, v)| (text(k), ciborium_to_ecf(v)))
            .collect(),
    )
}

/// Convert a ciborium::Value to entity_ecf::Value for encoding in grant entries.
fn ciborium_to_ecf(val: &ciborium::Value) -> entity_ecf::Value {
    use entity_ecf::Value;
    match val {
        ciborium::Value::Null => Value::Null,
        ciborium::Value::Bool(b) => Value::Bool(*b),
        ciborium::Value::Integer(i) => {
            let n: i128 = (*i).into();
            entity_ecf::integer(n as i64)
        }
        ciborium::Value::Text(s) => Value::Text(s.clone()),
        ciborium::Value::Bytes(b) => Value::Bytes(b.clone()),
        ciborium::Value::Array(arr) => Value::Array(arr.iter().map(ciborium_to_ecf).collect()),
        ciborium::Value::Map(map) => Value::Map(
            map.iter()
                .map(|(k, v)| (ciborium_to_ecf(k), ciborium_to_ecf(v)))
                .collect(),
        ),
        ciborium::Value::Float(f) => Value::Float(*f),
        _ => Value::Null,
    }
}

fn scope_to_value_path(scope: &PathScope) -> entity_ecf::Value {
    use entity_ecf::{text, Value};
    let mut entries = Vec::new();
    if !scope.exclude.is_empty() {
        let exc: Vec<Value> = scope.exclude.iter().map(text).collect();
        entries.push((text("exclude"), Value::Array(exc)));
    }
    let inc: Vec<Value> = scope.include.iter().map(text).collect();
    entries.push((text("include"), Value::Array(inc)));
    Value::Map(entries)
}

fn scope_to_value_id(scope: &IdScope) -> entity_ecf::Value {
    use entity_ecf::{text, Value};
    let mut entries = Vec::new();
    if !scope.exclude.is_empty() {
        let exc: Vec<Value> = scope.exclude.iter().map(text).collect();
        entries.push((text("exclude"), Value::Array(exc)));
    }
    let inc: Vec<Value> = scope.include.iter().map(text).collect();
    entries.push((text("include"), Value::Array(inc)));
    Value::Map(entries)
}

/// Encode a `Granter` to ECF Value (M8).
///
/// - `Granter::Single(hash)` → CBOR byte string (major type 2)
/// - `Granter::Multi(multi)` → CBOR map (major type 5) with `signers` and `threshold`
///
/// No CBOR tags are emitted (ENTITY-CBOR-ENCODING.md §11).
pub fn encode_granter(granter: &Granter) -> entity_ecf::Value {
    use entity_ecf::{integer, text, Value};
    match granter {
        Granter::Single(h) => Value::Bytes(h.to_bytes().to_vec()),
        Granter::Multi(m) => {
            let signers: Vec<Value> = m
                .signers
                .iter()
                .map(|h| Value::Bytes(h.to_bytes().to_vec()))
                .collect();
            // ECF key order: signers, threshold (alphabetical)
            Value::Map(vec![
                (text("signers"), Value::Array(signers)),
                (text("threshold"), integer(m.threshold as i64)),
            ])
        }
    }
}

/// Decode a `Granter` from a CBOR value (M8).
///
/// Branches on CBOR major type:
/// - byte string (`as_bytes`) → `Granter::Single`
/// - map (`as_map`) → `Granter::Multi`
/// - any other type (including tag-wrapped) → reject (M8 bans tags on data fields)
pub fn decode_granter(value: &ciborium::Value) -> Result<Granter, CapabilityError> {
    // Tag rejection (M8 / ENTITY-CBOR-ENCODING.md §11): test vector #18c.
    if matches!(value, ciborium::Value::Tag(_, _)) {
        return Err(CapabilityError::Invalid(
            "granter MUST NOT be CBOR-tagged (ENTITY-CBOR-ENCODING.md §11)".into(),
        ));
    }
    if let Some(b) = value.as_bytes() {
        let h = Hash::from_bytes(b).map_err(|e| CapabilityError::Invalid(e.to_string()))?;
        return Ok(Granter::Single(h));
    }
    if let Some(map) = value.as_map() {
        let mut signers: Option<Vec<Hash>> = None;
        let mut threshold: Option<u64> = None;
        for (k, v) in map {
            match k.as_text() {
                Some("signers") => {
                    let arr = v.as_array().ok_or_else(|| {
                        CapabilityError::Invalid("multi-granter signers must be an array".into())
                    })?;
                    let mut out = Vec::with_capacity(arr.len());
                    for item in arr {
                        let bytes = item.as_bytes().ok_or_else(|| {
                            CapabilityError::Invalid(
                                "multi-granter signer entries must be byte strings".into(),
                            )
                        })?;
                        out.push(
                            Hash::from_bytes(bytes)
                                .map_err(|e| CapabilityError::Invalid(e.to_string()))?,
                        );
                    }
                    signers = Some(out);
                }
                Some("threshold") => {
                    threshold = v.as_integer().and_then(|i| u64::try_from(i).ok());
                }
                _ => {}
            }
        }
        let signers = signers
            .ok_or_else(|| CapabilityError::Invalid("multi-granter missing signers".into()))?;
        let threshold = threshold
            .ok_or_else(|| CapabilityError::Invalid("multi-granter missing threshold".into()))?;
        return Ok(Granter::Multi(MultiGranter { signers, threshold }));
    }
    Err(CapabilityError::Invalid(
        "granter must be a byte string (single-sig) or map (multi-sig)".into(),
    ))
}

/// Decode a single grant entry CBOR value into a GrantEntry struct.
/// Made public so handler-side code (e.g., the handlers handler installing a
/// derived grant from a manifest's `internal_scope` array) can decode without
/// going through full CapabilityToken::from_entity round-trips.
pub fn decode_grant_entry(value: &ciborium::Value) -> Result<GrantEntry, CapabilityError> {
    let map = value
        .as_map()
        .ok_or_else(|| CapabilityError::Invalid("grant entry must be a map".into()))?;

    let mut handlers = None;
    let mut resources = None;
    let mut operations = None;
    let mut peers = None;
    let mut constraints = None;
    let mut allowances = None;

    for (k, v) in map {
        match k.as_text() {
            Some("handlers") => handlers = Some(decode_path_scope(v)?),
            Some("resources") => resources = Some(decode_path_scope(v)?),
            Some("operations") => operations = Some(decode_id_scope(v)?),
            Some("peers") => peers = Some(decode_id_scope(v)?),
            Some("constraints") => constraints = Some(decode_string_keyed_map(v)),
            Some("allowances") => allowances = Some(decode_string_keyed_map(v)),
            _ => {}
        }
    }

    Ok(GrantEntry {
        handlers: handlers
            .ok_or_else(|| CapabilityError::Invalid("missing handlers in grant".into()))?,
        resources: resources
            .ok_or_else(|| CapabilityError::Invalid("missing resources in grant".into()))?,
        operations: operations
            .ok_or_else(|| CapabilityError::Invalid("missing operations in grant".into()))?,
        peers,
        constraints,
        allowances,
    })
}

/// Decode a CBOR map into a BTreeMap<String, ciborium::Value>.
/// Non-map values are treated as empty maps (defensive).
fn decode_string_keyed_map(
    value: &ciborium::Value,
) -> std::collections::BTreeMap<String, ciborium::Value> {
    let mut result = std::collections::BTreeMap::new();
    if let Some(entries) = value.as_map() {
        for (k, v) in entries {
            if let Some(key) = k.as_text() {
                result.insert(key.to_string(), v.clone());
            }
        }
    }
    result
}

/// Decode include/exclude string lists from a CBOR scope map.
fn decode_scope_lists(
    value: &ciborium::Value,
) -> Result<(Vec<String>, Vec<String>), CapabilityError> {
    let map = value
        .as_map()
        .ok_or_else(|| CapabilityError::Invalid("scope must be a map".into()))?;

    let mut include = Vec::new();
    let mut exclude = Vec::new();

    for (k, v) in map {
        let target = match k.as_text() {
            Some("include") => &mut include,
            Some("exclude") => &mut exclude,
            _ => continue,
        };
        if let Some(arr) = v.as_array() {
            for item in arr {
                if let Some(s) = item.as_text() {
                    target.push(s.to_string());
                }
            }
        }
    }

    Ok((include, exclude))
}

fn decode_path_scope(value: &ciborium::Value) -> Result<PathScope, CapabilityError> {
    let (include, exclude) = decode_scope_lists(value)?;
    Ok(PathScope { include, exclude })
}

fn decode_id_scope(value: &ciborium::Value) -> Result<IdScope, CapabilityError> {
    let (include, exclude) = decode_scope_lists(value)?;
    Ok(IdScope { include, exclude })
}

fn decode_delegation_caveats(
    value: &ciborium::Value,
) -> Result<DelegationCaveats, CapabilityError> {
    let map = value
        .as_map()
        .ok_or_else(|| CapabilityError::Invalid("delegation_caveats must be a map".into()))?;

    let mut no_delegation = None;
    let mut max_delegation_depth = None;
    let mut max_delegation_ttl = None;

    for (k, v) in map {
        match k.as_text() {
            Some("no_delegation") => no_delegation = v.as_bool(),
            Some("max_delegation_depth") => {
                max_delegation_depth = v.as_integer().and_then(|i| u64::try_from(i).ok());
            }
            Some("max_delegation_ttl") => {
                max_delegation_ttl = v.as_integer().and_then(|i| u64::try_from(i).ok());
            }
            _ => {}
        }
    }

    Ok(DelegationCaveats {
        no_delegation,
        max_delegation_depth,
        max_delegation_ttl,
    })
}

impl DelegationCaveats {
    fn to_value(&self) -> entity_ecf::Value {
        use entity_ecf::{text, Value};
        let mut entries = Vec::new();
        if let Some(max_depth) = self.max_delegation_depth {
            entries.push((
                text("max_delegation_depth"),
                entity_ecf::integer(max_depth as i64),
            ));
        }
        if let Some(max_ttl) = self.max_delegation_ttl {
            entries.push((
                text("max_delegation_ttl"),
                entity_ecf::integer(max_ttl as i64),
            ));
        }
        if let Some(nd) = self.no_delegation {
            entries.push((text("no_delegation"), entity_ecf::bool_val(nd)));
        }
        Value::Map(entries)
    }
}

#[derive(Debug, Error)]
pub enum CapabilityError {
    #[error("capability denied: {0}")]
    Denied(String),

    #[error("invalid capability: {0}")]
    Invalid(String),

    #[error("delegation error: {0}")]
    DelegationError(String),

    #[error("entity error: {0}")]
    EntityError(String),

    #[error("expired capability")]
    Expired,
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL_PEER: &str = "2DFfrCdapVgjiNBPRUdNpwKLfLsmUaKHod4jmhakzBDs3W";
    /// A second peer id. MUST be a real 46-char Base58 string, not a readable
    /// placeholder: since 0.8.2.20 `check_resource_scope` consumes
    /// `validate_absolute_path`'s verdict on every concrete target (§5.4 R11/G6),
    /// so `/some-other-peer/...` is now a malformed path and denies — which is
    /// the check working, and three fixtures here were that shape.
    const OTHER_PEER: &str = "2EGgsDebqWhkjXCQSVeQqxLgMtnVbLJpe5knibmkzCEt4X";

    /// §6.2 — the default per-handler self-grant carries `peers` **absent**, and
    /// `resources` **`/*/*`**. The two are pinned in one test because they are
    /// the two halves of one sentence and each is the wrong answer to the
    /// other's question.
    ///
    /// `peers` absent defaults to `{include: [local_peer_id]}` and is still
    /// checked (§5.2 Dimension 4), so a default-scope handler cannot dispatch at
    /// a foreign peer. `IdScope::all()` — which we shipped until arch ruled go's
    /// spec-issue `2026-08-23-a` — authorizes exactly that, under a bootstrap
    /// grant nobody minted for the purpose. §6.2 names it "specifically wrong"
    /// and "the one direction that must not be widened".
    ///
    /// `resources` stays `/*/*` and this test exists as much to hold that as to
    /// move `peers`. Edit E proposed narrowing it to `/{local_peer_id}/*`;
    /// entity-core-go refuted it by building it (their foreign-namespace ceiling
    /// test failed), and arch withdrew the narrowing at 0.8.2.3. The reason the
    /// two dimensions differ is §6.3: a peer's store is ONE local address space
    /// keyed by peer id, so `/{them}/…` is a local region and writing there is a
    /// local write. `resources` bounds the address space; `peers` bounds the
    /// network. Narrowing `resources` closes no hole `peers` does not already
    /// close, and it breaks the follow-mirror write.
    ///
    /// This is inert in this tree today — `make_execute_fn` returns at its
    /// `is_remote` branch before the ceiling check, so Dimension 4 never sees a
    /// foreign target on that path. That is the argument FOR pinning it, not
    /// against: an unread field spelled wrong is the exact shape that produced
    /// the `resources` defect the moment D1 made this grant an enforcement input.
    #[test]
    fn the_default_handler_self_grant_omits_peers_and_spans_namespaces() {
        let grant = default_handler_self_grant();
        assert_eq!(grant.len(), 1, "§6.2 describes a single default entry");
        assert!(
            grant[0].peers.is_none(),
            "`peers` MUST be absent, not `*`. Absent means the local peer and is \
             still checked; `*` authorizes sub-dispatch at foreign peers' \
             handlers and undoes the dimension §5.2 Dimension 4 exists to close"
        );
        assert_eq!(
            grant[0].resources.include,
            vec!["/*/*".to_string()],
            "`resources` MUST stay universal. Bare `*` canonicalizes to \
             `/{{local}}/*` and a narrowed ceiling 403s a default-scope handler's \
             follow-mirror write into the foreign-namespace region its OWN store \
             holds (§1.4 Category A) — the regression Edit E proposed and arch \
             withdrew at 0.8.2.3"
        );

        // The neighbouring constructor keeps `*`, and that is deliberate: it is
        // the own-namespace form for call sites that want confinement. If a
        // future edit "unifies" the two, this row is what says they were never
        // the same function.
        assert!(
            wildcard_handler_grant()[0].peers.is_some(),
            "`wildcard_handler_grant` is a different grant with a different \
             purpose — collapsing the two is how the default gets re-widened"
        );
    }

    // --- resolve_granter_peer_id (PR-8 / V7 §5.5) ---
    //
    // These pin the B-side decision point behind the cross-impl
    // `convergence.rexec_delivered` seam (arch `ROUTING-2026-08-13-m`,
    // relaying `entity-core-go`). Under EXTENSION-CONTINUATION §4.2 case 3 the
    // leaf granter is the INSTALLER — a third peer that is neither the EXECUTE
    // author (A) nor the peer serving the request (B). PR-8 canonicalizes the
    // grant's resource patterns against the GRANTER's namespace, so B must know
    // the installer's peer-id, and the only place it can learn it is the
    // granter's `system/peer` entity riding in `envelope.included`.
    //
    // `collect_chain_bundle` gathered those identities best-effort when these
    // tests were written; v1.22 §4.3 made them a MUST, so a bundler that
    // cannot resolve one now fails at bundle time rather than dispatching an
    // incomplete bundle (resolving in-band authority first — §7a.2a — before
    // its own store). B's side is unchanged and is what these pin: whatever
    // reaches it, it authorizes only on identities actually present.

    #[test]
    fn granter_identity_absent_from_included_denies_fail_closed() {
        let installer = entity_crypto::Keypair::generate();
        let installer_id = installer.peer_entity().unwrap();

        // The §4.2 case-3 leaf: granter is the installer, not the local peer.
        let granter = Granter::Single(installer_id.content_hash);

        // B receives a bundle WITHOUT the installer's identity entity.
        let resolved = resolve_granter_peer_id(&granter, LOCAL_PEER, |_| None);

        assert_eq!(
            resolved, None,
            "an unresolvable granter MUST deny rather than fall back to the              local peer — falling back would canonicalize a foreign bare-`*`              grant into THIS peer's namespace"
        );
    }

    #[test]
    fn granter_identity_present_in_included_resolves_to_the_installer() {
        let installer = entity_crypto::Keypair::generate();
        let installer_id = installer.peer_entity().unwrap();
        let expected = installer.peer_id().as_str().to_string();
        let granter = Granter::Single(installer_id.content_hash);

        let resolved = resolve_granter_peer_id(&granter, LOCAL_PEER, |h| {
            (*h == installer_id.content_hash).then_some(&installer_id)
        });

        assert_eq!(
            resolved.as_deref(),
            Some(expected.as_str()),
            "with the identity present the leaf granter resolves to the              installer — NOT to the local peer"
        );
        assert_ne!(
            resolved.as_deref(),
            Some(LOCAL_PEER),
            "resolving to the local peer would silently widen a foreign grant"
        );
    }

    // --- Pattern matching ---

    #[test]
    fn test_matches_pattern_wildcard() {
        assert!(matches_pattern("/peer/anything/at/all", "*"));
        assert!(matches_pattern("anything", "*"));
    }

    #[test]
    fn test_matches_pattern_exact() {
        assert!(matches_pattern("/peer/system/tree", "/peer/system/tree"));
        assert!(!matches_pattern(
            "/peer/system/tree",
            "/peer/system/handler"
        ));
    }

    #[test]
    fn test_matches_pattern_prefix() {
        assert!(matches_pattern(
            "/peer/system/tree/foo",
            "/peer/system/tree/*"
        ));
        assert!(matches_pattern(
            "/peer/system/tree/foo/bar",
            "/peer/system/tree/*"
        ));
        assert!(!matches_pattern(
            "/peer/system/treefoo",
            "/peer/system/tree/*"
        ));
        assert!(!matches_pattern("/peer/system/tree", "/peer/system/tree/*"));
    }

    #[test]
    fn test_matches_pattern_peer_wildcard() {
        assert!(matches_pattern("/somepeer/system/tree", "/*/system/tree"));
        assert!(!matches_pattern("system/tree", "/*/system/tree"));
    }

    #[test]
    fn test_matches_pattern_double_peer_wildcard() {
        // /*/*  matches any peer, any path
        assert!(matches_pattern("/peer/system/tree", "/*/*"));
        assert!(matches_pattern("/otherpeer/anything", "/*/*"));
    }

    #[test]
    fn test_matches_pattern_peer_wildcard_subtree() {
        // /*/system/* matches any peer, subtree under system/
        assert!(matches_pattern("/peer/system/tree", "/*/system/*"));
        assert!(matches_pattern("/peer/system/handler/foo", "/*/system/*"));
        assert!(!matches_pattern("/peer/local/files", "/*/system/*"));
    }

    // --- Canonicalize ---

    #[test]
    fn test_canonicalize_wildcard() {
        assert_eq!(canonicalize("*", LOCAL_PEER), format!("/{}/*", LOCAL_PEER));
    }

    #[test]
    fn test_canonicalize_absolute_peer_wildcard() {
        assert_eq!(
            canonicalize("/*/system/tree", LOCAL_PEER).as_str(),
            "/*/system/tree"
        );
    }

    #[test]
    fn test_canonicalize_rejects_bare_star_slash() {
        // Fail-closed (§1.11): ambiguous `*/rest` → None, never a panic.
        assert_eq!(canonicalize("*/system/tree", LOCAL_PEER), NEVER_MATCH);
    }

    #[test]
    fn test_canonicalize_rejects_dot_slash() {
        // Fail-closed (§1.11): reserved `./` and `../` → None, never a panic.
        assert_eq!(canonicalize("./relative", LOCAL_PEER), NEVER_MATCH);
        assert_eq!(canonicalize("../escape", LOCAL_PEER), NEVER_MATCH);
    }

    #[test]
    fn test_canonicalize_bare_path() {
        assert_eq!(
            canonicalize("system/tree", LOCAL_PEER),
            format!("/{}/system/tree", LOCAL_PEER)
        );
    }

    #[test]
    fn test_canonicalize_already_absolute() {
        let path = format!("/{}/system/tree", LOCAL_PEER);
        assert_eq!(canonicalize(&path, LOCAL_PEER).as_str(), path.as_str());
    }

    // --- matches_scope ---

    #[test]
    fn test_matches_scope_basic() {
        assert!(matches_scope("get", &["*".into()], &[], LOCAL_PEER,));
        assert!(matches_scope(
            "get",
            &["get".into(), "put".into()],
            &[],
            LOCAL_PEER,
        ));
        assert!(!matches_scope(
            "delete",
            &["get".into(), "put".into()],
            &[],
            LOCAL_PEER,
        ));
    }

    #[test]
    fn test_matches_scope_with_exclude() {
        // After canonicalization, paths become absolute — exclude still works
        assert!(!matches_scope(
            "system/tree/secret",
            &["system/tree/*".into()],
            &["system/tree/secret".into()],
            LOCAL_PEER,
        ));
    }

    // --- matches_id_scope (F40, §5.2) ---
    //
    // id-scope compares literally: a pattern carrying path syntax (`/*/get`)
    // matches only as a literal string, never canonicalized against a peer
    // frame the way path-scope is. These mirror the oracle's accept-path
    // vectors (entity-core-go `f40_id_scope_exclude_literal` /
    // `f40_id_scope_include_no_overgrant`).

    #[test]
    fn test_f40_id_scope_exclude_literal_does_not_block_real_operation() {
        // A canonicalizing matcher would resolve "/*/get" to a peer-wildcard
        // pattern and treat the literal operation "get" as matching it,
        // wrongly excluding it. Literal matching: "get" != "/*/get".
        assert!(matches_id_scope("get", &["*".into()], &["/*/get".into()]));
    }

    #[test]
    fn test_f40_id_scope_include_no_overgrant() {
        // A canonicalizing matcher would resolve "/*/get" to a peer-wildcard
        // subtree pattern and let it authorize the bare operation "get".
        // Literal matching: an include of "/*/get" never matches "get".
        assert!(!matches_id_scope("get", &["/*/get".into()], &[]));
        // It also doesn't over-grant via the segment-prefix wildcard reading
        // ("/*/*" as "anything") — still a literal string comparison.
        assert!(!matches_id_scope("get", &["/*/*".into()], &[]));
    }

    #[test]
    fn test_f40_id_scope_trailing_wildcard_is_literal_segment_prefix() {
        assert!(matches_id_scope(
            "compute/apply",
            &["compute/*".into()],
            &[]
        ));
        assert!(!matches_id_scope("compute", &["compute/*".into()], &[]));
        assert!(!matches_id_scope(
            "computeextra",
            &["compute/*".into()],
            &[]
        ));
    }

    #[test]
    fn test_f40_id_scope_bare_star_matches_any() {
        assert!(matches_id_scope("anything/at/all", &["*".into()], &[]));
    }

    #[test]
    fn test_f40_check_permission_exclude_literal_does_not_block_real_get() {
        // Same accept-path shape as the oracle vector, at the check_permission
        // level: a grant excluding the literal pattern "/*/get" must not deny
        // a real "get" operation.
        let mut grant = make_grant(&["system/tree"], &["*"], &["*"]);
        grant.operations = IdScope::with_exclude(vec!["*".into()], vec!["/*/get".into()]);
        let token = make_token(vec![grant]);
        assert!(check_permission(
            "get",
            "system/tree",
            LOCAL_PEER,
            None,
            &token,
            LOCAL_PEER
        ));
    }

    #[test]
    fn test_f40_check_permission_include_does_not_overgrant() {
        let grant = make_grant(&["system/tree"], &["*"], &["/*/get"]);
        let token = make_token(vec![grant]);
        assert!(!check_permission(
            "get",
            "system/tree",
            LOCAL_PEER,
            None,
            &token,
            LOCAL_PEER
        ));
    }

    // --- check_permission ---

    fn make_grant(handlers: &[&str], resources: &[&str], ops: &[&str]) -> GrantEntry {
        GrantEntry {
            handlers: PathScope::new(handlers.iter().map(|s| s.to_string()).collect()),
            resources: PathScope::new(resources.iter().map(|s| s.to_string()).collect()),
            operations: IdScope::new(ops.iter().map(|s| s.to_string()).collect()),
            peers: None,
            constraints: None,
            allowances: None,
        }
    }

    /// §5.2 peers dimension — the P-1/P-2/P-3 trio go's
    /// `authz.authz_peers_target_from_uri` runs, as an in-process unit.
    ///
    /// The dimension is what stops a grant that names only the LOCAL peer from
    /// authorizing a dispatch into a FOREIGN namespace. It is load-bearing only
    /// if `target_peer` is `extract_peer(execute.data.uri, local)`; a caller
    /// that passes `local_peer_id` makes P-2 and P-3 compare local against
    /// local, always match, and allow the escalation. That is exactly what
    /// `core/peer/src/connection.rs` did, and go measured it as
    /// `P2 grant={L} uri=/R/: allow=true` / `P3 absent uri=/R/: allow=true`
    /// while go and py both denied.
    ///
    /// Teeth: pass `LOCAL_PEER` instead of `FOREIGN_PEER` as the third argument
    /// and P-2/P-3 flip to allow.
    #[test]
    fn peers_dimension_denies_a_foreign_target_from_a_local_or_absent_scope() {
        const FOREIGN_PEER: &str = "2DFfrCdapVgjiNBPRUdNpwKLfLsmUaKHod4jmhakzBDs3X";
        let foreign_uri_handler = format!("/{}/system/tree", FOREIGN_PEER);

        // Cross-peer wildcards on handlers/resources (`/*/*`, not bare `*`) so
        // the PEERS dimension is the only thing that can deny. A bare `*`
        // canonicalizes into the local namespace and would fail P-1 on the
        // handlers dimension instead, hiding what this test is about.
        let with_peers = |peers: Option<IdScope>| {
            let mut g = make_grant(&["/*/*"], &["/*/*"], &["get"]);
            g.peers = peers;
            make_token(vec![g])
        };

        // P-1 (control): a grant naming the foreign peer allows it.
        assert!(
            check_permission(
                "get",
                &foreign_uri_handler,
                FOREIGN_PEER,
                None,
                &with_peers(Some(IdScope::new(vec![FOREIGN_PEER.into()]))),
                LOCAL_PEER,
            ),
            "P-1: peers={{R}} must allow a dispatch to R"
        );

        // P-2: a grant naming only the LOCAL peer must NOT reach R.
        assert!(
            !check_permission(
                "get",
                &foreign_uri_handler,
                FOREIGN_PEER,
                None,
                &with_peers(Some(IdScope::new(vec![LOCAL_PEER.into()]))),
                LOCAL_PEER,
            ),
            "P-2: peers={{local}} must DENY a dispatch to a foreign peer — \
             allowing it is foreign-namespace privilege escalation"
        );

        // P-3: an ABSENT peers field defaults to {include:[local]} and is still
        // checked — absent is not "unscoped".
        assert!(
            !check_permission(
                "get",
                &foreign_uri_handler,
                FOREIGN_PEER,
                None,
                &with_peers(None),
                LOCAL_PEER,
            ),
            "P-3: absent peers defaults to {{include:[local]}} and MUST still deny R"
        );

        // The same trio through the dispatch-boundary entry point, which is the
        // one `connection.rs` actually calls.
        assert!(check_permission_with_grant(
            "get",
            &foreign_uri_handler,
            FOREIGN_PEER,
            None,
            &with_peers(Some(IdScope::new(vec![FOREIGN_PEER.into()]))),
            LOCAL_PEER,
            LOCAL_PEER,
        )
        .is_some());
        assert!(
            check_permission_with_grant(
                "get",
                &foreign_uri_handler,
                FOREIGN_PEER,
                None,
                &with_peers(None),
                LOCAL_PEER,
                LOCAL_PEER,
            )
            .is_none(),
            "the dispatch boundary must deny the absent-peers escalation too"
        );
    }

    /// **0.8.2.16 in the DELEGATION path — the two defects core-go found in
    /// their own `grantCovers`, driven against ours.**
    ///
    /// §5.2 has said since `0.8.1` that a scope is matched **by its scope type**
    /// — `path-scope` (handlers, resources) canonicalized, `id-scope`
    /// (operations, peers) compared as literal identifiers — and that *"an id
    /// dimension canonicalized is a conformance defect."* `0.8.2.16` found that
    /// **both** normative code blocks did the thing the prose forbids, under a
    /// comment reading `; Uniform scope check for all grant dimensions`, and
    /// that *"an implementation reading the prose was conformant; one reading
    /// the pseudocode was not, and the pseudocode is what gets transcribed."*
    ///
    /// We read the prose. `check_permission` and `scope_subset_id` have always
    /// matched `operations` and `peers` literally, so this fold is a **no-op in
    /// this tree** — and the rule here is that an unproven negative in a sweep is
    /// how a no-op gets reported as a fix. These are the proofs, one per defect
    /// core-go reported at their seat:
    ///
    /// 1. **Operations matched with the path matcher instead of literal
    ///    id-scope**, which over-permits on a subset check. Under
    ///    canonicalization both sides of the pair below become
    ///    `/{local}/…`-qualified paths and `matches_pattern` reads the parent's
    ///    `pwn/*` as covering the child — the child is judged an attenuation of
    ///    a parent that does not grant it.
    /// 2. **The `peers` dimension not checked in the subset at all**, so a child
    ///    grant widens its network reach past its parent. Latent until PD-2
    ///    (0.8.2.17) makes `peers` live on the outbound path, and reachable the
    ///    moment it does — which it now is, at
    ///    `connection.rs::outbound_sub_dispatch_authorized`.
    ///
    /// **Enforcement is the mutation, not the assertion.** For (1), swapping
    /// `scope_subset_id` for `scope_subset_path` on the `operations` line of
    /// `grant_axes_subset` reddens the first row. For (2), deleting the final
    /// `scope_subset_id(child_peers, parent_peers)` — i.e. returning `true` —
    /// reddens the second. Both verified; each mutation reddens only its own row,
    /// which is what says the two dimensions are checked separately rather than
    /// one masking the other.
    #[test]
    fn delegation_attenuates_operations_and_peers_as_literal_id_scope() {
        let child_ops = make_token(vec![{
            let mut g = make_grant(&["*"], &["*"], &["pwn/escalate"]);
            g.peers = Some(IdScope::new(vec!["peer-a".into()]));
            g
        }]);
        let parent_ops = make_token(vec![{
            // `pwn/*` is a literal segment-prefix over IDENTIFIERS. It covers
            // `pwn/escalate` under either reading, so it is not the discriminator
            // — `system/tree` is: a canonicalizing matcher qualifies both sides
            // to `/{local}/…` and the parent's include list, read as paths, no
            // longer says what it says as identifiers.
            let mut g = make_grant(&["*"], &["*"], &["/*/pwn/escalate"]);
            g.peers = Some(IdScope::new(vec!["peer-a".into()]));
            g
        }]);
        assert!(
            !is_attenuated(&child_ops, &parent_ops, "local"),
            "operations is id-scope: the parent's `/*/pwn/escalate` is a LITERAL \
             identifier and does not cover the operation `pwn/escalate`. A \
             canonicalizing matcher reads it as a peer-wildcard path pattern and \
             covers it — that is 0.8.2.16 defect (1), and it widens authority \
             down a chain nobody re-checks."
        );

        let child_peers = make_token(vec![{
            let mut g = make_grant(&["*"], &["*"], &["*"]);
            g.peers = Some(IdScope::new(vec!["peer-a".into(), "peer-b".into()]));
            g
        }]);
        let parent_peers = make_token(vec![{
            let mut g = make_grant(&["*"], &["*"], &["*"]);
            g.peers = Some(IdScope::new(vec!["peer-a".into()]));
            g
        }]);
        assert!(
            !is_attenuated(&child_peers, &parent_peers, "local"),
            "peers is one of the four attenuated dimensions (§5.6): a child that \
             adds `peer-b` reaches a peer its parent never granted. Skipping the \
             dimension in the subset check is 0.8.2.16 defect (2)."
        );

        // The control the two rows above need: an honest narrowing on BOTH
        // dimensions still attenuates. Without it a `scope_subset` that returns
        // `false` unconditionally satisfies every assertion here.
        let honest = make_token(vec![{
            let mut g = make_grant(&["*"], &["*"], &["get"]);
            g.peers = Some(IdScope::new(vec!["peer-a".into()]));
            g
        }]);
        let broad = make_token(vec![{
            let mut g = make_grant(&["*"], &["*"], &["*"]);
            g.peers = Some(IdScope::new(vec!["peer-a".into(), "peer-b".into()]));
            g
        }]);
        assert!(
            is_attenuated(&honest, &broad, "local"),
            "narrowing operations and peers together is a valid attenuation"
        );
    }

    /// The other half of `0.8.2.16`, and it is an **absence** rather than a
    /// check: `scope_subset` gained `if child_scope.type != parent_scope.type:
    /// return false`, and there is nothing here to add.
    ///
    /// The spec's scopes are entities carrying their own `type`
    /// (`system/capability/path-scope` / `system/capability/id-scope`), so a
    /// grant can carry a mismatched pair and a transcribing implementation must
    /// refuse it. In this tree the scope type is fixed by the **dimension name**
    /// at the decoder — `decode_grant_entry` sends `handlers`/`resources` to
    /// `decode_path_scope` and `operations`/`peers` to `decode_id_scope`, with no
    /// wire field consulted — so `PathScope` and `IdScope` are distinct Rust
    /// types and a mismatched pair does not typecheck. `grant_axes_subset` calls
    /// `scope_subset_path` and `scope_subset_id` on fixed dimensions; there is no
    /// call site where the two could meet.
    ///
    /// **Stated rather than silently omitted, per the closed-grammar rule**: a
    /// refusal that is unrepresentable and a refusal that was forgotten look
    /// identical from outside, and the next reader porting the spec's line has to
    /// know which this is. This test is the statement — it pins the
    /// dimension→scope-type mapping the argument rests on, so if a decoder ever
    /// starts reading a declared `type` off the wire, this row is where the
    /// missing refusal surfaces.
    #[test]
    fn scope_type_is_fixed_by_dimension_so_a_mismatched_pair_is_unrepresentable() {
        let g = decode_grant_entry(&ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("handlers".into()),
                ciborium::Value::Map(vec![(
                    ciborium::Value::Text("include".into()),
                    ciborium::Value::Array(vec![ciborium::Value::Text("system/tree".into())]),
                )]),
            ),
            (
                ciborium::Value::Text("resources".into()),
                ciborium::Value::Map(vec![(
                    ciborium::Value::Text("include".into()),
                    ciborium::Value::Array(vec![ciborium::Value::Text("*".into())]),
                )]),
            ),
            (
                ciborium::Value::Text("operations".into()),
                ciborium::Value::Map(vec![
                    (
                        ciborium::Value::Text("include".into()),
                        ciborium::Value::Array(vec![ciborium::Value::Text("get".into())]),
                    ),
                    // A declared `type` claiming the OTHER scope type. The
                    // decoder does not read it, which is the point: there is no
                    // input that produces a mismatched child/parent pair.
                    (
                        ciborium::Value::Text("type".into()),
                        ciborium::Value::Text("system/capability/path-scope".into()),
                    ),
                ]),
            ),
        ]))
        .expect("grant decodes");

        // `operations` came back an IdScope regardless of the declared type —
        // it is the field name that decides, at exactly one site.
        assert_eq!(g.operations.include, vec!["get".to_string()]);
        assert!(
            !matches_id_scope("/local/get", &g.operations.include, &g.operations.exclude),
            "operations matches LITERALLY: a path-shaped value does not match the \
             identifier `get`, whatever the scope map claimed its type was"
        );
        assert!(matches_id_scope(
            "get",
            &g.operations.include,
            &g.operations.exclude
        ));
    }

    fn make_token(grants: Vec<GrantEntry>) -> CapabilityToken {
        CapabilityToken {
            grants,
            granter: Granter::Single(Hash::zero()),
            grantee: Hash::zero(),
            parent: None,
            created_at: 0,
            expires_at: None,
            not_before: None,
            delegation_caveats: None,
        }
    }

    /// **core-go's cohort question, answered by measurement rather than by
    /// reading our own dispatch code** — "can a delegated child capability
    /// `register` in your tree?"
    ///
    /// Our previous answer was that we found no rule treating a child
    /// (`parent != None`) differently, so it "points toward yes". Under §5.5a
    /// that reasoning describes the **defect**, not the pass, and it was
    /// looking at the wrong dimension entirely: nothing about delegation
    /// decides this. The **granter frame** does.
    ///
    /// §5.5a: a peer-relative resource pattern (bare `*`, `system/foo`)
    /// canonicalizes against the **granter's** peer-id, not the verifier's.
    /// A cap granted by the client therefore authorizes only the *client's*
    /// namespace, and reaches nothing on the responder — so `403` is the
    /// spec-REQUIRED answer, not a defect. go withdrew the same theory after
    /// reading the same passage.
    ///
    /// The control is the half that makes this a measurement: the identical
    /// cap with `/*/*` (explicit cross-peer form, which §5.5a MANDATES for
    /// cross-peer dispatch) **is** admitted. Without it, "denied" would be
    /// satisfied by a peer that denies everything.
    #[test]
    fn foreign_granted_peer_relative_resources_reach_nothing_locally() {
        // The cap is minted by REMOTE and presented against LOCAL_PEER.
        const REMOTE_GRANTER: &str = "2KRemoteGranterBase58xxxxxxxxxxxxxxxxxxxxxxxxx";
        let target = ResourceTarget {
            targets: vec![format!("/{}/system/registry", LOCAL_PEER)],
            exclude: vec![],
        };

        // Every peer-relative spelling go probed, including the wildcard and
        // a literal path. All are granter-local, so none of them reach here.
        for resource in ["*", "system/registry", "system/registry/*"] {
            let token = make_token(vec![make_grant(&["*"], &[resource], &["*"])]);
            assert!(
                check_permission_with_grant(
                    "register-request",
                    "system/registry",
                    LOCAL_PEER,
                    Some(&target),
                    &token,
                    LOCAL_PEER,
                    REMOTE_GRANTER,
                )
                .is_none(),
                "peer-relative resource {:?} on a FOREIGN-granted cap authorized \
                 the verifier's namespace — §5.5a says it canonicalizes to the \
                 granter's",
                resource,
            );
        }

        // Control: explicit cross-peer form is admitted. This is the arm that
        // proves the denials above are about the frame and not about the cap
        // being refused wholesale.
        let open = make_token(vec![make_grant(&["*"], &["/*/*"], &["*"])]);
        assert!(
            check_permission_with_grant(
                "register-request",
                "system/registry",
                LOCAL_PEER,
                Some(&target),
                &open,
                LOCAL_PEER,
                REMOTE_GRANTER,
            )
            .is_some(),
            "explicit cross-peer /*/* form must still authorize — §5.5a mandates \
             exactly this form for cross-peer dispatch",
        );

        // And the same peer-relative cap DOES reach its own granter's
        // namespace — the frame is applied, not merely ignored.
        let self_target = ResourceTarget {
            targets: vec![format!("/{}/system/registry", REMOTE_GRANTER)],
            exclude: vec![],
        };
        let token = make_token(vec![make_grant(&["*"], &["system/registry"], &["*"])]);
        assert!(
            check_permission_with_grant(
                "register-request",
                "system/registry",
                LOCAL_PEER,
                Some(&self_target),
                &token,
                LOCAL_PEER,
                REMOTE_GRANTER,
            )
            .is_some(),
            "a granter-local resource must cover the GRANTER's own namespace",
        );
    }

    #[test]
    fn test_check_permission_simple() {
        let token = make_token(vec![make_grant(&["system/tree"], &["*"], &["get"])]);
        assert!(check_permission(
            "get",
            "system/tree",
            LOCAL_PEER,
            None,
            &token,
            LOCAL_PEER
        ));
        assert!(!check_permission(
            "put",
            "system/tree",
            LOCAL_PEER,
            None,
            &token,
            LOCAL_PEER
        ));
    }

    #[test]
    fn test_check_permission_wildcard_handlers() {
        let token = make_token(vec![make_grant(&["*"], &["*"], &["*"])]);
        assert!(check_permission(
            "get",
            "system/tree",
            LOCAL_PEER,
            None,
            &token,
            LOCAL_PEER
        ));
        assert!(check_permission(
            "put",
            "system/handler",
            LOCAL_PEER,
            None,
            &token,
            LOCAL_PEER
        ));
    }

    #[test]
    fn test_check_permission_wrong_handler() {
        let token = make_token(vec![make_grant(&["system/tree"], &["*"], &["get"])]);
        assert!(!check_permission(
            "get",
            "system/handler",
            LOCAL_PEER,
            None,
            &token,
            LOCAL_PEER
        ));
    }

    #[test]
    fn test_check_permission_with_resource() {
        let token = make_token(vec![make_grant(
            &["system/tree"],
            &["system/type/*"],
            &["get"],
        )]);
        let rt = ResourceTarget {
            targets: vec!["system/type/foo".into()],
            exclude: vec![],
        };
        assert!(check_permission(
            "get",
            "system/tree",
            LOCAL_PEER,
            Some(&rt),
            &token,
            LOCAL_PEER
        ));

        let rt_bad = ResourceTarget {
            targets: vec!["system/handler/foo".into()],
            exclude: vec![],
        };
        assert!(!check_permission(
            "get",
            "system/tree",
            LOCAL_PEER,
            Some(&rt_bad),
            &token,
            LOCAL_PEER
        ));
    }

    #[test]
    fn test_check_permission_multiple_grants() {
        let token = make_token(vec![
            make_grant(&["system/tree"], &["*"], &["get"]),
            make_grant(&["system/capability"], &[], &["request"]),
        ]);
        assert!(check_permission(
            "get",
            "system/tree",
            LOCAL_PEER,
            None,
            &token,
            LOCAL_PEER
        ));
        assert!(check_permission(
            "request",
            "system/capability",
            LOCAL_PEER,
            None,
            &token,
            LOCAL_PEER
        ));
    }

    /// R-5 (CROSS-IMPL-ACME-RUST): a grant whose resources use
    /// the bare `*` wildcard does NOT cover paths in other peers' namespaces
    /// (canonicalize maps `*` → `/{local}/*`). Cross-namespace coverage
    /// requires the explicit peer-wildcard form `/*/*`. This test pins the
    /// distinction so future grant constructors don't drift.
    #[test]
    fn test_resource_wildcard_local_vs_cross_namespace() {
        // Bare `*` — local-namespace-only.
        let local_only_token = make_token(vec![make_grant(&["system/tree"], &["*"], &["put"])]);
        let local_target = ResourceTarget {
            targets: vec![format!("/{}/system/foo", LOCAL_PEER)],
            exclude: vec![],
        };
        let cross_target = ResourceTarget {
            targets: vec![format!("/{}/system/signature/abc", OTHER_PEER)],
            exclude: vec![],
        };
        assert!(
            check_permission(
                "put",
                "system/tree",
                LOCAL_PEER,
                Some(&local_target),
                &local_only_token,
                LOCAL_PEER
            ),
            "bare `*` covers local-namespace paths"
        );
        assert!(
            !check_permission(
                "put",
                "system/tree",
                LOCAL_PEER,
                Some(&cross_target),
                &local_only_token,
                LOCAL_PEER
            ),
            "bare `*` MUST NOT cover other-peer namespaces"
        );

        // Explicit `/*/*` — cross-namespace.
        let cross_token = make_token(vec![make_grant(&["system/tree"], &["/*/*"], &["put"])]);
        assert!(
            check_permission(
                "put",
                "system/tree",
                LOCAL_PEER,
                Some(&cross_target),
                &cross_token,
                LOCAL_PEER
            ),
            "/*/* MUST cover any peer namespace (V7 §6.5 invariant pointer)"
        );
    }

    /// R-5 conformance: `debug_open_grants` MUST authorize tree:put to
    /// signature paths under any peer namespace. The pre-R-5 shape used
    /// bare `*` for resources, which canonicalized to local-only and
    /// rejected cross-namespace writes the test driver issues.
    #[test]
    fn test_debug_open_grants_authorizes_cross_namespace_signature_writes() {
        let token = make_token(debug_open_grants());
        let rt = ResourceTarget {
            targets: vec![format!("/{}/system/signature/abcdef", OTHER_PEER)],
            exclude: vec![],
        };
        assert!(
            check_permission(
                "put",
                "system/tree",
                LOCAL_PEER,
                Some(&rt),
                &token,
                LOCAL_PEER
            ),
            "R-5: --debug-grants MUST permit cross-namespace tree:put"
        );
    }

    // --- §3 advertisement filter (arch ruling 2026-08-05) ---

    /// One advertised entry in the shape `advertised_served_scope` builds:
    /// a handler, everything else unconstrained.
    fn advertised_entry(handler: &str, ops: Vec<&str>) -> GrantEntry {
        GrantEntry {
            handlers: PathScope::new(vec![handler.into()]),
            resources: PathScope::new(vec!["*".into()]),
            operations: IdScope::new(ops.into_iter().map(String::from).collect()),
            peers: None,
            constraints: None,
            allowances: None,
        }
    }

    fn grant_entry(handlers: Vec<&str>, ops: Vec<&str>) -> GrantEntry {
        GrantEntry {
            handlers: PathScope::new(handlers.into_iter().map(String::from).collect()),
            resources: PathScope::new(vec![]),
            operations: IdScope::new(ops.into_iter().map(String::from).collect()),
            peers: None,
            constraints: None,
            allowances: None,
        }
    }

    /// The ruled matching rule: entry ⊆ advertised on the four axes, under the
    /// same relation the chain uses for attenuation. Exact-op-match and
    /// namespace-prefix-match are named non-conformant, so the cases that
    /// distinguish them are the load-bearing ones.
    #[test]
    fn test_advertisement_filter_matching_rule() {
        let advertised = vec![advertised_entry("foo/bar", vec!["*"])];

        // Ordinary attenuation direction — covered.
        assert!(
            advertisement_covers(
                &advertised,
                &grant_entry(vec!["foo/bar"], vec!["get"]),
                LOCAL_PEER
            ),
            "entry ⊆ advertised on every axis is exactly the retained case"
        );

        // A sibling under the same namespace prefix is NOT covered: the
        // advertised scope names `foo/bar`, not `foo/*`. Namespace-prefix
        // matching is what the ruling calls non-conformant.
        assert!(
            !advertisement_covers(
                &advertised,
                &grant_entry(vec!["foo/baz"], vec!["get"]),
                LOCAL_PEER
            ),
            "namespace-prefix matching is non-conformant — `foo/baz` is not served"
        );

        // A wildcard subtree claim exceeds the single advertised handler.
        assert!(
            !advertisement_covers(
                &advertised,
                &grant_entry(vec!["foo/*"], vec!["get"]),
                LOCAL_PEER
            ),
            "`foo/*` claims more than the one handler advertised under it"
        );

        // Operations narrow correctly against an advertised operation set.
        let narrow = vec![advertised_entry("foo/bar", vec!["get"])];
        assert!(advertisement_covers(
            &narrow,
            &grant_entry(vec!["foo/bar"], vec!["get"]),
            LOCAL_PEER
        ),);
        assert!(
            !advertisement_covers(
                &narrow,
                &grant_entry(vec!["foo/bar"], vec!["put"]),
                LOCAL_PEER
            ),
            "an operation the advertised scope does not carry is not covered"
        );
    }

    /// **Drop, not narrow** — the half of the ruling a rewrite would quietly
    /// violate. A mixed entry naming one served and one unserved handler is
    /// dropped whole; it is NOT rewritten to the served half, because that
    /// would hand a counterpart a grant no operator authored.
    #[test]
    fn test_advertisement_filter_drops_a_mixed_entry_whole() {
        let advertised = vec![advertised_entry("foo/bar", vec!["*"])];
        let mixed = grant_entry(vec!["foo/bar", "app/echo"], vec!["get"]);

        assert!(
            !advertisement_covers(&advertised, &mixed, LOCAL_PEER),
            "an entry is retained only if ALL of it is covered — any-include \
             matching would retain this one and grant `app/echo` authority the \
             peer does not serve"
        );
    }

    /// §5.6 constraint/allowance attenuation is deliberately NOT applied: the
    /// ruling names four axes, and an advertised scope is a statement about
    /// what this peer serves, not a parent capability. Applying the allowance
    /// rule ("child MUST NOT add keys the parent lacks") against a manifest
    /// that expresses no allowances would drop every operator entry carrying
    /// one, silently and entry-wide.
    #[test]
    fn test_advertisement_filter_ignores_constraints_and_allowances() {
        let advertised = vec![advertised_entry("foo/bar", vec!["*"])];
        let mut entry = grant_entry(vec!["foo/bar"], vec!["get"]);
        let mut allowances = std::collections::BTreeMap::new();
        allowances.insert(
            "scope".to_string(),
            ciborium::Value::Text("content_store".into()),
        );
        entry.allowances = Some(allowances);

        assert!(
            advertisement_covers(&advertised, &entry, LOCAL_PEER),
            "an operator-authored allowance is not an unadvertised handler"
        );
    }

    /// The universal-handler carve-out, pinned so that a later arch ruling
    /// against it is a visible test change rather than silent drift.
    ///
    /// No finite advertised scope covers `handlers: ["*"]`, so the literal
    /// "drop, not narrow" deletes open access entirely. Retained iff this peer
    /// serves anything at all. Converged with `entity-core-go`'s
    /// `advertisedCovers`; both routed.
    #[test]
    fn test_advertisement_filter_keeps_the_universal_carve_out() {
        let advertised = vec![advertised_entry("foo/bar", vec!["*"])];
        let universal = grant_entry(vec!["*"], vec!["*"]);

        assert!(
            advertisement_covers(&advertised, &universal, LOCAL_PEER),
            "the universal grant was dropped — that is the literal reading, and \
             it deletes open access on every peer. If arch rules for the literal \
             reading this test changes deliberately"
        );
        assert!(
            !advertisement_covers(&[], &universal, LOCAL_PEER),
            "a peer that serves nothing advertises nothing — the carve-out is \
             'backed by whatever we serve', not 'always backed'"
        );
    }

    // --- Resource scope checking ---

    #[test]
    fn test_check_resource_scope_simple() {
        let rt = ResourceTarget {
            targets: vec!["system/type/foo".into()],
            exclude: vec![],
        };
        let scope = PathScope::new(vec!["system/type/*".into()]);
        assert!(check_resource_scope(&rt, &scope, LOCAL_PEER, LOCAL_PEER));
    }

    #[test]
    fn test_check_resource_scope_denied() {
        let rt = ResourceTarget {
            targets: vec!["system/handler/foo".into()],
            exclude: vec![],
        };
        let scope = PathScope::new(vec!["system/type/*".into()]);
        assert!(!check_resource_scope(&rt, &scope, LOCAL_PEER, LOCAL_PEER));
    }

    #[test]
    fn test_check_resource_scope_with_grant_exclude() {
        let rt = ResourceTarget {
            targets: vec!["system/type/secret".into()],
            exclude: vec![],
        };
        let scope = PathScope::with_exclude(
            vec!["system/type/*".into()],
            vec!["system/type/secret".into()],
        );
        assert!(!check_resource_scope(&rt, &scope, LOCAL_PEER, LOCAL_PEER));
    }

    /// V7 §5.5 / PR-8 (v7.73 V2(a) shape): a cap's bare `*` resource pattern
    /// canonicalizes against the *granter's* namespace, not the verifier's.
    /// A foreign-granted bare-`*` cap MUST NOT cover a target in the verifier's
    /// namespace; the same cap self-issued (granter == verifier) DOES.
    #[test]
    fn test_check_resource_scope_pr8_granter_frame() {
        // Any peer-id distinct from LOCAL_PEER; canonicalize only string-formats it.
        const FOREIGN_GRANTER: &str = "9aBcDeFgHiJkLmNoPqRsTuVwXyZabcdefghijkLmNoPqRsTu";
        let scope = PathScope::new(vec!["*".into()]); // peer-local-of-granter
        let rt = ResourceTarget {
            targets: vec!["system/type/system/peer".into()], // bare → verifier (local) frame
            exclude: vec![],
        };
        // Foreign granter: grant `*` → /{FOREIGN}/*, target → /{LOCAL}/... → DENY.
        assert!(
            !check_resource_scope(&rt, &scope, LOCAL_PEER, FOREIGN_GRANTER),
            "foreign-granted bare-* cap must not reach the verifier's namespace (PR-8)"
        );
        // Self-issued: grant `*` → /{LOCAL}/*, covers the local-frame target → ALLOW.
        assert!(
            check_resource_scope(&rt, &scope, LOCAL_PEER, LOCAL_PEER),
            "self-issued bare-* cap covers the local namespace"
        );
    }

    // -----------------------------------------------------------------------
    // §5.2 `effective_targets` + §5.4 R11/G6 (0.8.2.20)
    // -----------------------------------------------------------------------

    /// `effective_targets` is **pattern-aware and canonicalizing**, not set
    /// subtraction.
    ///
    /// This row exists because `[t for t in targets if t not in exclude]` is the
    /// obvious reading of *"targets minus the caller's own exclude"* and it
    /// implements none of the rule: an exclude of `app/*` removes a target of
    /// `/{p}/app/x`, and an exclude written peer-relative removes a target
    /// written absolute. A naive string reduction removes nothing, the arity
    /// stays 1, and the fix reports done while the bypass is open.
    #[test]
    fn effective_targets_is_pattern_aware_and_canonicalizing() {
        // Pattern exclude removes a concrete target under it.
        let rt = ResourceTarget {
            targets: vec![format!("/{}/app/x", LOCAL_PEER)],
            exclude: vec!["app/*".into()], // peer-relative, canonicalizes
        };
        assert!(
            effective_targets(Some(&rt), LOCAL_PEER).is_empty(),
            "a patterned, peer-relative exclude must remove an absolute target under it"
        );

        // Mixed: the survivor is the one NOT excluded, and it is the SUBJECT.
        let rt = ResourceTarget {
            targets: vec![
                format!("/{}/app/secret", LOCAL_PEER),
                format!("/{}/app/public", LOCAL_PEER),
            ],
            exclude: vec![format!("/{}/app/secret", LOCAL_PEER)],
        };
        let eff = effective_targets(Some(&rt), LOCAL_PEER);
        assert_eq!(
            eff.len(),
            1,
            "arity one — an arity check alone says `proceed`"
        );
        assert_eq!(
            eff[0],
            format!("/{}/app/public", LOCAL_PEER),
            "⛔ the element, not targets[0]: `targets[0]` is the EXCLUDED path, and \
             a handler that counts this list and then indexes targets[0] has \
             implemented the arithmetic completely and shipped the bypass"
        );

        // An absent resource and a fully self-excluded one are the same answer.
        assert!(effective_targets(None, LOCAL_PEER).is_empty());
        let rt = ResourceTarget {
            targets: vec![format!("/{}/app/x", LOCAL_PEER)],
            exclude: vec![format!("/{}/app/x", LOCAL_PEER)],
        };
        assert!(effective_targets(Some(&rt), LOCAL_PEER).is_empty());
    }

    /// A malformed target **stays in the effective list** (§5.2's comment:
    /// *"NEVER_MATCH is not skipped here — it cannot be covered by any
    /// exclude"*), so it counts toward the arity and is refused downstream.
    ///
    /// Dropping it instead would be the quiet wrong answer: `targets:[*/x, good]`
    /// would reduce to `[good]` and **proceed**, where the rule makes it two
    /// entries and therefore `ambiguous_resource`.
    #[test]
    fn a_malformed_target_stays_in_the_effective_list_and_counts() {
        let rt = ResourceTarget {
            targets: vec!["*/x".into(), format!("/{}/app/good", LOCAL_PEER)],
            exclude: vec![],
        };
        let eff = effective_targets(Some(&rt), LOCAL_PEER);
        assert_eq!(eff.len(), 2, "the malformed target is counted, not dropped");
        // The RAW survivor (0.8.2.21) — the target as the caller wrote it. The
        // SKIP that let it survive was decided on the canonical form, which is
        // the half that has to agree across layers; the returned value is not.
        assert_eq!(
            eff[0], "*/x",
            "returns the raw survivor, not its canonical form"
        );
        assert_eq!(
            canonicalize(&eff[0], LOCAL_PEER),
            NEVER_MATCH,
            "and canonicalizing it is still NEVER_MATCH — the consumer's job"
        );

        // And it cannot be excluded away, which is why the skip is safe to run
        // before the refusal.
        let rt = ResourceTarget {
            targets: vec!["*/x".into()],
            exclude: vec!["*".into(), "/*/*".into()],
        };
        assert_eq!(
            effective_targets(Some(&rt), LOCAL_PEER),
            vec!["*/x".to_string()],
            "no exclude — not even a universal one — removes the NEVER_MATCH target"
        );
    }

    /// The raw return is a property of the VALUE only; the SKIP still runs on
    /// canonical forms, and that half is what two layers have to agree on.
    ///
    /// The discriminator is a peer-relative target excluded by its absolute
    /// spelling: under a raw *skip* the two strings never compare equal and the
    /// target survives — which is `F68` with the comparison done in the wrong
    /// frame. Mutation-verified: replacing `is_covered_by(&ct, …)` with
    /// `is_covered_by(target, …)` reddens this row and leaves the raw-return
    /// assertions above green.
    #[test]
    fn the_skip_is_canonical_even_though_the_return_is_raw() {
        let rt = ResourceTarget {
            targets: vec!["app/secret".into()],
            exclude: vec![format!("/{}/app/secret", LOCAL_PEER)],
        };
        assert!(
            effective_targets(Some(&rt), LOCAL_PEER).is_empty(),
            "a peer-relative target excluded by its ABSOLUTE spelling is still excluded"
        );

        // And the surviving value is the caller's spelling, not ours — this is
        // what §6.13's install-pattern derivation reads.
        let rt = ResourceTarget {
            targets: vec!["system/handler/myapp".into()],
            exclude: vec![],
        };
        assert_eq!(
            effective_targets(Some(&rt), LOCAL_PEER),
            vec!["system/handler/myapp".to_string()],
            "§6.13 derives the install pattern against the `system/handler/` \
             prefix and its worked example target is peer-relative — a canonical \
             return makes that derivation not fire"
        );
    }

    /// §5.4's matcher rule, asserted **directly on the function** because that is
    /// the level the spec rules it at: *"NEVER_MATCH never matches, in either
    /// operand. This arm is FIRST and is a matcher rule, not a property of the
    /// string: the arm below returns true for a bare `*` operand, so safety MUST
    /// NOT rest on a value merely looking unmatchable."*
    ///
    /// ⚠ **This row exists because the claim was written in a comment and the
    /// mutation that was supposed to prove it PASSED.** Moving the NEVER_MATCH
    /// arm after the `pattern == "*"` arm left every other test in this file
    /// green — `canonicalize` never yields a bare `*` (it yields
    /// `/{peer}/*`), and `/*/*` reaches the recursion through the `/*/` arm, so
    /// no fixture anywhere put NEVER_MATCH next to a bare `*`. The ordering is
    /// still the rule; it was simply unmeasured, which is indistinguishable from
    /// absent.
    #[test]
    fn never_match_loses_to_every_pattern_including_a_bare_star() {
        assert!(
            !matches_pattern(NEVER_MATCH, "*"),
            "the bare-`*` arm returns true for any path — the NEVER_MATCH arm \
             MUST precede it, and this is the only assertion in the tree that \
             fails if the two are swapped"
        );
        // CONTROL: the bare-`*` arm still matches an ordinary path, so the row
        // above is not satisfied by a matcher that refuses everything.
        assert!(matches_pattern(&format!("/{}/app/x", LOCAL_PEER), "*"));

        // Either operand, and the other shapes for completeness.
        assert!(!matches_pattern(NEVER_MATCH, "/*/*"));
        assert!(!matches_pattern(NEVER_MATCH, NEVER_MATCH));
        assert!(!matches_pattern(
            &format!("/{}/app/x", LOCAL_PEER),
            NEVER_MATCH
        ));
        assert!(!matches_pattern(NEVER_MATCH, &format!("/{}/*", LOCAL_PEER)));
    }

    /// ⛔ **`CORE-EXCLUDE-UNMATCHABLE-1` (§5.2, §5.4 — 0.8.2.21), at the three
    /// sites the ruling enumerates, plus the control that makes a denial mean
    /// something.**
    ///
    /// The vector's own shape: a grant `{include:["/*/*"], exclude:["*/secret"]}`
    /// and a request for `/{peer}/secret`. `*/`-leading canonicalizes to
    /// `NEVER_MATCH`, so under `0.8.2.20` the exclusion excluded **nothing** and
    /// the request was allowed — a grant silently wider than its author wrote,
    /// with no error anywhere, because the sentinel is designed not to raise.
    ///
    /// **Every deny row here is paired with the well-formed-exclude control the
    /// vector requires**, because all three denials pass trivially against a
    /// peer that denies everything, and that peer is what a "fix" that deletes
    /// the exclude arm looks like from outside.
    #[test]
    fn an_unmatchable_exclude_excludes_everything_at_every_site() {
        let secret = format!("/{}/secret", LOCAL_PEER);
        let other = format!("/{}/public", LOCAL_PEER);

        // --- Site 1: matches_scope's exclude loop (every dimension, every grant)
        assert!(
            !matches_scope(&secret, &["/*/*".into()], &["*/secret".into()], LOCAL_PEER),
            "site 1 (matches_scope): an unmatchable exclude denies"
        );
        assert!(
            !matches_scope(&secret, &["/*/*".into()], &["/*/secret".into()], LOCAL_PEER),
            "CONTROL: a well-formed exclude denies the path it covers"
        );
        assert!(
            matches_scope(&other, &["/*/*".into()], &["/*/secret".into()], LOCAL_PEER),
            "CONTROL: and it allows the path it does not — a working exclusion \
             is not a matcher that refuses everything"
        );

        // --- Site 2: check_resource_scope, CONCRETE target arm
        let concrete = ResourceTarget {
            targets: vec![secret.clone()],
            exclude: vec![],
        };
        let unmatchable = PathScope::with_exclude(vec!["/*/*".into()], vec!["*/secret".into()]);
        let well_formed = PathScope::with_exclude(vec!["/*/*".into()], vec!["/*/secret".into()]);
        assert!(
            !check_resource_scope(&concrete, &unmatchable, LOCAL_PEER, LOCAL_PEER),
            "site 2 (concrete arm): the vector's own row"
        );
        assert!(
            !check_resource_scope(&concrete, &well_formed, LOCAL_PEER, LOCAL_PEER),
            "CONTROL: well-formed exclude still denies"
        );
        let elsewhere = ResourceTarget {
            targets: vec![other.clone()],
            exclude: vec![],
        };
        assert!(
            check_resource_scope(&elsewhere, &well_formed, LOCAL_PEER, LOCAL_PEER),
            "CONTROL: the discriminating allow — without it the two denies above \
             are satisfied by a peer that denies everything"
        );

        // --- Site 3: check_resource_scope, PATTERN target arm.
        //
        // ⚠ **This is a DEPARTURE from 0.8.2.21's pseudocode and the reason is a
        // measurement, not a reading.** The fold enumerates three sites and adds
        // the arm to two, calling this one *"fail-closed BY ACCIDENT, the test
        // is negated for an unrelated reason"* — the negated test being
        // `if not is_covered_by(cge, caller_exclude): return false`, which does
        // deny, because `is_covered_by` cannot cover NEVER_MATCH.
        //
        // That line is never REACHED. `patterns_overlap(ct, "/never-match")` is
        // false for every real pattern target — `strip_wildcard` leaves the
        // sentinel intact and neither string is a prefix of the other — so the
        // loop `continue`s and the unmatchable exclude is skipped, exactly as it
        // was in the concrete arm. Spec-literal, site 3 is fail-OPEN.
        //
        // The two assertions below are the measurement: the first states the
        // overlap predicate's answer (the premise), the second states the
        // consequence.
        assert!(
            !patterns_overlap(&format!("/{}/*", LOCAL_PEER), NEVER_MATCH),
            "the premise: an unmatchable grant exclude does not OVERLAP a pattern \
             target, so the negated is_covered_by test the ruling relies on is \
             never reached"
        );
        let pattern_target = ResourceTarget {
            targets: vec![format!("/{}/*", LOCAL_PEER)],
            exclude: vec![],
        };
        assert!(
            !check_resource_scope(&pattern_target, &unmatchable, LOCAL_PEER, LOCAL_PEER),
            "site 3 (pattern arm): denies here too — spec-literal this ALLOWS"
        );
        assert!(
            check_resource_scope(
                &pattern_target,
                &PathScope::new(vec!["/*/*".into()]),
                LOCAL_PEER,
                LOCAL_PEER
            ),
            "CONTROL: a pattern target under a grant with no exclude is allowed"
        );
    }

    /// ⛔ **The FOURTH site, which `0.8.2.21` does not enumerate: §6.3's
    /// `check_path_permission`.**
    ///
    /// The ruling measures three sites and all three are in §5.2, because §6.3's
    /// pseudocode delegates its resource dimension to `matches_scope` and
    /// therefore inherits the fix for free. **Ours did not**: it open-coded the
    /// same predicate as `is_covered_by(include) && !is_covered_by(exclude)`,
    /// which is `matches_scope`'s body minus the arm — so the fail-open survived
    /// here after the three named sites were closed.
    ///
    /// This is the site where it costs most. §6.3 is **sole** resource
    /// enforcement whenever `EXECUTE.resource` is absent (§3.2 runs no
    /// dispatch-level resource check at all), so there is no §5.2 layer behind
    /// it to catch the miss.
    ///
    /// Mutation-verified: restoring the `is_covered_by` pair reddens the first
    /// row here and leaves both controls green.
    #[test]
    fn an_unmatchable_exclude_also_denies_at_the_handler_level_check() {
        let secret = format!("/{}/secret", LOCAL_PEER);
        let cap = |exclude: Vec<String>| {
            make_token(vec![GrantEntry {
                handlers: PathScope::new(vec!["system/tree".into()]),
                resources: PathScope::with_exclude(vec!["/*/*".into()], exclude),
                operations: IdScope::new(vec!["get".into()]),
                peers: None,
                constraints: None,
                allowances: None,
            }])
        };
        let check = |token: &CapabilityToken, path: &str| {
            check_path_permission("get", path, token, "system/tree", LOCAL_PEER, LOCAL_PEER)
        };

        assert!(
            !check(&cap(vec!["*/secret".into()]), &secret),
            "an unmatchable exclude denies at §6.3 too — this is the check that \
             is SOLE enforcement when `resource` is absent"
        );
        assert!(
            !check(&cap(vec!["/*/secret".into()]), &secret),
            "CONTROL: a well-formed exclude still denies"
        );
        assert!(
            check(
                &cap(vec!["/*/secret".into()]),
                &format!("/{}/public", LOCAL_PEER)
            ),
            "CONTROL: and a working exclusion is not a check that denies everything"
        );
    }

    /// ⛔ **§6.3's PATTERN SUBJECT (0.8.2.22 — J3): a pattern re-spells past a
    /// concrete grant exclude it SPANS, because `matches_scope`'s exclude test
    /// is a literal comparison.**
    ///
    /// The two subjects ask different questions in the same call:
    ///
    /// | subject | question | a concrete exclude `/{p}/app/secret` |
    /// |---|---|---|
    /// | `/{p}/app/secret` | *is this path in scope?* | matches → DENY ✓ |
    /// | `/{p}/app/*` | *is every path this names in scope?* | does not literally equal it → **ALLOW** ✗ |
    ///
    /// Row 1 below is that fail-open. The subject `/{p}/app/*` names a set that
    /// plainly contains `/{p}/app/secret`, the grant excludes exactly that path,
    /// and the literal test answered ALLOW — authorizing a subject strictly
    /// wider than the grant. §6.3 pins the correct reading to §5.2's: *"a pattern
    /// subject is authorized exactly as §5.2 authorizes a pattern target, with
    /// the caller-exclude set empty"*, so every **overlapping** grant exclude is
    /// uncovered and denies.
    ///
    /// **The controls are the load-bearing half, because the fix is one edit away
    /// from "deny every pattern".** Row 3 is a pattern subject under a grant whose
    /// exclude does NOT overlap it — that MUST still be allowed, and it is the row
    /// that fails if the pattern arm is written as a blanket refusal. Row 4 is the
    /// concrete subject the same grant covers, which pins that routing patterns
    /// through a second arm did not disturb the concrete one.
    ///
    /// ⚠ **Latent, not live, and the distinction is recorded rather than left to
    /// be rediscovered.** Neither production consumer passes a pattern here today
    /// (see [`path_scope_admits_subject`]); `EXTENSION-SUBSCRIPTION` §2.3's
    /// `include_payload` check — §6.3's own worked case for a pattern subject —
    /// routes through [`check_permission`] in this tree and so reaches
    /// `check_resource_scope`'s pattern arm, which has had the rule since
    /// `9beb723`. Row 5 drives that path to pin the equivalence, so the two
    /// consumers cannot answer the same question differently.
    ///
    /// **Mutation-verified, and the result corrects what was written here before
    /// it was run.** Forcing `path_scope_admits_subject` to take the
    /// `matches_scope` branch for every subject reddens **row 1 only** — rows 2
    /// through 5 stay green.
    ///
    /// Row 2 staying green is the useful part, not a gap: `matches_scope` carries
    /// 0.8.2.21's sentinel arm itself (site 1, `9beb723`), so an unmatchable
    /// exclude denies a pattern subject under **either** implementation. Row 2 is
    /// therefore a **containment pin** rather than a discriminator — it fails if
    /// the new pattern arm is ever written without the sentinel, which is the one
    /// way this refactor could have lost a rule it was supposed to inherit. The
    /// prediction that it would redden was a guess about which of two guards
    /// catches the input, and two guards that refuse the same input tell you
    /// nothing about each other — the same no-op-mutation shape this repo has
    /// already recorded once.
    ///
    /// The single-row result is also why row 1 is written with a **concrete**
    /// exclude rather than a sentinel one: only a well-formed exclude that the
    /// literal test misses can separate the two readings.
    #[test]
    fn a_pattern_subject_is_authorized_as_a_pattern_not_matched_as_a_literal() {
        let app_star = format!("/{}/app/*", LOCAL_PEER);
        let secret = format!("/{}/app/secret", LOCAL_PEER);

        let cap = |exclude: Vec<String>| {
            make_token(vec![GrantEntry {
                handlers: PathScope::new(vec!["system/tree".into()]),
                resources: PathScope::with_exclude(vec![format!("/{}/app/*", LOCAL_PEER)], exclude),
                operations: IdScope::new(vec!["get".into()]),
                peers: None,
                constraints: None,
                allowances: None,
            }])
        };
        let check = |token: &CapabilityToken, path: &str| {
            check_path_permission("get", path, token, "system/tree", LOCAL_PEER, LOCAL_PEER)
        };

        let spanning = cap(vec![secret.clone()]);
        let disjoint = cap(vec![format!("/{}/other/thing", LOCAL_PEER)]);

        let mut mismatches: Vec<String> = Vec::new();
        let mut row = |label: &str, got: bool, expected: bool| {
            if got != expected {
                mismatches.push(format!("[{label}]: got {got}, expected {expected}"));
            }
        };

        row(
            "row 1 — a pattern subject SPANNING a concrete grant exclude denies",
            check(&spanning, &app_star),
            false,
        );
        row(
            "row 2 — and an UNMATCHABLE grant exclude denies a pattern subject too \
             (the sentinel arm, which sits before the overlap test)",
            check(&cap(vec!["*/secret".into()]), &app_star),
            false,
        );
        row(
            "row 3 CONTROL — a pattern subject under a NON-overlapping exclude is \
             still ALLOWED; this is the row a blanket pattern refusal fails",
            check(&disjoint, &app_star),
            true,
        );
        row(
            "row 4 CONTROL — the concrete arm is undisturbed: the excluded path \
             itself still denies",
            check(&spanning, &secret),
            false,
        );
        row(
            "row 5 — §5.2's pattern-target arm answers identically, which is what \
             says the two consumers share one rule rather than two copies",
            check_resource_scope(
                &ResourceTarget {
                    targets: vec![app_star.clone()],
                    exclude: vec![],
                },
                &PathScope::with_exclude(vec![format!("/{}/app/*", LOCAL_PEER)], vec![secret]),
                LOCAL_PEER,
                LOCAL_PEER,
            ),
            false,
        );

        assert!(
            mismatches.is_empty(),
            "§6.3 pattern subject (0.8.2.22 J3):\n  {}",
            mismatches.join("\n  ")
        );
    }

    /// The unmatchable verdict does not depend on the canonicalization frame,
    /// which is why [`unmatchable_scope_pattern`] takes no peer id.
    ///
    /// `canonicalize` yields `NEVER_MATCH` for exactly three reserved prefixes,
    /// all decided before any peer-id qualification — so the granter's frame and
    /// the verifier's frame give the same answer, and a call site cannot get it
    /// wrong by passing the one it happens to hold. This row fails if that stops
    /// being true.
    #[test]
    fn frame_is_irrelevant_to_the_unmatchable_verdict() {
        for pattern in ["*/secret", "./x", "../x"] {
            for frame in [LOCAL_PEER, "some-other-frame", ""] {
                assert_eq!(
                    canonicalize(pattern, frame),
                    NEVER_MATCH,
                    "{pattern:?} is unmatchable in every frame"
                );
            }
        }
        // CONTROL: an ordinary peer-relative pattern IS frame-dependent, so the
        // row above is not satisfied by a canonicalize that ignores its frame.
        assert_ne!(
            canonicalize("app/*", LOCAL_PEER),
            canonicalize("app/*", "other"),
        );

        let grants = vec![GrantEntry {
            handlers: PathScope::all(),
            resources: PathScope::with_exclude(vec!["/*/*".into()], vec!["*/secret".into()]),
            operations: IdScope::all(),
            peers: None,
            constraints: None,
            allowances: None,
        }];
        assert_eq!(
            unmatchable_scope_pattern(&grants).as_deref(),
            Some("*/secret")
        );

        // Both path scopes are swept, and the exclude arrays too — the
        // `include`-only reading is the one that would leave the fail-OPEN
        // direction unguarded.
        let handler_side = vec![GrantEntry {
            handlers: PathScope::with_exclude(vec!["*".into()], vec!["../escape".into()]),
            resources: PathScope::all(),
            operations: IdScope::all(),
            peers: None,
            constraints: None,
            allowances: None,
        }];
        assert_eq!(
            unmatchable_scope_pattern(&handler_side).as_deref(),
            Some("../escape")
        );

        // CONTROL: an ordinary grant is not flagged. `operations`/`peers` are
        // id-scopes — literal matching, no canonicalization — so a `*/`-leading
        // OPERATION is a legal (if odd) literal and is deliberately not swept.
        let ok = vec![GrantEntry {
            handlers: PathScope::new(vec!["system/tree".into()]),
            resources: PathScope::with_exclude(vec!["/*/*".into()], vec!["/*/secret".into()]),
            operations: IdScope::new(vec!["*/weird".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        }];
        assert!(unmatchable_scope_pattern(&ok).is_none());
    }

    /// **G6 / `CORE-CANONICALIZE-TOTAL-1`'s discriminating arm** — a malformed
    /// concrete target reaching `check_resource_scope` MUST return `false`.
    ///
    /// `check_resource_scope` called `validate_absolute_path` nowhere at all, so
    /// `/notapeerid/x` was matched against the grant as an ordinary string and a
    /// broad grant covered it. The CONTROL is the same broad grant against a
    /// WELL-FORMED cross-namespace target, which MUST still be allowed —
    /// otherwise this row is satisfied by a grant that refuses everything, and
    /// the R-5 invariant-pointer behaviour (`/*/*` reaches any namespace) is a
    /// pin one screen up.
    #[test]
    fn a_malformed_concrete_target_is_refused_by_check_resource_scope() {
        let open = PathScope::new(vec!["/*/*".into()]);

        for bad in ["/notapeerid/x", "/abc/system/tree", "*/x", "./x", "../x"] {
            let rt = ResourceTarget {
                targets: vec![bad.into()],
                exclude: vec![],
            };
            assert!(
                !check_resource_scope(&rt, &open, LOCAL_PEER, LOCAL_PEER),
                "a malformed target ({bad}) must deny even under a `/*/*` grant — \
                 the verdict of validate_absolute_path is consumed, not discarded"
            );
        }

        // CONTROL — a well-formed foreign-namespace target under the same grant
        // is ALLOWED, so the rows above are attributable to the path being
        // malformed and not to the grant refusing cross-namespace access.
        let good = ResourceTarget {
            targets: vec![format!("/{}/app/x", OTHER_PEER)],
            exclude: vec![],
        };
        assert!(
            check_resource_scope(&good, &open, LOCAL_PEER, LOCAL_PEER),
            "CONTROL: `/*/*` must still reach a well-formed foreign namespace"
        );

        // CONTROL — a PATTERN target is not put through validate_absolute_path
        // (§5.4: "NOT called on patterns — patterns may have wildcard segments
        // which are valid pattern syntax but not valid peer_ids"), so the guard
        // must be `!is_pattern`-conditioned rather than unconditional.
        let pattern = ResourceTarget {
            targets: vec!["/*/*".into()],
            exclude: vec![],
        };
        assert!(
            check_resource_scope(&pattern, &open, LOCAL_PEER, LOCAL_PEER),
            "CONTROL: a pattern target must not be run through the peer_id validator"
        );
    }

    /// Fail-closed (V7 §1.11, F5): a malformed resource pattern in a grant
    /// MUST yield a clean DENY, never a panic / dropped connection. Covers
    /// every dimension — a malformed include, a malformed exclude, and a
    /// malformed requested target each deny rather than crash.
    #[test]
    fn test_malformed_pattern_fails_closed() {
        let target = ResourceTarget {
            targets: vec!["system/type/foo".into()],
            exclude: vec![],
        };

        // Malformed resource include in the grant → cannot grant (previously
        // panicked inside canonicalize, dropping the connection).
        let bad_include = make_token(vec![make_grant(
            &["system/tree"],
            &["../escape/*"],
            &["get"],
        )]);
        assert!(!check_permission(
            "get",
            "system/tree",
            LOCAL_PEER,
            Some(&target),
            &bad_include,
            LOCAL_PEER
        ));

        // ⛔ A malformed EXCLUDE **denies** — §5.4/§5.2 (0.8.2.21), and this row
        // has now flipped twice. 0.8.2.20 ruled `matches_pattern` returns false
        // on either operand and argued the safety from the `include` side only,
        // so this line became an ALLOW; we shipped it with the control below and
        // filed the objection. 0.8.2.21 upholds the objection: matches-nothing
        // is fail-closed in an include and fail-OPEN here, and an unmatchable
        // exclude now excludes EVERYTHING. The disposition is the one this file
        // carried before 0.8.2.20.
        //
        // Kept as the SAME row through both flips on purpose: an assertion that
        // gets deleted and rewritten loses the history that it is contested.
        let scope = PathScope::with_exclude(vec!["system/type/*".into()], vec!["*/sneaky".into()]);
        assert!(
            !check_resource_scope(&target, &scope, LOCAL_PEER, LOCAL_PEER),
            "0.8.2.21: an unmatchable grant exclude carves out nothing and so must \
             exclude everything — otherwise the grant is silently wider than written"
        );
        // CONTROL 1, and it is the whole reason that row is allowed to flip: a
        // WELL-FORMED exclude still excludes. Without this the assertion above
        // is indistinguishable from having deleted the exclude arm.
        let well_formed =
            PathScope::with_exclude(vec!["system/type/*".into()], vec!["system/type/foo".into()]);
        assert!(
            !check_resource_scope(&target, &well_formed, LOCAL_PEER, LOCAL_PEER),
            "a well-formed grant exclude still denies the target it covers"
        );
        // CONTROL 2 — the one `CORE-EXCLUDE-UNMATCHABLE-1` names by name, and
        // the one control 1 cannot supply. Both rows above are DENIALS, so a
        // peer that denies everything passes both. This row must ALLOW: the same
        // include, a well-formed exclude that does NOT cover the target.
        let elsewhere = PathScope::with_exclude(
            vec!["system/type/*".into()],
            vec!["system/type/other".into()],
        );
        assert!(
            check_resource_scope(&target, &elsewhere, LOCAL_PEER, LOCAL_PEER),
            "a working exclusion is not a peer that denies everything — without \
             this row the two denials above cannot tell those apart"
        );

        // Malformed HANDLER exclude → same ruling, same direction, and this is
        // the site the vector does not name: `matches_scope`'s exclude loop runs
        // for **every dimension of every grant**, not only `resources`. Flipped
        // with the resources row at 0.8.2.21.
        let mut grant = make_grant(&["system/tree"], &["*"], &["get"]);
        grant.handlers.exclude = vec!["*/sneaky".into()];
        let bad_handler_exclude = make_token(vec![grant]);
        assert!(!check_permission(
            "get",
            "system/tree",
            LOCAL_PEER,
            None,
            &bad_handler_exclude,
            LOCAL_PEER
        ));
        // CONTROL: the same grant with NO handler exclude still authorizes, so
        // the denial above is not "check_permission refuses everything".
        let grant = make_grant(&["system/tree"], &["*"], &["get"]);
        assert!(check_permission(
            "get",
            "system/tree",
            LOCAL_PEER,
            None,
            &make_token(vec![grant]),
            LOCAL_PEER
        ));
        // CONTROL: a well-formed handler exclude still denies.
        let mut grant = make_grant(&["system/tree"], &["*"], &["get"]);
        grant.handlers.exclude = vec!["system/tree".into()];
        assert!(!check_permission(
            "get",
            "system/tree",
            LOCAL_PEER,
            None,
            &make_token(vec![grant]),
            LOCAL_PEER
        ));

        // Malformed requested resource target → deny, not panic.
        let good = make_token(vec![make_grant(
            &["system/tree"],
            &["system/type/*"],
            &["get"],
        )]);
        let bad_target = ResourceTarget {
            targets: vec!["../escape".into()],
            exclude: vec![],
        };
        assert!(!check_resource_scope(
            &bad_target,
            &good.grants[0].resources,
            LOCAL_PEER,
            LOCAL_PEER
        ));
    }

    // --- Attenuation ---

    #[test]
    fn test_is_attenuated_same_scope() {
        let parent = make_token(vec![make_grant(&["*"], &["*"], &["*"])]);
        let child = make_token(vec![make_grant(&["system/tree"], &["*"], &["get"])]);
        assert!(is_attenuated(&child, &parent, LOCAL_PEER));
    }

    #[test]
    fn test_is_attenuated_amplification_denied() {
        let parent = make_token(vec![make_grant(&["system/tree"], &["*"], &["get"])]);
        let child = make_token(vec![make_grant(&["*"], &["*"], &["*"])]);
        assert!(!is_attenuated(&child, &parent, LOCAL_PEER));
    }

    #[test]
    fn test_is_attenuated_expiration() {
        let mut parent = make_token(vec![make_grant(&["*"], &["*"], &["*"])]);
        parent.expires_at = Some(1000);

        let mut child = make_token(vec![make_grant(&["*"], &["*"], &["*"])]);
        child.expires_at = Some(500);
        assert!(is_attenuated(&child, &parent, LOCAL_PEER));

        child.expires_at = Some(2000);
        assert!(!is_attenuated(&child, &parent, LOCAL_PEER));

        child.expires_at = None; // infinite child, finite parent
        assert!(!is_attenuated(&child, &parent, LOCAL_PEER));
    }

    #[test]
    fn test_is_attenuated_split_grants() {
        let parent = make_token(vec![make_grant(&["*"], &["*"], &["*"])]);
        // Child splits into two narrower grants — this is valid
        let child = make_token(vec![
            make_grant(&["system/tree"], &["*"], &["get"]),
            make_grant(&["system/handler"], &["*"], &["register"]),
        ]);
        assert!(is_attenuated(&child, &parent, LOCAL_PEER));
    }

    // --- Delegation caveats ---

    #[test]
    fn test_delegation_caveats_none() {
        let parent = make_token(vec![]);
        let child = make_token(vec![]);
        assert!(check_delegation_caveats(&parent, &child, 0));
    }

    #[test]
    fn test_delegation_caveats_no_delegation() {
        let mut parent = make_token(vec![]);
        parent.delegation_caveats = Some(DelegationCaveats {
            no_delegation: Some(true),
            max_delegation_depth: None,
            max_delegation_ttl: None,
        });
        assert!(!check_delegation_caveats(&parent, &make_token(vec![]), 0));
    }

    #[test]
    fn test_delegation_caveats_max_depth() {
        let mut parent = make_token(vec![]);
        parent.delegation_caveats = Some(DelegationCaveats {
            no_delegation: None,
            max_delegation_depth: Some(1),
            max_delegation_ttl: None,
        });
        assert!(check_delegation_caveats(&parent, &make_token(vec![]), 0));
        assert!(!check_delegation_caveats(&parent, &make_token(vec![]), 1));
    }

    #[test]
    fn test_delegation_caveats_max_ttl() {
        let mut parent = make_token(vec![]);
        parent.delegation_caveats = Some(DelegationCaveats {
            no_delegation: None,
            max_delegation_depth: None,
            max_delegation_ttl: Some(3_600_000),
        });

        let mut child = make_token(vec![]);
        child.created_at = 1000;
        child.expires_at = Some(1000 + 3_600_000);
        assert!(check_delegation_caveats(&parent, &child, 0));

        child.expires_at = Some(1000 + 7_200_000);
        assert!(!check_delegation_caveats(&parent, &child, 0));

        child.expires_at = None; // infinite
        assert!(!check_delegation_caveats(&parent, &child, 0));
    }

    // --- Token encoding ---

    #[test]
    fn test_capability_token_to_entity() {
        let token = make_token(vec![make_grant(&["system/tree"], &["*"], &["get"])]);
        let entity = token.to_entity().unwrap();
        assert_eq!(entity.entity_type, entity_types::TYPE_CAP_TOKEN);
        assert!(entity.validate().is_ok());
    }

    #[test]
    fn test_capability_token_roundtrip() {
        let granter = Hash::compute("system/peer", &[1, 2, 3]);
        let grantee = Hash::compute("system/peer", &[4, 5, 6]);
        let parent = Hash::compute("system/capability/token", &[7, 8, 9]);

        let token = CapabilityToken {
            grants: vec![
                GrantEntry {
                    handlers: PathScope::new(vec!["system/tree".into()]),
                    resources: PathScope::with_exclude(
                        vec!["system/type/*".into()],
                        vec!["system/type/secret".into()],
                    ),
                    operations: IdScope::new(vec!["get".into(), "put".into()]),
                    peers: Some(IdScope::new(vec!["*".into()])),
                    constraints: None,
                    allowances: None,
                },
                GrantEntry {
                    handlers: PathScope::new(vec!["system/capability".into()]),
                    resources: PathScope::none(),
                    operations: IdScope::new(vec!["request".into()]),
                    peers: None,
                    constraints: None,
                    allowances: None,
                },
            ],
            granter: Granter::Single(granter),
            grantee,
            parent: Some(parent),
            created_at: 1710000000,
            expires_at: Some(1710003600),
            not_before: Some(1710000000),
            delegation_caveats: Some(DelegationCaveats {
                no_delegation: Some(false),
                max_delegation_depth: Some(3),
                max_delegation_ttl: Some(86400000),
            }),
        };

        let entity = token.to_entity().unwrap();
        let decoded = CapabilityToken::from_entity(&entity).unwrap();

        assert_eq!(decoded.grants, token.grants);
        assert_eq!(decoded.granter, token.granter);
        assert_eq!(decoded.grantee, token.grantee);
        assert_eq!(decoded.parent, token.parent);
        assert_eq!(decoded.created_at, token.created_at);
        assert_eq!(decoded.expires_at, token.expires_at);
        assert_eq!(decoded.not_before, token.not_before);
        assert_eq!(decoded.delegation_caveats, token.delegation_caveats);
    }

    #[test]
    fn test_capability_token_roundtrip_minimal() {
        let token = make_token(vec![make_grant(&["*"], &["*"], &["*"])]);
        let entity = token.to_entity().unwrap();
        let decoded = CapabilityToken::from_entity(&entity).unwrap();
        assert_eq!(decoded.grants, token.grants);
        assert_eq!(decoded.granter, token.granter);
        assert_eq!(decoded.grantee, token.grantee);
        assert_eq!(decoded.parent, token.parent);
        assert_eq!(decoded.created_at, token.created_at);
        assert_eq!(decoded.expires_at, token.expires_at);
        assert_eq!(decoded.delegation_caveats, token.delegation_caveats);
    }

    #[test]
    fn test_capability_token_from_entity_wrong_type() {
        let entity = entity_entity::Entity::new(
            "system/wrong",
            entity_ecf::to_ecf(&entity_ecf::text("test")),
        )
        .unwrap();
        assert!(CapabilityToken::from_entity(&entity).is_err());
    }
}

#[cfg(test)]
mod canonicalize_entity_uri_tests {
    use super::*;

    const LOCAL: &str = "2KLocalPeerIdBase58xxxxxxxxxxxxxxxxxxxxxxxxxxx";
    const REMOTE: &str = "2KRemotePeerIdBase58xxxxxxxxxxxxxxxxxxxxxxxxxx";

    /// Arch ruling 24: `entity://{p}/x` and `/{p}/x` are the same address, so
    /// canonicalization MUST converge them. This was Rust's longest-standing
    /// cross-impl blocker (logged in docs/SPEC-AMBIGUITIES.md) and the ruling
    /// is that it was never a cross-impl question: *cleaning* preserves the
    /// scheme, *canonicalizing* resolves it. Rust had conflated the two.
    #[test]
    fn entity_uri_canonicalizes_to_the_address_it_names() {
        assert_eq!(
            canonicalize(&format!("entity://{}/system/inbox", REMOTE), LOCAL),
            format!("/{}/system/inbox", REMOTE),
        );
        // The two spellings of one address MUST converge — this is the whole
        // point, and the property the 403 came from violating.
        assert_eq!(
            canonicalize(&format!("entity://{}/system/inbox", REMOTE), LOCAL),
            canonicalize(&format!("/{}/system/inbox", REMOTE), LOCAL),
        );
        // Bare peer, no path.
        assert_eq!(
            canonicalize(&format!("entity://{}", REMOTE), LOCAL),
            format!("/{}", REMOTE),
        );
    }

    /// The regression this actually fixes: a cross-peer `deliver_token`'s
    /// `resources` scope carries the `entity://` form (the shape the spec
    /// uses for a cross-peer deliver_uri), and the delivery-time request
    /// target is the normalized absolute path. Pre-ruling these could never
    /// match, so every cross-peer delivery 403'd `operation permission
    /// denied` — including the spec-model inbox delivery.
    #[test]
    fn entity_uri_scope_matches_normalized_delivery_target() {
        let scope = canonicalize(&format!("entity://{}/system/inbox/*", REMOTE), LOCAL);
        let target = canonicalize(&format!("/{}/system/inbox/msg-1", REMOTE), LOCAL);
        assert!(
            matches_pattern(&target, &scope),
            "an entity:// deliver_token scope {:?} must cover its own \
             delivery target {:?} — this mismatch was the cross-peer 403",
            scope,
            target,
        );
    }

    /// Pre-ruling behavior, pinned so it cannot come back: the bare-path arm
    /// swallowed the scheme and produced a path naming the LOCAL peer and a
    /// literal `entity:` segment.
    #[test]
    fn entity_uri_is_not_mangled_into_a_local_path() {
        let got = canonicalize(&format!("entity://{}/system/inbox", REMOTE), LOCAL);
        assert!(
            !got.contains("entity:"),
            "the scheme survived canonicalization: {}",
            got
        );
        assert!(
            !got.starts_with(&format!("/{}/entity", LOCAL)),
            "a remote address canonicalized to a LOCAL path: {}",
            got
        );
    }
}

#[cfg(test)]
mod temporal_field_wire_tests {
    use super::*;

    fn token_with_expiry(expires_at: Option<u64>) -> CapabilityToken {
        CapabilityToken {
            grants: Vec::new(),
            granter: Granter::single(Hash::compute("system/peer", &[9])),
            grantee: Hash::compute("system/peer", &[8]),
            parent: None,
            created_at: 1_700_000_000_000,
            expires_at,
            not_before: None,
            delegation_caveats: None,
        }
    }

    /// `expires_at` is `primitive/uint`. Encoding it through `x as i64` made
    /// every value above `i64::MAX` **negative** on the wire — and the values
    /// that reach that range are exactly the ones a saturating temporal clamp
    /// produces (`u64::MAX`, e.g. EXTENSION-ROLE §5.3's `saturating_add`). A
    /// negative `expires_at` is refused by a `u64` reader (or read as absent),
    /// so the cast turned an absurd expiry into a malformed one.
    #[test]
    fn an_expires_at_above_i64_max_survives_the_round_trip() {
        for exp in [u64::MAX, (i64::MAX as u64) + 1, 1_700_000_000_000] {
            let entity = token_with_expiry(Some(exp)).to_entity().unwrap();
            let back = CapabilityToken::from_entity(&entity).unwrap();
            assert_eq!(
                back.expires_at,
                Some(exp),
                "expires_at {exp} must round-trip as a CBOR uint, not wrap negative"
            );
        }
    }

    /// The ingest half of CAP-6, and the fail-open one. A peer that computes
    /// `created_at + ttl_ms` at arbitrary precision (py's defect, wire-caught
    /// by core-go's no-ceiling probe) mints an `expires_at` no `u64` reader can
    /// represent. Reading it as *absent* would hand the grantee an immortal
    /// cap while go refuses the same bytes — one token, two peers, two
    /// lifetimes, which is what §5.10 determinism forbids. Refuse it.
    #[test]
    fn an_unrepresentable_expires_at_is_refused_not_read_as_absent() {
        // The two shapes an out-of-range `expires_at` actually arrives in:
        // a CBOR bignum (tag 2 — what a language whose integers cannot
        // overflow emits for `created_at + ttl_ms`), and a negative integer
        // (what a `u64 as i64` encoder emits above `i64::MAX` — the bug fixed
        // one test up, whose output any peer may still be holding).
        let bignum = ciborium::Value::Tag(
            2,
            Box::new(ciborium::Value::Bytes(
                (u128::from(u64::MAX) + 1_000).to_be_bytes().to_vec(),
            )),
        );
        let negative = ciborium::Value::Integer(ciborium::value::Integer::from(-11i64));
        for hostile in [bignum, negative] {
            let entity = token_with_expiry(Some(1_700_000_000_000))
                .to_entity()
                .unwrap();
            let value: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).unwrap();
            let mut map = value.as_map().unwrap().clone();
            for (k, v) in map.iter_mut() {
                if k.as_text() == Some("expires_at") {
                    *v = hostile.clone();
                }
            }
            let data = entity_ecf::to_ecf(&ciborium::Value::Map(map));
            let entity = entity_entity::Entity::new(entity_types::TYPE_CAP_TOKEN, data).unwrap();
            let err = CapabilityToken::from_entity(&entity)
                .expect_err("a token whose expires_at is not a primitive/uint is malformed");
            assert!(
                err.to_string().contains("expires_at"),
                "the error must name the field: {err}"
            );
        }
    }

    /// `null` remains the legal-but-discouraged spelling of "no bound" — the
    /// optional-field convention is *SHOULD be absent, null is valid*, and the
    /// refusal above must not sweep it up.
    #[test]
    fn a_null_expires_at_still_decodes_as_no_expiry() {
        let entity = token_with_expiry(None).to_entity().unwrap();
        let value: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).unwrap();
        let mut map = value.as_map().unwrap().clone();
        map.push((entity_ecf::text("expires_at"), ciborium::Value::Null));
        map.sort_by(|a, b| {
            a.0.as_text()
                .unwrap_or_default()
                .cmp(b.0.as_text().unwrap_or_default())
        });
        let data = entity_ecf::to_ecf(&ciborium::Value::Map(map));
        let entity = entity_entity::Entity::new(entity_types::TYPE_CAP_TOKEN, data).unwrap();
        assert_eq!(
            CapabilityToken::from_entity(&entity).unwrap().expires_at,
            None
        );
    }
}
