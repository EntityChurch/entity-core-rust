//! Meta-resolver substrate (§2 / §4) — the `system/registry` handler.
//!
//! Ops: `:resolve(name, [hints]) → ResolutionResult` and
//! `:invalidate-cache(name | null) → ()`. The resolve algorithm (§4.1):
//!
//! 1. **Pinned bindings** override everything → synthesized result (§4.1.2).
//! 2. **`name_format_dispatch`** narrows the chain (§4's closed grammar —
//!    `*` only, every other byte literal; see [`dispatch_match`]); the
//!    primary privacy mechanism — backends without a dispatch entry match-all.
//! 3. **Filtered chain in priority order** — first validated hit wins.
//! 4. else **`chain_exhausted`** (fail-closed; no silent fallback).
//!
//! Validation = trust-anchor receiver policy + revocation honor + (for signed,
//! non-local-name/non-self-certifying kinds) signature verification. v1 ships the
//! local-name backend as the only concrete chain backend; other `backend_kind`s
//! skip-with-warning (§4.2). The signature primitive
//! ([`verify_binding_signature`]) is provided for backends shipped separately.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use entity_crypto::Keypair;
use entity_entity::{Entity, TYPE_SIGNATURE};
use entity_handler::{Handler, HandlerContext, HandlerError, HandlerResult, STATUS_BAD_REQUEST};
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};
use entity_types::SignatureData;

use crate::data::{
    decode_map, get_field, BindingData, ResolutionResult, ResolverConfigData, RevocationData,
    KIND_LOCAL_NAME, KIND_SELF_CERTIFYING, TRUST_OUT_OF_BAND,
};
use crate::local_name::{load_local_name_config, resolve_one};
use crate::log::ResolutionLog;
use crate::result::{error, status_result};
use crate::{resolver_config_path, BACKEND_KIND_LOCAL_NAME, BACKEND_KIND_PEER_ISSUED};

/// `system/registry` meta-resolver handler.
pub struct RegistryHandler {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    peer_id: String,
    qualified_pattern: String,
    log: Arc<ResolutionLog>,
    /// The live remote-read transport for `peer-issued` chain entries, if the
    /// host wired one. `None` is the v1 posture and stays fully supported: the
    /// backend then resolves against the local store only — the §2.2
    /// precede/offline path.
    reader: Option<Arc<dyn crate::peer_issued::RegistryTreeReader>>,
}

impl RegistryHandler {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
        log: Arc<ResolutionLog>,
    ) -> Self {
        let qualified_pattern = format!("/{}/system/registry", local_peer_id);
        Self {
            content_store,
            location_index,
            peer_id: local_peer_id,
            qualified_pattern,
            log,
            reader: None,
        }
    }

    /// Wire the live remote-read transport for `peer-issued` backends.
    ///
    /// Without it the backend is the offline half only: it resolves whatever a
    /// deployment pre-fetched into the local store and never dials the pinned
    /// registry.
    pub fn with_reader(mut self, reader: Arc<dyn crate::peer_issued::RegistryTreeReader>) -> Self {
        self.reader = Some(reader);
        self
    }

    /// Fetch what a `peer-issued` resolve of this name will read, for every
    /// pinned registry in the chain that carries an endpoint hint.
    ///
    /// Runs before the sync resolve and is a no-op when no reader is wired, when
    /// no chain entry is `peer-issued`, or when the name is already cached
    /// (§2.2 — the precede path MUST NOT touch the wire).
    async fn warm_peer_issued(&self, ctx: &HandlerContext) {
        let Some(reader) = self.reader.as_ref() else {
            return;
        };
        let Ok(map) = decode_map(&ctx.params.data) else {
            return;
        };
        let Some(name) = get_field(&map, "name").and_then(|v| v.as_text()) else {
            return;
        };
        for entry in self.load_config().resolver_chain.iter() {
            if entry.backend_kind != BACKEND_KIND_PEER_ISSUED {
                continue;
            }
            crate::peer_issued::warm_cache(
                reader.as_ref(),
                &self.content_store,
                &self.location_index,
                entry,
                name,
            )
            .await;
        }
    }

    fn load_config(&self) -> ResolverConfigData {
        self.location_index
            .get(&resolver_config_path(&self.peer_id))
            .and_then(|h| self.content_store.get(&h))
            .and_then(|e| ResolverConfigData::from_entity(&e).ok())
            .unwrap_or_else(|| self.default_local_name_only())
    }

    /// Default when no resolver-config exists: a single local-name backend at
    /// priority 0 (the §10 "local-name-only" deployment), so the local store works
    /// out of the box. The seed-policy MAY overwrite this with a richer config.
    fn default_local_name_only(&self) -> ResolverConfigData {
        use crate::data::ResolverChainEntry;
        ResolverConfigData {
            resolver_chain: vec![ResolverChainEntry {
                backend_kind: BACKEND_KIND_LOCAL_NAME.into(),
                backend_id: self.peer_id.clone(),
                priority: 0,
                accepted_trust_anchors: Vec::new(),
                hints: None,
            }],
            ..Default::default()
        }
    }

    /// §4.1 meta_resolve.
    fn meta_resolve(&self, name: &str, config: &ResolverConfigData) -> ResolutionResult {
        // Step 1: pinned bindings override everything.
        if let Some(pin) = config.pinned_bindings.iter().find(|p| p.name == name) {
            return self.synthesize_pin(pin);
        }

        // Step 2: name_format_dispatch filter (the primary privacy mechanism).
        // A backend kind that appears in ANY dispatch rule is "restricted" —
        // consulted only when a rule whose backend_kinds contains it matches
        // the name. Kinds appearing in no rule are match-all.
        //
        // **This is §4.1 step 2's second sentence, per backend, both clauses:**
        // *"Backends without a `name_format_dispatch` entry default to 'match
        // all' (no filtering); backends with one are consulted ONLY when the
        // pattern matches."*
        //
        // **core-go reads it differently and its `registry.v15_dispatch_grammar`
        // check encodes their reading** (`ext/registry/registry.go`): if any
        // rule matches, the chain is restricted to the union of the matching
        // rules' kinds; if none matches, the chain is left unfiltered. Those
        // two algorithms differ on two cases, and neither of us is right on
        // both:
        //
        // | case | this peer | core-go | §4.1 step 2 |
        // |---|---|---|---|
        // | kind named by NO rule, some other rule matches | consulted | excluded | *"without an entry … match all"* → **ours** |
        // | kind named by a rule, NO rule matches the name | excluded | consulted | *"with one … ONLY when the pattern matches"* → **ours** |
        //
        // We hold this reading because both rows follow from the sentence that
        // addresses the case directly, and go's fallback contradicts the
        // second clause outright. **It is not the comfortable answer:** on row
        // 1 our reading makes step 2's own MUST — *"the catch-all MUST NOT
        // name a backend whose consultation transmits the queried name"* —
        // evadable by **omitting** the row, since a `dns-txt` backend named by
        // no rule is then consulted for every bare name. That is a real
        // argument for go's direction and it is why this is routed rather
        // than settled here (`docs/SPEC-AMBIGUITIES.md`); converging a
        // security-relevant cross-impl surface onto a reading that
        // contradicts a plain normative sentence, to turn a wire check green,
        // is the move this repo does not make.
        let restricted: std::collections::HashSet<&str> = config
            .name_format_dispatch
            .iter()
            .flat_map(|r| r.backend_kinds.iter().map(|s| s.as_str()))
            .collect();
        let allowed = |kind: &str| -> bool {
            if !restricted.contains(kind) {
                return true;
            }
            config.name_format_dispatch.iter().any(|r| {
                r.backend_kinds.iter().any(|k| k == kind) && dispatch_match(&r.pattern, name)
            })
        };

        // Step 3: filtered chain in ascending priority order; first validated hit.
        let mut chain: Vec<&crate::data::ResolverChainEntry> = config
            .resolver_chain
            .iter()
            .filter(|e| allowed(&e.backend_kind))
            .collect();
        chain.sort_by_key(|e| e.priority);

        for entry in chain {
            let candidate = match entry.backend_kind.as_str() {
                BACKEND_KIND_LOCAL_NAME => {
                    let pcfg = load_local_name_config(
                        &self.content_store,
                        &self.location_index,
                        &self.peer_id,
                    );
                    resolve_one(
                        &self.content_store,
                        &self.location_index,
                        &self.peer_id,
                        &pcfg,
                        name,
                    )
                }
                BACKEND_KIND_PEER_ISSUED => crate::peer_issued::resolve_one(
                    &self.content_store,
                    &self.location_index,
                    entry,
                    name,
                ),
                other => {
                    // Unknown / unsupported backend kind in v1 — skip-with-warning
                    // (§4.2 forward-compat). Backends ship in their own proposals.
                    tracing::warn!(
                        backend_kind = other,
                        "registry: skipping unsupported backend"
                    );
                    None
                }
            };
            let Some(result) = candidate else { continue };
            if !result.is_resolved() {
                continue;
            }
            // Receiver-policy: trust-anchor must pass accepted_trust_anchors.
            if !entry.accepted_trust_anchors.is_empty() {
                let ok = result
                    .trust_anchor
                    .as_deref()
                    .map(|ta| entry.accepted_trust_anchors.iter().any(|a| a == ta))
                    .unwrap_or(false);
                if !ok {
                    continue;
                }
            }
            // Revocation honor (§3.1 / §6.6): exclude + advance if revoked.
            if let Some(binding_hash) = result.binding {
                if self.is_revoked(binding_hash) {
                    continue;
                }
            }
            return apply_resolver_ceiling(result, entry);
        }
        ResolutionResult::chain_exhausted()
    }

    /// §4.1.2 — deterministic synthesized result for a pinned binding. The
    /// synthetic `out-of-band` binding entity is stored so its hash resolves
    /// (inspectability invariant); `issued_at: 0` keeps the hash deterministic.
    fn synthesize_pin(&self, pin: &crate::data::PinnedBinding) -> ResolutionResult {
        let synthetic = BindingData {
            name: pin.name.clone(),
            kind: "out-of-band".into(),
            target_peer_id: pin.target_peer_id.clone(),
            transports: Vec::new(),
            issued_at: 0,
            ttl: None,
            supersedes: None,
            issuer_attestation: None,
            metadata: None,
        };
        let binding_hash = match synthetic.to_entity() {
            Ok(e) => {
                let h = e.content_hash;
                let _ = self.content_store.put(e);
                Some(h)
            }
            Err(_) => None,
        };
        ResolutionResult {
            status: crate::data::STATUS_RESOLVED.into(),
            binding: binding_hash,
            peer_id: Some(pin.target_peer_id.clone()),
            transports: Vec::new(),
            attestations: Vec::new(),
            trust_anchor: Some(TRUST_OUT_OF_BAND.into()),
            ttl: None,
            neg_ttl: None,
            backend_id: Some("pinned".into()),
        }
    }

    /// Look for a `system/registry/revocation` entity targeting `binding_hash`.
    ///
    /// Revocation entities are stored at `system/registry/revocation/{hex}`
    /// keyed by the **revocation entity's own content hash** (cohort
    /// convention — Go `RevocationStoragePath`, validate-peer v6), NOT by the
    /// binding they revoke. So discovery is a **scan** of the revocation
    /// subtree, matching on the `revokes:` field — not an O(1) lookup keyed by
    /// the binding hash (the spec pins the entity type + signature carriage,
    /// not a binding-keyed path — see docs/SPEC-AMBIGUITIES.md §3.1 carve-out).
    ///
    /// A local-name binding is excluded on presence of any type-valid
    /// revocation: the local store is itself the trust source (§6.3 carve-out,
    /// same as the local-name binding), so an unsigned local revocation suffices.
    /// Signed kinds (DID-web, etc.) would additionally require a same-authority
    /// signed revocation.
    fn is_revoked(&self, binding_hash: Hash) -> bool {
        let prefix = format!("/{}/system/registry/revocation/", self.peer_id);
        self.location_index.list(&prefix).into_iter().any(|entry| {
            self.content_store
                .get(&entry.hash)
                .and_then(|e| RevocationData::from_entity(&e).ok())
                .map(|rev| rev.revokes == binding_hash)
                .unwrap_or(false)
        })
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for RegistryHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        match ctx.operation.as_str() {
            "resolve" => {
                // The live remote-read seam runs HERE, not inside the backend:
                // `meta_resolve` and every backend under it are sync, and the
                // fetch is not. Warming the store first lets the whole resolve
                // algorithm stay unchanged and transport-blind — which is the
                // architecture `peer_issued`'s module doc has described since
                // v1 ("a core/peer/SDK concern that POPULATES this store").
                // No reader configured ⇒ the precede/offline path, unchanged.
                self.warm_peer_issued(ctx).await;
                Ok(self.handle_resolve(ctx))
            }
            "invalidate-cache" => Ok(self.handle_invalidate_cache(ctx)),
            other => Ok(error(
                STATUS_BAD_REQUEST,
                "unknown_operation",
                &format!("unknown registry op: {}", other),
            )),
        }
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "registry"
    }

    fn operations(&self) -> &[&str] {
        &["resolve", "invalidate-cache"]
    }
}

impl RegistryHandler {
    fn handle_resolve(&self, ctx: &HandlerContext) -> HandlerResult {
        let map = match decode_map(&ctx.params.data) {
            Ok(m) => m,
            Err(e) => return error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string()),
        };
        let name = match get_field(&map, "name").and_then(|v| v.as_text()) {
            Some(n) => n.to_string(),
            None => return error(STATUS_BAD_REQUEST, "invalid_params", "name required"),
        };
        let is_fallback = get_field(&map, "is_fallback_reresolve")
            .and_then(|v| match v {
                ciborium::Value::Bool(b) => Some(*b),
                _ => None,
            })
            .unwrap_or(false);

        let config = self.load_config();
        let result = self.meta_resolve(&name, &config);

        // §11.2: one log entry per top-level meta_resolve; transport-fallback
        // re-resolves are NOT written (avoid hot-path write amplification).
        if !is_fallback {
            self.log.record(
                &name,
                &result.status,
                result.backend_id.clone(),
                None,
                result.binding,
                false,
            );
        }
        // §2.1 Ruling-3: return the bare `system/registry/resolution-result`
        // entity with flat data — NOT wrapped under `system/protocol/status`.
        HandlerResult {
            status: entity_handler::STATUS_OK,
            result: result.to_entity(),
            included: HashMap::new(),
        }
    }

    /// `:invalidate-cache(name | null)` — v1's resolver is stateless
    /// (re-resolves each call), so there is no positive-resolution cache to
    /// flush; returns ok. TTL-based caching is a SHOULD layered on top (§11.2).
    fn handle_invalidate_cache(&self, _ctx: &HandlerContext) -> HandlerResult {
        status_result(vec![(
            entity_ecf::text("invalidated"),
            ciborium::Value::Bool(true),
        )])
    }
}

// ---------------------------------------------------------------------------
// Signature verification primitive (§3) — for signed (non-local-name) backends.
// ---------------------------------------------------------------------------

/// Verify a binding's authenticating `system/signature` (§3). Returns `true`
/// for self-certifying (name == target_peer_id, valid V7 §1.5 structure) and
/// local-name (user is trust source) bindings without a signature. For all
/// other kinds, locates the signature via `included` or the invariant-pointer
/// path `system/signature/{hex(binding_hash)}` and verifies it against the
/// issuer's published key.
pub fn verify_binding_signature(
    binding: &BindingData,
    binding_hash: &Hash,
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
    included: &HashMap<Hash, Entity>,
) -> bool {
    match binding.kind.as_str() {
        KIND_LOCAL_NAME => true,
        KIND_SELF_CERTIFYING => {
            binding.name == binding.target_peer_id
                && entity_crypto::PeerId::from(binding.target_peer_id.clone())
                    .decode()
                    .is_ok()
        }
        _ => {
            let sig =
                match find_binding_signature(binding_hash, content_store, location_index, included)
                {
                    Some(s) => s,
                    None => return false,
                };
            let pubkey = match resolve_peer_pubkey(&sig.signer, content_store) {
                Some(pk) => pk,
                None => return false,
            };
            Keypair::verify(&pubkey, &binding_hash.to_bytes(), &sig.signature).is_ok()
        }
    }
}

pub(crate) fn find_binding_signature(
    target: &Hash,
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
    included: &HashMap<Hash, Entity>,
) -> Option<SignatureData> {
    // (1) envelope-bundled.
    for entity in included.values() {
        if entity.entity_type == TYPE_SIGNATURE {
            if let Ok(sig) = SignatureData::from_entity(entity) {
                if &sig.target == target {
                    return Some(sig);
                }
            }
        }
    }
    // (2) invariant-pointer at .../system/signature/{target_hex}.
    let suffix = format!("system/signature/{}", target.to_hex());
    for entry in location_index.list("/") {
        if !entry.path.ends_with(&suffix) {
            continue;
        }
        if let Some(e) = content_store.get(&entry.hash) {
            if e.entity_type == TYPE_SIGNATURE {
                if let Ok(sig) = SignatureData::from_entity(&e) {
                    if &sig.target == target {
                        return Some(sig);
                    }
                }
            }
        }
    }
    None
}

pub(crate) fn resolve_peer_pubkey(
    peer_hash: &Hash,
    content_store: &Arc<dyn ContentStore>,
) -> Option<[u8; 32]> {
    peer_pubkey_from_entity(&content_store.get(peer_hash)?)
}

/// Extract the Ed25519 `public_key` digest from a `system/peer` entity (v1
/// trust-anchor floor, §6a.5 — Ed25519-only). Shared by the resolve-side
/// pin check and the registration-side layer-1 proof.
pub(crate) fn peer_pubkey_from_entity(entity: &Entity) -> Option<[u8; 32]> {
    if entity.entity_type != entity_crypto::TYPE_PEER {
        return None;
    }
    let value: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).ok()?;
    let map = value.as_map()?;
    let pk = map.iter().find_map(|(k, v)| {
        if k.as_text() == Some("public_key") {
            v.as_bytes()
        } else {
            None
        }
    })?;
    pk.as_slice().try_into().ok()
}

/// §6a.9.1 `[MUST when present, v1.11]` — the **resolver's own** TTL ceiling:
/// a binding's effective lifetime is `min(binding.ttl, local_max)`, computed
/// at resolution and **never written back** into the binding.
///
/// **This is the half that protects the consumer, and it is the load-bearing
/// one.** §6a.3's whole argument is about the consumer: a hostile byte-server
/// withholds a revocation and `ttl` bounds the exposure. A ceiling the
/// *registry* enforces cannot protect a consumer from that registry — a
/// hostile or compromised issuer simply sets `max_ttl` high. Only the party
/// bearing the risk can bound it. This is the split DNS settled decades ago:
/// the authority sets the record's TTL, the resolver caps what it will honor
/// (`max-cache-ttl`), because the resolver is the one holding stale data.
///
/// **Never written back, and that is the property that would rot silently.**
/// This is a *use* bound, not a re-issue: the binding body is untouched, so
/// `result.binding` stays byte-identical clamped and unclamped. If a refactor
/// ever rewrote the binding to carry the clamped TTL, its content address
/// would move and every signature over it would stop verifying — gated by
/// `resolver_ceiling_does_not_move_the_binding_hash`, which asserts the hash
/// rather than the number for exactly that reason.
///
/// **No default is shipped, and that is conformance rather than
/// incompleteness.** §6a.3's ceiling is a `MAY` and the spec writes no number
/// for the reason §4.10 writes none: there is no defensible constant, and
/// choosing one makes every unconfigured deployment look configured.
///
/// The value rides the chain entry's `hints` — §4's own opaque
/// backend-config slot, which `neg_ttl` already uses — so it is **durable
/// config read at resolution**, not a process-lifetime setting. A ceiling
/// read at fetch time applies on a cold boot and silently does not on a warm
/// one, and a security control present on one boot path and absent on the
/// other is worse than absent: it tests green on whichever path the test
/// happens to take.
pub(crate) fn apply_resolver_ceiling(
    mut result: ResolutionResult,
    entry: &crate::data::ResolverChainEntry,
) -> ResolutionResult {
    let Some(local_max) = resolver_max_ttl_from_hints(&entry.hints) else {
        return result;
    };
    result.ttl = match result.ttl {
        Some(t) => Some(t.min(local_max)),
        // A sticky binding (a pin, a local-name) carries no `ttl`. The
        // resolver's ceiling is a bound on how long a value may be honored,
        // so an absent lifetime becomes the declared maximum rather than
        // staying unbounded — that is the whole point of declaring one.
        // (`peer-issued` never reaches this arm: §6a.4 requires a non-null
        // `ttl` before a result is surfaced at all.)
        None => Some(local_max),
    };
    result
}

/// Read the resolver's declared ceiling (ms) from a chain entry's `hints`.
///
/// `0` is **dropped rather than honored**: taken literally it expires every
/// binding instantly and the operator sees *"no binding for this name"* —
/// indistinguishable from a bad signature or a revocation, which is the worst
/// possible diagnostic for a value that is almost certainly a typo or an
/// unset field serialized as zero.
fn resolver_max_ttl_from_hints(hints: &Option<entity_ecf::Value>) -> Option<u64> {
    let map = hints.as_ref()?.as_map()?;
    map.iter().find_map(|(k, v)| {
        if k.as_text() == Some("max_ttl") {
            v.as_integer()
                .and_then(|i| u64::try_from(i).ok())
                .filter(|ms| *ms > 0)
        } else {
            None
        }
    })
}

// ---------------------------------------------------------------------------
// §4 `name_format_dispatch.pattern` — the CLOSED grammar `[MUST, REGISTRY 1.13]`
// ---------------------------------------------------------------------------

/// Match a `name_format_dispatch[].pattern` against a user-facing name.
///
/// **The grammar is closed and every byte that is not `*` is a literal.**
/// §4's pseudocode, verbatim:
///
/// - `*` matches any run of characters, **including none**.
/// - **Any other byte** — `?`, `[`, `]`, `\`, `.`, `:`, `@`, `/` — matches
///   only itself.
/// - Any **number** of `*` is permitted; `*@*.*` is three and it is in
///   §4.1a's own table.
/// - **`/` is not a separator.** A name is a flat string with no segment
///   structure.
/// - The match is **anchored at both ends**; there is no substring form.
///
/// **Implementations MUST NOT delegate this to a path-glob or shell-glob
/// library**, which is what this replaced: a POSIX matcher granting `?` a
/// one-character meaning and `[…]` a character-class meaning the grammar does
/// not confer. *"A matcher that merely omits those features and one that
/// treats them as literals are indistinguishable until a name or a pattern
/// carries one"* — the `**` lesson, transplanted. `entity-core-go` found this
/// by reading its own call site (`08684b2`), routed the reading rather than
/// shipping a third matcher, and arch closed the grammar in `1.13`.
///
/// **This is not `ENTITY-CORE-PROTOCOL` §5.4 and MUST NOT be read as it.**
/// §5.4 governs *paths*, where `pattern/*` is a subtree prefix; a name is
/// flat, so §5.4's forms have nothing to bind to. The two are separate
/// matchers over separate domains and neither confers a reading on the other.
///
/// **No pattern is invalid, so there is no write-time rejection** — every
/// string is well-formed because every non-`*` byte is a literal. That is a
/// deliberate difference from `EXTENSION-REVISION`'s four forms, which need a
/// `400` because that grammar *can* be violated: a registry MUST NOT reject a
/// dispatch pattern for containing `?`, `[`, or `\`.
pub fn dispatch_match(pattern: &str, name: &str) -> bool {
    dispatch_match_bytes(pattern.as_bytes(), name.as_bytes())
}

fn dispatch_match_bytes(mut p: &[u8], mut n: &[u8]) -> bool {
    loop {
        match p.first() {
            // Anchored at the end: the pattern is spent, so the name must be.
            None => return n.is_empty(),
            Some(b'*') => {
                // Collapse a run of `*` — `**` is not a token here, it is two
                // wildcards, and any number is permitted.
                while p.first() == Some(&b'*') {
                    p = &p[1..];
                }
                if p.is_empty() {
                    // Trailing `*` absorbs the remainder, `/` included.
                    return true;
                }
                // `*` crosses `/`: every suffix is a candidate, with no
                // separator to stop at. This is `REG-DISPATCH-GRAMMAR-1`'s
                // fourth row (`x*z` matches `x/y/z`) and the one that fails
                // against every path-glob implementation.
                for i in 0..=n.len() {
                    if dispatch_match_bytes(p, &n[i..]) {
                        return true;
                    }
                }
                return false;
            }
            // EVERY other byte is a literal. No `?`, no `[…]`, no escape:
            // a `\` matches a `\`.
            Some(&c) => {
                if n.first() != Some(&c) {
                    return false;
                }
                p = &p[1..];
                n = &n[1..];
            }
        }
    }
}
