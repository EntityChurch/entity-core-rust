//! Meta-resolver substrate (§2 / §4) — the `system/registry` handler.
//!
//! Ops: `:resolve(name, [hints]) → ResolutionResult` and
//! `:invalidate-cache(name | null) → ()`. The resolve algorithm (§4.1):
//!
//! 1. **Pinned bindings** override everything → synthesized result (§4.1.2).
//! 2. **`name_format_dispatch`** narrows the chain (§4's closed grammar —
//!    `*` only, every other byte literal; see [`dispatch_match`]); the primary
//!    privacy mechanism. Eligibility is a pure function of the name: the union
//!    of the matching rules' `backend_kinds`, empty when none match `[1.14]`.
//! 3. **Filtered chain in priority order** — first validated hit wins.
//! 4. else **`chain_exhausted`** (fail-closed; no silent fallback).
//!
//! Validation = trust-anchor receiver policy + revocation honor + (for signed,
//! non-local-name/non-self-certifying kinds) signature verification. v1 ships the
//! local-name backend as the only concrete chain backend; other `backend_kind`s
//! skip-with-warning (§4.2). The signature primitive
//! ([`verify_binding_signature`]) is provided for backends shipped separately.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use entity_crypto::Keypair;
use entity_entity::{Entity, TYPE_SIGNATURE};
use entity_handler::{
    Handler, HandlerContext, HandlerError, HandlerResult, STATUS_BAD_REQUEST, STATUS_FORBIDDEN,
    STATUS_NOT_FOUND,
};
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};
use entity_types::SignatureData;

use crate::data::{
    decode_map, get_field, BindingData, ResolutionResult, ResolverConfigData, RevocationData,
    KIND_LOCAL_NAME, KIND_SELF_CERTIFYING, TRUST_OUT_OF_BAND,
};
use crate::local_name::{load_local_name_config, resolve_one};
use crate::log::ResolutionLog;
use crate::result::{entity_result, error, status_result};
use crate::{
    resolver_config_path, BACKEND_KIND_CONSENSUS_ANCHORED, BACKEND_KIND_DID_WEB,
    BACKEND_KIND_DNS_TXT, BACKEND_KIND_LOCAL_NAME, BACKEND_KIND_PEER_ISSUED,
    BACKEND_KIND_WELL_KNOWN_URL,
};

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
    /// The last §4.3 load-side diagnostic, keyed by the config's content hash.
    ///
    /// **Bounded by construction, and that is deliberate.** The obligation is
    /// to *surface* (§4.1 step 2 `[MUST, v1.17]`), not to accumulate: a
    /// growing list of every violating config ever loaded is the unaccounted
    /// accumulation the charter names, on a path that runs twice per resolve.
    /// Holding one `(hash, violations)` makes the emit fire once per distinct
    /// config and gives a test something to read without a sink injection.
    config_diagnostic: RwLock<Option<(Hash, Vec<String>)>>,
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
            config_diagnostic: RwLock::new(None),
        }
    }

    /// The §4.3 load-side diagnostic for the currently-stored resolver-config,
    /// as `(config content hash, violations)` — `None` when the stored config
    /// discloses nothing (or none has been loaded yet).
    ///
    /// This is the *observable* half of *"surface it, never normalize it,
    /// never refuse to start"*: the peer keeps running on the operator's bytes
    /// and says so. There is no conformance instrument for it — the diagnostic
    /// channel is undefined at the wire, which core-go flagged from its own
    /// seat — so this accessor plus `tracing::warn!` is the whole surface.
    pub fn last_config_diagnostic(&self) -> Option<(Hash, Vec<String>)> {
        self.config_diagnostic
            .read()
            .ok()?
            .clone()
            .filter(|(_, violations)| !violations.is_empty())
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

    /// Load the stored resolver-config, or [`Self::default_local_name_only`].
    ///
    /// **§4.3 / §4.1 step 2 `[MUST, v1.17]` — at load: surface it, never
    /// normalize it, never refuse to start.** A stored config may violate the
    /// name-disclosure rule by two routes the write-time check cannot see: an
    /// **out-of-band seed** (a raw `tree-put` at `resolver_config_path`, which
    /// §4.3 keeps working on purpose — *"the undocumented path is loud rather
    /// than blocked"*), and a kind that was unknown when it was written and
    /// has since been **declared** name-transmitting (§4.2's forward risk,
    /// *"discharged by when the check runs"*). So this reads the same
    /// classifier at every load and reports.
    ///
    /// The three things it deliberately does **not** do: it does not refuse
    /// (that would delete the operator `MAY` — *"a peer that will not boot on
    /// a config the operator deliberately wrote has revoked the override it
    /// was granted"*), it does not narrow the chain in memory (silent
    /// normalization *"makes the operator's stored bytes lie"*), and it does
    /// not rewrite the entity (§4.1 `[MUST, v1.17]` — reading is not writing,
    /// at any configuration surface; a rewrite moves the content hash and
    /// republishes the operator's intent as the peer's).
    fn load_config(&self) -> ResolverConfigData {
        let Some(hash) = self
            .location_index
            .get(&resolver_config_path(&self.peer_id))
        else {
            return self.default_local_name_only();
        };
        let Some(config) = self
            .content_store
            .get(&hash)
            .and_then(|e| ResolverConfigData::from_entity(&e).ok())
        else {
            return self.default_local_name_only();
        };
        self.surface_config_disclosure(hash, &config);
        config
    }

    /// Emit the §4.3 load-side diagnostic, once per distinct config hash.
    ///
    /// Keyed on the hash so the twice-per-resolve load path costs one
    /// comparison in the steady state and never re-runs the classifier.
    fn surface_config_disclosure(&self, hash: Hash, config: &ResolverConfigData) {
        // The slot records the last config **examined**, clean or not, so a
        // clean config is classified once too. Recording only violations would
        // re-run the classifier on every load of the common (clean) case.
        if self
            .config_diagnostic
            .read()
            .ok()
            .is_some_and(|d| d.as_ref().is_some_and(|(h, _)| *h == hash))
        {
            return;
        }
        let violations = disclosure_violations(config);
        if violations.is_empty() {
            // A config that discloses nothing also clears a stale diagnostic —
            // the operator repaired it, and a diagnostic that outlives its
            // cause is the same lie in the other direction.
            if let Ok(mut slot) = self.config_diagnostic.write() {
                *slot = Some((hash, Vec::new()));
            }
            return;
        }
        tracing::warn!(
            config = %hash.to_hex(),
            violations = %violations.join("; "),
            "registry: the stored resolver-config makes a name-transmitting backend eligible \
             for unscoped names (§4.1 step 2) — honored as written, surfaced not refused (§4.3)"
        );
        if let Ok(mut slot) = self.config_diagnostic.write() {
            *slot = Some((hash, violations));
        }
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
        //
        // **Eligibility is a pure function of the name** `[MUST, REGISTRY
        // 1.14]` — arch `86643f8`, routed as `ROUTING-2026-08-19-a` §1:
        //
        //     rules := config.name_format_dispatch
        //     if rules is absent or empty:  return ALL          ; filter disabled
        //     matched := [ r for r in rules if dispatch_match(r.pattern, name) ]
        //     return union( r.backend_kinds for r in matched )  ; EMPTY if none matched
        //
        //     ; consult an entry IFF entry.backend_kind ∈ eligible_kinds(config, name)
        //
        // **A kind reaches eligibility only by being named.** There is no
        // per-backend default, no "match all" for a kind named nowhere, and no
        // fallback when nothing matches — that is the empty set, so the chain
        // narrows to empty and step 4 reports `chain_exhausted` (fail-closed).
        //
        // This replaced the per-backend reading we shipped and routed, and
        // core-go's "if nothing matched, leave the chain unfiltered" fallback;
        // **neither seat was right on both rows** and the paragraph is what
        // changed. It answered the same question twice — one sentence
        // set-valued, the next per-backend — and the per-backend sentence was
        // a **category error**: rules name `backend_kinds`, not backends, so
        // *"a backend without a `name_format_dispatch` entry"* had no
        // referent. Our contradiction report is confirmed on the text; the row
        // it cost us is the one where a kind named by no rule stayed
        // consulted, which made step 2's own privacy MUST evadable by
        // **omitting** a row — the argument we filed against our own reading,
        // and the one arch ruled on. §4's withdrawn *"a name matching no entry
        // is treated as matching the catch-all"* is gone with it: the
        // catch-all is `*`, which matches every name, so that sentence named a
        // row with no referent.
        //
        // Three gates, one per branch: `a_kind_named_by_no_dispatch_rule_is_not_eligible`
        // (the row that flipped here), `meta_resolver_dispatch_filter_excludes_local_name`
        // (nothing matched → `chain_exhausted`, the row go's guard flipped),
        // and `an_absent_dispatch_list_disables_the_filter_rather_than_narrowing_to_empty`
        // (the `None` branch — the unconfigured deployment must not fail closed).
        let eligible: Option<std::collections::HashSet<&str>> =
            if config.name_format_dispatch.is_empty() {
                None // filter disabled — every kind in the chain is eligible
            } else {
                Some(
                    config
                        .name_format_dispatch
                        .iter()
                        .filter(|r| dispatch_match(&r.pattern, name))
                        .flat_map(|r| r.backend_kinds.iter().map(|s| s.as_str()))
                        .collect(),
                )
            };
        let allowed = |kind: &str| -> bool {
            match &eligible {
                None => true,
                Some(kinds) => kinds.contains(kind),
            }
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

    /// §3.1 — look for a `system/registry/revocation` targeting `binding_hash`,
    /// over the registry's revocation subtree.
    ///
    /// **§3.1 and §6a.6 are two different normative sentences, and R-4 named
    /// only one of them.**
    ///
    /// - **§6a.6 `[NORMATIVE]`** makes `revoked(registry, binding_hash)` an O(1)
    ///   lookup at `by-target/{hex}` — *"not a scan"*. It is called from
    ///   **§6a.4**, the peer-issued resolve algorithm, and its argument is a
    ///   `registry`. That reader is [`crate::peer_issued::resolve_one`], and it
    ///   has been the keyed form since `a23bb27`, write side included.
    /// - **§3.1** is this reader, and it is a *different* rule: *"`:resolve`
    ///   MUST check for a `system/registry/revocation` targeting a candidate
    ///   binding before returning `resolved`"* — over any candidate from any
    ///   backend, with **no storage path constrained and no index mandated**.
    ///   The cohort convention here is own-hash-keyed, and conformance drives
    ///   it directly: `registry.v6_meta_resolver_revocation_honored` writes the
    ///   revocation at the own-hash path with `tree-put` — never through
    ///   `revoke-request` — and requires exclusion. An index-only reader is
    ///   **non-conformant**, which is how this was caught: index-only FAILed
    ///   `v6` on the armed gate, against a peer whose in-tree suite was green.
    ///
    /// **So R-4 is not closed here, and it is reported as mis-scoped rather
    /// than deferred** — with the measurement, in `docs/SPEC-AMBIGUITIES.md`:
    ///
    /// - `entity-core-go`'s meta-resolver (`ext/registry/registry.go`
    ///   `revocationFor`) **scans the same prefix**, so the seat the item calls
    ///   conformant is in the same state at this layer. The comparison behind
    ///   R-4 read go's §6a reader against our §3.1 reader.
    /// - An **index-first fast path is not a distinguishable behaviour** here,
    ///   which is why one is not shipped: `by-target/{hex}` sits *inside*
    ///   `revocation_prefix`, so every revocation the keyed lookup finds, the
    ///   scan finds too. Deleting such a branch fails no test — a branch that
    ///   reads as covered and cannot fail is worse than its absence
    ///   (`revocation_by_target_is_inside_the_scanned_prefix` pins the
    ///   containment that makes this true).
    /// - The scaling argument lands on §6a, not here: this walks the **local**
    ///   peer's own revocations — bounded by what this peer itself revoked —
    ///   while §6a.6's index governs a **remote registry's** subtree, which is
    ///   the internet-scale case, and is where we are already keyed.
    ///
    /// Closing it at this layer needs §3.1 to mandate an index at the *write*
    /// side, which is arch's to state and not ours to invent.
    ///
    /// A local-name binding is excluded on presence of any type-valid
    /// revocation: the local store is itself the trust source (§6.3 carve-out,
    /// same as the local-name binding), so an unsigned local revocation
    /// suffices. Signed kinds go through [`crate::peer_issued::resolve_one`],
    /// which additionally requires a `K_registry` signature — and there the
    /// index KEY is host-served and proves nothing, so the signed body's
    /// `revokes` is re-checked. A scan cannot be misfiled: it matches on
    /// `revokes` by construction.
    fn is_revoked(&self, binding_hash: Hash) -> bool {
        self.location_index
            .list(&crate::revocation_prefix(&self.peer_id))
            .into_iter()
            .any(|entry| {
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
            "set-resolver-config" => Ok(self.handle_set_resolver_config(ctx)),
            "get-resolver-config" => Ok(self.handle_get_resolver_config()),
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
        &[
            "resolve",
            "invalidate-cache",
            "set-resolver-config",
            "get-resolver-config",
        ]
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

    /// `set-resolver-config` (§4.3 `[v1.18]`).
    ///
    /// **The operation exists because the write-time MUST had nowhere to
    /// bind.** `system/capability/registry-configure` named an act the corpus
    /// never defined — a bare tree-write against
    /// `system/registry/resolver-config` — and *"a raw tree write cannot
    /// refuse selectively and cannot carry an acknowledgement"*. Same shape,
    /// and for the same reason, as §6a.9.2's `set-issuer-policy`.
    ///
    /// Three properties the spec states and this function holds:
    ///
    /// - **Whole-config validation before storing `[MUST]`**, not the delta:
    ///   §4.1 step 2 binds the configuration as a whole, which is also what
    ///   closes the "silent arming" hole under *either* scoping reading —
    ///   adding a chain entry later is itself a write this check evaluates.
    /// - **No partial application `[MUST]`**: a refusal returns before the
    ///   store touch, so a following `get-resolver-config` returns the
    ///   previous bytes unchanged.
    /// - **Byte-exact round-trip**: the submitted config entity is stored
    ///   *verbatim* and returned as the result. Re-encoding through
    ///   [`ResolverConfigData::to_entity`] would author a second entity with
    ///   the same fields and a different identity — the fields we do not model
    ///   (a forward-compat key, `hints` we do not read) would silently vanish
    ///   with it.
    fn handle_set_resolver_config(&self, ctx: &HandlerContext) -> HandlerResult {
        if ctx.params.entity_type != entity_types::TYPE_REGISTRY_SET_RESOLVER_CONFIG_REQUEST {
            return error(
                STATUS_BAD_REQUEST,
                "invalid_params",
                &format!(
                    "set-resolver-config expects a {} entity, got {}",
                    entity_types::TYPE_REGISTRY_SET_RESOLVER_CONFIG_REQUEST,
                    ctx.params.entity_type
                ),
            );
        }
        // The nested `config` is a real entity wrapper, so it is lifted from
        // the params' RAW bytes — never decoded to a `Value` and re-encoded,
        // which is what would move its content hash out from under the
        // byte-exact round-trip the operation promises.
        let Some(raw) = entity_wire::cbor_map_field_raw(&ctx.params.data, "config") else {
            return error(
                STATUS_BAD_REQUEST,
                "invalid_params",
                "set-resolver-config requires a `config` field carrying the \
                 system/registry/resolver-config entity",
            );
        };
        let config_entity = match entity_wire::decode_entity(raw) {
            Ok(e) => e,
            Err(e) => {
                return error(
                    STATUS_BAD_REQUEST,
                    "invalid_params",
                    &format!("decode config entity: {}", e),
                )
            }
        };
        if config_entity.entity_type != entity_types::TYPE_REGISTRY_RESOLVER_CONFIG {
            return error(
                STATUS_BAD_REQUEST,
                "invalid_params",
                &format!(
                    "config MUST be a {} entity, got {}",
                    entity_types::TYPE_REGISTRY_RESOLVER_CONFIG,
                    config_entity.entity_type
                ),
            );
        }
        // V7 §1.8 validate-on-receipt. The envelope layer validates the
        // *params* entity; a nested entity inside its `data` is opaque bytes
        // to it, so this is the only place the claim is checked. Our
        // `ContentStore::put` keys on the CLAIMED hash, so a lying
        // `content_hash` would file the bytes under one key while the location
        // index points at another — a `get-resolver-config` that 404s on a
        // config that was just accepted. (`entity-core-go` is covered here by
        // its store, which recomputes at `Put`; ours does not.)
        if let Err(e) = config_entity.validate() {
            return error(
                STATUS_BAD_REQUEST,
                "invalid_params",
                &format!(
                    "config content_hash does not match its bytes (V7 §1.8): {}",
                    e
                ),
            );
        }
        let config = match ResolverConfigData::from_entity(&config_entity) {
            Ok(c) => c,
            Err(e) => {
                return error(
                    STATUS_BAD_REQUEST,
                    "invalid_params",
                    &format!("decode resolver-config: {}", e),
                )
            }
        };

        // §4.3 `[MUST]` — `acknowledge_name_disclosure` is the operator MAY,
        // made expressible, and it is read from the OPERATION's params. It is
        // never read from the config entity: a field there is written by
        // whoever writes the bytes, so a distribution could set it and defeat
        // the rule it is meant to bound.
        let acknowledged = decode_map(&ctx.params.data)
            .ok()
            .and_then(|m| match get_field(&m, "acknowledge_name_disclosure") {
                Some(ciborium::Value::Bool(b)) => Some(*b),
                _ => None,
            })
            .unwrap_or(false);

        let violations = disclosure_violations(&config);
        if !violations.is_empty() && !acknowledged {
            return error(
                STATUS_FORBIDDEN,
                "policy_rejected",
                &format!(
                    "this resolver-config would make a name-transmitting backend eligible for \
                     unscoped names (§4.1 step 2) — every bare name a user types, including a \
                     private handle or a typo, would go to a third party. Set \
                     acknowledge_name_disclosure to store it deliberately on your own peer. \
                     Violations: {}",
                    violations.join("; ")
                ),
            );
        }

        let hash = config_entity.content_hash;
        if let Err(e) = self.content_store.put(config_entity.clone()) {
            return error(STATUS_BAD_REQUEST, "store_failed", &e.to_string());
        }
        self.location_index
            .set(&resolver_config_path(&self.peer_id), hash);
        entity_result(config_entity)
    }

    /// `get-resolver-config` (§4.3) — the stored config as written, or `404
    /// not_found` when unset.
    ///
    /// It MUST NOT synthesize [`Self::default_local_name_only`]: that default
    /// is what `meta_resolve` *runs* with no config, not what an operator
    /// *wrote*, and returning it here would report a configuration that does
    /// not exist — the same reason `get-issuer-policy` refuses to synthesize
    /// an `open` mode (§6a.9.2: unset is not a mode).
    fn handle_get_resolver_config(&self) -> HandlerResult {
        match self
            .location_index
            .get(&resolver_config_path(&self.peer_id))
            .and_then(|h| self.content_store.get(&h))
        {
            Some(e) => entity_result(e),
            None => error(
                STATUS_NOT_FOUND,
                "not_found",
                "no resolver-config is stored (§4.3) — the meta-resolver runs its \
                 local-name-only default, which is not a stored configuration",
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// §4.1 step 2 — the name-disclosure MUST `[MUST, v1.14 / v1.17 / v1.18]`
// ---------------------------------------------------------------------------

/// The four kinds §4.1 step 2 **declares** name-transmitting: consultation
/// *is* disclosure — the name goes to a third party as a query, a path
/// segment, or a document name.
///
/// **The set is closed, and an undeclared kind is NOT transmitting `[MUST,
/// v1.14]`** (§4.2). Refusing a config because a broad rule names a kind this
/// build does not recognize would reject a deployment authored against a
/// *newer* vocabulary — the case §4.2 exists to permit. The forward risk (a
/// kind that becomes transmitting tomorrow) is discharged by *when* the check
/// runs, not by guessing here: [`RegistryHandler::load_config`] re-classifies
/// the same stored config on every load, so an entry that was inert surfaces
/// at the moment it stops being.
///
/// The safe kinds are safe for two different reasons and neither is
/// remoteness: `local-name` / `self-certifying` / `out-of-band` consult no
/// network at all, and `peer-issued` is content-addressed and name-blind —
/// §6a.4 requires the name to be matched *inside* an already-fetched signed
/// node, so it never appears in a request.
pub fn is_name_transmitting_kind(kind: &str) -> bool {
    matches!(
        kind,
        BACKEND_KIND_DNS_TXT
            | BACKEND_KIND_WELL_KNOWN_URL
            | BACKEND_KIND_DID_WEB
            | BACKEND_KIND_CONSENSUS_ANCHORED
    )
}

/// Whether a dispatch pattern can match an **unscoped** name — a bare name a
/// user types with no authority stated (contrast the scoped `alice@example.org`,
/// which §4.1 calls *"the user stating which authority they are willing to
/// tell"*).
///
/// **The §4.1a recommended default list is the fixture that pins this, and it
/// is the spec's own text rather than an external glob convention.** A
/// distribution SHOULD ship that list and the catch-all MUST lives inside it,
/// so every non-catch-all row must classify **narrow** or the recommended list
/// would violate its own MUST. Row 3 is the decisive one: `*.eth` names
/// `consensus-anchored`, a *transmitting* kind, so a classifier that calls
/// `*.eth` broad refuses the very list §4.1a recommends. Rows 1–2 (`did:web:*`,
/// `did:key:*`) and rows 4–5 (`*@*.*`, `*@*`) give the other two markers.
/// Hence three scope markers, and nothing else:
///
/// - an `@` anywhere — the user names an authority (rows 4, 5);
/// - a `:` anywhere — a scheme-typed prefix (rows 1, 2);
/// - `*.<literal>` with no further `*` — a dotted literal suffix (row 3).
///
/// Everything else is **broad**: the catch-all `*`, a bare prefix `a*`, and
/// `*.*` — whose suffix is a star, not a literal, so it matches `alice.bob`
/// as readily as a domain. The asymmetry §4.1 draws settles the doubt: a false
/// "broad" refuses a presently-harmless config and the operator edits one row,
/// while a false "narrow" discloses every bare name a user types, silently and
/// irreversibly.
///
/// **This is a pure function of the pattern text — no `resolver_chain` input.**
/// That is what "kind-scoped" means (§4.1 `[MUST, v1.17/v1.18]`): a reviewed
/// artifact stays reviewed, because its validity cannot be changed by what a
/// downstream operator later adds to a chain the shipper will never see.
///
/// **`REG-DISPATCH-CONFIG-REFUSED-1` only exercises two of the shapes** (`*`
/// broad, `did:web:*` narrow), so the boundary between them is in-tree
/// agreement, not wire-verified convergence. The spec defines "unscoped" by
/// example rather than by grammar; filed in `docs/SPEC-AMBIGUITIES.md`.
pub fn pattern_matches_unscoped_name(pattern: &str) -> bool {
    if pattern.contains('@') || pattern.contains(':') {
        return false;
    }
    if let Some(rest) = pattern.strip_prefix("*.") {
        if !rest.is_empty() && !rest.contains('*') {
            return false;
        }
    }
    true
}

/// Every way a resolver-config makes a name-transmitting backend eligible for
/// an unscoped name — §4.1 step 2's `[MUST, v1.14]`, *"stated at the width of
/// the invariant, not of the instance"*.
///
/// **Two doors, because binding only the catch-all row made the rule evadable
/// by not writing that row:**
///
/// 1. any rule whose pattern matches unscoped names naming a transmitting
///    kind — the catch-all `*` is the usual one; and
/// 2. an **absent or empty** `name_format_dispatch` while a transmitting kind
///    sits in the chain — the filter is disabled, every kind is eligible, and
///    there is no catch-all row to inspect.
///
/// A third door — leaving a transmitting kind out of every rule so it
/// "defaults to match all" — is closed **by construction** by the union rule
/// (`meta_resolve` step 2): a kind named nowhere is eligible nowhere. It needs
/// no clause here, and adding one would re-introduce the per-backend reading
/// §4.1's own erratum withdrew.
///
/// **Door 1 is kind-scoped: it does not read `resolver_chain` at all.** Every
/// violation is returned, never just the first — *"an operator repairing a
/// chain wants the whole list"*.
pub fn disclosure_violations(config: &ResolverConfigData) -> Vec<String> {
    // Door 2 — the filter is disabled, so every kind in the chain is eligible
    // for every name. This door DOES read the chain, and must: with no rules
    // there is nothing else to read, and the disclosure is real rather than
    // hypothetical.
    if config.name_format_dispatch.is_empty() {
        return config
            .resolver_chain
            .iter()
            .filter(|e| is_name_transmitting_kind(&e.backend_kind))
            .map(|e| {
                format!(
                    "no name_format_dispatch, so the filter is disabled and {:?} in the \
                     resolver_chain is eligible for every unscoped name",
                    e.backend_kind
                )
            })
            .collect();
    }
    // Door 1 — a broad rule names a transmitting kind, chain or no chain.
    let mut out = Vec::new();
    for rule in &config.name_format_dispatch {
        if !pattern_matches_unscoped_name(&rule.pattern) {
            continue;
        }
        for kind in &rule.backend_kinds {
            if is_name_transmitting_kind(kind) {
                out.push(format!(
                    "dispatch pattern {:?} matches unscoped names and names transmitting \
                     backend kind {:?}",
                    rule.pattern, kind
                ));
            }
        }
    }
    out
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
