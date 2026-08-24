//! Peer-issued live registration (EXTENSION-REGISTRY §6a.9).
//!
//! Curated registration (§6a.8) is the operator signing bindings by hand
//! ([`crate::peer_issued`] reads + verifies them). **Live** registration lets a
//! *publisher* self-register against a registry that runs this handler. A
//! registry is just a peer (§1 position 4); running `system/registry/peer-issued`
//! is what makes it a *live* registry rather than a curated/static one.
//!
//! The handler serves three registration ops:
//! - `register-request` — admit (or queue/reject) a publisher's self-signed
//!   claim, then sign + publish the binding with `K_registry` (§6a.8 act).
//! - `revoke-request` — emit a registry-signed §3.1 revocation.
//! - `renew-request` — issue a successor binding (supersedes-chain) with a new
//!   TTL.
//!
//! …and two policy-management ops (§6a.9.2 `[RATIFIED 2026-08-10]`):
//! - `set-issuer-policy` — replace the stored policy whole.
//! - `get-issuer-policy` — read it back, or `404` when unset.
//!
//! Those two are **operator** surface, gated by
//! `system/capability/registry-manage-issuer-policy` and never reachable
//! through the `registry-request-binding` a publisher holds — otherwise a
//! publisher the policy admits could rewrite the policy admitting it. Before
//! §6a.9.2 that capability named an act the corpus never defined, so a client
//! written against the spec had nothing to call, and each impl armed the
//! policy its own out-of-band way.
//!
//! **The policy is resolved store-first and store-only** (§6a.9.2 `[MUST]`).
//! There is no in-memory fallback and no CLI flag consulted at request time;
//! out-of-band arming, if it is ever added, must *seed the entity* rather than
//! shadow it — otherwise a conformance run cannot drive all three modes
//! against a single peer by writing that entity, and `get-issuer-policy` would
//! report `not_found` on a registry demonstrably running a mode.
//!
//! Two proof layers gate registration (§6a.9.1):
//! - **Layer 1 — peer-id control (always):** the request carries a
//!   `system/signature` by `target_peer_id` over the request's `content_hash`
//!   (V7 §5.2). This proves the requester holds the key they are binding the
//!   name to — no one can register *someone else's* peer-id.
//! - **Layer 2 — name entitlement (policy):** the registry-local
//!   [`IssuerPolicyData`] mode (`open` / `allowlist` / `manual`) decides whether
//!   *this* requester may have *this* name. `domain-control` is DEFERRED (§6a.10).
//!
//! **Layer 1 binds all three write ops** (§6a.9 `[RULED 2026-08-11]`), via
//! [`RegisterRequestHandler::require_layer1`] — for `revoke`/`renew` against the
//! `target_peer_id` of the binding named by `binding_hash`, before any state
//! change and before any publication. Layer 2 gates `register` alone: revoke and
//! renew act on an *existing* binding the registry already chose to issue, so
//! there is no fresh entitlement question to ask.
//!
//! Replay defense: a per-requester seen-`nonce` marker plus an `issued_at`
//! freshness window (§6a.9), bound to `register` and `renew` by the §6a.9
//! discriminator — replay of either has a non-idempotent state effect, while
//! `revoke` is monotonic on a content-addressed target. Ed25519-only,
//! consistent with the resolve-side pin (spec-problems **P5**).

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use entity_crypto::{IdentityKeypair, Keypair, PeerId};
use entity_ecf::{text, Value};
use entity_handler::{
    Handler, HandlerContext, HandlerError, HandlerResult, STATUS_ACCEPTED, STATUS_AUTH_FAILED,
    STATUS_BAD_REQUEST, STATUS_CONFLICT, STATUS_FORBIDDEN, STATUS_NOT_FOUND, STATUS_NOT_SUPPORTED,
};
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};
use entity_types::{SignatureData, TYPE_REGISTRY_BINDING};

use crate::data::{
    decode_map, get_field, normalize_name, validate_name_safety, BindingData, IssuerPolicyData,
    PendingBindingData, RegisterRequestData, RevocationData, KIND_PEER_ISSUED, MODE_ALLOWLIST,
    MODE_DOMAIN_CONTROL, MODE_MANUAL, MODE_OPEN, PENDING_STATUS_APPROVED, PENDING_STATUS_DENIED,
    STATUS_BOUND, STATUS_PENDING_REVIEW,
};
use crate::log::now_ms;
use crate::resolver::{find_binding_signature, peer_pubkey_from_entity};
use crate::result::{entity_result, error, hash_result, register_result, status_result};
use crate::{
    binding_body_path, by_name_pointer_path, issuer_policy_path, pending_body_path,
    pending_by_request_path, pending_by_request_prefix, register_nonce_path,
    revocation_by_target_path, revocation_prefix, signature_pointer_path,
};

/// Layer-1 rejection code (§6a.9 ratified status table). **Normative** — this
/// is what a peer branches on; the accompanying message text is impl-local and
/// no conformance check may assert on it. rust previously answered
/// `invalid_signature`, which no longer matches the table.
const REG_ERR_SIGNATURE_INVALID: &str = "signature_invalid";

/// Reject a request whose `issued_at` is older than this (replay-window floor).
const REGISTER_STALE_AFTER_MS: u64 = 600_000; // 10 min
/// Tolerate this much clock skew on a future-dated `issued_at`.
const REGISTER_FUTURE_SKEW_MS: u64 = 120_000; // 2 min

/// `system/registry/peer-issued` handler — the live-registration surface.
pub struct RegisterRequestHandler {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    peer_id: String,
    signer: IdentityKeypair,
    qualified_pattern: String,
    /// §6a.9.3 retention `[SHOULD]` — ms after `queued_at` before a **decided**
    /// head's pointer is collected. `0` disables. A deployment knob (§7: "all
    /// retention windows are operator-configurable"), not a wire field.
    pending_retention_ms: u64,
}

/// Default §6a.9.3 retention window for decided pending-bindings: 30 days.
/// Conservative per §7's "defaults conservative (unlimited / off / largest)" —
/// long enough that an operator's audit trail outlives any plausible dispute.
pub const DEFAULT_PENDING_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1000;

impl RegisterRequestHandler {
    /// `local_peer_id` is the registry's own peer-id; `signer` is `K_registry`
    /// (the local identity), held in-process to sign issued bindings — the
    /// operator's own peer signing its own bindings, never exported.
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
        signer: IdentityKeypair,
    ) -> Self {
        let qualified_pattern = format!("/{}/system/registry/peer-issued", local_peer_id);
        Self {
            content_store,
            location_index,
            peer_id: local_peer_id,
            signer,
            qualified_pattern,
            pending_retention_ms: DEFAULT_PENDING_RETENTION_MS,
        }
    }

    /// Override the §6a.9.3 retention window (ms). `0` disables collection.
    pub fn with_pending_retention(mut self, ms: u64) -> Self {
        self.pending_retention_ms = ms;
        self
    }

    /// §6a.9.3 retention `[SHOULD]` — collect the pointers of **decided** heads
    /// once the window has elapsed since `queued_at`.
    ///
    /// A `pending_review` head is **never** eligible: it is live queue state,
    /// and expiring it would silently drop a request no operator has seen —
    /// the same deliver-or-signal violation that deny-is-not-a-delete forbids.
    ///
    /// **Only the pointer is removed.** The body stays content-addressed and
    /// auditable independently of the pointer, exactly as the ruling specifies.
    ///
    /// Opportunistic rather than timer-driven: it runs on the queue path, so
    /// the sweep is bounded by the traffic that creates the entries it
    /// collects, and a registry with no traffic has no queue to leak. No task,
    /// no background clock.
    fn gc_decided_pending(&self) {
        if self.pending_retention_ms == 0 {
            return;
        }
        let now = now_ms();
        for entry in self
            .location_index
            .list(&pending_by_request_prefix(&self.peer_id))
        {
            let Some(entity) = self.content_store.get(&entry.hash) else {
                continue;
            };
            let Ok(pending) = PendingBindingData::from_entity(&entity) else {
                continue;
            };
            if !pending.is_decided() {
                continue;
            }
            if now < pending.queued_at || now - pending.queued_at < self.pending_retention_ms {
                continue;
            }
            self.location_index.remove(&entry.path);
        }
    }

    /// Read the issuer-policy from the local tree. **The store is the only
    /// source** — §6a.9.2 makes resolution order store-first `[MUST]` and
    /// bars any parallel source at request time (out-of-band arming is "a
    /// seed for that entity, never a parallel source consulted at request
    /// time"). That order is load-bearing beyond tidiness: it is what lets
    /// a conformance run drive all three modes against a *single* peer by
    /// writing the entity.
    ///
    /// `None` means **unarmed**, and callers MUST NOT substitute a default.
    /// "Unset is not a mode" (§6a.9.2): a registry with no policy entity is
    /// a conformant curated-only registry (§6a.8), not an implicitly-`open`
    /// or implicitly-`manual` one. A decode failure is also `None` — a
    /// policy we cannot read is not a policy we may guess at.
    fn load_policy(&self) -> Option<IssuerPolicyData> {
        self.location_index
            .get(&issuer_policy_path(&self.peer_id))
            .and_then(|h| self.content_store.get(&h))
            .and_then(|e| IssuerPolicyData::from_entity(&e).ok())
    }
}

/// The answer the live-registration surface gives when no policy entity is
/// stored. §6a.9.2: with no policy the registry "does not run live
/// registration at all (§6a.9's handler is unregistered) — it is a
/// conformant curated-only registry per §6a.8."
///
/// We register the handler unconditionally (it is wired at build time,
/// before there is a store to consult), so the closest conformant behaviour
/// available is to answer as though the handler were absent: 404. The
/// distinction is invisible to a client, which is the point.
fn curated_only(op: &str) -> HandlerResult {
    error(
        STATUS_NOT_FOUND,
        "not_found",
        &format!(
            "no issuer-policy is stored — this registry is curated-only (§6a.8) and does not \
             serve {}. Arm it with set-issuer-policy (§6a.9.2)",
            op
        ),
    )
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for RegisterRequestHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        match ctx.operation.as_str() {
            "register-request" => Ok(self.handle_register(ctx)),
            "revoke-request" => Ok(self.handle_revoke(ctx)),
            "renew-request" => Ok(self.handle_renew(ctx)),
            "approve-request" => Ok(self.handle_approve(ctx)),
            "deny-request" => Ok(self.handle_deny(ctx)),
            "set-issuer-policy" => Ok(self.handle_set_issuer_policy(ctx)),
            "get-issuer-policy" => Ok(self.handle_get_issuer_policy()),
            other => Ok(error(
                STATUS_BAD_REQUEST,
                "unknown_operation",
                &format!("unknown peer-issued op: {}", other),
            )),
        }
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "registry-peer-issued"
    }

    fn operations(&self) -> &[&str] {
        &[
            "register-request",
            "revoke-request",
            "renew-request",
            // §6a.9.3 `[RULED 2026-08-13]`. The operator's decisions on the
            // manual queue, both gated by the EXISTING
            // `system/capability/registry-issue-binding` — approving a queued
            // request *is* issuing a binding, so the section defines no new
            // capability and this handler invents none.
            "approve-request",
            "deny-request",
            // §6a.9.2 `[RATIFIED 2026-08-10]`. Operator surface, gated by
            // `system/capability/registry-manage-issuer-policy` — never
            // reachable from the `registry-request-binding` a publisher
            // holds, or a publisher admitted by the policy could rewrite
            // the policy that admits it.
            "set-issuer-policy",
            "get-issuer-policy",
        ]
    }
}

impl RegisterRequestHandler {
    // -------------------------------------------------------------------
    // §6a.9 :register-request
    // -------------------------------------------------------------------
    fn handle_register(&self, ctx: &HandlerContext) -> HandlerResult {
        // `ctx.params` IS the register-request entity; its content_hash is what
        // the requester signed (layer-1).
        let req = match RegisterRequestData::from_entity(&ctx.params) {
            Ok(r) => r,
            Err(e) => return error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string()),
        };
        let request_hash = ctx.params.content_hash;

        // §6.3 name-path safety (NFC, no '/', no control chars).
        if let Err(reason) = validate_name_safety(&req.name) {
            return error(STATUS_BAD_REQUEST, "bind_invalid_name", &reason);
        }

        // Layer 1 — peer-id control: a system/signature by `target_peer_id` over
        // the request hash (REG-REGISTER-PROOF-1). Always required.
        // 401, not 403 — layer-1 is an *authentication* result, now pinned by
        // the ratified status table along with the `signature_invalid` code.
        if let Some(rejection) =
            self.require_layer1(&request_hash, &req.target_peer_id, &ctx.included)
        {
            return rejection;
        }

        // Replay defense — freshness window + per-requester seen-nonce
        // (REG-REGISTER-REPLAY-1).
        if let Some(rejection) = self.check_replay(&req.target_peer_id, &req.nonce, req.issued_at) {
            return rejection;
        }
        let nonce_path = register_nonce_path(&self.peer_id, &req.target_peer_id, &req.nonce);

        // Layer 2 — issuer-policy admission (§6a.9.1). Store-only, and an
        // unarmed registry does not run this surface at all (§6a.9.2).
        let policy = match self.load_policy() {
            Some(p) => p,
            None => return curated_only("register-request"),
        };
        // name_constraints bounds which names the registry will issue, in any mode.
        if let Some(glob) = &policy.name_constraints {
            if !name_constraints_match(glob, &req.name) {
                return error(
                    STATUS_FORBIDDEN,
                    "not_entitled",
                    "name outside the registry's name_constraints",
                );
            }
        }
        let norm = normalize_name(&req.name, "none");

        // D12 — the backstop for D11 (below, at `set-issuer-policy`).
        //
        // D11 refuses a null-`default_ttl` policy at the door, but §6a.9.2's
        // store-first rule means such a policy is still reachable: seeded by a
        // CLI flag, written directly to the tree, or predating the rule. So the
        // resolved ttl is re-checked here, BEFORE both the manual-queue and the
        // direct-issue arms — queueing a request that can only ever mint an
        // invalid binding just moves the failure to the operator's approval.
        //
        // Refuse rather than substitute an implementation-chosen default: that
        // is §6a.9.2's default-synthesis mistake applied to a security-relevant
        // field, and it would let two registries answer identically-stored
        // policies with different binding lifetimes — a determinism split the
        // operator never sees. Minting is not an option either: the result is a
        // null-ttl binding, which D3 now makes unresolvable.
        //
        // The clamp (§6a.9.1 `[MUST, v1.11]`) rides the same expression:
        // resolve through the cascade, then `min(resolved, policy.max_ttl)`.
        // A request above the ceiling is **CLAMPED, not refused** — refusing
        // would bill a well-formed request for a policy the requester cannot
        // read (§6a.9.2's own reason for not gating the requester) and would
        // teach requesters to probe for the ceiling. The clamp is silent by
        // design: the issued binding carries the clamped value, which is
        // signed, published and readable.
        let resolved_ttl = clamp_to_ceiling(req.requested_ttl.or(policy.default_ttl), &policy);
        if resolved_ttl.is_none() {
            return error(
                STATUS_FORBIDDEN,
                "policy_rejected",
                "resolved ttl is null: the request omitted requested_ttl and the issuer \
                 policy defines no default_ttl. Refusing rather than minting a null-ttl \
                 binding (unresolvable per CAP registry D3) or substituting an \
                 implementation-chosen default (CAP registry D12). Set default_ttl on \
                 the issuer policy.",
            );
        }

        match policy.mode.as_str() {
            MODE_OPEN => {
                // First-come-first-serve: only the name-taken check gates.
                if self
                    .location_index
                    .get(&by_name_pointer_path(&self.peer_id, &norm))
                    .is_some()
                {
                    return error(STATUS_CONFLICT, "name_taken", "name already bound");
                }
            }
            MODE_ALLOWLIST => {
                let allowed = policy
                    .allowlist
                    .as_ref()
                    .map(|a| a.iter().any(|p| p == &req.target_peer_id))
                    .unwrap_or(false);
                if !allowed {
                    return error(
                        STATUS_FORBIDDEN,
                        "not_entitled",
                        "target_peer_id not in the registry allowlist",
                    );
                }
                if self
                    .location_index
                    .get(&by_name_pointer_path(&self.peer_id, &norm))
                    .is_some()
                {
                    return error(STATUS_CONFLICT, "name_taken", "name already bound");
                }
            }
            MODE_MANUAL => {
                // Queue for out-of-band operator approval. Record the nonce so a
                // resubmission of the *same* request can't double-queue; the
                // pending request body is content-addressable for review.
                self.location_index.set(&nonce_path, request_hash);
                // §6a.9.3 — store the queued request as a `pending-binding` and
                // return a handle that names IT, never the request. A hash the
                // client computed before it dispatched is not a handle.
                //
                // Supersession: one head per (target_peer_id, name). A retry
                // carries a fresh nonce and is a distinct request by
                // construction, so without replace-whole an operator's queue
                // fills with duplicates of a single intent. The superseded body
                // stays at its own content-addressed path — only the pointer
                // moves.
                let pending = PendingBindingData::queued(&req, &norm, now_ms());
                let pending_hash = match self.store_pending(&pending) {
                    Ok(h) => h,
                    Err(result) => return result,
                };
                self.location_index.set(
                    &pending_by_request_path(&self.peer_id, &req.target_peer_id, &norm),
                    pending_hash,
                );
                self.gc_decided_pending();
                // 202 in `system/registry/register-result` — §6a.9 `[RULED
                // 2026-08-12]`. The status is a result FIELD on a success shape,
                // not a code on an error entity, and the type is
                // register-request's own.
                return register_result(
                    STATUS_ACCEPTED,
                    vec![
                        (text("status"), text(STATUS_PENDING_REVIEW)),
                        (
                            text("pending_hash"),
                            Value::Bytes(pending_hash.to_bytes().to_vec()),
                        ),
                    ],
                );
            }
            MODE_DOMAIN_CONTROL => {
                // DEFERRED — the DNS-proof challenge format co-designs with the
                // web-native dns-txt / well_known_url backends (§6a.10).
                return error(
                    STATUS_NOT_SUPPORTED,
                    "unsupported_mode",
                    "domain-control registration is not yet implemented",
                );
            }
            other => {
                return error(
                    STATUS_BAD_REQUEST,
                    "unknown_policy_mode",
                    &format!("unknown issuer-policy mode: {}", other),
                );
            }
        }

        // Approved — record the nonce, then sign + publish (the §6a.8 act).
        self.location_index.set(&nonce_path, request_hash);
        // Non-null by the D12 guard above.
        let ttl = resolved_ttl;
        match self.issue_binding(&norm, &req.target_peer_id, req.transports, ttl, None) {
            // §6a.9 step 3 `[RULED 2026-08-12]`: `{status: "bound", binding_hash}`
            // in register-request's own result type. Previously a bare
            // `{binding_hash}` under `system/protocol/status`, which left the
            // discriminator the ruling turns on absent from the success branch.
            Ok(binding_hash) => register_result(
                entity_handler::STATUS_OK,
                vec![
                    (text("status"), text(STATUS_BOUND)),
                    (
                        text("binding_hash"),
                        Value::Bytes(binding_hash.to_bytes().to_vec()),
                    ),
                ],
            ),
            Err(result) => result,
        }
    }

    // -------------------------------------------------------------------
    // §6a.9 :revoke-request — registry-signed §3.1 revocation
    // -------------------------------------------------------------------
    fn handle_revoke(&self, ctx: &HandlerContext) -> HandlerResult {
        let map = match decode_map(&ctx.params.data) {
            Ok(m) => m,
            Err(e) => return error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string()),
        };
        let binding_hash = match get_field(&map, "binding_hash")
            .and_then(|v| v.as_bytes())
            .and_then(|b| Hash::from_bytes(b).ok())
        {
            Some(h) => h,
            None => {
                return error(
                    STATUS_BAD_REQUEST,
                    "invalid_params",
                    "binding_hash required",
                )
            }
        };
        let reason = get_field(&map, "reason")
            .and_then(|v| v.as_text())
            .map(|s| s.to_string());

        // Layer 1 (§6a.9 `[RULED 2026-08-11]`) — signed by the *binding's*
        // `target_peer_id`, before any state change and before any publication.
        // This verified NOTHING: any peer that could reach the registry could
        // revoke any binding in it, and revocation is monotonic, so there was
        // no undo. Found because core-py declined to converge and reported.
        //
        // "Or the operator" is ruled local-only — the corpus defines no
        // operator key and no request field one could populate, so the wire
        // surface accepts `target_peer_id` proof exclusively. An operator
        // revokes by acting on its own registry directly.
        let binding = match self.load_binding(&binding_hash) {
            Ok(b) => b,
            Err(result) => return result,
        };
        if let Some(rejection) = self.require_layer1(
            &ctx.params.content_hash,
            &binding.target_peer_id,
            &ctx.included,
        ) {
            return rejection;
        }

        let rev = RevocationData {
            revokes: binding_hash,
            revoked_at: now_ms(),
            reason,
        };
        let rev_entity = match rev.to_entity() {
            Ok(e) => e,
            Err(e) => return error(STATUS_BAD_REQUEST, "encode_failed", &e.to_string()),
        };
        let rev_hash = rev_entity.content_hash;
        if let Err(e) = self.content_store.put(rev_entity) {
            return error(STATUS_BAD_REQUEST, "store_failed", &e.to_string());
        }
        // Registry-signed (peer-issued revocations MUST verify against K_registry,
        // §2.3 / §6a.6) at the invariant-pointer over the revocation's own hash.
        if let Err(result) = self.sign_and_publish(&rev_hash) {
            return result;
        }
        // Own-hash-keyed pointer (the resolve-side scan reads this) + the §6a.6
        // by-target index.
        self.location_index.set(
            &format!("{}{}", revocation_prefix(&self.peer_id), rev_hash.to_hex()),
            rev_hash,
        );
        self.location_index.set(
            &revocation_by_target_path(&self.peer_id, &binding_hash),
            rev_hash,
        );
        status_result(vec![
            (text("revoked"), Value::Bool(true)),
            (
                text("revocation"),
                Value::Bytes(rev_hash.to_bytes().to_vec()),
            ),
        ])
    }

    // -------------------------------------------------------------------
    // §6a.9 :renew-request — successor binding (supersedes-chain), new TTL
    // -------------------------------------------------------------------
    fn handle_renew(&self, ctx: &HandlerContext) -> HandlerResult {
        let map = match decode_map(&ctx.params.data) {
            Ok(m) => m,
            Err(e) => return error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string()),
        };
        let binding_hash = match get_field(&map, "binding_hash")
            .and_then(|v| v.as_bytes())
            .and_then(|b| Hash::from_bytes(b).ok())
        {
            Some(h) => h,
            None => {
                return error(
                    STATUS_BAD_REQUEST,
                    "invalid_params",
                    "binding_hash required",
                )
            }
        };
        let new_ttl = get_field(&map, "ttl")
            .and_then(|v| v.as_integer())
            .and_then(|i| u64::try_from(i).ok());
        // `nonce` + `issued_at` are pinned into renew's schema (§6a.9): renew
        // has a non-idempotent state effect, so a captured one can be replayed
        // to keep a binding alive past the registrant's intended lapse.
        let nonce = match get_field(&map, "nonce").and_then(|v| v.as_bytes()) {
            Some(n) => n.to_vec(),
            None => return error(STATUS_BAD_REQUEST, "invalid_params", "nonce required"),
        };
        let issued_at = match get_field(&map, "issued_at")
            .and_then(|v| v.as_integer())
            .and_then(|i| u64::try_from(i).ok())
        {
            Some(t) => t,
            None => return error(STATUS_BAD_REQUEST, "invalid_params", "issued_at required"),
        };

        // Layer 1 before replay, and both before any state change (§6a.9
        // `[RULED 2026-08-11]`). Replay defense alone is not authorization: it
        // stopped a *captured* renew being re-run while leaving a *fresh
        // unsigned* one from any peer accepted. The nonce is keyed off the
        // binding's `target_peer_id`, so an unauthorized renew also burned the
        // real target's nonce space.
        let prev = match self.load_binding(&binding_hash) {
            Ok(p) => p,
            Err(result) => return result,
        };
        if let Some(rejection) = self.require_layer1(
            &ctx.params.content_hash,
            &prev.target_peer_id,
            &ctx.included,
        ) {
            return rejection;
        }
        if let Some(rejection) = self.check_replay(&prev.target_peer_id, &nonce, issued_at) {
            return rejection;
        }
        // §6a.9.1 `[MUST, v1.9/v1.10/v1.11]` — renew resolves its `ttl`
        // through a THREE-STEP cascade and never refuses for a missing one.
        //
        // Renew is a **second producer of peer-issued bindings** and the
        // null-`ttl` rules swept only `register-request`: a renew omitting
        // `ttl` against a policy with no `default_ttl` minted a null-`ttl`
        // successor, which §6a.3 forbids and §6a.4 will not honor. Steps, in
        // order:
        //
        //   1. the request's own `ttl`
        //   2. the issuer policy's `default_ttl` — current operator intent
        //      outranks history, so an operator who lowers it sees renewals
        //      pick it up. **This is why the order is not inherit-first.**
        //   3. the superseded binding's `ttl`
        //
        // Step 3 is *not* an implementation-chosen default, and that
        // distinction is the whole ruling: a synthesized number is one the
        // implementation invents, so two registries answer identically-stored
        // policies differently. The predecessor's `ttl` is **the registry's
        // own prior signed act on this exact name** — recovered, not chosen,
        // byte-identical at every conformant peer.
        //
        // Refusing at renew would be the wrong side by §6a.9.2's own
        // reasoning: at register the input is genuinely missing, at renew the
        // registry holds a valid `ttl` it issued itself. Refusing would revoke
        // a name by inaction, for a policy defect the registrant cannot see or
        // fix, on the one operation whose purpose is to keep the name alive.
        //
        // The policy is optional here on purpose. §6a.9.2's *"unset is not a
        // mode"* closes the **register** surface on an unarmed registry; a
        // curated registry (§6a.8) that issued a binding out-of-band can still
        // be asked to renew it, and step 3 answers that without a policy.
        let policy = self.load_policy();
        let cascaded = new_ttl
            .or_else(|| policy.as_ref().and_then(|p| p.default_ttl))
            .or(prev.ttl);

        // The cascade fails closed when the predecessor itself is invalid
        // `[MUST, v1.10]`. Step 3 is non-null *on every conformant mint path*,
        // which is not the same as non-null: a predecessor carrying
        // `ttl: null` can be already there — seeded out-of-band, written
        // straight to the tree, or predating these rules. **An unreachable
        // branch that is asserted rather than enforced is how the shape it
        // forbids gets minted**: guard the deref to avoid a panic, fall
        // through, and out comes the null-`ttl` binding the whole rule set
        // exists to prevent. So it is enforced, and it is unreachable on any
        // conformant path for exactly that reason.
        let Some(resolved) = cascaded else {
            return error(
                STATUS_FORBIDDEN,
                "policy_rejected",
                "renew ttl cascade yielded null at all three steps (request, issuer \
                 policy default_ttl, superseded binding) — the predecessor carries a \
                 null ttl, which §6a.3 forbids and no conformant path mints. Refusing \
                 and publishing nothing rather than minting a null-ttl successor or \
                 substituting a default (§6a.9.1 v1.10).",
            );
        };
        // …then the ceiling, as on the register path.
        let renew_ttl = policy
            .as_ref()
            .map_or(Some(resolved), |p| clamp_to_ceiling(Some(resolved), p));

        // Nonce recorded only once the request is going to be honored. The
        // v1.10 refusal MUST publish nothing, and burning the requester's
        // nonce on a refusal is a publication in the only sense that matters
        // to them: the retry that would succeed after the operator fixes the
        // policy comes back as a replay instead.
        self.location_index.set(
            &register_nonce_path(&self.peer_id, &prev.target_peer_id, &nonce),
            ctx.params.content_hash,
        );

        let norm = normalize_name(&prev.name, "none");
        match self.issue_binding(
            &norm,
            &prev.target_peer_id,
            prev.transports,
            renew_ttl,
            Some(binding_hash),
        ) {
            Ok(h) => hash_result("binding_hash", h),
            Err(result) => result,
        }
    }

    // -------------------------------------------------------------------
    // §6a.9.2 policy management — `set-issuer-policy` / `get-issuer-policy`
    // -------------------------------------------------------------------

    // -------------------------------------------------------------------
    // §6a.9.3 :approve-request / :deny-request — the operator decisions
    // -------------------------------------------------------------------

    /// `approve-request` (§6a.9.3) — issue the queued binding, then record the
    /// decision.
    ///
    /// Gated by the **existing** `system/capability/registry-issue-binding`:
    /// approving a queued request *is* issuing a binding, so §6a.9.3 defines no
    /// new capability for it.
    fn handle_approve(&self, ctx: &HandlerContext) -> HandlerResult {
        let pending = match self.load_pending_for_decision(ctx) {
            Ok(v) => v,
            Err(result) => return result,
        };

        // §6a.9.3 `[MUST]` — the queue is NOT a reservation. If the name went to
        // someone else between queue and approval, issuing anyway would silently
        // overwrite a live binding, so the decision refuses instead. Checked
        // against the *target*, because a head already pointing at this same
        // requester is this request's own intent, not a collision.
        if let Some(existing) = self
            .location_index
            .get(&by_name_pointer_path(&self.peer_id, &pending.name))
        {
            if let Ok(bound) = self.load_binding(&existing) {
                if bound.target_peer_id != pending.target_peer_id {
                    return error(
                        STATUS_CONFLICT,
                        "name_taken",
                        "name was bound to another peer between queue and approval",
                    );
                }
            }
        }

        // The **third** producer of peer-issued bindings, and the one no
        // routing named. `approve-request` mints from a body queued days
        // earlier, so it owes the register path's cascade *and* its ceiling —
        // read from the policy **now**, not from the policy that was live when
        // the request was queued. An operator who lowers `max_ttl` after
        // queueing and then approves must not sign above the ceiling they
        // just set; §6a.9.2's *"current operator intent outranks history"* is
        // the same argument the renew cascade puts step 2 above step 3 for.
        //
        // A queued request whose ttl cannot resolve is refused rather than
        // signed: the D12 guard on the register path already declines to
        // *queue* one, so reaching here means the policy changed underneath —
        // which is exactly the stored-state-is-already-bad case, at the
        // operator's own operation.
        let policy = self.load_policy();
        let approve_ttl = clamp_to_ceiling(
            pending
                .requested_ttl
                .or_else(|| policy.as_ref().and_then(|p| p.default_ttl)),
            &policy.clone().unwrap_or_default(),
        );
        if approve_ttl.is_none() {
            return error(
                STATUS_FORBIDDEN,
                "policy_rejected",
                "resolved ttl is null at approval: the queued request carried no \
                 requested_ttl and the issuer policy now defines no default_ttl. \
                 Refusing rather than minting a null-ttl binding (§6a.3 / D3) or \
                 substituting a default (§6a.9.2 / D12).",
            );
        }

        let binding_hash = match self.issue_binding(
            &pending.name,
            &pending.target_peer_id,
            pending.transports.clone(),
            approve_ttl,
            None,
        ) {
            Ok(h) => h,
            Err(result) => return result,
        };

        if let Err(result) =
            self.record_decision(&pending, PENDING_STATUS_APPROVED, Some(binding_hash), None)
        {
            return result;
        }

        register_result(
            entity_handler::STATUS_OK,
            vec![
                (text("status"), text(STATUS_BOUND)),
                (
                    text("binding_hash"),
                    Value::Bytes(binding_hash.to_bytes().to_vec()),
                ),
            ],
        )
    }

    /// `deny-request` (§6a.9.3) — record the refusal. **Nothing is signed and
    /// nothing is published.**
    ///
    /// **Deny is not a delete `[MUST]`.** The denied head stays reachable
    /// through the by-request pointer, because a requester polling a *vanished*
    /// pointer cannot distinguish `denied` from `never received` — and a silent
    /// drop is what the substrate's deliver-or-signal floor forbids.
    fn handle_deny(&self, ctx: &HandlerContext) -> HandlerResult {
        let pending = match self.load_pending_for_decision(ctx) {
            Ok(v) => v,
            Err(result) => return result,
        };
        // Operator-supplied and never parsed — carried verbatim for a human
        // reader, so nothing downstream branches on its content.
        let reason = decode_map(&ctx.params.data)
            .ok()
            .and_then(|m| get_field(&m, "reason").and_then(|v| v.as_text().map(str::to_string)));

        if let Err(result) = self.record_decision(&pending, PENDING_STATUS_DENIED, None, reason) {
            return result;
        }

        register_result(
            entity_handler::STATUS_OK,
            vec![(text("status"), text(PENDING_STATUS_DENIED))],
        )
    }

    /// Shared prologue for both decisions: read `pending_hash`, resolve the
    /// body, and refuse a second decision.
    #[allow(clippy::result_large_err)]
    fn load_pending_for_decision(
        &self,
        ctx: &HandlerContext,
    ) -> Result<PendingBindingData, HandlerResult> {
        // §6a.9.3 declares no input entity type for these ops (routed by
        // core-go as a gap), so the params are read as a bare map rather than
        // gated on a type this handler would have to invent.
        let map = decode_map(&ctx.params.data)
            .map_err(|e| error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string()))?;
        let pending_hash = get_field(&map, "pending_hash")
            .and_then(|v| v.as_bytes())
            .and_then(|b| Hash::from_bytes(b).ok())
            .ok_or_else(|| {
                error(
                    STATUS_BAD_REQUEST,
                    "invalid_params",
                    "pending_hash required (system/hash)",
                )
            })?;

        let entity = self.content_store.get(&pending_hash).ok_or_else(|| {
            error(
                STATUS_NOT_FOUND,
                "not_found",
                "pending_hash names no stored pending-binding",
            )
        })?;
        let pending = PendingBindingData::from_entity(&entity)
            .map_err(|e| error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string()))?;

        // **A superseded head is not decidable.** Supersession repoints the
        // by-request pointer and deliberately leaves the old body in place for
        // audit, so a stale `pending_review` body stays fetchable forever.
        // Without this check, approving a superseded hash would mint a binding
        // on terms the operator's queue no longer shows and leave the pointer
        // naming a different head than the one decided — an inconsistency no
        // later read could untangle. §6a.9.3's "one head per pair" is a rule
        // about what is DECIDABLE, not only about what is listed.
        //
        // §6a.9.3 pins a code for "names no stored pending-binding" and none for
        // "names a superseded one". Reusing the pinned `404` with a message that
        // names supersession beats inventing a cohort-divergent code; core-go
        // reached the same reading independently and routed the gap
        // (`spec-issues/2026-08-13-d`). Converged on the argument, not the count.
        let head = self.location_index.get(&pending_by_request_path(
            &self.peer_id,
            &pending.target_peer_id,
            &pending.name,
        ));
        if head != Some(pending_hash) {
            return Err(error(
                STATUS_NOT_FOUND,
                "not_found",
                "pending_hash names a superseded head — a later register-request \
                 replaced it (§6a.9.3, one head per pair), or retention removed it",
            ));
        }

        // Approve and deny are not idempotent-by-replay: re-approving would mint
        // a second binding for one request.
        if pending.is_decided() {
            return Err(error(
                STATUS_CONFLICT,
                "already_decided",
                "this request already carries a decision",
            ));
        }
        Ok(pending)
    }

    /// Write the decided successor body and repoint. Replace-whole: the prior
    /// body stays at its own content-addressed path, so the queue's history
    /// remains auditable independently of the pointer.
    #[allow(clippy::result_large_err)]
    fn record_decision(
        &self,
        pending: &PendingBindingData,
        status: &str,
        binding_hash: Option<Hash>,
        reason: Option<String>,
    ) -> Result<Hash, HandlerResult> {
        let decided = pending.decided(status, binding_hash, reason);
        let decided_hash = self.store_pending(&decided)?;
        self.location_index.set(
            &pending_by_request_path(&self.peer_id, &pending.target_peer_id, &pending.name),
            decided_hash,
        );
        Ok(decided_hash)
    }

    /// Store a pending-binding body at its content-addressed §6a.9.3 path.
    #[allow(clippy::result_large_err)]
    fn store_pending(&self, pending: &PendingBindingData) -> Result<Hash, HandlerResult> {
        let entity = pending
            .to_entity()
            .map_err(|e| error(STATUS_BAD_REQUEST, "encode_failed", &e.to_string()))?;
        let hash = entity.content_hash;
        self.content_store
            .put(entity)
            .map_err(|e| error(STATUS_BAD_REQUEST, "store_failed", &e.to_string()))?;
        self.location_index
            .set(&pending_body_path(&self.peer_id, &hash), hash);
        Ok(hash)
    }

    /// `set-issuer-policy` (§6a.9.2 `[RATIFIED 2026-08-10]`).
    ///
    /// **Replace-whole `[MUST]`** — the stored entity becomes exactly the
    /// submitted policy, with no merge against whatever was there before.
    /// "An absent optional field means *unset*, not *unchanged*; a merge
    /// semantics would make the resulting policy depend on write order,
    /// which two peers cannot reconstruct." Implemented by storing the
    /// submitted entity verbatim, which is also what makes the response
    /// "the stored policy, as written" byte-for-byte.
    fn handle_set_issuer_policy(&self, ctx: &HandlerContext) -> HandlerResult {
        if ctx.params.entity_type != entity_types::TYPE_REGISTRY_ISSUER_POLICY {
            return error(
                STATUS_BAD_REQUEST,
                "invalid_params",
                &format!(
                    "set-issuer-policy expects a {} entity, got {}",
                    entity_types::TYPE_REGISTRY_ISSUER_POLICY,
                    ctx.params.entity_type
                ),
            );
        }
        let policy = match IssuerPolicyData::from_entity(&ctx.params) {
            Ok(p) => p,
            Err(e) => {
                return error(
                    STATUS_BAD_REQUEST,
                    "invalid_params",
                    &format!("decode issuer-policy: {}", e),
                )
            }
        };

        // §6a.9.2 refuses `domain-control` **at the door**, "rather than
        // storing a policy it cannot enforce". That is a different act from
        // the 501 the register path gives a *stored* domain-control policy:
        // the 400 binds `set-issuer-policy`, which declines to arm the mode
        // at all, while a policy predating that refusal still has to be
        // answered when a request arrives against it.
        match policy.mode.as_str() {
            MODE_OPEN | MODE_ALLOWLIST | MODE_MANUAL => {}
            MODE_DOMAIN_CONTROL => {
                return error(
                    STATUS_BAD_REQUEST,
                    "unsupported_mode",
                    "mode \"domain-control\" is deferred to the web-native domain-proof \
                     co-design (§6a.9.1/§6a.10) and will not be stored",
                )
            }
            other => {
                return error(
                    STATUS_BAD_REQUEST,
                    "unsupported_mode",
                    &format!(
                        "unknown issuer-policy mode {:?} (expected open, allowlist or manual)",
                        other
                    ),
                )
            }
        }

        // D11 (§6a.9.2 / CAP registry, arch 2026-08-18) — a live-registration
        // policy MUST define `default_ttl`.
        //
        // Every storable mode reaching this point (open, allowlist, manual) can
        // issue a binding, and a request that omits `requested_ttl` against a
        // policy with no `default_ttl` resolves to a null ttl — a binding D3
        // makes unresolvable. So such a policy can only mint bindings no
        // conformant resolver will accept.
        //
        // Refused HERE rather than at register-time, which is the whole point of
        // the ruling: a 400 at register bills the *requester* for what is an
        // *operator* misconfiguration, and the operator's field lives on this
        // entity — this is the only place the missing value can actually be
        // supplied. Same move §6a.9.2 already makes for domain-control one
        // bullet up: decline to arm a mode we cannot serve, rather than storing
        // a policy that can only fail later.
        if policy.default_ttl.is_none() {
            return error(
                STATUS_BAD_REQUEST,
                "invalid_params",
                "a live-registration issuer policy MUST define default_ttl: without it \
                 a request that omits requested_ttl resolves to a null ttl, and a \
                 null-ttl peer-issued binding is unresolvable (CAP registry D3). \
                 Refusing to store rather than arming a policy that can only mint \
                 invalid bindings (CAP registry D11).",
            );
        }

        // §6a.9.1 `[MUST, v1.11]` — `max_ttl` is REQUIRED on any policy that
        // can reach *approve*, and it is refused **here**, at *"the same
        // trigger, the same site, and the same reason as the `default_ttl`
        // rule above"*: the operator's field, set through the operator's
        // operation.
        //
        // What it bounds is not a null — it is the requester's own number.
        // Step 1 of both cascades accepts `requested_ttl` verbatim and until
        // now nothing capped it, so an unbounded requester-chosen `ttl`
        // reproduces the permanently-unrevokable binding §6a.3 exists to
        // prevent **without ever setting the field to null**: §6a.4's expiry
        // check is the only check a hostile byte-server cannot influence, and
        // a decade-long `ttl` makes a withheld revocation last a decade.
        //
        // The ceiling that actually protects a consumer is the *resolver's*
        // (see `RegistryHandler::apply_resolver_ceiling`) — a hostile issuer
        // just sets `max_ttl` high, so only the party bearing the risk can
        // bound it. This half is operator hygiene: it stops a careless
        // registrant asking for a decade.
        let Some(max_ttl) = policy.max_ttl else {
            return error(
                STATUS_BAD_REQUEST,
                "invalid_params",
                "a live-registration issuer policy MUST define max_ttl (§6a.9.1 v1.11): \
                 without it `requested_ttl` is unbounded, and an unbounded ttl is a \
                 binding whose withheld revocation has no bound at all — the \
                 permanently-unrevokable shape §6a.3 exists to prevent, reached \
                 without ever setting the field to null.",
            );
        };
        // `default_ttl` MUST NOT exceed `max_ttl`. A policy violating that is
        // internally contradictory rather than merely lax: the value the
        // registry supplies when the requester omits one would itself be
        // clamped by the next line of the same policy.
        if policy.default_ttl.is_some_and(|d| d > max_ttl) {
            return error(
                STATUS_BAD_REQUEST,
                "invalid_params",
                "issuer policy is self-contradictory: default_ttl exceeds max_ttl \
                 (§6a.9.1 v1.11) — the registry's own fallback would be clamped by \
                 its own ceiling",
            );
        }

        // Store the submitted entity as-is. Re-encoding via `to_entity`
        // would author a second entity with the same fields but its own
        // identity; writing what arrived is what keeps the round-trip
        // byte-exact (the §1.7 preserve-bytes discipline).
        let stored = ctx.params.clone();
        let hash = stored.content_hash;
        if let Err(e) = self.content_store.put(stored) {
            return error(STATUS_BAD_REQUEST, "store_failed", &e.to_string());
        }
        self.location_index
            .set(&issuer_policy_path(&self.peer_id), hash);
        entity_result(ctx.params.clone())
    }

    /// `get-issuer-policy` (§6a.9.2) — the stored policy, or `404
    /// not_found` when unset.
    ///
    /// It MUST NOT synthesize a default `open`: that "would silently turn a
    /// curated registry into a first-come-first-serve one." Takes no input;
    /// the cohort convention for an input-less op is an empty
    /// `primitive/map` params entity, because a zero-value params entity is
    /// refused `400 invalid_params` by the envelope layer before it ever
    /// reaches a handler.
    fn handle_get_issuer_policy(&self) -> HandlerResult {
        let path = issuer_policy_path(&self.peer_id);
        let stored = self
            .location_index
            .get(&path)
            .and_then(|h| self.content_store.get(&h));
        match stored {
            Some(e) => entity_result(e),
            None => error(
                STATUS_NOT_FOUND,
                "not_found",
                "no issuer-policy is stored (§6a.9.2 — unset is not a mode)",
            ),
        }
    }

    // -------------------------------------------------------------------
    // Layer-1 verification + the §6a.8 sign+publish act
    // -------------------------------------------------------------------

    /// Layer-1 proof: a `system/signature` (in `included` or at the invariant
    /// pointer) targeting `request_hash`, whose signer's identity derives to
    /// `target_peer_id`, and which crypto-verifies. Ed25519-only (P5).
    fn verify_layer1(
        &self,
        request_hash: &Hash,
        target_peer_id: &str,
        included: &HashMap<Hash, entity_entity::Entity>,
    ) -> bool {
        let sig = match find_binding_signature(
            request_hash,
            &self.content_store,
            &self.location_index,
            included,
        ) {
            Some(s) => s,
            None => return false,
        };
        let signer_entity = match included
            .get(&sig.signer)
            .cloned()
            .or_else(|| self.content_store.get(&sig.signer))
        {
            Some(e) => e,
            None => return false,
        };
        let pubkey = match peer_pubkey_from_entity(&signer_entity) {
            Some(pk) => pk,
            None => return false,
        };
        // The proof: the signer's key must derive to the claimed target_peer_id.
        if PeerId::from_public_key(&pubkey).as_str() != target_peer_id {
            return false;
        }
        Keypair::verify(&pubkey, &request_hash.to_bytes(), &sig.signature).is_ok()
    }

    /// The layer-1 gate for **all three write ops** (§6a.9 `[RULED 2026-08-11]`).
    ///
    /// `Some(rejection)` means refuse and publish nothing. This is a helper and
    /// not three inline checks on purpose: `revoke` and `renew` shipped with no
    /// verification at all because §6a.9 named `REG-REGISTER-PROOF-1` and no
    /// vector for the other two — *the vector list, not the prose, is what got
    /// implemented against*, in all three impls. A gate every caller inherits
    /// is the only shape where a fourth op can't reintroduce the hole.
    ///
    /// 401 (not 403) per the ratified status table: an unverifiable signer is
    /// an authentication failure. Code is `signature_invalid` — normative, and
    /// what a peer branches on.
    #[allow(clippy::result_large_err)]
    fn require_layer1(
        &self,
        request_hash: &Hash,
        target_peer_id: &str,
        included: &HashMap<Hash, entity_entity::Entity>,
    ) -> Option<HandlerResult> {
        if self.verify_layer1(request_hash, target_peer_id, included) {
            return None;
        }
        Some(error(
            STATUS_AUTH_FAILED,
            REG_ERR_SIGNATURE_INVALID,
            "request not signed by target_peer_id (layer-1 ownership proof failed)",
        ))
    }

    /// Replay defense — `issued_at` freshness window + per-requester seen-nonce
    /// (§6a.9.1). Checks only; the marker is written by the caller after
    /// admission, so a rejected request leaves no trace.
    ///
    /// Bound to `register` and `renew` by the §6a.9 discriminator (replay has a
    /// non-idempotent state effect), **not** to `revoke`, which is monotonic on
    /// a content-addressed target. Replay defense is not authorization — it is
    /// layered on top of [`Self::require_layer1`], never instead of it.
    fn check_replay(
        &self,
        requester_peer_id: &str,
        nonce: &[u8],
        issued_at: u64,
    ) -> Option<HandlerResult> {
        let now = now_ms();
        if issued_at > now.saturating_add(REGISTER_FUTURE_SKEW_MS)
            || now > issued_at.saturating_add(REGISTER_STALE_AFTER_MS)
        {
            return Some(error(
                STATUS_FORBIDDEN,
                "stale_request",
                "issued_at outside the accepted freshness window",
            ));
        }
        if self
            .location_index
            .get(&register_nonce_path(
                &self.peer_id,
                requester_peer_id,
                nonce,
            ))
            .is_some()
        {
            return Some(error(
                STATUS_CONFLICT,
                "replay",
                "nonce already seen for this requester",
            ));
        }
        None
    }

    /// Resolve the binding named by `binding_hash`. `revoke`/`renew` take their
    /// layer-1 `target_peer_id` from **the binding**, not from the request —
    /// a request-supplied one would let the requester name the peer it claims
    /// to be, which proves nothing.
    #[allow(clippy::result_large_err)]
    fn load_binding(&self, binding_hash: &Hash) -> Result<BindingData, HandlerResult> {
        let entity = self.content_store.get(binding_hash).ok_or_else(|| {
            error(
                STATUS_NOT_FOUND,
                "not_found",
                "no such binding in this registry",
            )
        })?;
        if entity.entity_type != TYPE_REGISTRY_BINDING {
            return Err(error(
                STATUS_BAD_REQUEST,
                "invalid_params",
                "binding_hash addresses a non-binding entity",
            ));
        }
        BindingData::from_entity(&entity).map_err(|e| {
            error(
                STATUS_BAD_REQUEST,
                "invalid_params",
                &format!("decode existing binding: {}", e),
            )
        })
    }

    /// `registry-issue-binding` (§6a.8): build the binding body, sign its hash
    /// with `K_registry`, and publish body + invariant-pointer signature +
    /// by-name pointer. `supersedes` threads the renew chain. Returns the
    /// binding hash, or an error `HandlerResult` to surface verbatim. (The
    /// `Err` carries a `HandlerResult` by design — it's the rejection entity the
    /// caller forwards untouched, not a hot-path value.)
    #[allow(clippy::result_large_err)]
    fn issue_binding(
        &self,
        name_norm: &str,
        target_peer_id: &str,
        transports: Vec<Value>,
        ttl: Option<u64>,
        supersedes: Option<Hash>,
    ) -> Result<Hash, HandlerResult> {
        let binding = BindingData {
            name: name_norm.to_string(),
            kind: KIND_PEER_ISSUED.into(),
            target_peer_id: target_peer_id.to_string(),
            transports,
            issued_at: now_ms(),
            ttl,
            supersedes,
            issuer_attestation: None,
            metadata: None,
        };
        let entity = binding
            .to_entity()
            .map_err(|e| error(STATUS_BAD_REQUEST, "encode_failed", &e.to_string()))?;
        let binding_hash = entity.content_hash;
        self.content_store
            .put(entity)
            .map_err(|e| error(STATUS_BAD_REQUEST, "store_failed", &e.to_string()))?;
        self.sign_and_publish(&binding_hash)?;
        // §3 universal body path + §6a.3 by-name index.
        self.location_index.set(
            &binding_body_path(&self.peer_id, &binding_hash),
            binding_hash,
        );
        self.location_index.set(
            &by_name_pointer_path(&self.peer_id, name_norm),
            binding_hash,
        );
        Ok(binding_hash)
    }

    /// Sign `target` with `K_registry` and publish the signature at the
    /// invariant-pointer `system/signature/{hex(target)}`, plus the registry's
    /// own `system/peer` entity so verifiers can resolve `sig.signer`.
    #[allow(clippy::result_large_err)]
    fn sign_and_publish(&self, target: &Hash) -> Result<(), HandlerResult> {
        let peer_entity = self
            .signer
            .peer_entity()
            .map_err(|e| error(STATUS_BAD_REQUEST, "encode_failed", &e.to_string()))?;
        let _ = self.content_store.put(peer_entity);

        let sig = SignatureData {
            target: *target,
            signer: self.signer.peer_identity_hash(),
            algorithm: self.signer.key_type().label().to_string(),
            signature: self.signer.sign(&target.to_bytes()),
        };
        let sig_entity = sig
            .to_entity()
            .map_err(|e| error(STATUS_BAD_REQUEST, "encode_failed", &e.to_string()))?;
        let sig_hash = sig_entity.content_hash;
        self.content_store
            .put(sig_entity)
            .map_err(|e| error(STATUS_BAD_REQUEST, "store_failed", &e.to_string()))?;
        self.location_index
            .set(&signature_pointer_path(&self.peer_id, target), sig_hash);
        Ok(())
    }
}

/// §6a.9.1 `[MUST, v1.11]` — apply the issuer-side ceiling to a resolved
/// `ttl`: `effective = min(resolved, policy.max_ttl)`.
///
/// **A request above the ceiling is CLAMPED, not refused.** Refusing would
/// bill a well-formed request for a policy the requester cannot read —
/// §6a.9.2's own stated reason for not gating the requester — and it teaches
/// requesters to probe for the ceiling. DNS does not `NXDOMAIN` a long TTL;
/// it caps it.
///
/// `None` in, `None` out: this bounds a value, it never supplies one. The
/// null-`ttl` refusals are the callers' job and they run on the clamped
/// result, so a policy whose ceiling is the only source of a number still
/// refuses rather than inventing one.
///
/// A policy with **no** `max_ttl` clamps nothing. `set-issuer-policy` refuses
/// to store such a policy, so reaching this with `max_ttl: None` means the
/// stored state predates the rule or was seeded out-of-band — the same
/// already-bad-stored-state case the register/renew backstops answer, and
/// silently substituting a ceiling here would be the implementation-chosen
/// default §6a.9.2 forbids one paragraph up.
fn clamp_to_ceiling(resolved: Option<u64>, policy: &IssuerPolicyData) -> Option<u64> {
    match (resolved, policy.max_ttl) {
        (Some(t), Some(ceiling)) => Some(t.min(ceiling)),
        (other, _) => other,
    }
}

// ---------------------------------------------------------------------------
// §6a.9.1 `issuer-policy.name_constraints` — grammar UNRULED, deliberately
// left on the POSIX reading
// ---------------------------------------------------------------------------

/// Match a name against `issuer-policy.name_constraints` (§6a.9.1).
///
/// **This is NOT [`crate::resolver::dispatch_match`], and the split is the
/// point.** §4's `name_format_dispatch.pattern` grammar was closed at
/// `REGISTRY 1.13` — `*` only, every other byte a literal. §6a.9.1's
/// `name_constraints` is the *fourth* glob-shaped field in this extension and
/// its grammar is **unruled**: the spec says only *"`<glob | null>`, e.g. only
/// issue `"*.lab"`"*, which every POSIX and every closed reading satisfies
/// identically.
///
/// `entity-core-go` surfaced this by running the matcher-convergence grep its
/// own discipline mandates, and **routed it (spec-issue `2026-08-18-e`)
/// rather than converging a cross-impl-observable surface unilaterally** —
/// which is the call arch upheld on the dispatch matter one field over. We
/// hold the same line: this field decides which names a registry will sign,
/// so a peer that reads `app-[0-9]` as a character class and one that reads
/// it as five literal bytes admit **different name sets** from the same
/// stored policy. Converging it here, ahead of a ruling, is how three
/// implementations end up with three matchers.
///
/// So this keeps the POSIX behaviour the field has always had —
/// `*` (any run), `?` (one character), `[…]` character classes with `!`
/// negation — **unchanged and unshared**, and it is a separate function from
/// the ruled one so that neither can drift into the other. Two matchers in
/// one tree silently agreeing is exactly what core-go's finding names.
///
/// **Owed when arch rules:** if the answer is "same closed grammar as §4",
/// this collapses to a call to `dispatch_match` and the vector rows below
/// invert.
pub(crate) fn name_constraints_match(pattern: &str, name: &str) -> bool {
    posix_glob(pattern.as_bytes(), name.as_bytes())
}

fn posix_glob(mut p: &[u8], mut t: &[u8]) -> bool {
    loop {
        match p.first() {
            None => return t.is_empty(),
            Some(b'*') => {
                while p.first() == Some(&b'*') {
                    p = &p[1..];
                }
                if p.is_empty() {
                    return true;
                }
                for i in 0..=t.len() {
                    if posix_glob(p, &t[i..]) {
                        return true;
                    }
                }
                return false;
            }
            Some(b'?') => {
                if t.is_empty() {
                    return false;
                }
                p = &p[1..];
                t = &t[1..];
            }
            Some(b'[') => {
                if t.is_empty() {
                    return false;
                }
                match posix_class(&p[1..], t[0]) {
                    Some(consumed) => {
                        p = &p[1 + consumed..];
                        t = &t[1..];
                    }
                    None => return false,
                }
            }
            Some(&c) => {
                if t.first() != Some(&c) {
                    return false;
                }
                p = &p[1..];
                t = &t[1..];
            }
        }
    }
}

/// Match `ch` against a `[...]` class starting after the `[`. Returns the
/// number of bytes consumed up to and including the closing `]`, or `None` if
/// no match / malformed.
fn posix_class(spec: &[u8], ch: u8) -> Option<usize> {
    let mut i = 0;
    let negate = spec.first() == Some(&b'!');
    if negate {
        i += 1;
    }
    let mut matched = false;
    let start = i;
    while i < spec.len() {
        let c = spec[i];
        if c == b']' && i > start {
            return if matched != negate { Some(i + 1) } else { None };
        }
        if i + 2 < spec.len() && spec[i + 1] == b'-' && spec[i + 2] != b']' {
            let lo = c;
            let hi = spec[i + 2];
            if ch >= lo && ch <= hi {
                matched = true;
            }
            i += 3;
        } else {
            if ch == c {
                matched = true;
            }
            i += 1;
        }
    }
    None // unterminated class
}
