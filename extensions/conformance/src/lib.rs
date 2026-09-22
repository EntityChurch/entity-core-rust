//! GUIDE-CONFORMANCE §7a — the two `system/validate/*` wire-gate handlers
//! behind a runtime opt-in.
//!
//! These handlers are conformance **scaffolding**: not core protocol, not an
//! extension primitive. They expose two existing core capabilities at
//! well-known patterns so a black-box validator can probe them:
//!
//!   - `system/validate/echo:echo` — exercises §6.13(a) resolve→dispatch
//!     (verbatim-echo contract).
//!   - `system/validate/dispatch-outbound:dispatch` — exercises §6.13(b)
//!     outbound seam routed through §6.11 reentry: the handler originates ONE
//!     outbound EXECUTE back to the caller over the same accepted connection.
//!
//! In a core-only peer (no compute / continuation / subscription / inbox)
//! neither capability has another wire-reachable trigger, which is the whole
//! reason this exists.
//!
//! Both are OFF by default. The wire-host opts in (typically a `--validate`
//! flag → `PeerBuilder::with_conformance_handlers()`); a peer without the
//! opt-in 404s both patterns and the validator SKIPs honestly per §7a.4.
//!
//! **Cap-passing convention (§7a.2a, RATIFIED shape (a)):** the reentry
//! authority rides **in-band, nested in params** (`reentry_capability` /
//! `reentry_granters` / `reentry_cap_signatures`) — NOT via the envelope
//! `included` set. It is extracted with byte fidelity
//! (`entity_wire::cbor_map_field_raw` / `cbor_array_elements_raw`) and forwarded
//! on the outbound EXECUTE via the `ExecuteOptions.included` channel (the Rust
//! analog of Go's `WithIncludedChain`).
//!
//! **The granter and signature carriers are PLURAL (§7a.1, `0.8.2.19`)** —
//! arrays, the single-granter case being an array of one. They were singular,
//! and that made one normative rule ungateable: `ENTITY-CORE-PROTOCOL` §1.4's
//! multi-signature-root rule needs a K-of-2 root to drive it, which requires
//! **two** granter identities and **two** signatures. A singular carrier cannot
//! express the input, so every seat drove E3/F66 in-process only — this is the
//! params change that makes it a wire vector.

use async_trait::async_trait;
use entity_entity::Entity;
use entity_handler::{
    error_entity, ExecuteOptions, Handler, HandlerContext, HandlerError, HandlerResult,
    STATUS_BAD_GATEWAY, STATUS_BAD_REQUEST, STATUS_INTERNAL_ERROR, STATUS_NOT_SUPPORTED,
};

/// `system/validate/echo` bare pattern.
pub const PATTERN_ECHO: &str = "system/validate/echo";
/// `system/validate/dispatch-outbound` bare pattern.
pub const PATTERN_DISPATCH_OUTBOUND: &str = "system/validate/dispatch-outbound";

fn qualify(local_peer_id: &str, bare: &str) -> String {
    format!("/{}/{}", local_peer_id, bare)
}

// ---------------------------------------------------------------------------
// EchoHandler — §7a.1 verbatim echo (proves §6.13(a)).
// ---------------------------------------------------------------------------

/// `system/validate/echo` — operation `echo` returns the params entity
/// verbatim. The §7a.1 contract is byte equality: `result.value` ==
/// `params.value` for any ECF value the caller passes, satisfied by returning
/// the params entity itself with no decode/re-encode roundtrip.
pub struct EchoHandler {
    qualified_pattern: String,
}

impl EchoHandler {
    pub fn new(local_peer_id: &str) -> Self {
        Self {
            qualified_pattern: qualify(local_peer_id, PATTERN_ECHO),
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for EchoHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        if ctx.operation != "echo" {
            return Ok(HandlerResult::error(
                STATUS_NOT_SUPPORTED,
                error_entity(
                    "unsupported_operation",
                    &format!(
                        "system/validate/echo: operation {:?} not supported",
                        ctx.operation
                    ),
                ),
            ));
        }
        // Verbatim echo — clone the params entity through unmodified. No
        // decode/re-encode, so the §7a.1 byte-equality assertion holds.
        Ok(HandlerResult::ok(ctx.params.clone()))
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "validate/echo"
    }

    fn operations(&self) -> &[&str] {
        &["echo"]
    }
}

// ---------------------------------------------------------------------------
// DispatchOutboundHandler — §7a.1 outbound-seam-via-reentry (proves §6.13(b)).
// ---------------------------------------------------------------------------

/// `system/validate/dispatch-outbound` — operation `dispatch` originates
/// exactly one outbound EXECUTE via `ctx.execute_fn` (the §6.13(b) seam routed
/// through §6.11 reentry) to `operation@target`. The validator sets `target`
/// to itself, so the EXECUTE travels back over the same accepted connection
/// (B-role-same-connection per §7a.2a), where its `system/validate/echo`
/// serves the reentrant call. The downstream `{status, result}` is returned.
pub struct DispatchOutboundHandler {
    qualified_pattern: String,
}

impl DispatchOutboundHandler {
    pub fn new(local_peer_id: &str) -> Self {
        Self {
            qualified_pattern: qualify(local_peer_id, PATTERN_DISPATCH_OUTBOUND),
        }
    }

    async fn dispatch(&self, ctx: &HandlerContext) -> HandlerResult {
        // §6.13(b) seam must be wired (set by the connection dispatcher).
        let execute_fn = match ctx.execute_fn.as_ref() {
            Some(f) => f,
            None => {
                return HandlerResult::error(
                    STATUS_INTERNAL_ERROR,
                    error_entity(
                        "internal_error",
                        "dispatcher did not wire ctx.execute_fn (§6.13(b) seam missing)",
                    ),
                )
            }
        };

        // Text fields — no byte-fidelity concern.
        let data: ciborium::value::Value = match ciborium::from_reader(ctx.params.data.as_slice()) {
            Ok(v) => v,
            Err(e) => {
                return HandlerResult::error(
                    STATUS_BAD_REQUEST,
                    error_entity(
                        "invalid_params",
                        &format!("decode dispatch-outbound params: {}", e),
                    ),
                )
            }
        };
        let target = field_text(&data, "target");
        let operation = field_text(&data, "operation");
        if target.is_empty() || operation.is_empty() {
            return HandlerResult::error(
                STATUS_BAD_REQUEST,
                error_entity(
                    "invalid_params",
                    "dispatch-outbound requires target and operation",
                ),
            );
        }

        // §7a.2a in-band cap-passing: the authority entities and the opaque
        // `value` ride nested in params as raw CBOR. Extract them with byte
        // fidelity — a decode+re-encode would break content-hash recomputation
        // and the verbatim echo round-trip. The granter/signature carriers are
        // ARRAYS (§7a.1, 0.8.2.19); an absent key and an empty array are the
        // same fact for an optional array, so both land as an empty Vec.
        let cap_raw = entity_wire::cbor_map_field_raw(&ctx.params.data, "reentry_capability");
        let granter_raws =
            match entity_wire::cbor_map_field_raw(&ctx.params.data, "reentry_granters") {
                None => Vec::new(),
                Some(raw) => match entity_wire::cbor_array_elements_raw(raw) {
                    Some(v) => v,
                    None => return invalid("reentry_granters", "not a definite-length CBOR array"),
                },
            };
        let sig_raws =
            match entity_wire::cbor_map_field_raw(&ctx.params.data, "reentry_cap_signatures") {
                None => Vec::new(),
                Some(raw) => match entity_wire::cbor_array_elements_raw(raw) {
                    Some(v) => v,
                    None => {
                        return invalid(
                            "reentry_cap_signatures",
                            "not a definite-length CBOR array",
                        )
                    }
                },
            };
        //
        // **The set is OPTIONAL, and that is what makes PD-2 drivable here.**
        // It used to be required, and a request omitting it got `400
        // invalid_params` — which reads as strictness and is the reason
        // `origination.dispatch_outbound_ambient_refused` could not score us.
        // That check (0.8.2.17's §9.1 negative arm) drives this exact handler
        // with the authority deliberately absent, so the sub-dispatch rides
        // **ambient** handler authority; a 400 here means the probe never
        // reaches the outbound branch and the arm it exists to measure is never
        // entered. The refusal we owe that probe is the one §1.4 specifies —
        // `403 capability_denied` from `outbound_sub_dispatch_authorized`, on
        // the inner leg — and we cannot owe it from a handler that returns
        // first.
        //
        // **All-or-none, per §7a.1's own words**: credential + ≥1 granter + ≥1
        // signature selects the PRESENTED arm, all three absent selects the
        // AMBIENT arm, and anything in between is `400 invalid_params` — *"a
        // partial credential is malformed, not ambient."*
        let present = cap_raw.is_some() || !granter_raws.is_empty() || !sig_raws.is_empty();
        let complete = cap_raw.is_some() && !granter_raws.is_empty() && !sig_raws.is_empty();
        if present && !complete {
            return HandlerResult::error(
                STATUS_BAD_REQUEST,
                error_entity(
                    "invalid_params",
                    "dispatch-outbound takes reentry_capability + at least one \
                     reentry_granters + at least one reentry_cap_signatures together \
                     (§7a.1) or none of them (the §1.4 ambient-authority arm); a \
                     partial set is neither",
                ),
            );
        }
        let (cap, included) = if !present {
            (None, Vec::new())
        } else {
            // Decode the authority entities byte-faithfully, then
            // re-canonicalize so each carries the right content_hash before
            // dispatch (decode keeps type+data; the constructor recomputes the
            // hash deterministically).
            let cap = match recanonicalize(cap_raw.expect("complete")) {
                Ok(e) => e,
                Err(e) => return invalid("reentry_capability", &e),
            };
            let mut chain = Vec::with_capacity(granter_raws.len() + sig_raws.len());
            for (i, raw) in granter_raws.iter().enumerate() {
                // Each granter is a `system/peer` identity, so it is rebuilt at
                // the **ECFv1-SHA-256 floor** rather than under this peer's home
                // format: `ENTITY-CORE-PROTOCOL` §4.5a item 1a pins the identity
                // entity to the floor unconditionally, whatever the peer's home
                // format. Plain `Entity::new` here is a latent defect on a
                // non-floor-home peer — it would manufacture a second
                // content_hash for the one identity item 1a exists to collapse,
                // on the exact surface where §5.2's granter/grantee equality is
                // evaluated, and both sides of every downstream comparison would
                // be wrong the same way.
                match recanonicalize_identity(raw) {
                    Ok(e) => chain.push(e),
                    Err(e) => return invalid(&format!("reentry_granters[{}]", i), &e),
                }
            }
            for (i, raw) in sig_raws.iter().enumerate() {
                match recanonicalize(raw) {
                    Ok(e) => chain.push(e),
                    Err(e) => return invalid(&format!("reentry_cap_signatures[{}]", i), &e),
                }
            }
            (Some(cap), chain)
        };

        // The caller passed `value` as a raw-CBOR opaque payload; wrap it as a
        // primitive/any entity for the §3.4 "params is an entity" requirement.
        // Default an absent value to CBOR null.
        let value_raw = entity_wire::cbor_map_field_raw(&ctx.params.data, "value")
            .map(|s| s.to_vec())
            .unwrap_or_else(|| vec![0xf6]);
        let outbound_params = match Entity::new("primitive/any", value_raw) {
            Ok(e) => e,
            Err(e) => {
                return HandlerResult::error(
                    STATUS_BAD_REQUEST,
                    error_entity(
                        "invalid_params",
                        &format!("build outbound params entity: {}", e),
                    ),
                )
            }
        };

        // Originate one outbound EXECUTE through the §6.13(b) seam. When the
        // §7a.2a triple was supplied, the reentry capability authorizes this
        // EXECUTE (opts.capability) and its granter identity + signature ride in
        // the envelope `included` via opts.included — the in-band chain isn't in
        // the local store, so `collect_chain_bundle` can't reach it. With no
        // triple, `capability: None` and the dispatch rides ambient authority,
        // which is §1.4's other arm and the one PD-2's negative check drives.
        let opts = ExecuteOptions {
            capability: cap,
            included,
            ..Default::default()
        };
        let downstream = match execute_fn(target, operation, outbound_params, opts).await {
            Ok(r) => r,
            Err(e) => {
                return HandlerResult::error(
                    STATUS_BAD_GATEWAY,
                    error_entity(
                        "reentry_dispatch_failed",
                        &format!("originate reentry EXECUTE: {}", e),
                    ),
                )
            }
        };

        // Pack the downstream EXECUTE_RESPONSE into the §7a.1 result shape
        // {status, result}, wrapped as primitive/any. `result` is the
        // downstream result entity encoded canonically (raw-embedded so its
        // data byte-fidelity — and thus the echo round-trip — survives).
        let result_entity_bytes = entity_wire::encode_entity(&downstream.result);
        let mut out = Vec::new();
        out.push(0xA2); // CBOR map, 2 items
                        // ECF key order: "result" < "status" (equal length, lexicographic).
        entity_ecf::encode_cbor_text(&mut out, "result");
        out.extend_from_slice(&result_entity_bytes);
        entity_ecf::encode_cbor_text(&mut out, "status");
        out.extend_from_slice(&entity_ecf::to_ecf(&entity_ecf::integer(
            downstream.status as i64,
        )));

        match Entity::new("primitive/any", out) {
            Ok(e) => HandlerResult::ok(e),
            Err(e) => HandlerResult::error(
                STATUS_INTERNAL_ERROR,
                error_entity(
                    "internal_error",
                    &format!("build dispatch-outbound result: {}", e),
                ),
            ),
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for DispatchOutboundHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        if ctx.operation != "dispatch" {
            return Ok(HandlerResult::error(
                STATUS_NOT_SUPPORTED,
                error_entity(
                    "unsupported_operation",
                    &format!(
                        "system/validate/dispatch-outbound: operation {:?} not supported",
                        ctx.operation
                    ),
                ),
            ));
        }
        Ok(self.dispatch(ctx).await)
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "validate/dispatch-outbound"
    }

    fn operations(&self) -> &[&str] {
        &["dispatch"]
    }

    /// **NARROW, and that is a GUIDE-CONFORMANCE §7a.1 ⛔ scaffold-contract
    /// requirement — not hardening, and not an implementation detail.**
    ///
    /// Returning `None` here means `default_handler_self_grant()`, which is wide
    /// on Dimensions 1–3 (`handlers: *`, `operations: *`, `resources: /*/*`).
    /// That is what made the F67 confused-deputy bypass *unobservable*:
    /// `ENTITY-CORE-PROTOCOL` §1.4's outbound gate admits two authority
    /// contributions — the executing handler's grant (Dims 1–3, always) and a
    /// target-minted credential (Dim 4 only) — and the vector that tells a
    /// **compose** from a **bypass** is *a valid credential presented to a
    /// handler whose own grant does not cover the request → MUST refuse*.
    /// Against a wide grant that vector is unconstructible: the composed and the
    /// bypassed readings return the same answer for **every** input a probe can
    /// send, so the probe sits exactly where the two readings agree. Which is
    /// how F67 passed two green wire rows at three reference seats and across 46
    /// generated peers, with this tree's design prose defending it.
    ///
    /// The declared set is the §7a.2a reentry contract's minimum and nothing
    /// else: `echo` on `system/validate/echo`. The in-scope reentry still
    /// succeeds — Dims 1–2 covered here, Dim 3 unchecked (`echo` carries no
    /// resource target), Dim 4 relaxed by the caller-minted reentry credential.
    /// An out-of-scope **operation** fails Dimension 1 unless a credential is
    /// wrongly treated as a standalone authorizer, and the operation is
    /// therefore the axis go's `dispatch_outbound_narrow_grant_refuses_out_of_
    /// scope` (F63) drives.
    ///
    /// `peers` is deliberately **absent**, not `["*"]`: absent defaults to
    /// `{include: [local_peer_id]}`, and Dimension 4 is the one the credential
    /// relaxes. Writing `*` here would make that dimension vacuous and delete
    /// the very check the reentry arm exists to exercise.
    fn internal_scope(&self) -> Option<Vec<entity_capability::GrantEntry>> {
        Some(vec![entity_capability::GrantEntry {
            handlers: entity_capability::PathScope::new(vec![PATTERN_ECHO.to_string()]),
            operations: entity_capability::IdScope::new(vec!["echo".to_string()]),
            resources: entity_capability::PathScope::new(vec![format!("/*/{}", PATTERN_ECHO)]),
            peers: None,
            constraints: None,
            allowances: None,
        }])
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn field_text(data: &ciborium::value::Value, key: &str) -> String {
    data.as_map()
        .and_then(|m| {
            m.iter()
                .find(|(k, _)| k.as_text() == Some(key))
                .and_then(|(_, v)| v.as_text())
        })
        .unwrap_or("")
        .to_string()
}

/// Decode an entity-CBOR slice byte-faithfully, then re-canonicalize so its
/// content_hash is recomputed from `{type, data}` under this peer's home format.
fn recanonicalize(raw: &[u8]) -> Result<Entity, String> {
    let decoded = entity_wire::decode_entity(raw).map_err(|e| e.to_string())?;
    let ty = decoded.entity_type;
    let data = decoded.data;
    Entity::new(&ty, data).map_err(|e| e.to_string())
}

/// [`recanonicalize`] for an entity pinned to the **ECFv1-SHA-256 floor**
/// (`ENTITY-CORE-PROTOCOL` §4.5a item 1a): the `system/peer` identity entity is
/// authored at the floor unconditionally, whatever the active format and
/// whatever this peer's home format. Applied to the §7a.1 `reentry_granters`
/// entries, which are identities by contract.
///
/// Rebuilding a non-`system/peer` entity at the floor would be the mirror
/// defect, so the type is checked rather than assumed — a caller that puts
/// something else in the granter array gets told so rather than silently
/// getting a hash under the wrong format.
fn recanonicalize_identity(raw: &[u8]) -> Result<Entity, String> {
    let decoded = entity_wire::decode_entity(raw).map_err(|e| e.to_string())?;
    if decoded.entity_type != entity_types::TYPE_PEER {
        return Err(format!(
            "expected a {} identity entity, got {:?}",
            entity_types::TYPE_PEER,
            decoded.entity_type
        ));
    }
    Entity::new_with_format(
        &decoded.entity_type,
        decoded.data,
        entity_hash::HASH_ALGORITHM_SHA256,
    )
    .map_err(|e| e.to_string())
}

fn invalid(field: &str, msg: &str) -> HandlerResult {
    HandlerResult::error(
        STATUS_BAD_REQUEST,
        error_entity("invalid_params", &format!("rebuild {}: {}", field, msg)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use entity_handler::ExecuteFn;
    use std::sync::Arc;

    const PID: &str = "testpeer";

    fn ctx(op: &str, params: Entity) -> HandlerContext {
        HandlerContext::builder(execute_stub(), params)
            .operation(op)
            .build()
    }

    fn ctx_with_fn(op: &str, params: Entity) -> HandlerContext {
        // Dummy §6.13(b) seam — never reached on the error-branch tests, but
        // its presence distinguishes the 500 (no seam) path from the rest.
        let f: ExecuteFn = Arc::new(|_h, _o, _p, _opts| {
            Box::pin(async move { Ok(HandlerResult::ok(null_entity())) })
        });
        HandlerContext::builder(execute_stub(), params)
            .operation(op)
            .execute_fn(f)
            .build()
    }

    fn execute_stub() -> Entity {
        Entity::new("system/protocol/execute", vec![0xa0]).unwrap()
    }

    fn null_entity() -> Entity {
        Entity::new("primitive/any", vec![0xf6]).unwrap()
    }

    fn err_code(r: &HandlerResult) -> String {
        let v: ciborium::value::Value = ciborium::from_reader(r.result.data.as_slice()).unwrap();
        field_text(&v, "code")
    }

    /// params map carrying target + operation but no reentry-authority fields.
    fn dispatch_params_no_reentry() -> Entity {
        let data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "target" => entity_ecf::text("entity://x/system/validate/echo"),
            "operation" => entity_ecf::text("echo")
        });
        Entity::new("primitive/any", data).unwrap()
    }

    #[tokio::test]
    async fn echo_returns_params_verbatim() {
        let h = EchoHandler::new(PID);
        // CBOR text "hi" = 0x62 'h' 'i'.
        let params = Entity::new("primitive/any", vec![0x62, b'h', b'i']).unwrap();
        let r = h.handle(&ctx("echo", params.clone())).await.unwrap();
        assert_eq!(r.status, 200);
        // Byte-exact: same content_hash AND same data bytes (no re-encode).
        assert_eq!(r.result.content_hash, params.content_hash);
        assert_eq!(r.result.data, params.data);
    }

    #[tokio::test]
    async fn echo_rejects_unknown_op() {
        let h = EchoHandler::new(PID);
        let r = h.handle(&ctx("ping", null_entity())).await.unwrap();
        assert_eq!(r.status, STATUS_NOT_SUPPORTED);
        assert_eq!(err_code(&r), "unsupported_operation");
    }

    #[tokio::test]
    async fn dispatch_rejects_unknown_op() {
        let h = DispatchOutboundHandler::new(PID);
        let r = h.handle(&ctx("nope", null_entity())).await.unwrap();
        assert_eq!(r.status, STATUS_NOT_SUPPORTED);
    }

    #[tokio::test]
    async fn dispatch_500_without_execute_fn() {
        let h = DispatchOutboundHandler::new(PID);
        // No execute_fn on the context → §6.13(b) seam missing.
        let r = h
            .handle(&ctx("dispatch", dispatch_params_no_reentry()))
            .await
            .unwrap();
        assert_eq!(r.status, STATUS_INTERNAL_ERROR);
        assert_eq!(err_code(&r), "internal_error");
    }

    /// **This row's expectation was rewritten, and it therefore witnesses
    /// nothing on its own.** It asserted `400 invalid_params` for an absent
    /// §7a.2a triple; 0.8.2.17 makes an absent triple the *ambient-authority*
    /// input, which the handler must run rather than refuse — otherwise
    /// `origination.dispatch_outbound_ambient_refused` cannot reach the arm it
    /// scores, which is what it did against this peer. A test edited in the same
    /// commit as the behaviour is not an independent witness of the behaviour,
    /// so the evidence for this change is the cross-impl run and the control
    /// below, not this line going green.
    #[tokio::test]
    async fn dispatch_with_no_reentry_authority_runs_on_ambient_authority() {
        let h = DispatchOutboundHandler::new(PID);
        let r = h
            .handle(&ctx_with_fn("dispatch", dispatch_params_no_reentry()))
            .await
            .unwrap();
        assert_ne!(
            r.status, STATUS_BAD_REQUEST,
            "an absent triple selects §1.4's ambient arm; refusing here makes \
             the arm unmeasurable from the wire"
        );
    }

    /// **The control, and it is the row that says this was a discrimination and
    /// not a deletion.** An incomplete authority set is a malformed §7a.1
    /// request, not an ambient dispatch — the handler must still refuse it.
    /// Without this, "the absent set now runs" is indistinguishable from "the
    /// 400 was removed", and the check above would pass against a handler that
    /// accepts anything.
    ///
    /// Deliberately on the same handler and in the same file as the change, per
    /// the rule that a control is scoped to the code path its input takes:
    /// `dispatch_400_missing_target` refuses one branch earlier and would stay
    /// green through a relabel of this one.
    ///
    /// **Mutation verified, run not predicted**: collapsing the partial arm into
    /// the ambient arm (`if present && !complete` → `if false`) reddens **this
    /// row only** — `9 passed; 1 failed`, with
    /// `dispatch_with_no_reentry_authority_runs_on_ambient_authority` and
    /// `all_keys_present_but_both_arrays_empty_is_the_ambient_arm` both green.
    /// The two mutations' reddened rows are disjoint, which is what says this is
    /// a discrimination and not a widening.
    ///
    /// **Three rows, because the plural carrier gave "partial" three shapes**
    /// and §7a.1's all-or-none is stated over the *set*, not over a triple of
    /// scalars. An **empty array** is the one a singular-carrier reading gets
    /// wrong: `reentry_granters: []` is present-as-a-key and empty-as-a-value,
    /// and "absent and empty are the same fact for an optional array" is what
    /// makes it the ambient arm's shape rather than a fourth state — so the row
    /// that must refuse is credential-plus-empty-array, and it is exactly the
    /// row a `.is_some()`-on-the-key test would pass.
    #[tokio::test]
    async fn a_partial_reentry_set_is_still_a_malformed_request() {
        let h = DispatchOutboundHandler::new(PID);
        let cap = || entity_ecf::Value::Bytes(vec![0xa0]);
        let one = || entity_ecf::Value::Array(vec![entity_ecf::Value::Bytes(vec![0xa0])]);
        let empty = || entity_ecf::Value::Array(vec![]);
        let rows: Vec<(&str, Vec<(ciborium::value::Value, ciborium::value::Value)>)> = vec![
            // Credential alone — no granters, no signatures.
            (
                "cap only",
                vec![(entity_ecf::text("reentry_capability"), cap())],
            ),
            // Credential + granters, signatures missing entirely.
            (
                "cap + granters, no sigs",
                vec![
                    (entity_ecf::text("reentry_capability"), cap()),
                    (entity_ecf::text("reentry_granters"), one()),
                ],
            ),
            // Granters alone — no credential for them to authorize.
            (
                "granters only",
                vec![(entity_ecf::text("reentry_granters"), one())],
            ),
            // The plural-only shape: every key present, one array EMPTY.
            (
                "cap + empty granters + sigs",
                vec![
                    (entity_ecf::text("reentry_capability"), cap()),
                    (entity_ecf::text("reentry_granters"), empty()),
                    (entity_ecf::text("reentry_cap_signatures"), one()),
                ],
            ),
            (
                "cap + granters + empty sigs",
                vec![
                    (entity_ecf::text("reentry_capability"), cap()),
                    (entity_ecf::text("reentry_granters"), one()),
                    (entity_ecf::text("reentry_cap_signatures"), empty()),
                ],
            ),
        ];
        for (label, extra) in rows {
            let mut fields = vec![
                (
                    entity_ecf::text("target"),
                    entity_ecf::text("entity://x/system/validate/echo"),
                ),
                (entity_ecf::text("operation"), entity_ecf::text("echo")),
            ];
            fields.extend(extra);
            let params = Entity::new(
                "primitive/any",
                entity_ecf::to_ecf(&entity_ecf::Value::Map(fields)),
            )
            .unwrap();
            let r = h.handle(&ctx_with_fn("dispatch", params)).await.unwrap();
            assert_eq!(
                r.status, STATUS_BAD_REQUEST,
                "{label}: a partial set is neither a §7a.1 presented dispatch nor an ambient one"
            );
            assert_eq!(err_code(&r), "invalid_params", "{label}");
        }
    }

    /// **All three keys absent is the ambient arm — and all three present but
    /// BOTH arrays empty is the same fact, not a partial set.** This is the row
    /// the "absent and empty are the same fact" rule buys: a peer that keyed the
    /// presence test on the map key rather than on the array's length would
    /// refuse this input as partial, and PD-2's ambient arm would go unreachable
    /// again — the precise unmeasurability the 0.8.2.17 fix was about, coming
    /// back through the plural carrier.
    ///
    /// **Mutation verified, run not predicted**: keying `present` on
    /// `cbor_map_field_raw(...).is_some()` instead of on the decoded array's
    /// length reddens **this row only** (`9 passed; 1 failed`) — every partial
    /// row above stays green, because under that reading they are still partial.
    /// It is the one mutation the partial suite cannot see.
    #[tokio::test]
    async fn all_keys_present_but_both_arrays_empty_is_the_ambient_arm() {
        let h = DispatchOutboundHandler::new(PID);
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("target"),
                entity_ecf::text("entity://x/system/validate/echo"),
            ),
            (entity_ecf::text("operation"), entity_ecf::text("echo")),
            (
                entity_ecf::text("reentry_granters"),
                entity_ecf::Value::Array(vec![]),
            ),
            (
                entity_ecf::text("reentry_cap_signatures"),
                entity_ecf::Value::Array(vec![]),
            ),
        ]));
        let params = Entity::new("primitive/any", data).unwrap();
        let r = h.handle(&ctx_with_fn("dispatch", params)).await.unwrap();
        assert_ne!(
            r.status, STATUS_BAD_REQUEST,
            "two empty arrays and no credential is the ambient arm"
        );
    }

    /// A non-array in a plural carrier is malformed, and it is worth its own row
    /// because the singular shape was a bare entity — a peer that kept the old
    /// producer would send exactly this and must be told, not silently read as
    /// ambient.
    #[tokio::test]
    async fn a_singular_granter_where_an_array_belongs_is_malformed() {
        let h = DispatchOutboundHandler::new(PID);
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("target"),
                entity_ecf::text("entity://x/system/validate/echo"),
            ),
            (entity_ecf::text("operation"), entity_ecf::text("echo")),
            (
                entity_ecf::text("reentry_capability"),
                entity_ecf::Value::Bytes(vec![0xa0]),
            ),
            // The pre-0.8.2.19 shape: a bare entity, not an array of one.
            (
                entity_ecf::text("reentry_granters"),
                entity_ecf::Value::Bytes(vec![0xa0]),
            ),
            (
                entity_ecf::text("reentry_cap_signatures"),
                entity_ecf::Value::Array(vec![entity_ecf::Value::Bytes(vec![0xa0])]),
            ),
        ]));
        let params = Entity::new("primitive/any", data).unwrap();
        let r = h.handle(&ctx_with_fn("dispatch", params)).await.unwrap();
        assert_eq!(r.status, STATUS_BAD_REQUEST);
        assert_eq!(err_code(&r), "invalid_params");
    }

    /// **§7a.1 ⛔ — the scaffold's own grant, pinned.** Not hardening: an absent
    /// `internal_scope` falls back to `default_handler_self_grant()`, which is
    /// wide on Dimensions 1–3, and against a wide grant the compose reading and
    /// the bypass reading return the same answer for every input a probe can
    /// send. F63's wire discriminator is *unconstructible* at this seat until
    /// this returns a narrow set — so a silent drop of this method does not lose
    /// a defence, it deletes the only vector that can observe F67.
    ///
    /// Asserts the shape rather than equality with a fixture, so widening any
    /// one dimension to a wildcard reddens the row that names it.
    ///
    /// **Mutation verified, run not predicted**: making this method return
    /// `None` — the silent drop, which is the realistic failure since declining
    /// to override a defaulted trait method leaves no diff to review — reddens
    /// **this row only** (`9 passed; 1 failed`). Note what that measures and
    /// what it does not: it pins the *declaration*. The wire consequence is
    /// F63's `dispatch_outbound_narrow_grant_refuses_out_of_scope`, and per
    /// §7a.1 no in-tree row can stand in for it, because against a wide grant a
    /// compose and a bypass return the same answer for every input.
    #[test]
    fn dispatch_outbound_declares_a_narrow_internal_scope() {
        let scope = DispatchOutboundHandler::new(PID)
            .internal_scope()
            .expect("§7a.1 ⛔: dispatch-outbound MUST declare its own narrow grant");
        assert!(!scope.is_empty(), "an empty scope grants nothing at all");
        for g in &scope {
            assert_eq!(
                g.operations.include,
                vec!["echo".to_string()],
                "the declared minimum is the echo operation only, never a wildcard"
            );
            assert_eq!(
                g.handlers.include,
                vec![PATTERN_ECHO.to_string()],
                "the declared minimum is system/validate/echo only, never a wildcard"
            );
            assert!(
                g.peers.is_none(),
                "peers absent, not [*] — Dimension 4 is the one a target-minted \
                 credential relaxes, and a wildcard here makes it vacuous"
            );
        }
    }

    #[tokio::test]
    async fn dispatch_400_missing_target() {
        let h = DispatchOutboundHandler::new(PID);
        // Empty params map → no target/operation.
        let params = Entity::new("primitive/any", vec![0xa0]).unwrap();
        let r = h.handle(&ctx_with_fn("dispatch", params)).await.unwrap();
        assert_eq!(r.status, STATUS_BAD_REQUEST);
        assert_eq!(err_code(&r), "invalid_params");
    }
}
