//! `system/type:validate` handler — two-phase validation (§2.3).
//!
//! Phase 1: structural validation (entity type matches, required fields
//! present). Phase 2: constraint dispatch — for each field-spec carrying
//! `constraints`, dispatch each constraint to the appropriate handler via
//! `ctx.execute_fn`. Resolution uses Strategy 1 (path-convention lookup)
//! per v1.1 §1.5.
//!
//! Unknown-constraint classification (§1.2 / §8.5):
//! - Dispatch returns valid=false with `reason` starting with "unknown
//!   constraint type:" or "unknown format:" → kind="unknown_constraint".
//! - Dispatch fails entirely (no handler matched, internal error) →
//!   kind="unknown_constraint" with reason capturing the dispatch failure.
//! - Otherwise valid=false → kind="constraint".
//!
//! **Error codes: `invalid_request`, never `bad_request`.** `EXTENSION-TYPE`
//! declares eight operations and *zero* error codes — grep it for
//! `invalid_request` / `invalid_params` / `bad_request` / `Errors:` and there
//! are no hits — so this seat, as the only one that has built these handlers,
//! had to pick one and picked a code in no spec code set. `ENTITY-CORE-PROTOCOL`
//! §4.7 forbids that independent of anything TYPE says: *"a well-formed frame
//! whose content the responder cannot act on as a request … is refused 400
//! `invalid_request`. … Extension specifications use this code for the same
//! class and MUST NOT mint a synonym."* §3.3 says the same from the other side —
//! `invalid_request` is the default 400 code. Eight sites here and in
//! `constraint.rs`; the rename is forced, not a taxonomy choice.
//!
//! **What is NOT an error code here, and it is the load-bearing half:** a
//! *typing verdict* is a `200`. `system/type/validate-result` carries
//! `valid: bool` + `violations`, so "this entity does not conform" is the
//! payload, not a refusal — including the unresolvable-type case, which returns
//! `valid: false` with a `structural` violation rather than a 404. Error codes
//! on these operations are reserved for defects of the *request*: the operation
//! could not be performed at all. Gated by
//! `a_failed_validation_is_a_200_and_an_unresolvable_type_is_too`.

use std::sync::Arc;

use async_trait::async_trait;
use ciborium::Value;
use entity_ecf::ValueExt;
use entity_entity::Entity;
use entity_handler::{
    error_entity, ExecuteOptions, Handler, HandlerContext, HandlerError, HandlerResult,
    STATUS_BAD_REQUEST, STATUS_NOT_SUPPORTED, STATUS_OK,
};
use entity_store::LocationIndex;
use entity_types::{TYPE_VALIDATE_RES, TYPE_VIOLATION};

use crate::{compare, narrowing};

/// `system/type` handler — validate (R-T3 of EXTENSION-TYPE v1.1).
pub struct TypeHandler {
    qualified_pattern: String,
    local_peer_id: String,
    content_store: Arc<dyn entity_store::ContentStore>,
    location_index: Arc<dyn LocationIndex>,
}

impl TypeHandler {
    pub fn new(
        local_peer_id: String,
        content_store: Arc<dyn entity_store::ContentStore>,
        location_index: Arc<dyn LocationIndex>,
    ) -> Self {
        let qualified_pattern = format!("/{}/system/type", local_peer_id);
        Self {
            qualified_pattern,
            local_peer_id,
            content_store,
            location_index,
        }
    }

    /// Look up a type definition by name via Strategy 1
    /// (`system/type/{name}` path lookup). Returns the decoded data
    /// (ciborium Value of the `system/type` entity's data map) and the
    /// canonical name.
    fn resolve_type(&self, name: &str) -> Option<Value> {
        let path = format!("/{}/system/type/{}", self.local_peer_id, name);
        let hash = self.location_index.get(&path)?;
        let entity = self.content_store.get(&hash)?;
        if entity.entity_type != "system/type" {
            return None;
        }
        ciborium::from_reader(entity.data.as_slice()).ok()
    }

    async fn handle_validate(&self, ctx: &HandlerContext) -> HandlerResult {
        // Decode the validate-request.
        let params_value: Value = match ciborium::from_reader(ctx.params.data.as_slice()) {
            Ok(v) => v,
            Err(e) => {
                return HandlerResult::error(
                    STATUS_BAD_REQUEST,
                    error_entity("invalid_request", &format!("decode params: {}", e)),
                );
            }
        };
        let (entity_value, type_path_override) = match parse_validate_request(&params_value) {
            Ok(t) => t,
            Err(e) => {
                return HandlerResult::error(
                    STATUS_BAD_REQUEST,
                    error_entity("invalid_request", &e),
                );
            }
        };

        // Extract the entity's type + data from the inline core/entity map.
        let entity_type = match entity_value.get("type").and_then(|v| v.as_text()) {
            Some(s) => s.to_string(),
            None => {
                return HandlerResult::error(
                    STATUS_BAD_REQUEST,
                    error_entity("invalid_request", "entity.type missing"),
                );
            }
        };
        let entity_data = entity_value
            .get("data")
            .cloned()
            .unwrap_or(Value::Map(vec![]));

        // Resolve type definition by Strategy 1.
        let type_name = type_path_override.unwrap_or(entity_type.clone());
        let type_def_data = match self.resolve_type(&type_name) {
            Some(v) => v,
            None => {
                // Type not found → report as structural violation.
                let violations = vec![Violation {
                    field: String::new(),
                    kind: "structural".to_string(),
                    constraint: None,
                    reason: format!("type not resolved: {}", type_name),
                }];
                let result = ValidateResult {
                    valid: false,
                    violations,
                    unevaluated_fields: Vec::new(),
                };
                return HandlerResult::ok(result.to_entity());
            }
        };

        let mut violations: Vec<Violation> = Vec::new();
        let mut unevaluated_fields: Vec<String> = Vec::new();

        // Phase 1: structural validation (minimal — type match + required
        // field presence). Deep CBOR-type coercion checking belongs to
        // ENTITY-NATIVE-TYPE-SYSTEM core (not this extension); the Rust
        // kernel has no general structural validator yet — logged in
        // docs/SPEC-AMBIGUITIES.md as an impl gap. The validator here
        // covers what's locally derivable from a `system/type` entity.
        let fields_map = type_def_data
            .get("fields")
            .and_then(|v| v.as_map().map(|m| m.to_vec()))
            .unwrap_or_default();

        // The entity's data should be a map for fielded types.
        let entity_fields = entity_data.as_map().map(|m| m.to_vec()).unwrap_or_default();
        let present_keys: Vec<String> = entity_fields
            .iter()
            .filter_map(|(k, _)| k.as_text().map(String::from))
            .collect();

        for (k, spec_v) in &fields_map {
            let field_name = match k.as_text() {
                Some(s) => s.to_string(),
                None => continue,
            };
            let optional = spec_v
                .get("optional")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let value = entity_fields
                .iter()
                .find(|(k2, _)| k2.as_text() == Some(field_name.as_str()))
                .map(|(_, v)| v.clone());

            if value.is_none() {
                if !optional {
                    violations.push(Violation {
                        field: field_name.clone(),
                        kind: "structural".to_string(),
                        constraint: None,
                        reason: "required field missing".to_string(),
                    });
                }
                // Absent optional field: skip constraints (§2.3).
                continue;
            }
            let value = value.unwrap();

            // Phase 2: constraint dispatch for this field.
            let constraints = spec_v
                .get("constraints")
                .and_then(|v| v.as_array().cloned())
                .unwrap_or_default();
            for constraint in &constraints {
                let (c_type, c_data) = match decode_constraint(constraint) {
                    Some(t) => t,
                    None => continue,
                };
                let v = self
                    .dispatch_constraint(ctx, &value, &c_type, &c_data)
                    .await;
                match v {
                    DispatchOutcome::Valid => {}
                    DispatchOutcome::Invalid { reason } => {
                        let kind = classify_reason(&reason);
                        violations.push(Violation {
                            field: field_name.clone(),
                            kind: kind.to_string(),
                            constraint: Some(c_type.clone()),
                            reason,
                        });
                    }
                    DispatchOutcome::DispatchFailed { reason } => {
                        violations.push(Violation {
                            field: field_name.clone(),
                            kind: "unknown_constraint".to_string(),
                            constraint: Some(c_type.clone()),
                            reason: format!("constraint_dispatch_failed: {}", reason),
                        });
                    }
                }
            }
        }

        // §6.4 narrowing verification — when the entity being validated
        // IS a `system/type` definition with `extends`, walk the parent
        // chain and verify per-field per-constraint narrowing.
        if entity_type == "system/type" {
            let narrowing_violations = narrowing::verify_narrowing(
                &entity_data,
                &self.local_peer_id,
                &self.content_store,
                &self.location_index,
            );
            for nv in narrowing_violations {
                violations.push(Violation {
                    field: nv.field,
                    kind: "structural".to_string(),
                    constraint: if nv.constraint.is_empty() {
                        None
                    } else {
                        Some(nv.constraint)
                    },
                    reason: format!("narrowing violation: {}", nv.reason),
                });
            }
        }

        // Detect open-type extension fields the validator didn't interpret.
        // §8.4: at the type-definition level (e.g., unknown extension
        // fields on a system/type entity). For v1.1 baseline, we only
        // report field-spec-level extensions we don't recognize; this is
        // a forward-looking placeholder. Currently empty — known
        // extension fields (constraints) are evaluated above.
        let _ = &mut unevaluated_fields;
        let _ = &present_keys;

        let result = ValidateResult {
            valid: violations.is_empty(),
            violations,
            unevaluated_fields,
        };
        HandlerResult::ok(result.to_entity())
    }

    async fn dispatch_constraint(
        &self,
        ctx: &HandlerContext,
        value: &Value,
        constraint_type: &str,
        constraint_data: &Value,
    ) -> DispatchOutcome {
        let execute_fn = match ctx.execute_fn.as_ref() {
            Some(f) => f.clone(),
            None => {
                return DispatchOutcome::DispatchFailed {
                    reason: "no execute_fn".to_string(),
                };
            }
        };
        let req_data = entity_ecf::to_ecf(&Value::Map(vec![
            (entity_ecf::text("value"), value.clone()),
            (
                entity_ecf::text("constraint_type"),
                entity_ecf::text(constraint_type),
            ),
            (entity_ecf::text("constraint_data"), constraint_data.clone()),
        ]));
        let req = match Entity::new("system/type/constraint/validate-request", req_data) {
            Ok(e) => e,
            Err(e) => {
                return DispatchOutcome::DispatchFailed {
                    reason: format!("build request: {}", e),
                };
            }
        };
        let opts = ExecuteOptions::default();
        match execute_fn(
            constraint_type.to_string(),
            "validate".to_string(),
            req,
            opts,
        )
        .await
        {
            Ok(res) => {
                // Non-OK status from the dispatched handler (4xx/5xx)
                // means the handler couldn't evaluate the constraint —
                // classify as unknown_constraint per §1.2 fail-closed.
                if res.status != STATUS_OK {
                    DispatchOutcome::DispatchFailed {
                        reason: match entity_handler::decode_error_entity(&res.result) {
                            // The handler's own code, not just its status
                            // (R-7 extractor audit): "handler status 403"
                            // and "403 capability_denied" send a constraint
                            // author to very different places.
                            Some((Some(code), _)) => {
                                format!("handler status {} {}", res.status, code)
                            }
                            _ => format!("handler status {}", res.status),
                        },
                    }
                } else {
                    parse_dispatch_result(&res.result)
                }
            }
            Err(e) => DispatchOutcome::DispatchFailed {
                reason: format!("{}", e),
            },
        }
    }

    fn handle_compare(&self, ctx: &HandlerContext) -> HandlerResult {
        let value: Value = match ciborium::from_reader(ctx.params.data.as_slice()) {
            Ok(v) => v,
            Err(e) => {
                return HandlerResult::error(
                    STATUS_BAD_REQUEST,
                    error_entity("invalid_request", &format!("decode: {}", e)),
                );
            }
        };
        let type_a = value.get("type_a").and_then(|v| v.as_text()).unwrap_or("");
        let type_b = value.get("type_b").and_then(|v| v.as_text()).unwrap_or("");
        if type_a.is_empty() || type_b.is_empty() {
            return HandlerResult::error(
                STATUS_BAD_REQUEST,
                error_entity("invalid_request", "type_a and type_b required"),
            );
        }
        match compare::compare(
            type_a,
            type_b,
            &self.local_peer_id,
            &self.content_store,
            &self.location_index,
        ) {
            Ok(e) => HandlerResult::ok(e),
            Err(e) => compare_error_result(e),
        }
    }

    fn handle_compatible(&self, ctx: &HandlerContext) -> HandlerResult {
        let value: Value = match ciborium::from_reader(ctx.params.data.as_slice()) {
            Ok(v) => v,
            Err(e) => {
                return HandlerResult::error(
                    STATUS_BAD_REQUEST,
                    error_entity("invalid_request", &format!("decode: {}", e)),
                );
            }
        };
        let type_a = value.get("type_a").and_then(|v| v.as_text()).unwrap_or("");
        let type_b = value.get("type_b").and_then(|v| v.as_text()).unwrap_or("");
        let direction = value
            .get("direction")
            .and_then(|v| v.as_text())
            .unwrap_or("bidirectional");
        if type_a.is_empty() || type_b.is_empty() {
            return HandlerResult::error(
                STATUS_BAD_REQUEST,
                error_entity("invalid_request", "type_a and type_b required"),
            );
        }
        match compare::compatible(
            type_a,
            type_b,
            direction,
            &self.local_peer_id,
            &self.content_store,
            &self.location_index,
        ) {
            Ok(e) => HandlerResult::ok(e),
            Err(e) => compare_error_result(e),
        }
    }
}

/// The §8.5 row for a `compare` / `compatible` failure.
///
/// `PROPOSAL-TYPE-OPERATION-ERROR-TAXONOMY` §6a.2 derives the 404 by its own
/// criterion — *can the declared result type carry the outcome?* —
/// and `system/type/compatibility-report` cannot say *"that path named
/// nothing"*, so an unresolvable type is a lookup miss and nothing else.
/// §6a.3 pins the **code**: `type_not_found`, adopting core-go's spelling
/// (go was already there; py's bare `not_found` moves too). Ours was the bare
/// `not_found` that ruling narrows, and it was also answering the encode
/// failure — see [`CompareError`] for why that half was a wrong status class.
///
/// Cited to the **proposal** deliberately, not to `EXTENSION-TYPE` §8.5: the
/// section is un-folded and its number currently collides with the shipped
/// `system/type/violation`. This is behaviour, not a published declaration —
/// nothing here edits a type descriptor, so it lands seat-by-seat without the
/// first-seat-goes-red hazard that held `concat-args`.
fn compare_error_result(e: compare::CompareError) -> HandlerResult {
    match e {
        compare::CompareError::TypeNotFound(ref msg) => HandlerResult::error(
            entity_handler::STATUS_NOT_FOUND,
            error_entity("type_not_found", msg),
        ),
        compare::CompareError::Encode(ref msg) => HandlerResult::error(
            entity_handler::STATUS_INTERNAL_ERROR,
            error_entity("internal_error", msg),
        ),
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for TypeHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        match ctx.operation.as_str() {
            "validate" => Ok(self.handle_validate(ctx).await),
            "compare" => Ok(self.handle_compare(ctx)),
            "compatible" => Ok(self.handle_compatible(ctx)),
            other => Ok(HandlerResult::error(
                STATUS_NOT_SUPPORTED,
                error_entity(
                    "unsupported_operation",
                    &format!("system/type does not support {}", other),
                ),
            )),
        }
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "types"
    }

    fn operations(&self) -> &[&str] {
        &["validate", "compare", "compatible"]
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Violation {
    pub field: String,
    pub kind: String,
    pub constraint: Option<String>,
    pub reason: String,
}

impl Violation {
    pub fn to_entity(&self) -> Entity {
        let mut entries = vec![
            (entity_ecf::text("field"), entity_ecf::text(&self.field)),
            (entity_ecf::text("kind"), entity_ecf::text(&self.kind)),
            (entity_ecf::text("reason"), entity_ecf::text(&self.reason)),
        ];
        if let Some(ref c) = self.constraint {
            entries.push((entity_ecf::text("constraint"), entity_ecf::text(c)));
        }
        let data = entity_ecf::to_ecf(&Value::Map(entries));
        Entity::new(TYPE_VIOLATION, data).expect("violation entity")
    }
}

#[derive(Debug, Clone)]
pub struct ValidateResult {
    pub valid: bool,
    pub violations: Vec<Violation>,
    pub unevaluated_fields: Vec<String>,
}

impl ValidateResult {
    pub fn to_entity(&self) -> Entity {
        let mut entries = vec![(entity_ecf::text("valid"), entity_ecf::bool_val(self.valid))];
        if !self.violations.is_empty() {
            let arr: Vec<Value> = self
                .violations
                .iter()
                .map(|v| {
                    let e = v.to_entity();
                    let inner: Value =
                        ciborium::from_reader(e.data.as_slice()).unwrap_or(Value::Map(vec![]));
                    inner
                })
                .collect();
            entries.push((entity_ecf::text("violations"), entity_ecf::array(arr)));
        }
        if !self.unevaluated_fields.is_empty() {
            let arr: Vec<Value> = self
                .unevaluated_fields
                .iter()
                .map(|s| entity_ecf::text(s.as_str()))
                .collect();
            entries.push((
                entity_ecf::text("unevaluated_fields"),
                entity_ecf::array(arr),
            ));
        }
        let data = entity_ecf::to_ecf(&Value::Map(entries));
        Entity::new(TYPE_VALIDATE_RES, data).expect("validate-result entity")
    }
}

fn parse_validate_request(value: &Value) -> Result<(Value, Option<String>), String> {
    let map = value
        .as_map()
        .ok_or_else(|| "validate-request must be a map".to_string())?;
    let mut entity_v: Option<Value> = None;
    let mut type_path: Option<String> = None;
    for (k, v) in map {
        match k.as_text() {
            Some("entity") => entity_v = Some(v.clone()),
            Some("type_path") => type_path = v.as_text().map(String::from),
            _ => {}
        }
    }
    Ok((
        entity_v.ok_or_else(|| "missing entity".to_string())?,
        type_path,
    ))
}

/// Decode a constraint entry (`{type, data, content_hash}` shape) into
/// (constraint_type, inline constraint data).
fn decode_constraint(value: &Value) -> Option<(String, Value)> {
    let map = value.as_map()?;
    let mut c_type = None;
    let mut c_data = None;
    for (k, v) in map {
        match k.as_text() {
            Some("type") => c_type = v.as_text().map(String::from),
            Some("data") => c_data = Some(v.clone()),
            _ => {}
        }
    }
    Some((c_type?, c_data.unwrap_or(Value::Null)))
}

#[derive(Debug)]
enum DispatchOutcome {
    Valid,
    Invalid { reason: String },
    DispatchFailed { reason: String },
}

fn parse_dispatch_result(entity: &Entity) -> DispatchOutcome {
    let value: Value = match ciborium::from_reader(entity.data.as_slice()) {
        Ok(v) => v,
        Err(e) => {
            return DispatchOutcome::DispatchFailed {
                reason: format!("decode: {}", e),
            };
        }
    };
    let valid = value
        .get("valid")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let reason = value
        .get("reason")
        .and_then(|v| v.as_text())
        .map(String::from)
        .unwrap_or_default();
    if valid {
        DispatchOutcome::Valid
    } else {
        DispatchOutcome::Invalid { reason }
    }
}

fn classify_reason(reason: &str) -> &'static str {
    if reason.starts_with("unknown constraint type:") || reason.starts_with("unknown format:") {
        "unknown_constraint"
    } else {
        "constraint"
    }
}

// The error body is built by `entity_handler::error_entity`, never a local
// copy. §3.3's code slot is a claim about the `code` FIELD, not just the
// spelling: this file shadowed the canonical helper and wrote the code under
// key `type`, so every 400/404/501 it emitted decoded to `code = absent` at a
// conformant reader — including the `unsupported_operation` spelling the
// 0.8.2.7 slot sweep had just landed here. `system/protocol/error` declares
// `code` REQUIRED (`core/types::system_protocol_error`), so the local shape
// also violated our own published descriptor.

#[cfg(test)]
mod tests {
    use super::*;

    /// The other half of the `CompareError` split: an **encode** failure
    /// building the report is `500 internal_error`
    /// (`PROPOSAL-TYPE-OPERATION-ERROR-TAXONOMY` §3's last row), never the 404
    /// that its sibling variant takes.
    ///
    /// Both arms travelled as `Err(String)` through one `HandlerResult::error`
    /// call, so this failure — about a type that had already *resolved* —
    /// reached the caller as *"that type does not exist"*. Wrong status class,
    /// and the exact shape of the "one representation carrying two meanings"
    /// rule.
    ///
    /// **Why the mapping and not the wire, stated rather than hidden.** The
    /// `Encode` arm is not reachable through `compare()` with any input this
    /// suite can build — `Entity::new` refuses data our own encoder does not
    /// produce — so an integration row for it would be theater. What is
    /// testable, and is the thing the collapsed `Err(String)` got wrong, is
    /// **which row each variant takes**. Mutation: point either arm at the
    /// other's status/code and exactly one assertion below goes RED.
    #[test]
    fn compare_error_takes_one_row_per_variant() {
        let not_found =
            compare_error_result(compare::CompareError::TypeNotFound("type_b: x".into()));
        assert_eq!(not_found.status, entity_handler::STATUS_NOT_FOUND);
        assert_eq!(
            error_code_of(&not_found).as_deref(),
            Some("type_not_found"),
            "§6a.3 — an unresolvable type names which lookup missed"
        );

        let encode = compare_error_result(compare::CompareError::Encode("not ECF".into()));
        assert_eq!(
            encode.status,
            entity_handler::STATUS_INTERNAL_ERROR,
            "§3's last row — an encode failure is a 500, not a report that the \
             type is absent; the type resolved"
        );
        assert_eq!(error_code_of(&encode).as_deref(), Some("internal_error"));
    }

    /// Reads the decoded `code` **key**, never a substring of the body:
    /// `not_found` is a substring of `type_not_found`, so a byte scan cannot
    /// tell the pre-fix spelling from the fixed one.
    fn error_code_of(res: &HandlerResult) -> Option<String> {
        let v: ciborium::Value = ciborium::from_reader(res.result.data.as_slice()).ok()?;
        match v {
            ciborium::Value::Map(m) => m
                .iter()
                .find(|(k, _)| k.as_text() == Some("code"))
                .and_then(|(_, val)| val.as_text().map(str::to_string)),
            _ => None,
        }
    }
}
