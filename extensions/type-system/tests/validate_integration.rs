//! End-to-end test for `system/type:validate`. Builds a content store +
//! location index, registers a `system/type` definition at the
//! conventional path, wires the standard constraint handler under a
//! mock ExecuteFn, and runs the type handler.

use std::sync::Arc;

use ciborium::Value;
use entity_ecf::{cbor_map, integer, text, ValueExt};
use entity_entity::Entity;
use entity_handler::{ExecuteOptions, Handler, HandlerContext, HandlerResult, STATUS_OK};
use entity_store::{ContentStore, LocationIndex, MemoryContentStore, MemoryLocationIndex};
use entity_type_system::{StandardConstraintHandler, TypeHandler};

const PEER_ID: &str = "test-peer";

fn store_type_def(
    cs: &Arc<MemoryContentStore>,
    li: &Arc<MemoryLocationIndex>,
    type_name: &str,
    type_data: Value,
) {
    let entity = Entity::new("system/type", entity_ecf::to_ecf(&type_data)).unwrap();
    let hash = cs.put(entity).unwrap();
    li.set(&format!("/{}/system/type/{}", PEER_ID, type_name), hash);
}

fn build_execute_fn(
    constraint_handler: Arc<StandardConstraintHandler>,
) -> entity_handler::ExecuteFn {
    Arc::new(move |handler_path, op, params, _opts: ExecuteOptions| {
        let ch = constraint_handler.clone();
        Box::pin(async move {
            let ctx = HandlerContext::builder(params.clone(), params)
                .pattern(handler_path)
                .operation(op)
                .request_id("test")
                .build();
            ch.handle(&ctx).await
        })
    })
}

fn validate_request(entity_type: &str, entity_data: Value) -> Entity {
    let inline = cbor_map! {
        "type" => text(entity_type),
        "data" => entity_data
    };
    let params = cbor_map! {
        "entity" => inline
    };
    Entity::new("system/type/validate-request", entity_ecf::to_ecf(&params)).unwrap()
}

fn run_validate(
    handler: &TypeHandler,
    params: Entity,
    exec: entity_handler::ExecuteFn,
) -> HandlerResult {
    let ctx = HandlerContext::builder(params.clone(), params)
        .pattern(format!("/{}/system/type", PEER_ID))
        .operation("validate")
        .request_id("test")
        .execute_fn(exec)
        .build();
    futures_block_on(handler.handle(&ctx)).unwrap()
}

// Tokio rt without depending on a runtime macro at file scope.
fn futures_block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

#[test]
fn validate_pass_through_constraint() {
    let cs = Arc::new(MemoryContentStore::new());
    let li = Arc::new(MemoryLocationIndex::new());

    // Type def: app/user with a `name` field carrying min_length=1
    // and max_length=10 constraints.
    let min_len_constraint = build_constraint(
        "system/type/constraint/min-length",
        cbor_map! {
            "min_length" => integer(1)
        },
    );
    let max_len_constraint = build_constraint(
        "system/type/constraint/max-length",
        cbor_map! {
            "max_length" => integer(10)
        },
    );
    let name_field = cbor_map! {
        "type_ref" => text("primitive/string"),
        "constraints" => entity_ecf::array(vec![min_len_constraint, max_len_constraint])
    };
    let type_def = cbor_map! {
        "name" => text("app/user"),
        "fields" => Value::Map(vec![
            (text("name"), name_field),
        ])
    };
    store_type_def(&cs, &li, "app/user", type_def);

    // Wire handlers.
    let constraint_handler = Arc::new(StandardConstraintHandler::new(PEER_ID.to_string()));
    let exec = build_execute_fn(constraint_handler);
    let type_handler = TypeHandler::new(
        PEER_ID.to_string(),
        cs.clone() as Arc<dyn ContentStore>,
        li.clone() as Arc<dyn LocationIndex>,
    );

    // Valid case: name = "alice" (5 chars).
    let entity_data = cbor_map! {
        "name" => text("alice")
    };
    let req = validate_request("app/user", entity_data);
    let res = run_validate(&type_handler, req, exec.clone());
    assert_eq!(res.status, STATUS_OK);
    let result: Value = ciborium::from_reader(res.result.data.as_slice()).unwrap();
    assert_eq!(result.get("valid").and_then(|v| v.as_bool()), Some(true));
}

#[test]
fn validate_reports_constraint_violation() {
    let cs = Arc::new(MemoryContentStore::new());
    let li = Arc::new(MemoryLocationIndex::new());

    let max_len_constraint = build_constraint(
        "system/type/constraint/max-length",
        cbor_map! {
            "max_length" => integer(3)
        },
    );
    let name_field = cbor_map! {
        "type_ref" => text("primitive/string"),
        "constraints" => entity_ecf::array(vec![max_len_constraint])
    };
    let type_def = cbor_map! {
        "name" => text("app/user"),
        "fields" => Value::Map(vec![
            (text("name"), name_field),
        ])
    };
    store_type_def(&cs, &li, "app/user", type_def);

    let constraint_handler = Arc::new(StandardConstraintHandler::new(PEER_ID.to_string()));
    let exec = build_execute_fn(constraint_handler);
    let type_handler = TypeHandler::new(
        PEER_ID.to_string(),
        cs.clone() as Arc<dyn ContentStore>,
        li.clone() as Arc<dyn LocationIndex>,
    );

    let entity_data = cbor_map! {
        "name" => text("ALongName")
    };
    let req = validate_request("app/user", entity_data);
    let res = run_validate(&type_handler, req, exec);
    assert_eq!(res.status, STATUS_OK);
    let result: Value = ciborium::from_reader(res.result.data.as_slice()).unwrap();
    assert_eq!(result.get("valid").and_then(|v| v.as_bool()), Some(false));
    let violations = result
        .get("violations")
        .and_then(|v| v.as_array().cloned())
        .unwrap();
    assert_eq!(violations.len(), 1);
    let kind = violations[0].get("kind").and_then(|v| v.as_text()).unwrap();
    assert_eq!(kind, "constraint");
    let constraint = violations[0]
        .get("constraint")
        .and_then(|v| v.as_text())
        .unwrap();
    assert_eq!(constraint, "system/type/constraint/max-length");
}

#[test]
fn validate_unknown_constraint_kind_classified() {
    let cs = Arc::new(MemoryContentStore::new());
    let li = Arc::new(MemoryLocationIndex::new());

    let unknown = build_constraint("system/type/constraint/no-such-kind", cbor_map! {});
    let name_field = cbor_map! {
        "type_ref" => text("primitive/string"),
        "constraints" => entity_ecf::array(vec![unknown])
    };
    let type_def = cbor_map! {
        "name" => text("app/user"),
        "fields" => Value::Map(vec![
            (text("name"), name_field),
        ])
    };
    store_type_def(&cs, &li, "app/user", type_def);

    let constraint_handler = Arc::new(StandardConstraintHandler::new(PEER_ID.to_string()));
    let exec = build_execute_fn(constraint_handler);
    let type_handler = TypeHandler::new(
        PEER_ID.to_string(),
        cs.clone() as Arc<dyn ContentStore>,
        li.clone() as Arc<dyn LocationIndex>,
    );

    let entity_data = cbor_map! {
        "name" => text("anything")
    };
    let req = validate_request("app/user", entity_data);
    let res = run_validate(&type_handler, req, exec);
    let result: Value = ciborium::from_reader(res.result.data.as_slice()).unwrap();
    assert_eq!(result.get("valid").and_then(|v| v.as_bool()), Some(false));
    let violations = result
        .get("violations")
        .and_then(|v| v.as_array().cloned())
        .unwrap();
    let kind = violations[0].get("kind").and_then(|v| v.as_text()).unwrap();
    assert_eq!(kind, "unknown_constraint");
}

#[test]
fn validate_required_field_missing_is_structural() {
    let cs = Arc::new(MemoryContentStore::new());
    let li = Arc::new(MemoryLocationIndex::new());

    let name_field = cbor_map! {
        "type_ref" => text("primitive/string")
    };
    let type_def = cbor_map! {
        "name" => text("app/user"),
        "fields" => Value::Map(vec![
            (text("name"), name_field),
        ])
    };
    store_type_def(&cs, &li, "app/user", type_def);

    let constraint_handler = Arc::new(StandardConstraintHandler::new(PEER_ID.to_string()));
    let exec = build_execute_fn(constraint_handler);
    let type_handler = TypeHandler::new(
        PEER_ID.to_string(),
        cs.clone() as Arc<dyn ContentStore>,
        li.clone() as Arc<dyn LocationIndex>,
    );

    // Entity with no name field.
    let req = validate_request("app/user", Value::Map(vec![]));
    let res = run_validate(&type_handler, req, exec);
    let result: Value = ciborium::from_reader(res.result.data.as_slice()).unwrap();
    assert_eq!(result.get("valid").and_then(|v| v.as_bool()), Some(false));
    let violations = result
        .get("violations")
        .and_then(|v| v.as_array().cloned())
        .unwrap();
    assert_eq!(violations.len(), 1);
    let kind = violations[0].get("kind").and_then(|v| v.as_text()).unwrap();
    assert_eq!(kind, "structural");
}

#[test]
fn validate_optional_field_absent_skips_constraints() {
    let cs = Arc::new(MemoryContentStore::new());
    let li = Arc::new(MemoryLocationIndex::new());

    let min_constraint = build_constraint(
        "system/type/constraint/min-length",
        cbor_map! {
            "min_length" => integer(1)
        },
    );
    let name_field = cbor_map! {
        "type_ref" => text("primitive/string"),
        "optional" => entity_ecf::bool_val(true),
        "constraints" => entity_ecf::array(vec![min_constraint])
    };
    let type_def = cbor_map! {
        "name" => text("app/user"),
        "fields" => Value::Map(vec![
            (text("name"), name_field),
        ])
    };
    store_type_def(&cs, &li, "app/user", type_def);

    let constraint_handler = Arc::new(StandardConstraintHandler::new(PEER_ID.to_string()));
    let exec = build_execute_fn(constraint_handler);
    let type_handler = TypeHandler::new(
        PEER_ID.to_string(),
        cs.clone() as Arc<dyn ContentStore>,
        li.clone() as Arc<dyn LocationIndex>,
    );

    let req = validate_request("app/user", Value::Map(vec![]));
    let res = run_validate(&type_handler, req, exec);
    let result: Value = ciborium::from_reader(res.result.data.as_slice()).unwrap();
    assert_eq!(result.get("valid").and_then(|v| v.as_bool()), Some(true));
}

#[test]
fn validate_type_not_resolved_reports_structural() {
    let cs = Arc::new(MemoryContentStore::new());
    let li = Arc::new(MemoryLocationIndex::new());

    let constraint_handler = Arc::new(StandardConstraintHandler::new(PEER_ID.to_string()));
    let exec = build_execute_fn(constraint_handler);
    let type_handler = TypeHandler::new(
        PEER_ID.to_string(),
        cs.clone() as Arc<dyn ContentStore>,
        li.clone() as Arc<dyn LocationIndex>,
    );

    let req = validate_request("app/missing", Value::Map(vec![]));
    let res = run_validate(&type_handler, req, exec);
    let result: Value = ciborium::from_reader(res.result.data.as_slice()).unwrap();
    assert_eq!(result.get("valid").and_then(|v| v.as_bool()), Some(false));
}

#[test]
fn validate_one_of_with_mixed_types_matches_string() {
    // Mirrors the cross-impl conformance scenario: a string value
    // validates against a one_of list containing strings + numbers
    // (heterogeneous). The §5.5 ECF byte-equality rule MUST find the
    // matching string regardless of other element types.
    let cs = Arc::new(MemoryContentStore::new());
    let li = Arc::new(MemoryLocationIndex::new());

    let one_of_constraint = build_constraint(
        "system/type/constraint/one-of",
        cbor_map! {
            "values" => entity_ecf::array(vec![
                text("alice"),
                text("bob"),
                integer(42),
            ])
        },
    );
    let name_field = cbor_map! {
        "type_ref" => text("primitive/string"),
        "constraints" => entity_ecf::array(vec![one_of_constraint])
    };
    let type_def = cbor_map! {
        "name" => text("app/user"),
        "fields" => Value::Map(vec![
            (text("name"), name_field)
        ])
    };
    store_type_def(&cs, &li, "app/user", type_def);

    let constraint_handler = Arc::new(StandardConstraintHandler::new(PEER_ID.to_string()));
    let exec = build_execute_fn(constraint_handler);
    let type_handler = TypeHandler::new(
        PEER_ID.to_string(),
        cs.clone() as Arc<dyn ContentStore>,
        li.clone() as Arc<dyn LocationIndex>,
    );

    let entity_data = cbor_map! { "name" => text("alice") };
    let req = validate_request("app/user", entity_data);
    let res = run_validate(&type_handler, req, exec);
    let result: Value = ciborium::from_reader(res.result.data.as_slice()).unwrap();
    assert_eq!(
        result.get("valid").and_then(|v| v.as_bool()),
        Some(true),
        "one_of must accept matching string from heterogeneous list, got: {:?}",
        result
    );
}

#[test]
fn validate_narrowing_violation_on_child_type_def() {
    let cs = Arc::new(MemoryContentStore::new());
    let li = Arc::new(MemoryLocationIndex::new());

    // Parent type with min=5 on `age`.
    let parent_min = build_constraint(
        "system/type/constraint/min",
        cbor_map! {
            "min" => integer(5)
        },
    );
    let parent_age_field = cbor_map! {
        "type_ref" => text("primitive/uint"),
        "constraints" => entity_ecf::array(vec![parent_min])
    };
    let parent_def = cbor_map! {
        "name" => text("base/with-min"),
        "fields" => Value::Map(vec![
            (text("age"), parent_age_field)
        ])
    };
    store_type_def(&cs, &li, "base/with-min", parent_def);

    // Child type that WIDENS min — should narrow but widens (min=0).
    let child_min = build_constraint(
        "system/type/constraint/min",
        cbor_map! {
            "min" => integer(0)
        },
    );
    let child_age_field = cbor_map! {
        "type_ref" => text("primitive/uint"),
        "constraints" => entity_ecf::array(vec![child_min])
    };
    let child_def = cbor_map! {
        "name" => text("derived/widened"),
        "extends" => text("base/with-min"),
        "fields" => Value::Map(vec![
            (text("age"), child_age_field)
        ])
    };
    // Validate the child type definition itself by passing the
    // `system/type` entity as the entity to validate.
    // We also need `system/type` registered so structural phase
    // doesn't fail trying to resolve it (it's a core type with no fields
    // requirement). Register the bootstrap system/type definition.
    let system_type_def = cbor_map! {
        "name" => text("system/type"),
        "fields" => Value::Map(vec![])
    };
    store_type_def(&cs, &li, "system/type", system_type_def);

    let constraint_handler = Arc::new(StandardConstraintHandler::new(PEER_ID.to_string()));
    let exec = build_execute_fn(constraint_handler);
    let type_handler = TypeHandler::new(
        PEER_ID.to_string(),
        cs.clone() as Arc<dyn ContentStore>,
        li.clone() as Arc<dyn LocationIndex>,
    );

    let req = validate_request("system/type", child_def);
    let res = run_validate(&type_handler, req, exec);
    let result: Value = ciborium::from_reader(res.result.data.as_slice()).unwrap();
    assert_eq!(result.get("valid").and_then(|v| v.as_bool()), Some(false));
    let violations = result
        .get("violations")
        .and_then(|v| v.as_array().cloned())
        .unwrap();
    let narrowing_violations: Vec<&Value> = violations
        .iter()
        .filter(|v| {
            v.get("reason")
                .and_then(|r| r.as_text())
                .map(|s| s.contains("narrowing violation"))
                .unwrap_or(false)
        })
        .collect();
    assert!(
        !narrowing_violations.is_empty(),
        "expected at least one narrowing violation, got {:?}",
        violations
    );
}

// Build a constraint entry inline-shaped: {content_hash: ..., data:
// <inline>, type: text}. content_hash is computed but not load-bearing
// for the validate path (the type handler looks at type+data only).
fn build_constraint(constraint_type: &str, data: Value) -> Value {
    let data_bytes = entity_ecf::to_ecf(&data);
    let hash = entity_hash::Hash::compute(constraint_type, &data_bytes);
    cbor_map! {
        "content_hash" => Value::Bytes(hash.to_bytes().to_vec()),
        "data" => data,
        "type" => text(constraint_type)
    }
}

// ---------------------------------------------------------------------------
// PROPOSAL-TYPE-OPERATION-ERROR-TAXONOMY §2 / §3 — the two claims routed to
// this seat, pinned so the fold has something to cite besides prose.
// ---------------------------------------------------------------------------

/// §2, the load-bearing half: **a typing verdict is a `200`, never a `400`.**
///
/// `system/type/validate-result` carries `valid: bool` + `violations`, so "this
/// entity does not conform" is the *payload* of a successful analysis, not a
/// refusal of the request. A peer that answered `400` for `valid: false` would
/// make the operation useless to a caller doing schema exploration — every
/// answer it is asking for arrives as an error — and nothing in the landed
/// `EXTENSION-TYPE` text stops it, because that document declares zero error
/// codes. The proposal asks whether this is already true here. It is, and both
/// halves are asserted rather than the first one only.
///
/// **The second row is the one worth the proposal's attention.** An
/// *unresolvable type* is also a `200` with `valid: false` and a `structural`
/// violation here — NOT the `404 not_found` the proposal's §3 table row 4
/// proposes. That is a deliberate split against `compare`/`compatible`, which
/// do answer 404: `validate-result` has a field that can *express* "I could not
/// resolve the type" as an outcome, and `compatibility-report` has no such
/// field, so the same input is an outcome on one operation and a lookup miss on
/// the other. Routed rather than assumed — if the fold takes row 4 as written,
/// this row is what flips.
#[test]
fn a_failed_validation_is_a_200_and_an_unresolvable_type_is_too() {
    let cs = Arc::new(MemoryContentStore::new());
    let li = Arc::new(MemoryLocationIndex::new());

    // `app/user` requires `name`; the entity omits it.
    let type_def = cbor_map! {
        "name" => text("app/user"),
        "fields" => Value::Map(vec![
            (text("name"), cbor_map! { "type_ref" => text("primitive/string") }),
        ])
    };
    store_type_def(&cs, &li, "app/user", type_def);

    let constraint_handler = Arc::new(StandardConstraintHandler::new(PEER_ID.to_string()));
    let type_handler = TypeHandler::new(
        PEER_ID.to_string(),
        cs.clone() as Arc<dyn ContentStore>,
        li.clone() as Arc<dyn LocationIndex>,
    );

    let res = run_validate(
        &type_handler,
        validate_request("app/user", Value::Map(vec![])),
        build_execute_fn(constraint_handler.clone()),
    );
    let result: Value = ciborium::from_reader(res.result.data.as_slice()).unwrap();
    assert_eq!(
        (res.status, result.get("valid").and_then(|v| v.as_bool())),
        (STATUS_OK, Some(false)),
        "a validation FAILURE is a successful analysis: 200 with `valid: false`, \
         never a 4xx. This is the cross-peer-observable divergence the proposal \
         routes now rather than at fold time"
    );

    let res = run_validate(
        &type_handler,
        validate_request("app/missing", Value::Map(vec![])),
        build_execute_fn(constraint_handler),
    );
    let result: Value = ciborium::from_reader(res.result.data.as_slice()).unwrap();
    assert_eq!(
        (res.status, result.get("valid").and_then(|v| v.as_bool())),
        (STATUS_OK, Some(false)),
        "an UNRESOLVABLE type is also a 200 with `valid: false` on `validate` — \
         the result type can carry the outcome, so it is one. `compare` and \
         `compatible` answer 404 for the same input because their result type \
         cannot. Proposal §3 row 4 proposes 404 for both; this row is the \
         measurement it asked for and it disagrees"
    );
}

/// The forced rename: **`invalid_request`, never `bad_request`.**
///
/// `ENTITY-CORE-PROTOCOL` §4.7 — *"Extension specifications use this code for
/// the same class and MUST NOT mint a synonym"* — and §3.3, which names
/// `invalid_request` the default 400 code. `bad_request` appears in no spec code
/// set. `EXTENSION-TYPE` declares no error codes at all, which is why this seat
/// had to pick one; that is arch's gap, and the rename is forced independent of
/// how the taxonomy proposal lands.
///
/// Asserting `!bad_request` on the encoded bytes rather than only
/// `invalid_request`: the error entity carries both a `type` and a `message`,
/// and a message that still said "bad request" would leave the retired spelling
/// on the wire for a client keying off it.
#[test]
fn a_malformed_validate_request_is_invalid_request_never_bad_request() {
    let cs = Arc::new(MemoryContentStore::new());
    let li = Arc::new(MemoryLocationIndex::new());
    let constraint_handler = Arc::new(StandardConstraintHandler::new(PEER_ID.to_string()));
    let type_handler = TypeHandler::new(
        PEER_ID.to_string(),
        cs.clone() as Arc<dyn ContentStore>,
        li.clone() as Arc<dyn LocationIndex>,
    );

    // A `validate-request` with no `entity` field at all — a defect of the
    // REQUEST, which is the whole (small) set that legitimately carries a code.
    let params = Entity::new(
        "system/type/validate-request",
        entity_ecf::to_ecf(&cbor_map! { "not_entity" => text("x") }),
    )
    .unwrap();
    let res = run_validate(&type_handler, params, build_execute_fn(constraint_handler));

    let has = |needle: &str| {
        res.result
            .data
            .windows(needle.len())
            .any(|w| w == needle.as_bytes())
    };
    assert!(
        res.status == 400 && has("invalid_request") && !has("bad_request"),
        "a request defect is 400 `invalid_request`; `bad_request` is a minted \
         synonym §4.7 forbids. Got status {}, invalid_request={}, \
         bad_request={}",
        res.status,
        has("invalid_request"),
        has("bad_request")
    );
}

/// §3.3's code slot is a property of the **`code` field**, not of the spelling
/// appearing somewhere in the body.
///
/// Both handlers in this crate shadowed `entity_handler::error_entity` with a
/// local copy that wrote the code under key `type`, so every error they emitted
/// decoded to `code = absent` at a conformant reader — including the
/// `unsupported_operation` spelling the 0.8.2.7 slot sweep had just landed here,
/// and including `system/protocol/error`'s own REQUIRED `code` field
/// (`core/types::system_protocol_error`). core-go's corrected `checkOptionalOp`
/// is what surfaced it; nothing in this tree could.
///
/// Note why the neighbour above cannot stand in for this: it scans the body for
/// a **substring**, and `invalid_request` is present under `type` and under
/// `code` alike — it passes under both shapes. The discriminator is the KEY, so
/// this asserts on the decoded map key and never on a byte scan or a round-trip
/// through our own reader.
#[test]
fn every_type_handler_error_carries_its_code_in_the_code_field() {
    fn error_fields(data: &[u8]) -> Vec<(String, String)> {
        let v: Value = ciborium::from_reader(data).expect("error body is CBOR");
        match v {
            Value::Map(m) => m
                .iter()
                .filter_map(|(k, val)| {
                    Some((
                        k.as_text()?.to_string(),
                        val.as_text().unwrap_or("<non-text>").to_string(),
                    ))
                })
                .collect(),
            _ => panic!("error body is not a map"),
        }
    }

    fn assert_coded(label: &str, res: &HandlerResult, want_status: u32, want_code: &str) {
        assert_eq!(res.status, want_status, "{label}: status");
        assert_eq!(
            res.result.entity_type, "system/protocol/error",
            "{label}: entity type"
        );
        let fields = error_fields(&res.result.data);
        let code = fields.iter().find(|(k, _)| k == "code").map(|(_, v)| v);
        assert_eq!(
            code.map(String::as_str),
            Some(want_code),
            "{label}: the code MUST be under key `code`. Got fields {fields:?}"
        );
        assert!(
            !fields.iter().any(|(k, _)| k == "type"),
            "{label}: `type` is not a field of system/protocol/error. Got {fields:?}"
        );
    }

    let cs = Arc::new(MemoryContentStore::new());
    let li = Arc::new(MemoryLocationIndex::new());
    let constraint_handler = Arc::new(StandardConstraintHandler::new(PEER_ID.to_string()));
    let type_handler = TypeHandler::new(
        PEER_ID.to_string(),
        cs.clone() as Arc<dyn ContentStore>,
        li.clone() as Arc<dyn LocationIndex>,
    );

    // The 501 row — the spelling the slot sweep landed, in the field that
    // makes it readable. One row per handler: both shadowed the helper, so a
    // fix to one is not a fix to the other.
    let unknown_op = |pattern: String, op: &str| {
        let params = Entity::new(
            "system/type/validate-request",
            entity_ecf::to_ecf(&cbor_map! { "entity" => text("x") }),
        )
        .unwrap();
        HandlerContext::builder(params.clone(), params)
            .pattern(pattern)
            .operation(op)
            .request_id("test")
            .build()
    };

    let res = futures_block_on(
        type_handler.handle(&unknown_op(format!("/{}/system/type", PEER_ID), "converge")),
    )
    .unwrap();
    assert_coded("system/type unknown op", &res, 501, "unsupported_operation");

    let res = futures_block_on(constraint_handler.handle(&unknown_op(
        format!("/{}/system/type/constraint/max", PEER_ID),
        "converge",
    )))
    .unwrap();
    assert_coded(
        "system/type/constraint/* unknown op",
        &res,
        501,
        "unsupported_operation",
    );

    // The 400 row — same helper, so it drifted with it.
    let params = Entity::new(
        "system/type/validate-request",
        entity_ecf::to_ecf(&cbor_map! { "not_entity" => text("x") }),
    )
    .unwrap();
    let res = run_validate(&type_handler, params, build_execute_fn(constraint_handler));
    assert_coded(
        "system/type malformed request",
        &res,
        400,
        "invalid_request",
    );
}
