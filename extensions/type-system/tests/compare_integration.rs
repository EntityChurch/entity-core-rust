//! End-to-end tests for `system/type:compare` and `system/type:compatible`.

use std::sync::Arc;

use ciborium::Value;
use entity_ecf::{cbor_map, text, ValueExt};
use entity_entity::Entity;
use entity_handler::{Handler, HandlerContext, HandlerResult, STATUS_OK};
use entity_store::{ContentStore, LocationIndex, MemoryContentStore, MemoryLocationIndex};
use entity_type_system::TypeHandler;

const PEER_ID: &str = "test-peer";

fn store_type_def(
    cs: &Arc<MemoryContentStore>,
    li: &Arc<MemoryLocationIndex>,
    name: &str,
    def: Value,
) {
    let entity = Entity::new("system/type", entity_ecf::to_ecf(&def)).unwrap();
    let hash = cs.put(entity).unwrap();
    li.set(&format!("/{}/system/type/{}", PEER_ID, name), hash);
}

fn run_op(handler: &TypeHandler, op: &str, params: Entity) -> HandlerResult {
    let ctx = HandlerContext::builder(params.clone(), params)
        .pattern(format!("/{}/system/type", PEER_ID))
        .operation(op)
        .request_id("test")
        .build();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(handler.handle(&ctx))
        .unwrap()
}

#[test]
fn compare_lists_only_a_only_b_and_shared() {
    let cs = Arc::new(MemoryContentStore::new());
    let li = Arc::new(MemoryLocationIndex::new());

    let def_a = cbor_map! {
        "name" => text("app/A"),
        "fields" => Value::Map(vec![
            (text("name"), cbor_map! { "type_ref" => text("primitive/string") }),
            (text("age"),  cbor_map! { "type_ref" => text("primitive/uint") }),
        ])
    };
    let def_b = cbor_map! {
        "name" => text("app/B"),
        "fields" => Value::Map(vec![
            (text("name"),  cbor_map! { "type_ref" => text("primitive/string") }),
            (text("email"), cbor_map! { "type_ref" => text("primitive/string") }),
        ])
    };
    store_type_def(&cs, &li, "app/A", def_a);
    store_type_def(&cs, &li, "app/B", def_b);

    let handler = TypeHandler::new(
        PEER_ID.to_string(),
        cs.clone() as Arc<dyn ContentStore>,
        li.clone() as Arc<dyn LocationIndex>,
    );
    let params_data = cbor_map! {
        "type_a" => text("system/type/app/A"),
        "type_b" => text("system/type/app/B")
    };
    let params = Entity::new(
        "system/type/compare-request",
        entity_ecf::to_ecf(&params_data),
    )
    .unwrap();
    let res = run_op(&handler, "compare", params);
    assert_eq!(res.status, STATUS_OK);
    let result: Value = ciborium::from_reader(res.result.data.as_slice()).unwrap();
    let only_a: Vec<String> = result
        .get("only_a")
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|v| v.as_text().map(String::from))
        .collect();
    let only_b: Vec<String> = result
        .get("only_b")
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|v| v.as_text().map(String::from))
        .collect();
    assert!(only_a.contains(&"age".to_string()));
    assert!(only_b.contains(&"email".to_string()));
    let shared = result
        .get("shared")
        .and_then(|v| v.as_map().cloned())
        .unwrap();
    assert!(shared.iter().any(|(k, _)| k.as_text() == Some("name")));
}

#[test]
fn compatible_forward_only_when_b_has_extra_required() {
    let cs = Arc::new(MemoryContentStore::new());
    let li = Arc::new(MemoryLocationIndex::new());

    // A has just `name`. B requires `name` AND `email`. An entity of
    // type A satisfies B? No — B requires `email`. Backward (B → A)?
    // B has extra field; A's required fields are present; A doesn't
    // require email. So B can supply an entity satisfying A.
    let def_a = cbor_map! {
        "name" => text("app/A"),
        "fields" => Value::Map(vec![
            (text("name"), cbor_map! { "type_ref" => text("primitive/string") }),
        ])
    };
    let def_b = cbor_map! {
        "name" => text("app/B"),
        "fields" => Value::Map(vec![
            (text("name"),  cbor_map! { "type_ref" => text("primitive/string") }),
            (text("email"), cbor_map! { "type_ref" => text("primitive/string") }),
        ])
    };
    store_type_def(&cs, &li, "app/A", def_a);
    store_type_def(&cs, &li, "app/B", def_b);

    let handler = TypeHandler::new(
        PEER_ID.to_string(),
        cs.clone() as Arc<dyn ContentStore>,
        li.clone() as Arc<dyn LocationIndex>,
    );
    let params_data = cbor_map! {
        "type_a" => text("system/type/app/A"),
        "type_b" => text("system/type/app/B"),
        "direction" => text("bidirectional")
    };
    let params = Entity::new(
        "system/type/compatible-request",
        entity_ecf::to_ecf(&params_data),
    )
    .unwrap();
    let res = run_op(&handler, "compatible", params);
    let result: Value = ciborium::from_reader(res.result.data.as_slice()).unwrap();
    let level = result.get("level").and_then(|v| v.as_text()).unwrap();
    assert_eq!(level, "backward_only");
}

#[test]
fn compatible_fully_compatible_on_identical_schemas() {
    let cs = Arc::new(MemoryContentStore::new());
    let li = Arc::new(MemoryLocationIndex::new());

    let def = cbor_map! {
        "name" => text("app/X"),
        "fields" => Value::Map(vec![
            (text("name"), cbor_map! { "type_ref" => text("primitive/string") }),
        ])
    };
    store_type_def(&cs, &li, "app/X", def.clone());
    store_type_def(&cs, &li, "app/Y", def);

    let handler = TypeHandler::new(
        PEER_ID.to_string(),
        cs.clone() as Arc<dyn ContentStore>,
        li.clone() as Arc<dyn LocationIndex>,
    );
    let params_data = cbor_map! {
        "type_a" => text("system/type/app/X"),
        "type_b" => text("system/type/app/Y")
    };
    let params = Entity::new(
        "system/type/compatible-request",
        entity_ecf::to_ecf(&params_data),
    )
    .unwrap();
    let res = run_op(&handler, "compatible", params);
    let result: Value = ciborium::from_reader(res.result.data.as_slice()).unwrap();
    let level = result.get("level").and_then(|v| v.as_text()).unwrap();
    assert_eq!(level, "fully_compatible");
}

#[test]
fn compatible_incompatible_on_type_mismatch() {
    let cs = Arc::new(MemoryContentStore::new());
    let li = Arc::new(MemoryLocationIndex::new());

    let def_a = cbor_map! {
        "name" => text("app/A"),
        "fields" => Value::Map(vec![
            (text("v"), cbor_map! { "type_ref" => text("primitive/string") }),
        ])
    };
    let def_b = cbor_map! {
        "name" => text("app/B"),
        "fields" => Value::Map(vec![
            (text("v"), cbor_map! { "type_ref" => text("primitive/uint") }),
        ])
    };
    store_type_def(&cs, &li, "app/A", def_a);
    store_type_def(&cs, &li, "app/B", def_b);

    let handler = TypeHandler::new(
        PEER_ID.to_string(),
        cs.clone() as Arc<dyn ContentStore>,
        li.clone() as Arc<dyn LocationIndex>,
    );
    let params_data = cbor_map! {
        "type_a" => text("system/type/app/A"),
        "type_b" => text("system/type/app/B")
    };
    let params = Entity::new(
        "system/type/compatible-request",
        entity_ecf::to_ecf(&params_data),
    )
    .unwrap();
    let res = run_op(&handler, "compatible", params);
    let result: Value = ciborium::from_reader(res.result.data.as_slice()).unwrap();
    let level = result.get("level").and_then(|v| v.as_text()).unwrap();
    assert_eq!(level, "incompatible");
}

/// `PROPOSAL-TYPE-OPERATION-ERROR-TAXONOMY` §6a.3 — an unresolvable type on
/// `compare` / `compatible` is **404 `type_not_found`**, not bare `not_found`.
///
/// The status was already right and is not what this pins. §6a.2 derives the
/// 404 from the criterion rust filed against the proposal's own draft row —
/// *can the declared result type carry the outcome?* — and
/// `system/type/compatibility-report` has nowhere to say *"that path named
/// nothing"*, so it stays a lookup miss. §6a.3 then pins the **code**: bare
/// `not_found` is ambiguous with the entity-level 404 that `0.8.2.7`'s 404 row
/// carves out, so the cohort takes go's `type_not_found`, which names which
/// lookup missed. go was already there; py's single `not_found` moves too.
///
/// **Why this is a test and not a byte scan.** `not_found` is a *substring of*
/// `type_not_found`, so any assertion written as "the body contains
/// `not_found`" passes under both spellings and could not have failed against
/// the pre-fix code — the same shape as the substring assertion that let the
/// `code`-vs-`type` field defect survive three revisions one file over. This
/// reads the decoded `code` key and compares it whole.
///
/// Mutation: restore `error_entity("not_found", …)` at either arm of
/// `compare_error_result` → the matching row goes RED on the code, with the
/// status still 404.
#[test]
fn an_unresolvable_type_is_404_type_not_found_on_both_pairwise_ops() {
    fn code_of(res: &HandlerResult) -> Option<String> {
        let v: Value = ciborium::from_reader(res.result.data.as_slice()).expect("CBOR body");
        match v {
            Value::Map(m) => m
                .iter()
                .find(|(k, _)| k.as_text() == Some("code"))
                .and_then(|(_, val)| val.as_text().map(str::to_string)),
            _ => None,
        }
    }

    let cs = Arc::new(MemoryContentStore::new());
    let li = Arc::new(MemoryLocationIndex::new());
    // Only A exists. B is the missing lookup in every row below.
    store_type_def(
        &cs,
        &li,
        "app/A",
        cbor_map! {
            "name" => text("app/A"),
            "fields" => Value::Map(vec![
                (text("name"), cbor_map! { "type_ref" => text("primitive/string") }),
            ])
        },
    );
    let handler = TypeHandler::new(
        PEER_ID.to_string(),
        cs.clone() as Arc<dyn ContentStore>,
        li.clone() as Arc<dyn LocationIndex>,
    );

    let pairwise = |type_a: &str, type_b: &str| {
        Entity::new(
            "system/type/compare-request",
            entity_ecf::to_ecf(&cbor_map! {
                "type_a" => text(type_a),
                "type_b" => text(type_b)
            }),
        )
        .unwrap()
    };
    let missing = "system/type/app/does-not-exist";

    for op in ["compare", "compatible"] {
        // The missing type in each position, because the two `resolve` calls
        // are separate sites and a fix to one is not a fix to the other.
        for (label, a, b) in [
            ("type_a missing", missing, "system/type/app/A"),
            ("type_b missing", "system/type/app/A", missing),
        ] {
            let res = run_op(&handler, op, pairwise(a, b));
            assert_eq!(res.status, 404, "{op} / {label}: status");
            assert_eq!(
                code_of(&res).as_deref(),
                Some("type_not_found"),
                "{op} / {label}: §6a.3 pins the code to `type_not_found`; bare \
                 `not_found` is the spelling that ruling narrows, and it is a \
                 substring of the right answer so only a whole-value compare \
                 can tell them apart"
            );
        }
    }

    // Control: the pair that RESOLVES is still a 200, so the rows above are
    // measuring the missing type and not a `compare` that refuses everything.
    let res = run_op(
        &handler,
        "compare",
        pairwise("system/type/app/A", "system/type/app/A"),
    );
    assert_eq!(
        res.status, STATUS_OK,
        "a resolvable pair still compares — without this the 404 rows pass \
         against a handler that 404s unconditionally"
    );
}
