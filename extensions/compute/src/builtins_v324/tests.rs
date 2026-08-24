//! Teeth for the v3.24 collection primitives and the v3.26 contained-error
//! boundary form.
//!
//! Every assertion here was run against the mutation it guards (the mutation is
//! named at the test). The ones that matter most are the **discriminators**:
//! `assoc`'s `index` and `assoc`'s `value` are the same operation and opposite
//! dispositions, so a uniform per-primitive rule fails exactly one arm, and a
//! test that exercises only one of them measures nothing.

use std::collections::HashMap;

use ciborium::Value;
use entity_ecf::ValueExt;
use entity_entity::Entity;
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex, MemoryContentStore, MemoryLocationIndex};

use crate::builtins::{BUILTIN_ASSOC, BUILTIN_CONCAT, BUILTIN_GROUP_BY, BUILTIN_RANGE};
use crate::eval::{evaluate, EvalContext};
use crate::types::*;

const TEST_PID: &str = "testpeer123456789012345678901234567890123456";

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

fn lit(value: Value) -> Entity {
    Entity::new(
        TYPE_LITERAL,
        entity_ecf::to_ecf(&entity_ecf::cbor_map! { "value" => value }),
    )
    .unwrap()
}

fn lit_int(n: i64) -> Entity {
    lit(entity_ecf::integer(n))
}

fn lit_array(items: Vec<Value>) -> Entity {
    lit(Value::Array(items))
}

fn ints(items: &[i64]) -> Vec<Value> {
    items.iter().copied().map(entity_ecf::integer).collect()
}

fn scope_lookup(name: &str) -> Entity {
    Entity::new(
        TYPE_LOOKUP_SCOPE,
        entity_ecf::to_ecf(&entity_ecf::cbor_map! { "name" => entity_ecf::text(name) }),
    )
    .unwrap()
}

fn lambda(params: &[&str], body: Hash) -> Entity {
    let data = entity_ecf::cbor_map! {
        "body" => Value::Bytes(body.to_bytes().to_vec()),
        "params" => Value::Array(params.iter().map(|p| Value::Text(p.to_string())).collect())
    };
    Entity::new(TYPE_LAMBDA, entity_ecf::to_ecf(&data)).unwrap()
}

fn arithmetic(op: &str, left: Hash, right: Hash) -> Entity {
    let data = entity_ecf::cbor_map! {
        "left" => Value::Bytes(left.to_bytes().to_vec()),
        "op" => entity_ecf::text(op),
        "right" => Value::Bytes(right.to_bytes().to_vec())
    };
    Entity::new(TYPE_ARITHMETIC, entity_ecf::to_ecf(&data)).unwrap()
}

fn construct(entity_type: &str, fields: &[(&str, Hash)]) -> Entity {
    let fields_map: Vec<(Value, Value)> = fields
        .iter()
        .map(|(name, hash)| {
            (
                Value::Text(name.to_string()),
                Value::Bytes(hash.to_bytes().to_vec()),
            )
        })
        .collect();
    let data = entity_ecf::cbor_map! {
        "entity_type" => entity_ecf::text(entity_type),
        "fields" => Value::Map(fields_map)
    };
    Entity::new(TYPE_CONSTRUCT, entity_ecf::to_ecf(&data)).unwrap()
}

fn apply(path: &str, args: &[(&str, Hash)]) -> Entity {
    let args_map: Vec<(Value, Value)> = args
        .iter()
        .map(|(name, hash)| {
            (
                Value::Text(name.to_string()),
                Value::Bytes(hash.to_bytes().to_vec()),
            )
        })
        .collect();
    let data = entity_ecf::cbor_map! {
        "args" => Value::Map(args_map),
        "operation" => entity_ecf::text("eval"),
        "path" => entity_ecf::text(path)
    };
    Entity::new(TYPE_APPLY, entity_ecf::to_ecf(&data)).unwrap()
}

/// A live `compute/error` **value** (the SA-1 form): an error entity carrying
/// the diagnostic `message` that §2.4 keeps out of the materialized bytes. It
/// cannot be embedded in frozen literal CBOR — a literal would round-trip it to
/// a bare map — so every contained-position fixture injects it by hash, exactly
/// as the corpus's shared `E` does.
fn seeded_error(cs: &MemoryContentStore, code: &str, message: &str) -> Hash {
    let data = entity_ecf::cbor_map! {
        "code" => entity_ecf::text(code),
        "message" => entity_ecf::text(message)
    };
    let e = Entity::new(TYPE_ERROR, entity_ecf::to_ecf(&data)).unwrap();
    cs.put(e).unwrap()
}

fn eval_entity(cs: &dyn ContentStore, li: &dyn LocationIndex, entity: &Entity) -> ComputeValue {
    let included: HashMap<Hash, Entity> = HashMap::new();
    let pid = TEST_PID.to_string();
    let mut budget = Budget::default_budget();
    let mut ctx = EvalContext::new(cs, li, &included, &pid);
    evaluate(entity, &Scope::new(), &mut budget, &mut ctx)
}

fn array_of(value: &ComputeValue) -> Vec<Value> {
    match value {
        ComputeValue::Primitive(Value::Array(items)) => items.clone(),
        other => panic!("expected an array result, got {:?}", other),
    }
}

fn error_code_of(value: &ComputeValue) -> String {
    match value {
        ComputeValue::Error(e) => e.code().to_string(),
        ComputeValue::Entity(e) if e.entity_type == TYPE_ERROR => decode_data(e)
            .as_ref()
            .and_then(|d| data_str(d, "code"))
            .unwrap_or_default(),
        other => panic!("expected an error result, got {:?}", other),
    }
}

fn hash_element(v: &Value) -> Hash {
    match v {
        Value::Bytes(b) => Hash::from_bytes(b).expect("element is a bare system/hash"),
        other => panic!("expected a bare system/hash element, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// range (§3.5, v3.25 C-3)
// ---------------------------------------------------------------------------

#[test]
fn range_produces_zero_to_n_minus_one_and_empty_at_zero() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    let three = cs.put(lit_int(3)).unwrap();
    let got = eval_entity(&cs, &li, &apply(BUILTIN_RANGE, &[("n", three)]));
    assert_eq!(array_of(&got), ints(&[0, 1, 2]));

    // CV-3 arm b — the anti-vacuity partner. Without it a peer that errors on
    // every `range` scores green on the negative arm alone.
    let zero = cs.put(lit_int(0)).unwrap();
    let got = eval_entity(&cs, &li, &apply(BUILTIN_RANGE, &[("n", zero)]));
    assert_eq!(array_of(&got), Vec::<Value>::new());
}

#[test]
fn range_negative_n_is_count_out_of_range_not_type_mismatch() {
    // CV-3 arm a. §2.2's cross-impl ruling: `int`/`uint` are annotations, not
    // distinct value types, so an out-of-domain MAGNITUDE is a domain error and
    // not a type error. Mutation run: returning `type_mismatch` here (v3.24's
    // wording, which v3.25 corrected) fails this test.
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let neg = cs.put(lit_int(-1)).unwrap();
    let got = eval_entity(&cs, &li, &apply(BUILTIN_RANGE, &[("n", neg)]));
    assert_eq!(error_code_of(&got), "count_out_of_range");
}

#[test]
fn range_n_above_the_representable_length_is_count_out_of_range() {
    // The second half of C-3's condition — "or an `n` exceeding the maximum
    // representable array length". A negative-only guard passes the arm above
    // and fails this one, which is why both are here.
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let huge = cs
        .put(lit(Value::Integer(ciborium::value::Integer::from(
            u64::MAX,
        ))))
        .unwrap();
    let got = eval_entity(&cs, &li, &apply(BUILTIN_RANGE, &[("n", huge)]));
    assert_eq!(error_code_of(&got), "count_out_of_range");
}

#[test]
fn range_beyond_the_budget_exhausts_rather_than_allocating() {
    // `n` is charged per produced element, so `range(huge)` reports
    // budget_exhausted instead of trying to build the array.
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let n = cs
        .put(lit_int(PEER_DEFAULT_MAX_OPS as i64 + 1_000))
        .unwrap();
    let got = eval_entity(&cs, &li, &apply(BUILTIN_RANGE, &[("n", n)]));
    assert_eq!(error_code_of(&got), "budget_exhausted");
}

// ---------------------------------------------------------------------------
// assoc (§3.5, v3.25 C-2) — and the v3.26 discriminator
// ---------------------------------------------------------------------------

#[test]
fn assoc_replaces_exactly_one_element() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let coll = cs.put(lit_array(ints(&[10, 20, 30]))).unwrap();
    let idx = cs.put(lit_int(1)).unwrap();
    let val = cs.put(lit_int(99)).unwrap();
    let got = eval_entity(
        &cs,
        &li,
        &apply(
            BUILTIN_ASSOC,
            &[("collection", coll), ("index", idx), ("value", val)],
        ),
    );
    assert_eq!(array_of(&got), ints(&[10, 99, 30]));
}

#[test]
fn assoc_out_of_range_index_is_index_out_of_range_on_both_magnitudes() {
    // CV-2 arms a and b. Both are required: an impl special-casing one
    // magnitude passes a single-arm test. The code is `index_out_of_range` —
    // the SAME code and condition as `compute/index` (§2.2), because one
    // document must not answer one malformed program with two codes depending
    // on which array operation it reached. Mutation run: `type_mismatch`
    // (v3.24's wording) fails both arms.
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let coll = cs.put(lit_array(ints(&[10, 20, 30]))).unwrap();
    let val = cs.put(lit_int(99)).unwrap();

    for bad in [-1i64, 3] {
        let idx = cs.put(lit_int(bad)).unwrap();
        let got = eval_entity(
            &cs,
            &li,
            &apply(
                BUILTIN_ASSOC,
                &[("collection", coll), ("index", idx), ("value", val)],
            ),
        );
        assert_eq!(
            error_code_of(&got),
            "index_out_of_range",
            "assoc index {} must be index_out_of_range",
            bad
        );
    }
}

#[test]
fn assoc_index_consumes_and_value_contains_the_same_error() {
    // **THE discriminator (CV-4b / CV-4a).** One operation, one error value,
    // two positions, opposite outcomes — §3.5's flow-through table is a claim
    // about POSITIONS, so a rule applied per-primitive fails exactly one of
    // these two arms and a test carrying only one arm cannot tell.
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let e = seeded_error(&cs, "seeded_error", "corner-vector seed E");
    let coll = cs.put(lit_array(ints(&[1, 2, 3]))).unwrap();

    // index = E → CONSUMED (read to position the write) → short-circuit to E.
    let nine = cs.put(lit_int(9)).unwrap();
    let got = eval_entity(
        &cs,
        &li,
        &apply(
            BUILTIN_ASSOC,
            &[("collection", coll), ("index", e), ("value", nine)],
        ),
    );
    assert_eq!(error_code_of(&got), "seeded_error");

    // value = E → CONTAINED (placed into the output) → [1, E, 3].
    let one = cs.put(lit_int(1)).unwrap();
    let got = eval_entity(
        &cs,
        &li,
        &apply(
            BUILTIN_ASSOC,
            &[("collection", coll), ("index", one), ("value", e)],
        ),
    );
    let items = array_of(&got);
    assert_eq!(items.len(), 3);
    assert_eq!(items[0], entity_ecf::integer(1));
    assert_eq!(items[2], entity_ecf::integer(3));

    // The contained element is a bare `system/hash` and its referent is
    // resident — a dangling reference is not a materialized value.
    let h = hash_element(&items[1]);
    let stored = cs.get(&h).expect("contained error is resident");
    assert_eq!(stored.entity_type, TYPE_ERROR);

    // …and it is CODE-ONLY. `message` is an in-flight diagnostic (§2.4) and
    // MUST NOT be in the bytes V7 content-addresses.
    let data = decode_data(&stored).expect("error data decodes");
    assert_eq!(data_str(&data, "code").as_deref(), Some("seeded_error"));
    match &data {
        Value::Map(fields) => assert_eq!(
            fields.len(),
            1,
            "§2.4: a materialized compute/error is code-only, got {:?}",
            fields
        ),
        other => panic!("expected a CBOR map, got {:?}", other),
    }
}

#[test]
fn a_contained_error_that_differs_only_in_message_yields_identical_array_bytes() {
    // The load-bearing property, and the one row that fails the mutation
    // *reference the SA-1 entity by its own content_hash* (i.e. dropping the
    // `materialize_error_value` re-canonicalization in `contained_element`).
    // Under that mutation both arrays are still well-formed and both still
    // "contain the error" — they simply disagree, which is exactly the
    // cross-impl fork §2.4 exists to prevent: two conformant peers whose
    // diagnostics differ would produce different bytes for the CONTAINING
    // array, on a string no spec pins.
    //
    // Note what the fixture carries that our own codec never emits: a
    // `message` field. A probe built from `ComputeError::to_entity` is
    // code-only by construction, so it passes under both implementations and
    // proves nothing.
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let coll = cs.put(lit_array(ints(&[1, 2, 3]))).unwrap();
    let idx = cs.put(lit_int(1)).unwrap();

    let mut encodings = Vec::new();
    for message in ["one wording", "an entirely different wording"] {
        let e = seeded_error(&cs, "seeded_error", message);
        let got = eval_entity(
            &cs,
            &li,
            &apply(
                BUILTIN_ASSOC,
                &[("collection", coll), ("index", idx), ("value", e)],
            ),
        );
        encodings.push(entity_ecf::to_ecf(&Value::Array(array_of(&got))));
    }
    assert_eq!(
        encodings[0], encodings[1],
        "§3.5 v3.26: a contained error is code-only, so the containing array's \
         bytes MUST NOT depend on the error's message"
    );
}

// ---------------------------------------------------------------------------
// concat (§3.5, v3.25 C-4)
// ---------------------------------------------------------------------------

#[test]
fn concat_joins_one_level_and_preserves_order() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let colls = cs
        .put(lit(Value::Array(vec![
            Value::Array(ints(&[1, 2])),
            Value::Array(ints(&[3, 4, 5])),
        ])))
        .unwrap();
    let got = eval_entity(&cs, &li, &apply(BUILTIN_CONCAT, &[("collections", colls)]));
    assert_eq!(array_of(&got), ints(&[1, 2, 3, 4, 5]));
}

#[test]
fn concat_of_nothing_is_empty_and_concat_of_one_is_identity() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    let none = cs.put(lit(Value::Array(vec![]))).unwrap();
    let got = eval_entity(&cs, &li, &apply(BUILTIN_CONCAT, &[("collections", none)]));
    assert_eq!(array_of(&got), Vec::<Value>::new());

    let one = cs
        .put(lit(Value::Array(vec![Value::Array(ints(&[7, 8]))])))
        .unwrap();
    let got = eval_entity(&cs, &li, &apply(BUILTIN_CONCAT, &[("collections", one)]));
    assert_eq!(array_of(&got), ints(&[7, 8]));
}

#[test]
fn concat_element_type_mismatch_is_an_error_value() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let colls = cs
        .put(lit(Value::Array(vec![
            Value::Array(ints(&[1])),
            Value::Array(vec![entity_ecf::text("a")]),
        ])))
        .unwrap();
    let got = eval_entity(&cs, &li, &apply(BUILTIN_CONCAT, &[("collections", colls)]));
    assert_eq!(error_code_of(&got), "type_mismatch");
}

#[test]
fn concat_treats_an_error_element_as_type_transparent() {
    // CV-5. The element-type check is the thing under test, so the fixture is
    // built the way the corpus builds it: the error must be a LIVE value, and a
    // frozen literal cannot carry one, so `[E]` is produced by an `assoc`.
    //
    // Mutation run: dropping the `element_is_error` skip in `dispatch_concat`
    // fails this test with `type_mismatch` — the error element tags as an
    // entity reference and the integers as `integer`. Per §1.5 an error is a
    // poisoned value **of** the element type (the NaN analogy), not a value of
    // a different type.
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let e = seeded_error(&cs, "seeded_error", "corner-vector seed E");
    let zero = cs.put(lit_int(0)).unwrap();

    // live_err_arr = assoc([0], 0, E)  →  [E]
    let single = cs.put(lit_array(ints(&[0]))).unwrap();
    let live_err_arr = cs
        .put(apply(
            BUILTIN_ASSOC,
            &[("collection", single), ("index", zero), ("value", e)],
        ))
        .unwrap();

    // collections = assoc([[1,2],[0]], 1, live_err_arr)  →  [[1,2],[E]]
    let placeholder = cs
        .put(lit(Value::Array(vec![
            Value::Array(ints(&[1, 2])),
            Value::Array(ints(&[0])),
        ])))
        .unwrap();
    let one = cs.put(lit_int(1)).unwrap();
    let collections = cs
        .put(apply(
            BUILTIN_ASSOC,
            &[
                ("collection", placeholder),
                ("index", one),
                ("value", live_err_arr),
            ],
        ))
        .unwrap();

    let got = eval_entity(
        &cs,
        &li,
        &apply(BUILTIN_CONCAT, &[("collections", collections)]),
    );
    let items = array_of(&got);
    assert_eq!(items.len(), 3, "expected [1, 2, E], got {:?}", items);
    assert_eq!(items[0], entity_ecf::integer(1));
    assert_eq!(items[1], entity_ecf::integer(2));
    let stored = cs
        .get(&hash_element(&items[2]))
        .expect("contained error is resident");
    assert_eq!(stored.entity_type, TYPE_ERROR);
}

#[test]
fn concat_short_circuits_on_an_error_collection() {
    // The other half of concat's row: an error in a `collection` (a CONSUMED
    // position — its length is read to copy) short-circuits, while an error in
    // an ELEMENT contains. Same primitive, two positions, opposite outcomes.
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let e = seeded_error(&cs, "seeded_error", "corner-vector seed E");
    let got = eval_entity(&cs, &li, &apply(BUILTIN_CONCAT, &[("collections", e)]));
    assert_eq!(error_code_of(&got), "seeded_error");
}

/// **CV-7c — an error SUB-collection short-circuits**, and the pair with CV-5
/// is what makes either row mean anything.
///
/// `collections = assoc([0], 0, E)` evaluates to `[E]`: one sub-collection, and
/// it is a live error. §7.2 makes each `collection` a consumed position (its
/// length is read to copy it), so `concat` short-circuits to E.
///
/// This seat answered `type_mismatch` — "not an array" — which is the same
/// class of defect core-go had one code path over, and it was **found on the
/// wire, not in the tree**: the corpus LOCKED at 352 with it live because no
/// vector put an error in that position, and our seat never re-blessed at 355
/// where CV-7c was seeded. Measured by bisect at `145cd1c`: 3 two-way, this one
/// among them.
///
/// Its anti-vacuity partner is `concat_treats_an_error_element_as_type_
/// transparent` (CV-5): an error **element** of a *valid* sub-collection is
/// CONTAINED. Same primitive, two positions, opposite outcomes — a uniform
/// per-primitive rule fails exactly one of the two, which is why neither row
/// measures anything alone.
#[test]
fn concat_short_circuits_an_error_sub_collection() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let e = seeded_error(&cs, "seeded_error", "corner-vector seed E");

    // CV-7c: assoc([0], 0, E) → [E]; the single sub-collection IS the error.
    let base = cs.put(lit_array(ints(&[0]))).unwrap();
    let idx = cs.put(lit_int(0)).unwrap();
    let assoc = Entity::new(
        TYPE_APPLY,
        entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "args" => Value::Map(vec![
                (Value::Text("collection".into()), Value::Bytes(base.to_bytes().to_vec())),
                (Value::Text("index".into()), Value::Bytes(idx.to_bytes().to_vec())),
                (Value::Text("value".into()), Value::Bytes(e.to_bytes().to_vec())),
            ]),
            "operation" => entity_ecf::text("eval"),
            "path" => entity_ecf::text(BUILTIN_ASSOC)
        }),
    )
    .unwrap();
    let collections = cs.put(assoc).unwrap();
    let got = eval_entity(
        &cs,
        &li,
        &apply(BUILTIN_CONCAT, &[("collections", collections)]),
    );
    assert_eq!(
        error_code_of(&got),
        "seeded_error",
        "an error sub-collection is a consumed operand — it short-circuits, it is not type_mismatch"
    );
}

/// Both `collections` encodings are read, and this pins the array-of-hashes one
/// **because it is the shape C-11 Corner 2 (D3) withdraws** — so when v3.27
/// folds, this is the test that flips, and it flips alone.
///
/// It is held rather than landed for a measured reason, not a cautious one: a
/// type descriptor is a published contract, so the first seat to narrow it goes
/// red against every seat that has not. Landing D3 here scored
/// `type_system_compute_concat_args_match` **1F** (446 · 439P · 6W · 1F) against
/// core-go's unchanged local type table, then was backed out. The corpus is
/// unaffected either way — CV-5 and CV-7c both carry the single-hash form.
#[test]
fn concat_reads_the_array_of_hashes_shape_the_landed_spec_declares() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let a = cs.put(lit_array(ints(&[1, 2]))).unwrap();
    let b = cs.put(lit_array(ints(&[3]))).unwrap();
    let params = Entity::new(
        TYPE_CONCAT_ARGS,
        entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "collections" => Value::Array(vec![
                Value::Bytes(a.to_bytes().to_vec()),
                Value::Bytes(b.to_bytes().to_vec()),
            ])
        }),
    )
    .unwrap();

    let included: HashMap<Hash, Entity> = HashMap::new();
    let pid = TEST_PID.to_string();
    let mut budget = Budget::default_budget();
    let mut ctx = EvalContext::new(&cs, &li, &included, &pid);
    let got = crate::builtins::dispatch_builtin(
        BUILTIN_CONCAT,
        "eval",
        &params,
        &Scope::new(),
        &mut budget,
        &mut ctx,
    )
    .expect("concat is a builtin");
    assert_eq!(array_of(&got), ints(&[1, 2, 3]));
}

/// The other encoding, and the one every seat's evaluator actually reads (and
/// the one D3 will make the only one): a single hash resolving to an array of
/// arrays. This is the shape the corpus carries.
#[test]
fn concat_reads_the_single_hash_shape_the_ruling_made_normative() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let a = cs.put(lit_array(ints(&[1, 2]))).unwrap();
    let b = cs.put(lit_array(ints(&[3]))).unwrap();
    let outer = cs
        .put(lit_array(vec![
            Value::Bytes(a.to_bytes().to_vec()),
            Value::Bytes(b.to_bytes().to_vec()),
        ]))
        .unwrap();
    let _ = outer;
    // The corpus form: `collections` names an expression yielding [[1,2],[3]].
    let nested = cs
        .put(lit_array(vec![
            Value::Array(ints(&[1, 2])),
            Value::Array(ints(&[3])),
        ]))
        .unwrap();
    let got = eval_entity(&cs, &li, &apply(BUILTIN_CONCAT, &[("collections", nested)]));
    assert_eq!(array_of(&got), ints(&[1, 2, 3]));
}

// ---------------------------------------------------------------------------
// group-by (§3.5, v3.25 C-1)
// ---------------------------------------------------------------------------

#[test]
fn group_by_carries_the_key_and_orders_groups_by_first_appearance() {
    // CV-1. The result is an array of `system/compute/group{key, members}` —
    // the key is IN the result. Mutation run: returning bare arrays of members
    // (v3.24's array-of-arrays, which the fold lost) fails at the entity-type
    // assertion; dropping the first-appearance ordering for key-sort order
    // fails the ordering assertion, since key 1 appears before key 0 here.
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let coll = cs.put(lit_array(ints(&[1, 2, 3, 4]))).unwrap();
    let x = cs.put(scope_lookup("x")).unwrap();
    let two = cs.put(lit_int(2)).unwrap();
    let body = cs.put(arithmetic("mod", x, two)).unwrap();
    let f = cs.put(lambda(&["x"], body)).unwrap();

    let got = eval_entity(
        &cs,
        &li,
        &apply(BUILTIN_GROUP_BY, &[("collection", coll), ("fn", f)]),
    );
    let groups = array_of(&got);
    assert_eq!(groups.len(), 2);

    let mut seen: Vec<(i128, Vec<i128>)> = Vec::new();
    for g in &groups {
        let entity = cs
            .get(&hash_element(g))
            .expect("each group is a resident entity");
        assert_eq!(entity.entity_type, TYPE_GROUP);
        let data = decode_data(&entity).expect("group data decodes");
        let key = match data.get("key") {
            Some(Value::Integer(i)) => (*i).into(),
            other => panic!("expected an integer key, got {:?}", other),
        };
        let members = match data.get("members") {
            Some(Value::Array(items)) => items
                .iter()
                .map(|v| match v {
                    Value::Integer(i) => (*i).into(),
                    other => panic!("expected integer members, got {:?}", other),
                })
                .collect::<Vec<i128>>(),
            other => panic!("expected a members array, got {:?}", other),
        };
        seen.push((key, members));
    }
    // 1 appears first (1 % 2 == 1), so its group leads; members keep input order.
    assert_eq!(seen, vec![(1, vec![1, 3]), (0, vec![2, 4])]);
}

#[test]
fn group_by_short_circuits_on_an_error_key() {
    // CV-6. The derived key is CONSUMED — compared to assign a group — so it
    // short-circuits even though the key now has an output position
    // (`system/compute/group.key`). Grouping BY an error would make its message
    // string structurally load-bearing: two failures worded differently would
    // become two groups, and one reworded message would change the result's
    // shape.
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let e = seeded_error(&cs, "seeded_error", "corner-vector seed E");
    let coll = cs.put(lit_array(ints(&[1, 2]))).unwrap();
    let f = cs.put(lambda(&["x"], e)).unwrap();

    let got = eval_entity(
        &cs,
        &li,
        &apply(BUILTIN_GROUP_BY, &[("collection", coll), ("fn", f)]),
    );
    assert_eq!(error_code_of(&got), "seeded_error");
}

// ---------------------------------------------------------------------------
// The guard that v3.26 SCOPES rather than removes
// ---------------------------------------------------------------------------

#[test]
fn an_error_in_a_non_contained_position_still_short_circuits() {
    // "Add the carve-out, not remove the guard." The contained set is exactly
    // the three data positions; everywhere else §7.2's short-circuit is
    // unchanged, and the tell that the scope went wrong is a SCALAR error
    // materializing quietly. `compute/construct`'s field is the site v3.23
    // ruling B was written about, so it is the one pinned here: the result must
    // be the error itself, never a `test/holder` entity whose field carries the
    // error's hash.
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let e = seeded_error(&cs, "seeded_error", "corner-vector seed E");
    let got = eval_entity(&cs, &li, &construct("test/holder", &[("f", e)]));
    match &got {
        ComputeValue::Entity(ent) => assert_eq!(
            ent.entity_type, TYPE_ERROR,
            "a construct field error must short-circuit, not embed"
        ),
        ComputeValue::Error(_) => {}
        other => panic!("expected the error to short-circuit, got {:?}", other),
    }
    assert_eq!(error_code_of(&got), "seeded_error");
}

// ---------------------------------------------------------------------------
// Registration — the two sites an operation has to appear at
// ---------------------------------------------------------------------------

#[test]
fn the_four_primitives_declare_their_spec_pinned_input_types() {
    // §3.5: each builtin MUST declare an `input_type` so `compute/apply`
    // handler-mode can construct a properly-typed params entity via V30. These
    // names are spec-pinned, not implementation-owned — a transferable IR
    // requires every peer to agree on them, so a typo here diverges the params
    // entity's content hash rather than failing locally.
    for (path, want) in [
        (BUILTIN_RANGE, TYPE_RANGE_ARGS),
        (BUILTIN_GROUP_BY, TYPE_GROUP_BY_ARGS),
        (BUILTIN_CONCAT, TYPE_CONCAT_ARGS),
        (BUILTIN_ASSOC, TYPE_ASSOC_ARGS),
    ] {
        assert_eq!(
            crate::builtins::builtin_input_type(path, "eval"),
            Some(want)
        );
        assert!(
            crate::builtins::ALL_BUILTINS.contains(&path),
            "{} must be listed in ALL_BUILTINS",
            path
        );
        assert!(crate::builtins::is_builtin_path(path));
    }
}

// ---------------------------------------------------------------------------
// The boundary of the contained set — pinned so the reading is not accidental
// ---------------------------------------------------------------------------

/// **CV-8a / CV-8b — the pair is the point.** `map`'s output element CONTAINS,
/// and it contains identically for both in-language error forms.
///
/// This test previously asserted the opposite (short-circuit), citing v3.26's
/// "the contained set is exactly three positions". C-11 Corner 1 replaced that
/// count with the rule that generates it — *places without reading = contain* —
/// and `map` places. Rewritten, and the honest consequence is that the in-tree
/// suite is a smoke check for this behaviour: the cross-impl corpus is the
/// evidence, because a test edited in the same commit as the behaviour is not an
/// independent witness of anything.
///
/// The byte-identity assertion is the load-bearing half and it is D1's, not
/// `map`'s: the two closures produce the SAME `code` by different provenance —
/// one minted by `div(1,0)`, one an authored SA-1 `compute/error` value carrying
/// a diagnostic `message` — and §2.4 makes the in-flight representation
/// implementation-private, so the materialized bytes MUST NOT be able to tell
/// them apart. Mutation: give the SA-1 arm of `contained_element` its own
/// `content_hash` instead of re-canonicalizing to code-only, and this fails on
/// the byte compare while both arms still "contain".
#[test]
fn map_output_element_contains_in_both_error_forms_with_identical_bytes() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let coll = cs.put(lit_array(ints(&[1, 2]))).unwrap();

    // Minted: the closure body divides by zero on every element.
    let one = cs.put(lit_int(1)).unwrap();
    let zero = cs.put(lit_int(0)).unwrap();
    let div = cs.put(arithmetic("div", one, zero)).unwrap();
    let minted_fn = cs.put(lambda(&["x"], div)).unwrap();
    let minted = eval_entity(
        &cs,
        &li,
        &apply(
            "system/compute/builtins/map",
            &[("collection", coll), ("fn", minted_fn)],
        ),
    );

    // Value form: the closure body IS a stored `compute/error` with the same
    // code — and a `message`, which is exactly what must not reach the bytes.
    let e = seeded_error(&cs, "division_by_zero", "authored, carries a message");
    let value_fn = cs.put(lambda(&["x"], e)).unwrap();
    let value_form = eval_entity(
        &cs,
        &li,
        &apply(
            "system/compute/builtins/map",
            &[("collection", coll), ("fn", value_fn)],
        ),
    );

    let minted_items = array_of(&minted);
    let value_items = array_of(&value_form);
    assert_eq!(
        minted_items.len(),
        2,
        "map contains element-wise: one output per input, not a whole-array abort"
    );
    assert_eq!(value_items.len(), 2);
    assert_eq!(
        minted_items, value_items,
        "D1 (§2.4): a compute/error's materialized bytes may not depend on how it was produced"
    );

    // And what is contained is code-only, resident, and followable.
    let stored = cs
        .get(&hash_element(&minted_items[0]))
        .expect("the contained error is made resident, not left dangling");
    assert_eq!(stored.entity_type, TYPE_ERROR);
    let data = decode_data(&stored).expect("error data decodes");
    assert_eq!(data_str(&data, "code").as_deref(), Some("division_by_zero"));
    assert!(
        data_str(&data, "message").is_none(),
        "a contained error is code-only — an unpinned message would fork the array's identity"
    );
}

/// **CV-8c — `filter`'s predicate result SHORT-CIRCUITS**, in both forms.
///
/// This seat was already right and the test is new, so unlike its `map`
/// neighbour it is an independent witness. The disposition is the opposite of
/// `map`'s one function away, which is the whole point of the position rule:
/// `filter` *reads* the result for truthiness (§4.5) to decide inclusion.
///
/// Containing it would be the worse of the two bugs — an error has no truth
/// value, so it coerces to false and the element is **silently dropped**,
/// yielding a well-formed wrong answer carrying no error at all.
#[test]
fn filter_predicate_error_short_circuits_in_both_forms() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let coll = cs.put(lit_array(ints(&[1, 2]))).unwrap();

    let e = seeded_error(&cs, "seeded_error", "corner-vector seed E");
    let value_fn = cs.put(lambda(&["x"], e)).unwrap();
    let got = eval_entity(
        &cs,
        &li,
        &apply(
            "system/compute/builtins/filter",
            &[("collection", coll), ("fn", value_fn)],
        ),
    );
    assert_eq!(
        error_code_of(&got),
        "seeded_error",
        "a value-form predicate error short-circuits; it must not coerce to false"
    );

    let one = cs.put(lit_int(1)).unwrap();
    let zero = cs.put(lit_int(0)).unwrap();
    let div = cs.put(arithmetic("div", one, zero)).unwrap();
    let minted_fn = cs.put(lambda(&["x"], div)).unwrap();
    let got = eval_entity(
        &cs,
        &li,
        &apply(
            "system/compute/builtins/filter",
            &[("collection", coll), ("fn", minted_fn)],
        ),
    );
    assert_eq!(error_code_of(&got), "division_by_zero");
}

/// **CV-8d — the arm with the widest blast radius: `fold` RECOVERS.**
///
/// The accumulator is *bound* into the next invocation, never read, so a closure
/// that ignores it recovers. Arch flagged this as the one position of the three
/// where the alternative reading produces a different **value** rather than a
/// different cost, and this is the shape that separates them: under the
/// short-circuit reading the error `initial` aborts and the answer is the error;
/// under the ruling the closure ignores `acc` and the answer is `2`.
///
/// Two elements rather than one, deliberately — a single element cannot tell
/// "bound through once" from "the loop never ran".
#[test]
fn fold_recovers_when_the_closure_ignores_an_error_accumulator() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let coll = cs.put(lit_array(ints(&[1, 2]))).unwrap();
    let e = seeded_error(&cs, "seeded_error", "corner-vector seed E");
    // λ(acc, x). x — ignores the accumulator entirely.
    let body = cs.put(scope_lookup("x")).unwrap();
    let f = cs.put(lambda(&["acc", "x"], body)).unwrap();

    let got = eval_entity(
        &cs,
        &li,
        &apply(
            "system/compute/builtins/fold",
            &[("collection", coll), ("fn", f), ("initial", e)],
        ),
    );
    assert_eq!(
        got.as_i128(),
        Some(2),
        "an error accumulator is bound, not consumed — a closure that ignores it recovers"
    );
}

/// The **intermediate** accumulator, which is a separate branch from `initial`
/// and was not measured by the test above.
///
/// Caught by the mutation, not by review: restoring the per-iteration
/// `if acc.is_error() { return acc }` left
/// `fold_recovers_when_the_closure_ignores_an_error_accumulator` green, because
/// in that fixture only `initial` is ever an error — the closure never produces
/// one, so the loop's own check is never reached. A branch that reads as covered
/// and cannot fail is worse than its absence.
///
/// `fold(λ(acc, x). div(1, x), 0, [0, 1])` separates them: the first invocation
/// divides by zero and makes the accumulator an error, the second ignores `acc`
/// and returns 1. Under the ruling the answer is 1; under the withdrawn
/// short-circuit reading it is `division_by_zero`.
#[test]
fn fold_binds_an_intermediate_error_accumulator_into_the_next_invocation() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let coll = cs.put(lit_array(ints(&[0, 1]))).unwrap();
    let zero = cs.put(lit_int(0)).unwrap();

    let one = cs.put(lit_int(1)).unwrap();
    let x = cs.put(scope_lookup("x")).unwrap();
    let body = cs.put(arithmetic("div", one, x)).unwrap();
    let f = cs.put(lambda(&["acc", "x"], body)).unwrap();

    let got = eval_entity(
        &cs,
        &li,
        &apply(
            "system/compute/builtins/fold",
            &[("collection", coll), ("fn", f), ("initial", zero)],
        ),
    );
    assert_eq!(
        got.as_i128(),
        Some(1),
        "an error produced mid-fold is bound into the next invocation, not returned"
    );
}

/// The other half of `fold`'s row: when the closure's LAST result is an error,
/// that error is the final accumulator and it comes back.
///
/// **Stated as a non-discriminator on purpose.** Both readings agree on this
/// shape — short-circuiting at the last element and returning the last
/// accumulator produce the same answer — so it measures that the value survives
/// the return, and nothing about the disposition. The discriminator is
/// `fold_recovers_when_the_closure_ignores_an_error_accumulator` above, and a
/// suite carrying only this shape would pass under the reading the ruling
/// withdrew. (This is the shape core-go froze as its CV-8c.)
#[test]
fn fold_returns_an_error_final_accumulator_but_this_does_not_discriminate() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let coll = cs.put(lit_array(ints(&[1]))).unwrap();
    let e = seeded_error(&cs, "seeded_error", "corner-vector seed E");
    let zero = cs.put(lit_int(0)).unwrap();
    let f = cs.put(lambda(&["acc", "x"], e)).unwrap();

    let got = eval_entity(
        &cs,
        &li,
        &apply(
            "system/compute/builtins/fold",
            &[("collection", coll), ("fn", f), ("initial", zero)],
        ),
    );
    assert_eq!(error_code_of(&got), "seeded_error");
}

/// The one carve-out on the contain rule, and **both** of its directions.
///
/// The criterion is a resource **shared across the elements**, not "it is a
/// limit code" — see `ComputeValue::is_shared_resource_error`:
///
/// - `budget_exhausted` aborts. `budget.operations` is one counter for the whole
///   evaluation, pinned at 0 by `saturating_sub` once it trips, so containing it
///   would fill the output with copies at a split point decided by cost
///   accounting and then report **success** for an aborted evaluation.
/// - `depth_exceeded` CONTAINS. `budget.depth` is restored on unwind, so it is
///   per-branch and element-wise: a closure that is too deep fails identically
///   on every element for a structural reason, exactly like `div(x, 0)` does.
///
/// **This is a named divergence from core-go**, which propagates all three
/// evaluation-limit codes. It is routed, not silent, and it is deliberately not
/// in the frozen corpus at either seat.
///
/// Both probes use *authored* SA-1 values, which also pins the consequence the
/// carve-out carries: because it must key on the `code` to stay §2.4-conformant
/// (keying on the variant would reinstate the exact provenance-dependence
/// Corner 1 removed), an authored `budget_exhausted` aborts a `map` too.
#[test]
fn the_map_carve_out_is_shared_resource_not_limit_code() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let coll = cs.put(lit_array(ints(&[1, 2]))).unwrap();

    let budget_e = seeded_error(&cs, "budget_exhausted", "shared counter");
    let f = cs.put(lambda(&["x"], budget_e)).unwrap();
    let got = eval_entity(
        &cs,
        &li,
        &apply(
            "system/compute/builtins/map",
            &[("collection", coll), ("fn", f)],
        ),
    );
    assert_eq!(
        error_code_of(&got),
        "budget_exhausted",
        "a shared-resource error aborts the map rather than filling it"
    );

    let depth_e = seeded_error(&cs, "depth_exceeded", "per-branch, restored on unwind");
    let f = cs.put(lambda(&["x"], depth_e)).unwrap();
    let got = eval_entity(
        &cs,
        &li,
        &apply(
            "system/compute/builtins/map",
            &[("collection", coll), ("fn", f)],
        ),
    );
    assert_eq!(
        array_of(&got).len(),
        2,
        "depth_exceeded is element-wise and contains — the carve-out is about sharing, not limits"
    );
}
