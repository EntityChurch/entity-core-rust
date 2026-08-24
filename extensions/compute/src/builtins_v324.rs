//! The v3.24 collection primitives — `range` / `group-by` / `concat` / `assoc`
//! (EXTENSION-COMPUTE §3.5 "The v3.24 collection primitives"), carrying the
//! v3.25 corner rulings (C-1…C-4) and the v3.26 contained-error boundary form.
//!
//! All four are **MUST-given-COMPUTE** (§10.1): they produce boundary bytes, so
//! a peer that computes a different result is divergent, not merely slower.
//! They are evaluated internally within the evaluator (the §3.5 SHOULD),
//! alongside `map`/`filter`/`fold`, and their args types are spec-pinned.
//!
//! # Error-as-value flow-through is §7.2's, not a rule of its own (v3.25)
//!
//! §3.5's table applies §7.2's short-circuit `[MUST]` — which binds *"all
//! expression types that **consume values**"* — position by position, and its
//! SA-9 `store` worked example settles the other side (*"a builtin's write
//! payload is not a consumed operand"*):
//!
//! | Primitive  | Position          | Class                                  | Behaviour |
//! |------------|-------------------|----------------------------------------|-----------|
//! | `range`    | `n`               | consumed — read to size the array       | short-circuit |
//! | `group-by` | derived key       | consumed — compared to assign a group   | short-circuit |
//! | `group-by` | element           | copied into `members`                   | **contain** |
//! | `assoc`    | `index`           | consumed — read to position the write   | short-circuit |
//! | `assoc`    | `value`           | placed into the output (the SA-9 case)  | **contain** |
//! | `concat`   | each `collection` | consumed — its length is read to copy   | short-circuit |
//! | `concat`   | element           | copied into the output                  | **contain** |
//! | `map`      | output element    | placed into the output, never read      | **contain** |
//! | `filter`   | predicate result  | consumed — read for truthiness (§4.5)   | short-circuit |
//! | `fold`     | final accumulator | returned, never read                    | **contain** |
//!
//! The discriminator is the *position*, never the primitive: `assoc`'s `index`
//! and `assoc`'s `value` are the same operation and opposite outcomes, so a
//! uniform per-primitive rule fails exactly one of them (corpus CV-4b vs CV-4a).
//!
//! The last three rows are C-11 Corner 1, ruled 2026-08-21; `map`/`filter`/`fold`
//! predate the §3.5 table and were never in it. See `crate::builtins`, which is
//! where they are evaluated.
//!
//! # The v3.26 contained form
//!
//! Where the table says **contain**, the error is present in the value when
//! that value crosses a materialization boundary (§2.3 N1, scoped v3.26). It
//! materializes **code-only** — content-hashed over `code` alone per §2.4 — and
//! is referenced by a **bare `system/hash`** like any other entity-valued
//! element. Code-only is load-bearing and not tidiness: a contained `message`
//! would fork the containing array's bytes across two conformant peers on a
//! string no spec pins. [`contained_element`] is the single site that does it.
//!
//! **The contained set is defined by a rule, not by a count** — C-11 Corner 1's
//! D2 *replaced* the v3.26 sentence "the contained set is exactly three
//! positions" rather than incrementing it, because an enumeration written at the
//! width of one table is wrong again at the next primitive (it already was: it
//! was taken over the four v3.25 collection primitives, and `map`/`filter`/`fold`
//! predate that table):
//!
//! > A position is **contained** when the primitive **places** the value without
//! > reading it, and **consumed** when the primitive reads it to decide control
//! > flow, ordering, membership, or a write location. A new primitive adds rows
//! > to the table by applying the rule, not by amending the count.
//!
//! Today that rule's extension is the five contained positions above. An error
//! reaching materialization from anywhere *else* — a top-level result, a
//! `compute/construct` field scalar, a scope-binding scalar, an arithmetic
//! operand, `if`'s condition — is the §4.1 defect it has always been, and every
//! one of those sites short-circuits it upstream (`ComputeValue::is_error` is
//! kind-based, so the minted and SA-1 value forms are one fact). Arch's words on
//! the ruling: *"add the carve-out, not remove the guard."*
//!
//! **And the rule that makes all of this well-posed is §2.4's, restated as D1:**
//! a `compute/error` behaves identically regardless of how it was produced.
//! "Minted" vs "value-form" is an in-flight representation, which §2.4 already
//! declares implementation-private — so no disposition anywhere may be decided
//! by which one arrived. That is why every predicate here keys on kind or on
//! `code`, never on the `ComputeValue` variant.

use std::collections::HashMap;

use ciborium::Value;
use entity_ecf::ValueExt;
use entity_entity::Entity;
use entity_hash::Hash;

use crate::builtins::{apply_closure_to_value, eval_ref, extract_closure};
use crate::eval::EvalContext;
use crate::types::*;

// ---------------------------------------------------------------------------
// The v3.26 contained-value boundary
// ---------------------------------------------------------------------------

/// Encode an evaluated value for placement **into an array** — the bare V7 §1.4
/// form, with the v3.26 contained-`compute/error` carve-out.
///
/// Entity-, closure- and error-valued elements become a bare `system/hash`
/// byte string and the referent is made resident in the content store, so the
/// reference is followable (`compute/lookup/hash`) rather than dangling.
/// Primitives inline; a `Uint` keeps CBOR major type 0 per §2.2 rule 10's
/// exception, matching `encode_construct_field_bare`.
///
/// **The error arms are the v3.26 carve-out and they re-canonicalize.** Both
/// in-language error forms funnel to `code`-only bytes: a minted
/// `ComputeValue::Error` via [`ComputeError::to_entity`], and the SA-1 value
/// form (a `compute/error` entity that evaluated *successfully* — an authored
/// literal, or a lookup onto a stored error) via [`materialize_error_value`].
/// The second arm is the one that bites: an SA-1 error carries the diagnostic
/// `message`, so referencing it by its **own** `content_hash` would put an
/// unpinned prose string into the containing array's identity.
pub(crate) fn contained_element(value: &ComputeValue, ctx: &mut EvalContext<'_>) -> Value {
    match value {
        // v3.26 contained form — minted error, already code-only by construction.
        ComputeValue::Error(err) => store_ref(err.to_entity(), ctx),
        // v3.26 contained form — SA-1 value form, re-canonicalized to code-only.
        ComputeValue::Entity(e) if e.entity_type == TYPE_ERROR => {
            store_ref(materialize_error_value(e), ctx)
        }
        ComputeValue::Entity(e) => store_ref(e.clone(), ctx),
        ComputeValue::Closure(c) => store_ref(c.to_entity(), ctx),
        ComputeValue::Primitive(v) => v.clone(),
        ComputeValue::Uint(u) => Value::Integer(ciborium::value::Integer::from(*u)),
    }
}

/// Make `entity` resident and return the bare `system/hash` reference to it.
fn store_ref(entity: Entity, ctx: &mut EvalContext<'_>) -> Value {
    let h = entity.content_hash;
    let _ = ctx.content_store.put(entity.clone());
    ctx.encountered.insert(h, entity);
    Value::Bytes(h.to_bytes().to_vec())
}

/// The referent of a bare V7 §1.4 array element, if this evaluation is the one
/// that put it there.
///
/// Our in-flight arrays are `Vec<Value>` — an entity element is *already*
/// materialized to its bare `system/hash`, so the element's entity **type** is
/// only recoverable by looking the reference up. `concat`'s element-type-match
/// check (§3.5) needs that type, and its error-transparency clause needs to
/// know whether the referent is a `compute/error`. Go keeps typed values inside
/// its collection arrays and reads the type directly; this is the same fact,
/// reached the way our representation allows.
///
/// **Registry-identity resolution only — NOT the N3-forbidden shape sniff.**
/// The lookup is confined to the per-eval `encountered` registry and the
/// envelope `included` map: hashes *this* evaluation materialized or was handed
/// pre-authorized. It never consults the content store, so an arbitrary byte
/// payload cannot be re-read as an entity by looking like a hash, and nothing
/// is auto-resolved *into* the value — the element is copied through
/// byte-for-byte either way. (Same boundary `constructed_in_flight` draws for
/// `compute/field` over a `map`-produced constructed entity.)
fn referent_type(v: &Value, ctx: &EvalContext<'_>) -> Option<String> {
    let Value::Bytes(bytes) = v else {
        return None;
    };
    let h = Hash::from_bytes(bytes).ok()?;
    ctx.encountered
        .get(&h)
        .or_else(|| ctx.included.get(&h))
        .map(|e| e.entity_type.clone())
}

/// Whether an already-materialized array element is a contained `compute/error`.
fn element_is_error(v: &Value, ctx: &EvalContext<'_>) -> bool {
    referent_type(v, ctx).as_deref() == Some(TYPE_ERROR)
}

/// Classify an element for `concat`'s element-type-match check.
///
/// `int`/`uint` collapse to one `integer` tag — they are annotations, not
/// distinct value types (§2.2's cross-impl ruling), so a `numeric-cast` result
/// does not make an otherwise-uniform array heterogeneous.
fn element_type_tag(v: &Value, ctx: &EvalContext<'_>) -> String {
    match v {
        Value::Null => "null".to_string(),
        Value::Bool(_) => "bool".to_string(),
        Value::Integer(_) => "integer".to_string(),
        Value::Float(_) => "float".to_string(),
        Value::Text(_) => "string".to_string(),
        Value::Array(_) => "array".to_string(),
        Value::Map(_) => "record".to_string(),
        Value::Bytes(_) => match referent_type(v, ctx) {
            Some(t) => format!("entity:{}", t),
            None => "bytes".to_string(),
        },
        _ => "unknown".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Shared argument helpers
// ---------------------------------------------------------------------------

/// Evaluate a **consumed** (steering) arg: an error-as-value short-circuits
/// (§7.2). This is the disposition for `range`'s `n`, `assoc`'s `index`,
/// `concat`'s `collections`, and `group-by`'s derived key.
fn consumed_arg(
    data: &Value,
    key: &str,
    label: &str,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> Result<ComputeValue, ComputeValue> {
    let value = eval_ref(data, key, label, scope, budget, ctx);
    if value.is_error() {
        return Err(value);
    }
    Ok(value)
}

/// Evaluate a consumed `collection` arg and require an array.
fn consumed_collection(
    data: &Value,
    key: &str,
    label: &str,
    op: &str,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> Result<Vec<Value>, ComputeValue> {
    let value = consumed_arg(data, key, label, scope, budget, ctx)?;
    match value {
        ComputeValue::Primitive(Value::Array(items)) => Ok(items),
        other => Err(ComputeError::TypeMismatch(format!(
            "{}: {} must be an array, got {}",
            op,
            key,
            value_kind(&other)
        ))
        .to_value()),
    }
}

fn value_kind(v: &ComputeValue) -> &'static str {
    match v {
        ComputeValue::Primitive(Value::Null) => "null",
        ComputeValue::Primitive(Value::Bool(_)) => "bool",
        ComputeValue::Primitive(Value::Integer(_)) => "integer",
        ComputeValue::Primitive(Value::Float(_)) => "float",
        ComputeValue::Primitive(Value::Text(_)) => "string",
        ComputeValue::Primitive(Value::Bytes(_)) => "bytes",
        ComputeValue::Primitive(Value::Array(_)) => "array",
        ComputeValue::Primitive(Value::Map(_)) => "record",
        ComputeValue::Primitive(_) => "value",
        ComputeValue::Entity(_) => "entity",
        ComputeValue::Closure(_) => "closure",
        ComputeValue::Error(_) => "error",
        ComputeValue::Uint(_) => "integer",
    }
}

// ---------------------------------------------------------------------------
// range (§3.5, v3.25 C-3)
// ---------------------------------------------------------------------------

/// `range(n)` → `[0 … n-1]`, empty when `n` is `0`. **Single-argument form
/// only** — a start offset is expressed inside the lambda, not as a second
/// parameter.
///
/// **A negative `n`, or an `n` exceeding the maximum representable array
/// length, is `count_out_of_range` `[MUST, v3.25]`** — *not* `type_mismatch`
/// (§2.2: `int`/`uint` are annotations, so an out-of-domain magnitude is not a
/// type error) and *not* clamped to `[]`: `n` is a loop bound, so a silent
/// empty propagates through every downstream `map`/`filter`/`fold` and yields a
/// well-formed wrong answer carrying no error.
pub(crate) fn dispatch_range(
    data: &Value,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    let n_val = match consumed_arg(data, "n", "range n", scope, budget, ctx) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let n = match n_val.as_i128() {
        Some(n) => n,
        None => {
            return ComputeError::TypeMismatch(format!(
                "range: n must be an integer, got {}",
                value_kind(&n_val)
            ))
            .to_value()
        }
    };
    if n < 0 || n > i64::MAX as i128 {
        return ComputeError::CountOutOfRange(format!(
            "range: n must be non-negative and representable, got {}",
            n
        ))
        .to_value();
    }
    // Charge the budget per produced element so range(huge) exhausts rather
    // than OOMs — the same per-element cost map/filter/fold already pay
    // through their per-`evaluate` decrement.
    let n = n as u64;
    if n > budget.operations {
        return ComputeError::BudgetExhausted.to_value();
    }
    budget.operations -= n;

    let out: Vec<Value> = (0..n as i64).map(entity_ecf::integer).collect();
    ComputeValue::Primitive(Value::Array(out))
}

// ---------------------------------------------------------------------------
// group-by (§3.5, v3.25 C-1)
// ---------------------------------------------------------------------------

/// `group-by(collection, fn)` applies `fn` to each element to derive a key and
/// returns the elements grouped by that key in **one pass**.
///
/// **The result is an array of `system/compute/group{key, members}`
/// `[MUST, v3.25]`** — the key is part of the result and is not dropped,
/// because the shapes this primitive exists to serve (a histogram, a bucketed
/// aggregation, a router) are unreadable without their labels. Within a group,
/// elements retain input index order; groups are ordered by **first appearance
/// of their key**, not by key sort order (which would need a total order over
/// arbitrary key types this extension does not define).
///
/// Key **equality** is byte-identity over the canonical ECF encoding of the
/// derived key — the protocol's own value identity, defined for every key type
/// `fn` may return.
///
/// A `compute/error` **key** short-circuits even though the key now has an
/// output position: grouping by an error would make its message string
/// structurally load-bearing, so two failures worded differently would become
/// two groups and one reworded message would change the result's shape. The
/// *elements*, by contrast, are copied into `members` and contain.
pub(crate) fn dispatch_group_by(
    data: &Value,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    let items = match consumed_collection(
        data,
        "collection",
        "group-by collection",
        "group-by",
        scope,
        budget,
        ctx,
    ) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let fn_val = match consumed_arg(data, "fn", "group-by fn", scope, budget, ctx) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let closure = match extract_closure(&fn_val) {
        Some(c) => c,
        None => {
            return ComputeError::TypeMismatch("group-by: fn must be a closure".into()).to_value()
        }
    };

    let mut order: Vec<Vec<u8>> = Vec::new();
    let mut members: HashMap<Vec<u8>, Vec<Value>> = HashMap::new();
    let mut keys: HashMap<Vec<u8>, Value> = HashMap::new();

    for item in &items {
        let key_val = apply_closure_to_value(&closure, item, scope, budget, ctx);
        // §3.5: the derived key is a CONSUMED position — it is compared to
        // assign a group, so an error key short-circuits.
        if key_val.is_error() {
            return key_val;
        }
        let key_cbor = contained_element(&key_val, ctx);
        let key_bytes = entity_ecf::to_ecf(&key_cbor);
        if !members.contains_key(&key_bytes) {
            order.push(key_bytes.clone());
            keys.insert(key_bytes.clone(), key_cbor);
        }
        members.entry(key_bytes).or_default().push(item.clone());
    }

    let mut out: Vec<Value> = Vec::with_capacity(order.len());
    for key_bytes in &order {
        let group_data = entity_ecf::cbor_map! {
            "key" => keys[key_bytes].clone(),
            "members" => Value::Array(members[key_bytes].clone())
        };
        let group = match Entity::new(TYPE_GROUP, entity_ecf::to_ecf(&group_data)) {
            Ok(e) => e,
            Err(err) => {
                return ComputeError::InvalidExpression(format!("group-by: build group: {}", err))
                    .to_value()
            }
        };
        out.push(store_ref(group, ctx));
    }
    ComputeValue::Primitive(Value::Array(out))
}

// ---------------------------------------------------------------------------
// concat (§3.5, v3.25 C-4)
// ---------------------------------------------------------------------------

/// `concat(...collections)` joins arrays **order-preserving, one level** — it
/// does not flatten recursively. `concat()` is the empty array; `concat(a)` is
/// `a`. Element types MUST match; a mismatch is a `type_mismatch`
/// **error-as-value**, not a fault.
///
/// **A `compute/error` element is type-transparent to that check
/// `[MUST, v3.25]`**: it neither matches nor mismatches, and flows through
/// untouched. Per §1.5 an error is *"the same model as NaN propagation in IEEE
/// 754"* — a poisoned value **of** the array's element type, not a value of a
/// different type — and §7.2 scopes `concat` to consuming its `collections`,
/// never their elements, so inspecting elements for errors is the one behaviour
/// it must not have.
pub(crate) fn dispatch_concat(
    data: &Value,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    let collections = match resolve_concat_collections(data, scope, budget, ctx) {
        Ok(c) => c,
        Err(e) => return e,
    };

    let mut out: Vec<Value> = Vec::new();
    let mut tag: Option<String> = None;
    for sub in &collections {
        for element in sub {
            if element_is_error(element, ctx) {
                out.push(element.clone());
                continue;
            }
            let et = element_type_tag(element, ctx);
            match &tag {
                None => tag = Some(et),
                Some(t) if *t != et => {
                    return ComputeError::TypeMismatch(format!(
                        "concat: element type {:?} does not match {:?}",
                        et, t
                    ))
                    .to_value()
                }
                Some(_) => {}
            }
            out.push(element.clone());
        }
    }
    ComputeValue::Primitive(Value::Array(out))
}

/// Resolve `concat`'s `collections` arg into the sub-collections it names.
///
/// **Two encodings reach this, and both are accepted.** The landed §3.5 declares
/// `concat-args.collections` as `{array_of: {type_ref: "system/hash"}}` — an
/// array of expression hashes — while `compute/apply`'s args map is
/// `name → hash`, so a `collections` arg arriving through apply is a *single*
/// hash naming an expression that evaluates to an array of arrays. The corpus
/// vectors (CV-5, CV-7c) carry the second form. Both are read; the CBOR kind of
/// the field distinguishes them without ambiguity (`Bytes` = one hash, `Array`
/// = many). Logged in `docs/SPEC-AMBIGUITIES.md`.
///
/// **C-11 Corner 2 (D3) rules the single-hash form normative and withdraws the
/// array — and that is deliberately NOT implemented here yet.** The derivation
/// is worth recording because it is not the obvious one and it is not
/// "three seats agree": §7.1's reactive `walk` recurses only on **scalar**
/// `system/hash` field values, so under the array shape every
/// `compute/lookup/tree` inside every sub-collection goes unregistered and a
/// reactive `concat` evaluates correctly once and is then never woken again.
///
/// It is held because the ruling is a DRAFT proposal targeting v3.27 and the
/// declaration it changes is a **published contract**: landing it at one seat
/// scores a cross-impl FAIL against every seat that has not
/// (`type_system_compute_concat_args_match`, measured 1F here). It lands with
/// the v3.27 fold, cohort-wide, not seat-by-seat.
fn resolve_concat_collections(
    data: &Value,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> Result<Vec<Vec<Value>>, ComputeValue> {
    let field = match data.get("collections") {
        Some(f) => f.clone(),
        None => {
            return Err(
                ComputeError::MissingArgument("concat: missing 'collections'".into()).to_value(),
            )
        }
    };

    // Spec-declared form: an array of expression hashes, each an array.
    if let Value::Array(entries) = &field {
        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            let hash = match entry.as_bytes().and_then(|b| Hash::from_bytes(b).ok()) {
                Some(h) => h,
                None => {
                    return Err(ComputeError::TypeMismatch(
                        "concat: each collections entry must be a system/hash".into(),
                    )
                    .to_value())
                }
            };
            let target = ctx.resolve_or_error(&hash, "concat collection")?;
            let value = crate::eval::evaluate(&target, scope, budget, ctx);
            // Each sub-collection is a CONSUMED operand (its length is read to
            // copy), so an error there short-circuits.
            if value.is_error() {
                return Err(value);
            }
            match value {
                ComputeValue::Primitive(Value::Array(items)) => out.push(items),
                other => {
                    return Err(ComputeError::TypeMismatch(format!(
                        "concat: each collection must be an array, got {}",
                        value_kind(&other)
                    ))
                    .to_value())
                }
            }
        }
        return Ok(out);
    }

    // Apply form: one hash naming an expression that yields an array of arrays.
    let value = consumed_arg(
        data,
        "collections",
        "concat collections",
        scope,
        budget,
        ctx,
    )?;
    let outer = match value {
        ComputeValue::Primitive(Value::Array(items)) => items,
        other => {
            return Err(ComputeError::TypeMismatch(format!(
                "concat: collections must be an array of arrays, got {}",
                value_kind(&other)
            ))
            .to_value())
        }
    };
    let mut out = Vec::with_capacity(outer.len());
    for entry in outer {
        match entry {
            Value::Array(items) => out.push(items),
            // **Each sub-collection is a CONSUMED position** (§7.2 — its length
            // is read in order to copy it), so an error *sub-collection*
            // short-circuits to that error. It must not be reported as
            // `type_mismatch` for "not an array": the operand did not have the
            // wrong type, it had no value at all, and answering with a local
            // complaint loses the real failure.
            //
            // Distinct from an error **element** *of* a valid sub-collection,
            // which is contained (CV-5) — same primitive, two positions,
            // opposite dispositions. Corpus discriminator: **CV-7c**, where
            // `collections` is `assoc([0], 0, E)` → `[E]`, one live error
            // sub-collection.
            //
            // Reached by `element_is_error` rather than by a type check because
            // by this point the sub-collection is already materialized to its
            // bare `system/hash`; the referent lookup is the registry-identity
            // one, never a shape sniff.
            other if element_is_error(&other, ctx) => {
                return Err(contained_error_value(&other, ctx))
            }
            other => {
                return Err(ComputeError::TypeMismatch(format!(
                    "concat: each collection must be an array, got {}",
                    element_type_tag(&other, ctx)
                ))
                .to_value())
            }
        }
    }
    Ok(out)
}

/// Recover the `compute/error` a materialized array element references, as a
/// value that can be short-circuited.
///
/// Only called after [`element_is_error`] has confirmed the referent's type, so
/// the fallback is unreachable in practice; it is written as an
/// `invalid_expression` rather than a panic because a malformed referent is a
/// program's problem, not this peer's.
fn contained_error_value(v: &Value, ctx: &EvalContext<'_>) -> ComputeValue {
    let entity = match v {
        Value::Bytes(bytes) => Hash::from_bytes(bytes)
            .ok()
            .and_then(|h| ctx.encountered.get(&h).or_else(|| ctx.included.get(&h)))
            .cloned(),
        _ => None,
    };
    match entity {
        Some(e) => ComputeValue::Entity(e),
        None => ComputeError::InvalidExpression(
            "concat: error sub-collection referent is not resolvable".into(),
        )
        .to_value(),
    }
}

// ---------------------------------------------------------------------------
// assoc (§3.5, v3.25 C-2)
// ---------------------------------------------------------------------------

/// `assoc(collection, index, value)` returns a new array identical to
/// `collection` except at `index`, which carries `value`.
///
/// **An out-of-range `index` — negative, or ≥ the collection's length — is
/// `index_out_of_range` `[MUST, v3.25]`**, the same code and the same condition
/// as `compute/index` (§2.2): one document must not answer one malformed
/// program with two codes depending on which array operation it reached.
///
/// **`assoc` MUST NOT be an implicit lowering target `[MUST]`** — `map` and
/// `fold` are never lowered onto it; this implementation performs no such
/// lowering, so there is nothing to suppress. The choice stays the author's
/// because an indexed update buys scatter at the cost of sharding.
///
/// `value` is the **data** position: it is placed into the output — the SA-9
/// `store` case — so an error-as-value there contains rather than
/// short-circuiting (§3.5, v3.26). `index` is the consumed position and its
/// opposite. Same operation, two positions, two outcomes.
pub(crate) fn dispatch_assoc(
    data: &Value,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    let items = match consumed_collection(
        data,
        "collection",
        "assoc collection",
        "assoc",
        scope,
        budget,
        ctx,
    ) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let index_val = match consumed_arg(data, "index", "assoc index", scope, budget, ctx) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let idx = match index_val.as_i128() {
        Some(i) => i,
        None => {
            return ComputeError::TypeMismatch(format!(
                "assoc: index must be an integer, got {}",
                value_kind(&index_val)
            ))
            .to_value()
        }
    };
    if idx < 0 || idx >= items.len() as i128 {
        return ComputeError::IndexOutOfRange(format!(
            "assoc: index {} out of range for array of length {}",
            idx,
            items.len()
        ))
        .to_value();
    }

    // DATA position — deliberately NOT short-circuited (§3.5 flow-through).
    let value = eval_ref(data, "value", "assoc value", scope, budget, ctx);
    let element = contained_element(&value, ctx);

    let mut out = items;
    out[idx as usize] = element;
    ComputeValue::Primitive(Value::Array(out))
}

#[cfg(test)]
mod tests;
