//! Every builtin's spec-pinned `input_type` owes a published type descriptor.
//!
//! An operation added to the evaluator has **three** registration sites, and
//! only two of them are in the compute crate: the dispatch tables
//! (`dispatch_builtin` / `dispatch_builtin_alias`) make it answerable,
//! `builtin_input_type` names the params-entity type `compute/apply`
//! handler-mode constructs via V30 — and `all_core_types()` in `core/types`
//! **publishes** that type at `system/type/{name}`, which is what the
//! cross-impl `type_system` category fetches.
//!
//! The third site is in a different crate from the first two and the compute
//! crate's own tests cannot see it: they construct the evaluator directly and
//! never read the type surface. Landing EXTENSION-COMPUTE v3.24's four
//! primitives with the first two sites done and the third missing was green on
//! `cargo test`, green on `make clippy`, and **9 FAIL** on
//! `validate-peer -category type_system` — one `_fetch` and one `_match` per
//! unpublished type, plus `types_all_present`.
//!
//! This test closes the loop generically rather than by re-listing the names:
//! it walks `ALL_BUILTINS`, and any builtin whose `input_type` is a dedicated
//! `system/compute/*-args` type must be findable in the published set. Adding a
//! fifth primitive and forgetting the descriptor fails here, in-tree, instead of
//! on a sibling's harness.

#![cfg(feature = "compute")]

use entity_compute::builtins::{builtin_input_type, ALL_BUILTINS};

#[test]
fn every_builtin_args_type_has_a_published_descriptor() {
    let published: Vec<String> = entity_types::core_types::all_core_types()
        .into_iter()
        .map(|d| d.name)
        .collect();

    let mut checked = 0;
    for path in ALL_BUILTINS {
        let input_type = builtin_input_type(path, "eval")
            .unwrap_or_else(|| panic!("{path} declares no input_type for `eval` (§3.5)"));
        // Inline-equivalent builtins alias an expression type (`compute/*`),
        // which is published under its own name; the dedicated args types are
        // the `system/compute/*-args` ones this rule is about.
        if !input_type.starts_with("system/compute/") {
            continue;
        }
        checked += 1;
        assert!(
            published.iter().any(|n| n == input_type),
            "{path} declares input_type {input_type}, which is NOT in \
             all_core_types() — the peer would answer an operation whose params \
             type it does not publish, and `validate-peer -category type_system` \
             reports it as a _fetch + _match FAIL pair"
        );
    }
    // Anti-vacuity: a rename that made the prefix test match nothing would
    // otherwise leave this test passing over an empty loop.
    assert!(
        checked >= 8,
        "expected at least the 4 map/filter/fold/store args types plus the 4 \
         v3.24 ones, found {checked}"
    );
}
