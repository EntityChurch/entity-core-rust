//! Negative controls for the verifier.
//!
//! A harness that only ever verifies its own emission proves a **round trip** —
//! the loopback trap in a different costume. Encoder and decoder agree with each
//! other by construction, so a same-side green says nothing about whether the
//! checks can fail at all.
//!
//! Every test here mutates one surface the way a real divergence would and
//! asserts the verifier **catches** it. `core-go` ran this discipline first and
//! it found a real flaw in their verifier before it ever ran against us — their
//! convergence check recomputed roles with Go's own function, so it could only
//! prove Go agrees with itself. `role_set_that_is_jointly_non_convergent_*`
//! below is the Rust guard against writing that same check.

use super::*;

/// Emit the real rows and parse them back. Every test starts from bytes this
/// implementation actually produces, so a control that fires is telling us
/// about the checks, not about a hand-built fixture.
fn round_trip() -> VectorFile {
    let entities = emit_entities().expect("emit entities");
    let roles = emit_roles();
    let session_ids = emit_session_ids();
    let signatures = emit_signatures().expect("emit signatures");
    let root = Value::Map(vec![
        (text("schema"), text(SCHEMA_VERSION)),
        (text("emitter"), text(EMITTER)),
        (text("emitter_commit"), text("test")),
        (text("entities"), Value::Array(entities)),
        (text("roles"), Value::Array(roles)),
        (text("session_ids"), Value::Array(session_ids)),
        (text("signatures"), Value::Array(signatures)),
    ]);
    parse_file(&to_ecf(&root)).expect("our own emission parses")
}

#[test]
fn our_own_emission_verifies_clean() {
    // The baseline every control below is a mutation of. On its own this is a
    // round trip and proves nothing about the crossing — it is here so that a
    // failing control cannot be blamed on a broken fixture.
    let f = round_trip();
    assert_eq!(f.schema, SCHEMA_VERSION);
    for r in [
        verify_entities(&f.entities),
        verify_roles(&f.roles),
        verify_session_ids(&f.session_ids),
        verify_signatures(&f.signatures),
    ] {
        assert_eq!(r.fail, 0, "{} reported failures: {:?}", r.surface, r.lines);
        assert!(r.pass > 0, "{} checked nothing", r.surface);
    }
}

// ---------------------------------------------------------------------------
// Surface 1 — wire shape
// ---------------------------------------------------------------------------

#[test]
fn a_ufrag_present_where_absence_was_claimed_is_caught() {
    // The row the whole exercise turns on. An OPTIONAL that arrives as "" or
    // null instead of absent round-trips perfectly same-side and is wrong on
    // the wire: addIceCandidate reads "" as a real ufrag.
    let mut f = round_trip();
    let row = f
        .entities
        .iter_mut()
        .find(|e| e.expect_absent.iter().any(|x| x == "username_fragment"))
        .expect("an absent-ufrag row exists");

    // Rebuild the blob WITH a ufrag while the row still claims absence.
    let cand = IceCandidate {
        session_id: SessionId::parse(row.session_id.clone()).unwrap(),
        candidate: row.candidate.clone(),
        sdp_mid: row.sdp_mid.clone(),
        sdp_mline_index: row.sdp_mline_index,
        username_fragment: Some("smuggled".into()),
    };
    row.blob = entity_wire::encode_entity(&cand.to_entity().unwrap());

    assert_eq!(verify_entities(&f.entities).fail, 1);
}

#[test]
fn an_empty_string_ufrag_is_not_accepted_as_absence() {
    // Distinct from the test above: "" is the shape a careless encoder actually
    // produces. Our decoder maps both absent and "" to None, so the DECODE
    // direction alone would pass this — it is the byte-level re-encode check
    // that catches it. That asymmetry with Go's field-level check is the reason
    // the re-encode direction exists.
    let mut f = round_trip();
    let row = f
        .entities
        .iter_mut()
        .find(|e| e.expect_absent.iter().any(|x| x == "username_fragment"))
        .expect("an absent-ufrag row exists");

    let cand = IceCandidate {
        session_id: SessionId::parse(row.session_id.clone()).unwrap(),
        candidate: row.candidate.clone(),
        sdp_mid: row.sdp_mid.clone(),
        sdp_mline_index: row.sdp_mline_index,
        username_fragment: Some(String::new()),
    };
    row.blob = entity_wire::encode_entity(&cand.to_entity().unwrap());

    assert_eq!(verify_entities(&f.entities).fail, 1);
}

#[test]
fn a_row_whose_stated_sdp_is_not_the_sdp_in_the_blob_is_caught() {
    // `sdp` is sealed behind a VerifiedSigner, so this is the check that stands
    // in for Go's field comparison. If it did not fire, the sealed field would
    // be entirely unchecked and the suite would be quietly blind to the payload
    // that matters most.
    let mut f = round_trip();
    f.entities
        .iter_mut()
        .find(|e| e.kind == "offer")
        .expect("an offer row exists")
        .sdp
        .push_str("a=smuggled\r\n");
    assert_eq!(verify_entities(&f.entities).fail, 1);
}

#[test]
fn a_mislabelled_kind_is_caught() {
    let mut f = round_trip();
    f.entities
        .iter_mut()
        .find(|e| e.kind == "offer")
        .expect("an offer row exists")
        .kind = "answer".into();
    assert_eq!(verify_entities(&f.entities).fail, 1);
}

#[test]
fn a_session_id_that_does_not_match_the_blob_is_caught() {
    let mut f = round_trip();
    f.entities[0].session_id = sid_bytes(0x77, 16);
    assert_eq!(verify_entities(&f.entities).fail, 1);
}

// ---------------------------------------------------------------------------
// Surface 2 — the offerer rule
// ---------------------------------------------------------------------------

#[test]
fn a_flipped_offerer_decision_is_caught() {
    let mut f = round_trip();
    let row = f
        .roles
        .iter_mut()
        .find(|r| r.impolite.is_some())
        .expect("a role row exists");
    row.impolite = Some(!row.impolite.unwrap());
    assert!(verify_roles(&f.roles).fail >= 1);
}

#[test]
fn a_flipped_pair_suppress_is_caught() {
    let mut f = round_trip();
    let row = f
        .roles
        .iter_mut()
        .find(|r| r.pair_suppress.is_some())
        .expect("a pair_suppress row exists");
    row.pair_suppress = Some(!row.pair_suppress.unwrap());
    assert!(verify_roles(&f.roles).fail >= 1);
}

#[test]
fn role_set_that_is_jointly_non_convergent_both_impolite_is_caught() {
    // Each row here is individually plausible; the SET describes a fatal glare.
    // This is the check that must read the FILE's stated values — recomputing
    // with our own `glare_role` would report convergence and pass.
    let mut f = round_trip();
    for r in f.roles.iter_mut() {
        if r.impolite.is_some() {
            r.impolite = Some(true);
            r.pair_suppress = Some(false);
        }
    }
    let report = verify_roles(&f.roles);
    assert!(
        report
            .lines
            .iter()
            .any(|l| l.contains("set/convergence") && l.contains("FAIL")),
        "convergence check did not fire; it is probably recomputing rather than \
         reading the file: {:?}",
        report.lines
    );
}

#[test]
fn role_set_that_is_jointly_non_convergent_neither_impolite_is_caught() {
    // The deadlock direction — neither side offers. Asserted separately because
    // a check written as "not both true" passes this one.
    let mut f = round_trip();
    for r in f.roles.iter_mut() {
        if r.impolite.is_some() {
            r.impolite = Some(false);
            r.pair_suppress = Some(true);
        }
    }
    let report = verify_roles(&f.roles);
    assert!(
        report
            .lines
            .iter()
            .any(|l| l.contains("set/convergence") && l.contains("FAIL")),
        "convergence check did not catch the deadlock direction: {:?}",
        report.lines
    );
}

#[test]
fn a_role_returned_for_equal_ids_is_caught() {
    // §6.4's skip-own failing OPEN is the class the spec calls miserable to
    // diagnose, because every individual step reports success. A file claiming
    // a role where a refusal is required must fail.
    let mut f = round_trip();
    let row = f
        .roles
        .iter_mut()
        .find(|r| !r.error.is_empty())
        .expect("the equal-ids row exists");
    row.error = String::new();
    row.impolite = Some(true);
    row.pair_suppress = Some(false);
    assert!(verify_roles(&f.roles).fail >= 1);
}

#[test]
fn an_unknown_expected_error_is_refused_rather_than_ignored() {
    let mut f = round_trip();
    f.roles
        .iter_mut()
        .find(|r| !r.error.is_empty())
        .expect("the equal-ids row exists")
        .error = "something_else".into();
    assert!(verify_roles(&f.roles).fail >= 1);
}

// ---------------------------------------------------------------------------
// Surface 3 — the session_id floor
// ---------------------------------------------------------------------------

#[test]
fn a_floor_decision_flipped_in_either_direction_is_caught() {
    for want_accept in [true, false] {
        let mut f = round_trip();
        let row = f
            .session_ids
            .iter_mut()
            .find(|s| s.accept == want_accept)
            .unwrap_or_else(|| panic!("no accept={want_accept} row to flip"));
        row.accept = !want_accept;
        assert_eq!(
            verify_session_ids(&f.session_ids).fail,
            1,
            "flipping accept={want_accept} was not caught"
        );
    }
}

// ---------------------------------------------------------------------------
// Surface 4 — §6.3 verification
// ---------------------------------------------------------------------------

#[test]
fn every_negative_signature_row_relabelled_ok_is_caught() {
    // The control that distinguishes a verifier from a stub: a verifier that
    // returns `ok` unconditionally passes a suite of positives. Each negative
    // row, relabelled as a positive, must fail.
    let f = round_trip();
    let negatives: Vec<String> = f
        .signatures
        .iter()
        .filter(|s| s.expect != EXPECT_OK)
        .map(|s| s.name.clone())
        .collect();
    assert!(
        negatives.len() >= 3,
        "expected several negative rows, found {negatives:?}"
    );

    for name in negatives {
        let mut f = round_trip();
        f.signatures
            .iter_mut()
            .find(|s| s.name == name)
            .unwrap()
            .expect = EXPECT_OK.into();
        assert_eq!(
            verify_signatures(&f.signatures).fail,
            1,
            "relabelling {name} as ok was not caught"
        );
    }
}

#[test]
fn a_positive_row_relabelled_as_a_failure_is_caught() {
    // The other direction: a verifier that returned an error unconditionally
    // would pass every negative row, so the positives must be load-bearing too.
    let mut f = round_trip();
    f.signatures
        .iter_mut()
        .find(|s| s.expect == EXPECT_OK)
        .expect("a positive row exists")
        .expect = EXPECT_BAD_SIGNATURE.into();
    assert_eq!(verify_signatures(&f.signatures).fail, 1);
}

#[test]
fn a_wrong_expect_signer_is_caught() {
    // Check (b) passes here — the signature is genuine. Only the derived-id
    // comparison catches it, which is what makes §6.3's check (a) load-bearing.
    let mut f = round_trip();
    f.signatures
        .iter_mut()
        .find(|s| !s.expect_signer.is_empty())
        .expect("a row states an expected signer")
        .expect_signer = "peer-that-did-not-sign".into();
    assert_eq!(verify_signatures(&f.signatures).fail, 1);
}

#[test]
fn bad_signature_and_signer_mismatch_are_not_interchangeable() {
    // A verifier that collapsed the two error kinds would pass both rows. They
    // mean different things: one is a forged payload, the other a truthful
    // signature under a false name.
    let mut f = round_trip();
    let mut swapped = 0;
    for s in f.signatures.iter_mut() {
        if s.expect == EXPECT_BAD_SIGNATURE {
            s.expect = EXPECT_SIGNER_MISMATCH.into();
            swapped += 1;
        } else if s.expect == EXPECT_SIGNER_MISMATCH {
            s.expect = EXPECT_BAD_SIGNATURE.into();
            swapped += 1;
        }
    }
    assert!(swapped > 0, "no negative rows to swap");
    assert_eq!(verify_signatures(&f.signatures).fail, swapped);
}

#[test]
fn the_ed448_row_is_actually_exercised() {
    // Guards the fix this crossing found. If the Ed448 row were dropped from
    // our emission, the suite would go green while the §6.3 key-type narrowing
    // silently returned.
    let f = round_trip();
    let ed448 = f
        .signatures
        .iter()
        .find(|s| s.key_type == u64::from(entity_crypto::KEY_TYPE_ED448))
        .expect("an Ed448 signature row must be crossed — §6.3 spells key_type 0x01 literally");
    assert_eq!(ed448.expect, EXPECT_OK);
    assert!(!ed448.expect_signer.is_empty());
}

// ---------------------------------------------------------------------------
// File-level
// ---------------------------------------------------------------------------

#[test]
fn expect_absent_must_be_present_as_an_array() {
    // Go's amendment, and the one that matters most: expressing "expected
    // absent" by OMITTING the field would re-create, one level up, the exact
    // absent-vs-null ambiguity the row exists to test. A file that omits it is
    // refused, not read permissively.
    let root = Value::Map(vec![
        (text("schema"), text(SCHEMA_VERSION)),
        (text("emitter"), text("someone-else")),
        (text("emitter_commit"), text("test")),
        (
            text("entities"),
            Value::Array(vec![Value::Map(vec![
                (text("name"), text("offer/basic")),
                (text("kind"), text("offer")),
                (text("blob"), ecf_bytes(vec![0x01])),
                (text("session_id"), ecf_bytes(sid_bytes(0x10, 16))),
                // expect_absent deliberately omitted
            ])]),
        ),
        (text("roles"), Value::Array(vec![])),
        (text("session_ids"), Value::Array(vec![])),
        (text("signatures"), Value::Array(vec![])),
    ]);
    let err = parse_file(&to_ecf(&root)).expect_err("omitted expect_absent must be refused");
    assert!(
        format!("{err:#}").contains("expect_absent"),
        "refusal did not name the field: {err:#}"
    );
}

#[test]
fn the_emitted_rows_are_byte_stable_across_runs() {
    // Determinism is what makes `emitter_commit` mean anything: re-emitting at
    // the same commit must reproduce the bytes exactly, or the file is an
    // assertion rather than re-derivable evidence (ADR-0012). Nothing in the
    // emit path may touch a clock or a random source.
    assert_eq!(
        to_ecf(&Value::Array(emit_signatures().unwrap())),
        to_ecf(&Value::Array(emit_signatures().unwrap())),
        "signature rows are not deterministic"
    );
    assert_eq!(
        to_ecf(&Value::Array(emit_entities().unwrap())),
        to_ecf(&Value::Array(emit_entities().unwrap())),
        "entity rows are not deterministic"
    );
}

#[test]
fn a_file_with_a_foreign_schema_is_refused_not_partially_checked() {
    let root = Value::Map(vec![
        (text("schema"), text("webrtc-sdp-ice/99")),
        (text("emitter"), text("someone-else")),
        (text("emitter_commit"), text("test")),
        (text("entities"), Value::Array(vec![])),
        (text("roles"), Value::Array(vec![])),
        (text("session_ids"), Value::Array(vec![])),
        (text("signatures"), Value::Array(vec![])),
    ]);
    let path = std::env::temp_dir().join("webrtc-vectors-foreign-schema.cbor");
    std::fs::write(&path, to_ecf(&root)).unwrap();
    let err = verify_file(path.to_str().unwrap()).expect_err("foreign schema must be refused");
    assert!(format!("{err:#}").contains("webrtc-sdp-ice/99"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn emit_and_verify_together_is_refused() {
    // A run that silently did both would report a round trip as a crossing.
    let args = vec![
        "-emit".to_string(),
        "a".to_string(),
        "-verify".to_string(),
        "b".to_string(),
    ];
    assert!(parse_args(&args).is_err());
}
