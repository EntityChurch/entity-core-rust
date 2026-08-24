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
    let signed_blobs = emit_signed_blobs().expect("emit signed blobs");
    let root = Value::Map(vec![
        (text("schema"), text(SCHEMA_VERSION)),
        (text("emitter"), text(EMITTER)),
        (text("emitter_commit"), text("test")),
        (text("entities"), Value::Array(entities)),
        (text("roles"), Value::Array(roles)),
        (text("session_ids"), Value::Array(session_ids)),
        (text("signatures"), Value::Array(signatures)),
        (text("signed_blobs"), Value::Array(signed_blobs)),
        (text("signing_input"), emit_signing_input()),
    ]);
    parse_file(&to_ecf(&root)).expect("our own emission parses")
}

/// The row arrays exactly as `-emit` writes them, keyed by name.
fn emitted_payload() -> Vec<(String, Value)> {
    vec![
        (
            "entities".into(),
            Value::Array(emit_entities().expect("emit entities")),
        ),
        ("roles".into(), Value::Array(emit_roles())),
        ("session_ids".into(), Value::Array(emit_session_ids())),
        (
            "signatures".into(),
            Value::Array(emit_signatures().expect("emit signatures")),
        ),
        (
            "signed_blobs".into(),
            Value::Array(emit_signed_blobs().expect("emit signed blobs")),
        ),
        ("signing_input".into(), emit_signing_input()),
    ]
}

/// The same rows with `signed_blobs` omitted — a sibling that has not landed
/// the container surface yet.
fn round_trip_without_signed_blobs() -> VectorFile {
    let root = Value::Map(vec![
        (text("schema"), text(SCHEMA_VERSION)),
        (text("emitter"), text("core-go")),
        (text("emitter_commit"), text("test")),
        (
            text("entities"),
            Value::Array(emit_entities().expect("emit entities")),
        ),
        (text("roles"), Value::Array(emit_roles())),
        (text("session_ids"), Value::Array(emit_session_ids())),
        (
            text("signatures"),
            Value::Array(emit_signatures().expect("emit signatures")),
        ),
    ]);
    parse_file(&to_ecf(&root)).expect("a file without the new surface still parses")
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
        verify_signed_blobs(&f.signed_blobs, f.has_signed_blobs),
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

// ---------------------------------------------------------------------------
// Surface 5 — the §6.3 container
// ---------------------------------------------------------------------------

#[test]
fn every_negative_signed_blob_row_relabelled_ok_is_caught() {
    // Same control as surface 4's, and it matters more here: this surface is
    // the fold trigger, so a verifier that cannot fail would fold an
    // unimplemented security MUST.
    let f = round_trip();
    let negatives: Vec<String> = f
        .signed_blobs
        .iter()
        .filter(|s| s.expect != EXPECT_OK)
        .map(|s| s.name.clone())
        .collect();
    assert!(
        negatives.len() >= 6,
        "expected several negative rows, found {negatives:?}"
    );

    for name in negatives {
        let mut f = round_trip();
        f.signed_blobs
            .iter_mut()
            .find(|s| s.name == name)
            .unwrap()
            .expect = EXPECT_OK.into();
        assert_eq!(
            verify_signed_blobs(&f.signed_blobs, true).fail,
            1,
            "relabelling {name} as ok was not caught"
        );
    }
}

#[test]
fn the_four_verdicts_are_not_interchangeable() {
    // `unusable_key`, `signer_mismatch`, `bad_signature` and a decode skip are
    // four different diagnoses, and the taxonomy is only worth carrying if a
    // verifier refuses to accept one in place of another. Go's three classes
    // map 1:1 onto the first three names — this is what keeps them aligned.
    for (name, wrong) in [
        ("ed25519/forged-signer", EXPECT_SIGNER_MISMATCH),
        ("ed25519/false-claim", EXPECT_UNUSABLE_KEY),
        ("unsupported-key-type/0xfe", EXPECT_BAD_SIGNATURE),
        ("ed25519/tampered-inner-entity", EXPECT_UNUSABLE_KEY),
        ("not-a-container", EXPECT_BAD_SIGNATURE),
    ] {
        let mut f = round_trip();
        f.signed_blobs
            .iter_mut()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("row {name} is missing"))
            .expect = wrong.into();
        assert_eq!(
            verify_signed_blobs(&f.signed_blobs, true).fail,
            1,
            "{name} relabelled {wrong} was not caught — the taxonomy has collapsed"
        );
    }
}

#[test]
fn a_valid_blob_verified_under_the_wrong_bucket_is_caught() {
    // The bucket-binding mechanism, asserted from the other direction than the
    // replay row: take a row that MUST pass and move its key. If the signature
    // did not cover the rendezvous key this would still verify, and the whole
    // §5 protection would be absent while every row still read green.
    let mut f = round_trip();
    let row = f
        .signed_blobs
        .iter_mut()
        .find(|s| s.name == "ed25519/valid")
        .unwrap();
    row.rendezvous_key[0] ^= 0xFF;
    assert_eq!(
        verify_signed_blobs(&f.signed_blobs, true).fail,
        1,
        "a valid blob must not verify under a bucket it was not signed for"
    );
}

#[test]
fn a_wrong_expect_signer_is_caught_on_the_container_too() {
    let mut f = round_trip();
    f.signed_blobs
        .iter_mut()
        .find(|s| s.name == "ed25519/valid")
        .unwrap()
        .expect_signer = "peer-nobody".into();
    assert_eq!(verify_signed_blobs(&f.signed_blobs, true).fail, 1);
}

#[test]
fn a_perturbed_inner_blob_expectation_is_caught() {
    // Byte preservation through the container. Field-wise equality would pass
    // a payload that was decoded and re-encoded; only the bytes catch it, and
    // only the bytes keep the signature valid.
    let mut f = round_trip();
    let row = f
        .signed_blobs
        .iter_mut()
        .find(|s| s.name == "ed25519/valid")
        .unwrap();
    let last = row.expect_inner_blob.len() - 1;
    row.expect_inner_blob[last] ^= 0x01;
    assert_eq!(verify_signed_blobs(&f.signed_blobs, true).fail, 1);
}

#[test]
fn a_file_without_the_container_surface_is_reported_absent_not_passed() {
    // The silent-zero guard. A missing array must not read as a clean surface:
    // "0 fail" on a surface nobody emitted is precisely the shape of the
    // §11.5.1 blindness the envelope proposal was written to end.
    let f = round_trip_without_signed_blobs();
    assert!(!f.has_signed_blobs);
    assert!(f.signed_blobs.is_empty());

    let r = verify_signed_blobs(&f.signed_blobs, f.has_signed_blobs);
    assert_eq!(r.fail, 0, "an absent surface is not a failure");
    assert_eq!(r.pass, 0, "and it is not a pass either");
    assert!(
        r.lines.iter().any(|l| l.contains("ABSENT")),
        "the absence must be stated, not inferred from a zero: {:?}",
        r.lines
    );

    // The other four surfaces still cross — that is the point of making the
    // array optional rather than bumping the schema.
    assert_eq!(verify_signatures(&f.signatures).fail, 0);
}

#[test]
fn a_signed_blobs_key_carrying_null_is_refused_rather_than_read_as_absence() {
    // An emitter that writes `signed_blobs: null` is claiming the surface while
    // carrying nothing. Treating that as absence would let it announce the
    // container and never be checked on it.
    let root = Value::Map(vec![
        (text("schema"), text(SCHEMA_VERSION)),
        (text("emitter"), text(EMITTER)),
        (text("emitter_commit"), text("test")),
        (text("entities"), Value::Array(vec![])),
        (text("roles"), Value::Array(vec![])),
        (text("session_ids"), Value::Array(vec![])),
        (text("signatures"), Value::Array(vec![])),
        (text("signed_blobs"), Value::Null),
    ]);
    assert!(parse_file(&to_ecf(&root)).is_err());
}

// ---------------------------------------------------------------------------
// The committed artifact — the guard that was missing
// ---------------------------------------------------------------------------

/// **The emitter is not the artifact.** `0dd1ba3` grew surface 5 and its tests
/// and never re-ran `-emit`, so the committed file stayed at `616f7d4` while the
/// routing doc claimed it carried the array. Every test passed; the whole suite
/// was green; the fold trigger was unmet and nothing said so. `core-go` found it
/// by running our own silent-zero guard against our own file.
///
/// So the artifact is now checked against the emitter. `emitter_commit` and
/// `schema` are excluded deliberately — the first changes every commit, and
/// neither is a row.
#[test]
fn the_committed_vector_file_is_not_stale() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/validation/vectors/webrtc-coordination-rust.cbor"
    );
    let raw = std::fs::read(path).expect("the committed vector file exists");
    let root: Value = ciborium::from_reader(raw.as_slice()).expect("it decodes");
    let committed = as_map(&root).expect("it is a map");

    for (key, fresh) in emitted_payload() {
        let on_disk = committed.get(&key).unwrap_or_else(|| {
            panic!(
                "the committed file has no {key:?} — re-run `-emit` and commit the result; \
                 an emitter change is not a crossing until the artifact carries it"
            )
        });
        // Compare **canonical bytes**, not `Value` trees. A decoded map comes
        // back in the file's ECF-sorted order while a freshly built one is in
        // insertion order, so `Value == Value` would report a diff for two
        // encodings that are byte-identical on the wire. Re-encoding both
        // through `to_ecf` is also the comparison that actually matters here:
        // what a sibling reads is bytes.
        // Report the *shape* of the difference, not two multi-kilobyte hex
        // dumps. A guard nobody can read is a guard that gets muted.
        let (a, b) = (to_ecf(on_disk), to_ecf(&fresh));
        if a != b {
            let at = a
                .iter()
                .zip(b.iter())
                .position(|(x, y)| x != y)
                .unwrap_or(a.len().min(b.len()));
            panic!(
                "{key:?} in the committed file differs from what this build emits.\n\
                 on disk: {} bytes, fresh: {} bytes, first difference at byte {at}\n\
                 fix: cargo run -p webrtc-vectors -- -emit \
                 docs/validation/vectors/webrtc-coordination-rust.cbor",
                a.len(),
                b.len()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Surface 0 — the signing input
// ---------------------------------------------------------------------------

#[test]
fn a_signing_input_divergence_is_caught_before_the_signature_rows() {
    // Go's contribution, and the case that motivated it: their first shape was
    // `content_hash ‖ rendezvous_key`. Reordered here, the block must fail on
    // its own rather than leaving a reader to infer it from 10 identical
    // signature failures.
    let mut f = round_trip();
    let si = f.signing_input.as_mut().expect("we emit the block");
    si.sample_bytes.reverse();
    assert!(verify_signing_input(f.signing_input.as_ref()).fail >= 1);
}

#[test]
fn a_signing_input_with_the_right_bytes_but_wrong_component_table_is_caught() {
    let mut f = round_trip();
    let si = f.signing_input.as_mut().expect("we emit the block");
    si.components[2].1 = 32; // rendezvous_key claimed as 32, not 33
    assert!(verify_signing_input(f.signing_input.as_ref()).fail >= 1);
}

#[test]
fn an_absent_signing_input_is_reported_absent_not_passed() {
    let r = verify_signing_input(None);
    assert_eq!(r.fail, 0);
    assert_eq!(r.pass, 0);
    assert!(
        r.lines.iter().any(|l| l.contains("ABSENT")),
        "{:?}",
        r.lines
    );
}

// ---------------------------------------------------------------------------
// Row guards — adopted from core-go
// ---------------------------------------------------------------------------

/// The replay row adjudicates the entire binding mechanism, so a **false pass**
/// there would be expensive: it would read as "binding confirmed" when the row
/// might simply never have been reachable. Re-point it at the bucket it was
/// actually signed under and it must flip to `ok`.
#[test]
fn the_replay_row_is_actually_exercised() {
    let mut f = round_trip();
    let signed_under = f
        .signed_blobs
        .iter()
        .find(|s| s.name == "ed25519/valid")
        .expect("the valid row states the bucket")
        .rendezvous_key
        .clone();

    let row = f
        .signed_blobs
        .iter_mut()
        .find(|s| s.name == "ed25519/replayed-into-another-bucket")
        .expect("the replay row exists");
    assert_ne!(
        row.rendezvous_key, signed_under,
        "the replay row must not already be pointed at its own bucket"
    );

    row.rendezvous_key = signed_under;
    row.expect = EXPECT_OK.into();
    assert_eq!(
        verify_signed_blobs(&f.signed_blobs, true).fail,
        0,
        "the replayed blob must verify in the bucket it WAS signed for — otherwise \
         the replay row passes for some reason other than bucket binding"
    );
}

/// The Ed448 ratchet: `key_type` is parametric, and a suite that quietly stopped
/// carrying a non-Ed25519 signer would pass while the floor-not-ceiling ruling
/// went unexercised. Surface 4 has this guard; surface 5 needs its own.
#[test]
fn the_ed448_signed_blob_row_is_actually_exercised() {
    let f = round_trip();
    let row = f
        .signed_blobs
        .iter()
        .find(|s| s.name == "ed448/valid")
        .expect("an Ed448 container row exists");
    assert_eq!(row.expect, EXPECT_OK);

    let signer = entity_crypto::Ed448Keypair::from_seed(&ed448_seed(0x42))
        .expect("seeds")
        .peer_id()
        .to_string();
    assert_eq!(
        row.expect_signer, signer,
        "the Ed448 row must name an Ed448 signer"
    );

    // And it must genuinely verify, not merely be labelled ok.
    let mut only_448 = f;
    only_448.signed_blobs.retain(|s| s.name == "ed448/valid");
    let r = verify_signed_blobs(&only_448.signed_blobs, true);
    assert_eq!(r.pass, 1);
    assert_eq!(r.fail, 0);
}
