//! Rust's seat in the §6.5 coordination crossing.
//!
//! `-emit PATH` writes this implementation's vector file; `-verify PATH` reads a
//! sibling's and checks every row against **this** implementation's functions.
//! The contract and field names were agreed with `entity-core-go` (their
//! `cmd/webrtc-vectors`), amended by them on four points — `expect_absent` as a
//! required array, `signatures` as a list carrying negatives, `key_type` as the
//! **binary peer-id wire prefix** rather than the entity-data string, and
//! `emitter_commit` for provenance (ADR-0012).
//!
//! **What a green run is worth.** This crosses the **coordination** layer — the
//! pure half: wire shape, the offerer rule, the `session_id` floor, and §6.3
//! verification. Per §11.5.1 it is **not** evidence that WebRTC transport works.
//! S5 (two real browser peers over a real signaling node) remains the only real
//! evidence, and this tool prints that line on success so a number can't be
//! quoted without it.
//!
//! **Two deliberate asymmetries with Go's harness**, both recorded rather than
//! silently absorbed:
//!
//! 1. **Entity rows are checked byte-first, not field-first.** Go reads the
//!    decoded struct's fields and compares them to the row. Rust's `sdp` is
//!    sealed behind [`entity_signaling::webrtc::Offer::accept_remote_description`]
//!    — a `VerifiedSigner` is required to read a remote SDP, and the entity rows
//!    carry no signature — so instead we **re-encode the row's stated fields and
//!    compare the resulting blob bytes**. That checks strictly more: it proves
//!    the two implementations agree on ECF bytes, and it catches a `null`
//!    where a field should be absent even though our decoder maps both to
//!    `None`. The decode direction is still checked for everything not sealed
//!    (kind, `session_id`, and every candidate field including the ufrag).
//! 2. **Convergence reads the file, never our own recomputation.** Go found this
//!    flaw in their own verifier before it ever ran against us: recomputing the
//!    roles with our own `glare_role` could only ever prove Rust agrees with
//!    Rust, and would happily pass a sibling file claiming both peers impolite.

use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use entity_ecf::{bytes as ecf_bytes, text, to_ecf, Value};
use entity_signaling::webrtc::{
    classify_blob, glare_role, pair_should_suppress_offer, verify_claimed_signer,
    verify_coordination_signature, Answer, CollectedWebRtc, GlareRole, IceCandidate, Offer,
    SessionId, SCHEMA_VERSION,
};
use entity_signaling::SignalingError;

const EMITTER: &str = "core-rust";

const EXPECT_OK: &str = "ok";
const EXPECT_BAD_SIGNATURE: &str = "bad_signature";
const EXPECT_SIGNER_MISMATCH: &str = "signer_mismatch";
const ERR_SELF_NEGOTIATION: &str = "self_negotiation";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let parsed = parse_args(&args);
    match parsed {
        Ok(Mode::Emit(path)) => match emit_file(&path) {
            Ok(()) => {}
            Err(e) => fail(&format!("emit: {e:#}")),
        },
        Ok(Mode::Verify(path)) => match verify_file(&path) {
            Ok(true) => {}
            Ok(false) => std::process::exit(1),
            Err(e) => fail(&format!("verify: {e:#}")),
        },
        Err(e) => {
            eprintln!("webrtc-vectors: {e}");
            eprintln!("usage: webrtc-vectors -emit PATH | -verify PATH");
            std::process::exit(2);
        }
    }
}

fn fail(msg: &str) -> ! {
    eprintln!("webrtc-vectors: {msg}");
    std::process::exit(1);
}

enum Mode {
    Emit(String),
    Verify(String),
}

/// Same flag surface as Go's, including the "pick one" refusal — a run that
/// silently emitted *and* verified would report a round trip as a crossing.
fn parse_args(args: &[String]) -> Result<Mode> {
    let mut emit = None;
    let mut verify = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-emit" | "--emit" => {
                emit = Some(args.get(i + 1).context("-emit needs a PATH")?.clone());
                i += 2;
            }
            "-verify" | "--verify" => {
                verify = Some(args.get(i + 1).context("-verify needs a PATH")?.clone());
                i += 2;
            }
            other => bail!("unknown argument {other:?}"),
        }
    }
    match (emit, verify) {
        (Some(_), Some(_)) => bail!("pick one of -emit / -verify"),
        (Some(p), None) => Ok(Mode::Emit(p)),
        (None, Some(p)) => Ok(Mode::Verify(p)),
        (None, None) => bail!("nothing to do"),
    }
}

// ---------------------------------------------------------------------------
// The row model
// ---------------------------------------------------------------------------

#[cfg_attr(test, derive(Debug))]
struct EntityVector {
    name: String,
    kind: String,
    blob: Vec<u8>,
    session_id: Vec<u8>,
    sdp: String,
    candidate: String,
    sdp_mid: String,
    sdp_mline_index: u64,
    username_fragment: Option<String>,
    expect_absent: Vec<String>,
}

#[cfg_attr(test, derive(Debug))]
struct RoleVector {
    name: String,
    self_id: String,
    other: String,
    impolite: Option<bool>,
    pair_suppress: Option<bool>,
    error: String,
}

#[cfg_attr(test, derive(Debug))]
struct SessionIdVector {
    name: String,
    bytes: Vec<u8>,
    accept: bool,
}

#[cfg_attr(test, derive(Debug))]
struct SignatureVector {
    name: String,
    entity_blob: Vec<u8>,
    public_key: Vec<u8>,
    key_type: u64,
    signature: Vec<u8>,
    claimed_peer_id: String,
    expect_signer: String,
    expect: String,
}

#[cfg_attr(test, derive(Debug))]
struct VectorFile {
    schema: String,
    emitter: String,
    emitter_commit: String,
    entities: Vec<EntityVector>,
    roles: Vec<RoleVector>,
    session_ids: Vec<SessionIdVector>,
    signatures: Vec<SignatureVector>,
}

// ---------------------------------------------------------------------------
// CBOR reading — hand-parsed on purpose
// ---------------------------------------------------------------------------
//
// A serde derive would be shorter, but this is a wire-fidelity tool: the whole
// point is that a bstr is not an array of integers and an absent key is not a
// null. Reading the `Value` tree explicitly keeps those distinctions visible
// instead of delegating them to a derive's defaults.

fn as_map(v: &Value) -> Result<BTreeMap<String, Value>> {
    let entries = v.as_map().context("expected a CBOR map")?;
    let mut out = BTreeMap::new();
    for (k, val) in entries {
        let key = k.as_text().context("map key is not text")?.to_string();
        out.insert(key, val.clone());
    }
    Ok(out)
}

fn get<'a>(m: &'a BTreeMap<String, Value>, k: &str) -> Option<&'a Value> {
    // A CBOR null is treated as "present but empty" only where the schema
    // permits it; callers that care about absent-vs-null check `contains_key`.
    m.get(k).filter(|v| !v.is_null())
}

fn req_text(m: &BTreeMap<String, Value>, k: &str) -> Result<String> {
    Ok(get(m, k)
        .and_then(|v| v.as_text())
        .with_context(|| format!("missing or non-text field {k:?}"))?
        .to_string())
}

fn opt_text(m: &BTreeMap<String, Value>, k: &str) -> String {
    get(m, k)
        .and_then(|v| v.as_text())
        .unwrap_or_default()
        .to_string()
}

fn req_bytes(m: &BTreeMap<String, Value>, k: &str) -> Result<Vec<u8>> {
    Ok(get(m, k)
        .and_then(|v| v.as_bytes())
        .with_context(|| format!("missing or non-bstr field {k:?}"))?
        .clone())
}

fn opt_u64(m: &BTreeMap<String, Value>, k: &str) -> u64 {
    get(m, k)
        .and_then(|v| v.as_integer())
        .and_then(|i| u64::try_from(i).ok())
        .unwrap_or(0)
}

fn opt_bool(m: &BTreeMap<String, Value>, k: &str) -> Option<bool> {
    get(m, k).and_then(|v| v.as_bool())
}

fn opt_string_field(m: &BTreeMap<String, Value>, k: &str) -> Option<String> {
    get(m, k).and_then(|v| v.as_text()).map(|s| s.to_string())
}

fn req_array<'a>(m: &'a BTreeMap<String, Value>, k: &str) -> Result<&'a Vec<Value>> {
    get(m, k)
        .and_then(|v| v.as_array())
        .with_context(|| format!("missing or non-array field {k:?}"))
}

fn parse_file(raw: &[u8]) -> Result<VectorFile> {
    let root: Value = ciborium::from_reader(raw).context("decode vector file")?;
    let m = as_map(&root)?;

    let mut entities = Vec::new();
    for row in req_array(&m, "entities")? {
        let r = as_map(row)?;
        // `expect_absent` is REQUIRED — Go's amendment, and the one that
        // matters: expressing "expected absent" by omitting the field would
        // re-create, one level up, the exact absent-vs-null ambiguity the row
        // exists to test.
        let expect_absent = req_array(&r, "expect_absent")
            .context("expect_absent is a required array (possibly empty), not an omitted field")?
            .iter()
            .map(|v| v.as_text().unwrap_or_default().to_string())
            .collect();
        entities.push(EntityVector {
            name: req_text(&r, "name")?,
            kind: req_text(&r, "kind")?,
            blob: req_bytes(&r, "blob")?,
            session_id: req_bytes(&r, "session_id")?,
            sdp: opt_text(&r, "sdp"),
            candidate: opt_text(&r, "candidate"),
            sdp_mid: opt_text(&r, "sdp_mid"),
            sdp_mline_index: opt_u64(&r, "sdp_mline_index"),
            username_fragment: opt_string_field(&r, "username_fragment"),
            expect_absent,
        });
    }

    let mut roles = Vec::new();
    for row in req_array(&m, "roles")? {
        let r = as_map(row)?;
        roles.push(RoleVector {
            name: req_text(&r, "name")?,
            self_id: req_text(&r, "self")?,
            other: req_text(&r, "other")?,
            impolite: opt_bool(&r, "impolite"),
            pair_suppress: opt_bool(&r, "pair_suppress"),
            error: opt_text(&r, "error"),
        });
    }

    let mut session_ids = Vec::new();
    for row in req_array(&m, "session_ids")? {
        let r = as_map(row)?;
        session_ids.push(SessionIdVector {
            name: req_text(&r, "name")?,
            bytes: req_bytes(&r, "bytes")?,
            accept: opt_bool(&r, "accept").context("session_id row needs `accept`")?,
        });
    }

    let mut signatures = Vec::new();
    for row in req_array(&m, "signatures")? {
        let r = as_map(row)?;
        signatures.push(SignatureVector {
            name: req_text(&r, "name")?,
            entity_blob: req_bytes(&r, "entity_blob")?,
            public_key: req_bytes(&r, "public_key")?,
            key_type: opt_u64(&r, "key_type"),
            signature: req_bytes(&r, "signature")?,
            claimed_peer_id: opt_text(&r, "claimed_peer_id"),
            expect_signer: opt_text(&r, "expect_signer"),
            expect: req_text(&r, "expect")?,
        });
    }

    Ok(VectorFile {
        schema: req_text(&m, "schema")?,
        emitter: req_text(&m, "emitter")?,
        emitter_commit: opt_text(&m, "emitter_commit"),
        entities,
        roles,
        session_ids,
        signatures,
    })
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

struct Report {
    surface: &'static str,
    pass: usize,
    fail: usize,
    lines: Vec<String>,
}

impl Report {
    fn new(surface: &'static str) -> Self {
        Self {
            surface,
            pass: 0,
            fail: 0,
            lines: Vec::new(),
        }
    }
    fn ok(&mut self, name: &str) {
        self.pass += 1;
        self.lines.push(format!("      PASS  {name}"));
    }
    fn bad(&mut self, name: &str, why: &str) {
        self.fail += 1;
        self.lines.push(format!("      FAIL  {name}: {why}"));
    }
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

fn verify_file(path: &str) -> Result<bool> {
    let raw = std::fs::read(path).with_context(|| format!("read {path}"))?;
    let f = parse_file(&raw)?;

    if f.schema != SCHEMA_VERSION {
        bail!(
            "schema {:?} is not {:?} — refusing to partially check a file this build does not speak",
            f.schema,
            SCHEMA_VERSION
        );
    }

    println!("verifying {path}");
    println!(
        "  emitter={} commit={} schema={}",
        f.emitter, f.emitter_commit, f.schema
    );
    println!();

    let reports = [
        verify_entities(&f.entities),
        verify_roles(&f.roles),
        verify_session_ids(&f.session_ids),
        verify_signatures(&f.signatures),
    ];

    let (mut total, mut failed) = (0usize, 0usize);
    for r in &reports {
        println!("  {:<24} {} pass / {} fail", r.surface, r.pass, r.fail);
        for l in &r.lines {
            println!("{l}");
        }
        total += r.pass + r.fail;
        failed += r.fail;
    }
    println!();
    if failed == 0 {
        println!(
            "WEBRTC COORDINATION VECTORS: PASS — {total}·0F @ {} ({})",
            f.emitter_commit, f.emitter
        );
        println!(
            "  Coordination layer only. NOT evidence that WebRTC transport works (§11.5.1: S5 is)."
        );
        return Ok(true);
    }
    println!(
        "WEBRTC COORDINATION VECTORS: FAIL — {total} checks, {failed} failed (emitter {} @ {})",
        f.emitter, f.emitter_commit
    );
    Ok(false)
}

/// Surface 1 — wire shape.
///
/// Two directions per row. **Decode:** the blob must classify as the stated kind
/// and yield the stated unsealed fields. **Encode:** rebuilding the entity from
/// the row's stated fields must reproduce the blob **byte for byte** — which is
/// how the sealed `sdp` gets checked without a `VerifiedSigner`, and how a
/// `null` that should have been an absent key gets caught.
fn verify_entities(rows: &[EntityVector]) -> Report {
    let mut r = Report::new("1. wire shape");
    for v in rows {
        if let Err(why) = check_entity(v) {
            r.bad(&v.name, &why);
            continue;
        }
        r.ok(&v.name);
    }
    r
}

fn check_entity(v: &EntityVector) -> std::result::Result<(), String> {
    let sid = SessionId::parse(v.session_id.clone())
        .map_err(|e| format!("row's own session_id does not meet the §6.5 floor: {e}"))?;
    let decoded = classify_blob(&v.blob);

    let rebuilt = match v.kind.as_str() {
        "offer" => {
            match &decoded {
                CollectedWebRtc::Offer(o) => {
                    if o.session_id.as_bytes() != v.session_id.as_slice() {
                        return Err("session_id mismatch".into());
                    }
                }
                other => return Err(format!("classified as {}, want offer", kind_of(other))),
            }
            Offer::new(sid, v.sdp.clone())
                .to_entity()
                .map_err(|e| format!("re-encode: {e}"))?
        }
        "answer" => {
            match &decoded {
                CollectedWebRtc::Answer(a) => {
                    if a.session_id.as_bytes() != v.session_id.as_slice() {
                        return Err("session_id mismatch".into());
                    }
                }
                other => return Err(format!("classified as {}, want answer", kind_of(other))),
            }
            Answer::new(sid, v.sdp.clone())
                .to_entity()
                .map_err(|e| format!("re-encode: {e}"))?
        }
        "candidate" => {
            let c = match &decoded {
                CollectedWebRtc::Candidate(c) => c,
                other => return Err(format!("classified as {}, want candidate", kind_of(other))),
            };
            if c.candidate != v.candidate
                || c.sdp_mid != v.sdp_mid
                || c.sdp_mline_index != v.sdp_mline_index
            {
                return Err(format!(
                    "field mismatch: got {{{:?},{:?},{}}}",
                    c.candidate, c.sdp_mid, c.sdp_mline_index
                ));
            }
            if c.session_id.as_bytes() != v.session_id.as_slice() {
                return Err("session_id mismatch".into());
            }
            check_ufrag(v, c.username_fragment.as_deref())?;
            IceCandidate {
                session_id: sid,
                candidate: v.candidate.clone(),
                sdp_mid: v.sdp_mid.clone(),
                sdp_mline_index: v.sdp_mline_index,
                username_fragment: if v.expect_absent.iter().any(|f| f == "username_fragment") {
                    None
                } else {
                    v.username_fragment.clone()
                },
            }
            .to_entity()
            .map_err(|e| format!("re-encode: {e}"))?
        }
        other => return Err(format!("unknown kind {other}")),
    };

    let ours = entity_wire::encode_entity(&rebuilt);
    if ours != v.blob {
        return Err(format!(
            "blob bytes differ: re-encoding this row's stated fields gives {} bytes, the file carries {} \
             — ECF is deterministic (RFC 8949 §4.2), so identical fields MUST give identical bytes. \
             ours={} theirs={}",
            ours.len(),
            v.blob.len(),
            hex(&ours),
            hex(&v.blob)
        ));
    }
    Ok(())
}

fn kind_of(c: &CollectedWebRtc) -> &'static str {
    match c {
        CollectedWebRtc::Offer(_) => "offer",
        CollectedWebRtc::Answer(_) => "answer",
        CollectedWebRtc::Candidate(_) => "candidate",
        CollectedWebRtc::Unknown => "unknown",
    }
}

/// The `expect_absent` contract for the one optional field. Absence is asserted
/// positively: a field named in `expect_absent` MUST decode as absent, and one
/// not named MUST decode equal to the row's value.
fn check_ufrag(v: &EntityVector, got: Option<&str>) -> std::result::Result<(), String> {
    let want_absent = v.expect_absent.iter().any(|f| f == "username_fragment");
    if want_absent {
        return match got {
            Some(s) => Err(format!(
                "username_fragment decoded as {s:?}; expect_absent says it must be ABSENT \
                 (addIceCandidate reads an empty string as a real ufrag)"
            )),
            None => Ok(()),
        };
    }
    match (got, &v.username_fragment) {
        (None, None) => Ok(()),
        (None, Some(want)) => Err(format!("username_fragment absent, want {want}")),
        (Some(g), Some(want)) if g == want => Ok(()),
        (Some(g), _) => Err(format!("username_fragment {g:?} does not match the row")),
    }
}

/// Surface 2 — the offerer rule, per row and across the set.
fn verify_roles(rows: &[RoleVector]) -> Report {
    let mut r = Report::new("2. offerer / glare");
    for v in rows {
        let imp = glare_role(&v.self_id, &v.other);
        let sup = pair_should_suppress_offer(&v.self_id, &v.other);

        if !v.error.is_empty() {
            if v.error != ERR_SELF_NEGOTIATION {
                r.bad(&v.name, &format!("unknown expected error {}", v.error));
                continue;
            }
            let refused = matches!(imp, Err(SignalingError::SelfNegotiation))
                && matches!(sup, Err(SignalingError::SelfNegotiation));
            if !refused {
                r.bad(
                    &v.name,
                    &format!(
                        "expected refusal, got impolite={imp:?} suppress={sup:?} \
                         — a role returned here is §6.4 skip-own failing OPEN"
                    ),
                );
                continue;
            }
            r.ok(&v.name);
            continue;
        }

        let (imp, sup) = match (imp, sup) {
            (Ok(i), Ok(s)) => (i == GlareRole::Impolite, s),
            (i, s) => {
                r.bad(&v.name, &format!("unexpected error: {i:?} / {s:?}"));
                continue;
            }
        };
        if let Some(want) = v.impolite {
            if imp != want {
                r.bad(&v.name, &format!("impolite={imp}, want {want}"));
                continue;
            }
        }
        if let Some(want) = v.pair_suppress {
            if sup != want {
                r.bad(&v.name, &format!("pair_suppress={sup}, want {want}"));
                continue;
            }
        }
        r.ok(&v.name);
    }

    // Convergence is a property of the SET, not of any row: for every pair
    // appearing in both directions, exactly one side may be impolite. Rows that
    // are each individually right but jointly non-convergent would pass every
    // row check and still describe a fatal glare (both impolite) or a deadlock
    // (neither).
    match check_role_convergence(rows) {
        Some(why) => r.bad("set/convergence", &why),
        None => r.ok("set/convergence"),
    }
    r
}

fn check_role_convergence(rows: &[RoleVector]) -> Option<String> {
    // Reads the FILE's stated values, never our own recomputation. Recomputing
    // with `glare_role` could only ever prove Rust agrees with Rust — it would
    // report convergence for a sibling file claiming both sides impolite, which
    // is the one thing this check exists to catch. (Go found exactly this flaw
    // in their own verifier before it ran against us.)
    let mut seen: BTreeMap<(String, String), bool> = BTreeMap::new();
    for v in rows {
        if !v.error.is_empty() {
            continue;
        }
        if let Some(i) = v.impolite {
            seen.insert((v.self_id.clone(), v.other.clone()), i);
        }
    }
    for ((a, b), mine) in &seen {
        if let Some(theirs) = seen.get(&(b.clone(), a.clone())) {
            if mine == theirs {
                return Some(format!(
                    "pair ({a},{b}): both sides impolite={mine} — a glare both keep is fatal to \
                     the RTCPeerConnection, one neither keeps deadlocks"
                ));
            }
        }
    }
    None
}

/// Surface 3 — the §6.5 `session_id` length floor.
fn verify_session_ids(rows: &[SessionIdVector]) -> Report {
    let mut r = Report::new("3. session_id floor");
    for v in rows {
        let accepted = SessionId::parse(v.bytes.clone()).is_ok();
        if accepted != v.accept {
            r.bad(
                &v.name,
                &format!(
                    "{} bytes accepted={accepted}, want {}",
                    v.bytes.len(),
                    v.accept
                ),
            );
            continue;
        }
        r.ok(&v.name);
    }
    r
}

/// Surface 4 — §6.3 verification, positives and negatives.
fn verify_signatures(rows: &[SignatureVector]) -> Report {
    let mut r = Report::new("4. §6.3 verification");
    for v in rows {
        let entity = match entity_wire::decode_entity(&v.entity_blob) {
            Ok(e) => e,
            Err(e) => {
                r.bad(&v.name, &format!("entity_blob does not decode: {e}"));
                continue;
            }
        };
        let key_type = match u8::try_from(v.key_type) {
            Ok(k) => k,
            Err(_) => {
                r.bad(
                    &v.name,
                    &format!("key_type {} is not a single wire byte", v.key_type),
                );
                continue;
            }
        };

        // A row that names a claimed peer-id exercises the native §6.1 path,
        // where check (a) cross-checks the payload's own initiator/responder.
        // §6.5's payloads carry no peer-id, so the derived id IS the claim.
        let outcome = if v.claimed_peer_id.is_empty() {
            verify_coordination_signature(&entity, &v.public_key, key_type, &v.signature)
        } else {
            verify_claimed_signer(
                &entity,
                &v.public_key,
                key_type,
                &v.signature,
                &v.claimed_peer_id,
            )
        };

        match v.expect.as_str() {
            EXPECT_OK => match outcome {
                Err(e) => {
                    r.bad(&v.name, &format!("expected ok, got {e}"));
                    continue;
                }
                Ok(signer) => {
                    if !v.expect_signer.is_empty() && signer.peer_id() != v.expect_signer {
                        r.bad(
                            &v.name,
                            &format!(
                                "derived signer {}, want {} — check §6.3's derivation: the \
                                 canonical Ed25519 form is hash_type 0x00 (identity), not the \
                                 SHA-256 form §6.3 spells",
                                signer.peer_id(),
                                v.expect_signer
                            ),
                        );
                        continue;
                    }
                }
            },
            EXPECT_BAD_SIGNATURE => {
                if !matches!(outcome, Err(SignalingError::BadSignature)) {
                    r.bad(
                        &v.name,
                        &format!(
                            "expected BadSignature, got {outcome:?} — a verifier that accepts \
                             this accepts a forged channel"
                        ),
                    );
                    continue;
                }
            }
            EXPECT_SIGNER_MISMATCH => {
                if !matches!(outcome, Err(SignalingError::SignerMismatch)) {
                    r.bad(
                        &v.name,
                        &format!(
                            "expected SignerMismatch, got {outcome:?} — check (a) is what \
                             catches a valid signature under a false claim"
                        ),
                    );
                    continue;
                }
            }
            other => {
                r.bad(&v.name, &format!("unknown expect {other}"));
                continue;
            }
        }
        r.ok(&v.name);
    }
    r
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---------------------------------------------------------------------------
// emit
// ---------------------------------------------------------------------------
//
// Fixed seeds throughout: the file must be byte-identical across runs, so
// nothing here may touch a random source or a clock. That is what makes
// `emitter_commit` mean something — re-emitting at the same commit reproduces
// the bytes exactly, so the file is re-derivable evidence rather than an
// assertion (ADR-0012).

const SEED_A: [u8; 32] = {
    let mut s = [0u8; 32];
    s[0] = 0x01;
    s[1] = 0x02;
    s[2] = 0x03;
    s[3] = 0x04;
    s
};
const SEED_B: [u8; 32] = {
    let mut s = [0u8; 32];
    s[0] = 0x05;
    s[1] = 0x06;
    s[2] = 0x07;
    s[3] = 0x08;
    s
};

fn ed448_seed(b: u8) -> [u8; 57] {
    let mut s = [0u8; 57];
    s[0] = b;
    s
}

/// A deterministic `session_id` of the given length.
fn sid_bytes(fill: u8, n: usize) -> Vec<u8> {
    (0..n).map(|i| fill.wrapping_add(i as u8)).collect()
}

fn head_commit() -> String {
    // "unknown" rather than a failure: a vector file emitted from a tarball is
    // still verifiable, it just cannot be re-derived, and saying so is better
    // than refusing to emit.
    let head = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let Some(head) = head else {
        return "unknown".to_string();
    };
    // A dirty tree emitting a commit-pinned file is the disk-state number
    // ADR-0012 exists to stop: the bytes came from code that is not at that
    // commit, so re-emitting there would not reproduce them. Say so in the
    // pin rather than let the file overclaim its own provenance.
    //
    // `-uno` — MODIFIED TRACKED files only. Untracked ones are excluded on
    // purpose, and not merely for convenience: the vector file itself is
    // untracked on its very first emit, so counting untracked content would
    // make a clean pin unreachable for the one file this flag exists to
    // protect. An untracked source file cannot silently change the emitter
    // either — it would have to be `mod`-referenced from a tracked file, which
    // fails to build at the pinned commit and so surfaces loudly rather than
    // as a wrong pin.
    let dirty = std::process::Command::new("git")
        .args(["status", "--porcelain", "-uno"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);
    if dirty {
        format!("{head}-dirty")
    } else {
        head
    }
}

fn emit_file(path: &str) -> Result<()> {
    let entities = emit_entities()?;
    let roles = emit_roles();
    let session_ids = emit_session_ids();
    let signatures = emit_signatures()?;
    let commit = head_commit();

    let root = Value::Map(vec![
        (text("schema"), text(SCHEMA_VERSION)),
        (text("emitter"), text(EMITTER)),
        (text("emitter_commit"), text(&commit)),
        (text("entities"), Value::Array(entities.clone())),
        (text("roles"), Value::Array(roles.clone())),
        (text("session_ids"), Value::Array(session_ids.clone())),
        (text("signatures"), Value::Array(signatures.clone())),
    ]);
    let raw = to_ecf(&root);
    std::fs::write(path, &raw).with_context(|| format!("write {path}"))?;

    println!("wrote {path} ({} bytes)", raw.len());
    println!("  schema={SCHEMA_VERSION} emitter={EMITTER} commit={commit}");
    println!(
        "  entities={} roles={} session_ids={} signatures={}",
        entities.len(),
        roles.len(),
        session_ids.len(),
        signatures.len()
    );
    Ok(())
}

fn entity_row(
    name: &str,
    kind: &str,
    blob: Vec<u8>,
    session_id: &[u8],
    extra: Vec<(Value, Value)>,
    expect_absent: Vec<&str>,
) -> Value {
    let mut entries = vec![
        (text("name"), text(name)),
        (text("kind"), text(kind)),
        (text("blob"), ecf_bytes(blob)),
        (text("session_id"), ecf_bytes(session_id.to_vec())),
        (
            text("expect_absent"),
            Value::Array(expect_absent.into_iter().map(text).collect()),
        ),
    ];
    entries.extend(extra);
    Value::Map(entries)
}

fn emit_entities() -> Result<Vec<Value>> {
    let ufrag = "ufrag-abc123";
    let sess_a = sid_bytes(0x10, 16);
    // Longer than the floor: the floor is a minimum, not a size.
    let sess_b = sid_bytes(0x20, 24);

    let offer_sdp = "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\na=fingerprint:sha-256 AB:CD\r\n";
    let answer_sdp = "v=0\r\no=- 2 2 IN IP4 0.0.0.0\r\na=fingerprint:sha-256 EF:01\r\n";

    let offer = Offer::new(SessionId::parse(sess_a.clone())?, offer_sdp).to_entity()?;
    let answer = Answer::new(SessionId::parse(sess_a.clone())?, answer_sdp).to_entity()?;

    // The absent-ufrag candidate: the row the whole exercise turns on. An unset
    // OPTIONAL that encodes as null or "" round-trips perfectly same-side and is
    // wrong on the wire — addIceCandidate reads "" as a real ufrag.
    let cand_bare = IceCandidate {
        session_id: SessionId::parse(sess_a.clone())?,
        candidate: "candidate:1 1 udp 2130706431 192.0.2.1 41000 typ host".into(),
        sdp_mid: "0".into(),
        sdp_mline_index: 0,
        username_fragment: None,
    }
    .to_entity()?;
    let cand_ufrag = IceCandidate {
        session_id: SessionId::parse(sess_b.clone())?,
        candidate:
            "candidate:2 1 udp 1694498815 198.51.100.7 52000 typ srflx raddr 192.0.2.1 rport 41000"
                .into(),
        sdp_mid: "1".into(),
        sdp_mline_index: 3,
        username_fragment: Some(ufrag.to_string()),
    }
    .to_entity()?;

    Ok(vec![
        entity_row(
            "offer/basic",
            "offer",
            entity_wire::encode_entity(&offer),
            &sess_a,
            vec![(text("sdp"), text(offer_sdp))],
            vec![],
        ),
        entity_row(
            "answer/basic",
            "answer",
            entity_wire::encode_entity(&answer),
            &sess_a,
            vec![(text("sdp"), text(answer_sdp))],
            vec![],
        ),
        entity_row(
            "candidate/no-ufrag",
            "candidate",
            entity_wire::encode_entity(&cand_bare),
            &sess_a,
            vec![
                (
                    text("candidate"),
                    text("candidate:1 1 udp 2130706431 192.0.2.1 41000 typ host"),
                ),
                (text("sdp_mid"), text("0")),
                // sdp_mline_index 0 is omitted under `omitempty` on Go's side;
                // the verifier defaults it to 0, so the two agree.
            ],
            vec!["username_fragment"],
        ),
        entity_row(
            "candidate/with-ufrag",
            "candidate",
            entity_wire::encode_entity(&cand_ufrag),
            &sess_b,
            vec![
                (
                    text("candidate"),
                    text(
                        "candidate:2 1 udp 1694498815 198.51.100.7 52000 typ srflx raddr 192.0.2.1 rport 41000",
                    ),
                ),
                (text("sdp_mid"), text("1")),
                (
                    text("sdp_mline_index"),
                    Value::Integer(ciborium::value::Integer::from(3u64)),
                ),
                (text("username_fragment"), text(ufrag)),
            ],
            vec![],
        ),
    ])
}

fn role_row(name: &str, self_id: &str, other: &str, extra: Vec<(Value, Value)>) -> Value {
    let mut entries = vec![
        (text("name"), text(name)),
        (text("self"), text(self_id)),
        (text("other"), text(other)),
    ];
    entries.extend(extra);
    Value::Map(entries)
}

fn emit_roles() -> Vec<Value> {
    // Both directions of each pair appear as separate rows, so a verifier checks
    // convergence rather than one side's answer.
    let pairs = [("peer-aaa", "peer-bbb"), ("peer-mmm", "peer-zzz")];
    let mut rows = Vec::new();
    for (lo, hi) in pairs {
        for (me, them) in [(lo, hi), (hi, lo)] {
            let impolite = me.as_bytes() < them.as_bytes();
            rows.push(role_row(
                &format!("pair/{me}-vs-{them}"),
                me,
                them,
                vec![
                    (text("impolite"), Value::Bool(impolite)),
                    (text("pair_suppress"), Value::Bool(!impolite)),
                ],
            ));
        }
    }
    // §6.4's skip-own failing OPEN is the class the spec calls miserable to
    // diagnose, because every individual step reports success. Equal ids get a
    // permanent row asserting a refusal, not a role.
    rows.push(role_row(
        "equal-ids/refused",
        "peer-same",
        "peer-same",
        vec![(text("error"), text(ERR_SELF_NEGOTIATION))],
    ));
    rows
}

fn emit_session_ids() -> Vec<Value> {
    let cases: [(&str, Vec<u8>, bool); 5] = [
        ("floor/exactly-16", sid_bytes(0x30, 16), true),
        ("floor/17", sid_bytes(0x31, 17), true),
        ("floor/32", sid_bytes(0x32, 32), true),
        ("floor/15-refused", sid_bytes(0x33, 15), false),
        ("floor/empty-refused", vec![], false),
    ];
    cases
        .into_iter()
        .map(|(name, b, accept)| {
            Value::Map(vec![
                (text("name"), text(name)),
                (text("bytes"), ecf_bytes(b)),
                (text("accept"), Value::Bool(accept)),
            ])
        })
        .collect()
}

fn sig_row(
    name: &str,
    entity_blob: Vec<u8>,
    public_key: Vec<u8>,
    key_type: u8,
    signature: Vec<u8>,
    expect: &str,
    extra: Vec<(Value, Value)>,
) -> Value {
    let mut entries = vec![
        (text("name"), text(name)),
        (text("entity_blob"), ecf_bytes(entity_blob)),
        (text("public_key"), ecf_bytes(public_key)),
        (
            text("key_type"),
            Value::Integer(ciborium::value::Integer::from(key_type)),
        ),
        (text("signature"), ecf_bytes(signature)),
        (text("expect"), text(expect)),
    ];
    entries.extend(extra);
    Value::Map(entries)
}

fn emit_signatures() -> Result<Vec<Value>> {
    let kp_a = entity_crypto::Keypair::from_seed(SEED_A);
    let kp_b = entity_crypto::Keypair::from_seed(SEED_B);
    let kp_448 = entity_crypto::Ed448Keypair::from_seed(&ed448_seed(0x42))?;

    let sess = sid_bytes(0x40, 16);
    let offer = Offer::new(
        SessionId::parse(sess.clone())?,
        "v=0\r\no=- 3 3 IN IP4 0.0.0.0\r\na=fingerprint:sha-256 12:34\r\n",
    )
    .to_entity()?;
    let blob = entity_wire::encode_entity(&offer);
    let sig_a = kp_a.sign(&offer.content_hash.to_bytes());
    let sig_448 = kp_448.sign(&offer.content_hash.to_bytes());

    // A different entity, signed correctly — used for the tampered row, where
    // the signature is real but covers other bytes.
    let other_offer = Offer::new(
        SessionId::parse(sess.clone())?,
        "v=0\r\no=- 3 3 IN IP4 0.0.0.0\r\na=fingerprint:sha-256 DE:AD\r\n",
    )
    .to_entity()?;

    Ok(vec![
        sig_row(
            "ed25519/valid",
            blob.clone(),
            kp_a.public_key_bytes().to_vec(),
            entity_crypto::KEY_TYPE_ED25519,
            sig_a.to_vec(),
            EXPECT_OK,
            vec![(text("expect_signer"), text(kp_a.peer_id().to_string()))],
        ),
        // Crossed alongside Ed25519 deliberately. §6.3 spells the derivation
        // with key_type hardcoded to 0x01; a verifier that took that literally
        // fails THIS row while ed25519/valid passes, which localizes the bug
        // instead of just reporting a diff. Logged in docs/SPEC-AMBIGUITIES.md.
        sig_row(
            "ed448/valid",
            blob.clone(),
            kp_448.public_key_bytes().to_vec(),
            entity_crypto::KEY_TYPE_ED448,
            sig_448.to_vec(),
            EXPECT_OK,
            vec![(text("expect_signer"), text(kp_448.peer_id().to_string()))],
        ),
        // Someone else's key: the MITM case the §6.5 discharge exists to stop.
        sig_row(
            "ed25519/wrong-key",
            blob.clone(),
            kp_b.public_key_bytes().to_vec(),
            entity_crypto::KEY_TYPE_ED25519,
            sig_a.to_vec(),
            EXPECT_BAD_SIGNATURE,
            vec![],
        ),
        // Substituted SDP: the content hash moves, so the signature no longer
        // covers it — which is exactly what binds the DTLS fingerprint.
        sig_row(
            "ed25519/tampered-sdp",
            entity_wire::encode_entity(&other_offer),
            kp_a.public_key_bytes().to_vec(),
            entity_crypto::KEY_TYPE_ED25519,
            sig_a.to_vec(),
            EXPECT_BAD_SIGNATURE,
            vec![],
        ),
        // A VALID signature under a FALSE claim. Only check (a) catches this;
        // a verifier running only check (b) passes everything else and fails
        // exactly this row.
        sig_row(
            "ed25519/false-claim",
            blob.clone(),
            kp_a.public_key_bytes().to_vec(),
            entity_crypto::KEY_TYPE_ED25519,
            sig_a.to_vec(),
            EXPECT_SIGNER_MISMATCH,
            vec![(text("claimed_peer_id"), text(kp_b.peer_id().to_string()))],
        ),
        // The same claim, told truthfully — so the row above cannot pass by a
        // verifier that rejects every claimed-signer row.
        sig_row(
            "ed25519/true-claim",
            blob,
            kp_a.public_key_bytes().to_vec(),
            entity_crypto::KEY_TYPE_ED25519,
            sig_a.to_vec(),
            EXPECT_OK,
            vec![
                (text("claimed_peer_id"), text(kp_a.peer_id().to_string())),
                (text("expect_signer"), text(kp_a.peer_id().to_string())),
            ],
        ),
    ])
}

#[cfg(test)]
mod tests;
