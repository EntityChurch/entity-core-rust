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
use entity_crypto::IdentityKeypair;
use entity_ecf::{bytes as ecf_bytes, text, to_ecf, Value};
use entity_signaling::webrtc::{
    classify_blob, glare_role, pair_should_suppress_offer, verify_claimed_signer,
    verify_coordination_signature, Answer, CollectedWebRtc, GlareRole, IceCandidate, Offer,
    SessionId, SCHEMA_VERSION,
};
use entity_signaling::{envelope, RendezvousKey, SignalingError, RENDEZVOUS_KEY_LEN};

const EMITTER: &str = "core-rust";

const EXPECT_OK: &str = "ok";
const EXPECT_BAD_SIGNATURE: &str = "bad_signature";
const EXPECT_SIGNER_MISMATCH: &str = "signer_mismatch";
/// The third settled taxonomy name — a key that cannot be *used* to answer the
/// question, as distinct from a peer claiming an identity it cannot support.
const EXPECT_UNUSABLE_KEY: &str = "unusable_key";
/// Not one of the three: the blob never parsed as a container at all, which
/// §6.4 makes a normal bucket occurrence rather than a verification verdict.
const EXPECT_DECODE_SKIP: &str = "decode_skip";
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

/// Surface 0 — the signing input, **as data, checked before anything else**.
///
/// Go's contribution, and the reason for it is the divergence that produced it:
/// Rust and Go independently reached "cover the rendezvous key, don't carry it"
/// and still disagreed on the bytes — Go had
/// `content_hash ‖ rendezvous_key`, Rust `domain ‖ SEP ‖ rendezvous_key ‖
/// content_hash`. A disagreement on this field makes **every** signature row
/// fail identically, which is indistinguishable from total breakage; the whole
/// container reads as broken when one 84-byte layout is off.
///
/// So it is checked first and separately, and it is `[K]`-free: a declarative
/// component list would still let two impls agree on names and lengths while
/// ordering them differently, so `sample` carries a worked example whose exact
/// bytes pin the order operationally.
#[cfg_attr(test, derive(Debug))]
struct SigningInputVector {
    /// `(name, len)` in wire order.
    components: Vec<(String, u64)>,
    total_len: u64,
    /// A worked example: these two inputs produce exactly these bytes.
    sample_key: Vec<u8>,
    sample_content_hash: Vec<u8>,
    sample_bytes: Vec<u8>,
}

/// Surface 5 — the §6.3 **container**, not the verification primitive.
///
/// Surface 4 crosses `verify_coordination_signature` on a scaffolded triple:
/// entity, key, signature handed over separately, as no wire format carried
/// them. This row is the thing a bucket actually holds.
#[cfg_attr(test, derive(Debug))]
struct SignedBlobVector {
    name: String,
    /// The whole `system/signaling/signed-blob` container.
    blob: Vec<u8>,
    /// The 33-byte bucket key the signature is bound to. Carried explicitly so
    /// the crossing is decidable regardless of which binding mechanism the
    /// cohort settles on — a verifier reproduces these exact bytes or it does
    /// not, and no prose is needed to adjudicate.
    rendezvous_key: Vec<u8>,
    /// Present only on §6.1-shaped rows that name their own signer.
    claimed_peer_id: String,
    expect_signer: String,
    /// The inner entity, verbatim — pins the byte-preservation MUST *through*
    /// the container, which is where a decode+re-encode would silently
    /// invalidate the signature.
    expect_inner_blob: Vec<u8>,
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
    /// **Optional on read, always emitted.** `signed_blobs` postdates the
    /// four original surfaces, and `SCHEMA_VERSION` cannot be bumped to
    /// announce it: the same string is pinned into every
    /// `system/peer/transport/webrtc` profile's `negotiation.signaling_schema`
    /// (`EXTENSION-NETWORK.md` §6.5.2d), so bumping it would be a wire-visible
    /// change to advertise a *test-harness* addition, and `verify_file` hard-
    /// refuses a schema it does not recognize — the two impls could never land
    /// it without a flag day.
    ///
    /// So the surface is added the way ADR-0002 says unknowns are handled, with
    /// the harness holding itself to the rule it tests: a sibling file without
    /// the array still verifies clean on the four crossed surfaces, and ours
    /// carries the array for them to pick up. [`verify_signed_blobs`] says
    /// **loudly** when the array was absent, so "0 fail" can never be misread
    /// as "the container crossed."
    signed_blobs: Vec<SignedBlobVector>,
    /// Whether the file carried the array at all — absent is not the same fact
    /// as present-and-empty.
    has_signed_blobs: bool,
    /// Optional for the same MUST-ignore reason as `signed_blobs`: Go offered
    /// this block rather than emitting it unilaterally, so either side may land
    /// it first without breaking the other.
    signing_input: Option<SigningInputVector>,
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

    // Optional by design — see `VectorFile::signed_blobs`. Note this reads
    // `m.get`, not `get()`: an explicit null is a malformed array here, not an
    // absence, and it should surface as a parse failure rather than pass as
    // "the emitter has not landed the surface yet."
    let has_signed_blobs = m.contains_key("signed_blobs");
    let mut signed_blobs = Vec::new();
    if has_signed_blobs {
        for row in req_array(&m, "signed_blobs").context(
            "signed_blobs is present but not an array — an emitter that writes null here \
             would be claiming the surface while carrying nothing",
        )? {
            let r = as_map(row)?;
            signed_blobs.push(SignedBlobVector {
                name: req_text(&r, "name")?,
                blob: req_bytes(&r, "blob")?,
                rendezvous_key: req_bytes(&r, "rendezvous_key")?,
                claimed_peer_id: opt_text(&r, "claimed_peer_id"),
                expect_signer: opt_text(&r, "expect_signer"),
                expect_inner_blob: get(&r, "expect_inner_blob")
                    .and_then(|v| v.as_bytes())
                    .cloned()
                    .unwrap_or_default(),
                expect: req_text(&r, "expect")?,
            });
        }
    }

    let signing_input = match get(&m, "signing_input") {
        None => None,
        Some(v) => {
            let r = as_map(v)?;
            let mut components = Vec::new();
            for c in req_array(&r, "components")? {
                let c = as_map(c)?;
                components.push((req_text(&c, "name")?, opt_u64(&c, "len")));
            }
            let sample = as_map(get(&r, "sample").context("signing_input needs a `sample`")?)?;
            Some(SigningInputVector {
                components,
                total_len: opt_u64(&r, "total_len"),
                sample_key: req_bytes(&sample, "rendezvous_key")?,
                sample_content_hash: req_bytes(&sample, "content_hash")?,
                sample_bytes: req_bytes(&sample, "bytes")?,
            })
        }
    };

    Ok(VectorFile {
        schema: req_text(&m, "schema")?,
        emitter: req_text(&m, "emitter")?,
        emitter_commit: opt_text(&m, "emitter_commit"),
        entities,
        roles,
        session_ids,
        signatures,
        signed_blobs,
        has_signed_blobs,
        signing_input,
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
        // First, and separately — see `verify_signing_input`.
        verify_signing_input(f.signing_input.as_ref()),
        verify_entities(&f.entities),
        verify_roles(&f.roles),
        verify_session_ids(&f.session_ids),
        verify_signatures(&f.signatures),
        verify_signed_blobs(&f.signed_blobs, f.has_signed_blobs),
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
        // The §6.3 fold trigger is defined as *this* surface crossing. A pass
        // on the other four while the container is absent is exactly the
        // "eight green crossings on an unimplemented security MUST" state the
        // envelope proposal was written to end — so it is named, not implied.
        if !f.has_signed_blobs {
            println!(
                "  §6.3 container NOT crossed: {} emitted no `signed_blobs`. The fold trigger \
                 is unmet.",
                f.emitter
            );
        }
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

/// Surface 0 — the signing input, checked before any signature is verified.
///
/// Reports `ABSENT` rather than passing when the block is missing, for the same
/// reason surface 5 does: a 0/0 that reads as agreement is the failure mode
/// these guards exist to prevent.
fn verify_signing_input(v: Option<&SigningInputVector>) -> Report {
    let mut r = Report::new("0. signing input");
    let Some(v) = v else {
        r.lines.push(
            "      ABSENT  no `signing_input` block — a signing-input divergence will \
             surface as every signature row failing at once"
                .to_string(),
        );
        return r;
    };

    // Ours, for the same sample inputs. Recomputing is correct here (unlike the
    // convergence check, which must read the file): the point is precisely to
    // compare their stated bytes against what this build would produce.
    let key = match RendezvousKey::from_slice(&v.sample_key) {
        Ok(k) => k,
        Err(e) => {
            r.bad("sample/key-length", &format!("{e}"));
            return r;
        }
    };
    let ours = envelope::signing_input(&key, &v.sample_content_hash);

    if ours != v.sample_bytes {
        r.bad(
            "sample/bytes",
            &format!(
                "signing input differs — ours {}, theirs {}. Everything downstream of this \
                 is meaningless until it agrees; do NOT read the signature rows as a crypto \
                 fault.",
                hex(&ours),
                hex(&v.sample_bytes)
            ),
        );
        return r;
    }
    r.ok("sample/bytes");

    let expected: Vec<(String, u64)> = vec![
        ("domain".into(), envelope::SIGNING_DOMAIN.len() as u64),
        ("sep".into(), 1),
        ("rendezvous_key".into(), RENDEZVOUS_KEY_LEN as u64),
        ("content_hash".into(), 33),
    ];
    if v.components != expected {
        r.bad(
            "components",
            &format!("stated {:?}, ours {:?}", v.components, expected),
        );
    } else {
        r.ok("components");
    }

    if v.total_len != ours.len() as u64 {
        r.bad(
            "total_len",
            &format!("stated {}, ours {}", v.total_len, ours.len()),
        );
    } else {
        r.ok("total_len");
    }
    r
}

/// Surface 5 — the §6.3 container end to end.
///
/// Every row is fed to the **real** [`entity_signaling::envelope::open`], the
/// same function the negotiation loop uses. Nothing here reconstructs the
/// expected answer locally: a row states the bucket key and the verdict, and
/// this build either reproduces it from the sibling's bytes or does not.
fn verify_signed_blobs(rows: &[SignedBlobVector], present: bool) -> Report {
    let mut r = Report::new("5. §6.3 signed-blob");
    if !present {
        // Deliberately loud. A surface that silently reports 0/0 reads as
        // "crossed" in a summary line, and this is the one surface the fold
        // trigger is defined against.
        r.lines.push(
            "      ABSENT  this file carries no `signed_blobs` array — the container \
             crossing has NOT happened"
                .to_string(),
        );
        return r;
    }
    for v in rows {
        let key = match RendezvousKey::from_slice(&v.rendezvous_key) {
            Ok(k) => k,
            Err(e) => {
                r.bad(
                    &v.name,
                    &format!(
                        "rendezvous_key is {} bytes, not {RENDEZVOUS_KEY_LEN}: {e}",
                        v.rendezvous_key.len()
                    ),
                );
                continue;
            }
        };

        let outcome = if v.claimed_peer_id.is_empty() {
            envelope::open(&v.blob, &key)
        } else {
            envelope::open_claimed(&v.blob, &key, &v.claimed_peer_id)
        };

        match v.expect.as_str() {
            EXPECT_OK => match outcome {
                Err(e) => {
                    r.bad(&v.name, &format!("expected ok, got {e}"));
                    continue;
                }
                Ok((signer, inner)) => {
                    if !v.expect_signer.is_empty() && signer.peer_id() != v.expect_signer {
                        r.bad(
                            &v.name,
                            &format!(
                                "derived signer {}, want {} — the id is derived canonically \
                                 from (public_key, key_type), never decoded from the wire",
                                signer.peer_id(),
                                v.expect_signer
                            ),
                        );
                        continue;
                    }
                    // The byte-preservation MUST, checked through the container.
                    if !v.expect_inner_blob.is_empty() {
                        let got = entity_wire::encode_entity(&inner);
                        if got != v.expect_inner_blob {
                            r.bad(
                                &v.name,
                                &format!(
                                    "inner entity came back as {} bytes, want {} — a container \
                                     that decodes and re-encodes its payload silently \
                                     invalidates the signature it carries (§6.2)",
                                    hex(&got),
                                    hex(&v.expect_inner_blob)
                                ),
                            );
                            continue;
                        }
                    }
                }
            },
            EXPECT_BAD_SIGNATURE => {
                if !matches!(outcome, Err(SignalingError::BadSignature)) {
                    r.bad(
                        &v.name,
                        &format!(
                            "expected BadSignature, got {:?}",
                            outcome.map(|(s, _)| s.peer_id().to_string())
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
                            "expected SignerMismatch, got {:?} — this name is reserved for a \
                             valid signature under a FALSE claim; collapsing it into \
                             unusable_key loses the distinction",
                            outcome.map(|(s, _)| s.peer_id().to_string())
                        ),
                    );
                    continue;
                }
            }
            EXPECT_UNUSABLE_KEY => {
                if !matches!(outcome, Err(SignalingError::UnusableKey)) {
                    r.bad(
                        &v.name,
                        &format!(
                            "expected UnusableKey, got {:?} — an unsupported key_type MUST be \
                             skipped (ADR-0002), not rejected as a false claim",
                            outcome.map(|(s, _)| s.peer_id().to_string())
                        ),
                    );
                    continue;
                }
            }
            EXPECT_DECODE_SKIP => {
                if !matches!(outcome, Err(SignalingError::Decode(_))) {
                    r.bad(
                        &v.name,
                        &format!(
                            "expected a decode skip, got {:?} — a bucket is a mixed set and a \
                             foreign blob is normal traffic, not a verdict",
                            outcome.map(|(s, _)| s.peer_id().to_string())
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
    let signed_blobs = emit_signed_blobs()?;
    let commit = head_commit();

    let root = Value::Map(vec![
        (text("schema"), text(SCHEMA_VERSION)),
        (text("emitter"), text(EMITTER)),
        (text("emitter_commit"), text(&commit)),
        (text("entities"), Value::Array(entities.clone())),
        (text("roles"), Value::Array(roles.clone())),
        (text("session_ids"), Value::Array(session_ids.clone())),
        (text("signatures"), Value::Array(signatures.clone())),
        (text("signed_blobs"), Value::Array(signed_blobs.clone())),
        (text("signing_input"), emit_signing_input()),
    ]);
    let raw = to_ecf(&root);
    std::fs::write(path, &raw).with_context(|| format!("write {path}"))?;

    println!("wrote {path} ({} bytes)", raw.len());
    println!("  schema={SCHEMA_VERSION} emitter={EMITTER} commit={commit}");
    println!(
        "  entities={} roles={} session_ids={} signatures={} signed_blobs={}",
        entities.len(),
        roles.len(),
        session_ids.len(),
        signatures.len(),
        signed_blobs.len()
    );
    Ok(())
}

/// Surface 5 rows — the §6.3 container.
///
/// **These rows also carry the open bucket-binding call.** Every signature here
/// is bound to the `rendezvous_key` the row states, and
/// `ed25519/replayed-into-another-bucket` is the row that decides it: it is the
/// same valid blob, verified under a different key, and it MUST fail. An
/// implementation that does not bind fails exactly that row and passes the
/// rest, which localizes the disagreement to the mechanism instead of
/// reporting a diff.
fn emit_signed_blobs() -> Result<Vec<Value>> {
    let kp_a = IdentityKeypair::Ed25519(entity_crypto::Keypair::from_seed(SEED_A));
    let kp_b = IdentityKeypair::Ed25519(entity_crypto::Keypair::from_seed(SEED_B));
    let kp_448 = IdentityKeypair::Ed448(entity_crypto::Ed448Keypair::from_seed(&ed448_seed(0x42))?);

    // Two fixed buckets. `pair_key` sorts its arguments, so these are exactly
    // what the two peers would derive — not synthetic byte strings.
    let a_id = kp_a.peer_id().to_string();
    let b_id = kp_b.peer_id().to_string();
    let c_id = kp_448.peer_id().to_string();
    let bucket = entity_signaling::pair_key(&a_id, &b_id);
    let other_bucket = entity_signaling::pair_key(&a_id, &c_id);

    let sess = sid_bytes(0x40, 16);
    let inner = Offer::new(
        SessionId::parse(sess.clone())?,
        "v=0\r\no=- 5 5 IN IP4 0.0.0.0\r\na=fingerprint:sha-256 12:34\r\n",
    )
    .to_entity()?;
    let inner_blob = entity_wire::encode_entity(&inner);

    let valid_a = envelope::seal(&inner, &bucket, &kp_a)?;
    let valid_448 = envelope::seal(&inner, &bucket, &kp_448)?;

    // Adopted from core-go's file. A signature over the **bare** 33-byte
    // content_hash — the unbound shape, and the one both impls would have built
    // without §5's binding. It is the direct negative for the binding: an impl
    // that omitted it entirely passes the replay row (both keys "work") and
    // fails only this one.
    let mut bare_hash = envelope::parse(&valid_a)?;
    bare_hash.signature = entity_crypto::Keypair::from_seed(SEED_A)
        .sign(&inner.content_hash.to_bytes())
        .to_vec();
    let bare_hash_blob = bare_hash.to_blob()?;

    // Also from Go. A valid signature over the correct input, made by a key
    // that is not the one named — derivation binds `signer` to A's key, so this
    // reaches step 4 and fails there. Distinct from `forged-signer`, which
    // fails at step 2 and never reaches the signature at all.
    let mut other_key = envelope::parse(&valid_a)?;
    other_key.signature = kp_b.sign(&envelope::signing_input(
        &bucket,
        &inner.content_hash.to_bytes(),
    ));
    let other_key_blob = other_key.to_blob()?;

    // A forged `signer`: A's key and signature, B's id in the field.
    let mut forged = envelope::parse(&valid_a)?;
    forged.signer = b_id.clone();
    let forged_blob = forged.to_blob()?;

    // A well-formed but NON-CANONICAL id for the very same key — the legacy
    // SHA-256 form. Admitting it gives one key two valid ids, and every §6.5
    // decision is a sort over that id.
    let mut relabelled = envelope::parse(&valid_a)?;
    relabelled.signer = entity_crypto::legacy_sha256_peer_id_fixture(
        &entity_crypto::Keypair::from_seed(SEED_A).public_key_bytes(),
    )
    .to_string();
    let relabelled_blob = relabelled.to_blob()?;

    // Substituted SDP under a real signature — what binds the DTLS fingerprint.
    let other_inner = Offer::new(
        SessionId::parse(sess.clone())?,
        "v=0\r\no=- 5 5 IN IP4 0.0.0.0\r\na=fingerprint:sha-256 DE:AD\r\n",
    )
    .to_entity()?;
    let mut tampered = envelope::parse(&valid_a)?;
    tampered.entity = entity_wire::encode_entity(&other_inner);
    let tampered_blob = tampered.to_blob()?;

    // A well-formed key_type this build cannot verify (`0xFE`, 64-byte key).
    // MUST be skipped, never hardcode-rejected — the Ed448 defect, generalized.
    let exotic_pk = vec![0x07u8; 64];
    let exotic = envelope::SignedBlob {
        entity: inner_blob.clone(),
        signer: entity_crypto::PeerId::from_public_key_with_key_type(
            &exotic_pk,
            entity_crypto::KeyType::ExperimentalTest,
        )?
        .to_string(),
        public_key: exotic_pk,
        signature: vec![0x00; 64],
    }
    .to_blob()?;

    // ---------------------------------------------------------------------
    // §6.1 inners — the shape §6.5 cannot reach
    // ---------------------------------------------------------------------
    //
    // Every row above wraps a §6.5 payload, which names nobody: the derived
    // signer simply *is* the identity. §6.1's `connect-request` /
    // `connect-response` carry `initiator` / `responder` AS WIRE FIELDS, so a
    // signature that is entirely valid under a **false** claim passes steps 2
    // and 4 and is caught only by step 3. That is a distinct failure surface,
    // and it survived a 38·0F crossing in both impls because no row exercised
    // it. Adopted from core-go's four rows (`204e1d9`) so the check crosses in
    // both directions rather than one.
    //
    // Nonces are fixed, not generated: a vector file must re-emit byte-identical
    // at the same commit or its provenance means nothing.
    let native_candidates = vec![entity_signaling::coordination::Candidate::new(
        entity_signaling::coordination::CANDIDATE_HOST,
        entity_signaling::coordination::SUBSTRATE_TCP,
        "192.0.2.7:9000",
    )];
    let request = entity_signaling::coordination::ConnectRequest {
        initiator: a_id.clone(),
        candidates: native_candidates.clone(),
        nonce: entity_signaling::coordination::Nonce(vec![0x51; 16]),
    }
    .to_entity()?;
    // The same shape with the lie moved INSIDE the signature: `initiator` names
    // B, and A signs it anyway. Sealed by `kp_a` exactly like the truthful one,
    // so steps 2 and 4 pass and only step 3 — "the payload's author must be the
    // verified signer" — can catch it.
    //
    // The first cut of the false-claim row reused the truthful blob and lied
    // only in the row's own `claimed_peer_id`. `entity-core-go` ran their
    // verifier against our file and reported it as a `W`: a real §6.1 collector
    // reads `initiator` out of the signed entity, so it saw a truthful message
    // and correctly returned ok — the row could not catch the regression it is
    // named for. Their `OpenBlobClaimed` was in exactly that state (tested
    // directly, no caller in the read path) and would have passed it.
    let request_lying = entity_signaling::coordination::ConnectRequest {
        initiator: b_id.clone(),
        candidates: native_candidates.clone(),
        nonce: entity_signaling::coordination::Nonce(vec![0x51; 16]),
    }
    .to_entity()?;
    let response = entity_signaling::coordination::ConnectResponse {
        responder: a_id.clone(),
        candidates: native_candidates,
        nonce: entity_signaling::coordination::Nonce(vec![0x51; 16]),
    }
    .to_entity()?;
    let sync = entity_signaling::coordination::PunchSync {
        nonce: entity_signaling::coordination::Nonce(vec![0x51; 16]),
        fire_at: 40,
    }
    .to_entity()?;

    let request_blob = envelope::seal(&request, &bucket, &kp_a)?;
    let request_blob_lying = envelope::seal(&request_lying, &bucket, &kp_a)?;
    let response_blob = envelope::seal(&response, &bucket, &kp_a)?;
    let sync_blob = envelope::seal(&sync, &bucket, &kp_a)?;

    Ok(vec![
        signed_blob_row(
            "ed25519/valid",
            valid_a.clone(),
            &bucket,
            EXPECT_OK,
            vec![
                (text("expect_signer"), text(&a_id)),
                (text("expect_inner_blob"), ecf_bytes(inner_blob.clone())),
            ],
        ),
        // Parametric key_type: the floor is Ed25519, not the ceiling.
        signed_blob_row(
            "ed448/valid",
            valid_448,
            &bucket,
            EXPECT_OK,
            vec![
                (text("expect_signer"), text(&c_id)),
                (text("expect_inner_blob"), ecf_bytes(inner_blob.clone())),
            ],
        ),
        // THE bucket-binding row. Same bytes, different bucket.
        signed_blob_row(
            "ed25519/replayed-into-another-bucket",
            valid_a.clone(),
            &other_bucket,
            EXPECT_BAD_SIGNATURE,
            vec![],
        ),
        signed_blob_row(
            "ed25519/forged-signer",
            forged_blob,
            &bucket,
            EXPECT_UNUSABLE_KEY,
            vec![],
        ),
        signed_blob_row(
            "ed25519/non-canonical-hash-type",
            relabelled_blob,
            &bucket,
            EXPECT_UNUSABLE_KEY,
            vec![],
        ),
        signed_blob_row(
            "ed25519/tampered-inner-entity",
            tampered_blob,
            &bucket,
            EXPECT_BAD_SIGNATURE,
            vec![],
        ),
        signed_blob_row(
            "unsupported-key-type/0xfe",
            exotic,
            &bucket,
            EXPECT_UNUSABLE_KEY,
            vec![],
        ),
        signed_blob_row(
            "ed25519/bare-content-hash-signature",
            bare_hash_blob,
            &bucket,
            EXPECT_BAD_SIGNATURE,
            vec![],
        ),
        signed_blob_row(
            "ed25519/signed-by-another-key",
            other_key_blob,
            &bucket,
            EXPECT_BAD_SIGNATURE,
            vec![],
        ),
        // §6.1's step 3 — only the claim comparison catches a valid signature
        // under a false claim.
        signed_blob_row(
            "ed25519/false-claim",
            valid_a.clone(),
            &bucket,
            EXPECT_SIGNER_MISMATCH,
            vec![(text("claimed_peer_id"), text(&b_id))],
        ),
        // The same claim told truthfully, so the row above cannot pass by a
        // verifier that rejects every claimed-signer row.
        signed_blob_row(
            "ed25519/true-claim",
            valid_a,
            &bucket,
            EXPECT_OK,
            vec![
                (text("claimed_peer_id"), text(&a_id)),
                (text("expect_signer"), text(&a_id)),
            ],
        ),
        // A bare coordination entity — legacy unsigned traffic, or another
        // impl's blob. Normal bucket contents, so a skip and not a verdict.
        signed_blob_row(
            "not-a-container",
            inner_blob,
            &bucket,
            EXPECT_DECODE_SKIP,
            vec![],
        ),
    ]
    .into_iter()
    .chain(signed_blob_rows_6_1(
        request_blob,
        request_blob_lying,
        response_blob,
        sync_blob,
        &bucket,
        &a_id,
        &b_id,
    ))
    .collect())
}

/// Surface 0 — emit the signing input as data.
fn emit_signing_input() -> Value {
    // Fixed, recognizable inputs: neither is a real key or a real hash, which
    // is the point — the block describes a layout, not a signature.
    let key = entity_signaling::RendezvousKey::from_slice(&[0x5Au8; RENDEZVOUS_KEY_LEN])
        .expect("33 bytes is the key length");
    let content_hash = vec![0xC7u8; 33];
    let bytes = envelope::signing_input(&key, &content_hash);

    let component = |name: &str, len: usize| {
        Value::Map(vec![
            (text("name"), text(name)),
            (
                text("len"),
                Value::Integer(ciborium::value::Integer::from(len as u64)),
            ),
        ])
    };

    Value::Map(vec![
        (
            text("components"),
            Value::Array(vec![
                component("domain", envelope::SIGNING_DOMAIN.len()),
                component("sep", 1),
                component("rendezvous_key", RENDEZVOUS_KEY_LEN),
                component("content_hash", 33),
            ]),
        ),
        (
            text("sample"),
            Value::Map(vec![
                (text("bytes"), ecf_bytes(bytes.clone())),
                (text("content_hash"), ecf_bytes(content_hash)),
                (text("rendezvous_key"), ecf_bytes(key.as_bytes().to_vec())),
            ]),
        ),
        (
            text("total_len"),
            Value::Integer(ciborium::value::Integer::from(bytes.len() as u64)),
        ),
    ])
}

fn signed_blob_row(
    name: &str,
    blob: Vec<u8>,
    key: &RendezvousKey,
    expect: &str,
    extra: Vec<(Value, Value)>,
) -> Value {
    let mut entries = vec![
        (text("name"), text(name)),
        (text("blob"), ecf_bytes(blob)),
        (text("rendezvous_key"), ecf_bytes(key.as_bytes().to_vec())),
        (text("expect"), text(expect)),
    ];
    entries.extend(extra);
    Value::Map(entries)
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

/// Append the §6.1-inner rows to the signed-blob set.
fn signed_blob_rows_6_1(
    request_blob: Vec<u8>,
    request_blob_lying: Vec<u8>,
    response_blob: Vec<u8>,
    sync_blob: Vec<u8>,
    bucket: &RendezvousKey,
    a_id: &str,
    b_id: &str,
) -> Vec<Value> {
    vec![
        // The claim, told truthfully. Present so the row below cannot pass in a
        // verifier that simply rejects every §6.1 container it meets.
        signed_blob_row(
            "ed25519/connect-request/true-initiator",
            request_blob.clone(),
            bucket,
            EXPECT_OK,
            vec![
                (text("claimed_peer_id"), text(a_id)),
                (text("expect_signer"), text(a_id)),
            ],
        ),
        // THE §6.1 row: a signature that verifies perfectly, over a payload
        // whose `initiator` names someone else. Steps 2 and 4 pass; only step 3
        // fails. An impl that skipped step 3 passes every other row in this
        // file and fails exactly this one.
        //
        // **The lie lives in the payload, not in this row's `claimed_peer_id`.**
        // `claimed_peer_id` here EQUALS the `initiator` inside the signed
        // entity, so a payload-driven collector — which is what every real §6.1
        // read path is — reads B, verifies A, and must reject. When the row
        // instead carried the truthful blob and lied only in this field, a
        // payload-driven verifier saw a consistent message and returned ok:
        // the row tested the row, not the read path. `entity-core-go` caught
        // that by running their verifier against our file; the pin it argues
        // for is that on a §6.1 row `claimed_peer_id` MUST equal the author
        // field inside the signed payload, because that is the only
        // construction under which the row tests what a live collector does.
        signed_blob_row(
            "ed25519/connect-request/initiator-names-another-peer",
            request_blob_lying,
            bucket,
            EXPECT_SIGNER_MISMATCH,
            vec![(text("claimed_peer_id"), text(b_id))],
        ),
        // `responder` is the same hazard under a different field name — worth
        // its own row because a verifier that hardcoded `initiator` would pass
        // the two above and let every answer through unchecked.
        signed_blob_row(
            "ed25519/connect-response/true-responder",
            response_blob,
            bucket,
            EXPECT_OK,
            vec![
                (text("claimed_peer_id"), text(a_id)),
                (text("expect_signer"), text(a_id)),
            ],
        ),
        // `punch-sync` names nobody, so step 3 has nothing to compare and step
        // 2 is the whole check — the position all of §6.5's payloads are in.
        // It still governs when both peers fire, so it is sealed like the rest.
        signed_blob_row(
            "ed25519/punch-sync/names-nobody",
            sync_blob,
            bucket,
            EXPECT_OK,
            vec![(text("expect_signer"), text(a_id))],
        ),
    ]
}

#[cfg(test)]
mod tests;
