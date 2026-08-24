//! The coordination messages — **what actually rides through the node**
//! (`PROPOSAL-CONNECTIVITY-SIGNALING-AND-PUNCH` §3, §4).
//!
//! Everything above this module moves opaque bytes. This is what those bytes
//! *are*: the DCUtR-analog "we both dial at T" dance, three message types,
//! ordinary V7 entities. **The rendezvous node sees only the 33-byte key and an
//! opaque blob** — it never decodes any of this, which is why §3 calls them
//! carrier-agnostic.
//!
//! ```text
//!   A                          node                          B
//!   │  offer(K, connect-request) ─►│                          │
//!   │                              │◄─ collect(K) ────────────│
//!   │                              │── connect-response ─────►│  offer(K, ...)
//!   │◄─ collect(K) ────────────────│                          │
//!   │  punch-sync(fire_at) ───────►│─────────────────────────►│
//!   └──────────── both fire at ≈ the same instant ────────────┘   ← Stage 2
//! ```
//!
//! # What is here and what is not
//!
//! The three **wire shapes** and the §4 step-2 exchange (offer/collect the
//! candidate lists) are here — that is the rendezvous carrier's job and it is
//! Stage 1. [`PunchSync`] is carried too, because its shape is part of the same
//! message family, but **nothing fires it**: §4 steps 3–5 are RTT measurement, a
//! simultaneous open, and a transport upgrade — socket work, Stage 2, and per
//! `PROPOSAL-CONNECTION-NODE` §3.1 it needs a service-owning lifecycle that does
//! not yet exist.
//!
//! One piece of step 3 *is* here, and deliberately: [`punch_delay`] and
//! `fire_at`'s clock domain (§4.1, pinned 2026-07-28). Both are pure
//! computation — no socket, no lifecycle — and both are cross-peer-observable,
//! so they belong with the wire shapes rather than with the socket work that
//! consumes them. It is the same split [`key`](crate::key) already makes: the
//! §2.2 derivation ships in Stage 1 because getting it wrong is a silent
//! never-meet, even though only Stage 2 dials.
//!
//! # Signing: this module reads the container, and does not yet write it
//!
//! §3.3 pins that a coordination blob is **self-contained** — the entity plus a
//! detached signature carrying the signer's `public_key`, which a stranger
//! verifies with no key lookup. That is a deliberate exception to the
//! ecosystem's `/{signer}/system/signature/{hash}` convention, which is
//! *structurally unavailable* here: the whole point of the carrier is that no
//! connection exists yet, so there is no session to sync over and no tree to
//! bind into.
//!
//! The container is [`crate::envelope`] (`system/signaling/signed-blob`), folded
//! into the spec on 2026-08-04. **The read side is here**
//! ([`classify_collected`]): a sealed §6.1 deposit is unwrapped, verified
//! against its bucket, and checked against the `initiator` / `responder` the
//! payload claims (§6.3 step 3), while a bare one still reads as the §6.2
//! framing and a container that fails to verify is skipped without falling back
//! to it.
//!
//! **[`to_blob`] still emits the bare, unsigned encoding**, and that is the
//! remaining half. Switching what a bucket holds is a wire-visible flag day: a
//! signed depositor and an unsigned collector do not interoperate, so Rust and
//! Go turn it on together. §6.5 flipped first (`d70f245`) because its container
//! had crossed; §6.1's window has not opened, and reading first is exactly what
//! makes it safe to open — a collector that already understands both framings
//! turns the cutover into a rolling changeover.
//!
//! **The derivation is the canonical one, not §3.3's spelled-out byte string.**
//! §3.3 writes `Base58(0x01 ‖ 0x01 ‖ SHA-256(pk))` — the legacy SHA-256 form
//! that V7 §1.5 v7.65 Amendment 3 made decode-only and that neither reference
//! implementation mints. Following it literally derives a peer-id that compares
//! unequal against every canonical one, and a failed §3.3 check is skipped
//! *silently*, so every message would simply vanish. Logged as
//! `docs/SPEC-AMBIGUITIES.md` #67; arch is routing the same correction through
//! `ENTITY-SYSTEM-REFERENCE.md:75/601`, which still carries the stale form.
//!
//! Two things that are easy to over-read once signing is on: the signature
//! authenticates the **author, not the address** (an attacker signs its own
//! candidate list containing a victim's address perfectly well), so the
//! anti-amplification probe budget is needed *independently* rather than as
//! belt-and-braces. And what bounds the exposure meanwhile: **the key
//! introduces, it never authorizes** — a punched connection still runs the full
//! handshake and capability flow, so the worst case is a wasted dial.
//!
//! # The MUST that is easy to violate
//!
//! **Candidates are session-scoped and ephemeral. They MUST NOT be persisted as
//! durable `system/peer/transport/{peer}/{profile-id}` profiles**
//! (`PROPOSAL-NETWORK-REACHABILITY-FACTS` §4.1). Profiles are *stable published
//! endpoints*; a candidate is one NAT mapping for one connection attempt and
//! goes stale instantly. Writing one as a profile mis-routes every later
//! dispatch that reads it — the classic "worked for the issuer, stale for
//! everyone else" cross-peer failure. So candidates live **inside** these
//! messages and never as tree state, and nothing in this module writes anything.

use entity_ecf::{array, bytes, text, to_ecf, Value};
use entity_entity::Entity;

use crate::core::RendezvousKey;
use crate::webrtc::VerifiedSigner;
use crate::SignalingError;

// ---------------------------------------------------------------------------
// Entity types (§3.1). §10 listed `system/nat/*` vs `system/signaling/*` vs
// `system/connectivity/*` as §13 Open Item #1; arch resolved it to
// `system/signaling/*` and the cohort renamed together (S0, 2026-08-02).
//
// This was a flag day, not a cleanup: the type strings feed the content hash,
// so a peer on the old names derives a different rendezvous key and silently
// never meets one on the new names — nothing errors, nothing logs. Measured
// rather than predicted; see `key.rs` for why the derivation is that brittle.
// ---------------------------------------------------------------------------

pub const TYPE_CONNECT_REQUEST: &str = "system/signaling/connect-request";
pub const TYPE_CONNECT_RESPONSE: &str = "system/signaling/connect-response";
pub const TYPE_PUNCH_SYNC: &str = "system/signaling/punch-sync";

// ---------------------------------------------------------------------------
// Candidates (`PROPOSAL-NETWORK-REACHABILITY-FACTS` §4)
// ---------------------------------------------------------------------------

/// A local/LAN address — works when the peers share a network. Cheapest, tried
/// first.
pub const CANDIDATE_HOST: &str = "host";
/// Server-reflexive: the public mapping a reflector observed. **The hole-punch
/// target.**
pub const CANDIDATE_SRFLX: &str = "srflx";
/// A public relay address — the always-works fallback, tried last because it is
/// the metered path.
pub const CANDIDATE_RELAY: &str = "relay";

/// Built and shipping.
pub const SUBSTRATE_TCP: &str = "tcp";
/// Declared but unbuilt in v1 (§5) — gated on building our own QUIC transport.
pub const SUBSTRATE_QUIC: &str = "quic";
/// Declared but unbuilt in v1 (§5).
pub const SUBSTRATE_WEBRTC: &str = "webrtc";

/// One address a peer might be reachable at, typed and ordered ICE-style.
///
/// **Exactly the three fields of `system/network/candidate`**
/// (`EXTENSION-NETWORK.md` §6.7.3) — this is that type, carried, not a signaling
/// variant of it. There is deliberately **no `priority`**: try order derives
/// from the candidate `type` (`host` → `srflx` → `relay`), so a wire priority
/// would be a second, disagreeing source for the same ordering. §10's
/// `(priority asc, profile-id lex)` loop orders *durable transport profiles*;
/// candidates are ephemeral and ordered by class instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// `host` | `srflx` | `relay`.
    pub candidate_type: String,
    /// `tcp` | `quic` | `webrtc`.
    pub substrate: String,
    /// The address itself. Deliberately an opaque string at this layer — the
    /// entity layer never interprets `IP:port`, which is the load-bearing
    /// addressing invariant these facts are careful not to break.
    pub address: String,
}

impl Candidate {
    pub fn new(
        candidate_type: impl Into<String>,
        substrate: impl Into<String>,
        address: impl Into<String>,
    ) -> Self {
        Self {
            candidate_type: candidate_type.into(),
            substrate: substrate.into(),
            address: address.into(),
        }
    }

    /// The §4 class ordering: `host` → `srflx` → `relay`. An unknown type sorts
    /// last rather than being dropped — MUST-ignore says a peer that learns a
    /// new candidate class from a newer impl should still try what it does
    /// understand first, not refuse the whole message.
    fn class_rank(&self) -> u8 {
        match self.candidate_type.as_str() {
            CANDIDATE_HOST => 0,
            CANDIDATE_SRFLX => 1,
            CANDIDATE_RELAY => 2,
            _ => 3,
        }
    }

    fn to_value(&self) -> Value {
        Value::Map(vec![
            (text("address"), text(&self.address)),
            (text("substrate"), text(&self.substrate)),
            (text("type"), text(&self.candidate_type)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, SignalingError> {
        let map = v
            .as_map()
            .ok_or_else(|| SignalingError::Decode("candidate is not a map".into()))?;
        Ok(Self {
            candidate_type: field_text(map, "type")?,
            substrate: field_text(map, "substrate")?,
            address: field_text(map, "address")?,
        })
    }
}

/// Order a candidate list for dialing: class first (`host` → `srflx` →
/// `relay`), then address for a total order.
///
/// "First pair that completes a connectivity check wins"
/// (`EXTENSION-NETWORK.md` §6.7.3), so this ordering *is* the dial plan. It is
/// deterministic to the last tiebreak on purpose — two peers that order
/// differently waste attempts crossing at different candidates. Address is that
/// tiebreak precisely because the wire carries no `priority` to break it with.
pub fn order_for_dialing(candidates: &[Candidate]) -> Vec<Candidate> {
    let mut ordered = candidates.to_vec();
    ordered.sort_by(|a, b| {
        a.class_rank()
            .cmp(&b.class_rank())
            .then_with(|| a.address.cmp(&b.address))
    });
    ordered
}

// ---------------------------------------------------------------------------
// The nonce — correlates one exchange
// ---------------------------------------------------------------------------

/// Correlates a request with its response and supplies freshness (§3).
///
/// Load-bearing in the multi-party modes: a `lobby` or `tag` bucket holds
/// everyone's messages, and `collect` is non-destructive, so a peer re-reads the
/// whole bucket every poll. Without the nonce echo there is no way to tell
/// *your* answer from someone else's, or a fresh answer from one you already
/// processed two polls ago.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Nonce(pub Vec<u8>);

impl Nonce {
    /// 16 random bytes — enough that two concurrent exchanges in one `lobby`
    /// bucket will not collide.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut b = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut b);
        Self(b.to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// §3 — the three messages
// ---------------------------------------------------------------------------

/// A → B. "Here is who I am, where I might be reached, and the tag that ties
/// your answer to this attempt."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    pub initiator: String,
    pub candidates: Vec<Candidate>,
    pub nonce: Nonce,
}

impl ConnectRequest {
    pub fn to_entity(&self) -> Result<Entity, SignalingError> {
        let data = to_ecf(&Value::Map(vec![
            (
                text("candidates"),
                array(self.candidates.iter().map(|c| c.to_value()).collect()),
            ),
            (text("initiator"), text(&self.initiator)),
            (text("nonce"), bytes(self.nonce.0.clone())),
        ]));
        Entity::new(TYPE_CONNECT_REQUEST, data).map_err(|e| SignalingError::Encode(e.to_string()))
    }

    pub fn from_entity_bytes(data: &[u8]) -> Result<Self, SignalingError> {
        let map = decode_map(data)?;
        Ok(Self {
            initiator: field_text(&map, "initiator")?,
            candidates: field_candidates(&map)?,
            nonce: Nonce(field_bytes(&map, "nonce")?),
        })
    }
}

/// B → A, echoing A's nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectResponse {
    pub responder: String,
    pub candidates: Vec<Candidate>,
    pub nonce: Nonce,
}

impl ConnectResponse {
    pub fn to_entity(&self) -> Result<Entity, SignalingError> {
        let data = to_ecf(&Value::Map(vec![
            (
                text("candidates"),
                array(self.candidates.iter().map(|c| c.to_value()).collect()),
            ),
            (text("nonce"), bytes(self.nonce.0.clone())),
            (text("responder"), text(&self.responder)),
        ]));
        Entity::new(TYPE_CONNECT_RESPONSE, data).map_err(|e| SignalingError::Encode(e.to_string()))
    }

    pub fn from_entity_bytes(data: &[u8]) -> Result<Self, SignalingError> {
        let map = decode_map(data)?;
        Ok(Self {
            responder: field_text(&map, "responder")?,
            candidates: field_candidates(&map)?,
            nonce: Nonce(field_bytes(&map, "nonce")?),
        })
    }
}

/// Either direction — aligns the moment both sides fire.
///
/// **`fire_at` is a delay, not a timestamp** (§4.1, pinned 2026-07-28, MUST).
/// It is **unsigned integer milliseconds measured from the receiving peer's
/// moment of receipt** of this entity. V7 assumes no synchronized clocks, and
/// two peers' wall clocks can differ by far more than the whole punch window, so
/// a wall-clock instant on the wire is a silent never-meet. §9's conformance
/// list carries it as MUST #5 for exactly that reason.
///
/// **Why this shape needs a test rather than care.** The failure is invisible to
/// every same-host test — both peers read the same clock, so a wall-clock
/// encoding passes — which is the same masking shape §2.2's home-format trap
/// has. It is also the *plausible* implementation: "the agreed instant" reads
/// like a timestamp, and this build encoded one (a signed `i64` holding ms since
/// epoch) until §4.1 pinned the clock domain.
///
/// Who fires when (§4.1): **A fires `d` after *sending*, B fires `d` after
/// *receiving*.** The sync crosses roughly half the carrier round trip, so the
/// two firings meet near the middle. Deriving `d` is [`punch_delay`]; measuring
/// the RTT and actually firing are Stage 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PunchSync {
    pub nonce: Nonce,
    /// Milliseconds from **receipt**, never an absolute instant. See the type
    /// doc — the clock domain and the unsigned encoding are the interoperable
    /// surface; the *value* is a local tunable (§4.1, §9).
    pub fire_at: u64,
}

impl PunchSync {
    pub fn to_entity(&self) -> Result<Entity, SignalingError> {
        let data = to_ecf(&Value::Map(vec![
            // A CBOR uint (major 0), not a signed integer: §4.1 pins the
            // encoding alongside the clock domain, and `u64` is what makes a
            // negative delay unrepresentable rather than merely unwise.
            (
                text("fire_at"),
                Value::Integer(ciborium::value::Integer::from(self.fire_at)),
            ),
            (text("nonce"), bytes(self.nonce.0.clone())),
        ]));
        Entity::new(TYPE_PUNCH_SYNC, data).map_err(|e| SignalingError::Encode(e.to_string()))
    }

    pub fn from_entity_bytes(data: &[u8]) -> Result<Self, SignalingError> {
        let map = decode_map(data)?;
        Ok(Self {
            nonce: Nonce(field_bytes(&map, "nonce")?),
            fire_at: field_u64(&map, "fire_at")?,
        })
    }
}

/// The default `d` in §4.1's derivation: `d = max(rtt, 250 ms)`.
///
/// `[K]` industry-typical, **not** measured here — §4.1 pins the shape and
/// leaves the number to the live gate, so this is a tunable default rather than
/// a wire constant. Two peers may hold different floors without failing to meet;
/// they may not differ on the clock domain or the encoding.
pub const PUNCH_DELAY_FLOOR_MS: u64 = 250;

/// Derive the `fire_at` delay from the measured carrier round-trip (§4.1).
///
/// `rtt_ms` is the round trip **through the carrier** — A's `offer` to the
/// `collect` that returns B's response. That is the only latency estimate either
/// peer has, since by construction neither can yet reach the other directly.
///
/// The MUST this enforces: **`d` ≥ the one-way carrier latency (`rtt/2`)**.
/// Below that floor B's fire time has already elapsed when the sync lands and
/// the two sides never overlap. `max(rtt, 250)` satisfies it with margin —
/// `d ≥ rtt` implies `d ≥ rtt/2` — so the guarantee holds for any floor, not
/// just this default. Retry counts and probe pacing stay local (§4.1).
pub fn punch_delay(rtt_ms: u64) -> u64 {
    rtt_ms.max(PUNCH_DELAY_FLOOR_MS)
}

// ---------------------------------------------------------------------------
// Reading a bucket — §3.2, where a naive impl breaks. All three filters are
// MUSTs, and they were ratified from this build rather than authored ahead of
// it: skip your own messages, correlate a response by nonce echo, and skip an
// undecodable blob rather than erroring. Bucket order is deposit order, oldest
// first (§1.1 pin 4). *Which* of several `lobby` requests to answer is
// deliberately left as peer policy.
// ---------------------------------------------------------------------------

/// A blob collected from a bucket, classified by which message it is.
///
/// A bucket is a *set* the node never interprets, so anything may be in it: your
/// own offer (collect is non-destructive, so you always re-read what you wrote),
/// other pairs' traffic in `lobby`/`tag`, and — MUST-ignore — message types a
/// newer impl introduced. Classification is therefore lossy on purpose:
/// [`Unknown`](CollectedMessage::Unknown) is a normal outcome, never an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectedMessage {
    Request(ConnectRequest),
    Response(ConnectResponse),
    Sync(PunchSync),
    /// Undecodable or an unrecognized type. Kept rather than dropped so a caller
    /// can count what it skipped instead of silently ignoring a bucket full of
    /// messages it does not understand.
    Unknown,
}

/// Serialize a coordination entity into the opaque blob the node stores —
/// **§3.1, the pinned framing.**
///
/// The blob is the canonical `{type, data, content_hash}` encoding, so the
/// message's **type travels with it** — a bucket holds a mixed set and the
/// reader has nothing else to dispatch on; `connect-request` and
/// `connect-response` differ by a single field *name*, so a reader handed bare
/// `data` would be reduced to sniffing map keys. `encode_entity` embeds `data`
/// as raw CBOR rather than re-encoding it, which is the byte-fidelity rule the
/// whole substrate rests on: the node stores these bytes verbatim and hands them
/// back verbatim, so a round trip through the carrier cannot perturb the §3.3
/// signature these messages will carry.
///
/// This shape was chosen by the Stage-1 build and **ratified unchanged** as
/// §3.1 — the spec had never said what `offer`'s `message` bytes are, which
/// would have meant Go and Rust wrapping differently and every cross-impl
/// rendezvous returning blobs nobody could classify.
pub fn to_blob(entity: &Entity) -> Vec<u8> {
    entity_wire::encode_entity(entity)
}

/// Classify one blob collected from a bucket.
///
/// An undecodable blob is [`CollectedMessage::Unknown`], not an error: a shared
/// `lobby` bucket may legitimately hold anything, including a future message
/// type this build has never heard of, and MUST-ignore says we skip it rather
/// than fail the poll.
pub fn classify_blob(blob: &[u8]) -> CollectedMessage {
    match entity_wire::decode_entity(blob) {
        Ok(e) => classify(&e.entity_type, &e.data),
        Err(_) => CollectedMessage::Unknown,
    }
}

/// Classify from an already-split type and data.
///
/// We match on the type string rather than sniffing the map, because two of
/// these three have identical field sets apart from `initiator`/`responder`.
pub fn classify(entity_type: &str, data: &[u8]) -> CollectedMessage {
    match entity_type {
        TYPE_CONNECT_REQUEST => ConnectRequest::from_entity_bytes(data)
            .map(CollectedMessage::Request)
            .unwrap_or(CollectedMessage::Unknown),
        TYPE_CONNECT_RESPONSE => ConnectResponse::from_entity_bytes(data)
            .map(CollectedMessage::Response)
            .unwrap_or(CollectedMessage::Unknown),
        TYPE_PUNCH_SYNC => PunchSync::from_entity_bytes(data)
            .map(CollectedMessage::Sync)
            .unwrap_or(CollectedMessage::Unknown),
        _ => CollectedMessage::Unknown,
    }
}

// ---------------------------------------------------------------------------
// §6.3 — the container, read side
// ---------------------------------------------------------------------------

/// Whether a party demands §6.3 verification before it acts on a collected
/// message.
///
/// **Substrate-neutral, and deliberately one type.** §6.1 (native punch) and
/// §6.5 (the browser leg) read the same envelope out of the same buckets under
/// the same MUST; two policy enums would be two things to keep in step at a
/// security seam, and the one that drifted would be the one nobody was looking
/// at. Re-exported as `webrtc::VerificationPolicy`, which is where it was born
/// and where `core/peer` names it.
///
/// **There is no `Default`, on purpose.** Making this a named argument at every
/// call site — rather than a silently-permissive default — is what keeps "we
/// shipped it with no identity binding" from being something a reader has to
/// infer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationPolicy {
    /// Conformant: refuse to act on a message that did not pass §6.3. Satisfied
    /// by any counterpart that deposits sealed, and a refusal for any that does
    /// not — the correct posture for a peer that would rather not connect than
    /// connect to an unverified counterpart.
    Require,
    /// Migration interop: act on a counterpart's message without verification.
    /// Grep for this variant to find every place that matters.
    AllowUnverifiedPreContainer,
}

/// One collected blob, classified — plus the signer, when it arrived inside a
/// §6.3 container.
#[derive(Debug, Clone)]
pub struct CollectedCoordination {
    pub msg: CollectedMessage,
    /// `Some` **only** when the blob was a `signed-blob` that verified against
    /// the bucket it was collected from *and* whose signer matched whatever
    /// identity the payload claimed. There is no other way to obtain one.
    pub signer: Option<VerifiedSigner>,
}

/// The identity a §6.1 payload claims for its own author, if it claims one.
///
/// `connect-request` and `connect-response` name their author on the wire, so a
/// signature valid under a **false claim** passes every other step — the bytes
/// really were signed by the key presented, just not by the peer the message
/// says wrote it. `punch-sync` names nobody: it is correlated by the nonce echo
/// and carries only a delay, which puts it in the same position as all of
/// §6.5's payloads, where the derived signer simply *is* the identity.
fn claimed_signer(msg: &CollectedMessage) -> Option<&str> {
    match msg {
        CollectedMessage::Request(r) => Some(&r.initiator),
        CollectedMessage::Response(r) => Some(&r.responder),
        CollectedMessage::Sync(_) | CollectedMessage::Unknown => None,
    }
}

/// Classify a collected blob, unwrapping a §6.3 container if that is what it is
/// — the §6.1 counterpart of [`crate::webrtc::classify_collected`].
///
/// **Four dispositions, not three** (spec §6.3, folded 2026-08-04). The three
/// verify failures — `unusable_key` / `signer_mismatch` / `bad_signature` — are
/// one outcome here (skip), and "it never was a container" is a *different*
/// one (read it as the bare §6.2 framing). Collapsing them is a downgrade: if a
/// verify failure could fall back to the bare inner entity, flipping one
/// signature byte turns a signed message into an accepted unsigned one, which
/// is the whole attack the container prevents.
///
/// Both bare and sealed are accepted **only for as long as the migration needs
/// it**. Which framing arrived is not lost — it is exactly the presence or
/// absence of `signer`, and [`VerificationPolicy::Require`] is what turns that
/// into a refusal.
pub fn classify_collected(blob: &[u8], key: &RendezvousKey) -> CollectedCoordination {
    // Not a container at all → the bare framing every §6.1 depositor still
    // writes. `envelope::parse` failing is the normal outcome here, not a
    // diagnosis.
    if crate::envelope::parse(blob).is_err() {
        return CollectedCoordination {
            msg: classify_blob(blob),
            signer: None,
        };
    }
    match crate::envelope::open(blob, key) {
        Ok((signer, inner)) => {
            let msg = classify(&inner.entity_type, &inner.data);
            match claimed_signer(&msg) {
                // §6.3 step 3 — `signer_mismatch`. Skipped, and skipped as a
                // container: never re-read as its bare inner entity.
                Some(claim) if claim != signer.peer_id() => CollectedCoordination {
                    msg: CollectedMessage::Unknown,
                    signer: None,
                },
                _ => CollectedCoordination {
                    msg,
                    signer: Some(signer),
                },
            }
        }
        // It claimed to be a container and failed to verify. Skip it.
        Err(_) => CollectedCoordination {
            msg: CollectedMessage::Unknown,
            signer: None,
        },
    }
}

/// Find the response to *my* exchange in a collected bucket.
///
/// Two §3.2 MUSTs, both necessary:
/// - **nonce echo** — in `lobby`/`tag` the bucket is shared, so someone else's
///   response is not mine, and a fresh answer is not one processed two polls
///   ago. The nonce is a **correlator, not a secret**: anyone who can collect
///   the bucket can read it and echo it, which is what §3.3's signature is for.
/// - **not my own peer-id** — a peer that answered its own request would
///   "succeed" at meeting itself, and that failure is miserable to diagnose
///   because every individual step reports success.
///
/// The signer travels with the message because the two are only meaningful
/// together: a candidate list is worth dialing on the strength of who signed
/// *that* blob, so re-pairing them after the fact would reintroduce exactly the
/// substitution the container prevents.
pub fn find_response<'a>(
    messages: impl IntoIterator<Item = &'a CollectedCoordination>,
    my_nonce: &Nonce,
    my_peer_id: &str,
) -> Option<(ConnectResponse, Option<VerifiedSigner>)> {
    messages.into_iter().find_map(|c| match &c.msg {
        CollectedMessage::Response(r)
            if &r.nonce == my_nonce && author_of(c, &r.responder) != my_peer_id =>
        {
            Some((r.clone(), c.signer.clone()))
        }
        _ => None,
    })
}

/// Who a collected message is **from**, for the §6.4 filters.
///
/// The verified signer when there is one; the wire claim otherwise. For a
/// sealed message step 3 has already proven the two equal, so this changes no
/// outcome — it changes which value the code is *written against*, and that is
/// the difference between a filter that keeps working when the claim becomes
/// hostile and one that only looked correct. For a bare message the claim is
/// all there is, and it is exactly as trustworthy as whoever wrote it.
fn author_of<'a>(c: &'a CollectedCoordination, claimed: &'a str) -> &'a str {
    c.signer.as_ref().map(|s| s.peer_id()).unwrap_or(claimed)
}

/// Find a request addressed at this rendezvous that I should answer — anyone's
/// but my own.
///
/// Returns the first match in bucket order. A `lobby` bucket may hold several,
/// and which one to answer is a **peer policy** question (answer all, answer
/// one, prefer a known peer) that this layer deliberately does not decide.
///
/// **The trap that policy leaves to the caller** (found by the Python client,
/// 2026-07-30, and it will bite any repeated run): `pair` and `lobby` keys are
/// **stable by construction**, so their buckets still hold *earlier* exchanges
/// until the 60 s TTL reaps them. A responder that answers the first hit on a
/// rerun adopts a **stale** request — echoing a nonce nobody is waiting on — and
/// leaves the live request unanswered, while every step reports success. Track
/// the nonces you have already answered and skip them; the bucket is a set with
/// history, not a queue.
pub fn find_request<'a>(
    messages: impl IntoIterator<Item = &'a CollectedCoordination>,
    my_peer_id: &str,
) -> Option<(ConnectRequest, Option<VerifiedSigner>)> {
    messages.into_iter().find_map(|c| match &c.msg {
        CollectedMessage::Request(r) if author_of(c, &r.initiator) != my_peer_id => {
            Some((r.clone(), c.signer.clone()))
        }
        _ => None,
    })
}

// ---------------------------------------------------------------------------
// CBOR helpers
// ---------------------------------------------------------------------------

pub(crate) fn decode_map(data: &[u8]) -> Result<Vec<(Value, Value)>, SignalingError> {
    let value: Value =
        ciborium::from_reader(data).map_err(|e| SignalingError::Decode(e.to_string()))?;
    value
        .into_map()
        .map_err(|_| SignalingError::Decode("expected CBOR map".into()))
}

fn get_field<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter().find_map(|(k, v)| {
        if k.as_text() == Some(key) {
            Some(v)
        } else {
            None
        }
    })
}

pub(crate) fn field_text(map: &[(Value, Value)], key: &str) -> Result<String, SignalingError> {
    get_field(map, key)
        .and_then(|v| v.as_text())
        .map(|s| s.to_string())
        .ok_or_else(|| SignalingError::Decode(format!("missing/invalid text field {}", key)))
}

pub(crate) fn field_bytes(map: &[(Value, Value)], key: &str) -> Result<Vec<u8>, SignalingError> {
    get_field(map, key)
        .and_then(|v| v.as_bytes())
        .map(|b| b.to_vec())
        .ok_or_else(|| SignalingError::Decode(format!("missing/invalid bstr field {}", key)))
}

/// Read an unsigned integer field. A negative value fails here rather than
/// being clamped or widened: `fire_at` is a delay (§4.1), so a negative one is
/// not a small mistake to tolerate — it is the wall-clock reading of a field
/// that has none, and acting on it means firing into a window that has passed.
pub(crate) fn field_u64(map: &[(Value, Value)], key: &str) -> Result<u64, SignalingError> {
    get_field(map, key)
        .and_then(|v| v.as_integer())
        .and_then(|i| u64::try_from(i).ok())
        .ok_or_else(|| {
            SignalingError::Decode(format!("missing/invalid unsigned integer field {}", key))
        })
}

fn field_candidates(map: &[(Value, Value)]) -> Result<Vec<Candidate>, SignalingError> {
    let items = get_field(map, "candidates")
        .and_then(|v| v.as_array())
        .ok_or_else(|| SignalingError::Decode("missing/invalid array field candidates".into()))?;
    items.iter().map(Candidate::from_value).collect()
}
