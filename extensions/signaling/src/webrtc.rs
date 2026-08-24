//! `EXTENSION-SIGNALING.md` §6.5 — WebRTC substrate coordination (the browser leg).
//!
//! The browser's only peer-to-peer transport is a WebRTC data channel, and its
//! coordination is an **SDP/ICE exchange** which §6.1's `connect-request` /
//! `connect-response` cannot carry — those hold a candidate array and no SDP. So
//! the substrate defines three signed entities of its own. They ride the carrier
//! under §6.2 (blob framing), §6.3 (self-contained signature) and §6.4 (bucket
//! read) **unchanged**; only the payload differs, which is why this module sits
//! beside [`crate::coordination`] and reuses its framing wholesale.
//!
//! This is the coordination half only — pure data and pure decisions, no
//! `RTCPeerConnection` and no socket. That is the same split [`crate::punch`]
//! makes for the native substrate, and it is what lets the whole §6.5 exchange
//! be unit-tested natively while the browser glue stays behind a seam.
//!
//! # The schema version is pinned, and something pins to it
//!
//! [`crate::webrtc::SCHEMA_VERSION`] is the identifier a `system/peer/transport/webrtc` profile
//! carries in `negotiation.signaling_schema` (`EXTENSION-NETWORK.md` §6.5.2d).
//! The two must agree or a peer advertises a dialect it does not speak.
//!
//! # Two deliberate non-collapses, both easy to get wrong
//!
//! - **[`crate::webrtc::IceCandidate`] is NOT [`crate::coordination::Candidate`]** — and the
//!   names differ here to keep anyone from "unifying" them. §6.5 draws the same
//!   line §6.7 draws for reflection: a `system/network/candidate` is
//!   entity-core's own reachability fact, gathered from `observe-address`; an
//!   `IceCandidate` is the **browser's** ICE format, produced and consumed by
//!   the browser's ICE stack and carried **verbatim**. Translating between them
//!   is a MUST NOT.
//! - **The candidate is a structured tuple, not a bare line** `[MUST]`.
//!   `RTCPeerConnection.addIceCandidate()` rejects a bare candidate string — it
//!   needs `sdp_mid` and `sdp_mline_index` alongside it. That was found by an
//!   implementer against a real browser, not by review, which is why the fields
//!   are REQUIRED rather than optional. The offer/answer `sdp` is the opposite:
//!   **opaque**, fed verbatim to `setRemoteDescription`, so structuring it would
//!   be wrong.
//!
//! # The §6.3 hole — why nothing here verifies a signature yet
//!
//! §6.5's security rests entirely on §6.3: *verify the entity's signature → feed
//! **that** entity's SDP verbatim to `setRemoteDescription` → never
//! `setRemoteDescription` on an unverified entity.* Arch confirmed (2026-08-03)
//! that this **is** the browser leg's discharge of §7.4 — a browser peer does
//! **not** run the native connectivity check, and no runtime fingerprint compare
//! is expected; the browser's own stack binds the DTLS cert to the SDP
//! `a=fingerprint` (RFC 8827) automatically.
//!
//! **But the signature has nowhere to ride.** §6.3 specifies the two *checks*
//! (derive `Base58(0x01 ‖ 0x01 ‖ SHA-256(pk))`, compare to the claimed peer-id;
//! verify over the content hash) and no *container*: §6.2 pins the blob as the
//! bare `{type, data, content_hash}` encoding, §12 registers no envelope type,
//! and `system/signature` carries its signer as a **hash** — not self-contained
//! for a stranger, which is the whole point of the §6.3 exception. Inventing one
//! locally would be protocol design. `entity-core-go` reached the identical
//! conclusion independently and routed it upstream
//! (`ROUTING-2026-08-03-webrtc-coordination-in-go-and-the-6.3-hole`).
//!
//! Two consequences this module is built around, both worth stating plainly:
//!
//! 1. **The discharge is inoperative until the container lands.** Verification
//!    that cannot happen cannot bind an identity, so §6.5's MUST is *buildable*
//!    now and *dischargeable* only later. Nothing here should be read as the
//!    browser leg being secure against a signaling MITM today.
//! 2. **These entities carry no `peer_id` at all** — deliberately; a counterpart's
//!    identity comes *only* from the §6.3 signature. So the offerer rule below
//!    cannot even be *evaluated* in `tag` / `secret` / `lobby`, where the
//!    counterpart is unknown until its first entity is collected. **`pair` mode
//!    is the exception and therefore S3's scope**: both ids are known out of
//!    band, which is exactly why §6.5 names it the natural default and why the
//!    S5 gate uses it.

use ciborium::Value;
use entity_ecf::{bytes, text, to_ecf};
use entity_entity::Entity;

use crate::coordination::{decode_map, field_bytes, field_text, field_u64};
use crate::punch::Carrier;
use crate::RendezvousKey;
use crate::SignalingError;

// ---------------------------------------------------------------------------
// Types and the pinned schema version (§6.5)
// ---------------------------------------------------------------------------

pub const TYPE_WEBRTC_OFFER: &str = "system/signaling/webrtc/offer";
pub const TYPE_WEBRTC_ANSWER: &str = "system/signaling/webrtc/answer";
pub const TYPE_WEBRTC_CANDIDATE: &str = "system/signaling/webrtc/candidate";

/// The schema identifier a `webrtc` transport profile pins in
/// `negotiation.signaling_schema` (`EXTENSION-NETWORK.md` §6.5.2d).
pub const SCHEMA_VERSION: &str = "webrtc-sdp-ice/1";

/// The §6.5 minimum for a `session_id`, in bytes `[MUST]`.
pub const SESSION_ID_MIN_BYTES: usize = 16;

// ---------------------------------------------------------------------------
// session_id
// ---------------------------------------------------------------------------

/// Correlates one pairing's offer / answer / candidates **within** a rendezvous
/// key — the WebRTC analogue of the native `nonce` echo.
///
/// **MUST be freshly random and ≥16 bytes** (§6.5). A `lobby` or `tag` key may
/// host several concurrent pairings, and a weak or colliding `session_id`
/// splices two of them together: peer A's offer answered against peer B's
/// candidates, a silent cross-handshake that no individual step reports as an
/// error. The length floor is enforced on the way *in* ([`SessionId::parse`]) as
/// well as generated on the way out, because a counterpart's short id is exactly
/// as dangerous as our own.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(Vec<u8>);

impl SessionId {
    /// 16 fresh random bytes from the OS CSPRNG.
    ///
    /// **On wasm32 this is `crypto.getRandomValues`, never `Math.random`.**
    /// `OsRng` resolves through `getrandom`, whose `js` backend is declared for
    /// `cfg(target_arch = "wasm32")` in this crate's `Cargo.toml`. Worth pinning
    /// in a comment because `entity-browser-rust` raised it as a hazard of the
    /// class that "passes every native test and is wrong only on the wire" —
    /// and the answer is better than that: `getrandom` has **no** insecure
    /// fallback, so a missing backend is a build/runtime *failure*, not a
    /// silent downgrade. The bad outcome here is loud, not quiet.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut b = [0u8; SESSION_ID_MIN_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut b);
        Self(b.to_vec())
    }

    /// Accept a counterpart's `session_id`, enforcing the §6.5 floor.
    pub fn parse(raw: Vec<u8>) -> Result<Self, SignalingError> {
        if raw.len() < SESSION_ID_MIN_BYTES {
            return Err(SignalingError::Decode(format!(
                "session_id is {} bytes; §6.5 requires at least {}",
                raw.len(),
                SESSION_ID_MIN_BYTES
            )));
        }
        Ok(Self(raw))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// §6.5 — the three messages
// ---------------------------------------------------------------------------

/// The offerer's SDP offer. `sdp` is **opaque** — fed verbatim to
/// `setRemoteDescription`, never parsed or rebuilt here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    pub session_id: SessionId,
    /// **Sealed.** Read it with [`Offer::accept_remote_description`], which
    /// demands a [`VerifiedSigner`]. See that method for why this is private.
    sdp: String,
}

impl Offer {
    /// Build **our own** offer, to sign and post. The local side is not gated:
    /// the MUST is about SDP arriving *from* the carrier.
    pub fn new(session_id: SessionId, sdp: impl Into<String>) -> Self {
        Self {
            session_id,
            sdp: sdp.into(),
        }
    }

    /// The SDP we are about to sign and send — our own, never a counterpart's.
    pub fn local_sdp(&self) -> &str {
        &self.sdp
    }

    /// The remote SDP, **without** §6.3 verification — crate-private and named
    /// to be greppable. Reachable only through
    /// [`VerificationPolicy::AllowUnverifiedPreContainer`], which every caller
    /// must name explicitly. Deletable the day the signature container lands.
    pub(crate) fn pre_container_sdp(&self) -> &str {
        &self.sdp
    }

    /// Release a **collected** offer's SDP for `setRemoteDescription`.
    ///
    /// §6.5's channel-identity MUST, enforced by the type system rather than by
    /// documentation: `sdp` is private, so the only way to reach a remote SDP is
    /// through a [`VerifiedSigner`], which only
    /// [`verify_coordination_signature`] can mint. "Call `setRemoteDescription`
    /// on unverified SDP" does not compile.
    ///
    /// `entity-core-go`'s `AcceptRemoteDescription` is the same guard, and its
    /// doc records that Go *cannot* seal the field against its own package —
    /// "this function is the guarded path, not a sealed one." Rust can, so it
    /// does; the discharge stops depending on nobody reaching past it.
    pub fn accept_remote_description(
        &self,
        signer: &VerifiedSigner,
        my_peer_id: &str,
    ) -> Result<&str, SignalingError> {
        signer.admit(my_peer_id)?;
        Ok(&self.sdp)
    }

    pub fn to_entity(&self) -> Result<Entity, SignalingError> {
        let data = to_ecf(&Value::Map(vec![
            (text("sdp"), text(&self.sdp)),
            (text("session_id"), bytes(self.session_id.0.clone())),
        ]));
        Entity::new(TYPE_WEBRTC_OFFER, data).map_err(|e| SignalingError::Encode(e.to_string()))
    }

    pub fn from_entity_bytes(data: &[u8]) -> Result<Self, SignalingError> {
        let map = decode_map(data)?;
        Ok(Self {
            session_id: SessionId::parse(field_bytes(&map, "session_id")?)?,
            sdp: field_text(&map, "sdp")?,
        })
    }
}

/// The responder's SDP answer, correlated by `session_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub session_id: SessionId,
    /// **Sealed** — see [`Offer::accept_remote_description`].
    sdp: String,
}

impl Answer {
    /// Build **our own** answer, to sign and post.
    pub fn new(session_id: SessionId, sdp: impl Into<String>) -> Self {
        Self {
            session_id,
            sdp: sdp.into(),
        }
    }

    /// The SDP we are about to sign and send — our own, never a counterpart's.
    pub fn local_sdp(&self) -> &str {
        &self.sdp
    }

    /// The remote SDP, **without** §6.3 verification — crate-private and named
    /// to be greppable. Reachable only through
    /// [`VerificationPolicy::AllowUnverifiedPreContainer`], which every caller
    /// must name explicitly. Deletable the day the signature container lands.
    pub(crate) fn pre_container_sdp(&self) -> &str {
        &self.sdp
    }

    /// Release a **collected** answer's SDP for `setRemoteDescription`.
    /// See [`Offer::accept_remote_description`].
    pub fn accept_remote_description(
        &self,
        signer: &VerifiedSigner,
        my_peer_id: &str,
    ) -> Result<&str, SignalingError> {
        signer.admit(my_peer_id)?;
        Ok(&self.sdp)
    }

    pub fn to_entity(&self) -> Result<Entity, SignalingError> {
        let data = to_ecf(&Value::Map(vec![
            (text("sdp"), text(&self.sdp)),
            (text("session_id"), bytes(self.session_id.0.clone())),
        ]));
        Entity::new(TYPE_WEBRTC_ANSWER, data).map_err(|e| SignalingError::Encode(e.to_string()))
    }

    pub fn from_entity_bytes(data: &[u8]) -> Result<Self, SignalingError> {
        let map = decode_map(data)?;
        Ok(Self {
            session_id: SessionId::parse(field_bytes(&map, "session_id")?)?,
            sdp: field_text(&map, "sdp")?,
        })
    }
}

/// One trickled ICE candidate (RFC 8838), either direction, post-offer/answer.
///
/// Trickle is the **sole** candidate path in §6.5: candidates flow as they are
/// gathered rather than blocking the offer on full gathering, which is what
/// keeps the handshake inside its seconds-bounded window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceCandidate {
    pub session_id: SessionId,
    /// The RFC 8445 candidate line, carried verbatim.
    pub candidate: String,
    /// REQUIRED — `addIceCandidate()`'s `sdpMid`.
    pub sdp_mid: String,
    /// REQUIRED — `addIceCandidate()`'s `sdpMLineIndex`.
    pub sdp_mline_index: u64,
    /// OPTIONAL — `addIceCandidate()`'s `usernameFragment`. Absent, not null,
    /// when unused (§2.8 optional-field rule).
    pub username_fragment: Option<String>,
}

impl IceCandidate {
    pub fn to_entity(&self) -> Result<Entity, SignalingError> {
        let mut entries = vec![
            (text("candidate"), text(&self.candidate)),
            (text("sdp_mid"), text(&self.sdp_mid)),
            (
                // A CBOR uint (major 0), matching `fire_at`'s encoding — an
                // m-line index is an index, and `u64` makes a negative one
                // unrepresentable rather than merely invalid.
                text("sdp_mline_index"),
                Value::Integer(ciborium::value::Integer::from(self.sdp_mline_index)),
            ),
            (text("session_id"), bytes(self.session_id.0.clone())),
        ];
        // OPTIONAL fields are ABSENT when unset — never null.
        if let Some(ufrag) = &self.username_fragment {
            entries.push((text("username_fragment"), text(ufrag)));
        }
        let data = to_ecf(&Value::Map(entries));
        Entity::new(TYPE_WEBRTC_CANDIDATE, data).map_err(|e| SignalingError::Encode(e.to_string()))
    }

    pub fn from_entity_bytes(data: &[u8]) -> Result<Self, SignalingError> {
        let map = decode_map(data)?;
        Ok(Self {
            session_id: SessionId::parse(field_bytes(&map, "session_id")?)?,
            candidate: field_text(&map, "candidate")?,
            sdp_mid: field_text(&map, "sdp_mid")?,
            sdp_mline_index: field_u64(&map, "sdp_mline_index")?,
            username_fragment: field_text(&map, "username_fragment").ok(),
        })
    }
}

// ---------------------------------------------------------------------------
// Bucket classification (§6.4, unchanged)
// ---------------------------------------------------------------------------

/// One classified blob from a bucket.
///
/// `Unknown` is not an error: a shared bucket legitimately holds native
/// `connect-request`s, other pairings' traffic, and message types this build has
/// never heard of. §6.4's MUST-ignore says skip it rather than fail the poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectedWebRtc {
    Offer(Offer),
    Answer(Answer),
    Candidate(IceCandidate),
    Unknown,
}

/// Classify one collected blob as a §6.5 message.
pub fn classify_blob(blob: &[u8]) -> CollectedWebRtc {
    match entity_wire::decode_entity(blob) {
        Ok(e) => classify(&e.entity_type, &e.data),
        Err(_) => CollectedWebRtc::Unknown,
    }
}

/// Classify from an already-split type and data.
pub fn classify(entity_type: &str, data: &[u8]) -> CollectedWebRtc {
    match entity_type {
        TYPE_WEBRTC_OFFER => Offer::from_entity_bytes(data)
            .map(CollectedWebRtc::Offer)
            .unwrap_or(CollectedWebRtc::Unknown),
        TYPE_WEBRTC_ANSWER => Answer::from_entity_bytes(data)
            .map(CollectedWebRtc::Answer)
            .unwrap_or(CollectedWebRtc::Unknown),
        TYPE_WEBRTC_CANDIDATE => IceCandidate::from_entity_bytes(data)
            .map(CollectedWebRtc::Candidate)
            .unwrap_or(CollectedWebRtc::Unknown),
        _ => CollectedWebRtc::Unknown,
    }
}

// ---------------------------------------------------------------------------
// §6.3 verification — the only source of a counterpart's identity
// ---------------------------------------------------------------------------

/// Proof that §6.3's two checks passed for one coordination entity.
///
/// Constructible **only** by [`verify_coordination_signature`], so a caller
/// cannot assert one into existence — which is what makes the sealed
/// `accept_remote_description` accessors mean something. Mirrors
/// `entity-core-go`'s `VerifiedSigner` deliberately: this is a cross-peer
/// security seam, and two impls agreeing on its shape is worth more than either
/// impl's own tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSigner {
    peer_id: String,
}

impl VerifiedSigner {
    /// The derived-and-checked signer identity. §6.5's payloads carry **no**
    /// `peer_id` field, so this is the only place a counterpart's identity comes
    /// from — which is why the offerer rule cannot run without it.
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    /// §6.4's skip-own, applied where it cannot be forgotten.
    fn admit(&self, my_peer_id: &str) -> Result<(), SignalingError> {
        if self.peer_id.is_empty() {
            return Err(SignalingError::UnverifiedSdp);
        }
        if self.peer_id == my_peer_id {
            return Err(SignalingError::SelfNegotiation);
        }
        Ok(())
    }
}

/// §6.3's two checks over one coordination entity.
///
/// (a) the `public_key` derives the signer's peer-id, and (b) the signature
/// verifies over the entity's **content hash in 33-byte wire form**
/// (`algorithm ‖ digest`) — the same thing every other signature in this
/// codebase binds, so the format byte travels with it.
///
/// **The derivation is the canonical one, not §6.3's spelled-out byte string.**
/// §6.3 writes `Base58(0x01 ‖ 0x01 ‖ SHA-256(pk))` — the legacy SHA-256 form
/// that V7 §1.5 v7.65 Amendment 3 made decode-only and that *both* reference
/// implementations refuse to mint. Following it literally yields a peer-id that
/// compares unequal against every canonical one, and §6.3 says a failed check is
/// skipped silently — so every message would vanish and the rendezvous would
/// simply never complete. Logged in `docs/SPEC-AMBIGUITIES.md`; Go's
/// `PeerIDFromPublicKey` selects the canonical hash type for the same reason.
///
/// **The key type is parametric, not §6.3's literal `0x01`.** §6.3 spells the
/// derivation with the key type hardcoded to Ed25519. Read literally that would
/// refuse every Ed448 signer — an identity this codebase *mints* (`KeyType::Ed448`,
/// [`entity_crypto::Ed448Keypair`], cross-validated against Go's CIRCL in
/// `core/peer/tests/cohort_compare_v767_phase1.rs`). Since §6.3 says a failed
/// check is skipped **silently**, a literal reading would make an Ed448 peer's
/// coordination messages vanish with nothing anywhere naming the cause. Both
/// reference implementations therefore dispatch on `key_type`, which
/// interoperates with either answer to the open question — logged in
/// `docs/SPEC-AMBIGUITIES.md` and pinned by `entity-core-go` as the third of
/// three §6.3 issues. There is no confusion hazard in widening it: the peer-id
/// embeds the key type, so an Ed448 key derives an Ed448 peer-id and cannot be
/// passed off as an Ed25519 one.
///
/// **What this cannot do yet.** §6.3 specifies no *container* carrying the
/// signature and public key alongside the entity, so nothing on the wire can be
/// fed to this function today (see the module doc). It exists now so the
/// container is a drop-in when it lands, and so the sealed accessors above have
/// a real gate rather than a placeholder.
pub fn verify_coordination_signature(
    entity: &Entity,
    public_key: &[u8],
    key_type: u8,
    signature: &[u8],
) -> Result<VerifiedSigner, SignalingError> {
    // An unallocated or sign-incapable key type is a *signer* fault, not a
    // signature fault — the distinction the cross-impl vectors assert on.
    let key_type =
        entity_crypto::KeyType::from_byte(key_type).map_err(|_| SignalingError::SignerMismatch)?;
    // Check (b) first: a bad signature makes the claimed identity meaningless.
    entity_crypto::verify_for_key_type(
        key_type,
        public_key,
        &entity.content_hash.to_bytes(),
        signature,
    )
    .map_err(|e| match e {
        // A wrong-length key or a key type with no verify semantics never got
        // as far as checking the signature; reporting `bad_signature` there
        // would send a diagnostician after the wrong half of the pair.
        entity_crypto::CryptoError::InvalidPublicKey
        | entity_crypto::CryptoError::UnsupportedKeyType(_) => SignalingError::SignerMismatch,
        _ => SignalingError::BadSignature,
    })?;
    // Check (a): the peer-id IS a commitment to the public key, so deriving it
    // is the whole verification — no key lookup, no prior contact (§6.3). The
    // canonical hash type per key type is selected inside the derivation
    // (Ed25519 → identity, Ed448 → SHA-256), not spelled here.
    let peer_id = entity_crypto::PeerId::from_public_key_with_key_type(public_key, key_type)
        .map_err(|_| SignalingError::SignerMismatch)?;
    Ok(VerifiedSigner {
        peer_id: peer_id.to_string(),
    })
}

/// §6.3 for a payload that **names its own signer** — the native §6.1 path.
///
/// §6.5's offer/answer/candidate carry no peer-id, so the derived id *is* the
/// claim and [`verify_coordination_signature`] is the whole check. §6.1's
/// `connect-request` / `connect-response` **do** carry `initiator` / `responder`,
/// and §6.3's check (a) is stated against that claim: *"checks it equals the
/// claimed `initiator` / `responder` peer-id."*
///
/// Splitting this out matters because the two checks fail differently. A valid
/// signature under a **false claim** passes check (b) completely — the bytes
/// really were signed by the key presented. Only the claim comparison catches
/// it, and a verifier that runs (b) alone admits every such payload. Mirrors
/// `entity-core-go`'s `VerifyClaimedSigner` (`ext/signaling/webrtc.go`).
pub fn verify_claimed_signer(
    entity: &Entity,
    public_key: &[u8],
    key_type: u8,
    signature: &[u8],
    claimed_peer_id: &str,
) -> Result<VerifiedSigner, SignalingError> {
    let signer = verify_coordination_signature(entity, public_key, key_type, signature)?;
    if signer.peer_id != claimed_peer_id {
        return Err(SignalingError::SignerMismatch);
    }
    Ok(signer)
}

// ---------------------------------------------------------------------------
// Offerer determination — W3C perfect negotiation (§6.5) `[cross-peer MUST]`
// ---------------------------------------------------------------------------

/// This peer's glare role, decided by the §3.2 peer-id sort.
///
/// WebRTC is **asymmetric** — one side offers, the other answers — and a glare
/// (both offered) is *fatal* to the `RTCPeerConnection` state machine. Native's
/// both-fire symmetry does not survive it, so §6.5 pins W3C perfect negotiation
/// keyed to the byte-wise ascending peer-id sort the rendezvous key derivation
/// **already uses** ([`crate::key::pair_key`]) — not a new convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlareRole {
    /// The lower-sorting peer-id (`lo`). Its offer **wins** a glare; it ignores
    /// the counterpart's competing offer.
    Impolite,
    /// The higher-sorting peer-id (`hi`). On a glare it **rolls back** its own
    /// offer and answers `lo`'s.
    Polite,
}

/// Resolve this peer's glare role against a counterpart.
///
/// Callable only once **both** ids are known — which is exactly when a glare is
/// detectable (the counterpart's entity is in hand, §6.3). That is why the rule
/// is a glare *resolution* and not a pre-assignment in the matchmaking modes.
///
/// **Equal ids are an error, not a role** ([`SignalingError::SelfNegotiation`]).
/// Returning a plausible role there would let a caller that skipped §6.4's
/// skip-own MUST negotiate against itself and succeed at every visible step.
/// Pinned to `entity-core-go`'s `Impolite` contract (`ext/signaling/webrtc.go`),
/// which refuses the same input — a cross-impl agreement worth more than either
/// impl's own test, since both were written from one spec passage.
pub fn glare_role(self_id: &str, other_id: &str) -> Result<GlareRole, SignalingError> {
    if self_id == other_id {
        return Err(SignalingError::SelfNegotiation);
    }
    if self_id.as_bytes() < other_id.as_bytes() {
        Ok(GlareRole::Impolite)
    } else {
        Ok(GlareRole::Polite)
    }
}

/// `pair` mode only: SHOULD `hi` suppress its offer and wait for `lo`'s?
///
/// An **optimization**, not the rule. In `pair` both ids are known in advance,
/// so skipping the glare round-trip is free. `tag` / `secret` / `lobby`
/// **cannot** pre-assign — a peer does not know its counterpart until it
/// collects the counterpart's first entity — so they rely on [`glare_role`].
///
/// A flat "`lo` always offers" is therefore **wrong** for the matchmaking modes:
/// `hi` may legitimately offer first, and forcing `lo` to counter-offer would
/// manufacture the very glare the rule exists to prevent.
pub fn pair_should_suppress_offer(self_id: &str, other_id: &str) -> Result<bool, SignalingError> {
    Ok(glare_role(self_id, other_id)? == GlareRole::Polite)
}

// ---------------------------------------------------------------------------
// Correlation helpers (§6.5 + §6.4)
// ---------------------------------------------------------------------------

/// Find the answer to *my* offer in a collected bucket.
///
/// Correlates on `session_id` — the §6.5 analogue of the native nonce echo.
/// A bucket in `lobby`/`tag` mode holds other pairings' answers, and they are
/// not mine.
pub fn find_answer<'a>(
    messages: impl IntoIterator<Item = &'a CollectedWebRtc>,
    my_session: &SessionId,
) -> Option<Answer> {
    messages.into_iter().find_map(|m| match m {
        CollectedWebRtc::Answer(a) if &a.session_id == my_session => Some(a.clone()),
        _ => None,
    })
}

/// Find a **counterpart's** offer in a collected bucket — the glare signal, and
/// the answerer's trigger.
///
/// Skips any offer carrying `my_session`, because that one is **ours**: a
/// counterpart opening its own pairing generates its own `session_id`, so the
/// session is what tells their offer apart from the copy of ours that the
/// non-destructive `collect` keeps handing back. That is §6.4's *skip your own
/// messages* MUST expressed in the only field this schema gives us to express it
/// — the §6.5 entities carry no `peer_id`.
///
/// **Pre-container caveat.** A counterpart reusing our `session_id` would slip
/// past this. Honest bound: at ≥16 random bytes an accidental collision is not
/// the concern, and a deliberate one is a spoof that §6.3's signature is what
/// catches — unavailable until the container lands. Recorded, not papered over.
pub fn find_counterpart_offer<'a>(
    messages: impl IntoIterator<Item = &'a CollectedWebRtc>,
    my_session: &SessionId,
) -> Option<Offer> {
    messages.into_iter().find_map(|m| match m {
        CollectedWebRtc::Offer(o) if &o.session_id != my_session => Some(o.clone()),
        _ => None,
    })
}

/// Every trickled candidate belonging to one session, in bucket order.
pub fn candidates_for<'a>(
    messages: impl IntoIterator<Item = &'a CollectedWebRtc>,
    session: &SessionId,
) -> Vec<IceCandidate> {
    messages
        .into_iter()
        .filter_map(|m| match m {
            CollectedWebRtc::Candidate(c) if &c.session_id == session => Some(c.clone()),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The negotiation — §6.5's choreography, substrate seam injected
// ---------------------------------------------------------------------------

/// A locally-gathered ICE candidate, before it is bound to a session.
///
/// The browser's ICE agent produces these; `session_id` is ours to attach, so it
/// is not a field the seam has to know about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalCandidate {
    pub candidate: String,
    pub sdp_mid: String,
    pub sdp_mline_index: u64,
    pub username_fragment: Option<String>,
}

/// The browser side of the negotiation, injected exactly as [`crate::punch`]
/// injects `PunchIo` for the native substrate.
///
/// Everything here is `RTCPeerConnection` surface and lives on the **main
/// thread** — `[Exposed=Window]` in the W3C IDL, so that is universal across
/// engines rather than an engine quirk. Keeping it behind a trait is what lets
/// the whole §6.5 choreography be tested natively with no browser at all.
///
/// **`create_offer` / `create_answer` MUST return the finalized local
/// description** — `localDescription.sdp` *after* `setLocalDescription`, not the
/// raw `createOffer()` output. That is the SDP carrying the DTLS
/// `a=fingerprint` this peer will actually present, so signing it is what makes
/// "the fingerprint the receiver binds equals the one we negotiate" structural
/// rather than incidental (arch, `ROUTING-2026-08-03`).
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait WebRtcIo {
    /// The negotiated data channel. Opaque here; `core/peer` resolves it to a
    /// transport connection.
    type Channel;

    /// Create an offer and apply it locally. Returns the **finalized** local SDP.
    async fn create_offer(&self) -> Result<String, String>;

    /// Apply a remote offer and answer it. Returns the **finalized** local SDP.
    async fn create_answer(&self, remote_offer_sdp: &str) -> Result<String, String>;

    /// Apply the remote answer to an offer we made.
    async fn accept_answer(&self, remote_answer_sdp: &str) -> Result<(), String>;

    /// Take everything the ICE agent has gathered since the last call. Trickle
    /// is the sole candidate path (§6.5), so this is polled rather than awaited.
    async fn drain_local_candidates(&self) -> Vec<LocalCandidate>;

    /// Hand a counterpart's candidate to the ICE agent.
    async fn add_remote_candidate(&self, candidate: &IceCandidate) -> Result<(), String>;

    /// Resolve once the data channel is open, or give up after `timeout_ms`.
    async fn wait_open(&self, timeout_ms: u64) -> Result<Self::Channel, String>;

    async fn sleep_ms(&self, ms: u64);

    /// Milliseconds on any monotonic scale. Never placed on the wire.
    fn now_ms(&self) -> u64;
}

/// Whether this negotiation demands §6.3 verification before it will feed a
/// counterpart's SDP to `setRemoteDescription`.
///
/// **There is no `Default`, on purpose.** §6.3 specifies the checks but no
/// container to carry a signature (module doc), so [`Require`](Self::Require)
/// cannot currently succeed and the pre-container path is the only one that
/// runs. Making that a named argument at every call site — rather than a
/// silently-permissive default — is what keeps "we shipped the browser leg with
/// no identity binding" from being something a reader has to infer.
///
/// The sealed SDP accessors are what force this decision into the open: without
/// them the missing container would simply be an absent check nobody wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationPolicy {
    /// Conformant: refuse SDP that did not pass §6.3. **Fails until the
    /// container lands** — which is the correct behaviour for a peer that would
    /// rather not connect than connect to an unverified counterpart.
    Require,
    /// Pre-container interop: accept a counterpart's SDP without verification.
    /// Bounded exactly as the native punch is bounded — *the key introduces, it
    /// never authorizes* — **except** that §6.5 discharges §7.4 for this
    /// substrate, so on the browser leg nothing downstream re-checks identity.
    /// Grep for this variant to find every place that matters.
    AllowUnverifiedPreContainer,
}

/// What went wrong in a §6.5 negotiation.
#[derive(Debug, thiserror::Error)]
pub enum WebRtcError {
    #[error("carrier refused or failed: {0}")]
    Carrier(String),
    #[error("no counterpart answered within the negotiation window")]
    Timeout,
    #[error("the browser's WebRTC stack refused: {0}")]
    Substrate(String),
    #[error("§6.3 verification is required but no signature container exists yet")]
    VerificationUnavailable,
    #[error(transparent)]
    Coding(#[from] SignalingError),
}

impl From<crate::punch::PunchError> for WebRtcError {
    fn from(e: crate::punch::PunchError) -> Self {
        match e {
            crate::punch::PunchError::Coding(c) => WebRtcError::Coding(c),
            other => WebRtcError::Carrier(other.to_string()),
        }
    }
}

/// One peer's side of a `pair`-mode §6.5 negotiation.
///
/// **`pair` only, deliberately.** The counterpart's `peer_id` is required, and
/// in `tag` / `secret` / `lobby` it is *unknowable* before the first collected
/// entity — those payloads carry no `peer_id` and the §6.3 signature that would
/// supply one has no container yet. So the offerer rule cannot be evaluated at
/// all in the matchmaking modes, which is independently why §6.5 names `pair`
/// the natural default and why the S5 gate uses it.
pub struct WebRtcParty {
    /// The rendezvous key both peers derived — `pair` mode, so
    /// [`crate::key::pair_key`] over the two ids.
    pub key: RendezvousKey,
    pub self_id: String,
    /// The counterpart, known out of band. This is what makes `pair` work.
    pub peer_id: String,
    /// Ours if we offer; replaced by the offerer's if we end up answering.
    pub session_id: SessionId,
    pub poll_interval_ms: u64,
    /// Total budget for the whole exchange. §6.5 calls this a seconds-bounded
    /// handshake, which is why trickle exists at all.
    pub deadline_ms: u64,
    pub trust: VerificationPolicy,
}

/// Release a collected SDP under `policy`.
///
/// The seal (`accept_remote_description`) needs a [`VerifiedSigner`], and
/// pre-container there is no way to mint one — so this is the single place the
/// gap is bridged, and it is bridged explicitly rather than by widening the
/// seal. When the container lands, the `Require` arm starts working and this
/// function is where verification plugs in; nothing else moves.
fn release_offer_sdp(offer: &Offer, policy: VerificationPolicy) -> Result<String, WebRtcError> {
    match policy {
        VerificationPolicy::Require => Err(WebRtcError::VerificationUnavailable),
        VerificationPolicy::AllowUnverifiedPreContainer => {
            Ok(offer.pre_container_sdp().to_string())
        }
    }
}

fn release_answer_sdp(answer: &Answer, policy: VerificationPolicy) -> Result<String, WebRtcError> {
    match policy {
        VerificationPolicy::Require => Err(WebRtcError::VerificationUnavailable),
        VerificationPolicy::AllowUnverifiedPreContainer => {
            Ok(answer.pre_container_sdp().to_string())
        }
    }
}

/// Drive a `pair`-mode §6.5 negotiation to an open data channel.
///
/// # The shape, and why post order carries most of it
///
/// §6.5's normal flow needs no pre-agreement: whoever collects an offer while
/// holding none of its own simply answers. `pair` adds one optimization — both
/// ids are known up front, so `hi` **SHOULD** suppress its offer and wait,
/// skipping a glare round trip ([`pair_should_suppress_offer`]). If `hi` offers
/// anyway the glare resolution still converges, so the optimization is not
/// load-bearing.
///
/// # Skip-own without an identity field
///
/// `collect` is non-destructive, so every poll returns our own postings back.
/// With no `peer_id` in these payloads, the negotiation tracks the exact blobs
/// it posted and skips them — §6.4's MUST, applied the only way this schema
/// allows. [`find_counterpart_offer`] adds the session-based half.
pub async fn negotiate<C: Carrier, I: WebRtcIo>(
    party: &WebRtcParty,
    carrier: &C,
    io: &I,
) -> Result<I::Channel, WebRtcError> {
    let started = io.now_ms();
    let mut posted: Vec<Vec<u8>> = Vec::new();
    let mut session = party.session_id.clone();
    let mut fed_candidates: Vec<IceCandidate> = Vec::new();

    // `hi` waits for `lo`'s offer (the pair optimization); `lo` offers now.
    let suppress = pair_should_suppress_offer(&party.self_id, &party.peer_id)?;
    let mut offered = false;
    if !suppress {
        let sdp = io.create_offer().await.map_err(WebRtcError::Substrate)?;
        let blob = post(
            carrier,
            &party.key,
            &Offer::new(session.clone(), sdp),
            &mut posted,
        )
        .await?;
        let _ = blob;
        offered = true;
    }

    let mut answered = false;
    loop {
        if io.now_ms().saturating_sub(started) >= party.deadline_ms {
            return Err(WebRtcError::Timeout);
        }

        let bucket = carrier
            .collect(&party.key)
            .await
            .map_err(|e| WebRtcError::Carrier(e.to_string()))?;
        let mine: Vec<CollectedWebRtc> = bucket
            .iter()
            .filter(|b| !posted.iter().any(|p| p == *b)) // §6.4 skip-own
            .map(|b| classify_blob(b))
            .collect();

        if offered && !answered {
            if let Some(answer) = find_answer(&mine, &session) {
                let sdp = release_answer_sdp(&answer, party.trust)?;
                io.accept_answer(&sdp)
                    .await
                    .map_err(WebRtcError::Substrate)?;
                answered = true;
            }
        }

        if !offered && !answered {
            if let Some(offer) = find_counterpart_offer(&mine, &session) {
                // The offerer's session governs the pairing from here.
                session = offer.session_id.clone();
                let remote = release_offer_sdp(&offer, party.trust)?;
                let sdp = io
                    .create_answer(&remote)
                    .await
                    .map_err(WebRtcError::Substrate)?;
                post(
                    carrier,
                    &party.key,
                    &Answer::new(session.clone(), sdp),
                    &mut posted,
                )
                .await?;
                answered = true;
            }
        }

        // Trickle both ways every tick — candidates flow as they are gathered
        // rather than blocking the offer (§6.5 / RFC 8838).
        //
        // **Not before the session is settled.** Candidates correlate on
        // `session_id` (`candidates_for` matches it exactly), and until this
        // peer has either offered or adopted the offerer's session, `session`
        // is a provisional id **no counterpart will ever query**. Draining into
        // it is worse than waiting: `drain_local_candidates` is destructive, so
        // a candidate posted under the provisional session is not merely
        // mistagged, it is gone — never re-offered under the real one.
        //
        // The answerer is the exposed side: it holds its own `party.session_id`
        // until it finds the offer, so anything gathered in that window is
        // lost. Browsers happen to gather only after `setLocalDescription` —
        // which for an answerer is inside `create_answer`, i.e. after adoption
        // — so this is latent against a browser and immediate against any
        // substrate that gathers earlier. Reproduced natively by
        // `entity_peer::carrier::rendezvous_over_a_real_node` (the offerer saw
        // zero remote candidates while the answerer saw its counterpart's).
        //
        // Holding them costs nothing: undrained candidates stay queued in the
        // substrate and go out on the next tick under the settled session.
        if !offered && !answered {
            io.sleep_ms(party.poll_interval_ms).await;
            continue;
        }

        for local in io.drain_local_candidates().await {
            let c = IceCandidate {
                session_id: session.clone(),
                candidate: local.candidate,
                sdp_mid: local.sdp_mid,
                sdp_mline_index: local.sdp_mline_index,
                username_fragment: local.username_fragment,
            };
            post(carrier, &party.key, &c, &mut posted).await?;
        }
        for remote in candidates_for(&mine, &session) {
            if fed_candidates.contains(&remote) {
                continue; // collect is non-destructive; feed each exactly once
            }
            io.add_remote_candidate(&remote)
                .await
                .map_err(WebRtcError::Substrate)?;
            fed_candidates.push(remote);
        }

        if answered {
            let remaining = party
                .deadline_ms
                .saturating_sub(io.now_ms().saturating_sub(started));
            if let Ok(channel) = io.wait_open(remaining.min(party.poll_interval_ms)).await {
                return Ok(channel);
            }
        }

        io.sleep_ms(party.poll_interval_ms).await;
    }
}

/// Frame, post, and remember — the remembering is §6.4's skip-own.
async fn post<C: Carrier, E: ToBlob>(
    carrier: &C,
    key: &RendezvousKey,
    msg: &E,
    posted: &mut Vec<Vec<u8>>,
) -> Result<Vec<u8>, WebRtcError> {
    let blob = crate::coordination::to_blob(&msg.to_entity()?);
    carrier
        .offer(key, blob.clone())
        .await
        .map_err(|e| WebRtcError::Carrier(e.to_string()))?;
    posted.push(blob.clone());
    Ok(blob)
}

/// The three §6.5 messages, uniformly framable.
pub trait ToBlob {
    fn to_entity(&self) -> Result<Entity, SignalingError>;
}
impl ToBlob for Offer {
    fn to_entity(&self) -> Result<Entity, SignalingError> {
        Offer::to_entity(self)
    }
}
impl ToBlob for Answer {
    fn to_entity(&self) -> Result<Entity, SignalingError> {
        Answer::to_entity(self)
    }
}
impl ToBlob for IceCandidate {
    fn to_entity(&self) -> Result<Entity, SignalingError> {
        IceCandidate::to_entity(self)
    }
}

#[cfg(test)]
mod mixed_encoding {
    //! Both halves of a `pair` rendezvous MUST be the same kind of string.
    //!
    //! `pair_key` and `glare_role` both consume their ids **byte-exact** — that
    //! is deliberate and documented (no case-folding, no normalization). The
    //! consequence is that they are only correct when both ids are drawn from
    //! the same namespace, and nothing in either function can detect that they
    //! are not.
    //!
    //! `entity-browser-rust` hit this live: a peer addressed by its
    //! identity-entity hash (`ecfv1-sha256:<hex>`) rather than its 46-char
    //! base58 peer-id produced a §6.5 negotiation where **both** sides offered
    //! and **neither** shared a bucket — `included_count=0` with every visible
    //! step reporting success. These tests pin the mechanism so the failure can
    //! never be silent again, and so a future normalization change has
    //! something to break.
    use super::*;
    use crate::key::pair_key;

    fn pid_and_hash(seed: u8) -> (String, String) {
        let kp = entity_crypto::Keypair::from_seed([seed; 32]);
        (
            kp.peer_id().to_string(),
            kp.peer_identity_hash().to_string(),
        )
    }

    /// The property the whole `pair` mode rests on: exactly one side offers,
    /// and both sides land in the same bucket.
    #[test]
    fn same_encoding_is_antisymmetric_and_agrees_on_a_bucket() {
        let (a, _) = pid_and_hash(1);
        let (b, _) = pid_and_hash(2);

        let a_suppresses = pair_should_suppress_offer(&a, &b).unwrap();
        let b_suppresses = pair_should_suppress_offer(&b, &a).unwrap();
        assert_ne!(
            a_suppresses, b_suppresses,
            "exactly one side of a pair may offer"
        );
        assert_eq!(
            pair_key(&a, &b),
            pair_key(&b, &a),
            "pair_key is order-independent, so both sides derive one bucket"
        );
    }

    /// The bug, reproduced. Each peer knows itself by peer-id and its
    /// counterpart by identity hash — so neither the glare rule nor the bucket
    /// survives.
    #[test]
    fn mixed_encoding_makes_both_peers_offer_into_different_buckets() {
        let (a_pid, a_hash) = pid_and_hash(1);
        let (b_pid, b_hash) = pid_and_hash(2);

        // Neither suppresses: every base58 peer-id sorts below every
        // `ecfv1-…` string, so BOTH sides resolve to Impolite.
        assert!(!pair_should_suppress_offer(&a_pid, &b_hash).unwrap());
        assert!(!pair_should_suppress_offer(&b_pid, &a_hash).unwrap());

        // And they are not even talking about the same rendezvous.
        assert_ne!(
            pair_key(&a_pid, &b_hash),
            pair_key(&b_pid, &a_hash),
            "mixed encodings derive different buckets — the collect that \
             returns included_count=0"
        );
    }

    /// Why it is specifically the *mixing* that breaks it: hashes on both
    /// sides would rendezvous fine. The rule needs one namespace, not a
    /// particular one — which is why this cannot be fixed inside `glare_role`
    /// and has to be fixed by whoever chooses the addressing form.
    #[test]
    fn either_encoding_works_as_long_as_both_sides_agree() {
        let (_, a_hash) = pid_and_hash(1);
        let (_, b_hash) = pid_and_hash(2);

        assert_ne!(
            pair_should_suppress_offer(&a_hash, &b_hash).unwrap(),
            pair_should_suppress_offer(&b_hash, &a_hash).unwrap()
        );
        assert_eq!(pair_key(&a_hash, &b_hash), pair_key(&b_hash, &a_hash));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordination::to_blob;

    fn sid() -> SessionId {
        SessionId::parse(vec![7u8; 16]).unwrap()
    }

    // -----------------------------------------------------------------------
    // The negotiation, driven against a stub browser and a shared bucket
    // -----------------------------------------------------------------------

    use crate::punch::PunchError;
    use std::sync::Mutex;

    /// The node, reduced to what §6.5 actually uses: an append-only bucket that
    /// `collect` reads non-destructively. Shared by both peers, which is what
    /// makes skip-own load-bearing rather than decorative.
    #[derive(Default)]
    struct SharedBucket {
        blobs: Mutex<Vec<Vec<u8>>>,
    }

    struct BucketView<'a>(&'a SharedBucket);

    #[async_trait::async_trait]
    impl Carrier for BucketView<'_> {
        async fn offer(&self, _k: &RendezvousKey, blob: Vec<u8>) -> Result<(), PunchError> {
            self.0.blobs.lock().unwrap().push(blob);
            Ok(())
        }
        async fn collect(&self, _k: &RendezvousKey) -> Result<Vec<Vec<u8>>, PunchError> {
            Ok(self.0.blobs.lock().unwrap().clone())
        }
    }

    /// A browser that isn't one. Records what the choreography asked it to do,
    /// which is the only thing these tests assert on.
    #[derive(Default)]
    struct StubBrowser {
        label: String,
        pending_local: Mutex<Vec<LocalCandidate>>,
        remote_fed: Mutex<Vec<IceCandidate>>,
        remote_offer_seen: Mutex<Option<String>>,
        remote_answer_seen: Mutex<Option<String>>,
        open_after_answer: bool,
        clock: Mutex<u64>,
    }

    impl StubBrowser {
        fn new(label: &str, open_after_answer: bool) -> Self {
            Self {
                label: label.into(),
                open_after_answer,
                pending_local: Mutex::new(vec![LocalCandidate {
                    candidate: format!("candidate:1 1 udp 1 192.0.2.1 5000 typ host {label}"),
                    sdp_mid: "0".into(),
                    sdp_mline_index: 0,
                    username_fragment: None,
                }]),
                ..Default::default()
            }
        }
        fn negotiated(&self) -> bool {
            self.remote_offer_seen.lock().unwrap().is_some()
                || self.remote_answer_seen.lock().unwrap().is_some()
        }
    }

    #[async_trait::async_trait]
    impl WebRtcIo for StubBrowser {
        type Channel = String;

        async fn create_offer(&self) -> Result<String, String> {
            // A finalized local description carries the fingerprint — the whole
            // reason §6.5 says sign the local description, not createOffer().
            Ok(format!("v=0\r\na=fingerprint:sha-256 {}\r\n", self.label))
        }
        async fn create_answer(&self, remote_offer_sdp: &str) -> Result<String, String> {
            *self.remote_offer_seen.lock().unwrap() = Some(remote_offer_sdp.to_string());
            Ok(format!(
                "v=0\r\na=fingerprint:sha-256 {}-answer\r\n",
                self.label
            ))
        }
        async fn accept_answer(&self, remote_answer_sdp: &str) -> Result<(), String> {
            *self.remote_answer_seen.lock().unwrap() = Some(remote_answer_sdp.to_string());
            Ok(())
        }
        async fn drain_local_candidates(&self) -> Vec<LocalCandidate> {
            std::mem::take(&mut *self.pending_local.lock().unwrap())
        }
        async fn add_remote_candidate(&self, candidate: &IceCandidate) -> Result<(), String> {
            self.remote_fed.lock().unwrap().push(candidate.clone());
            Ok(())
        }
        async fn wait_open(&self, _timeout_ms: u64) -> Result<String, String> {
            if self.open_after_answer && self.negotiated() {
                Ok(format!("channel-{}", self.label))
            } else {
                Err("not open".into())
            }
        }
        async fn sleep_ms(&self, ms: u64) {
            *self.clock.lock().unwrap() += ms.max(1);
            // A real sleep yields; this one must too, or `join!` lets one peer
            // run to its deadline before the other ever polls the bucket.
            tokio::task::yield_now().await;
        }
        fn now_ms(&self) -> u64 {
            *self.clock.lock().unwrap()
        }
    }

    fn party(self_id: &str, peer_id: &str, trust: VerificationPolicy) -> WebRtcParty {
        WebRtcParty {
            key: crate::key::pair_key(self_id, peer_id),
            self_id: self_id.into(),
            peer_id: peer_id.into(),
            session_id: SessionId::generate(),
            poll_interval_ms: 5,
            deadline_ms: 500,
            trust,
        }
    }

    /// Both peers on one bucket, stepped by polling — the real shape, minus the
    /// browser. `lo` offers, `hi` answers, both open.
    #[tokio::test]
    async fn two_peers_negotiate_to_an_open_channel() {
        let bucket = SharedBucket::default();
        let (lo_io, hi_io) = (StubBrowser::new("lo", true), StubBrowser::new("hi", true));
        let (lo_p, hi_p) = (
            party(
                "peer-a",
                "peer-b",
                VerificationPolicy::AllowUnverifiedPreContainer,
            ),
            party(
                "peer-b",
                "peer-a",
                VerificationPolicy::AllowUnverifiedPreContainer,
            ),
        );
        assert_eq!(lo_p.key, hi_p.key, "pair mode: both derive one key");

        let (lo_c, hi_c) = (BucketView(&bucket), BucketView(&bucket));
        let (lo_res, hi_res) = tokio::join!(
            negotiate(&lo_p, &lo_c, &lo_io),
            negotiate(&hi_p, &hi_c, &hi_io),
        );

        assert_eq!(lo_res.unwrap(), "channel-lo");
        assert_eq!(hi_res.unwrap(), "channel-hi");

        // The pair optimization actually applied: hi suppressed its offer and
        // answered lo's, so exactly one offer exists and hi never saw a glare.
        assert!(
            hi_io.remote_offer_seen.lock().unwrap().is_some(),
            "hi must have consumed lo's offer"
        );
        assert!(
            lo_io.remote_answer_seen.lock().unwrap().is_some(),
            "lo must have consumed hi's answer"
        );
        assert!(
            lo_io.remote_offer_seen.lock().unwrap().is_none(),
            "lo offered; it must never consume an offer"
        );
    }

    /// The failure this bucket shape exists to expose: `collect` is
    /// non-destructive, so a peer that does not skip its own postings feeds its
    /// own ICE candidates back into its own agent — and every step reports
    /// success while the connection never forms.
    #[tokio::test]
    async fn a_peer_never_feeds_its_own_candidates_back_to_itself() {
        let bucket = SharedBucket::default();
        let (lo_io, hi_io) = (StubBrowser::new("lo", true), StubBrowser::new("hi", true));
        let (lo_p, hi_p) = (
            party(
                "peer-a",
                "peer-b",
                VerificationPolicy::AllowUnverifiedPreContainer,
            ),
            party(
                "peer-b",
                "peer-a",
                VerificationPolicy::AllowUnverifiedPreContainer,
            ),
        );
        let (lo_c, hi_c) = (BucketView(&bucket), BucketView(&bucket));
        let _ = tokio::join!(
            negotiate(&lo_p, &lo_c, &lo_io),
            negotiate(&hi_p, &hi_c, &hi_io),
        );

        for (who, io) in [("lo", &lo_io), ("hi", &hi_io)] {
            let fed_count = io.remote_fed.lock().unwrap().len();
            // Guard against the vacuous pass: "fed nothing of its own" is
            // trivially true if it fed nothing at all, and that would hide the
            // very trickle path this asserts on.
            assert!(
                fed_count > 0,
                "{who} fed no remote candidates at all — the assertion below would be vacuous"
            );
            for fed in io.remote_fed.lock().unwrap().iter() {
                assert!(
                    !fed.candidate.ends_with(who),
                    "{who} fed itself its own candidate: {}",
                    fed.candidate
                );
            }
        }
    }

    /// A conformant peer refuses rather than connecting blind. Until the §6.3
    /// container exists this is the whole of `Require` — and it failing loudly
    /// is the point: the alternative is a browser leg that looks connected and
    /// has verified nothing.
    #[tokio::test]
    async fn requiring_verification_refuses_while_no_container_exists() {
        let bucket = SharedBucket::default();
        let (lo_io, hi_io) = (StubBrowser::new("lo", true), StubBrowser::new("hi", true));
        let lo_p = party(
            "peer-a",
            "peer-b",
            VerificationPolicy::AllowUnverifiedPreContainer,
        );
        let hi_p = party("peer-b", "peer-a", VerificationPolicy::Require);

        let (lo_c, hi_c) = (BucketView(&bucket), BucketView(&bucket));
        let (_, hi_res) = tokio::join!(
            negotiate(&lo_p, &lo_c, &lo_io),
            negotiate(&hi_p, &hi_c, &hi_io),
        );
        assert!(matches!(hi_res, Err(WebRtcError::VerificationUnavailable)));
    }

    /// No counterpart ever arrives. The exchange is seconds-bounded (§6.5), so
    /// it gives up rather than polling a shared node forever.
    #[tokio::test]
    async fn an_unanswered_offer_times_out_rather_than_polling_forever() {
        let bucket = SharedBucket::default();
        let io = StubBrowser::new("lo", true);
        let p = party(
            "peer-a",
            "peer-b",
            VerificationPolicy::AllowUnverifiedPreContainer,
        );
        assert!(matches!(
            negotiate(&p, &BucketView(&bucket), &io).await,
            Err(WebRtcError::Timeout)
        ));
    }

    #[test]
    fn offer_round_trips_through_the_carrier_framing() {
        let o = Offer::new(sid(), "v=0\r\no=- 1 2 IN IP4 0.0.0.0\r\n");
        let blob = to_blob(&o.to_entity().unwrap());
        assert_eq!(classify_blob(&blob), CollectedWebRtc::Offer(o));
    }

    #[test]
    fn answer_round_trips_and_does_not_classify_as_an_offer() {
        let a = Answer::new(sid(), "v=0\r\n");
        let blob = to_blob(&a.to_entity().unwrap());
        // The two differ only by type — the field sets are identical, which is
        // exactly why classification matches on the type string.
        assert_eq!(classify_blob(&blob), CollectedWebRtc::Answer(a));
    }

    #[test]
    fn candidate_carries_the_fields_addicecandidate_requires() {
        let c = IceCandidate {
            session_id: sid(),
            candidate: "candidate:1 1 udp 2130706431 192.0.2.1 5000 typ host".into(),
            sdp_mid: "0".into(),
            sdp_mline_index: 0,
            username_fragment: Some("abc1".into()),
        };
        let blob = to_blob(&c.to_entity().unwrap());
        let CollectedWebRtc::Candidate(back) = classify_blob(&blob) else {
            panic!("expected a candidate");
        };
        assert_eq!(back, c);
        assert_eq!(back.sdp_mid, "0");
        assert_eq!(back.sdp_mline_index, 0);
    }

    #[test]
    fn an_absent_username_fragment_is_absent_not_null() {
        let c = IceCandidate {
            session_id: sid(),
            candidate: "candidate:1 1 udp 1 192.0.2.1 5000 typ host".into(),
            sdp_mid: "0".into(),
            sdp_mline_index: 0,
            username_fragment: None,
        };
        let entity = c.to_entity().unwrap();
        let map = decode_map(&entity.data).unwrap();
        assert!(
            !map.iter()
                .any(|(k, _)| matches!(k, Value::Text(t) if t == "username_fragment")),
            "an unset OPTIONAL field must not appear as a key at all"
        );
        assert_eq!(
            classify_blob(&to_blob(&entity)),
            CollectedWebRtc::Candidate(c)
        );
    }

    #[test]
    fn a_short_session_id_is_rejected_on_the_way_in() {
        // A counterpart's weak id is as dangerous as our own: it is what
        // splices two concurrent pairings together.
        assert!(SessionId::parse(vec![0u8; 15]).is_err());
        assert!(SessionId::parse(vec![0u8; 16]).is_ok());
    }

    #[test]
    fn generated_session_ids_meet_the_floor_and_differ() {
        let a = SessionId::generate();
        let b = SessionId::generate();
        assert!(a.as_bytes().len() >= SESSION_ID_MIN_BYTES);
        assert_ne!(a, b, "a fresh session_id must not repeat");
    }

    #[test]
    fn an_unrecognized_blob_is_skipped_not_fatal() {
        assert_eq!(classify_blob(b"not an entity"), CollectedWebRtc::Unknown);
        // A native coordination message sharing the bucket is simply not ours.
        let native = crate::coordination::ConnectRequest {
            initiator: "peer-a".into(),
            candidates: vec![],
            nonce: crate::coordination::Nonce(vec![1u8; 16]),
        };
        assert_eq!(
            classify_blob(&to_blob(&native.to_entity().unwrap())),
            CollectedWebRtc::Unknown
        );
    }

    #[test]
    fn the_lower_peer_id_is_impolite_and_wins_a_glare() {
        assert_eq!(glare_role("peer-a", "peer-b").unwrap(), GlareRole::Impolite);
        assert_eq!(glare_role("peer-b", "peer-a").unwrap(), GlareRole::Polite);
        // Convergent: the two peers never both think they won.
        for (x, y) in [("aa", "ab"), ("z", "za"), ("peer-1", "peer-10")] {
            assert_ne!(
                glare_role(x, y).unwrap(),
                glare_role(y, x).unwrap(),
                "{x}/{y} must resolve to opposite roles"
            );
        }
    }

    #[test]
    fn glare_uses_the_same_byte_sort_the_key_derivation_uses() {
        // §6.5 keys the rule to §3.2's existing sort rather than inventing one.
        // If these ever disagree, two peers derive one key and disagree on who
        // offers — so the property is pinned, not assumed.
        let (a, b) = ("peer-B", "peer-a"); // uppercase sorts below lowercase
        let impolite = if glare_role(a, b).unwrap() == GlareRole::Impolite {
            a
        } else {
            b
        };
        let mut sorted = [a, b];
        sorted.sort_by(|x, y| x.as_bytes().cmp(y.as_bytes()));
        assert_eq!(impolite, sorted[0], "impolite MUST be the lower-sorting id");
    }

    #[test]
    fn pair_mode_suppresses_only_the_higher_id() {
        assert!(!pair_should_suppress_offer("peer-a", "peer-b").unwrap());
        assert!(pair_should_suppress_offer("peer-b", "peer-a").unwrap());
    }

    #[test]
    fn negotiating_against_our_own_id_is_an_error_not_a_role() {
        // §6.4's skip-own MUST is the caller's, and a peer that forgets it
        // "succeeds" at meeting itself — every step reports success. Refusing
        // here is what makes that loud. `entity-core-go`'s `Impolite` returns
        // `ErrSelfNegotiation` on the same input; an earlier draft of this
        // module silently returned `Polite`, which the cross-impl read caught.
        assert!(matches!(
            glare_role("peer-a", "peer-a"),
            Err(SignalingError::SelfNegotiation)
        ));
        assert!(matches!(
            pair_should_suppress_offer("peer-a", "peer-a"),
            Err(SignalingError::SelfNegotiation)
        ));
    }

    #[test]
    fn verification_admits_a_good_signature_and_names_the_signer() {
        let kp = entity_crypto::Keypair::generate();
        let offer = Offer::new(sid(), "v=0\r\n");
        let entity = offer.to_entity().unwrap();
        let sig = kp.sign(&entity.content_hash.to_bytes());

        let signer = verify_coordination_signature(
            &entity,
            &kp.public_key_bytes(),
            entity_crypto::KEY_TYPE_ED25519,
            &sig,
        )
        .unwrap();
        // §6.5 payloads carry no peer_id — the signature IS the claim, so this
        // is the only place the counterpart's identity can come from.
        assert_eq!(signer.peer_id(), kp.peer_id().to_string());
        assert_eq!(
            offer
                .accept_remote_description(&signer, "some-other-peer")
                .unwrap(),
            "v=0\r\n"
        );
    }

    #[test]
    fn a_tampered_sdp_or_a_foreign_key_does_not_verify() {
        let kp = entity_crypto::Keypair::generate();
        let other = entity_crypto::Keypair::generate();
        let entity = Offer::new(sid(), "v=0\r\n").to_entity().unwrap();
        let sig = kp.sign(&entity.content_hash.to_bytes());

        // Someone else's key: the MITM case the §6.5 discharge exists to stop.
        assert!(matches!(
            verify_coordination_signature(
                &entity,
                &other.public_key_bytes(),
                entity_crypto::KEY_TYPE_ED25519,
                &sig
            ),
            Err(SignalingError::BadSignature)
        ));

        // Substituted SDP: the content hash moves, so the signature no longer
        // covers it — which is exactly what binds the DTLS fingerprint.
        let tampered = Offer::new(sid(), "v=0\r\nEVIL\r\n").to_entity().unwrap();
        assert!(matches!(
            verify_coordination_signature(
                &tampered,
                &kp.public_key_bytes(),
                entity_crypto::KEY_TYPE_ED25519,
                &sig
            ),
            Err(SignalingError::BadSignature)
        ));
    }

    #[test]
    fn a_verified_signer_that_is_us_is_still_refused() {
        // §6.4 skip-own, applied at the point of use rather than trusted to the
        // caller — a peer answering its own offer succeeds at every step.
        let kp = entity_crypto::Keypair::generate();
        let offer = Offer::new(sid(), "v=0\r\n");
        let entity = offer.to_entity().unwrap();
        let sig = kp.sign(&entity.content_hash.to_bytes());
        let signer = verify_coordination_signature(
            &entity,
            &kp.public_key_bytes(),
            entity_crypto::KEY_TYPE_ED25519,
            &sig,
        )
        .unwrap();

        assert!(matches!(
            offer.accept_remote_description(&signer, &kp.peer_id().to_string()),
            Err(SignalingError::SelfNegotiation)
        ));
    }

    #[test]
    fn an_ed448_signer_verifies_and_derives_an_ed448_peer_id() {
        // §6.3 spells the derivation with `key_type` hardcoded to `0x01`. Taken
        // literally this row fails — and it fails *silently*, because §6.3 skips
        // a failed check rather than raising. `entity-core-go` crosses this row
        // deliberately for that reason; it is the probe, not an accident.
        let kp = entity_crypto::Ed448Keypair::from_seed(&[0x42; 57]).unwrap();
        let offer = Offer::new(sid(), "v=0\r\n");
        let entity = offer.to_entity().unwrap();
        let sig = kp.sign(&entity.content_hash.to_bytes());

        let signer = verify_coordination_signature(
            &entity,
            &kp.public_key_bytes(),
            entity_crypto::KEY_TYPE_ED448,
            &sig,
        )
        .unwrap();
        assert_eq!(signer.peer_id(), kp.peer_id().to_string());
        // The peer-id embeds the key type, so widening the accepted set cannot
        // let an Ed448 key present itself as an Ed25519 peer.
        assert_ne!(
            signer.peer_id(),
            entity_crypto::PeerId::from_public_key_with_key_type(
                &kp.public_key_bytes()[..32],
                entity_crypto::KeyType::Ed25519,
            )
            .map(|p| p.to_string())
            .unwrap_or_default()
        );
    }

    #[test]
    fn a_mismatched_key_type_is_a_signer_fault_not_a_signature_fault() {
        // The widening is bounded: dispatching on `key_type` must not become
        // "try until something verifies." Each of these stops before the
        // signature is ever checked, and reports the half that is actually
        // wrong — `bad_signature` here would send a diagnostician after the
        // key material instead of the key type.
        let kp = entity_crypto::Ed448Keypair::from_seed(&[0x42; 57]).unwrap();
        let entity = Offer::new(sid(), "v=0\r\n").to_entity().unwrap();
        let sig = kp.sign(&entity.content_hash.to_bytes());

        // A real Ed448 key + signature, declared as Ed25519: wrong length.
        assert!(matches!(
            verify_coordination_signature(
                &entity,
                &kp.public_key_bytes(),
                entity_crypto::KEY_TYPE_ED25519,
                &sig
            ),
            Err(SignalingError::SignerMismatch)
        ));

        // A key type with no sign/verify semantics (V7 §4.7).
        assert!(matches!(
            verify_coordination_signature(
                &entity,
                &kp.public_key_bytes(),
                entity_crypto::KEY_TYPE_EXPERIMENTAL_TEST,
                &sig
            ),
            Err(SignalingError::SignerMismatch)
        ));

        // An unallocated code — including v7.67 §5's reserved `0xFF`.
        assert!(matches!(
            verify_coordination_signature(&entity, &kp.public_key_bytes(), 0xFF, &sig),
            Err(SignalingError::SignerMismatch)
        ));
    }

    #[test]
    fn an_ed448_signature_over_tampered_sdp_still_fails() {
        // The Ed448 arm gets the same negative as the Ed25519 arm — a positive
        // row alone would pass against a verifier that returns `ok` for any
        // key type it recognizes.
        let kp = entity_crypto::Ed448Keypair::from_seed(&[0x42; 57]).unwrap();
        let entity = Offer::new(sid(), "v=0\r\n").to_entity().unwrap();
        let sig = kp.sign(&entity.content_hash.to_bytes());

        let tampered = Offer::new(sid(), "v=0\r\nEVIL\r\n").to_entity().unwrap();
        assert!(matches!(
            verify_coordination_signature(
                &tampered,
                &kp.public_key_bytes(),
                entity_crypto::KEY_TYPE_ED448,
                &sig
            ),
            Err(SignalingError::BadSignature)
        ));
    }

    #[test]
    fn an_answer_for_another_session_is_not_mine() {
        let mine = sid();
        let theirs = SessionId::parse(vec![9u8; 16]).unwrap();
        let bucket = vec![CollectedWebRtc::Answer(Answer::new(theirs, "v=0\r\n"))];
        assert!(find_answer(&bucket, &mine).is_none());
    }

    #[test]
    fn candidates_are_selected_by_session_not_swept_up() {
        let mine = sid();
        let theirs = SessionId::parse(vec![9u8; 16]).unwrap();
        let mk = |s: &SessionId, line: &str| {
            CollectedWebRtc::Candidate(IceCandidate {
                session_id: s.clone(),
                candidate: line.into(),
                sdp_mid: "0".into(),
                sdp_mline_index: 0,
                username_fragment: None,
            })
        };
        let bucket = vec![mk(&mine, "a"), mk(&theirs, "b"), mk(&mine, "c")];
        let got = candidates_for(&bucket, &mine);
        assert_eq!(
            got.len(),
            2,
            "another pairing's candidates must not be mixed in"
        );
        assert_eq!(got[0].candidate, "a");
        assert_eq!(got[1].candidate, "c");
    }
}
