//! `system/signaling/signed-blob` — the §6.3 **self-contained container**
//! (`PROPOSAL-EXTENSION-SIGNALING-COORDINATION-ENVELOPE`, building against the
//! cohort-reviewed draft; folds when Rust and Go cross-verify a vector).
//!
//! # The gap this closes
//!
//! §6.2 says the blob is the canonical entity encoding `{type, data,
//! content_hash}`. §6.3 says the blob is *self-contained* — the entity **plus a
//! detached signature carrying the signer's `public_key`**. Both cannot be true
//! of the same bytes: an entity encoding has no signature field, and §12
//! registered no envelope. So every coordination message this crate has shipped
//! so far is **unsigned**, and [`webrtc::verify_coordination_signature`] had
//! nothing on the wire it could be handed.
//!
//! `system/signaling/signed-blob` is that container:
//!
//! ```text
//! signed-blob := {
//!   entity:     bytes   ; the §6.2 canonical encoding of the coordination
//!                       ; entity, embedded VERBATIM
//!   public_key: bytes   ; the raw key the signer commits to
//!   signature:  bytes   ; detached, over `signing_input` below
//!   signer:     text    ; the signer's canonical peer-id (§1.5 multikey)
//! }
//! ```
//!
//! # Three things here are easy to get subtly wrong
//!
//! **1. The container is itself an entity.** What the carrier stores is
//! `encode_entity({type: "system/signaling/signed-blob", data, content_hash})`,
//! not a bare CBOR map. That is deliberate and it preserves the §3.1 framing
//! rule already documented in [`crate::coordination::to_blob`]: a bucket holds a
//! **mixed set** the node never interprets, so the reader has nothing but the
//! type string to dispatch on. A bare map would also make a signed blob
//! indistinguishable from a legacy unsigned one during migration.
//!
//! **2. The inner entity is embedded verbatim, never re-encoded.** The signature
//! covers the inner `content_hash`, so a decode + re-encode round trip that
//! perturbs a single byte silently invalidates it (§6.2 / §1.8 byte
//! preservation). [`seal`] embeds [`entity_wire::encode_entity`] output as a
//! CBOR bstr and [`parse`] hands the same bytes back untouched.
//!
//! **3. `signer` is verified-then-used, never trusted as given.** It is a wire
//! field and therefore forgeable. [`open`] derives the id canonically from
//! `(public_key, key_type)` and requires the wire `signer` to match **in full**;
//! only the derived value flows onward. A verifier that instead dispatched on
//! the envelope's own `hash_type` would accept **two** distinct `signer` values
//! for one key (`0x01‖0x00‖pk` and `0x01‖0x01‖SHA-256(pk)`), letting a peer
//! choose its own identity per message. Every §6.5 decision is a sort over that
//! id — [`crate::key::pair_key`], the offerer rule, §6.4's skip-own — so a
//! chosen id is a chosen glare role and a split rendezvous bucket.
//!
//! # Bucket binding — and why the key is *not* on the wire
//!
//! The signature covers the **rendezvous key**, so a blob lifted from one bucket
//! and replayed into another fails verification. Without it a valid blob replays
//! anywhere and verifies: not a channel hijack (the SDP fingerprint still binds
//! DTLS) but enough to point unsolicited connection attempts at a signer that
//! never addressed the victim.
//!
//! The key is **covered but not carried**. A verifier always knows which bucket
//! it collected from — it passed that key to `collect` — so putting it in the
//! envelope would add a second, forgeable copy that must be checked against the
//! real one anyway. That is the same trap `signer` sets, and the same answer:
//! bind against locally-known truth, don't re-read the claim. It also keeps the
//! §6.5 message shapes untouched, so the already-green coordination crossing
//! does not have to be re-run.
//!
//! Mechanism routed to the cohort; the conformance vectors carry the key
//! explicitly so the crossing is decidable either way.

use entity_crypto::{IdentityKeypair, KeyType, PeerId};
use entity_ecf::{bytes, text, to_ecf, Value};
use entity_entity::Entity;

use crate::coordination::{decode_map, field_bytes, field_text};
use crate::core::{RendezvousKey, RENDEZVOUS_KEY_LEN};
use crate::webrtc::VerifiedSigner;
use crate::SignalingError;

/// The §12 type of the container (registered by the envelope proposal).
pub const TYPE_SIGNED_BLOB: &str = "system/signaling/signed-blob";

/// Domain separation for the signed material. Versioned so a future change to
/// what is covered is a **new domain** rather than a silent reinterpretation of
/// the same bytes — the convention [`crate::key`] already uses.
pub const SIGNING_DOMAIN: &str = "entity:sigblob:v1";

/// `SEP` = ASCII US, matching [`crate::key::SEP`].
pub const SEP: u8 = 0x1F;

/// The exact bytes a coordination signature covers.
///
/// ```text
/// signing_input = "entity:sigblob:v1" ‖ 0x1F ‖ rendezvous_key(33) ‖ content_hash(33)
/// ```
///
/// **The content hash is the 33-byte wire form** (`content_hash_format ‖
/// digest`), not the bare 32-byte digest — the same thing every other signature
/// in this tree binds, so the format byte always travels with it. This is the
/// 66-vs-64-hex trap, and it is spelled here rather than left to convention
/// because a stranger's verifier has nothing else to derive it from.
///
/// Both components are fixed-length, so the concatenation is unambiguous
/// without length prefixes; the domain tag additionally makes a bound signature
/// unusable as an unbound one and vice versa.
pub fn signing_input(key: &RendezvousKey, content_hash: &[u8]) -> Vec<u8> {
    let mut input =
        Vec::with_capacity(SIGNING_DOMAIN.len() + 1 + RENDEZVOUS_KEY_LEN + content_hash.len());
    input.extend_from_slice(SIGNING_DOMAIN.as_bytes());
    input.push(SEP);
    input.extend_from_slice(key.as_bytes());
    input.extend_from_slice(content_hash);
    input
}

/// A parsed container, **not yet verified**.
///
/// Deliberately inert: holding one proves only that four fields decoded. The
/// SDP accessors in [`crate::webrtc`] require a [`VerifiedSigner`], which only
/// [`open`] can mint, so a caller cannot skip verification by parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedBlob {
    /// The §6.2 canonical encoding of the inner coordination entity, verbatim.
    pub entity: Vec<u8>,
    /// The signer's claimed canonical peer-id — **forgeable until [`open`]**.
    pub signer: String,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl SignedBlob {
    /// Encode to the bytes the carrier stores.
    pub fn to_blob(&self) -> Result<Vec<u8>, SignalingError> {
        let data = to_ecf(&Value::Map(vec![
            (text("entity"), bytes(self.entity.clone())),
            (text("public_key"), bytes(self.public_key.clone())),
            (text("signature"), bytes(self.signature.clone())),
            (text("signer"), text(&self.signer)),
        ]));
        let entity = Entity::new(TYPE_SIGNED_BLOB, data)
            .map_err(|e| SignalingError::Encode(e.to_string()))?;
        Ok(entity_wire::encode_entity(&entity))
    }
}

/// Sign a coordination entity into a container, bound to the bucket it is
/// being deposited in.
///
/// The `key` is the rendezvous key this blob will be `offer`ed under. Signing
/// under one key and depositing under another produces a blob that every
/// conforming verifier skips.
pub fn seal(
    inner: &Entity,
    key: &RendezvousKey,
    keypair: &IdentityKeypair,
) -> Result<Vec<u8>, SignalingError> {
    let message = signing_input(key, &inner.content_hash.to_bytes());
    SignedBlob {
        entity: entity_wire::encode_entity(inner),
        signer: keypair.peer_id().to_string(),
        public_key: keypair.public_key_bytes(),
        signature: keypair.sign(&message),
    }
    .to_blob()
}

/// Decode a container without verifying it.
///
/// Returns [`SignalingError::Decode`] for anything that is not a well-formed
/// `signed-blob`, **including a blob of some other type** — which callers treat
/// as §6.4's undecodable-blob skip, not an error.
pub fn parse(blob: &[u8]) -> Result<SignedBlob, SignalingError> {
    let entity = entity_wire::decode_entity(blob)
        .map_err(|e| SignalingError::Decode(format!("signed-blob does not decode: {e}")))?;
    if entity.entity_type != TYPE_SIGNED_BLOB {
        return Err(SignalingError::Decode(format!(
            "not a signed-blob: {}",
            entity.entity_type
        )));
    }
    let map = decode_map(&entity.data)?;
    Ok(SignedBlob {
        entity: field_bytes(&map, "entity")?,
        signer: field_text(&map, "signer")?,
        public_key: field_bytes(&map, "public_key")?,
        signature: field_bytes(&map, "signature")?,
    })
}

/// Parse **and** verify — the §6.3 procedure, and the only way to obtain a
/// [`VerifiedSigner`] from the wire.
///
/// `key` is the rendezvous key this blob was collected under; it is what the
/// signature is bound to.
///
/// The steps, in the order the proposal numbers them:
///
/// 1. **Parse `signer`** as a §1.5 multikey → `key_type`. The `hash_type` it
///    carries is *not* an input to verification; step 2 covers it.
/// 2. **Bind key to id** — derive the canonical id from `(public_key,
///    key_type)` and require `signer` to equal it in full →
///    [`SignalingError::UnusableKey`].
/// 3. *(caller)* where the inner entity names its own signer (§6.1's
///    `initiator`/`responder`), compare it — [`open_claimed`].
/// 4. **Verify the signature** over [`signing_input`] →
///    [`SignalingError::BadSignature`].
///
/// **`key_type` is parametric.** Ed25519 is the MUST-implement floor, not the
/// ceiling: a well-formed but unsupported key type yields `UnusableKey` and MUST
/// be **skipped** (ADR-0002 MUST-ignore), never hardcode-rejected. That exact
/// hardcode was a real defect here — a cross-impl vector caught this crate
/// locking out an Ed448 identity it mints itself.
///
/// Every failure is skipped exactly as an undecodable blob (§6.4) and MUST NOT
/// become visible on the wire. The distinct error names exist for local
/// diagnostics and conformance vectors — the skip **should** be logged with the
/// label and the offending `key_type`, because silence inside the
/// implementation is how the Ed448 hardcode survived.
pub fn open(blob: &[u8], key: &RendezvousKey) -> Result<(VerifiedSigner, Entity), SignalingError> {
    let parsed = parse(blob)?;
    let inner = entity_wire::decode_entity(&parsed.entity)
        .map_err(|e| SignalingError::Decode(format!("inner entity does not decode: {e}")))?;

    // Step 1 — the claimed id selects the algorithm, and nothing else yet.
    let claimed = PeerId::from(parsed.signer.clone());
    let decoded = claimed.decode().map_err(|_| SignalingError::UnusableKey)?;
    let key_type = KeyType::from_byte(decoded.key_type).map_err(|_| SignalingError::UnusableKey)?;

    // Step 2 — derive canonically and require a full match. This is what makes
    // the wire `signer` unforgeable, and it is *also* the hash_type check: the
    // derived id embeds the canonical hash_type for this key type, so a
    // well-formed but non-canonical one simply fails to compare equal.
    let derived = PeerId::from_public_key_with_key_type(&parsed.public_key, key_type)
        .map_err(|_| SignalingError::UnusableKey)?;
    if derived.as_str() != parsed.signer {
        return Err(SignalingError::UnusableKey);
    }

    // Step 4 — over the bucket-bound input, dispatching on key_type.
    let message = signing_input(key, &inner.content_hash.to_bytes());
    entity_crypto::verify_for_key_type(key_type, &parsed.public_key, &message, &parsed.signature)
        .map_err(|e| match e {
        entity_crypto::CryptoError::InvalidPublicKey
        | entity_crypto::CryptoError::UnsupportedKeyType(_) => SignalingError::UnusableKey,
        _ => SignalingError::BadSignature,
    })?;

    Ok((VerifiedSigner::new(derived.to_string()), inner))
}

/// [`open`] plus step 3 — for the §6.1 payloads that name their own signer.
///
/// §6.5's offer/answer/candidate carry no peer-id, so the derived id *is* the
/// claim and [`open`] is the whole check. §6.1's `connect-request` /
/// `connect-response` carry `initiator` / `responder`, and a valid signature
/// under a **false claim** passes every other step — the bytes really were
/// signed by the key presented. Only this comparison catches it.
pub fn open_claimed(
    blob: &[u8],
    key: &RendezvousKey,
    claimed_peer_id: &str,
) -> Result<(VerifiedSigner, Entity), SignalingError> {
    let (signer, inner) = open(blob, key)?;
    if signer.peer_id() != claimed_peer_id {
        return Err(SignalingError::SignerMismatch);
    }
    Ok((signer, inner))
}

#[cfg(test)]
mod tests {
    //! Every negative here is a **silent** failure in production — §6.3 skips a
    //! bad blob rather than reporting it — so these assertions are the only
    //! place the distinctions are ever visible.
    use super::*;
    use crate::key::pair_key;
    use crate::webrtc::{Offer, SessionId};

    fn ed25519(seed: u8) -> IdentityKeypair {
        IdentityKeypair::Ed25519(entity_crypto::Keypair::from_seed([seed; 32]))
    }

    fn offer_entity(sdp: &str) -> Entity {
        Offer::new(
            SessionId::parse(vec![0x40; 16]).expect("16 bytes clears the floor"),
            sdp,
        )
        .to_entity()
        .expect("offer encodes")
    }

    fn bucket(a: u8, b: u8) -> RendezvousKey {
        pair_key(
            &ed25519(a).peer_id().to_string(),
            &ed25519(b).peer_id().to_string(),
        )
    }

    /// The whole point: a stranger verifies with **no key lookup and no prior
    /// contact**, and gets the inner entity back byte-identical.
    #[test]
    fn seal_then_open_recovers_the_signer_and_the_exact_inner_bytes() {
        let kp = ed25519(0x11);
        let key = bucket(0x11, 0x22);
        let inner = offer_entity("v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\n");

        let blob = seal(&inner, &key, &kp).expect("seals");
        let (signer, recovered) = open(&blob, &key).expect("opens");

        assert_eq!(signer.peer_id(), kp.peer_id().to_string());
        // Byte preservation, not field equality: a decode+re-encode that moved
        // one byte would still compare equal field-wise and would still have
        // invalidated the signature.
        assert_eq!(
            entity_wire::encode_entity(&recovered),
            entity_wire::encode_entity(&inner),
            "the inner entity must survive the container verbatim (§6.2)"
        );
        assert_eq!(recovered.content_hash, inner.content_hash);
    }

    /// `key_type` is parametric — Ed25519 is the floor, not the ceiling. This
    /// is the row a hardcoded `0x01` fails while every Ed25519 row passes.
    #[test]
    fn an_ed448_signer_verifies_without_being_special_cased() {
        let kp = IdentityKeypair::Ed448(
            entity_crypto::Ed448Keypair::from_seed(&[0x42; 57]).expect("seeds"),
        );
        let key = bucket(0x11, 0x22);
        let inner = offer_entity("v=0\r\no=- 2 2 IN IP4 0.0.0.0\r\n");

        let blob = seal(&inner, &key, &kp).expect("seals");
        let (signer, _) = open(&blob, &key).expect("an Ed448 signer is a valid signer");
        assert_eq!(signer.peer_id(), kp.peer_id().to_string());
    }

    /// Bucket binding, stated as the attack it prevents: a blob lifted out of
    /// one bucket and replayed into another MUST NOT verify there.
    #[test]
    fn a_blob_replayed_into_a_different_bucket_does_not_verify() {
        let kp = ed25519(0x11);
        let signed_under = bucket(0x11, 0x22);
        let replayed_into = bucket(0x11, 0x33);
        assert_ne!(signed_under.as_bytes(), replayed_into.as_bytes());

        let blob = seal(&offer_entity("v=0\r\ns=-\r\n"), &signed_under, &kp).expect("seals");

        assert!(
            open(&blob, &signed_under).is_ok(),
            "sound in its own bucket"
        );
        assert!(
            matches!(
                open(&blob, &replayed_into),
                Err(SignalingError::BadSignature)
            ),
            "a replay into another bucket must fail — otherwise a signer can be \
             made the target of unsolicited connection attempts anywhere"
        );
    }

    /// `signer` is a wire field, so it is forgeable. Step 2 is what makes
    /// forging it useless.
    #[test]
    fn a_swapped_signer_field_does_not_survive_canonical_derivation() {
        let kp = ed25519(0x11);
        let other = ed25519(0x22);
        let key = bucket(0x11, 0x22);

        let blob = seal(&offer_entity("v=0\r\ns=-\r\n"), &key, &kp).expect("seals");
        let mut forged = parse(&blob).expect("parses");
        forged.signer = other.peer_id().to_string();

        assert!(
            matches!(
                open(&forged.to_blob().unwrap(), &key),
                Err(SignalingError::UnusableKey)
            ),
            "claiming someone else's id while presenting your own key must fail"
        );
    }

    /// The subtle one. A *well-formed* peer-id for the same key, in the legacy
    /// SHA-256 form — accepted on the wire elsewhere (§5 carve-out), but **not**
    /// canonical for Ed25519. Admitting it would give one key two valid ids, and
    /// every §6.5 decision is a sort over that id: a chosen id is a chosen glare
    /// role and a split bucket.
    #[test]
    fn a_non_canonical_hash_type_is_unusable_even_though_it_names_the_right_key() {
        let kp = entity_crypto::Keypair::from_seed([0x11; 32]);
        let identity = IdentityKeypair::Ed25519(entity_crypto::Keypair::from_seed([0x11; 32]));
        let key = bucket(0x11, 0x22);

        let blob = seal(&offer_entity("v=0\r\ns=-\r\n"), &key, &identity).expect("seals");
        let mut relabelled = parse(&blob).expect("parses");
        let legacy = entity_crypto::legacy_sha256_peer_id_fixture(&kp.public_key_bytes());
        assert_ne!(
            legacy.to_string(),
            relabelled.signer,
            "the two forms differ"
        );
        relabelled.signer = legacy.to_string();

        assert!(
            matches!(
                open(&relabelled.to_blob().unwrap(), &key),
                Err(SignalingError::UnusableKey)
            ),
            "a second valid-looking id for one key is exactly what step 2 forbids"
        );
    }

    /// Substituted SDP moves the content hash out from under the signature —
    /// which is what actually binds the DTLS fingerprint.
    #[test]
    fn tampering_with_the_inner_entity_breaks_the_signature() {
        let kp = ed25519(0x11);
        let key = bucket(0x11, 0x22);

        let blob = seal(&offer_entity("a=fingerprint:sha-256 12:34\r\n"), &key, &kp).unwrap();
        let mut tampered = parse(&blob).expect("parses");
        tampered.entity =
            entity_wire::encode_entity(&offer_entity("a=fingerprint:sha-256 DE:AD\r\n"));

        assert!(matches!(
            open(&tampered.to_blob().unwrap(), &key),
            Err(SignalingError::BadSignature)
        ));
    }

    /// ADR-0002 MUST-ignore: a well-formed key type this build cannot verify is
    /// **skipped**, and is reported as `unusable_key` — never as
    /// `signer_mismatch`. The peer is not lying; we simply cannot check it.
    /// A hardcoded reject here is the Ed448 defect, reproduced.
    #[test]
    fn a_well_formed_unsupported_key_type_is_unusable_not_a_false_claim() {
        let pk = vec![0x07u8; 64]; // 0xFE's public-key length per v7.66 §4.2
        let signer = PeerId::from_public_key_with_key_type(&pk, KeyType::ExperimentalTest)
            .expect("0xFE derives a well-formed id");
        let key = bucket(0x11, 0x22);
        let inner = offer_entity("v=0\r\ns=-\r\n");

        let blob = SignedBlob {
            entity: entity_wire::encode_entity(&inner),
            signer: signer.to_string(),
            public_key: pk,
            signature: vec![0x00; 64],
        }
        .to_blob()
        .unwrap();

        assert!(
            matches!(open(&blob, &key), Err(SignalingError::UnusableKey)),
            "an unsupported key_type must be skipped, not accused of lying"
        );
    }

    /// The §6.1 path. Only the claim comparison catches a **valid** signature
    /// under a **false** claim, and it is a different failure from an unusable
    /// key — the two names must not collapse.
    #[test]
    fn open_claimed_separates_a_false_claim_from_an_unusable_key() {
        let kp = ed25519(0x11);
        let other = ed25519(0x22);
        let key = bucket(0x11, 0x22);
        let blob = seal(&offer_entity("v=0\r\ns=-\r\n"), &key, &kp).expect("seals");

        assert!(open_claimed(&blob, &key, &kp.peer_id().to_string()).is_ok());
        assert!(matches!(
            open_claimed(&blob, &key, &other.peer_id().to_string()),
            Err(SignalingError::SignerMismatch)
        ));
    }

    /// A bucket is a mixed set the node never interprets, so a blob of some
    /// other type is a normal occurrence and a skip, not an error.
    #[test]
    fn a_blob_that_is_not_a_container_is_a_decode_skip() {
        let key = bucket(0x11, 0x22);
        let bare = entity_wire::encode_entity(&offer_entity("v=0\r\ns=-\r\n"));
        assert!(matches!(open(&bare, &key), Err(SignalingError::Decode(_))));
    }

    /// The 33-vs-32 trap, pinned where a stranger can see it.
    #[test]
    fn the_signed_material_is_the_key_then_the_33_byte_content_hash() {
        let key = bucket(0x11, 0x22);
        let inner = offer_entity("v=0\r\ns=-\r\n");
        let input = signing_input(&key, &inner.content_hash.to_bytes());

        assert_eq!(input.len(), SIGNING_DOMAIN.len() + 1 + 33 + 33);
        assert!(input.starts_with(SIGNING_DOMAIN.as_bytes()));
        assert_eq!(input[SIGNING_DOMAIN.len()], SEP);
        assert_eq!(&input[SIGNING_DOMAIN.len() + 1..][..33], key.as_bytes());
        assert_eq!(
            &input[SIGNING_DOMAIN.len() + 1 + 33..],
            &inner.content_hash.to_bytes()[..],
            "the format byte travels with the digest — 33 bytes, not 32"
        );
    }
}
