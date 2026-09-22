//! ⛔ **`envelope.included`'s MAP KEY must be the hash of the entity under it.**
//!
//! `verify_request` step 2b validated every included entity's **own**
//! `content_hash` against `Hash::compute(type, data)` — *"is this entity
//! self-consistent?"* — while iterating `.values()`. It did not answer *"is
//! this entity the one whose hash is the key it is filed under?"*, and every
//! authority lookup in the chain walk is `included.get(<a hash read out of a
//! capability's data>)`: `fields.granter`, `fields.grantee`,
//! `collect_authority_chain`'s resolver, and the §7a.2a presented-authority
//! bundle merge.
//!
//! The gap was found by reading step 2b's **own comment**, which names this
//! attack verbatim (*"a peer could substitute an entity for a known hash via
//! envelope manipulation … `included[h]` would index the substitute under h"*)
//! and describes the half of it the loop did not implement. Prose that sounds
//! like an invariant reads like one.
//!
//! Three sites now enforce it, and the mutations were run **per site**, because
//! a rule satisfiable at several places needs a mutation per place or the
//! extra ones are unmeasured claims:
//!
//! | mutated site | reddens |
//! |---|---|
//! | `entity_wire::decode_envelope` | `the_wire_decoder_refuses_…` |
//! | `verify_capability_chain` | `an_identity_filed_under_a_foreign_hash_…` |
//! | `verify_request` step 2b | **nothing** — defence in depth, and said so at the code |
//!
//! The two that bite redden **disjoint** rows, which is what says this file
//! measures two sites rather than one twice.

use entity_crypto::Keypair;
use entity_entity::Entity;
use entity_hash::Hash;
use entity_protocol::verify_capability_chain;
use entity_types::TYPE_SIGNATURE;

fn cap_entity(
    granter: Hash,
    grantee: Hash,
    parent: Option<Hash>,
    resource_include: &str,
) -> Entity {
    let mut fields = vec![
        (entity_ecf::text("created_at"), entity_ecf::integer(0)),
        (
            entity_ecf::text("grantee"),
            entity_ecf::Value::Bytes(grantee.to_bytes().to_vec()),
        ),
        (
            entity_ecf::text("granter"),
            entity_ecf::Value::Bytes(granter.to_bytes().to_vec()),
        ),
        (
            entity_ecf::text("grants"),
            entity_ecf::Value::Array(vec![entity_ecf::Value::Map(vec![
                (
                    entity_ecf::text("handlers"),
                    entity_ecf::Value::Map(vec![(
                        entity_ecf::text("include"),
                        entity_ecf::Value::Array(vec![entity_ecf::text("*")]),
                    )]),
                ),
                (
                    entity_ecf::text("operations"),
                    entity_ecf::Value::Map(vec![(
                        entity_ecf::text("include"),
                        entity_ecf::Value::Array(vec![entity_ecf::text("*")]),
                    )]),
                ),
                (
                    entity_ecf::text("resources"),
                    entity_ecf::Value::Map(vec![(
                        entity_ecf::text("include"),
                        entity_ecf::Value::Array(vec![entity_ecf::text(resource_include)]),
                    )]),
                ),
            ])]),
        ),
    ];
    if let Some(p) = parent {
        fields.push((
            entity_ecf::text("parent"),
            entity_ecf::Value::Bytes(p.to_bytes().to_vec()),
        ));
    }
    // ECF requires sorted keys; `to_ecf` sorts.
    Entity::new(
        entity_types::TYPE_CAP_TOKEN,
        entity_ecf::to_ecf(&entity_ecf::Value::Map(fields)),
    )
    .unwrap()
}

/// A `system/signature` over `target`, produced by `signing_kp`, but CLAIMING
/// `claimed_signer` as the signer identity hash.
///
/// For an honest signature `claimed_signer` is the signer's own identity hash.
/// The probe below passes a hash that is *not* the signing key's.
fn signature_entity(signing_kp: &Keypair, target: Hash, claimed_signer: Hash) -> Entity {
    let sig_bytes = signing_kp.sign(&target.to_bytes());
    Entity::new(
        TYPE_SIGNATURE,
        entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("algorithm"), entity_ecf::text("ed25519")),
            (
                entity_ecf::text("signature"),
                entity_ecf::Value::Bytes(sig_bytes.to_vec()),
            ),
            (
                entity_ecf::text("signer"),
                entity_ecf::Value::Bytes(claimed_signer.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("target"),
                entity_ecf::Value::Bytes(target.to_bytes().to_vec()),
            ),
        ])),
    )
    .unwrap()
}

/// ⛔ **The forgery this probe drives, and why the map key is the whole of it.**
///
/// V (the local peer) legitimately issued `P` to B. That capability, and B's
/// identity **hash** in its `grantee` field, travel in every envelope B
/// presents — so an eavesdropper A holds both, and holds neither B's key nor
/// B's identity entity.
///
/// A then mints `L` — `parent: P`, `granter: hash_B`, `grantee: hash_A`, grants
/// ⊆ P — signs it with **A's own key**, and files **A's own `system/peer`
/// entity under the key `hash_B`** in `included`.
///
/// Every per-entity check passes: A's entity is self-consistent, so step 2b's
/// `validate()` is green; `sig.signer == L.granter == hash_B`; the chain walk
/// resolves `hash_B` to *something* of type `system/peer`; and
/// `verify_peer_data_sig` verifies A's signature against **A's** public key,
/// because that is the key it just looked up under B's hash. The root link is
/// genuine and verifies against V. Attenuation holds because A wrote L ⊆ P.
///
/// The only thing that can refuse it is a check that the entity at key `K`
/// hashes to `K`.
///
/// **Measured against the pre-fix tree: `verify_capability_chain` returned
/// `Ok(())`.** Against the fixed tree it is `HashMismatch`. The control below
/// is the same chain with the identity filed correctly — it MUST verify, or
/// this row is passed by a verifier that refuses everything.
#[test]
fn an_identity_filed_under_a_foreign_hash_cannot_sign_as_that_identity() {
    let victim_kp = Keypair::from_seed([1u8; 32]); // V — the local peer
    let attacker_kp = Keypair::from_seed([3u8; 32]); // A — holds no victim key

    let v_ident = victim_kp.peer_entity().unwrap();
    let v_hash = v_ident.content_hash;
    let a_ident = attacker_kp.peer_entity().unwrap();
    let a_hash = a_ident.content_hash;

    // B's identity HASH is all the attacker needs, and it is public: it is the
    // `grantee` field of a capability B presents. B's key and B's identity
    // entity never appear anywhere in this test.
    let b_hash = Hash::compute("system/peer", b"B's identity, whose bytes A never sees");

    // --- the genuine root: V -> B, signed by V ---
    let parent = cap_entity(v_hash, b_hash, None, "/*/*");
    let parent_hash = parent.content_hash;
    let parent_sig = signature_entity(&victim_kp, parent_hash, v_hash);

    // --- the forged leaf: claims B -> A, actually signed by A ---
    let leaf = cap_entity(b_hash, a_hash, Some(parent_hash), "/*/*");
    let leaf_hash = leaf.content_hash;
    let leaf_sig = signature_entity(&attacker_kp, leaf_hash, b_hash);

    let mut included = std::collections::BTreeMap::new();
    included.insert(v_hash, v_ident);
    included.insert(a_hash, a_ident.clone());
    // ⛔ THE FORGERY: A's identity entity, filed under B's hash.
    included.insert(b_hash, a_ident);
    included.insert(parent_hash, parent);
    included.insert(leaf_hash, leaf);
    included.insert(parent_sig.content_hash, parent_sig);
    included.insert(leaf_sig.content_hash, leaf_sig);

    let result = verify_capability_chain(&leaf_hash, &included, victim_kp.peer_id().as_str());
    result.expect_err(
        "CAPABILITY FORGERY: a chain verified in which the attacker's own identity entity, \
         filed under the victim's identity hash, was used to verify a delegation the victim \
         never signed — an observer of any chain can mint a leaf off it without the \
         grantee's key",
    );
}

/// CONTROL — the same shape with the attacker's identity filed under **its own**
/// hash, so B is a real peer and the leaf is a real delegation B signed.
///
/// Without this row the one above is passed by a verifier that refuses every
/// chain, which is one edit away from the fix and is the more likely accident:
/// the added condition compares two `Hash`es, and getting the comparison
/// backwards refuses every well-formed envelope in the system.
#[test]
fn a_correctly_filed_delegation_chain_still_verifies() {
    let victim_kp = Keypair::from_seed([1u8; 32]); // V — the local peer
    let b_kp = Keypair::from_seed([2u8; 32]); // B — a real delegate
    let c_kp = Keypair::from_seed([3u8; 32]); // C — B's delegate

    let v_ident = victim_kp.peer_entity().unwrap();
    let v_hash = v_ident.content_hash;
    let b_ident = b_kp.peer_entity().unwrap();
    let b_hash = b_ident.content_hash;
    let c_ident = c_kp.peer_entity().unwrap();
    let c_hash = c_ident.content_hash;

    let parent = cap_entity(v_hash, b_hash, None, "/*/*");
    let parent_hash = parent.content_hash;
    let parent_sig = signature_entity(&victim_kp, parent_hash, v_hash);

    let leaf = cap_entity(b_hash, c_hash, Some(parent_hash), "/*/*");
    let leaf_hash = leaf.content_hash;
    let leaf_sig = signature_entity(&b_kp, leaf_hash, b_hash);

    let mut included = std::collections::BTreeMap::new();
    included.insert(v_hash, v_ident);
    included.insert(b_hash, b_ident);
    included.insert(c_hash, c_ident);
    included.insert(parent_hash, parent);
    included.insert(leaf_hash, leaf);
    included.insert(parent_sig.content_hash, parent_sig);
    included.insert(leaf_sig.content_hash, leaf_sig);

    verify_capability_chain(&leaf_hash, &included, victim_kp.peer_id().as_str()).expect(
        "CONTROL: a genuine V->B->C chain, every entity filed under its own hash, MUST verify \
         — if this fails the key check is inverted and every envelope in the system is refused",
    );
}

/// The same invariant at the **wire boundary**, which is the site
/// `verify_capability_chain` cannot speak for: `decode_envelope` is where an
/// `included` map is constructed from received bytes, and the §7a.2a
/// presented-authority path merges that map into its own chain bundle without
/// going through `verify_request` step 2b.
///
/// Driven by encoding a well-formed envelope and then rewriting one included
/// key in the byte stream — the attacker's actual primitive, rather than a
/// hand-built map that assumes the decoder's shape.
#[test]
fn the_wire_decoder_refuses_an_included_entity_filed_under_a_foreign_hash() {
    let kp = Keypair::from_seed([7u8; 32]);
    let root = Entity::new(
        "system/validate/root",
        entity_ecf::to_ecf(&entity_ecf::text("r")),
    )
    .unwrap();
    let ident = kp.peer_entity().unwrap();
    let ident_hash = ident.content_hash;

    let mut honest = std::collections::BTreeMap::new();
    honest.insert(ident_hash, ident.clone());
    let bytes = entity_wire::encode_envelope(&entity_entity::Envelope::with_included(
        root.clone(),
        honest,
    ));
    // CONTROL FIRST — the honest bytes decode, so the refusal below is
    // attributable to the key edit and not to the fixture.
    entity_wire::decode_envelope(&bytes).expect("CONTROL: a correctly keyed envelope decodes");

    // The forgery: file the same entity under a hash that is not its own. The
    // key is a fixed-width bstr, so swapping it is a byte substitution that
    // leaves every length prefix in the stream intact.
    let decoy = Hash::compute("system/peer", b"some other identity's hash");
    let key_bytes = ident_hash.to_bytes();
    let pos = bytes
        .windows(key_bytes.len())
        .position(|w| w == key_bytes.as_slice())
        .expect("fixture: the included key must appear verbatim in the encoding");
    let mut forged = bytes.clone();
    forged[pos..pos + key_bytes.len()].copy_from_slice(&decoy.to_bytes());

    let err = entity_wire::decode_envelope(&forged)
        .expect_err("the decoder admitted an included entity filed under a foreign hash");
    assert!(
        format!("{err}").contains("filed under a hash that is not its own"),
        "expected the mis-keyed-entry refusal, got: {err}"
    );
}
