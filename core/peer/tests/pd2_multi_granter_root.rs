//! §1.4 *"Root granter under multi-signature"* `[MUST]` — 0.8.2.19 / E3.
//!
//! *"The chain's ROOT `granter` resolves to the target peer's identity"* was
//! undefined for a §3.6 `multi-granter`, and M3 makes multi-signature
//! **root-only**, so a K-of-N-rooted credential is exactly where it lands.
//! 0.8.2.19 rules it **fail-closed**: such a credential satisfies the
//! root-granter check only when the target's identity **is** the multi-granter,
//! and a root whose signer set merely *includes* the target does not.
//!
//! **This file used to say the wire scaffold could not express the shape under
//! test. That was true when written, and it is why the sentence had to go.**
//! GUIDE-CONFORMANCE §7a.2a's carrier was `reentry_capability` /
//! `reentry_granter` / `reentry_cap_signature` — exactly three fields, one
//! granter identity and one signature — and a K-of-2 root needs two of each. So
//! the deferral was accurate, and it was also a standing instruction not to try:
//! every seat drove E3 in-process for the whole arc, and `0.8.2.19` made the
//! carriers **plural** for precisely this reason (*"the carrier makes the input
//! expressible, and only the paired arms make it measurable"*).
//!
//! **The wire attestation now exists** —
//! `conformance_reentry_7a2a::a_multi_sig_root_credential_is_refused_over_the_
//! wire`, with its §2.4b single-sig control beside it. This pair is kept as the
//! **cheap floor** under it, not as a substitute: it drives `make_execute_fn`
//! directly, which is not a weaker check of the gate itself — the §1.4 gate runs
//! **before the dial**, so refusal and non-refusal are two different observable
//! outcomes with no peer on the other end (a 403 we minted, versus a transport
//! error from the connection attempt the gate let through) — but it says nothing
//! about the scaffold, the params decode, or the cohort.
//!
//! **The trap E3 closes, and it is why "M6 already passes" is the wrong
//! reading.** `presented_credential_relaxes_peers` passes `target_peer` where
//! `verify_capability_chain` expects `local_peer_id`, which is correct and
//! load-bearing for a single-sig root (§5.5 root-trust becomes *"the root's
//! granter is the target"*). On a **multi-sig** root that same argument lands
//! in M6 instead, which asks whether the frame peer is *among* the signers and
//! signed — i.e. *"the target is one constituent of the group."* So the chain
//! walk **accepts** this credential and a reader who stops there concludes the
//! case is handled. It is not the same question: a K-of-N root is a **group's**
//! authority, and treating a constituent as the granter lets any single
//! signer's target confer the whole group's grant.

use entity_capability::{
    CapabilityToken, GrantEntry, Granter, IdScope, MultiGranter, PathScope, ResourceTarget,
};
use entity_crypto::Keypair;
use entity_entity::Entity;
use entity_peer::PeerBuilder;

/// Detached §5.5 signature over `target`, by `kp`.
fn sign(kp: &Keypair, signer: entity_hash::Hash, target: entity_hash::Hash) -> Entity {
    let sig_bytes = kp.sign(&target.to_bytes());
    Entity::new(
        entity_entity::TYPE_SIGNATURE,
        entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("algorithm"),
                entity_ecf::text(kp.key_type().label()),
            ),
            (
                entity_ecf::text("signature"),
                entity_ecf::Value::Bytes(sig_bytes.to_vec()),
            ),
            (
                entity_ecf::text("signer"),
                entity_ecf::Value::Bytes(signer.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("target"),
                entity_ecf::Value::Bytes(target.to_bytes().to_vec()),
            ),
        ])),
    )
    .expect("signature entity")
}

/// One grant entry that covers the sub-dispatch under test on all four of the
/// credential's own dimensions, so (d) coverage is never what refuses.
fn covers_echo() -> Vec<GrantEntry> {
    vec![GrantEntry {
        handlers: PathScope::new(vec!["system/validate/echo".into()]),
        resources: PathScope::new(vec!["*".into()]),
        operations: IdScope::new(vec!["echo".into()]),
        peers: Some(IdScope::all()),
        constraints: None,
        allowances: None,
    }]
}

/// Which root shape the presented credential carries — the only axis.
enum Root {
    /// Single-sig, granter = the target peer. Ordinary presented authority.
    SingleSigTarget,
    /// K-of-2 multi-granter whose signer set **includes** the target (and who
    /// both signed, so M4 threshold and M6 constituency both pass).
    MultiGranterIncludingTarget,
}

/// Returns `Ok(status)` when the gate refused before the dial, `Err(())` when
/// it let the dispatch through to the connection attempt.
async fn drive(root: Root) -> Result<(u32, String), ()> {
    let b = PeerBuilder::new()
        .keypair(Keypair::from_seed([0xb0u8; 32]))
        .build()
        .expect("local peer builds");
    let shared = b.shared();
    let b_identity = shared.identity_hash;
    let b_peer_entity = shared
        .content_store
        .get(&b_identity)
        .expect("B holds its own identity entity");

    // A — the target. Never runs; only its identity and signatures matter.
    let a_kp = Keypair::from_seed([0xa1u8; 32]);
    let a_pid = a_kp.peer_id().to_string();
    let a_peer_entity = a_kp.peer_entity().expect("A identity entity");
    let a_identity = a_peer_entity.content_hash;

    // C — a co-signer. The other constituent of the K-of-2 group.
    let c_kp = Keypair::from_seed([0xc3u8; 32]);
    let c_peer_entity = c_kp.peer_entity().expect("C identity entity");
    let c_identity = c_peer_entity.content_hash;

    let granter = match root {
        Root::SingleSigTarget => Granter::Single(a_identity),
        Root::MultiGranterIncludingTarget => Granter::Multi(MultiGranter {
            signers: vec![a_identity, c_identity],
            threshold: 2,
        }),
    };
    let cap = CapabilityToken {
        grants: covers_echo(),
        granter,
        // Leaf grantee = the local peer, as §1.4 requires. Nothing about this
        // credential is malformed; the root shape is the whole difference.
        grantee: b_identity,
        // M3: multi-sig is root-only, so `parent` MUST be null. Held for the
        // single-sig row too, keeping the two chains the same length.
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let cap_entity = cap.to_entity().expect("cap entity");

    let mut included: Vec<Entity> = vec![
        a_peer_entity.clone(),
        c_peer_entity.clone(),
        b_peer_entity.clone(),
    ];
    match root {
        Root::SingleSigTarget => {
            included.push(sign(&a_kp, a_identity, cap_entity.content_hash));
        }
        Root::MultiGranterIncludingTarget => {
            // Both constituents sign: M4's threshold is met and M6 sees the
            // frame peer (the target) in `signers` and signed. The chain walk
            // therefore ACCEPTS this credential — E3 is the only thing that
            // refuses it.
            included.push(sign(&a_kp, a_identity, cap_entity.content_hash));
            included.push(sign(&c_kp, c_identity, cap_entity.content_hash));
        }
    }

    // The executing handler's grant: the §6.9 bootstrap default — wide on
    // Dimensions 1-3, `peers` **absent** so it cannot reach A on its own. The
    // credential's Dimension-4 relaxation is the whole question.
    let ceiling_token = CapabilityToken {
        grants: entity_capability::default_handler_self_grant(),
        granter: Granter::Single(b_identity),
        grantee: b_identity,
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };

    let execute_fn = entity_peer::connection::make_execute_fn(
        shared.clone(),
        Some(b_identity),
        std::collections::HashMap::new(),
        None,
        None,
        entity_peer::connection::DispatchCeiling::Handler(Some(Box::new(ceiling_token))),
    );

    let params = Entity::new(
        "primitive/any",
        entity_ecf::to_ecf(&entity_ecf::text("pong")),
    )
    .unwrap();
    let opts = entity_handler::ExecuteOptions {
        capability: Some(cap_entity),
        included,
        resource: None::<ResourceTarget>,
        ..Default::default()
    };

    match execute_fn(
        format!("entity://{}/system/validate/echo", a_pid),
        "echo".into(),
        params,
        opts,
    )
    .await
    {
        Ok(r) => Ok((
            r.status,
            String::from_utf8_lossy(&r.result.data).to_string(),
        )),
        // The gate allowed it and the dispatch reached `get_or_connect`, which
        // has no address for a peer that was never dialed. That transport error
        // IS the "allowed" observable — there is deliberately no peer A.
        Err(_) => Err(()),
    }
}

/// **E3.** A K-of-2-rooted credential whose signer set includes the target
/// relaxes **nothing**, and the handler grant then gates unrelaxed — refused
/// before the dial.
///
/// **Mutation RUN:** delete the `(c2)` multi-granter block in
/// `presented_credential_relaxes_peers` and this row flips from `Ok(403)` to
/// `Err(())` — the dispatch is authorized and dies at the connection attempt
/// instead — while `a_single_sig_target_rooted_credential_still_relaxes` below
/// stays `Err(())`. The control is what makes that meaningful: it proves
/// `Err(())` is reachable through this harness at all, so the 403 here is a
/// refusal and not the drive failing to arrive.
#[tokio::test]
async fn a_multi_granter_root_including_the_target_relaxes_nothing() {
    let outcome = drive(Root::MultiGranterIncludingTarget).await;
    match outcome {
        Ok((status, body)) => {
            assert_eq!(
                status, 403,
                "§1.4 (0.8.2.19): a K-of-N root is a GROUP's authority; the \
                 target being one constituent does not make it the granter. \
                 Body: {}",
                body
            );
            assert!(
                body.contains("no authority to sub-dispatch"),
                "and the refusal is the §1.4 gate's, minted before the dial: {}",
                body
            );
        }
        Err(()) => panic!(
            "the sub-dispatch was AUTHORIZED and reached the dial — a \
             multi-granter root whose signer set merely includes the target \
             must not relax Dimension 4 (§1.4, 0.8.2.19 / E3). This is the \
             pre-E3 behaviour: M6 accepts the chain because the frame peer is \
             a signer, and nothing downstream re-asks the granter question."
        ),
    }
}

/// The control, and it is load-bearing twice over. It proves (a) the harness
/// can reach the dial, so the row above's 403 is the gate refusing rather than
/// the drive never arriving; and (b) E3 is scoped to the multi-granter case
/// and has not turned the presented arm off wholesale — *"looks implemented and
/// denies everything"* is §1.4's own named failure for this surface.
#[tokio::test]
async fn a_single_sig_target_rooted_credential_still_relaxes() {
    match drive(Root::SingleSigTarget).await {
        Err(()) => {}
        Ok((status, body)) => panic!(
            "a single-sig credential rooted at the target, naming this peer as \
             grantee and covering the request, MUST relax Dimension 4 — the \
             §1.4 arm exists to accept exactly this. Got {}: {}",
            status, body
        ),
    }
}
