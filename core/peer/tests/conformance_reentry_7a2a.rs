//! GUIDE-CONFORMANCE §7a.2a in-band cap-passing, end-to-end over the wire.
//!
//! The reentrant `system/validate/dispatch-outbound` path, which core-go's
//! `validate-complete.sh` scores as `concurrency.t1_2_concurrent_reentry` +
//! `origination.dispatch_outbound_reentry` and which **no rust test covered**:
//! A dispatches to B's `dispatch-outbound`, B originates one outbound EXECUTE
//! back to A's `system/validate/echo` over the §6.11-reused connection, and the
//! authority for that reentrant leg rides **in-band in params** (§7a.2a) rather
//! than in B's content store.
//!
//! That last clause is the whole point. Every other capability the dispatcher
//! bundles was persisted locally at install (§3.2 step 5), so a bundler that
//! resolves only against its own store passes every test we had — and 502s the
//! one path where the caller hands it the chain on the wire.
//! `2026-08-14-e-full-surface-three-way-and-rust-dispatch-outbound-502.md`.

#![cfg(all(feature = "conformance", feature = "capability-handler"))]

use entity_capability::{CapabilityToken, GrantEntry, Granter, IdScope, PathScope};
use entity_crypto::Keypair;
use entity_entity::Entity;
use entity_peer::{transport, PeerBuilder};

/// Which granter the minted reentry cap names — the axis the two rows differ
/// on, and the only one.
enum Granted {
    /// The real granter: A, whose `system/peer` entity rides in-band.
    Validator,
    /// A granter no one can resolve — not in-band, not in either store. §4.3's
    /// fail-closed MUST still has to bite.
    UnresolvableIdentity,
    /// A granter that resolves fine and is **not the target**: B, the peer
    /// making the outbound dispatch, granting to itself. Well-formed, signed,
    /// bundleable — and not presented authority under §1.4, because the party
    /// that decides what may happen at A is A. The PD-2 negative arm.
    SelfNotTarget,
    /// No §7a.2a triple at all — the sub-dispatch rides **ambient** handler
    /// authority. This is the input `origination.dispatch_outbound_ambient_refused`
    /// sends, driven in-process.
    Absent,
    /// **E3 / F66.** A K-of-2 `multi-granter` root whose signer set *includes*
    /// the target A, with both constituents signing — so §5.5's M4 threshold and
    /// M6 constituency both pass and the chain walk **accepts** the credential.
    /// §1.4 (`0.8.2.19`) still fails it closed: a K-of-N root is a *group's*
    /// authority, and the target being one constituent does not make it the
    /// granter.
    ///
    /// **This row exists on the wire only because the carrier went plural.**
    /// Two granter identities and two signatures do not fit the pre-`0.8.2.19`
    /// singular fields, which is why every seat drove E3 in-process and this
    /// file's own header used to say the scaffold *"cannot express the shape
    /// under test."* It can now.
    MultiGranterIncludingTarget,
}

/// What B's `system/validate/dispatch-outbound` **handler grant** covers — the
/// second axis, and **the one F67 was blind to** (0.8.2.19 E1).
///
/// Before 0.8.2.19 the presented credential authorized the sub-dispatch on its
/// own and returned before this grant was read at all, so every row in this
/// file could be driven at any value of this axis and none of them would move.
/// That is exactly why the bypass shipped in three independent trees: the two
/// obvious vectors — credential + covering grant → allow, no credential →
/// refuse — are the two that cannot see it.
enum HandlerGrant {
    /// Leave the bootstrap grant exactly as `PeerBuilder` built it.
    ///
    /// **This is no longer the wide §6.9 default, and that is the §7a.1 ⛔
    /// change (`0.8.2.19`).** `DispatchOutboundHandler::internal_scope()` now
    /// declares its own narrow set — handlers `system/validate/echo`, operations
    /// `echo`, resources `/*/system/validate/echo`, **`peers` absent** — so this
    /// variant drives the grant a shipping `--validate` peer actually runs
    /// under, which is what makes go's F63 wire discriminator constructible at
    /// this seat at all. It used to mean handlers `*` / operations `*` /
    /// resources `/*/*`, and under *that* grant a compose and a bypass returned
    /// the same answer for every input a probe could send.
    Default,
    /// Covers the sub-dispatched op on Dimensions 1–3 and still cannot reach a
    /// foreign peer on its own (`peers` absent ⇒ `{include: [local]}`). The
    /// **relaxation control**: only §1.4's one exemption gets this through.
    CoversOpPeersAbsent,
    /// Reaches any peer (`peers: *`, so Dimension 4 is satisfied outright) and
    /// does **not** cover the operation. The **confused-deputy discriminator**:
    /// the only thing that can authorize here is a credential displacing
    /// Dimensions 1–3, which is precisely what E1 forbids.
    DoesNotCoverOp,
    /// No handler grant bound at all. §9.1, 0.8.2.19: *"a credential is not a
    /// grant — with no handler grant there is nothing to supply Dimensions 1-3
    /// and the sub-dispatch is refused."*
    Unbound,
}

/// Rebind B's `dispatch-outbound` handler grant to `grants`, minted and signed
/// exactly as `create_handler_grant` does so `load_local_handler_grant`'s §S2
/// ladder (granter equality, detached-signature verification, temporal
/// validity) accepts it. `None` unbinds instead.
///
/// Writing the grant rather than declaring an `internal_scope()` is deliberate:
/// the scope this test needs is per-row, and the tree binding is what the
/// dispatcher actually reads.
fn rebind_dispatch_outbound_grant(
    shared: &std::sync::Arc<entity_peer::PeerShared>,
    pid: &str,
    grants: Option<Vec<GrantEntry>>,
) {
    let path = format!(
        "/{}/system/capability/grants/system/validate/dispatch-outbound",
        pid
    );
    let grants = match grants {
        Some(g) => g,
        None => {
            shared.location_index.remove(&path);
            return;
        }
    };
    let identity = shared.identity_hash;
    let token = CapabilityToken {
        grants,
        granter: Granter::Single(identity),
        grantee: identity,
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let entity = token.to_entity().expect("grant entity");
    let hash = shared.content_store.put(entity.clone()).expect("put grant");
    let sig_bytes = shared.keypair.sign(&entity.content_hash.to_bytes());
    let sig = Entity::new(
        entity_entity::TYPE_SIGNATURE,
        entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("algorithm"),
                entity_ecf::text(shared.keypair.key_type().label()),
            ),
            (
                entity_ecf::text("signature"),
                entity_ecf::Value::Bytes(sig_bytes),
            ),
            (
                entity_ecf::text("signer"),
                entity_ecf::Value::Bytes(identity.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("target"),
                entity_ecf::Value::Bytes(entity.content_hash.to_bytes().to_vec()),
            ),
        ])),
    )
    .expect("grant signature");
    let sig_hash = shared.content_store.put(sig).expect("put grant signature");
    shared.location_index.set(&path, hash);
    shared
        .location_index
        .set(&entity_hash::invariant_signature_path(pid, &hash), sig_hash);
}

/// Wildcard seed policy — the `--debug-grants` posture the validator harness
/// runs its target under. Keeps the OUTER execute authorized so a failure can
/// only be the inner reentrant leg.
fn wildcard() -> Vec<(String, Vec<GrantEntry>)> {
    vec![(
        "default".to_string(),
        vec![GrantEntry {
            handlers: PathScope::new(vec!["*".into()]),
            resources: PathScope::new(vec!["*".into()]),
            operations: IdScope::new(vec!["*".into()]),
            peers: Some(IdScope::all()),
            constraints: None,
            allowances: None,
        }],
    )]
}

/// Append `key` + a raw pre-encoded CBOR value to a map body. The nested
/// authority entities MUST ride byte-verbatim (§7a.2a) — a decode+re-encode
/// would move their content hashes.
fn put_raw(out: &mut Vec<u8>, key: &str, raw: &[u8]) {
    entity_ecf::encode_cbor_text(out, key);
    out.extend_from_slice(raw);
}

/// Drive one full §7a.2a round trip against B's **bootstrap-default** handler
/// grant and hand back B's outer response.
///
/// The four rows that predate 0.8.2.19 call this and are **untouched** by E1 —
/// that is what makes them controls for it rather than co-edited witnesses.
async fn dispatch_outbound_roundtrip(granted: Granted) -> entity_handler::HandlerResult {
    dispatch_outbound_roundtrip_with(granted, HandlerGrant::Default).await
}

/// Drive one full §7a.2a round trip and hand back B's outer response, with the
/// sub-dispatched operation left at the contract's `echo`.
async fn dispatch_outbound_roundtrip_with(
    granted: Granted,
    handler_grant: HandlerGrant,
) -> entity_handler::HandlerResult {
    dispatch_outbound_roundtrip_op(granted, handler_grant, "echo").await
}

/// Drive one full §7a.2a round trip, with the **sub-dispatched operation** as a
/// third axis.
///
/// That axis is §7a.1's own discriminating probe: *sub-dispatch an operation
/// outside the handler's declared set while presenting a credential that does
/// cover it.* The presented credential is minted over `sub_operation`, so the
/// only thing standing between the request and success is B's own grant.
async fn dispatch_outbound_roundtrip_op(
    granted: Granted,
    handler_grant: HandlerGrant,
    sub_operation: &str,
) -> entity_handler::HandlerResult {
    use transport::{MemoryConnector, MemoryListener, MemoryTransportRegistry};

    let registry = MemoryTransportRegistry::new();

    // --- B: the target under validation (the role rust plays in the harness).
    let b = PeerBuilder::new()
        .keypair(Keypair::from_seed([0x7bu8; 32]))
        .with_conformance_handlers()
        .with_seed_policy(wildcard())
        .build()
        .expect("target peer builds");
    let b_pid = b.peer_id().to_string();

    let listener = MemoryListener::bind(b_pid.clone(), registry.clone()).expect("bind");
    let b_shared = b.shared();

    // The E1 axis. `Default` leaves the §6.9 bootstrap grant exactly as built,
    // so the four pre-0.8.2.19 rows below drive the identical peer they always
    // did.
    let echo_only = |peers: Option<IdScope>| {
        vec![GrantEntry {
            handlers: PathScope::new(vec!["system/validate/echo".into()]),
            resources: PathScope::new(vec!["*".into()]),
            operations: IdScope::new(vec!["echo".into()]),
            peers,
            constraints: None,
            allowances: None,
        }]
    };
    match handler_grant {
        HandlerGrant::Default => {}
        HandlerGrant::CoversOpPeersAbsent => {
            rebind_dispatch_outbound_grant(&b_shared, &b_pid, Some(echo_only(None)))
        }
        HandlerGrant::DoesNotCoverOp => rebind_dispatch_outbound_grant(
            &b_shared,
            &b_pid,
            // Dimension 4 satisfied outright, Dimension 2 (operations) not — so
            // a refusal here can only be Dimensions 1-3, never the peers scope.
            Some(vec![GrantEntry {
                handlers: PathScope::new(vec!["system/validate/echo".into()]),
                resources: PathScope::new(vec!["*".into()]),
                operations: IdScope::new(vec!["not-echo".into()]),
                peers: Some(IdScope::all()),
                constraints: None,
                allowances: None,
            }]),
        ),
        HandlerGrant::Unbound => rebind_dispatch_outbound_grant(&b_shared, &b_pid, None),
    }

    b.start_engines(&b_shared);
    let b_shared_clone = b_shared.clone();
    let b_handle = tokio::spawn(async move {
        let _ = entity_peer::server::run(listener, b_shared_clone).await;
    });
    tokio::task::yield_now().await;

    // --- A: the validator. Serves the reentrant `echo` back over the
    // connection it dialed (§6.11 reuse — A never listens).
    let a = PeerBuilder::new()
        .keypair(Keypair::from_seed([0x7au8; 32]))
        .connector(std::sync::Arc::new(MemoryConnector::new(registry.clone())))
        .with_conformance_handlers()
        .with_seed_policy(wildcard())
        .build()
        .expect("validator peer builds");
    let a_pid = a.peer_id().to_string();
    let a_shared = a.shared();
    a.start_engines(&a_shared);

    let dialed = a
        .connect_to(&format!("memory://{}", b_pid))
        .await
        .expect("A dials B");
    assert_eq!(dialed, b_pid);

    // --- The §7a.2a authority: A mints a cap letting B reenter A's echo.
    let a_identity_hash = a_shared.identity_hash;
    let b_identity_hash = b_shared.identity_hash;

    // C — the other constituent of the E3 K-of-2 group. Never a live peer; only
    // its identity entity and its signature travel.
    let c_keypair = Keypair::from_seed([0x7cu8; 32]);
    let c_peer_entity = c_keypair.peer_entity().expect("C identity entity");
    let c_identity_hash = c_peer_entity.content_hash;

    let cap_granter = match granted {
        Granted::Validator => Granter::Single(a_identity_hash),
        // A well-formed hash of a `system/peer` entity that exists nowhere —
        // neither peer's store holds it and nothing carries it in-band.
        Granted::UnresolvableIdentity => Granter::Single(entity_hash::Hash::compute(
            "system/peer",
            b"granter-nobody-holds",
        )),
        Granted::SelfNotTarget => Granter::Single(b_identity_hash),
        // Built but never encoded — the Absent row omits the whole set.
        Granted::Absent => Granter::Single(a_identity_hash),
        // M3 makes multi-signature root-only, so `parent` stays null below and
        // this IS the root.
        Granted::MultiGranterIncludingTarget => Granter::Multi(entity_capability::MultiGranter {
            signers: vec![a_identity_hash, c_identity_hash],
            threshold: 2,
        }),
    };
    let cap = CapabilityToken {
        grants: vec![GrantEntry {
            handlers: PathScope::new(vec!["system/validate/echo".into()]),
            resources: PathScope::new(vec!["*".into()]),
            // Minted over the operation actually being sub-dispatched — §7a.1's
            // probe presents a credential that DOES cover the out-of-scope
            // request, so a refusal is attributable to B's grant and to nothing
            // about the credential.
            operations: IdScope::new(vec![sub_operation.to_string()]),
            peers: Some(IdScope::all()),
            constraints: None,
            allowances: None,
        }],
        granter: cap_granter,
        grantee: b_identity_hash,
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let cap_entity = cap.to_entity().expect("cap entity");

    // The granter signs it (V7 §5.5 detached signature, signer = granter's
    // identity hash). For the BySelfNotTarget row that is B, so the capability
    // is structurally impeccable and bundles cleanly — the ONLY thing wrong
    // with it is that B is not the peer being dispatched at, which is exactly
    // the property §1.4's presented arm tests.
    // Takes the raw signature + label rather than a keypair: A and B carry
    // `IdentityKeypair` (any allocated key type) while C is a plain Ed25519
    // `Keypair`, and their `sign` return types differ.
    let sig_entity_from = |sig_bytes: Vec<u8>, label: &str, signer: entity_hash::Hash| -> Entity {
        Entity::new(
            entity_entity::TYPE_SIGNATURE,
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
                (entity_ecf::text("algorithm"), entity_ecf::text(label)),
                (
                    entity_ecf::text("signature"),
                    entity_ecf::Value::Bytes(sig_bytes),
                ),
                (
                    entity_ecf::text("signer"),
                    entity_ecf::Value::Bytes(signer.to_bytes().to_vec()),
                ),
                (
                    entity_ecf::text("target"),
                    entity_ecf::Value::Bytes(cap_entity.content_hash.to_bytes().to_vec()),
                ),
            ])),
        )
        .expect("signature entity")
    };

    // The granter identities the §4.3 bundle MUST carry, and the signatures over
    // the credential — **arrays**, index-parallel by construction. B has never
    // seen A's (or C's) `system/peer` entity in its store; they arrive in-band.
    let a_peer_entity = a_shared
        .content_store
        .get(&a_identity_hash)
        .expect("A holds its own identity entity");
    let b_peer_entity = b_shared
        .content_store
        .get(&b_identity_hash)
        .expect("B holds its own identity entity");
    let target_bytes = cap_entity.content_hash.to_bytes();
    let by_a = || {
        sig_entity_from(
            a_shared.keypair.sign(&target_bytes),
            a_shared.keypair.key_type().label(),
            a_identity_hash,
        )
    };
    let (granter_entities, sig_entities): (Vec<Entity>, Vec<Entity>) = match granted {
        Granted::SelfNotTarget => (
            vec![b_peer_entity],
            vec![sig_entity_from(
                b_shared.keypair.sign(&target_bytes),
                b_shared.keypair.key_type().label(),
                b_identity_hash,
            )],
        ),
        // Both constituents sign: M4's threshold is met and M6 sees the frame
        // peer among `signers` and signed, so the chain walk ACCEPTS. E3 is then
        // the only thing that refuses — which is the antecedent this row's
        // control below has to establish rather than assert (§2.4b).
        Granted::MultiGranterIncludingTarget => (
            vec![a_peer_entity, c_peer_entity],
            vec![
                by_a(),
                sig_entity_from(
                    c_keypair.sign(&target_bytes).to_vec(),
                    c_keypair.key_type().label(),
                    c_identity_hash,
                ),
            ],
        ),
        _ => (vec![a_peer_entity], vec![by_a()]),
    };

    // --- Params, exactly as the §7a.2a convention lays them out. ECF map key
    // order: by encoded key length, then lexicographic.
    let mut body = Vec::new();
    body.push(if matches!(granted, Granted::Absent) {
        0xA3 // 3-item map: value, target, operation
    } else {
        0xA6 // 6-item map: + the §7a.1 authority set (capability + 2 arrays)
    });
    put_raw(
        &mut body,
        "value",
        &entity_ecf::to_ecf(&entity_ecf::text("pong")),
    );
    put_raw(
        &mut body,
        "target",
        &entity_ecf::to_ecf(&entity_ecf::text(format!(
            "/{}/system/validate/echo",
            a_pid
        ))),
    );
    put_raw(
        &mut body,
        "operation",
        &entity_ecf::to_ecf(&entity_ecf::text(sub_operation)),
    );
    if !matches!(granted, Granted::Absent) {
        // §7a.1 `0.8.2.19`: the granter and signature carriers are ARRAYS, and
        // the single-granter case is an array of one. The entities themselves
        // still ride byte-verbatim; the plural carrier is a change to the
        // container, not to their bytes — so the array head is written by hand
        // rather than by re-encoding through a CBOR value.
        let array_of = |es: &[Entity]| {
            assert!(es.len() < 24, "one-byte CBOR array head only");
            let mut v = vec![0x80u8 | es.len() as u8];
            for e in es {
                v.extend_from_slice(&entity_wire::encode_entity(e));
            }
            v
        };
        put_raw(&mut body, "reentry_granters", &array_of(&granter_entities));
        put_raw(
            &mut body,
            "reentry_capability",
            &entity_wire::encode_entity(&cap_entity),
        );
        put_raw(
            &mut body,
            "reentry_cap_signatures",
            &array_of(&sig_entities),
        );
    }
    let params = Entity::new("primitive/any", body).expect("params entity");

    // --- The outer EXECUTE: A → B's dispatch-outbound.
    let resp = a
        .execute(
            &format!("/{}/system/validate/dispatch-outbound", b_pid),
            "dispatch",
            params,
        )
        .await
        .expect("outer execute completes");

    b_handle.abort();
    resp
}

/// The row core-go scores. Green here == the 502 is gone.
#[tokio::test]
async fn dispatch_outbound_reentry_with_in_band_authority() {
    let resp = dispatch_outbound_roundtrip(Granted::Validator).await;

    assert_eq!(
        resp.status, 200,
        "§7a.1/§7a.2a: the reentrant dispatch-outbound MUST return 200 — the \
         authority for the inner leg rides in-band in params, and a bundler \
         that resolves only against its own content store fails it \
         (`chain_unreachable` → 502). Got {}: {:?}",
        resp.status, resp.result
    );

    // The §7a.1 result shape is `{status, result}` — the downstream echo's own
    // status, not the outer one. 200 here proves the reentrant leg was
    // authorized at A, not merely that B answered.
    let out: ciborium::value::Value =
        ciborium::from_reader(resp.result.data.as_slice()).expect("result decodes");
    let downstream_status = out
        .as_map()
        .and_then(|m| {
            m.iter()
                .find(|(k, _)| k.as_text() == Some("status"))
                .and_then(|(_, v)| v.as_integer())
        })
        .expect("result carries a downstream status");
    assert_eq!(
        i128::from(downstream_status),
        200,
        "downstream echo status (the reentrant leg A authorized): {:?}",
        out
    );
}

/// The control on the same row: reading in-band authority must NOT have turned
/// EXTENSION-CONTINUATION v1.22 §4.3 back off. Name a granter identity nobody
/// can resolve — in-band, local store, anywhere — and the bundler MUST still
/// refuse at bundle time rather than dispatch an incomplete bundle. Without
/// this, the green row above could pass for the wrong reason (a resolver that
/// waves everything through looks identical from the outside).
#[tokio::test]
async fn unresolvable_granter_identity_still_fails_the_bundle() {
    let resp = dispatch_outbound_roundtrip(Granted::UnresolvableIdentity).await;

    assert_eq!(
        resp.status, 502,
        "§4.3: a granter identity the bundler cannot resolve MUST fail at \
         bundle time, in-band resolution or not. Got {}: {:?}",
        resp.status, resp.result
    );
    let body = String::from_utf8_lossy(&resp.result.data);
    assert!(
        body.contains("chain_unreachable"),
        "the refusal names the §4.3 condition: {:?}",
        body
    );
}

/// **§9.1's PD-2 negative arm** (0.8.2.17): a locally-originated sub-dispatch
/// on **ambient** authority at a **foreign** peer is refused, because the
/// executing handler's grant carries no matching `peers` scope.
///
/// The row above is the positive arm and this is the negative one, on the same
/// handler in the same file, differing in exactly one field: **who granted the
/// capability**. §9.1 says outright that *"a check set MUST discriminate them"*,
/// and one arm alone does not — a peer that authorizes everything passes the
/// positive row, a peer that refuses everything passes this one.
///
/// The capability here is not malformed and does not fail §4.3: B grants to B,
/// B signs it, B's identity entity rides in-band, so the bundler assembles it
/// cleanly and the 502 control above does not fire. The single defect is that
/// **B is not A**, so under §1.4 it is not presented authority — the party that
/// decides what may be done at A is A — and the dispatch falls to the ambient
/// arm, where `dispatch-outbound`'s bootstrap grant (`default_handler_self_grant`,
/// `peers` absent ⇒ `{include: [local]}`) does not reach A.
///
/// **Asserts on wording only this peer authors.** A status code is the one part
/// of a refusal every seat spells identically, and A would also reject this
/// capability — for a different reason, one hop later. `no authority to
/// sub-dispatch` is minted at exactly one site in this tree
/// (`outbound_sub_dispatch_authorized`), so the assertion cannot be satisfied by
/// the far peer's refusal, which is what the pre-0.8.2.17 code produced.
///
/// **Mutations run, and both are recorded because the pair is the §9.1
/// requirement, not either one alone.**
///
/// 1. Disable `outbound_sub_dispatch_authorized` on the remote branch → **this
///    row reddens, the two above stay green.** And the failure is the reason
///    the wording assertion exists rather than being belt-and-braces: the
///    unfixed peer answers **403 as well**, because the EXECUTE reaches A and A
///    refuses the B→B capability with `verification_failed` / *"root capability
///    granter is not local peer."* Same status, different peer, different
///    defect. A status-only assertion passes under the mutation.
/// 2. Disable the **presented** arm (`presented_authority_authorizes` → false)
///    → **the two rows above redden and this one stays green**, together with
///    `follow_continuation_standing_leg_fires_cross_peer` in `entity-sdk`.
///
/// One mutation reddening only the negative row and the other only the positive
/// rows is what makes this a discriminating check set rather than two tests that
/// happen to agree with a peer that is uniformly permissive or uniformly
/// closed.
#[tokio::test]
async fn ambient_authority_cannot_sub_dispatch_at_a_foreign_peer() {
    let resp = dispatch_outbound_roundtrip(Granted::SelfNotTarget).await;

    // The §7a.1 envelope is still well-formed — the refusal is the inner leg's.
    assert_eq!(
        resp.status, 200,
        "the outer dispatch-outbound call itself is authorized: {:?}",
        resp.result
    );
    let out: ciborium::value::Value =
        ciborium::from_reader(resp.result.data.as_slice()).expect("result decodes");
    let downstream_status = out
        .as_map()
        .and_then(|m| {
            m.iter()
                .find(|(k, _)| k.as_text() == Some("status"))
                .and_then(|(_, v)| v.as_integer())
        })
        .expect("result carries a downstream status");
    assert_eq!(
        i128::from(downstream_status),
        403,
        "§1.4 PD-2: ambient authority at a foreign peer is refused BEFORE the \
         sub-dispatch leaves. Got: {:?}",
        out
    );

    let body = format!("{:?}", out);
    assert!(
        body.contains("capability_denied"),
        "the refusal carries the §5.2 verdict code: {:?}",
        out
    );
    assert!(
        body.contains("no authority to sub-dispatch"),
        "the refusal must be OURS, not the far peer's — this wording is minted \
         at one site in this tree, and a status code alone cannot tell the two \
         apart: {:?}",
        out
    );
}

/// Pull the §7a.1 `{status, result}` envelope's downstream status out of B's
/// outer response, asserting the outer call itself was fine.
fn downstream(resp: &entity_handler::HandlerResult) -> (i128, String) {
    assert_eq!(
        resp.status, 200,
        "the outer dispatch-outbound call itself is authorized: {:?}",
        resp.result
    );
    let out: ciborium::value::Value =
        ciborium::from_reader(resp.result.data.as_slice()).expect("result decodes");
    let status = out
        .as_map()
        .and_then(|m| {
            m.iter()
                .find(|(k, _)| k.as_text() == Some("status"))
                .and_then(|(_, v)| v.as_integer())
        })
        .expect("result carries a downstream status");
    (i128::from(status), format!("{:?}", out))
}

/// **THE F67 DISCRIMINATOR** — §1.4/§6.8 as corrected at 0.8.2.19, and §9.1's
/// *"a check set MUST discriminate a COMPOSE from a BYPASS."*
///
/// A **valid, target-minted, chain-verified, fully-covering** credential is
/// presented to a handler whose own grant does **not** cover the sub-dispatched
/// operation. The credential answers *where*; it does not answer *what*, and
/// the handler's grant does not authorize `echo`. **MUST refuse.**
///
/// This is the vector whose absence shipped a confused-deputy bypass in three
/// independent implementations. The two obvious ones cannot see it: with a
/// covering grant both the bypass and the compose allow, with no credential
/// both refuse. Only a *disagreement* between the two sources separates them.
///
/// **Why it matters and not just that it is missing.** The presented credential
/// is a caller-supplied parameter — this very handler reads it out of
/// `params.reentry_capability`. So before E1, a caller holding a copy of any
/// `A → B` capability could hand it to **any** handler on B and steer that
/// handler past its own grant to A. The caller cannot wield the credential
/// itself (its leaf `grantee` is B), which is what makes B the confused deputy.
///
/// **Dimension 4 is satisfied outright on this row** (`peers: *` on the handler
/// grant), so the refusal cannot be the peers check firing for an unrelated
/// reason — it is Dimensions 1–3, which is the claim.
///
/// **Mutation RUN, not predicted — and go's warning applies: a negative
/// security test can pass for the wrong reason.** Restoring the bypass (`for
/// cand in &candidates { if presented_credential_relaxes_peers(..) { return
/// true } }` ahead of the gate in `outbound_sub_dispatch_authorized`) scored
/// `5 passed; 2 failed`: **this row** and
/// `a_credential_does_not_substitute_for_a_handler_grant_that_is_absent` both
/// go to inner **200**, and the four pre-0.8.2.19 rows stay green. Both
/// reddened rows are named because the bypass returns before the ceiling match
/// and therefore reaches both — reporting only one would overstate how narrowly
/// this row bites. That run is what proves the probe REACHES the gate;
/// "refused" is the expected outcome here, so the refusal alone is worth
/// nothing as evidence.
#[tokio::test]
async fn a_target_minted_credential_does_not_lift_a_handler_grant_that_does_not_cover_the_op() {
    let resp =
        dispatch_outbound_roundtrip_with(Granted::Validator, HandlerGrant::DoesNotCoverOp).await;
    let (status, body) = downstream(&resp);

    assert_eq!(
        status, 403,
        "§1.4 (0.8.2.19): the executing handler's grant is the gate on all four \
         dimensions; a target-minted credential relaxes Dimension 4 and ONLY \
         Dimension 4. A grant that does not cover `echo` must refuse even with \
         a perfectly valid credential in hand — anything else is the F67 \
         confused deputy. Got: {}",
        body
    );
    assert!(
        body.contains("no authority to sub-dispatch"),
        "and the refusal must be OURS, minted before the dial — a status code \
         alone cannot tell our gate from A's own rejection one hop later: {}",
        body
    );
}

/// **E3 / F66 on the WIRE — the row the plural carrier exists to make
/// expressible**, and the in-tree twin of go's
/// `origination.dispatch_outbound_multisig_root_refused`.
///
/// A K-of-2 `multi-granter` root whose signer set includes the target, both
/// constituents signing, presented through the real §7a.1 scaffold over the real
/// connection. §1.4 (`0.8.2.19`) fails it closed: a K-of-N root is a **group's**
/// authority, and the target being one constituent does not make it the granter.
///
/// **Why this is not a duplicate of `pd2_multi_granter_root.rs`.** That file
/// drives `make_execute_fn` directly and says in its own header that the wire
/// scaffold *"cannot express the shape under test — exactly three fields, one
/// granter identity and one signature."* That was true and is no longer: the
/// sentence was load-bearing, in the way our own charter warns a deferral
/// comment is, and the plural carrier is what retired it. The in-process pair
/// stays as the cheap floor; this is the wire attestation.
///
/// **This row is DENY-ONLY and §2.4b binds it.** Its property has an antecedent
/// — *the credential MUST NOT relax Dimension 4 **even though chain verification
/// accepts the root*** — and a credential invalid for any unrelated reason (a
/// malformed multi-granter encoding, a signature over the wrong bytes, a grantee
/// mismatch, a scope that does not cover) is refused by every conformant peer for
/// that reason, leaving this row green having measured nothing. The antecedent
/// is therefore **established, not asserted**, by
/// `a_single_sig_root_over_the_identical_request_succeeds` below: same operation,
/// same target, same scope, same grantee, **the granter form the only variable**.
#[tokio::test]
async fn a_multi_sig_root_credential_is_refused_over_the_wire() {
    let resp = dispatch_outbound_roundtrip(Granted::MultiGranterIncludingTarget).await;
    let (status, body) = downstream(&resp);

    assert_eq!(
        status, 403,
        "§1.4 (0.8.2.19 / E3): a multi-signature root relaxes nothing, and the \
         handler grant then gates unrelaxed. The chain walk ACCEPTS this \
         credential — M4's threshold is met and M6 sees the target among the \
         signers — so a 200 here is over-acceptance, not a chain failure. Got: {}",
        body
    );
    assert!(
        body.contains("no authority to sub-dispatch"),
        "and the refusal is the §1.4 gate's, minted before the dial: {}",
        body
    );
}

/// **The §2.4b control for the row above, and it is the whole of that rule.**
/// Byte-parallel with the E3 credential except the `granter` field: same grants,
/// same handler/operation/resource scope, same grantee, same expiry window, same
/// scaffold, same connection. A single-signature root **MUST succeed**.
///
/// If it does not, the credential family is not valid-and-covering at this seat
/// and the multi-sig refusal above measures nothing — so this row failing is not
/// "one more red test", it retroactively voids the one beside it.
///
/// It is deliberately a *distinct* row from
/// `dispatch_outbound_reentry_with_in_band_authority`, which drives a separately
/// constructed credential and therefore controls for nothing about this one
/// (§2.4b item 2). The two look interchangeable and are not.
#[tokio::test]
async fn a_single_sig_root_over_the_identical_request_succeeds() {
    let resp = dispatch_outbound_roundtrip(Granted::Validator).await;
    let (status, body) = downstream(&resp);

    assert_eq!(
        status, 200,
        "the E3 antecedent: with the granter form the ONLY variable, the \
         single-signature root must reach A's echo. A failure here means the \
         multi-sig row above is an unattributable deny. Got: {}",
        body
    );
}

/// **§7a.1 ⛔ / F63, driven against the grant this peer actually SHIPS.**
///
/// The two rows above are the right shape and they prove it against a
/// *rebound* grant this test writes into B's tree. That is a claim about
/// `outbound_sub_dispatch_authorized`; it is not a claim about the scaffold. The
/// scaffold is the other half of the ⛔ block: go's wire discriminator
/// (`origination.dispatch_outbound_narrow_grant_refuses_out_of_scope`) drives a
/// `--validate` peer's **bootstrap** `dispatch-outbound` grant, and against the
/// wide §6.9 default it is unconstructible — a compose and a bypass return the
/// same answer for every input it can send. So the two claims are separate and
/// this row is the second one: **`HandlerGrant::Default`**, i.e. whatever
/// `DispatchOutboundHandler::internal_scope()` declared, with the sub-dispatched
/// operation OUTSIDE the declared set and a credential that DOES cover it.
///
/// This is the row that goes red if someone "simplifies" the scaffold's
/// `internal_scope()` back to `None` — the crate-local
/// `dispatch_outbound_declares_a_narrow_internal_scope` pins the *declaration*,
/// and this pins what the declaration BUYS. A declaration whose consequence is
/// untested is the §7a.1 hole one level in.
///
/// **Mutation RUN, not predicted** — see the note at the bottom of this file for
/// both directions and the exact reddened rows.
#[tokio::test]
async fn the_shipped_narrow_scaffold_grant_refuses_an_out_of_scope_sub_dispatch() {
    let resp =
        dispatch_outbound_roundtrip_op(Granted::Validator, HandlerGrant::Default, "not-echo").await;
    let (status, body) = downstream(&resp);

    assert_eq!(
        status, 403,
        "§7a.1 ⛔: `dispatch-outbound`'s own grant is scoped to `echo` on \
         `system/validate/echo`. A sub-dispatch of `not-echo` is outside it, and \
         a target-minted credential that covers `not-echo` relaxes Dimension 4 \
         and nothing else. A 200 here means either the scaffold grant went wide \
         again or the credential is authorizing alone (F67). Got: {}",
        body
    );
    assert!(
        body.contains("no authority to sub-dispatch"),
        "and the refusal must be OURS, minted before the dial — A would refuse \
         an unknown operation too, one hop later and with a different body, so \
         the status alone cannot tell the two apart: {}",
        body
    );
}

/// **The positive control for the row above, and §7a.1's own words on why one
/// arm is not a check set.** Identical peer, identical bootstrap grant,
/// identical credential family — the sub-dispatched **operation** is the only
/// variable, and at `echo` it MUST succeed and reach A's handler.
///
/// Without it, "refuses `not-echo`" is satisfied by a scaffold whose grant
/// refuses *everything* — which is the same defect as a deny-only check with its
/// antecedent asserted nowhere (§2.4b), and it is precisely how a narrow-grant
/// change could silently break the reentry contract while looking like it
/// hardened it.
#[tokio::test]
async fn the_shipped_narrow_scaffold_grant_still_admits_the_reentry_contract_op() {
    let resp =
        dispatch_outbound_roundtrip_op(Granted::Validator, HandlerGrant::Default, "echo").await;
    let (status, body) = downstream(&resp);

    assert_eq!(
        status, 200,
        "§7a.1: the declared set exists to admit the reentry contract's one \
         operation. If this fails, the narrow grant is too narrow and the ⛔ \
         change broke the gate it was supposed to make measurable. Got: {}",
        body
    );
}

/// **The relaxation control**, and the other half of the §9.1 pair. Same
/// credential, same handler-grant narrowness — but this grant **does** cover
/// `echo` on Dimensions 1–3 while still carrying no `peers` scope (absent ⇒
/// `{include: [local]}`), so it cannot reach A on its own.
///
/// The credential relaxes Dimension 4 to the peers it covers. **MUST succeed.**
///
/// Without this row the discriminator above is satisfied by a peer that refuses
/// everything — which is F63(b) verbatim, and it is why one arm is never a
/// check set.
///
/// **Mutation RUN:** neuter the relaxation (`let relax_peers = false;` ahead of
/// the ceiling match in `outbound_sub_dispatch_authorized`) scored `5 passed;
/// 2 failed` — **this row** and the pre-existing
/// `dispatch_outbound_reentry_with_in_band_authority` go to inner **403**,
/// while the discriminator above stays **green**. That disjointness from
/// mutation 1 is the point: the two mutations redden non-overlapping rows, so
/// the pair is orthogonal rather than two spellings of one assertion, and no
/// single uniformly-permissive or uniformly-closed peer passes both.
#[tokio::test]
async fn a_target_minted_credential_relaxes_dimension_4_and_only_dimension_4() {
    let resp =
        dispatch_outbound_roundtrip_with(Granted::Validator, HandlerGrant::CoversOpPeersAbsent)
            .await;
    let (status, body) = downstream(&resp);

    assert_eq!(
        status, 200,
        "§1.4 (0.8.2.19): a valid target-minted credential relaxes the handler \
         grant's `peers` dimension to the peers it covers. This grant covers \
         `echo` and names no peers, so the credential is the whole difference \
         between refused and allowed. Got: {}",
        body
    );
}

/// **A credential is not a grant** — §9.1 (0.8.2.19): *"with no handler grant
/// there is nothing to supply Dimensions 1-3 and the sub-dispatch is refused."*
///
/// The same valid, covering, target-minted credential, presented by a handler
/// holding **no** grant at all. A relaxation applies to something; there is
/// nothing here to relax.
///
/// Distinct from the discriminator above and kept separately because the two
/// take different arms of the `DispatchCeiling` match — `Handler(None)` versus
/// `Handler(Some(..))` — and a fix that read `relax_peers` on the `None` arm
/// would redden neither of the other rows.
///
/// **Mutation RUN:** making the `Handler(None)` arm answer `relax_peers`
/// instead of `false` scored `6 passed; 1 failed` — this row alone goes inner
/// **200**. That is the row-scoped witness; mutation 1 (restore the bypass)
/// also reddens it, for the coarser reason that the bypass never reaches the
/// match at all.
#[tokio::test]
async fn a_credential_does_not_substitute_for_a_handler_grant_that_is_absent() {
    let resp = dispatch_outbound_roundtrip_with(Granted::Validator, HandlerGrant::Unbound).await;
    let (status, body) = downstream(&resp);

    assert_eq!(
        status, 403,
        "§9.1 (0.8.2.19): a credential relaxes one dimension of a grant; it is \
         not a grant. Got: {}",
        body
    );
    assert!(
        body.contains("no authority to sub-dispatch"),
        "and the refusal is ours: {}",
        body
    );
}

/// The same PD-2 negative arm as the row above, driven through the input
/// **core-go's `origination.dispatch_outbound_ambient_refused` actually sends**:
/// no §7a.2a triple at all, so the sub-dispatch rides ambient handler authority
/// with `opts.capability: None`.
///
/// Kept alongside the `SelfNotTarget` row rather than replacing it, because the
/// two reach the ambient arm by different routes and only one of them is what a
/// sibling drives. `SelfNotTarget` proves a *presented* capability that fails
/// the target test falls through to ambient; this proves a dispatch presenting
/// *nothing* is refused. A peer could pass either alone — the first by never
/// running the presented arm, the second by 400-ing an absent triple, which is
/// exactly what this tree did until the handler made the triple optional.
///
/// **That is the point of this row.** `dispatch-outbound` used to require the
/// triple, so go's probe got `400 invalid_params` on the OUTER status and the
/// check scored us FAIL — not because the ambient arm was wrong, but because
/// the probe could not reach it. A handler that refuses early makes its peer
/// look strict and makes the thing under test unmeasurable; the 400 and the 403
/// are the same word to a reader and different facts to a check.
///
/// **Mutation verified**: disabling `outbound_sub_dispatch_authorized` makes
/// this row report inner 200 (the echo succeeds at A), and the two §7a.2a rows
/// above stay green.
#[tokio::test]
async fn an_absent_authority_triple_dispatches_ambiently_and_is_refused() {
    let resp = dispatch_outbound_roundtrip(Granted::Absent).await;

    assert_eq!(
        resp.status, 200,
        "an absent §7a.2a triple is not a malformed request — it selects the \
         §1.4 ambient arm, and a 400 here is what made this unmeasurable from \
         the wire: {:?}",
        resp.result
    );
    let out: ciborium::value::Value =
        ciborium::from_reader(resp.result.data.as_slice()).expect("result decodes");
    let downstream_status = out
        .as_map()
        .and_then(|m| {
            m.iter()
                .find(|(k, _)| k.as_text() == Some("status"))
                .and_then(|(_, v)| v.as_integer())
        })
        .expect("result carries a downstream status");
    assert_eq!(
        i128::from(downstream_status),
        403,
        "§1.4 PD-2 negative arm, sibling-driven shape: {:?}",
        out
    );
    let body = format!("{:?}", out);
    assert!(
        body.contains("no authority to sub-dispatch"),
        "and the refusal is ours, minted before the dial: {:?}",
        out
    );
}

// ---------------------------------------------------------------------------
// §7a.1 ⛔ — the two mutations for the narrow-scaffold pair, RUN and recorded
// with the rows each one reddened. `0.8.2.19`, landed 2026-09-10.
// ---------------------------------------------------------------------------
//
// **Mutation 1 — the scaffold's grant goes wide** (`DispatchOutboundHandler::
// internal_scope()` → `None`, i.e. `default_handler_self_grant()`):
//
//     8 passed; 1 failed
//     FAILED  the_shipped_narrow_scaffold_grant_refuses_an_out_of_scope_sub_dispatch
//
// The out-of-scope `not-echo` sub-dispatch **succeeds** — which is not a bug in
// the gate, it is §7a.1's own argument reproduced on the wire: a wide grant
// legitimately covers the request, so the compose reading and the bypass reading
// return the same answer and no probe can separate them. Every other row,
// including the positive control, stays green.
//
// **Mutation 2 — the pre-E1 F67 bypass restored** (`if relax_peers { return
// true }` ahead of the ceiling match in `outbound_sub_dispatch_authorized`):
//
//     6 passed; 3 failed
//     FAILED  the_shipped_narrow_scaffold_grant_refuses_an_out_of_scope_sub_dispatch
//     FAILED  a_target_minted_credential_does_not_lift_a_handler_grant_that_does_not_cover_the_op
//     FAILED  a_credential_does_not_substitute_for_a_handler_grant_that_is_absent
//
// **The two mutations are not interchangeable, and the difference between their
// reddened SETS is what tells the two causes apart.** go's F63 check says so in
// its own failure message — an out-of-scope success is *either* a code bypass
// *or* a non-narrow grant — and from outside a single red row cannot say which.
// From in here it can: a wide grant reddens exactly one row, because it changes
// what is authorized and not who authorizes it; a bypass reddens three, because
// it removes the ceiling for every row whose two authority sources DISAGREE.
// Reporting "the F63 row went red" without the cardinality would be the
// mislabeling this arc has already paid for twice.
//
// The positive control (`..._still_admits_the_reentry_contract_op`) stays green
// under both, which is what makes either red attributable at all.
//
// **Mutation 3 — the E3 multi-granter fail-closed neutered** (`if false &&
// matches!(root_fields.granter, Granter::Multi(_))` in
// `presented_credential_relaxes_peers`):
//
//     10 passed; 1 failed
//     FAILED  a_multi_sig_root_credential_is_refused_over_the_wire
//
// `a_single_sig_root_over_the_identical_request_succeeds` stayed green, which is
// the only reason that red is attributable: it says the credential family is
// valid-and-covering at this seat and the granter form was the whole difference.
// A deny-only E3 row without it would have gone green cohort-wide against a
// credential that was simply broken (§2.4b).
