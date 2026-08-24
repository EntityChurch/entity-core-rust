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
    ByValidator,
    /// A granter no one can resolve — not in-band, not in either store. §4.3's
    /// fail-closed MUST still has to bite.
    ByUnresolvableIdentity,
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

/// Drive one full §7a.2a round trip and hand back B's outer response.
async fn dispatch_outbound_roundtrip(granted: Granted) -> entity_handler::HandlerResult {
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
    let cap_granter_hash = match granted {
        Granted::ByValidator => a_identity_hash,
        // A well-formed hash of a `system/peer` entity that exists nowhere —
        // neither peer's store holds it and nothing carries it in-band.
        Granted::ByUnresolvableIdentity => {
            entity_hash::Hash::compute("system/peer", b"granter-nobody-holds")
        }
    };
    let cap = CapabilityToken {
        grants: vec![GrantEntry {
            handlers: PathScope::new(vec!["system/validate/echo".into()]),
            resources: PathScope::new(vec!["*".into()]),
            operations: IdScope::new(vec!["echo".into()]),
            peers: Some(IdScope::all()),
            constraints: None,
            allowances: None,
        }],
        granter: Granter::Single(cap_granter_hash),
        grantee: b_identity_hash,
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let cap_entity = cap.to_entity().expect("cap entity");

    // A signs it (V7 §5.5 detached signature, signer = A's identity hash).
    let sig_bytes = a_shared.keypair.sign(&cap_entity.content_hash.to_bytes());
    let sig_entity = Entity::new(
        entity_entity::TYPE_SIGNATURE,
        entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("algorithm"),
                entity_ecf::text(a_shared.keypair.key_type().label()),
            ),
            (
                entity_ecf::text("signature"),
                entity_ecf::Value::Bytes(sig_bytes),
            ),
            (
                entity_ecf::text("signer"),
                entity_ecf::Value::Bytes(a_identity_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("target"),
                entity_ecf::Value::Bytes(cap_entity.content_hash.to_bytes().to_vec()),
            ),
        ])),
    )
    .expect("signature entity");

    // A's own `system/peer` identity entity — the granter identity the §4.3
    // bundle MUST carry. B has never seen it in its store; it arrives in-band.
    let granter_entity = a_shared
        .content_store
        .get(&a_identity_hash)
        .expect("A holds its own identity entity");

    // --- Params, exactly as the §7a.2a convention lays them out. ECF map key
    // order: by encoded key length, then lexicographic.
    let mut body = Vec::new();
    body.push(0xA6); // 6-item map
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
        &entity_ecf::to_ecf(&entity_ecf::text("echo")),
    );
    put_raw(
        &mut body,
        "reentry_granter",
        &entity_wire::encode_entity(&granter_entity),
    );
    put_raw(
        &mut body,
        "reentry_capability",
        &entity_wire::encode_entity(&cap_entity),
    );
    put_raw(
        &mut body,
        "reentry_cap_signature",
        &entity_wire::encode_entity(&sig_entity),
    );
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
    let resp = dispatch_outbound_roundtrip(Granted::ByValidator).await;

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
    let resp = dispatch_outbound_roundtrip(Granted::ByUnresolvableIdentity).await;

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
