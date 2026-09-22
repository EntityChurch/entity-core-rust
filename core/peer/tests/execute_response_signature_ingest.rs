//! §6.5 envelope-`included` signature ingestion on **any received envelope** —
//! 0.8.2.19 / E4, driven over the `EXECUTE_RESPONSE` carrier.
//!
//! §6.5's ingestion was written for the inbound EXECUTE, then extended once
//! (0.8.2.18 / D7) to the connect/authenticate response — the **initial-grant**
//! carrier — leaving the **runtime** one unbound. §6.2 names which carrier is
//! the deliberate one: the capability handler is *"the runtime entry point for
//! in-band capability management, while §4.4 covers initial-grant delivery"*,
//! and its `request`/`delegate` result envelope carries the same three entities
//! D7 was about — the issued token, its detached signature, and the granter
//! identity. An `EXECUTE_RESPONSE` is neither an inbound EXECUTE nor a connect
//! response, so nothing reached it.
//!
//! **The consequence is not cosmetic and it is the reason this is a MUST.** A
//! peer that goes and *acquires* a target-minted credential in order to make a
//! §1.4 presented-authority sub-dispatch acquires it through exactly this call.
//! `collect_chain_bundle` resolves a detached signature **only** through the
//! §3.5 invariant pointer path, so an unbound signature makes every chain
//! rooted at that credential unverifiable **locally** — `MissingSignature` on a
//! credential the peer is holding. That is verbatim the defect the
//! connect-response ingest closed one surface earlier, and it hides for the
//! same reason: the far side verifies against its own store, where its own
//! signature IS bound, so every cross-peer dispatch keeps working.
//!
//! **Mutation RUN, and it measured the defect rather than the test.** Deleting
//! the `resp.included` ingest block in `connection.rs`'s remote branch takes
//! the binding assertion to `left: None` — i.e. before E4 that path bound
//! nothing at all, which is the defect, not a weaker form of it.
//!
//! **What this test asserts, and why not the status code.** A `200` from
//! `system/capability:request` says the far peer minted a token; it says
//! nothing about what this peer did with the response. The assertion is on the
//! **local index binding** at `/{A}/system/signature/{token_hash}` — a value
//! only the ingestion path can produce here, because the token was minted at A
//! and this peer has never seen it before.

#![cfg(feature = "capability-handler")]

use entity_capability::{GrantEntry, IdScope, PathScope};
use entity_crypto::Keypair;
use entity_entity::Entity;
use entity_peer::{transport, PeerBuilder};

fn wildcard_policy() -> Vec<(String, Vec<GrantEntry>)> {
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

#[tokio::test]
async fn a_capability_minted_in_an_execute_response_lands_with_its_signature_bound() {
    use transport::{MemoryConnector, MemoryListener, MemoryTransportRegistry};

    let registry = MemoryTransportRegistry::new();

    // --- A: the minter. Runs `system/capability` and hands out grants.
    let a = PeerBuilder::new()
        .keypair(Keypair::from_seed([0x4au8; 32]))
        .with_seed_policy(wildcard_policy())
        .build()
        .expect("minter peer builds");
    let a_pid = a.peer_id().to_string();
    let listener = MemoryListener::bind(a_pid.clone(), registry.clone()).expect("bind");
    let a_shared = a.shared();
    a.start_engines(&a_shared);
    let a_shared_clone = a_shared.clone();
    let a_handle = tokio::spawn(async move {
        let _ = entity_peer::server::run(listener, a_shared_clone).await;
    });
    tokio::task::yield_now().await;

    // --- B: the acquirer. This is the peer whose local index must end up
    //     holding the signature, and it has never seen the token before.
    let b = PeerBuilder::new()
        .keypair(Keypair::from_seed([0x4bu8; 32]))
        .connector(std::sync::Arc::new(MemoryConnector::new(registry.clone())))
        .with_seed_policy(wildcard_policy())
        .build()
        .expect("acquirer peer builds");
    let b_shared = b.shared();
    b.start_engines(&b_shared);
    assert_eq!(
        b.connect_to(&format!("memory://{}", a_pid))
            .await
            .expect("B dials A"),
        a_pid
    );

    // §6.2 `request`: ask A for a narrow grant over its own tree.
    let grants = [GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec![format!("/{}/data/*", a_pid)]),
        operations: IdScope::new(vec!["get".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];
    let params = Entity::new(
        "system/capability/request",
        entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("grants"),
            entity_ecf::Value::Array(
                grants
                    .iter()
                    .map(entity_capability::encode_grant_entry)
                    .collect(),
            ),
        )])),
    )
    .unwrap();

    let res = b
        .execute(
            &format!("entity://{}/system/capability", a_pid),
            "request",
            params,
        )
        .await
        .expect("the request completes");
    assert_eq!(
        res.status,
        200,
        "A mints the grant: {:?}",
        String::from_utf8_lossy(&res.result.data)
    );

    // The three §6.2 result entities came back on the EXECUTE_RESPONSE.
    let token = res
        .included
        .values()
        .find(|e| e.entity_type == "system/capability/token")
        .expect("the response carries the issued token")
        .clone();
    let sig = res
        .included
        .values()
        .find(|e| e.entity_type == entity_entity::TYPE_SIGNATURE)
        .expect("and its detached signature")
        .clone();

    // **The claim.** The signature is bound in B's OWN index at the §3.5
    // invariant pointer path, in A's namespace (A is the signer). Only the
    // ingestion path can have put it there — B did not mint this token and
    // never saw it before this call.
    let bound = b_shared
        .location_index
        .get(&entity_hash::invariant_signature_path(
            &a_pid,
            &token.content_hash,
        ));
    assert_eq!(
        bound,
        Some(sig.content_hash),
        "§6.5 (0.8.2.19 / E4): the signature over a capability issued in an \
         EXECUTE_RESPONSE MUST be bound at the §3.5 invariant pointer path on \
         receipt. Unbound, `collect_chain_bundle` cannot resolve it and every \
         chain rooted at this credential is locally unverifiable — the exact \
         `MissingSignature` the connect-response ingest fixed one surface \
         earlier."
    );

    // Control on the same claim: an assertion about a *binding* is worth
    // nothing if the entity was already reachable by some other route, because
    // then a reader cannot tell ingestion from a store that happened to have
    // it. Assert the token itself also landed in content — the same phase-1
    // pass — and that the peer id in the path is A's, not B's, which is the
    // one field a naive ingest keyed on "the local peer" would get wrong.
    assert!(
        b_shared.content_store.has(&sig.content_hash),
        "the signature entity itself is persisted, not just pointed at"
    );
    assert!(
        b_shared
            .location_index
            .get(&entity_hash::invariant_signature_path(
                &b.peer_id().to_string(),
                &token.content_hash
            ))
            .is_none(),
        "and it is bound under the SIGNER's namespace (A), never the \
         receiver's — the invariant path is `/{{signer}}/system/signature/...`"
    );

    a_handle.abort();
}
