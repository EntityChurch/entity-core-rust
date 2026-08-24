//! EXTENSION-SIGNALING §4/§5 — the rendezvous node mounted on a
//! **general-purpose peer**, which is what `entity-peer peer start
//! --signaling-node` produces.
//!
//! Why this file exists. The node role measures 7/7 against the Go oracle, but
//! that is a live cross-impl measurement of a host-native peer, not a
//! regression guard — and until `validate-complete.sh` forwards
//! `-signaling-node` for `--type rust` it was not even reachable from the
//! suite. Everything else that covers signaling covers a *different*
//! composition: `entity-signaling`'s own tests drive the handler directly,
//! `cmd/entity-signaling-node`'s tests build a peer that serves the one
//! handler, and `carrier.rs`'s rendezvous test builds the same bare node. None
//! of them stand up a peer with the ordinary handler set *and* the node on it.
//!
//! That composition is exactly where the 2026-08-08 regression lived: mounting
//! the node was fine, and the `system/capability/policy/default` entry seeded
//! alongside it took the `capability` category from 13/13 to 7 P / 6 F. A
//! signaling-only test cannot see that, because a node serving one handler has
//! no other capability to request. Both halves are asserted here, in one peer.
#![cfg(all(
    feature = "signaling",
    feature = "capability-handler",
    not(target_arch = "wasm32")
))]

use std::collections::HashMap;
use std::sync::Arc;

use entity_capability::GrantEntry;
use entity_crypto::{IdentityKeypair, Keypair};
use entity_entity::Entity;
use entity_peer::{remote, server, transport::Connector, transport::TcpConnector, PeerBuilder};

/// The one identity that dials in these tests.
fn caller_keypair() -> IdentityKeypair {
    IdentityKeypair::Ed25519(Keypair::from_seed([200u8; 32]))
}

/// Stand up a general-purpose peer carrying the signaling node: the full
/// default handler set, plus the node installed through the public
/// `PeerBuilder::handler` seam — the same construction
/// `peer start --signaling-node` performs.
///
/// `extra_policy` lets a test seed additional §6.9a entries, which is how the
/// second test re-creates the reversed regression.
///
/// **Admission is `debug_open_grants`, and that is load-bearing, not laziness.**
/// It is what `peer-manager` passes (`--debug-grants`, unconditionally) and so
/// the posture the 13/13 → 7 P / 6 F regression was measured under. It is also
/// the only admission that leaves the §6.2 policy lookup *unsatisfied* for this
/// caller: `debug_open_grants` is a connection-path union only
/// (`assemble_inbound_grants`) and writes no policy entry, so a
/// `capability:request` still falls through hex → Base58 → `default`.
///
/// Admitting the caller with a per-grantee `with_seed_policy` entry instead —
/// the tidier, non-deprecated shape — makes this file **unable to catch the bug
/// it exists for**, because the per-grantee entry is found first and the
/// `default` fallback is never consulted. That was the first version of this
/// test, and re-introducing the regression under it changed nothing.
async fn start_node_peer(
    seed: u8,
    extra_policy: Vec<(String, Vec<GrantEntry>)>,
) -> (String, u16, tokio::task::JoinHandle<()>) {
    let keypair = IdentityKeypair::Ed25519(Keypair::from_seed([seed; 32]));
    let peer_id = keypair.peer_id().to_string();
    let endpoint = format!("127.0.0.1:node-{}", seed);

    let core = Arc::new(entity_signaling::SignalingCore::new(endpoint));
    let peer = PeerBuilder::new()
        .identity_keypair(keypair)
        .config(entity_peer::PeerConfig {
            debug_open_grants: true,
            ..Default::default()
        })
        .listen_addr("127.0.0.1:0")
        .with_seed_policy(extra_policy)
        .handler(Arc::new(entity_signaling::SignalingHandler::new(
            core,
            peer_id.as_str(),
        )))
        .build()
        .expect("peer with the node mounted builds");

    let listener = peer.listen().await.expect("peer listens");
    let port = listener.socket_addr().port();
    let shared = peer.shared();
    peer.start_engines(&shared);
    let handle = tokio::spawn(async move {
        let _ = server::run(listener, shared).await;
    });
    (peer_id, port, handle)
}

/// `advertise` takes no params — the same empty-map entity
/// `SignalingClient::advertise` sends.
fn empty_params() -> Entity {
    Entity::new(
        "system/signaling/empty",
        entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![])),
    )
    .expect("empty params entity")
}

/// Dial the node and run one `system/signaling` verb over the wire.
async fn execute_against(
    node_peer_id: &str,
    port: u16,
    handler_pattern: &str,
    operation: &str,
    params: Entity,
) -> (u32, Entity) {
    let caller = caller_keypair();
    let transport = TcpConnector
        .connect(&format!("127.0.0.1:{}", port))
        .await
        .expect("dial node");
    let conn = remote::perform_connect(transport, &caller, entity_hash::HASH_ALGORITHM_SHA256)
        .await
        .expect("handshake with node");
    let uri = format!("/{}/{}", node_peer_id, handler_pattern);
    // `resource: None` is load-bearing on a signaling verb — a resource target
    // there is a 403 that reads as "not granted" (see `carrier.rs`'s module doc).
    let resp = remote::send_execute(
        &conn,
        &caller,
        &uri,
        operation,
        &params,
        None,
        None,
        None,
        &HashMap::new(),
        None,
    )
    .await
    .expect("execute reaches the handler");
    (resp.status, resp.result)
}

/// §4 `advertise` answers on a peer that is not a dedicated node — the seam
/// property PROPOSAL-CONNECTION-NODE §3 makes the deliverable, pinned in CI.
///
/// A 501 here means the handler never registered (the dispatch-index binding or
/// the interface entity the `handler()` seam mints); a 403 means it registered
/// but admission does not reach it.
#[tokio::test]
async fn a_general_purpose_peer_with_the_node_mounted_answers_advertise() {
    let (peer_id, port, handle) = start_node_peer(31, vec![]).await;

    let empty = empty_params();
    let (status, result) = execute_against(
        &peer_id,
        port,
        entity_signaling::PATTERN,
        entity_signaling::OP_ADVERTISE,
        empty,
    )
    .await;

    assert_eq!(
        status, 200,
        "§4 advertise MUST answer 200 on a general-purpose peer carrying the \
         node — 501 means the handler never registered, 403 means admission \
         never reached it"
    );
    let ad = entity_signaling::data::advertisement_from_params(&result.data)
        .expect("advertise result decodes as a §4 advertisement");
    assert!(
        !ad.endpoint.is_empty(),
        "the advertisement MUST carry the node's endpoint — a peer selecting \
         from a pool weighs over these bytes (§3.1.1)"
    );

    handle.abort();
}

/// Mounting the node MUST NOT narrow anything else on the peer.
///
/// This is the regression `0de80f7` shipped and `703bb7b` reversed, in the only
/// composition that can express it. Seeding `system/capability/policy/default`
/// with the node's three verbs reads as purely additive — and is, on the
/// connection path, where `assemble_inbound_grants` unions it on as a floor.
/// On the §6.2 `request` path the same entry is the attenuation *ceiling*, so a
/// signaling-only `default` 403s every unrelated capability request on the
/// peer. Measured: `capability` 13/13 → 7 P / 6 F, all six behind a
/// `request_returns_grant` 403.
///
/// Assert the two together: the node answers, AND a §6.2 request for an
/// unrelated handler still mints. Either alone passes the broken build.
#[tokio::test]
async fn mounting_the_node_does_not_cap_unrelated_capability_requests() {
    let (peer_id, port, handle) = start_node_peer(32, vec![]).await;

    // The node answers — otherwise the second assertion is vacuous.
    let empty = empty_params();
    let (signaling_status, _) = execute_against(
        &peer_id,
        port,
        entity_signaling::PATTERN,
        entity_signaling::OP_ADVERTISE,
        empty,
    )
    .await;
    assert_eq!(signaling_status, 200, "precondition: the node answers");

    // A §6.2 request for a scope that has nothing to do with signaling. Under
    // the reversed regression this is the 403.
    let req = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
        entity_ecf::Value::Text("grants".into()),
        entity_ecf::Value::Array(vec![entity_ecf::Value::Map(vec![
            (
                entity_ecf::Value::Text("handlers".into()),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::Value::Text("include".into()),
                    entity_ecf::Value::Array(vec![entity_ecf::Value::Text("system/tree".into())]),
                )]),
            ),
            (
                entity_ecf::Value::Text("operations".into()),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::Value::Text("include".into()),
                    entity_ecf::Value::Array(vec![entity_ecf::Value::Text("get".into())]),
                )]),
            ),
            (
                entity_ecf::Value::Text("resources".into()),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::Value::Text("include".into()),
                    entity_ecf::Value::Array(vec![entity_ecf::Value::Text(format!(
                        "/{}/system/content/public/*",
                        peer_id
                    ))]),
                )]),
            ),
        ])]),
    )]));
    let params = Entity::new("system/protocol/params", req).expect("request params entity");
    let (cap_status, _) =
        execute_against(&peer_id, port, "system/capability", "request", params).await;

    assert_eq!(
        cap_status, 200,
        "a §6.2 capability request unrelated to signaling MUST still mint on a \
         peer carrying the node — a 403 here means a narrow policy entry became \
         the request CEILING for the whole peer, which is what seeding \
         `policy/default` alongside the node did"
    );

    handle.abort();
}
