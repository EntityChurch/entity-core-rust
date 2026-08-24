//! **The admission model — the half `live_rendezvous.rs` could not test.**
//!
//! That file seeds a wildcard so its subject stays the rendezvous. The cost is
//! that it authorizes *everything*, so it says nothing about who may reach the
//! surface — and that blind spot shipped: `cmd/entity-signaling-node` installed
//! **no** seed policy at all, and no Rust-side run ever noticed, because no Rust
//! test ever connected to a node built the way the binary builds one.
//!
//! The go and py clients found it on their first attempt at the
//! `PROPOSAL-CONNECTION-NODE` §6 gate, independently, within a day of each other:
//! every call returned 403 before reaching a verb. The §4.4 floor a connecting
//! peer receives is `system/tree:get` (on `system/type/*` + `system/handler/*`)
//! plus `system/capability:request`, and `request` is **pure attenuation** — it
//! can only narrow authority the caller already holds — so there was no path from
//! the floor to `system/signaling` and no flag, config, or file to add one.
//!
//! This file is the regression that keeps that closed. It asserts three things
//! the wildcard harness structurally cannot:
//!
//! 1. an unprivileged foreign peer, under the **narrow** grant the binary seeds,
//!    can complete all three verbs;
//! 2. that same grant does **not** widen into anything else on the node;
//! 3. with no seed policy — the shipped default, and still the default posture —
//!    the surface refuses that peer.
//!
//! Point 3 is the one worth keeping honest about: the closed default is
//! **deliberate** (§2.1 — the wrapped surface's admission control *is* the
//! capability grant, and the open-to-strangers posture belongs to the unwrapped
//! listener, whose protocol is unwritten). What was defective was that no posture
//! could be expressed at all. So this asserts the refusal *as intended
//! behaviour*, next to the flag that lifts it.

use std::sync::Arc;

use entity_capability::GrantEntry;
use entity_core::crypto::{IdentityKeypair, Keypair};
use entity_core::peer::transport::Connector;
use entity_core::peer::{remote, server, transport, PeerBuilder};
use entity_signaling::{
    key, signaling_seed_grants, CollectRequest, OfferRequest, SignalingCore, SignalingHandler,
    LOBBY_DEFAULT, OPERATIONS,
};

const STATUS_OK: u32 = 200;
const STATUS_FORBIDDEN: u32 = 403;

struct LiveNode {
    peer_id: String,
    port: u16,
    core: Arc<SignalingCore>,
    _handle: tokio::task::JoinHandle<()>,
}

/// Stand up a node with an explicit seed policy — **the binary's construction
/// path**, parameterized by exactly the thing the binary's `--open` / `--grant`
/// flags decide. Pass `vec![]` for the shipped default.
async fn start_node(seed: u8, policy: Vec<(String, Vec<GrantEntry>)>) -> LiveNode {
    let keypair = IdentityKeypair::Ed25519(Keypair::from_seed([seed; 32]));
    let peer_id = keypair.peer_id().to_string();
    let core = Arc::new(SignalingCore::new(format!("test-node:{}", seed)));
    let handler = Arc::new(SignalingHandler::new(core.clone(), &peer_id));

    let peer = PeerBuilder::new()
        .identity_keypair(keypair)
        .listen_addr("127.0.0.1:0")
        .with_seed_policy(policy)
        .handler(handler)
        .build()
        .expect("node builds");

    let listener = peer.listen().await.expect("node listens");
    let port = listener.socket_addr().port();
    let shared = peer.shared();
    peer.start_engines(&shared);
    let handle = tokio::spawn(async move {
        let _ = server::run(listener, shared).await;
    });

    LiveNode {
        peer_id,
        port,
        core,
        _handle: handle,
    }
}

/// A stranger: a peer the node has never met, holding nothing but what the
/// handshake gives it. This is what a go or py client is.
struct Stranger {
    keypair: IdentityKeypair,
    conn: remote::RemoteConnection,
    node_peer_id: String,
}

impl Stranger {
    async fn connect(node: &LiveNode, seed: u8) -> Self {
        let keypair = IdentityKeypair::Ed25519(Keypair::from_seed([seed; 32]));
        let conn = remote::perform_connect(
            transport::TcpConnector
                .connect(&format!("tcp://127.0.0.1:{}", node.port))
                .await
                .expect("dial node"),
            &keypair,
            entity_hash::HASH_ALGORITHM_SHA256,
        )
        .await
        .expect("handshake with node");

        Self {
            keypair,
            conn,
            node_peer_id: node.peer_id.clone(),
        }
    }

    /// Dispatch against an arbitrary handler on the node and return the status —
    /// deliberately not asserting success, since refusal is half this file's
    /// subject.
    async fn execute(
        &self,
        handler_pattern: &str,
        operation: &str,
        params: entity_entity::Entity,
    ) -> u32 {
        remote::send_execute(
            &self.conn,
            &self.keypair,
            &format!("/{}/{}", self.node_peer_id, handler_pattern),
            operation,
            &params,
            None,
            None,
            None,
            &std::collections::HashMap::new(),
            None,
        )
        .await
        .expect("dispatch reaches the node")
        .status
    }

    /// Same, but carrying an explicit resource target — the shape that bit the
    /// Go client. See `a_resource_target_is_refused_by_the_narrow_grant`.
    async fn execute_with_resource(
        &self,
        handler_pattern: &str,
        operation: &str,
        params: entity_entity::Entity,
        targets: Vec<String>,
    ) -> u32 {
        let resource = entity_capability::ResourceTarget {
            targets,
            exclude: vec![],
        };
        remote::send_execute(
            &self.conn,
            &self.keypair,
            &format!("/{}/{}", self.node_peer_id, handler_pattern),
            operation,
            &params,
            Some(&resource),
            None,
            None,
            &std::collections::HashMap::new(),
            None,
        )
        .await
        .expect("dispatch reaches the node")
        .status
    }

    async fn offer(&self, k: entity_signaling::RendezvousKey, message: &[u8]) -> u32 {
        let params = OfferRequest {
            rendezvous_key: k,
            message: message.to_vec(),
        }
        .to_entity()
        .expect("encode offer");
        self.execute("system/signaling", "offer", params).await
    }

    async fn collect(&self, k: entity_signaling::RendezvousKey) -> u32 {
        let params = CollectRequest { rendezvous_key: k }
            .to_entity()
            .expect("encode collect");
        self.execute("system/signaling", "collect", params).await
    }

    async fn advertise(&self) -> u32 {
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![]));
        let params =
            entity_entity::Entity::new("system/signaling/empty", data).expect("empty params");
        self.execute("system/signaling", "advertise", params).await
    }
}

fn open_policy() -> Vec<(String, Vec<GrantEntry>)> {
    vec![("default".to_string(), signaling_seed_grants())]
}

/// **The regression.** With the shipped default — no seed policy — a stranger is
/// refused on every verb.
///
/// This is what go and py hit. It is asserted rather than fixed away because the
/// closed default is intended (§2.1); what was missing was any way to open it.
/// Note the refusal is a **403 on all three**, including `advertise`, which is
/// the call both clients tried first.
#[tokio::test]
async fn a_node_with_no_seed_policy_refuses_a_stranger() {
    let node = start_node(61, vec![]).await;
    let stranger = Stranger::connect(&node, 62).await;

    assert_eq!(stranger.advertise().await, STATUS_FORBIDDEN);
    assert_eq!(
        stranger.offer(key::tag_key("chess"), b"candidates").await,
        STATUS_FORBIDDEN
    );
    assert_eq!(
        stranger.collect(key::tag_key("chess")).await,
        STATUS_FORBIDDEN
    );

    // And nothing reached the core — the refusal is at the capability layer,
    // upstream of any verb. This is why the clients' 403 was evidence their
    // whole client path worked: connect, handshake, addressing, and a
    // well-formed EXECUTE all had to succeed to earn it.
    assert_eq!(node.core.key_count(), 0);
}

/// Under the grant `--open` seeds, the same stranger completes all three verbs.
#[tokio::test]
async fn the_seeded_grant_admits_a_stranger_to_all_three_verbs() {
    let node = start_node(63, open_policy()).await;
    let stranger = Stranger::connect(&node, 64).await;
    let k = key::lobby_key(LOBBY_DEFAULT);

    assert_eq!(stranger.advertise().await, STATUS_OK);
    assert_eq!(stranger.offer(k, b"candidates").await, STATUS_OK);
    assert_eq!(stranger.collect(k).await, STATUS_OK);

    // The offer actually landed — a 200 that deposited nothing would be a
    // worse result than the 403.
    assert_eq!(node.core.key_count(), 1);
    assert_eq!(
        node.core.collect(&k, now_ms()),
        vec![b"candidates".to_vec()]
    );
}

/// The grant covers **exactly** the three verbs and does not widen.
///
/// # `reflect`'s status depends on the grant shape, and that is worth knowing
///
/// Here `reflect` is a **403**, not the 400 `live_rendezvous.rs` asserts. Both
/// are correct and neither is a bug: the capability check runs *before* dispatch,
/// so an enumerated grant refuses an operation it does not name, while that
/// file's wildcard grant (`operations: ["*"]`) authorizes it through to the
/// handler, which then answers `unknown_operation`.
///
/// It matters cross-impl because it changes what a client sees for the same call
/// against the same node depending on how the operator seeded it. §1.4's point
/// stands — the *handler* does not serve `reflect`, and the 400 proves it — but a
/// client MUST NOT treat 400 as the only signal that `reflect` is unavailable on
/// the wrapped surface. Against a `--open` node it is a 403, and the honest
/// reading of that 403 is "you were not granted it", which is also true.
#[tokio::test]
async fn the_grant_does_not_widen_beyond_the_three_verbs() {
    let node = start_node(65, open_policy()).await;
    let stranger = Stranger::connect(&node, 66).await;

    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![]));
    let params = entity_entity::Entity::new("system/signaling/empty", data).expect("params");

    assert_eq!(
        stranger
            .execute("system/signaling", "reflect", params.clone())
            .await,
        STATUS_FORBIDDEN,
        "an enumerated grant refuses reflect at the capability layer, before the \
         handler's unknown-operation branch — see this test's doc comment"
    );

    // A handler the grant never mentioned stays refused. `system/tree:put` is
    // the sharp case: `get` *is* in the §4.4 floor, so this proves the refusal
    // tracks the operation rather than the handler being unreachable.
    assert_eq!(
        stranger.execute("system/tree", "put", params).await,
        STATUS_FORBIDDEN,
        "the signaling grant must not spill onto other handlers"
    );
}

/// **The resource-target trap** — a client that attaches a resource target to a
/// signaling EXECUTE is refused, even holding the grant.
///
/// Named by the Go client's 2026-07-30 report (Python avoids it; Go hit it). This
/// pins the behaviour rather than assuming it, and the answer is: the seeded
/// grant's resource scope is **empty**, `check_resource_scope` denies any target
/// not covered by the grant's include list, and an empty include covers nothing.
///
/// **Working as intended, and the empty scope stays.** Signaling addresses no
/// tree resource at all — the rendezvous key travels in `params`, the handler
/// reads and writes nothing, and its `internal_scope` is empty for the same
/// reason. `default_connection_grants`' own `system/capability:request` entry has
/// the identical empty shape. Widening it to `*` to be forgiving would grant
/// resource authority that no signaling verb can use, which is exactly the kind
/// of over-broad grant the narrow-by-design choice exists to avoid.
///
/// So this is a **client rule, and it belongs in the brief**: send no resource
/// target on `offer` / `collect` / `advertise`. The failure is a 403 that looks
/// identical to "not granted", which is why it cost the Go client time.
#[tokio::test]
async fn a_resource_target_is_refused_by_the_narrow_grant() {
    let node = start_node(70, open_policy()).await;
    let stranger = Stranger::connect(&node, 71).await;

    // The same call, twice, differing only in whether a resource target rides
    // along — so the 403 cannot be blamed on anything else.
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![]));
    let params = entity_entity::Entity::new("system/signaling/empty", data).expect("params");

    assert_eq!(
        stranger
            .execute("system/signaling", "advertise", params.clone())
            .await,
        STATUS_OK,
        "no resource target — admitted"
    );
    assert_eq!(
        stranger
            .execute_with_resource(
                "system/signaling",
                "advertise",
                params,
                vec![format!("/{}/system/signaling", node.peer_id)],
            )
            .await,
        STATUS_FORBIDDEN,
        "a resource target is not covered by the grant's empty resource scope"
    );
}

/// A named `--grant <peer-id>` admits that peer and nobody else — the
/// private-device-mesh posture (§2.1), where the grant *is* the point of choosing
/// the wrapped surface over the public one.
#[tokio::test]
async fn a_named_grant_admits_only_that_peer() {
    let invited_keypair = IdentityKeypair::Ed25519(Keypair::from_seed([68u8; 32]));
    let invited_id = invited_keypair.peer_id().to_string();

    let node = start_node(67, vec![(invited_id, signaling_seed_grants())]).await;
    let invited = Stranger::connect(&node, 68).await;
    let uninvited = Stranger::connect(&node, 69).await;

    assert_eq!(invited.advertise().await, STATUS_OK);
    assert_eq!(uninvited.advertise().await, STATUS_FORBIDDEN);
}

/// The seeded grant names every operation the handler declares — so adding a
/// verb without extending the grant fails here rather than in a cross-impl gate.
#[test]
fn the_grant_tracks_the_declared_operation_set() {
    let grants = signaling_seed_grants();
    let ops = &grants[0].operations.include;
    assert_eq!(ops.len(), OPERATIONS.len());
    for op in OPERATIONS {
        assert!(ops.contains(&(*op).to_string()), "grant is missing {}", op);
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
