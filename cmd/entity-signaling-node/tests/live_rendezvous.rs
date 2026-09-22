//! §6 validation gate, steps 1–2 — **exercised live, not stubbed.**
//!
//! `PROPOSAL-CONNECTION-NODE` §6 opens with the CDN-corridor meta-rule: *"none
//! of this is real until exercised live"*. Its gate was **reordered by the
//! 2026-07-28 rulings**, and now reads:
//!
//! 1. **Rendezvous in each mode** — two peers meet and exchange candidates at a
//!    `pair`, `tag`, `secret`, and `lobby` key. *One code path, four derived keys.*
//! 2. **Pool selection converges** — the pool holds **two** node instances and
//!    every impl independently selects the same one for the same key.
//! 3. **Reflect** — Stage 2, and now the unwrapped listener's (§1.4).
//! 4. **Punch** — Stage 2.
//! 5. **A message rides it** — Stage 2.
//!
//! This file holds **steps 1 and 2**, over real TCP with real peers. Steps 3–5
//! are Stage 2, behind `PROPOSAL-SDK-HANDLER-OWNED-SERVICES`.
//!
//! Step 2 gained its second node from the Stage-1 build's own finding: `argmax`
//! over a one-member pool returns that member whatever the weight computes, so
//! the previous single-node gate validated nothing about the selection rule.
//!
//! # Why this file exists when `extensions/signaling/src/tests.rs` already
//! covers the same verbs
//!
//! Those tests drive the handler through a stub dispatcher in-process. That
//! proves the verb logic and nothing about the *system*: no wire encode, no
//! handshake, no capability evaluation, no connection. §6 exists precisely
//! because prose review and same-process tests "do not catch rendezvous-key or
//! punch-timing bugs."
//!
//! Here, each peer:
//!   * dials the node over TCP and completes the real handshake,
//!   * receives a real capability grant from the node's seed policy,
//!   * derives its rendezvous key independently — Alice from her ordering, Bob
//!     from his,
//!   * issues a genuine cross-peer `EXECUTE` whose params are CBOR-encoded,
//!     signed, and decoded by the node.
//!
//! That is the Stage-1 mechanism end to end, minus the deployment.
//!
//! # What it still is not
//!
//! **Same-impl.** Both peers are this Rust code, so a wrong-but-self-consistent
//! §2.2 derivation passes here exactly as it would in a unit test — the whole
//! trap `AGENTS.md` names. **Only the cross-impl run settles the derivation**
//! (`validate-peer -category signaling`, go as oracle). What this file *does*
//! prove is everything around the derivation: the wire shapes survive a real
//! encode/decode, the capability path admits a legitimate caller, and the
//! bucket semantics hold across two independent connections.

use std::sync::Arc;

use entity_capability::{GrantEntry, IdScope, PathScope};
use entity_core::crypto::{IdentityKeypair, Keypair};
use entity_core::peer::transport::Connector;
use entity_core::peer::{remote, server, transport, PeerBuilder};
use entity_signaling::{
    data::CollectResult, key, CollectRequest, OfferRequest, RendezvousKey, SignalingCore,
    SignalingHandler, LOBBY_DEFAULT,
};

/// The node's seed policy: a connecting peer receives a grant covering the
/// signaling verbs. A public introducer wants a broad admission posture on the
/// wrapped surface — the capability gate is what makes this the *private mesh*
/// surface, and an operator narrows it per deployment. Wildcard here keeps the
/// test about rendezvous rather than about grant authoring.
fn wildcard_seed() -> Vec<(String, Vec<GrantEntry>)> {
    vec![(
        "default".to_string(),
        vec![GrantEntry {
            handlers: PathScope::new(vec!["*".into()]),
            resources: PathScope::new(vec!["*".into()]),
            operations: IdScope::new(vec!["*".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        }],
    )]
}

struct LiveNode {
    peer_id: String,
    port: u16,
    /// The string this node is advertised under, and therefore the bytes
    /// §3.1.1 weights over.
    endpoint: String,
    core: Arc<SignalingCore>,
    _handle: tokio::task::JoinHandle<()>,
}

/// Stand up a real signaling node on a real TCP port — the same construction
/// `cmd/entity-signaling-node` uses, including installing the handler through
/// the public `PeerBuilder::handler()` seam.
async fn start_node(seed: u8) -> LiveNode {
    let keypair = IdentityKeypair::Ed25519(Keypair::from_seed([seed; 32]));
    let peer_id = keypair.peer_id().to_string();
    // The advertised endpoint is per-node, because §3.1.1 weights over the
    // endpoint bytes — two nodes sharing one endpoint string would weigh
    // identically and make a two-member pool behave as one.
    let core = Arc::new(SignalingCore::new(format!("test-node:{}", seed)));
    let handler = Arc::new(SignalingHandler::new(core.clone(), &peer_id));

    let peer = PeerBuilder::new()
        .identity_keypair(keypair)
        .listen_addr("127.0.0.1:0")
        .with_seed_policy(wildcard_seed())
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
        endpoint: format!("test-node:{}", seed),
        core,
        _handle: handle,
    }
}

/// A peer that dials the node and speaks to it over the wire.
struct LivePeer {
    keypair: IdentityKeypair,
    conn: remote::RemoteConnection,
    node_uri: String,
}

impl LivePeer {
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
            node_uri: format!("/{}/system/signaling", node.peer_id),
        }
    }

    fn peer_id(&self) -> String {
        self.keypair.peer_id().to_string()
    }

    async fn offer(&self, key: RendezvousKey, message: &[u8]) -> u32 {
        let params = OfferRequest {
            rendezvous_key: key,
            message: message.to_vec(),
        }
        .to_entity()
        .expect("encode offer");
        remote::send_execute(
            &self.conn,
            &self.keypair,
            &self.node_uri,
            "offer",
            &params,
            None,
            None,
            None,
            &empty_chain(),
            None,
        )
        .await
        .expect("offer dispatch")
        .status
    }

    async fn collect(&self, key: RendezvousKey) -> Vec<Vec<u8>> {
        let params = CollectRequest {
            rendezvous_key: key,
        }
        .to_entity()
        .expect("encode collect");
        let resp = remote::send_execute(
            &self.conn,
            &self.keypair,
            &self.node_uri,
            "collect",
            &params,
            None,
            None,
            None,
            &empty_chain(),
            None,
        )
        .await
        .expect("collect dispatch");
        assert_eq!(resp.status, 200, "collect should succeed");
        CollectResult::from_params(&resp.result.data)
            .expect("decode collect-result")
            .messages
    }
}

/// **§6 gate step 2.** Two peers meet at all four key modes over a real
/// connection to a real node.
///
/// The four modes share **one code path exercised with four derived keys, not
/// four features** (§1) — the node is mode-blind and cannot tell them apart.
/// This asserts exactly that: the same offer/collect pair works for every mode,
/// and the node's bucket count equals the number of distinct derived keys.
#[tokio::test]
async fn two_peers_rendezvous_at_all_four_key_modes_over_tcp() {
    let node = start_node(41).await;
    let alice = LivePeer::connect(&node, 42).await;
    let bob = LivePeer::connect(&node, 43).await;

    let (a_pid, b_pid) = (alice.peer_id(), bob.peer_id());

    // Each mode is (alice's key, bob's key) — derived *independently* by each
    // side. For `pair` the two arguments are in opposite order on purpose: the
    // §2.2 sort is what makes them agree, and if it were missing this test is
    // where that shows up as an empty collect.
    let modes: Vec<(&str, RendezvousKey, RendezvousKey)> = vec![
        (
            "pair",
            key::pair_key(&a_pid, &b_pid),
            key::pair_key(&b_pid, &a_pid),
        ),
        ("tag", key::tag_key("chess"), key::tag_key("chess")),
        (
            "secret",
            key::secret_key("Xk7pQ2mR9vT4wL8n"),
            key::secret_key("Xk7pQ2mR9vT4wL8n"),
        ),
        (
            "lobby",
            key::lobby_key(LOBBY_DEFAULT),
            key::lobby_key(LOBBY_DEFAULT),
        ),
    ];

    for (mode, alice_key, bob_key) in &modes {
        let alice_blob = format!("alice-candidates-{}", mode).into_bytes();
        let bob_blob = format!("bob-candidates-{}", mode).into_bytes();

        // Alice deposits. Bob, who derived his key without ever seeing hers,
        // finds it.
        assert_eq!(alice.offer(*alice_key, &alice_blob).await, 200);
        let bob_sees = bob.collect(*bob_key).await;
        assert!(
            bob_sees.contains(&alice_blob),
            "{} mode: bob must find alice's offer at his independently derived key",
            mode
        );

        // Bob answers; both now see both — collect removed nothing (§1.1 pin 1),
        // which is what lets a real handshake poll from both sides.
        assert_eq!(bob.offer(*bob_key, &bob_blob).await, 200);
        let alice_sees = alice.collect(*alice_key).await;
        assert_eq!(alice_sees.len(), 2, "{} mode: both offers live", mode);
        assert!(alice_sees.contains(&bob_blob));
    }

    // Mode-blindness, observed from the node: four distinct derived keys ⇒ four
    // buckets, and the node never learned which mode produced any of them.
    assert_eq!(
        node.core.key_count(),
        4,
        "one bucket per derived key; the node cannot distinguish the modes"
    );
}

/// A retry across a **real** connection is idempotent — the property §1.1 pin 2
/// exists to give, checked where it actually matters: a peer that re-offers
/// after a network timeout must not accumulate duplicates in the bucket its
/// counterpart is polling.
#[tokio::test]
async fn a_retried_offer_over_the_wire_is_idempotent() {
    let node = start_node(44).await;
    let alice = LivePeer::connect(&node, 45).await;
    let k = key::tag_key("retry-room");

    for _ in 0..3 {
        assert_eq!(alice.offer(k, b"same-candidates").await, 200);
    }
    assert_eq!(alice.collect(k).await.len(), 1);
}

/// Two peers on *different* keys never see each other, over the wire. The
/// negative case matters as much as the positive: it is what makes a
/// `secret`-mode key a gate at all, and it is the shape a derivation mismatch
/// takes — an empty collect, no error.
#[tokio::test]
async fn different_keys_do_not_meet() {
    let node = start_node(46).await;
    let alice = LivePeer::connect(&node, 47).await;
    let bob = LivePeer::connect(&node, 48).await;

    alice
        .offer(key::secret_key("alice-secret"), b"alice-candidates")
        .await;
    let bob_sees = bob.collect(key::secret_key("bob-secret")).await;
    assert!(
        bob_sees.is_empty(),
        "a different secret is a different bucket — and this is exactly what a \
         silent §2.2 mismatch looks like: empty, not an error"
    );
}

/// **`reflect` is not served here, by design** (§1.4, ruling 2026-07-28) — and
/// it answers as an ordinary unknown operation, not a distinct refusal.
///
/// This test previously asserted a 501 and was described as "the thing that
/// flips when arch rules." Arch ruled, and it flipped: from *blocked pending
/// plumbing* to *not served here, ever*.
///
/// **The rationale was corrected 2026-07-28 and the ruling stands on better
/// ground.** The original reason given — that the wrapped surface could report
/// only a TCP/WS mapping while the punch needs a UDP one — is wrong for v1:
/// `PROPOSAL-CONNECTIVITY-SIGNALING-AND-PUNCH` §5 sequences **TCP
/// simultaneous-open first**, so the TCP mapping is precisely the one the v1
/// punch needs. The real reason is ownership: `PROPOSAL-NETWORK-REACHABILITY-FACTS`
/// §2.1(a) already owns "how a peer learns its observed address" — an optional
/// `observed_address` field the responder fills on the NETWORK §6.3 HELLO
/// handshake, from any peer, no node involved — so a wrapped `reflect` would be
/// a **second mechanism for a fact that has a canonical home**, which is the
/// defect regardless of which transport it reported.
///
/// The 400 rather than a 501 is the load-bearing part. A 501 would tell a client
/// "this verb exists and this node can't do it *yet*", which invites it to keep
/// a `reflect` path warm for a day that never comes on this surface.
#[tokio::test]
async fn reflect_is_an_unknown_operation_on_the_wrapped_surface() {
    let node = start_node(49).await;
    let alice = LivePeer::connect(&node, 50).await;

    let params = entity_entity::Entity::new(
        "system/signaling/empty",
        entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![])),
    )
    .expect("empty params");

    let resp = remote::send_execute(
        &alice.conn,
        &alice.keypair,
        &alice.node_uri,
        "reflect",
        &params,
        None,
        None,
        None,
        &empty_chain(),
        None,
    )
    .await
    .expect("reflect dispatch reaches the node");

    assert_eq!(
        resp.status, 501,
        "reflect is the unwrapped listener's verb (§1.4); on this surface it is \
         an operation this registered handler does not implement, which IS \
         §3.3's 501 row. This assertion read `400 ... not a 501 placeholder` \
         until 0.8.2.7 ruled the opposite: 501 is not a placeholder status, it \
         is the row for exactly this fact, and 400 told the caller its request \
         was malformed when the request was fine"
    );
}

/// **§6 gate step 2, live: pool selection converges over a two-instance pool.**
///
/// The second node is the whole point, and it is worth being precise about what
/// it buys and what it does not.
///
/// `argmax` over a **one**-member pool returns that member *whatever the weight
/// computes* — so a green single-node gate says nothing at all about §3.1.1, and
/// §1.2's mitigation ("three independently-written clients are a real
/// convergence signal") does not reach the selection rule: three clients
/// converge trivially on a pool of one, no matter what each of them implements.
/// A second instance is a second port on the same box, since the node is
/// stateless by §1.3, so this converts an unvalidatable pin into a validated one
/// for the cost of a config line.
///
/// **What it still does not settle:** both peers here run this same Rust
/// `pool::select`, so their agreement is tautological — a wrong-but-consistent
/// weight function passes exactly as it would in a unit test. What this proves
/// is the half that a same-impl test *can* prove: the construction discriminates
/// (both members own part of the key space), it ignores list order, and the
/// selection genuinely routes the traffic — the unchosen node ends with an empty
/// bucket. The cross-impl run is what settles the bytes.
#[tokio::test]
async fn gate_step_2_pool_selection_converges_over_a_two_instance_pool() {
    use entity_signaling::{pool, PoolMember};

    let node_a = start_node(60).await;
    let node_b = start_node(61).await;
    let advertised = vec![
        PoolMember::new(&node_a.endpoint, 10),
        PoolMember::new(&node_b.endpoint, 10),
    ];

    // (a) The pool discriminates. This is the assertion that is literally
    //     unwriteable against one node, and the reason step 2 changed.
    let mut winners = std::collections::BTreeSet::new();
    for i in 0..64 {
        let k = key::tag_key(&format!("room-{}", i));
        winners.insert(pool::select(&k, &advertised).unwrap().endpoint.clone());
    }
    assert_eq!(
        winners.len(),
        2,
        "each member must own a shard of the key space; got {:?}",
        winners
    );

    // (b) Selection is by endpoint identity, not list position — so an impl that
    //     "converges" by always taking the first advertised member fails here.
    let mut reversed = advertised.clone();
    reversed.reverse();
    for i in 0..32 {
        let k = key::tag_key(&format!("room-{}", i));
        assert_eq!(
            pool::select(&k, &advertised),
            pool::select(&k, &reversed),
            "a reordered advertisement must not move key room-{}",
            i
        );
    }

    // (c) The rendezvous itself routes through the selection. Alice and Bob
    //     derive the pair key from opposite orderings, each runs `select` over
    //     the advertisement, and each dials whatever it returned.
    let a_kp = IdentityKeypair::Ed25519(Keypair::from_seed([62u8; 32]));
    let b_kp = IdentityKeypair::Ed25519(Keypair::from_seed([63u8; 32]));
    let (a_pid, b_pid) = (a_kp.peer_id().to_string(), b_kp.peer_id().to_string());

    let alice_key = key::pair_key(&a_pid, &b_pid);
    let bob_key = key::pair_key(&b_pid, &a_pid);
    let alice_choice = pool::select(&alice_key, &advertised).unwrap();
    let bob_choice = pool::select(&bob_key, &advertised).unwrap();
    assert_eq!(
        alice_choice, bob_choice,
        "both peers of a handshake must meet at the same provider (§2.1)"
    );

    let (chosen, unchosen) = if alice_choice.endpoint == node_a.endpoint {
        (&node_a, &node_b)
    } else {
        (&node_b, &node_a)
    };

    let alice = LivePeer::connect(chosen, 62).await;
    let bob = LivePeer::connect(chosen, 63).await;
    assert_eq!(
        alice.peer_id(),
        a_pid,
        "the dialing peer is the one we weighed"
    );

    assert_eq!(alice.offer(alice_key, b"alice-candidates").await, 200);
    assert!(
        bob.collect(bob_key)
            .await
            .contains(&b"alice-candidates".to_vec()),
        "bob must find alice at the node they independently selected"
    );

    // (d) And the selection is what put it there. If the rendezvous had
    //     succeeded because both peers hardcoded one node, or because selection
    //     silently fell back to a default, this is the assertion that catches
    //     it: the *other* live node never saw a byte.
    assert_eq!(chosen.core.key_count(), 1);
    assert_eq!(
        unchosen.core.key_count(),
        0,
        "the unselected node must hold nothing — otherwise the traffic did not \
         follow the rendezvous hash"
    );
}

/// `send_execute` takes the authority-chain bundle by reference; ordinary
/// dispatches carry none (the connection grant is the authority), so this is the
/// empty map spelled once rather than inferred at six call sites.
fn empty_chain() -> std::collections::HashMap<entity_hash::Hash, entity_entity::Entity> {
    std::collections::HashMap::new()
}

/// **§4 step 2, live.** The candidate exchange that Stage 1 exists to carry:
/// Alice offers a `connect-request`, Bob collects it and answers with a
/// `connect-response`, Alice picks his answer out of the bucket by nonce — all
/// over real TCP, through a node that decoded none of it.
///
/// This is the last Stage-1 link. What follows it is §4 steps 3–5 — measure the
/// carrier RTT, agree a `fire_at`, both sides fire — which is socket work and
/// Stage 2. Note "both sides fire" and *not* "at that instant": §4.1 pins
/// `fire_at` as a **delay from receipt**, not a shared moment, because V7
/// assumes no synchronized clocks. The derivation and encoding ship here
/// (`coordination::punch_delay`); only the firing waits.
#[tokio::test]
async fn candidate_exchange_completes_over_tcp() {
    use entity_signaling::coordination::{
        self, Candidate, CANDIDATE_HOST, CANDIDATE_SRFLX, SUBSTRATE_TCP,
    };

    let node = start_node(51).await;
    let alice = LivePeer::connect(&node, 52).await;
    let bob = LivePeer::connect(&node, 53).await;
    let (a_pid, b_pid) = (alice.peer_id(), bob.peer_id());
    let k = key::pair_key(&a_pid, &b_pid);

    let alice_candidates = vec![
        Candidate::new(CANDIDATE_HOST, SUBSTRATE_TCP, "192.168.1.5:4040"),
        Candidate::new(CANDIDATE_SRFLX, SUBSTRATE_TCP, "203.0.113.7:51820"),
    ];
    let bob_candidates = vec![
        Candidate::new(CANDIDATE_HOST, SUBSTRATE_TCP, "10.0.0.9:4040"),
        Candidate::new(CANDIDATE_SRFLX, SUBSTRATE_TCP, "198.51.100.4:33445"),
    ];

    // Alice initiates.
    let nonce = coordination::Nonce::generate();
    let request = coordination::ConnectRequest {
        initiator: a_pid.clone(),
        candidates: alice_candidates.clone(),
        nonce: nonce.clone(),
    };
    assert_eq!(
        alice
            .offer(k, &coordination::to_blob(&request.to_entity().unwrap()))
            .await,
        200
    );

    // Bob collects, finds her request (not his own), answers.
    let bob_bucket: Vec<_> = bob
        .collect(k)
        .await
        .iter()
        .map(|b| coordination::classify_collected(b, &k))
        .collect();
    let (seen, signer) =
        coordination::find_request(&bob_bucket, &b_pid).expect("bob finds alice's request");
    assert_eq!(seen.initiator, a_pid);
    assert!(
        signer.is_none(),
        "this test deposits bare on purpose (it drives the client verbs directly, \
         not `punch::initiate`), so it also pins that the bare framing still reads \
         through the node — the migration case a peer on an older build presents"
    );
    assert_eq!(
        seen.candidates, alice_candidates,
        "candidates survive the carrier byte-for-byte"
    );

    let response = coordination::ConnectResponse {
        responder: b_pid.clone(),
        candidates: bob_candidates.clone(),
        nonce: seen.nonce.clone(),
    };
    assert_eq!(
        bob.offer(k, &coordination::to_blob(&response.to_entity().unwrap()))
            .await,
        200
    );

    // Alice collects and picks Bob's answer out by nonce echo.
    let alice_bucket: Vec<_> = alice
        .collect(k)
        .await
        .iter()
        .map(|b| coordination::classify_collected(b, &k))
        .collect();
    let (answer, _) =
        coordination::find_response(&alice_bucket, &nonce, &a_pid).expect("alice finds the answer");
    assert_eq!(answer.responder, b_pid);
    assert_eq!(answer.candidates, bob_candidates);

    // Both now hold the other's dial plan, ordered host → srflx.
    let plan = coordination::order_for_dialing(&answer.candidates);
    assert_eq!(plan[0].candidate_type, CANDIDATE_HOST);
    assert_eq!(plan[1].candidate_type, CANDIDATE_SRFLX);

    // The node carried two blobs in one bucket and understood neither.
    assert_eq!(node.core.key_count(), 1);
}
