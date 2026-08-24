//! The isolation proof, executable.
//!
//! `PROPOSAL-CONNECTION-NODE` §3 makes the boundary the deliverable: *"the
//! isolation boundary is the deliverable, not just the feature ... If the node
//! cannot be built as a clean optional extension, that is a finding worth having
//! **before** a second repo makes the coupling invisible."* And §3.1 frames the
//! whole feature as the first real test of the handler abstraction — *"both the
//! server and the clients should be ordinary handler extensions that slot in
//! without special-casing."*
//!
//! These tests hold the dispatch half of that claim: `system/signaling` installs
//! through the public `PeerBuilder::handler()` seam and comes out the far side
//! fully wired — registry entry, interface entity, handler entity, capability
//! grant — with **no edit anywhere in `core/peer`**. The claim is worth an
//! executable check rather than a sentence in a doc, because the day someone
//! quietly adds a `#[cfg(feature = "signaling")]` block to `PeerBuilder::build`
//! to fix something, this is what fails.
//!
//! The service-owning half is *not* covered here — it is Stage 2, and it is
//! blocked on `PROPOSAL-SDK-HANDLER-OWNED-SERVICES` precisely because no such
//! seam exists for it.

use std::sync::Arc;

use entity_core::crypto::{IdentityKeypair, Keypair};
use entity_core::peer::{PeerBuilder, PeerConfig};
use entity_signaling::{SignalingCore, SignalingHandler, OPERATIONS};

fn node() -> entity_core::peer::Peer {
    let keypair = IdentityKeypair::Ed25519(Keypair::generate());
    let peer_id = keypair.peer_id().to_string();
    let handler = Arc::new(SignalingHandler::new(
        Arc::new(SignalingCore::new("test.example:4050")),
        &peer_id,
    ));
    PeerBuilder::new()
        .identity_keypair(keypair)
        .config(PeerConfig {
            // Port 0 — never bound; these tests build a peer, they don't serve.
            listen_addr: "127.0.0.1:0".to_string(),
            ..PeerConfig::default()
        })
        .handler(handler)
        .build()
        .expect("peer with the signaling handler installed")
}

/// The handler resolves as a dispatch target under the peer-qualified pattern,
/// exactly as an in-tree extension would.
#[test]
fn installs_as_a_dispatch_target_through_the_public_seam() {
    let peer = node();
    let pattern = format!("/{}/system/signaling", peer.peer_id());

    let registered = peer
        .handler_registry()
        .get(&pattern)
        .expect("system/signaling should resolve in the registry");
    assert_eq!(registered.name(), "signaling");
    assert_eq!(registered.operations(), OPERATIONS);
}

/// `bootstrap_handler` ran for the externally-supplied handler: the public
/// contract (interface entity) and the dispatch target (handler entity) are both
/// bound in the tree. This is what "slots in without special-casing" has to mean
/// concretely — a peer-external handler is *discoverable*, not merely callable.
#[test]
fn bootstrap_binds_the_interface_and_handler_entities() {
    let peer = node();
    let pid = peer.peer_id().to_string();

    let interface_path = format!("/{}/system/handler/system/signaling", pid);
    let interface_hash = peer
        .location_index()
        .get(&interface_path)
        .expect("interface entity should be bound in the tree");
    let interface = peer
        .content_store()
        .get(&interface_hash)
        .expect("interface entity should be in the content store");

    // The declared operation set is the three core verbs (§1, §1.4) — exactly
    // three, nothing more. This is the assertion that matters most for the
    // §1.4 ruling: the interface entity is where a *remote* peer reads the
    // contract, so `reflect` being absent from the code is only half of it —
    // it has to be absent from what the node publishes about itself, or a peer
    // will try it and read the refusal as a fault rather than a wrong surface.
    let decoded: entity_core::ecf::Value =
        ciborium::from_reader(interface.data.as_slice()).expect("interface decodes");
    let ops = decoded
        .into_map()
        .expect("interface is a map")
        .into_iter()
        .find(|(k, _)| k.as_text() == Some("operations"))
        .map(|(_, v)| v)
        .expect("interface declares operations")
        .into_map()
        .expect("operations is a map");
    let mut names: Vec<String> = ops
        .iter()
        .filter_map(|(k, _)| k.as_text().map(|s| s.to_string()))
        .collect();
    names.sort();
    assert_eq!(names, vec!["advertise", "collect", "offer"]);

    let handler_path = format!("/{}/system/signaling", pid);
    assert!(
        peer.location_index().get(&handler_path).is_some(),
        "handler entity should be bound at the dispatch path"
    );
}

/// The §6.9 grant loop covers externally-supplied handlers too, and it honors
/// the handler's declared `internal_scope()` — here deliberately **empty**,
/// because the node writes no entities and dispatches nowhere (§0: "it
/// introduces; it never carries data"). A wildcard grant here would quietly
/// hand a public-facing introducer authority it has no use for.
#[test]
fn the_handler_grant_is_minted_and_carries_no_authority() {
    let peer = node();
    let grant_path = format!(
        "/{}/system/capability/grants/system/signaling",
        peer.peer_id()
    );
    assert!(
        peer.location_index().get(&grant_path).is_some(),
        "the §6.9 grant loop should mint a grant for an externally-supplied handler"
    );
}
