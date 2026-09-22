//! ⛔ **§5.4 byte fidelity across `tree:extract` → `tree:merge`, over the wire,
//! between two peers.**
//!
//! # Why this file exists beside the in-process rows
//!
//! `core/tree`'s `merge_from_an_envelope_preserves_entity_bytes` proves the
//! *handler's* half by building a `HandlerContext` by hand. That is a floor
//! under a vector, not a vector — and here the distinction was not theoretical
//! for even one commit: with `handle_extract` and `handle_merge` both fixed and
//! their own rows green, the defect was **still live on the wire**, because
//! four more layers between the socket and the handler each re-encoded the
//! payload independently, and this vector is the only thing that found them:
//!
//! | layer | what it did |
//! |---|---|
//! | `remote::build_authenticated_execute` | rebuilt `params.data` through `from_reader` + `to_ecf` on every outbound EXECUTE |
//! | `connection::extract_params_entity` | rebuilt it again, the same way, on receipt — **this is every handler's `ctx.params`** |
//! | `connection`'s in-process sub-dispatch | and again on every internal hop |
//! | `protocol::response::parse_execute_response` | rebuilt the **result** entity's `data` while keeping the wire's `content_hash`, so the caller got a self-inconsistent entity |
//!
//! Same shape as `0.8.2.24` N6, and the same lesson: *an in-process row is a
//! floor under a vector, not one.* Note the fourth row's asymmetry —
//! `build_execute_response_full` has always spliced with `encode_entity`, so
//! the write half was right and only the read half was wrong. A round-trip
//! test cannot see that: it is the one shape where encoder and decoder
//! *disagreeing* still produces a self-consistent pair of functions.
//!
//! # Mutations RUN, and what each reddened
//!
//! Every row below was executed against this file; none was predicted. All six
//! redden **this** row and none of them reddens any pre-existing row in the
//! 133-suite `make test` set, which is the finding restated: nothing in the
//! tree observed any of these sites.
//!
//! | # | mutation | result |
//! |---|---|---|
//! | M1 | `handle_merge` re-encodes each ingested entity | **RED** — merged path resolves to nothing |
//! | M2 | `handle_extract` re-encodes and keys by the store hash | **RED** — `400 hash_mismatch` |
//! | M6 | `extract_params_entity` walks the decoded `Value` | **RED** — `400 hash_mismatch` |
//! | M7 | `build_authenticated_execute` re-encodes `params.data` | **RED** — `400 hash_mismatch` |
//! | M8 | `parse_execute_response` uses `decode_entity_from_value` | **RED** — `400 hash_mismatch` |
//! | M5 | drop §3.1's key-binds-value check in `decode_envelope` | green here; reddens `core/tree`'s `a_miskeyed_source_envelope_is_refused…` |
//!
//! M5 staying green is the useful entry: this row measures the **bytes**, the
//! `core/tree` row measures the **addressing**, and they are disjoint
//! discriminators. Note also what M1/M2/M6/M7/M8 redden *as* — four of the five
//! are `400 hash_mismatch`, not a wrong answer, because once the bytes move the
//! `included` map's keys stop addressing their values and the receiver refuses.
//! A reader matching a failure message against this table should not read the
//! shared code as "the mutation missed."
//!
//! # The two axes that make this observable, and why one is not enough
//!
//! The fixture is **non-canonical** and the round trip is **cross-peer**. Drop
//! either and the row passes against the broken code:
//!
//! 1. **Non-canonical bytes.** Every re-encode under scrutiny is the *identity*
//!    on anything our own codec authored, so a fixture built with `to_ecf`
//!    makes the broken and the fixed implementation byte-identical. The
//!    fixture's `data` is `{"v": 1}` with the `1` written non-minimally
//!    (`0x18 0x01`) — valid CBOR, self-consistent under `content_hash`, and
//!    unauthorable by ECF.
//! 2. **Two peers.** The merge target must never have seen the entity. Merge
//!    binds `path → hash` from the *source trie*; if the target already holds
//!    that hash, the binding resolves whether or not the envelope ingest did
//!    anything at all.
//!
//! **Measured, not argued:** against the pre-fix tree, the same fixture merged
//! into a target sharing the source's store **passed**. Axis 2 alone is worth
//! as little as axis 1 alone.
//!
//! # What this says about the cohort's coverage
//!
//! `entity-core-go`'s `tree_operations.roundtrip_verify_entity` is the check
//! that would catch this, and it misses on **both** axes: its fixture is
//! `ecf.Encode`-authored (axis 1), and its round trip is
//! `system/validate/tree-ops/` → `…/tree-ops-mirror/` on **one** peer (axis 2).
//! Its `convergence.extractAndMerge` helper *is* cross-peer, but the harness
//! itself re-encodes — `cbor.Unmarshal` into `interface{}` then `ecf.Encode` —
//! so it would flatten the fixture before any peer saw it. Routed.

use std::collections::HashMap;

use entity_capability::{CapabilityToken, GrantEntry, Granter, IdScope, PathScope, ResourceTarget};
use entity_crypto::{IdentityKeypair, Keypair};
use entity_entity::Entity;
use entity_peer::{remote, transport, PeerBuilder, PeerShared};
use entity_types::SignatureData;

use std::sync::Arc;

/// `{"v": 1}` with the `1` written non-minimally. See axis 1 in the header —
/// this fixture **is** the test. `to_ecf` would emit `0xa1 0x61 0x76 0x01`.
const NONCANONICAL: [u8; 5] = [0xa1, 0x61, 0x76, 0x18, 0x01];
const SEED_TYPE: &str = "test/noncanon";

fn sign(kp: &Keypair, signer: entity_hash::Hash, target: entity_hash::Hash) -> Entity {
    SignatureData {
        target,
        signer,
        algorithm: "ed25519".to_string(),
        signature: kp.sign(&target.to_bytes()).to_vec(),
    }
    .to_entity()
    .expect("signature entity")
}

/// Wide on every dimension: the axis under test is the payload's bytes, and a
/// grant narrow enough to refuse a row for a *scope* reason would make that row
/// fail for the wrong cause.
fn wide_grant() -> GrantEntry {
    GrantEntry {
        handlers: PathScope::all(),
        resources: PathScope::new(vec!["/*/*".into()]),
        operations: IdScope::all(),
        peers: None,
        constraints: None,
        allowances: None,
    }
}

struct Server {
    pid: String,
    identity: entity_hash::Hash,
    kp: Keypair,
    shared: Arc<PeerShared>,
    task: tokio::task::JoinHandle<()>,
}

fn boot(seed: [u8; 32], registry: &Arc<transport::MemoryTransportRegistry>) -> Server {
    use transport::MemoryListener;

    let kp = Keypair::from_seed(seed);
    let identity = kp.peer_entity().expect("identity").content_hash;
    let peer = PeerBuilder::new()
        .keypair(Keypair::from_seed(seed))
        .build()
        .expect("peer builds");
    let pid = peer.peer_id().to_string();
    let shared = peer.shared();
    let listener = MemoryListener::bind(pid.clone(), registry.clone()).unwrap();
    peer.start_engines(&shared);
    let shared_clone = shared.clone();
    let task = tokio::spawn(async move {
        let _ = entity_peer::server::run(listener, shared_clone).await;
    });
    Server {
        pid,
        identity,
        kp,
        shared,
        task,
    }
}

/// One EXECUTE, authenticated with a capability the target server minted and
/// signed. Returns `(status, result_entity)`.
#[allow(clippy::too_many_arguments)]
async fn execute(
    endpoint: &dyn remote::RemoteEndpoint,
    client: &IdentityKeypair,
    server: &Server,
    request_id: &str,
    uri: &str,
    operation: &str,
    params: &Entity,
    resource: Option<&ResourceTarget>,
    auth_included: &HashMap<entity_hash::Hash, Entity>,
) -> (u32, Entity) {
    // `build_authenticated_execute` and `dispatch_raw` both want an owned
    // request id; bind it once so clippy's `ptr_arg` is not the reason this
    // signature takes a `String`.
    let request_id = request_id.to_string();
    let client_identity = client.peer_entity().expect("client identity").content_hash;
    let cap = CapabilityToken {
        grants: vec![wide_grant()],
        granter: Granter::Single(server.identity),
        grantee: client_identity,
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let cap_entity = cap.to_entity().expect("capability entity");
    let cap_sig = sign(&server.kp, server.identity, cap_entity.content_hash);
    let mut extra = HashMap::new();
    extra.insert(cap_sig.content_hash, cap_sig);

    let envelope = remote::build_authenticated_execute(
        client,
        &cap_entity,
        auth_included,
        &extra,
        &request_id,
        uri,
        operation,
        params,
        resource,
        None,
        None,
    )
    .expect("build execute");

    let resp = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        endpoint.dispatch_raw(request_id.clone(), entity_wire::encode_envelope(&envelope)),
    )
    .await
    .expect("the peer must ANSWER — a timeout here is a dropped frame, not a refusal")
    .expect("the answer must be a response, not a transport error");

    (resp.status, resp.result)
}

/// Read a refusal's code from the decoded `code` KEY, never a substring of the
/// body: a byte scan measures the spelling, which is the layer a census is
/// already blind at.
fn error_code(result: &Entity) -> String {
    let val: ciborium::Value =
        ciborium::from_reader(result.data.as_slice()).unwrap_or(ciborium::Value::Null);
    val.as_map()
        .and_then(|m| m.iter().find(|(k, _)| k.as_text() == Some("code")))
        .and_then(|(_, v)| v.as_text())
        .unwrap_or_default()
        .to_string()
}

#[tokio::test]
async fn a_non_canonical_entity_survives_extract_then_merge_to_a_second_peer() {
    use remote::RemoteEndpoint as _;
    use transport::{Connector as _, MemoryConnector, MemoryTransportRegistry};

    let registry = MemoryTransportRegistry::new();
    let source = boot([0x71u8; 32], &registry);
    let target = boot([0x72u8; 32], &registry);

    // The fixture, seeded on SOURCE only. PUT BEFORE BIND — `IndexingLocation
    // Index` reads the entity out of the content store to learn its type, so a
    // bind that precedes the put indexes nothing and every row goes trivially
    // empty.
    let seeded = Entity::new(SEED_TYPE, NONCANONICAL.to_vec()).expect("seed entity");
    let true_hash = seeded.content_hash;
    assert_eq!(
        seeded.data,
        NONCANONICAL.to_vec(),
        "Entity::new stores `data` verbatim, or this fixture is already flattened"
    );
    source
        .shared
        .content_store
        .put(seeded)
        .expect("seed content put");
    source
        .shared
        .location_index
        .set(&format!("/{}/src/a", source.pid), true_hash);

    let client = IdentityKeypair::Ed25519(Keypair::from_seed([0x73u8; 32]));

    let src_conn = MemoryConnector::new(registry.clone())
        .connect(&format!("memory://{}", source.pid))
        .await
        .expect("connect to source");
    let src_ep = remote::perform_connect(src_conn, &client, entity_hash::HASH_ALGORITHM_SHA256)
        .await
        .expect("source handshake");
    let src_auth = src_ep.auth_included().clone();

    let tgt_conn = MemoryConnector::new(registry.clone())
        .connect(&format!("memory://{}", target.pid))
        .await
        .expect("connect to target");
    let tgt_ep = remote::perform_connect(tgt_conn, &client, entity_hash::HASH_ALGORITHM_SHA256)
        .await
        .expect("target handshake");
    let tgt_auth = tgt_ep.auth_included().clone();

    // --- extract from SOURCE ---
    let src_prefix = format!("/{}/src/", source.pid);
    let (status, envelope_entity) = execute(
        &src_ep,
        &client,
        &source,
        "fidelity-extract",
        &format!("/{}/system/tree", source.pid),
        "extract",
        &Entity::new(
            "system/tree/extract-params",
            entity_ecf::to_ecf(&entity_ecf::Value::Null),
        )
        .expect("extract params"),
        Some(&ResourceTarget {
            targets: vec![src_prefix.clone()],
            exclude: vec![],
        }),
        &src_auth,
    )
    .await;
    assert_eq!(
        status,
        200,
        "extract refused: {}",
        error_code(&envelope_entity)
    );

    // --- merge into TARGET, which has never seen this entity ---
    //
    // `source_envelope` is spliced RAW, which is what both SDK producers do.
    // Building it with `to_ecf` over a decoded `Value` here would flatten the
    // fixture in the *test*, and the row would then measure nothing — the
    // precise mistake `entity-core-go`'s `extractAndMerge` helper makes.
    let wrapper = entity_wire::cbor_map_set_raw(
        &entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("type"),
            entity_ecf::text(&envelope_entity.entity_type),
        )])),
        "data",
        &envelope_entity.data,
    )
    .expect("wrap envelope");
    let dst_prefix = format!("/{}/dest/", target.pid);
    let merge_params_data = entity_wire::cbor_map_set_raw(
        &entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("source_prefix"),
                entity_ecf::text(&src_prefix),
            ),
            (
                entity_ecf::text("strategy"),
                entity_ecf::text("source-wins"),
            ),
            (
                entity_ecf::text("target_prefix"),
                entity_ecf::text(&dst_prefix),
            ),
        ])),
        "source_envelope",
        &wrapper,
    )
    .expect("merge params");

    let (status, merge_result) = execute(
        &tgt_ep,
        &client,
        &target,
        "fidelity-merge",
        &format!("/{}/system/tree", target.pid),
        "merge",
        &Entity::new("system/tree/merge-params", merge_params_data).expect("merge params entity"),
        Some(&ResourceTarget {
            targets: vec![dst_prefix.clone()],
            exclude: vec![],
        }),
        &tgt_auth,
    )
    .await;
    assert_eq!(status, 200, "merge refused: {}", error_code(&merge_result));

    // --- read it back from TARGET ---
    //
    // ⚠ The assertion is on the **bytes**, not the status and not the hash
    // alone. A `200` here with a different hash would mean the merge bound
    // something, and an assertion on presence alone would pass for a peer that
    // re-addressed the entity and bound the re-addressed hash.
    let (status, got) = execute(
        &tgt_ep,
        &client,
        &target,
        "fidelity-get",
        &format!("/{}/system/tree", target.pid),
        "get",
        &Entity::new(
            "system/tree/get-params",
            entity_ecf::to_ecf(&entity_ecf::Value::Null),
        )
        .expect("get params"),
        Some(&ResourceTarget {
            targets: vec![format!("/{}/dest/a", target.pid)],
            exclude: vec![],
        }),
        &tgt_auth,
    )
    .await;

    source.task.abort();
    target.task.abort();

    assert_eq!(
        status,
        200,
        "the merged path must resolve to content on the target peer; got {} {}",
        status,
        error_code(&got)
    );
    assert_eq!(
        got.content_hash, true_hash,
        "the target bound the hash the source trie names"
    );
    assert_eq!(
        got.data,
        NONCANONICAL.to_vec(),
        "§5.4 — the bytes crossed two sockets, an extract and a merge, unchanged"
    );
}
