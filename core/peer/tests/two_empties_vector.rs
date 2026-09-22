//! ⛔ **N6 — the two empties are not the same request `[MUST]`**
//! (`ENTITY-CORE-PROTOCOL` §3.3 + `EXTENSION-TREE` §4.10, `0.8.2.24`),
//! **over the wire**.
//!
//! # Why this file exists beside the in-process rows
//!
//! `core/tree`'s `the_two_empties_split_on_every_resource_optional_tree_op`
//! proves the *handler's* logic by building a `HandlerContext` by hand. That is
//! a floor under a vector, not a vector: it says nothing about whether a
//! `resource` carried on a real envelope, decoded by `extract_resource_target`
//! and narrowed at the dispatch boundary, **arrives** at the handler still
//! carrying the fact that the caller named a target. Three separate layers
//! between the wire and the branch get a vote, and each of them has, at some
//! point in this repo's history, been the one that collapsed the distinction.
//! **An in-process row and a vector are different artifacts with the same
//! assertions, and the word "built" hides the difference.**
//!
//! # The discriminating pair, as `entity-core-go` named it
//!
//! `targets:[qA] exclude:[qA]` → **`400 path_required`**, against an **absent**
//! `resource` → **a listing**. They must answer differently, and a peer that
//! answers either one for both is non-conformant in one direction or the other:
//!
//! - collapse them *toward the absent case* — the shape every seat shipped
//!   before `0.8.2.24` — and a request for **one excluded path** is answered
//!   with **a listing of the tree**, which is §5.2's subject rule (*a handler
//!   MUST NOT widen the set*) reached through the front door;
//! - collapse them *toward the refusal* and the root listing stops working,
//!   which is how a peer is browsed.
//!
//! **Both rows are therefore required, and they are collected rather than
//! asserted inline**, because they redden in opposite directions: an inline
//! row 1 short-circuits and reports nothing about row 2, and "the split is
//! implemented" is exactly the claim that needs both halves to be evidence.
//!
//! # Fixture obligations this vector inherits
//!
//! Both are from `handler_frame_vector.rs`, and both would make these rows lie:
//!
//! 1. **Put before bind.** `IndexingLocationIndex` reads the entity out of the
//!    content store to learn its type, so a bind that precedes the put indexes
//!    nothing — and row 2 would then pass with an empty listing for no reason.
//! 2. **A refusal is not an empty answer.** [`drive`] returns the status as a
//!    distinct outcome rather than folding a 4xx into "listed nothing." Row 2's
//!    claim is that the absent case is *served*; a peer that 403s the whole
//!    request would satisfy a naive emptiness assertion while never reaching the
//!    branch under test.
//!
//! # ⭐ What this vector found that the in-process rows could not
//!
//! **A handler-only fix does not work at this seat, and nothing short of a wire
//! drive says so.** With `core/tree`'s split already landed and its own rows
//! green, row 1 here answered **`200`**: `dispatch_request` narrows
//! `resource.targets` to the effective set immediately after qualifying them
//! (`connection.rs`, the §5.2 structural boundary `0.8.2.20` asks for), so by the
//! time `handle_get` runs the request is *already* indistinguishable from one
//! that named no target, and the `SelfExcluded` arm is **unreachable**.
//!
//! `0.8.2.20`'s boundary narrowing and `0.8.2.24`'s two-empties split are the
//! same field read twice, and the first silently deletes the second. So the fix
//! is two exemptions — *narrow when narrowing leaves something, keep the pair
//! when it would not* — at the inbound wire seam and at the in-process
//! sub-dispatch seam, kept in step so one door cannot answer differently from
//! the other. **Any seat that adopted the boundary narrowing has this; a seat
//! that only ever narrowed inside the handler does not.** Routed to the cohort
//! for that reason.
//!
//! # Mutations RUN, and the rows each reddened
//!
//! | mutation | row 1 (self-excluded) | row 2 (absent) |
//! |---|---|---|
//! | restore the collapse (`SelfExcluded` → the absent arm, in the one derivation) | **RED** — `200` carrying `system/handler` | green |
//! | invert (`Absent` → refuse) | green | **RED** — `400 path_required` where the listing is owed |
//! | narrow unconditionally at the **inbound** boundary | **RED** — `200` carrying `system/handler` | green |
//!
//! Rows 1 and 2 redden under **disjoint** mutations, which is what separates
//! *split the empties* from *refuse more* — a single-row vector cannot say it.
//!
//! Note what row 1 reddens **as**: a `200` carrying `system/handler`, not a
//! listing. With the collapse restored, `get` falls through to the URI-suffix
//! form, which for row 1's URI is the tree handler's own advertised-interface
//! binding. It is the same defect — the absent-case behaviour served to a
//! request that named a path — and it is worth recording precisely, because
//! "answers a listing" is the shape at one URI and not at another, and a reader
//! checking this table against a failure message should not conclude the
//! mutation missed.

use std::collections::HashMap;

use entity_capability::{CapabilityToken, GrantEntry, Granter, IdScope, PathScope, ResourceTarget};
use entity_crypto::{IdentityKeypair, Keypair};
use entity_entity::Entity;
use entity_peer::{remote, transport, PeerBuilder};
use entity_types::SignatureData;

/// The path both rows are about. Deliberately **under the tree handler's own
/// prefix**, so that one seeded binding serves both rows: row 1 names it as a
/// resource target and excludes it, and row 2 reaches it through the URI-suffix
/// listing form (`entity://{peer}/system/tree/`), which is the only way an
/// EXECUTE carrying no `resource` can name a path at all.
///
/// **Row 2 asserts the listing CONTAINS it**, not merely that a 200 came back.
/// An earlier draft listed a prefix with nothing under it and passed with
/// `count: 0` — which a peer that never reached the branch would also produce.
const SEEDED_LEAF: &str = "alpha";
const SEEDED: &str = "system/tree/alpha";
const SEEDED_TYPE: &str = "test/leaf";

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

/// The caller's grant. Deliberately **wide on every dimension**, because the
/// axis under test is the `resource`'s two empties and nothing else: a grant
/// narrow enough to refuse either row for a *scope* reason would make that row
/// pass or fail for the wrong cause, which is the failure mode this repo's
/// charter calls a vector whose discriminator is defeated by something the
/// vector does not control.
///
/// Measured rather than assumed: with `handlers: ["system/tree"]` the absent row
/// answered `403 capability_denied` at the handlers dimension — the trailing-
/// slash listing URI resolves a pattern that grant did not cover — and the row
/// then "failed" while saying nothing at all about the empties.
fn wide_tree_grant(_server_pid: &str) -> GrantEntry {
    GrantEntry {
        handlers: PathScope::all(),
        resources: PathScope::new(vec!["/*/*".into()]),
        operations: IdScope::all(),
        peers: None,
        constraints: None,
        allowances: None,
    }
}

/// Which `resource` the EXECUTE carries — the only axis.
enum Row {
    /// **Row 1.** `targets:[/{p}/system/tree/alpha] exclude:[same]`. The
    /// caller named exactly one target and its own exclude removed it, so the
    /// effective set is empty. **Not** the absent case: `400 path_required`.
    SelfExcluded,
    /// **Row 2.** No `resource` field at all, with the listing form in the URI
    /// suffix. §4.10's own operation row — *"Path ending with `/` or empty:
    /// listing"* — is `get`'s specification and this is the omitted-resource
    /// case it names. Must still be **served**.
    Absent,
}

/// What the peer answered: the listed paths, or the refusal status.
enum Answer {
    Listed(Vec<String>),
    Refused {
        status: u32,
        code: String,
    },
    /// A 200 whose body is not a listing — kept apart from `Listed` so row 2
    /// cannot pass on a point read.
    NotAListing(String),
}

/// Drive one row end to end: a real peer, a real handshake, a capability minted
/// and signed by the server, and an EXECUTE carrying (or omitting) a `resource`.
async fn drive(row: Row) -> Answer {
    use remote::RemoteEndpoint as _;
    use transport::{Connector as _, MemoryConnector, MemoryListener, MemoryTransportRegistry};

    let registry = MemoryTransportRegistry::new();

    // The server is the GRANTER: §5.5 root-trust requires a single-sig root's
    // granter to be the local peer, so the capability has to be minted and
    // signed by this identity. Two instances from one deterministic seed rather
    // than a clone — `Keypair` is deliberately not `Clone`.
    const SERVER_SEED: [u8; 32] = [0x61u8; 32];
    let server_kp = Keypair::from_seed(SERVER_SEED);
    let server_identity = server_kp
        .peer_entity()
        .expect("server identity")
        .content_hash;
    let server = PeerBuilder::new()
        .keypair(Keypair::from_seed(SERVER_SEED))
        .build()
        .expect("server builds");
    let server_pid = server.peer_id().to_string();
    let shared = server.shared();

    // PUT BEFORE BIND — see the fixture obligations in this file's header.
    let seeded = Entity::new(SEEDED_TYPE, entity_ecf::to_ecf(&entity_ecf::text("alpha")))
        .expect("seed entity");
    let seeded_hash = seeded.content_hash;
    shared.content_store.put(seeded).expect("seed put");
    shared
        .location_index
        .set(&format!("/{}/{}", server_pid, SEEDED), seeded_hash);

    let listener = MemoryListener::bind(server_pid.clone(), registry.clone()).unwrap();
    server.start_engines(&shared);
    let shared_clone = shared.clone();
    let server_task = tokio::spawn(async move {
        let _ = entity_peer::server::run(listener, shared_clone).await;
    });
    tokio::task::yield_now().await;

    let client = IdentityKeypair::Ed25519(Keypair::from_seed([0x62u8; 32]));
    let client_identity = client.peer_entity().expect("client identity").content_hash;
    let conn = MemoryConnector::new(registry.clone())
        .connect(&format!("memory://{}", server_pid))
        .await
        .expect("connect");
    let endpoint = remote::perform_connect(conn, &client, entity_hash::HASH_ALGORITHM_SHA256)
        .await
        .expect("handshake");

    let cap = CapabilityToken {
        grants: vec![wide_tree_grant(&server_pid)],
        granter: Granter::Single(server_identity),
        grantee: client_identity,
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let cap_entity = cap.to_entity().expect("capability entity");
    let cap_sig = sign(&server_kp, server_identity, cap_entity.content_hash);
    let mut extra = HashMap::new();
    extra.insert(cap_sig.content_hash, cap_sig);

    let target = format!("/{}/{}", server_pid, SEEDED);
    let resource = match row {
        Row::SelfExcluded => Some(ResourceTarget {
            targets: vec![target.clone()],
            exclude: vec![target.clone()],
        }),
        Row::Absent => None,
    };
    // Row 2 reaches the listing through the URI suffix, which is the only way an
    // EXECUTE with no `resource` can name a path at all — and it is §4.10's
    // "path ending with `/`" arm, so this is the absent case as specified rather
    // than a second way of writing row 1.
    let uri = match row {
        Row::SelfExcluded => format!("/{}/system/tree", server_pid),
        Row::Absent => format!("/{}/system/tree/", server_pid),
    };

    let params = Entity::new(
        "system/tree/get-params",
        entity_ecf::to_ecf(&entity_ecf::Value::Null),
    )
    .expect("params entity");

    let request_id = "two-empties-1".to_string();
    let envelope = remote::build_authenticated_execute(
        &client,
        &cap_entity,
        endpoint.auth_included(),
        &extra,
        &request_id,
        &uri,
        "get",
        &params,
        resource.as_ref(),
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

    server_task.abort();

    if resp.status != 200 {
        // Read the code from the decoded `code` KEY, never a substring of the
        // body: a byte scan measures the spelling, which is the layer a census
        // is already blind at.
        let val: ciborium::Value =
            ciborium::from_reader(resp.result.data.as_slice()).unwrap_or(ciborium::Value::Null);
        let code = val
            .as_map()
            .and_then(|m| m.iter().find(|(k, _)| k.as_text() == Some("code")))
            .and_then(|(_, v)| v.as_text())
            .unwrap_or_default()
            .to_string();
        return Answer::Refused {
            status: resp.status,
            code,
        };
    }

    if resp.result.entity_type != "system/tree/listing" {
        // A 200 that is not a listing is not the absent-case behaviour §4.10
        // names, and folding it into `Listed` would let row 2 pass on a point
        // read of the handler's own interface entity — which is exactly what an
        // earlier draft of this fixture did.
        return Answer::NotAListing(resp.result.entity_type.clone());
    }
    // `entries` is a CBOR **map** (name -> hash), not an array. Read by KEY.
    let val: ciborium::Value =
        ciborium::from_reader(resp.result.data.as_slice()).expect("result decodes");
    let names = val
        .as_map()
        .and_then(|m| m.iter().find(|(k, _)| k.as_text() == Some("entries")))
        .and_then(|(_, v)| v.as_map())
        .map(|entries| {
            entries
                .iter()
                .filter_map(|(k, _)| k.as_text().map(String::from))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Answer::Listed(names)
}

#[tokio::test]
async fn the_two_empties_answer_differently_over_the_wire() {
    let mut mismatches: Vec<String> = Vec::new();

    match drive(Row::SelfExcluded).await {
        Answer::Refused { status, code } => {
            if status != 400 || code != "path_required" {
                mismatches.push(format!(
                    "row 1 — `targets:[qA] exclude:[qA]` MUST be `400 path_required`; \
                     got {status} {code:?}"
                ));
            }
        }
        Answer::Listed(names) => mismatches.push(format!(
            "row 1 — a request naming ONE path, which the caller then excluded, was \
             SERVED a listing of {names:?}. This is the absent-case behaviour reached \
             through an empty effective list — §5.2's subject rule says a handler MUST \
             NOT widen the set, and on `get` the widening is a listing of the tree"
        )),
        Answer::NotAListing(t) => mismatches.push(format!(
            "row 1 — must be `400 path_required`; got a 200 carrying {t}"
        )),
    }

    match drive(Row::Absent).await {
        Answer::Listed(names) => {
            if !names.iter().any(|n| n == SEEDED_LEAF) {
                mismatches.push(format!(
                    "row 2 — the absent case must be SERVED, and served the thing it \
                     names: expected a listing containing {SEEDED_LEAF:?}, got {names:?}. \
                     An empty listing here is a 200 that never reached the branch"
                ));
            }
        }
        Answer::Refused { status, code } => mismatches.push(format!(
            "row 2 — a GENUINELY absent `resource` must still take §4.10's absent-case \
             behaviour (the listing); got {status} {code:?}. Refusing here is the split \
             implemented in the wrong direction, and it breaks how a peer is browsed"
        )),
        Answer::NotAListing(t) => mismatches.push(format!(
            "row 2 — §4.10's absent case for a `/`-terminated path is a LISTING; got a \
             200 carrying {t}"
        )),
    }

    assert!(
        mismatches.is_empty(),
        "N6 — the two empties (§3.3 + EXTENSION-TREE §4.10, 0.8.2.24), over the wire:\n  {}",
        mismatches.join("\n  ")
    );
}
