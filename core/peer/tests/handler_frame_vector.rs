//! §6.3's handler FRAME, driven over the wire — the K4/K5 discriminator
//! (`0.8.2.23`).
//!
//! **This file exists because the cohort's conformance to K4/K5 rests on three
//! seats having read four call sites at the line.** `ROUTING-2026-09-13-b` §2
//! measured that claim rather than repeating it: the frame defect was restored
//! in `extensions/query`, the peer was **rebuilt** (`dirty=true` at HEAD, label
//! checked), and four categories were re-scored — `query` 48P/0F, `security`
//! 31P/0F, `capability` 18P/0F, `tree_operations` 64P/0F. **161 rows, and not
//! one of them reddens.** go's `ROUTING-2026-09-13-h` §4 carries the same
//! finding and asks arch and keystone to adopt a discriminating vector.
//!
//! The cause is structural and this cohort has already named it: *whenever an
//! outcome is reachable from more than one source of authority, a check set that
//! never makes the sources disagree measures their union.* Every grant those
//! categories delegate either names **both** `system/query` and `system/tree`
//! (`query.go:679` — both frames allow) or omits `get` (`query.go:744` — both
//! frames deny). **The two frames agree on every row that exists.**
//!
//! ## Why the in-tree row is not this row
//!
//! `extensions/query::the_tree_read_filter_is_framed_by_the_owning_handler_not_
//! the_running_one` drives the same two shapes and is mutation-verified. It
//! builds a `HandlerContext` **in process**: it sets `ctx.pattern` and
//! `ctx.caller_capability` by hand, so it proves the filter's logic and says
//! nothing about whether a real capability, carried on a real envelope through
//! `verify_request` and the §5.2 dispatch check, arrives at that filter as the
//! authority the rule names. A vector has to cross the boundary the seats are
//! being compared across. These rows do: a peer, a handshake, a minted-and-signed
//! capability presented on the EXECUTE, and an assertion on the decoded response.
//!
//! ## The vector — two rows, opposite directions
//!
//! Both rows pass the §5.2 **dispatch** check and differ only at step 6b, which
//! is what makes them a frame test rather than a scope test:
//!
//! | row | capability | MUST return | under the running-handler frame |
//! |---|---|---|---|
//! | 1 | `{system/query: find}` **+** `{system/tree: get}` | the match | **empty** — the tree grant is discarded unread |
//! | 2 | `{system/query: find, get}` alone, wide `resources` | **empty** | the match — a query grant authorized a tree read |
//!
//! **They redden in opposite directions, and that is the whole point.** A frame
//! that is merely *narrow* reddens row 2 alone; a frame that is merely *wide*
//! reddens row 1 alone. Only a wrong frame reddens both, because the frame is
//! tested UPSTREAM of every dimension — §6.3 says so — so a wrong one is
//! indistinguishable from a broken matcher until you drive both directions.
//!
//! ## Portability
//!
//! Nothing here is rust-shaped. The rows are two capability shapes and one
//! `system/query:find`, so the vector ports unchanged to `history` (§4.2),
//! `compute` (§7.2) and `subscription` (§2.3) — every surface that authorizes a
//! tree read on a caller's behalf — by swapping the operation and the owning
//! handler. Offered to arch/keystone in that form.

#![cfg(all(feature = "query", feature = "capability-handler"))]

use entity_capability::{CapabilityToken, GrantEntry, Granter, IdScope, PathScope};
use entity_crypto::{IdentityKeypair, Keypair};
use entity_entity::Entity;
use entity_peer::{remote, transport, PeerBuilder};

/// The path the single seeded entity is bound at, relative to the server peer.
const SEEDED: &str = "users/alice";
/// The seeded entity's type, and the `type_filter` every row queries on.
const SEEDED_TYPE: &str = "app/user";

/// Detached §5.5 signature over `target`, by `kp`. Identical in shape to the one
/// `pd2_multi_granter_root` builds — the verifier resolves it out of `included`
/// by `target`, so it is a plain entity and not a wire field.
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

/// One grant entry, spelled the way a delegator writes one: a **named** handler
/// (never `*`), the operations it carries, and a resource scope.
///
/// The naming is load-bearing and it is why every pre-existing capability row in
/// the cohort is blind to this defect: a grant whose `handlers` is `*` covers
/// `system/query` and `system/tree` alike, so the two candidate frames agree and
/// the row measures their union.
fn grant(handlers: &str, ops: &[&str], resources: &str) -> GrantEntry {
    GrantEntry {
        handlers: PathScope::new(vec![handlers.into()]),
        resources: PathScope::new(vec![resources.into()]),
        operations: IdScope::new(ops.iter().map(|s| s.to_string()).collect()),
        peers: None,
        constraints: None,
        allowances: None,
    }
}

/// Which capability the caller presents — the only axis.
enum Row {
    /// **Row 1.** The conformant split: the query surface authorizes `find`, and
    /// the tree read the filter performs is carried in its own `system/tree`
    /// grant. This is how a delegator writes it, and only the owning-handler
    /// frame reaches the second grant.
    SplitQueryAndTree,
    /// **Row 2.** A grant naming only `system/query`, carrying `get` and a
    /// resource scope wide enough to cover the data — and **no tree grant at
    /// all**. However wide its `resources`, it authorizes no tree read.
    QueryOnlyCarryingGet,
}

/// Drive one row end to end and return the paths the peer disclosed.
///
/// Returns `Err(status)` if the request was refused, which is a distinct outcome
/// from an empty result: row 2's MUST is *"discloses nothing"*, and a peer that
/// 403s the whole `find` would satisfy a naive emptiness assertion while failing
/// row 1 for an unrelated reason. Keeping them apart is what lets the assertion
/// name which happened.
async fn drive(row: Row) -> Result<Vec<String>, u32> {
    use remote::RemoteEndpoint as _;
    use transport::{Connector as _, MemoryConnector, MemoryListener, MemoryTransportRegistry};

    let registry = MemoryTransportRegistry::new();

    // The server. Its keypair is held because it is the GRANTER: §5.5 root-trust
    // requires a single-sig root's granter to be the local peer, so the
    // capability under test has to be minted and signed by this peer.
    //
    // Two instances from one seed rather than a clone: `Keypair` is deliberately
    // not `Clone` (private keys live in exactly one place), and `from_seed` is
    // deterministic, so the signer and the peer are the same identity.
    const SERVER_SEED: [u8; 32] = [0x51u8; 32];
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

    // Seed one entity at a tree path. Put BEFORE bind: `IndexingLocationIndex`
    // reads the entity out of the content store to learn its type, so a bind
    // that precedes the put indexes nothing and every row goes trivially empty.
    let seeded = Entity::new(SEEDED_TYPE, entity_ecf::to_ecf(&entity_ecf::text("alice")))
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

    // The caller.
    let client = IdentityKeypair::Ed25519(Keypair::from_seed([0x52u8; 32]));
    // Read off the same object the handshake uses, so the fixture's notion of
    // the grantee cannot drift from the identity the wire presents.
    let client_identity = client.peer_entity().expect("client identity").content_hash;
    let conn = MemoryConnector::new(registry.clone())
        .connect(&format!("memory://{}", server_pid))
        .await
        .expect("connect");
    let endpoint = remote::perform_connect(conn, &client, entity_hash::HASH_ALGORITHM_SHA256)
        .await
        .expect("handshake");

    // The presented capability. A root granted BY the server TO the caller —
    // signed by the server, so §5.5's root-trust and per-link signature checks
    // both pass and the only thing left to decide the outcome is the frame.
    //
    // Every row's grants authorize the DISPATCH (`system/query:find`) so that
    // §5.2 is never what refuses; the rows differ only in what authority they
    // carry for the tree read the filter performs.
    let grants = match row {
        Row::SplitQueryAndTree => vec![
            grant("system/query", &["find"], &format!("/{}/*", server_pid)),
            grant("system/tree", &["get"], &format!("/{}/users/*", server_pid)),
        ],
        Row::QueryOnlyCarryingGet => vec![grant(
            "system/query",
            &["find", "get"],
            &format!("/{}/*", server_pid),
        )],
    };
    let cap = CapabilityToken {
        grants,
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

    let mut extra = std::collections::HashMap::new();
    extra.insert(cap_sig.content_hash, cap_sig);

    let params = Entity::new(
        "system/query/expression",
        entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("type_filter"),
            entity_ecf::text(SEEDED_TYPE),
        )])),
    )
    .expect("expression entity");

    let request_id = "frame-vector-1".to_string();
    let envelope = remote::build_authenticated_execute(
        &client,
        &cap_entity,
        endpoint.auth_included(),
        &extra,
        &request_id,
        &format!("/{}/system/query", server_pid),
        "find",
        &params,
        None,
        None,
        None,
    )
    .expect("build execute");

    let resp = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        endpoint.dispatch_raw(request_id.clone(), entity_wire::encode_envelope(&envelope)),
    )
    .await
    .expect("the peer must answer the find")
    .expect("the answer must be a response, not a transport error");

    server_task.abort();

    if resp.status != 200 {
        return Err(resp.status);
    }

    // The decoded `matches` array, by KEY — never a substring of the body.
    let val: ciborium::Value =
        ciborium::from_reader(resp.result.data.as_slice()).expect("result decodes");
    let paths = val
        .as_map()
        .and_then(|m| m.iter().find(|(k, _)| k.as_text() == Some("matches")))
        .and_then(|(_, v)| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| {
                    m.as_map()?
                        .iter()
                        .find(|(k, _)| k.as_text() == Some("path"))?
                        .1
                        .as_text()
                        .map(String::from)
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(paths)
}

/// ⛔ **§6.3: `handler_pattern` is the handler that OWNS the operation, never
/// the handler running the check `[MUST]`** (`0.8.2.23` K4/K5) — over the wire.
///
/// The two rows are **collected, not asserted inline**. They redden in opposite
/// directions under the same mutation, and an inline row 1 short-circuits and
/// reports nothing about row 2 — which is exactly what hid the
/// *admits-what-it-should-not* half of this defect on its first run
/// (`ROUTING-2026-09-13-b` §2).
///
/// **Mutation-verified. The runs, and the rows each reddened:**
///
/// | mutation at `filter_by_capability` | row 1 | row 2 |
/// |---|---|---|
/// | `&ctx.pattern` (the shipped defect) | **RED** — `[]`, the tree grant discarded unread | **RED** — disclosed `users/alice` holding no tree grant |
/// | `"*"` (§6.3's forbidden permissive default) | **RED** — `[]` | **green** |
/// | — (the fix) | green | green |
///
/// The `"*"` row's green half is recorded rather than left to be rediscovered as
/// a defect: `"*"` is **not** a permissive frame at this matcher.
/// `canonicalize("*")` is `/{local}/*`, and `matches_scope` compares it as a
/// **value** against each grant's include patterns, so it matches a grant whose
/// `handlers` is `*` and **no** grant that names one — it fails closed here. So
/// §6.3's *"MUST NOT treat an absent or empty `handler_pattern` as match-all"*
/// is a rule about a matcher that special-cases the value, which this one does
/// not. Stated so the next reader does not add a special case in order to have
/// something to forbid.
#[tokio::test]
async fn the_query_tree_read_is_framed_by_the_owning_handler_over_the_wire() {
    let mut mismatches: Vec<String> = Vec::new();

    match drive(Row::SplitQueryAndTree).await {
        Ok(paths) => {
            // Matched on the suffix, not on the whole string: the path is
            // peer-qualified with a peer id derived from the seed, and asserting
            // the qualified form would pin a value the fixture does not choose.
            if paths.len() != 1 || !paths[0].ends_with(SEEDED) {
                mismatches.push(format!(
                    "row 1 — `{{system/query: find}}` + `{{system/tree: get}}` is a conformant \
                     split and the `system/tree` grant MUST be the one consulted; got {paths:?}, \
                     expected exactly one match ending `{SEEDED}`. An empty result here is the \
                     running-handler frame discarding the tree grant unread"
                ));
            }
        }
        Err(status) => mismatches.push(format!(
            "row 1 — the conformant split was REFUSED with status {status}; the dispatch is \
             authorized by the `{{system/query: find}}` grant, so a refusal is not a frame \
             answer at all"
        )),
    }

    match drive(Row::QueryOnlyCarryingGet).await {
        Ok(paths) => {
            if !paths.is_empty() {
                mismatches.push(format!(
                    "row 2 — a grant naming only `system/query` authorizes no tree read, however \
                     wide its `resources`; got {paths:?}, expected []. Disclosure here is the \
                     running-handler frame letting a query grant stand in for a tree grant"
                ));
            }
        }
        // §5.5.3 requires an out-of-scope entity to be indistinguishable from a
        // non-existent one, so the conformant answer is an empty 200 — but a
        // refusal also discloses nothing, and this vector's MUST is about
        // disclosure. Recorded, not failed, with the status named.
        Err(status) => eprintln!(
            "row 2 — refused with status {status} rather than answering an empty result; \
             discloses nothing, which satisfies the MUST, but §5.5.3 prefers the empty 200"
        ),
    }

    assert!(
        mismatches.is_empty(),
        "§6.3 handler frame (0.8.2.23 K4/K5), over the wire:\n  {}",
        mismatches.join("\n  ")
    );
}
