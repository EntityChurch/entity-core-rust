//! EXTENSION-REGISTRY v1.0 unit + integration tests.

use std::sync::Arc;

use entity_ecf::{text, to_ecf, Value};
use entity_entity::Entity;
use entity_handler::{Handler, HandlerContext};
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex, MemoryContentStore, MemoryLocationIndex};

use crate::data::*;
use crate::local_name::LocalNameHandler;
use crate::log::ResolutionLog;
use crate::registration::name_constraints_match;
use crate::resolver::{dispatch_match, RegistryHandler};

const PEER: &str = "z6MkTestPeerIdForRegistry";

fn stores() -> (Arc<dyn ContentStore>, Arc<dyn LocationIndex>) {
    (
        Arc::new(MemoryContentStore::new()),
        Arc::new(MemoryLocationIndex::new()),
    )
}

fn ctx(op: &str, params_fields: Vec<(Value, Value)>) -> HandlerContext {
    let params = Entity::new(
        entity_types::TYPE_PROTOCOL_STATUS,
        to_ecf(&Value::Map(params_fields)),
    )
    .unwrap();
    let execute = Entity::new(entity_types::TYPE_EXECUTE, to_ecf(&Value::Map(vec![]))).unwrap();
    HandlerContext::builder(execute, params)
        .operation(op.to_string())
        .build()
}

fn registry(cs: &Arc<dyn ContentStore>, li: &Arc<dyn LocationIndex>) -> RegistryHandler {
    let log = Arc::new(ResolutionLog::new(
        cs.clone(),
        li.clone(),
        PEER.into(),
        1024,
    ));
    RegistryHandler::new(cs.clone(), li.clone(), PEER.into(), log)
}

fn decode_result(r: &entity_handler::HandlerResult) -> Vec<(Value, Value)> {
    let v: Value = ciborium::from_reader(r.result.data.as_slice()).unwrap();
    v.into_map().unwrap()
}

fn result_field<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter().find_map(|(k, v)| {
        if k.as_text() == Some(key) {
            Some(v)
        } else {
            None
        }
    })
}

// ---------------------------------------------------------------------------
// Entity round-trips (R5 *_round_trip)
// ---------------------------------------------------------------------------

#[test]
fn binding_round_trip() {
    let b = BindingData {
        name: "alice".into(),
        kind: KIND_LOCAL_NAME.into(),
        target_peer_id: "z6MkAlice".into(),
        transports: vec![Value::Text("tcp://host:9000".into())],
        issued_at: 1_700_000_000_000,
        ttl: None,
        supersedes: Some(Hash::compute("x", b"a")),
        issuer_attestation: None,
        metadata: Some(Value::Map(vec![(text("pinned"), Value::Bool(true))])),
    };
    let e = b.to_entity().unwrap();
    assert_eq!(BindingData::from_entity(&e).unwrap(), b);
}

#[test]
fn revocation_round_trip() {
    let r = RevocationData {
        revokes: Hash::compute("x", b"b"),
        revoked_at: 42,
        reason: Some("compromised".into()),
    };
    let e = r.to_entity().unwrap();
    assert_eq!(RevocationData::from_entity(&e).unwrap(), r);
}

#[test]
fn resolver_config_round_trip() {
    let c = ResolverConfigData {
        resolver_chain: vec![ResolverChainEntry {
            backend_kind: "local-name".into(),
            backend_id: PEER.into(),
            priority: 0,
            accepted_trust_anchors: vec!["local_name".into()],
            hints: None,
        }],
        pinned_bindings: vec![PinnedBinding {
            name: "nad-ccf".into(),
            target_peer_id: "z6MkCcf".into(),
            reason: Some("preload".into()),
        }],
        name_format_dispatch: vec![DispatchRule {
            pattern: "*.eth".into(),
            backend_kinds: vec!["dns-txt".into()],
        }],
        log_cache_hits: false,
        resolution_log_capacity: 512,
    };
    let e = c.to_entity().unwrap();
    assert_eq!(ResolverConfigData::from_entity(&e).unwrap(), c);
}

#[test]
fn local_name_config_round_trip() {
    let c = LocalNameConfigData {
        default_pinned: true,
        allow_supersede: false,
        case_normalization: "lower".into(),
    };
    let e = c.to_entity().unwrap();
    assert_eq!(LocalNameConfigData::from_entity(&e).unwrap(), c);
}

#[test]
fn resolution_log_round_trip() {
    let l = ResolutionLogData {
        seq: 5,
        name: "alice".into(),
        backend_id: Some(PEER.into()),
        status: STATUS_RESOLVED.into(),
        reason: None,
        binding: Some(Hash::compute("x", b"c")),
        attempted_at: 99,
        is_fallback_reresolve: false,
    };
    let e = l.to_entity().unwrap();
    assert_eq!(ResolutionLogData::from_entity(&e).unwrap(), l);
}

// ---------------------------------------------------------------------------
// Local-name bind / resolve / list / unbind / update-transports
// ---------------------------------------------------------------------------

#[tokio::test]
async fn local_name_bind_resolve_roundtrip() {
    let (cs, li) = stores();
    let pet = LocalNameHandler::new(cs.clone(), li.clone(), PEER.into());
    let reg = registry(&cs, &li);

    let r = pet
        .handle(&ctx(
            "bind",
            vec![
                (text("name"), text("alice")),
                (text("target_peer_id"), text("z6MkAlice")),
                (text("notes"), text("my friend")),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(r.status, 200);

    let r = reg
        .handle(&ctx("resolve", vec![(text("name"), text("alice"))]))
        .await
        .unwrap();
    // §2.1 Ruling-3: resolve returns the flat `system/registry/resolution-result`.
    assert_eq!(r.result.entity_type, crate::TYPE_REGISTRY_RESOLUTION_RESULT);
    let res = decode_result(&r);
    assert_eq!(
        result_field(&res, "status").unwrap().as_text(),
        Some("resolved")
    );
    assert_eq!(
        result_field(&res, "peer_id").unwrap().as_text(),
        Some("z6MkAlice")
    );
    assert_eq!(
        result_field(&res, "trust_anchor").unwrap().as_text(),
        Some("local_name")
    );
}

#[tokio::test]
async fn local_name_bind_invalid_name() {
    let (cs, li) = stores();
    let pet = LocalNameHandler::new(cs.clone(), li.clone(), PEER.into());
    for bad in ["a/b", "ctrl\u{7f}", "tab\tx", ""] {
        let r = pet
            .handle(&ctx(
                "bind",
                vec![
                    (text("name"), text(bad)),
                    (text("target_peer_id"), text("z6Mk")),
                ],
            ))
            .await
            .unwrap();
        assert_eq!(r.status, 400, "name {:?} should be rejected", bad);
        let m = decode_result(&r);
        assert_eq!(
            result_field(&m, "code").unwrap().as_text(),
            Some("bind_invalid_name")
        );
    }
}

#[tokio::test]
async fn local_name_bind_already_exists() {
    let (cs, li) = stores();
    // allow_supersede = false
    let cfg = LocalNameConfigData {
        default_pinned: true,
        allow_supersede: false,
        case_normalization: "none".into(),
    };
    li.set(
        &crate::local_name_config_path(PEER),
        cs.put(cfg.to_entity().unwrap()).unwrap(),
    );
    let pet = LocalNameHandler::new(cs.clone(), li.clone(), PEER.into());
    let bind = |n: &str| {
        ctx(
            "bind",
            vec![
                (text("name"), text(n)),
                (text("target_peer_id"), text("z6MkX")),
            ],
        )
    };
    assert_eq!(pet.handle(&bind("bob")).await.unwrap().status, 200);
    let r = pet.handle(&bind("bob")).await.unwrap();
    assert_eq!(r.status, 409);
    let m = decode_result(&r);
    assert_eq!(
        result_field(&m, "code").unwrap().as_text(),
        Some("bind_already_exists")
    );
}

#[tokio::test]
async fn local_name_supersede_on_rebind() {
    let (cs, li) = stores();
    let pet = LocalNameHandler::new(cs.clone(), li.clone(), PEER.into());
    let bind = |t: &str| {
        ctx(
            "bind",
            vec![
                (text("name"), text("carol")),
                (text("target_peer_id"), text(t)),
            ],
        )
    };
    let h1 = pet.handle(&bind("z6MkFirst")).await.unwrap();
    let first_hash = result_field(&decode_result(&h1), "binding_hash")
        .unwrap()
        .as_bytes()
        .unwrap()
        .to_vec();
    let _ = pet.handle(&bind("z6MkSecond")).await.unwrap();

    // resolve returns the new target; supersedes chain walks back to the first.
    let reg = registry(&cs, &li);
    let r = reg
        .handle(&ctx("resolve", vec![(text("name"), text("carol"))]))
        .await
        .unwrap();
    // §2.1 Ruling-3: resolve returns the flat `system/registry/resolution-result`.
    let res = decode_result(&r);
    assert_eq!(
        result_field(&res, "peer_id").unwrap().as_text(),
        Some("z6MkSecond")
    );
    let head_hash = result_field(&res, "binding").unwrap().as_bytes().unwrap();
    let head =
        BindingData::from_entity(&cs.get(&Hash::from_bytes(head_hash).unwrap()).unwrap()).unwrap();
    assert_eq!(head.supersedes.unwrap().to_bytes().to_vec(), first_hash);
}

#[tokio::test]
async fn local_name_list_and_unbind() {
    let (cs, li) = stores();
    let pet = LocalNameHandler::new(cs.clone(), li.clone(), PEER.into());
    for (n, t) in [("a", "z6MkA"), ("b", "z6MkB")] {
        pet.handle(&ctx(
            "bind",
            vec![(text("name"), text(n)), (text("target_peer_id"), text(t))],
        ))
        .await
        .unwrap();
    }
    let r = pet.handle(&ctx("list", vec![])).await.unwrap();
    let m = decode_result(&r);
    let entries = result_field(&m, "entries").unwrap().as_array().unwrap();
    assert_eq!(entries.len(), 2);

    // unbind one
    let r = pet
        .handle(&ctx("unbind", vec![(text("name"), text("a"))]))
        .await
        .unwrap();
    assert_eq!(r.status, 200);
    let r = pet.handle(&ctx("list", vec![])).await.unwrap();
    let m = decode_result(&r);
    assert_eq!(
        result_field(&m, "entries")
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // resolve of unbound name → chain_exhausted (§4.1.4: a backend miss folds
    // into fail-closed chain exhaustion; the meta-resolver does not surface a
    // top-level not_found).
    let reg = registry(&cs, &li);
    let r = reg
        .handle(&ctx("resolve", vec![(text("name"), text("a"))]))
        .await
        .unwrap();
    // §2.1 Ruling-3: resolve returns the flat `system/registry/resolution-result`.
    let res = decode_result(&r);
    assert_eq!(
        result_field(&res, "status").unwrap().as_text(),
        Some("chain_exhausted")
    );
}

#[tokio::test]
async fn local_name_resolve_nfc_symmetry() {
    let (cs, li) = stores();
    let pet = LocalNameHandler::new(cs.clone(), li.clone(), PEER.into());
    // Bind NFC "Café" (precomposed é = U+00E9).
    let nfc = "Caf\u{00e9}";
    pet.handle(&ctx(
        "bind",
        vec![
            (text("name"), text(nfc)),
            (text("target_peer_id"), text("z6MkCafe")),
        ],
    ))
    .await
    .unwrap();
    // Resolve with NFD "Café" (e + combining acute U+0301) → normalizes to same key.
    let nfd = "Cafe\u{0301}";
    let reg = registry(&cs, &li);
    let r = reg
        .handle(&ctx("resolve", vec![(text("name"), text(nfd))]))
        .await
        .unwrap();
    // §2.1 Ruling-3: resolve returns the flat `system/registry/resolution-result`.
    let res = decode_result(&r);
    assert_eq!(
        result_field(&res, "status").unwrap().as_text(),
        Some("resolved")
    );
    assert_eq!(
        result_field(&res, "peer_id").unwrap().as_text(),
        Some("z6MkCafe")
    );
}

// ---------------------------------------------------------------------------
// Meta-resolver: pins, dispatch, chain exhaustion, revocation
// ---------------------------------------------------------------------------

fn install_config(
    cs: &Arc<dyn ContentStore>,
    li: &Arc<dyn LocationIndex>,
    cfg: &ResolverConfigData,
) {
    let h = cs.put(cfg.to_entity().unwrap()).unwrap();
    li.set(&crate::resolver_config_path(PEER), h);
}

#[tokio::test]
async fn meta_resolver_pin_precedence() {
    let (cs, li) = stores();
    // bind a local-name for "nad" that should be overridden by a pin.
    let pet = LocalNameHandler::new(cs.clone(), li.clone(), PEER.into());
    pet.handle(&ctx(
        "bind",
        vec![
            (text("name"), text("nad")),
            (text("target_peer_id"), text("z6MkLocalName")),
        ],
    ))
    .await
    .unwrap();
    let cfg = ResolverConfigData {
        resolver_chain: vec![ResolverChainEntry {
            backend_kind: "local-name".into(),
            backend_id: PEER.into(),
            priority: 0,
            accepted_trust_anchors: vec![],
            hints: None,
        }],
        pinned_bindings: vec![PinnedBinding {
            name: "nad".into(),
            target_peer_id: "z6MkPinned".into(),
            reason: None,
        }],
        name_format_dispatch: vec![],
        log_cache_hits: false,
        resolution_log_capacity: 1024,
    };
    install_config(&cs, &li, &cfg);
    let reg = registry(&cs, &li);
    let r = reg
        .handle(&ctx("resolve", vec![(text("name"), text("nad"))]))
        .await
        .unwrap();
    // §2.1 Ruling-3: resolve returns the flat `system/registry/resolution-result`.
    let res = decode_result(&r);
    assert_eq!(
        result_field(&res, "peer_id").unwrap().as_text(),
        Some("z6MkPinned")
    );
    assert_eq!(
        result_field(&res, "trust_anchor").unwrap().as_text(),
        Some("out_of_band")
    );
    assert_eq!(
        result_field(&res, "backend_id").unwrap().as_text(),
        Some("pinned")
    );
}

#[tokio::test]
async fn meta_resolver_chain_exhaustion() {
    let (cs, li) = stores();
    // empty chain → fail-closed.
    let cfg = ResolverConfigData::default();
    install_config(&cs, &li, &cfg);
    let reg = registry(&cs, &li);
    let r = reg
        .handle(&ctx("resolve", vec![(text("name"), text("ghost"))]))
        .await
        .unwrap();
    // §2.1 Ruling-3: resolve returns the flat `system/registry/resolution-result`.
    let res = decode_result(&r);
    assert_eq!(
        result_field(&res, "status").unwrap().as_text(),
        Some("chain_exhausted")
    );
}

#[tokio::test]
async fn meta_resolver_dispatch_filter_excludes_local_name() {
    let (cs, li) = stores();
    let pet = LocalNameHandler::new(cs.clone(), li.clone(), PEER.into());
    pet.handle(&ctx(
        "bind",
        vec![
            (text("name"), text("alice")),
            (text("target_peer_id"), text("z6MkAlice")),
        ],
    ))
    .await
    .unwrap();
    // Restrict local-name to names matching "*.local" — "alice" won't match.
    let cfg = ResolverConfigData {
        resolver_chain: vec![ResolverChainEntry {
            backend_kind: "local-name".into(),
            backend_id: PEER.into(),
            priority: 0,
            accepted_trust_anchors: vec![],
            hints: None,
        }],
        pinned_bindings: vec![],
        name_format_dispatch: vec![DispatchRule {
            pattern: "*.local".into(),
            backend_kinds: vec!["local-name".into()],
        }],
        log_cache_hits: false,
        resolution_log_capacity: 1024,
    };
    install_config(&cs, &li, &cfg);
    let reg = registry(&cs, &li);
    // "alice" excluded by dispatch → chain_exhausted
    let r = reg
        .handle(&ctx("resolve", vec![(text("name"), text("alice"))]))
        .await
        .unwrap();
    let res = decode_result(&r);
    assert_eq!(
        result_field(&res, "status").unwrap().as_text(),
        Some("chain_exhausted")
    );
    // "alice.local" matches dispatch → local-name consulted, no such name →
    // chain_exhausted (the backend miss folds into fail-closed exhaustion).
    let r = reg
        .handle(&ctx("resolve", vec![(text("name"), text("alice.local"))]))
        .await
        .unwrap();
    let res = decode_result(&r);
    assert_eq!(
        result_field(&res, "status").unwrap().as_text(),
        Some("chain_exhausted")
    );
}

#[tokio::test]
async fn meta_resolver_revocation_honored() {
    let (cs, li) = stores();
    let pet = LocalNameHandler::new(cs.clone(), li.clone(), PEER.into());
    let h = pet
        .handle(&ctx(
            "bind",
            vec![
                (text("name"), text("dave")),
                (text("target_peer_id"), text("z6MkDave")),
            ],
        ))
        .await
        .unwrap();
    let binding_hash = Hash::from_bytes(
        result_field(&decode_result(&h), "binding_hash")
            .unwrap()
            .as_bytes()
            .unwrap(),
    )
    .unwrap();
    // §3.1's discovery contract constrains **no storage path**, and the cohort
    // convention is own-hash-keyed: a revocation written straight to the tree
    // — no `revoke-request`, so no by-target entry — MUST still exclude. This
    // is `registry.v6_meta_resolver_revocation_honored` in go's oracle, driven
    // by `tree-put` at exactly this path. An index-only reader fails it while
    // every in-tree test stays green, which is how the first attempt at R-4
    // was caught: green suite, red armed gate.
    let rev = RevocationData {
        revokes: binding_hash,
        revoked_at: 1,
        reason: Some("test".into()),
    };
    let rev_hash = cs.put(rev.to_entity().unwrap()).unwrap();
    li.set(
        &format!("/{}/system/registry/revocation/{}", PEER, rev_hash.to_hex()),
        rev_hash,
    );
    let reg = registry(&cs, &li);
    let r = reg
        .handle(&ctx("resolve", vec![(text("name"), text("dave"))]))
        .await
        .unwrap();
    assert_eq!(
        result_field(&decode_result(&r), "status")
            .unwrap()
            .as_text(),
        Some("chain_exhausted"),
        "an own-hash-keyed revocation excludes — §3.1 pins no path, and v6 \
         drives exactly this shape over the wire"
    );

    // A revocation reached only through the §6a.6 by-target key — what
    // `revoke-request` writes — also excludes. **This row does not
    // discriminate and is not claimed to**: `by-target/{hex}` sits inside
    // `revocation_prefix`, so the scan finds it too (pinned structurally by
    // `revocation_by_target_is_inside_the_scanned_prefix`). It is here as
    // coverage of the shape the write path produces, not as evidence about
    // which reader ran.
    let (cs2, li2) = stores();
    let pet2 = LocalNameHandler::new(cs2.clone(), li2.clone(), PEER.into());
    let h2 = pet2
        .handle(&ctx(
            "bind",
            vec![
                (text("name"), text("dave")),
                (text("target_peer_id"), text("z6MkDave")),
            ],
        ))
        .await
        .unwrap();
    let bh2 = Hash::from_bytes(
        result_field(&decode_result(&h2), "binding_hash")
            .unwrap()
            .as_bytes()
            .unwrap(),
    )
    .unwrap();
    let rev2 = RevocationData {
        revokes: bh2,
        revoked_at: 1,
        reason: None,
    };
    let rev2_hash = cs2.put(rev2.to_entity().unwrap()).unwrap();
    li2.set(&crate::revocation_by_target_path(PEER, &bh2), rev2_hash);
    let r2 = registry(&cs2, &li2)
        .handle(&ctx("resolve", vec![(text("name"), text("dave"))]))
        .await
        .unwrap();
    assert_eq!(
        result_field(&decode_result(&r2), "status")
            .unwrap()
            .as_text(),
        Some("chain_exhausted"),
        "a revocation filed ONLY in the by-target index excludes"
    );

    // Both keys, as `revoke-request` writes them.
    li.set(
        &crate::revocation_by_target_path(PEER, &binding_hash),
        rev_hash,
    );
    let r = reg
        .handle(&ctx("resolve", vec![(text("name"), text("dave"))]))
        .await
        .unwrap();
    assert_eq!(
        result_field(&decode_result(&r), "status")
            .unwrap()
            .as_text(),
        Some("chain_exhausted")
    );
}

/// The index KEY is a host-served pointer and proves nothing: a genuine
/// revocation naming binding A, filed by a hostile tree under `by-target/{B}`,
/// must not revoke B — the signed body's own `revokes` is the commitment.
///
/// **Stated honestly: this cannot currently fail at this reader**, because
/// §3.1 discovery here is a scan that matches on `revokes` and so cannot be
/// misfiled at all. It is kept as the regression guard for the keyed form —
/// it *did* go red against the index-only reader that shipped and was reverted
/// this session, and it is the assertion a future scan→lookup rewrite drops
/// first. The discriminating copy lives where the keyed reader actually is:
/// `peer_issued_misfiled_revocation_does_not_revoke_the_wrong_binding`.
#[tokio::test]
async fn meta_resolver_misfiled_revocation_does_not_revoke_the_wrong_binding() {
    let (cs, li) = stores();
    let pet = LocalNameHandler::new(cs.clone(), li.clone(), PEER.into());
    let victim = pet
        .handle(&ctx(
            "bind",
            vec![
                (text("name"), text("victim")),
                (text("target_peer_id"), text("z6MkVictim")),
            ],
        ))
        .await
        .unwrap();
    let victim_hash = Hash::from_bytes(
        result_field(&decode_result(&victim), "binding_hash")
            .unwrap()
            .as_bytes()
            .unwrap(),
    )
    .unwrap();

    // A second, unrelated binding — and a revocation that genuinely revokes
    // THAT one.
    let other = pet
        .handle(&ctx(
            "bind",
            vec![
                (text("name"), text("other")),
                (text("target_peer_id"), text("z6MkOther")),
            ],
        ))
        .await
        .unwrap();
    let other_hash = Hash::from_bytes(
        result_field(&decode_result(&other), "binding_hash")
            .unwrap()
            .as_bytes()
            .unwrap(),
    )
    .unwrap();
    let rev = RevocationData {
        revokes: other_hash,
        revoked_at: 1,
        reason: None,
    };
    let rev_hash = cs.put(rev.to_entity().unwrap()).unwrap();
    // Misfiled under the victim's index key.
    li.set(
        &crate::revocation_by_target_path(PEER, &victim_hash),
        rev_hash,
    );

    let reg = registry(&cs, &li);
    let r = reg
        .handle(&ctx("resolve", vec![(text("name"), text("victim"))]))
        .await
        .unwrap();
    assert_eq!(
        result_field(&decode_result(&r), "status")
            .unwrap()
            .as_text(),
        Some("resolved"),
        "a revocation whose signed `revokes` names another binding must not \
         revoke this one — the index key is not evidence"
    );
}

/// The containment that makes an index-first fast path at the §3.1 reader
/// **unobservable** — `by-target/{hex}` is a child of the scanned revocation
/// prefix, so a keyed lookup can only find revocations the scan already finds.
///
/// Pinned by construction because it is the reason this peer ships **no** such
/// branch: deleting one fails no test, and a branch that reads as covered and
/// cannot fail is worse than its absence. If the paths ever diverge — §3.1
/// gaining its own index, or the key moving out from under the prefix — this
/// fails, and the fast path becomes a real behaviour that owes a real row.
#[test]
fn revocation_by_target_is_inside_the_scanned_prefix() {
    let bh = Hash::from_bytes(&[0u8; 33]).expect("zero hash");
    let by_target = crate::revocation_by_target_path(PEER, &bh);
    assert!(
        by_target.starts_with(&crate::revocation_prefix(PEER)),
        "the by-target index key must sit under the scanned prefix — the §3.1 \
         scan and the §6a.6 lookup would otherwise see different sets"
    );
}

// ---------------------------------------------------------------------------
// Resolution log
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolution_log_writes_and_recovers_seq() {
    let (cs, li) = stores();
    let pet = LocalNameHandler::new(cs.clone(), li.clone(), PEER.into());
    pet.handle(&ctx(
        "bind",
        vec![
            (text("name"), text("e")),
            (text("target_peer_id"), text("z6MkE")),
        ],
    ))
    .await
    .unwrap();
    let reg = registry(&cs, &li);
    for _ in 0..3 {
        reg.handle(&ctx("resolve", vec![(text("name"), text("e"))]))
            .await
            .unwrap();
    }
    // 3 log entries written at seq 0,1,2.
    let entries = li.list(&crate::resolution_log_prefix(PEER));
    assert_eq!(entries.len(), 3);
    // A fresh log recovers next_seq = 3.
    let log2 = ResolutionLog::new(cs.clone(), li.clone(), PEER.into(), 1024);
    assert_eq!(log2.peek_next_seq(), 3);
}

#[tokio::test]
async fn resolution_log_skips_fallback_reresolve() {
    let (cs, li) = stores();
    let pet = LocalNameHandler::new(cs.clone(), li.clone(), PEER.into());
    pet.handle(&ctx(
        "bind",
        vec![
            (text("name"), text("f")),
            (text("target_peer_id"), text("z6MkF")),
        ],
    ))
    .await
    .unwrap();
    let reg = registry(&cs, &li);
    reg.handle(&ctx(
        "resolve",
        vec![
            (text("name"), text("f")),
            (text("is_fallback_reresolve"), Value::Bool(true)),
        ],
    ))
    .await
    .unwrap();
    assert_eq!(li.list(&crate::resolution_log_prefix(PEER)).len(), 0);
}

#[test]
fn resolution_log_ring_eviction() {
    let (cs, li) = stores();
    let log = ResolutionLog::new(cs.clone(), li.clone(), PEER.into(), 3);
    for i in 0..5 {
        log.record(&format!("n{}", i), "not_found", None, None, None, false);
    }
    // capacity 3 → only seq 2,3,4 pointers remain.
    let entries = li.list(&crate::resolution_log_prefix(PEER));
    assert_eq!(entries.len(), 3);
}

// ---------------------------------------------------------------------------
// §4 `name_format_dispatch.pattern` — the closed grammar
// ---------------------------------------------------------------------------

/// `REG-DISPATCH-GRAMMAR-1` (REQUIRED, cross-impl-observable) — the four
/// rows arch pinned at `REGISTRY 1.13`, each with the control that makes it
/// discriminating.
///
/// Rows 1 and 2 are what fail against a POSIX / shell-glob matcher, which is
/// what this peer shipped: `?` had a one-character meaning and `[…]` a
/// character-class meaning the grammar does not grant. Row 4 is what fails
/// against a **path**-glob, where `*` stops at `/`. **A matcher that merely
/// omits those features and one that treats them as literals are
/// indistinguishable until a name or a pattern carries one.**
#[test]
fn reg_dispatch_grammar_1() {
    // Row 1 — `?` is a literal question mark, not "any one character".
    assert!(dispatch_match("a?c", "a?c"));
    assert!(!dispatch_match("a?c", "abc"));

    // Row 2 — `[…]` is four literal bytes, not a character class.
    assert!(dispatch_match("a[bc]d", "a[bc]d"));
    assert!(!dispatch_match("a[bc]d", "abd"));

    // Row 3 — any NUMBER of `*` is permitted; `*@*.*` is three, and it is in
    // §4.1a's own table.
    assert!(dispatch_match("*@*.*", "alice@example.com"));

    // Row 4 — `*` crosses `/`. A name is a flat string with no segment
    // structure; this is the row that fails against every path-glob.
    assert!(dispatch_match("x*z", "x/y/z"));
}

/// The rest of the grammar, since each clause of §4's pseudocode is one
/// assertion and none of them is exercised by the four rows above.
#[test]
fn dispatch_grammar_closed_clauses() {
    // `*` matches any run INCLUDING NONE.
    assert!(dispatch_match("a*c", "ac"));
    assert!(dispatch_match("*", ""));

    // Anchored at BOTH ends — there is no substring form.
    assert!(!dispatch_match("bc", "abcd"));
    assert!(dispatch_match("*bc*", "abcd"));

    // Every other byte is a literal, including the ones a shell would eat.
    for (pattern, name) in [
        ("a\\c", "a\\c"),
        ("a.c", "a.c"),
        ("did:web:*", "did:web:example.com"),
        ("*.eth", "vitalik.eth"),
    ] {
        assert!(dispatch_match(pattern, name), "{pattern:?} vs {name:?}");
    }
    assert!(!dispatch_match("a.c", "abc"), "`.` is a literal dot");
    assert!(!dispatch_match("*.eth", "vitalik.com"));
    assert!(!dispatch_match("*@*.*", "noatsign"));

    // No pattern is invalid — every string is well-formed because every
    // non-`*` byte is a literal. An unterminated `[` is a literal `[`, not a
    // parse failure and not a rejection.
    assert!(dispatch_match("a[b", "a[b"));
    assert!(!dispatch_match("a[b", "ab"));
}

/// §4.1 step 2 `[MUST, REGISTRY 1.14]` — **eligibility is a pure function of
/// the name**: the union of the matching rules' `backend_kinds`, and a kind
/// reaches eligibility only by being *named*.
///
/// This test asserted the opposite until the ruling (*"a kind named by no rule
/// defaults to match-all"*), which is the branch this peer shipped and routed;
/// arch's `ROUTING-2026-08-19-a` confirmed the contradiction report and changed
/// the text, ruling **against** this row. It is the row that made step 2's own
/// privacy MUST evadable by omitting a rule — a `dns-txt` backend named
/// nowhere was consulted for every bare name — which is the argument we filed
/// against our own reading.
///
/// **Teeth:** reinstating the old `restricted`-set branch in `meta_resolve`
/// flips exactly this test and leaves
/// `meta_resolver_dispatch_filter_excludes_local_name` (the other row, which
/// we always had right) green.
#[tokio::test]
async fn a_kind_named_by_no_dispatch_rule_is_not_eligible() {
    let (cs, li) = stores();
    let pet = LocalNameHandler::new(cs.clone(), li.clone(), PEER.into());
    pet.handle(&ctx(
        "bind",
        vec![
            (text("name"), text("a?c")),
            (text("target_peer_id"), text("z6MkAlice")),
        ],
    ))
    .await
    .unwrap();

    // A rule that MATCHES the queried name and names a kind the chain does
    // not carry. `local-name` appears in no rule at all, so it is not in the
    // eligible union and the chain narrows to empty.
    let cfg = ResolverConfigData {
        resolver_chain: vec![ResolverChainEntry {
            backend_kind: "local-name".into(),
            backend_id: PEER.into(),
            priority: 0,
            accepted_trust_anchors: vec![],
            hints: None,
        }],
        name_format_dispatch: vec![DispatchRule {
            pattern: "a?c".into(),
            backend_kinds: vec!["did-web".into()],
        }],
        ..Default::default()
    };
    install_config(&cs, &li, &cfg);
    let reg = registry(&cs, &li);
    let r = reg
        .handle(&ctx("resolve", vec![(text("name"), text("a?c"))]))
        .await
        .unwrap();
    assert_eq!(
        result_field(&decode_result(&r), "status")
            .unwrap()
            .as_text(),
        Some("chain_exhausted"),
        "a kind named by no dispatch rule is not eligible (§4.1 step 2, 1.14)"
    );
}

/// The `None` branch of the same ruling: *"if `rules` is absent or empty,
/// return ALL"* — the filter is **disabled**, not empty-set. Pinned because
/// the fail-closed reading above is one line away from swallowing the
/// unconfigured deployment, which is every peer that never writes a
/// resolver-config (`default_local_name_only`).
#[tokio::test]
async fn an_absent_dispatch_list_disables_the_filter_rather_than_narrowing_to_empty() {
    let (cs, li) = stores();
    let pet = LocalNameHandler::new(cs.clone(), li.clone(), PEER.into());
    pet.handle(&ctx(
        "bind",
        vec![
            (text("name"), text("alice")),
            (text("target_peer_id"), text("z6MkAlice")),
        ],
    ))
    .await
    .unwrap();

    let cfg = ResolverConfigData {
        resolver_chain: vec![ResolverChainEntry {
            backend_kind: "local-name".into(),
            backend_id: PEER.into(),
            priority: 0,
            accepted_trust_anchors: vec![],
            hints: None,
        }],
        name_format_dispatch: vec![], // no rules at all
        ..Default::default()
    };
    install_config(&cs, &li, &cfg);
    let reg = registry(&cs, &li);
    let r = reg
        .handle(&ctx("resolve", vec![(text("name"), text("alice"))]))
        .await
        .unwrap();
    assert_eq!(
        result_field(&decode_result(&r), "status")
            .unwrap()
            .as_text(),
        Some("resolved"),
        "an empty name_format_dispatch disables the filter (§4.1 step 2, 1.14)"
    );
}

/// §4.1a rows 2 and 6 are a **no-op for this peer, proven by construction**
/// — arch's `-o` §4 files them as *"owed if you ship the list"*, and we do
/// not ship it.
///
/// The bounded region that makes the enumeration exhaustive is *every
/// construction of a `ResolverConfigData` and every write to
/// `resolver_config_path` in non-test code*, not a grep for `did:web:`.
/// There are exactly three: `RegistryHandler::default_local_name_only`
/// (below); `cmd/entity-peer`'s `--peer-issued-registry` install, which builds
/// its chain explicitly and takes `name_format_dispatch` from
/// `..Default::default()`; and — since §4.3 `[v1.18]` — the
/// `set-resolver-config` handler, which stores the **operator's** submitted
/// bytes verbatim and authors no list of its own. `DispatchRule` itself is
/// constructed only by the decoder — i.e. only from a config an operator
/// supplied.
///
/// This is the gate, not the proof: if a seed policy ever *does* ship the
/// §4.1a list, this test fails and rows 2 (`did:key:*` → `self-certifying`)
/// and 6 (catch-all admits `out-of-band`, not `pinned`) become owed at their
/// v1.13 values.
#[test]
fn we_ship_no_default_dispatch_list_so_rows_2_and_6_are_inert() {
    let cfg = ResolverConfigData::default();
    assert!(
        cfg.name_format_dispatch.is_empty(),
        "shipping a §4.1a default list makes rows 2 and 6 owed — see arch ROUTING-2026-08-18-q §3"
    );

    // With no entries at all the filter is disabled and every backend is
    // eligible (§4.1 step 2, 1.14) — pinned from the other side by
    // `an_absent_dispatch_list_disables_the_filter_rather_than_narrowing_to_empty`.
    // §4's *"a name matching no entry is treated as matching the catch-all"*
    // was **withdrawn** at 1.14 and is deliberately not cited here: the
    // catch-all is `*`, which matches every name, so the sentence named a row
    // with no referent.
    assert!(cfg.resolver_chain.is_empty());
}

/// `REG-NAME-CONSTRAINTS-GRAMMAR-1` (§11.1) — §6a.9.1's `name_constraints`
/// is **§4's closed grammar** `[MUST, REGISTRY 1.15]`, one name matcher per
/// registry (arch `c984f93`, `ROUTING-2026-08-19-c` §1).
///
/// Every row here asserted the **opposite** until the ruling: the field said
/// `<glob | null>` and defined the grammar nowhere, so this peer held the
/// POSIX reading it had always had and routed rather than converged. core-go's
/// `registry_issuer.name_constraints_grammar` measured that as a live FAIL
/// against us at row 1 (`"a?c"` admitted `abc`, 200 where the ruling says
/// 403) — the admission gate two registries running one operator policy
/// disagreed on.
#[test]
fn name_constraints_uses_the_closed_dispatch_grammar() {
    // Control — the field's only spec example. Grammar-identical under every
    // candidate reading, which is why it discriminated nothing and the
    // divergence survived review on both sides of the wire for as long as it
    // did.
    assert!(name_constraints_match("*.lab", "widget.lab"));
    assert!(!name_constraints_match("*.lab", "widget.com"));

    // Row 1 — `?` is a LITERAL.
    assert!(!name_constraints_match("a?c", "abc"));
    assert!(name_constraints_match("a?c", "a?c"));

    // Row 2 — `[…]` is literal bytes, not a character class, and `!` negates
    // nothing.
    assert!(!name_constraints_match("[a-c]x", "bx"));
    assert!(name_constraints_match("[a-c]x", "[a-c]x"));
    assert!(!name_constraints_match("[!a-c]x", "dx"));

    // Row 4 — **no pattern is invalid**, which is why it is asserted apart
    // from row 2: a shell-glob fails this row by *erroring* rather than by
    // answering wrongly. go 500ed here; we answered a wrong 403, because
    // `posix_class` returned `None` on the unterminated class and so refused
    // the literal name the policy names. Neither is reachable now — there is
    // no error path to take and nothing for `set-issuer-policy` to reject.
    assert!(name_constraints_match("a[b", "a[b"));
    assert!(!name_constraints_match("a[b", "ab"));

    // Row 3 — `*` crosses `/` — holds at the matcher and is **unbindable over
    // the wire on this peer**, for a reason 1.15 does not control:
    // `handle_register` runs §6.3 `validate_name_safety` (no `/` in a name)
    // BEFORE the policy check, so no register-request carrying `x/y/z` ever
    // reaches the matcher. Same shape as `REG-DISPATCH-GRAMMAR-1`'s `x*z` row,
    // and the same in core-go (`normalizeName`) — their spec-issue
    // `2026-08-19-b` asks §11.1 to mark both rows in-tree-only. Pinned here,
    // not claimed on the wire.
    assert!(name_constraints_match("x*z", "x/y/z"));
    assert!(
        crate::data::validate_name_safety("x/y/z").is_err(),
        "row 3 is unbindable through register-request — §6.3 rejects the name first"
    );

    // ONE matcher, not two agreeing. This was an `assert_ne!` — "these MUST
    // NOT be the same function" — until the ruling; the drift it guarded
    // against is now prevented by there being nothing to drift.
    for (p, n) in [
        ("a?c", "abc"),
        ("[a-c]x", "bx"),
        ("a[b", "a[b"),
        ("x*z", "x/y/z"),
        ("*.lab", "widget.lab"),
    ] {
        assert_eq!(
            name_constraints_match(p, n),
            dispatch_match(p, n),
            "§6a.9.1 and §4 are one matcher (1.15) — pattern {p:?} vs name {n:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Binding signature verification primitive (§3)
// ---------------------------------------------------------------------------

#[test]
fn self_certifying_binding_verifies_without_signature() {
    use crate::resolver::verify_binding_signature;
    let kp = entity_crypto::Keypair::generate();
    let peer_id = entity_crypto::PeerId::from_keypair(&kp)
        .as_str()
        .to_string();
    let b = BindingData {
        name: peer_id.clone(),
        kind: KIND_SELF_CERTIFYING.into(),
        target_peer_id: peer_id,
        transports: vec![],
        issued_at: 0,
        ttl: None,
        supersedes: None,
        issuer_attestation: None,
        metadata: None,
    };
    let (cs, li) = stores();
    let included = std::collections::HashMap::new();
    let h = b.to_entity().unwrap().content_hash;
    assert!(verify_binding_signature(&b, &h, &cs, &li, &included));

    // Tampered self-certifying (name != target) → reject.
    let mut bad = b.clone();
    bad.name = "not-the-peer-id".into();
    assert!(!verify_binding_signature(&bad, &h, &cs, &li, &included));
}

// ===========================================================================
// Peer-issued backend (PROPOSAL-PEER-ISSUED-REGISTRY-BACKEND) — Part-A vectors.
//
// The reads resolve against the local store: the offline/precede path (§2.2),
// which is byte-identical to a live fetch's verify (precedes are a warm cache).
// ===========================================================================

use crate::peer_issued;
use crate::{
    by_name_pointer_path, revocation_prefix, signature_pointer_path, BACKEND_KIND_PEER_ISSUED,
};
use entity_crypto::Keypair;

fn pi_entry(registry_id: &str, hints: Option<Value>) -> ResolverChainEntry {
    ResolverChainEntry {
        backend_kind: BACKEND_KIND_PEER_ISSUED.into(),
        backend_id: registry_id.into(),
        priority: 0,
        accepted_trust_anchors: vec![],
        hints,
    }
}

/// Sign `target` with `signer` and publish the signature at the invariant
/// pointer under the registry's namespace, plus the signer's identity entity.
fn sign_into(
    cs: &Arc<dyn ContentStore>,
    li: &Arc<dyn LocationIndex>,
    registry_id: &str,
    signer: &Keypair,
    target: &Hash,
) {
    cs.put(signer.peer_entity().unwrap()).unwrap();
    let sig = entity_types::SignatureData {
        target: *target,
        signer: signer.peer_identity_hash(),
        algorithm: "ed25519".into(),
        signature: signer.sign(&target.to_bytes()).to_vec(),
    };
    let sig_entity = sig.to_entity().unwrap();
    let sig_hash = sig_entity.content_hash;
    cs.put(sig_entity).unwrap();
    li.set(&signature_pointer_path(registry_id, target), sig_hash);
}

/// A comfortably-live TTL for peer-issued fixtures. D3 makes a non-null `ttl`
/// mandatory for `kind: "peer-issued"`, so fixtures that are testing something
/// else (signature pinning, revocation, chain order) must carry a real one —
/// otherwise they would pass for the wrong reason, refused by the D3 rule
/// rather than by the thing under test.
const LIVE_TTL_MS: u64 = 86_400_000;

/// Publish a peer-issued binding into the local store (the precede path):
/// body + by-name pointer + invariant-pointer signature (by `signer`).
#[allow(clippy::too_many_arguments)]
fn publish_binding(
    cs: &Arc<dyn ContentStore>,
    li: &Arc<dyn LocationIndex>,
    registry_id: &str,
    signer: &Keypair,
    name: &str,
    target: &str,
    issued_at: u64,
    ttl: Option<u64>,
) -> Hash {
    let binding = BindingData {
        name: name.into(),
        kind: KIND_PEER_ISSUED.into(),
        target_peer_id: target.into(),
        transports: vec![Value::Text("tcp://billslab.com:9000".into())],
        issued_at,
        ttl,
        supersedes: None,
        issuer_attestation: None,
        metadata: None,
    };
    let entity = binding.to_entity().unwrap();
    let binding_hash = entity.content_hash;
    cs.put(entity).unwrap();
    li.set(&by_name_pointer_path(registry_id, name), binding_hash);
    sign_into(cs, li, registry_id, signer, &binding_hash);
    binding_hash
}

// REG-PEERISSUED-RESOLVE-1 — happy path: by-name → binding → verify against the
// pinned registry key → resolved.
#[test]
fn peer_issued_resolve_happy_path() {
    let (cs, li) = stores();
    let registry = Keypair::generate();
    let rid = registry.peer_id().as_str().to_string();
    let target = Keypair::generate().peer_id().as_str().to_string();
    let bh = publish_binding(
        &cs,
        &li,
        &rid,
        &registry,
        "billslab.com",
        &target,
        crate::log::now_ms(),
        Some(LIVE_TTL_MS),
    );

    let r = peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "billslab.com")
        .expect("backend returned a result");
    assert!(r.is_resolved(), "expected resolved, got {}", r.status);
    assert_eq!(r.peer_id.as_deref(), Some(target.as_str()));
    assert_eq!(r.binding, Some(bh));
    assert_eq!(
        r.trust_anchor.as_deref(),
        Some(format!("peer_issued:{rid}").as_str())
    );
    assert_eq!(r.backend_id.as_deref(), Some(rid.as_str()));
    assert_eq!(r.transports.len(), 1);
}

// REG-PEERISSUED-VERIFY-FAIL-1 — binding signed by a NON-pinned key → rejected,
// chain advances. NOT accepted, NOT downgraded to a pin.
#[test]
fn peer_issued_verify_fail_rejected() {
    let (cs, li) = stores();
    let registry = Keypair::generate();
    let attacker = Keypair::generate();
    let rid = registry.peer_id().as_str().to_string();
    let target = Keypair::generate().peer_id().as_str().to_string();
    // Signed by the attacker, but the chain entry pins the real registry id.
    publish_binding(
        &cs,
        &li,
        &rid,
        &attacker,
        "billslab.com",
        &target,
        crate::log::now_ms(),
        Some(LIVE_TTL_MS),
    );

    let r = peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "billslab.com");
    assert!(
        r.is_none(),
        "non-pinned signer must reject (chain advances), got {r:?}"
    );
}

// REG-PEERISSUED-REVOKED-1 — valid binding + a verifying revocation → excluded.
// Also asserts an UNSIGNED revocation does NOT exclude (peer-issued revocations
// MUST verify against the registry key, proposal §2.3).
#[test]
fn peer_issued_revoked_excluded() {
    let (cs, li) = stores();
    let registry = Keypair::generate();
    let rid = registry.peer_id().as_str().to_string();
    let target = Keypair::generate().peer_id().as_str().to_string();
    let bh = publish_binding(
        &cs,
        &li,
        &rid,
        &registry,
        "billslab.com",
        &target,
        crate::log::now_ms(),
        Some(LIVE_TTL_MS),
    );

    // Unsigned revocation present → still resolves (signature is required).
    let rev = RevocationData {
        revokes: bh,
        revoked_at: 2000,
        reason: None,
    };
    let rev_entity = rev.to_entity().unwrap();
    let rev_hash = rev_entity.content_hash;
    cs.put(rev_entity).unwrap();
    li.set(
        &format!("{}{}", revocation_prefix(&rid), rev_hash.to_hex()),
        rev_hash,
    );
    // §6a.6: the resolver finds a revocation through the by-target INDEX, not by
    // scanning the revocation subtree. A fixture that files only the own-hash
    // pointer is invisible to a conformant resolver.
    li.set(&crate::revocation_by_target_path(&rid, &bh), rev_hash);
    assert!(
        peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "billslab.com")
            .map(|r| r.is_resolved())
            .unwrap_or(false),
        "unsigned revocation must NOT exclude"
    );

    // Registry-signed revocation → excluded, chain advances.
    sign_into(&cs, &li, &rid, &registry, &rev_hash);
    let r = peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "billslab.com");
    assert!(r.is_none(), "verifying revocation must exclude, got {r:?}");
}

// D1 (REG-PEERISSUED-NAME-SUBSTITUTION-1) — a validly-signed binding for name X,
// served at `by-name/{Y}`, MUST NOT answer a query for Y.
//
// This is the hostile-host substitution: the attacker never forges anything. It
// repoints one pointer file at a binding the registry genuinely issued, so every
// signature check passes. The `name` is inside the SIGNED body, so the
// association is committed — we were discarding it. Nothing else on this path
// can catch it, which is why the check is fail-closed and advances the chain.
//
// Teeth: delete the `binding.name != norm` comparison in `resolve_one` and this
// resolves `evil.example` to the honest binding's target.
#[test]
fn peer_issued_name_substitution_refused() {
    let (cs, li) = stores();
    let registry = Keypair::generate();
    let rid = registry.peer_id().as_str().to_string();
    let target = Keypair::generate().peer_id().as_str().to_string();

    // The registry legitimately issues + signs a binding for `honest.example`.
    let bh = publish_binding(
        &cs,
        &li,
        &rid,
        &registry,
        "honest.example",
        &target,
        crate::log::now_ms(),
        Some(LIVE_TTL_MS),
    );

    // A hostile host serving the registry's tree repoints `evil.example` at it.
    // No forgery: same entity, same registry signature, different pointer.
    li.set(&by_name_pointer_path(&rid, "evil.example"), bh);

    let r = peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "evil.example");
    assert!(
        r.is_none(),
        "a binding whose signed name is `honest.example` MUST NOT answer a query \
         for `evil.example` — got {r:?}"
    );

    // The honest name still resolves, so the check is a comparison and not a
    // blanket refusal.
    assert!(
        peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "honest.example")
            .map(|r| r.is_resolved())
            .unwrap_or(false),
        "the legitimately-bound name must still resolve"
    );
}

// D3 (REG-PEERISSUED-NULL-TTL-1) — a `peer-issued` binding with a null `ttl` is
// refused and the chain advances.
//
// Revocation is the only other check on this path that can retire a compromised
// binding, and it asks the hostile host — which can withhold. `issued_at + ttl`
// is computed locally from the signed body, so it is the one bound the attacker
// cannot touch. Null ttl means permanently unrevokable.
//
// Teeth: restore `if let Some(ttl) = binding.ttl` (ttl-null = no expiry) and
// this resolves.
#[test]
fn peer_issued_null_ttl_refused() {
    let (cs, li) = stores();
    let registry = Keypair::generate();
    let rid = registry.peer_id().as_str().to_string();
    let target = Keypair::generate().peer_id().as_str().to_string();
    publish_binding(
        &cs,
        &li,
        &rid,
        &registry,
        "billslab.com",
        &target,
        crate::log::now_ms(),
        None, // null ttl — permanently unrevokable against a withholding origin
    );

    let r = peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "billslab.com");
    assert!(
        r.is_none(),
        "a peer-issued binding with null ttl MUST be refused (D3), got {r:?}"
    );
}

// §6a.6 / P7 — revocation is found through the by-target INDEX, not a scan of the
// revocation subtree.
//
// Teeth: restore the `location_index.list(revocation_prefix(..))` scan and the
// second half of this test passes anyway (the scan finds the same revocation by
// its `revokes` field) — which is exactly why the divergence stayed invisible.
// The FIRST half is the part that bites: a revocation filed ONLY under the
// own-hash pointer must not exclude, because a conformant resolver never looks
// there.
#[test]
fn peer_issued_revocation_is_found_by_target_index_not_by_scan() {
    let (cs, li) = stores();
    let registry = Keypair::generate();
    let rid = registry.peer_id().as_str().to_string();
    let target = Keypair::generate().peer_id().as_str().to_string();
    let bh = publish_binding(
        &cs,
        &li,
        &rid,
        &registry,
        "billslab.com",
        &target,
        crate::log::now_ms(),
        Some(LIVE_TTL_MS),
    );

    // A signed revocation that exists in the subtree but is NOT in the index.
    let rev = RevocationData {
        revokes: bh,
        revoked_at: crate::log::now_ms(),
        reason: None,
    };
    let rev_entity = rev.to_entity().unwrap();
    let rev_hash = rev_entity.content_hash;
    cs.put(rev_entity).unwrap();
    li.set(
        &format!("{}{}", revocation_prefix(&rid), rev_hash.to_hex()),
        rev_hash,
    );
    sign_into(&cs, &li, &rid, &registry, &rev_hash);

    assert!(
        peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "billslab.com")
            .map(|r| r.is_resolved())
            .unwrap_or(false),
        "an unindexed revocation must not exclude — a §6a.6 resolver reads the \
         by-target index, so finding this one would prove we are scanning"
    );

    // Filed in the index → excluded.
    li.set(&crate::revocation_by_target_path(&rid, &bh), rev_hash);
    assert!(
        peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "billslab.com").is_none(),
        "an indexed, registry-signed revocation MUST exclude"
    );
}

// §6a.6 — the index KEY is host-served and proves nothing. A genuine
// registry-signed revocation for binding A, filed under `by-target/{B}`, must not
// revoke B: the `revokes` field inside the signed body is what the registry
// committed to.
#[test]
fn peer_issued_misfiled_revocation_does_not_revoke_the_wrong_binding() {
    let (cs, li) = stores();
    let registry = Keypair::generate();
    let rid = registry.peer_id().as_str().to_string();
    let target = Keypair::generate().peer_id().as_str().to_string();
    let victim = publish_binding(
        &cs,
        &li,
        &rid,
        &registry,
        "victim.example",
        &target,
        crate::log::now_ms(),
        Some(LIVE_TTL_MS),
    );
    let other = publish_binding(
        &cs,
        &li,
        &rid,
        &registry,
        "other.example",
        &target,
        crate::log::now_ms(),
        Some(LIVE_TTL_MS),
    );

    // Genuine, registry-signed revocation — but it revokes `other`, not `victim`.
    let rev = RevocationData {
        revokes: other,
        revoked_at: crate::log::now_ms(),
        reason: None,
    };
    let rev_entity = rev.to_entity().unwrap();
    let rev_hash = rev_entity.content_hash;
    cs.put(rev_entity).unwrap();
    sign_into(&cs, &li, &rid, &registry, &rev_hash);
    // The hostile host misfiles it under the victim's index key.
    li.set(&crate::revocation_by_target_path(&rid, &victim), rev_hash);

    assert!(
        peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "victim.example")
            .map(|r| r.is_resolved())
            .unwrap_or(false),
        "a revocation whose signed `revokes` names another binding must not \
         revoke this one — the index key is not evidence"
    );
}

// REG-PEERISSUED-EXPIRED-1 — issued_at + ttl < now → excluded.
#[test]
fn peer_issued_expired_excluded() {
    let (cs, li) = stores();
    let registry = Keypair::generate();
    let rid = registry.peer_id().as_str().to_string();
    let target = Keypair::generate().peer_id().as_str().to_string();
    // issued_at=1ms, ttl=1ms → expired long ago.
    publish_binding(
        &cs,
        &li,
        &rid,
        &registry,
        "billslab.com",
        &target,
        1,
        Some(1),
    );

    let r = peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "billslab.com");
    assert!(r.is_none(), "expired binding must be excluded, got {r:?}");
}

// REG-PEERISSUED-PRECEDE-1 — a binding resolved from the local store (precede)
// has identical verify + result as a live fetch. Here the store IS the precede;
// the assertion is that the offline path produces a fully-verified resolved
// result (same code path the live-fetch precede would populate).
#[test]
fn peer_issued_precede_identical_to_live() {
    let (cs, li) = stores();
    let registry = Keypair::generate();
    let rid = registry.peer_id().as_str().to_string();
    let target = Keypair::generate().peer_id().as_str().to_string();
    publish_binding(
        &cs,
        &li,
        &rid,
        &registry,
        "billslab.com",
        &target,
        crate::log::now_ms(),
        Some(LIVE_TTL_MS),
    );

    let r = peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "billslab.com").unwrap();
    assert!(r.is_resolved());
    assert_eq!(
        r.trust_anchor.as_deref(),
        Some(format!("peer_issued:{rid}").as_str())
    );
}

// REG-PEERISSUED-OFFLINE-NOTFOUND-1 — name not in the by-name index → not_found
// with neg_ttl (read from the chain entry's hints, spec-problems P3).
#[test]
fn peer_issued_offline_not_found() {
    let (cs, li) = stores();
    let registry = Keypair::generate();
    let rid = registry.peer_id().as_str().to_string();
    cs.put(registry.peer_entity().unwrap()).unwrap();
    let hints = Value::Map(vec![(text("neg_ttl"), entity_ecf::integer(5000))]);

    let r = peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, Some(hints)), "absent.com")
        .expect("backend returns a not_found result");
    assert_eq!(r.status, STATUS_NOT_FOUND);
    assert_eq!(r.neg_ttl, Some(5000));
    assert!(r.binding.is_none());
}

// Integration through meta_resolve: a peer-issued chain entry resolves end-to-end.
#[tokio::test]
async fn peer_issued_via_meta_resolve() {
    let (cs, li) = stores();
    let registry_kp = Keypair::generate();
    let rid = registry_kp.peer_id().as_str().to_string();
    let target = Keypair::generate().peer_id().as_str().to_string();
    publish_binding(
        &cs,
        &li,
        &rid,
        &registry_kp,
        "billslab.com",
        &target,
        crate::log::now_ms(),
        Some(LIVE_TTL_MS),
    );

    let cfg = ResolverConfigData {
        resolver_chain: vec![pi_entry(&rid, None)],
        ..Default::default()
    };
    let cfg_entity = cfg.to_entity().unwrap();
    let cfg_hash = cfg_entity.content_hash;
    cs.put(cfg_entity).unwrap();
    li.set(&crate::resolver_config_path(PEER), cfg_hash);

    let handler = registry(&cs, &li);
    let result = handler
        .handle(&ctx("resolve", vec![(text("name"), text("billslab.com"))]))
        .await
        .unwrap();
    let map = decode_result(&result);
    assert_eq!(
        result_field(&map, "status").and_then(|v| v.as_text()),
        Some("resolved")
    );
    assert_eq!(
        result_field(&map, "peer_id").and_then(|v| v.as_text()),
        Some(target.as_str())
    );
}

// VERIFY-FAIL through meta_resolve → chain_exhausted (fail-closed, no pin downgrade).
#[tokio::test]
async fn peer_issued_verify_fail_via_meta_is_chain_exhausted() {
    let (cs, li) = stores();
    let registry_kp = Keypair::generate();
    let attacker = Keypair::generate();
    let rid = registry_kp.peer_id().as_str().to_string();
    let target = Keypair::generate().peer_id().as_str().to_string();
    publish_binding(
        &cs,
        &li,
        &rid,
        &attacker,
        "billslab.com",
        &target,
        crate::log::now_ms(),
        Some(LIVE_TTL_MS),
    );

    let cfg = ResolverConfigData {
        resolver_chain: vec![pi_entry(&rid, None)],
        ..Default::default()
    };
    let cfg_entity = cfg.to_entity().unwrap();
    let cfg_hash = cfg_entity.content_hash;
    cs.put(cfg_entity).unwrap();
    li.set(&crate::resolver_config_path(PEER), cfg_hash);

    let handler = registry(&cs, &li);
    let result = handler
        .handle(&ctx("resolve", vec![(text("name"), text("billslab.com"))]))
        .await
        .unwrap();
    let map = decode_result(&result);
    assert_eq!(
        result_field(&map, "status").and_then(|v| v.as_text()),
        Some("chain_exhausted"),
        "verify-fail must fail closed, never downgrade to a pin"
    );
}

// ---------------------------------------------------------------------------
// §6a.9 live registration — register-request / issuer-policy / replay
// ---------------------------------------------------------------------------

use std::collections::HashMap;

use crate::registration::RegisterRequestHandler;
use crate::{issuer_policy_path, RegisterRequestData};
use entity_crypto::IdentityKeypair;
use entity_types::SignatureData;

fn reg_handler(
    cs: &Arc<dyn ContentStore>,
    li: &Arc<dyn LocationIndex>,
    registry: &IdentityKeypair,
) -> RegisterRequestHandler {
    RegisterRequestHandler::new(
        cs.clone(),
        li.clone(),
        registry.peer_id().as_str().to_string(),
        registry.clone_identity(),
    )
}

fn install_policy(
    cs: &Arc<dyn ContentStore>,
    li: &Arc<dyn LocationIndex>,
    registry_id: &str,
    policy: &IssuerPolicyData,
) {
    let e = policy.to_entity().unwrap();
    let h = e.content_hash;
    cs.put(e).unwrap();
    li.set(&issuer_policy_path(registry_id), h);
}

/// Build a `register-request` entity for `name → target`, fresh `issued_at`.
fn mk_request(name: &str, target: &str, nonce: &[u8]) -> Entity {
    RegisterRequestData {
        name: name.into(),
        target_peer_id: target.into(),
        transports: vec![Value::Text("tcp://billslab.com:9000".into())],
        requested_ttl: Some(86_400_000),
        nonce: nonce.to_vec(),
        issued_at: crate::log::now_ms(),
    }
    .to_entity()
    .unwrap()
}

/// A `register-request` ctx: params = the request entity; `included` carries the
/// layer-1 `system/signature` (by `signing_key`) over the request hash + the
/// signer's `system/peer` entity.
/// Spec-pinned request types for the two follow-on ops (§6a.9). The handler
/// decodes the params map and does not branch on the type, but a test that
/// sends the wrong type proves less than it looks like it does.
const TYPE_REVOKE_REQUEST: &str = "system/registry/revoke-request";
const TYPE_RENEW_REQUEST: &str = "system/registry/renew-request";

/// A `revoke`/`renew` request carrying a layer-1 `system/signature` by
/// `signing_key` over its own `content_hash` (§6a.9). The unsigned counterpart
/// is [`ctx`] — which is what these two ops used to be tested with, and is
/// exactly the request a stranger sends.
fn signed_op_ctx(
    op: &str,
    entity_type: &str,
    params_fields: Vec<(Value, Value)>,
    signing_key: &Keypair,
) -> HandlerContext {
    let params = Entity::new(entity_type, to_ecf(&Value::Map(params_fields))).unwrap();
    signed_ctx(op, params, signing_key)
}

/// `renew-request` params per the pinned schema — `nonce` + `issued_at`
/// included, since renew is replay-defended (§6a.9's discriminator: replay
/// extends a binding's life past the registrant's intended lapse).
fn renew_fields(binding_hash: Hash, nonce: &[u8]) -> Vec<(Value, Value)> {
    vec![
        (
            text("binding_hash"),
            Value::Bytes(binding_hash.to_bytes().to_vec()),
        ),
        (text("ttl"), entity_ecf::integer(172_800_000)),
        (text("nonce"), Value::Bytes(nonce.to_vec())),
        (
            text("issued_at"),
            entity_ecf::integer(crate::log::now_ms() as i64),
        ),
    ]
}

fn register_ctx(req: Entity, signing_key: &Keypair) -> HandlerContext {
    signed_ctx("register-request", req, signing_key)
}

fn signed_ctx(op: &str, req: Entity, signing_key: &Keypair) -> HandlerContext {
    let request_hash = req.content_hash;
    let sig = SignatureData {
        target: request_hash,
        signer: signing_key.peer_identity_hash(),
        algorithm: "ed25519".into(),
        signature: signing_key.sign(&request_hash.to_bytes()).to_vec(),
    };
    let sig_entity = sig.to_entity().unwrap();
    let peer_entity = signing_key.peer_entity().unwrap();
    let mut included = HashMap::new();
    included.insert(sig_entity.content_hash, sig_entity);
    included.insert(peer_entity.content_hash, peer_entity);

    let execute = Entity::new(entity_types::TYPE_EXECUTE, to_ecf(&Value::Map(vec![]))).unwrap();
    HandlerContext::builder(execute, req)
        .operation(op.to_string())
        .included(included)
        .build()
}

fn binding_hash_of(r: &entity_handler::HandlerResult) -> Hash {
    let map = decode_result(r);
    let b = result_field(&map, "binding_hash")
        .and_then(|v| v.as_bytes())
        .expect("binding_hash present");
    Hash::from_bytes(b).unwrap()
}

// REG-REGISTER-PROOF-1 — a request whose signature is NOT by target_peer_id is
// rejected (layer-1 ownership proof). `open` policy, so only layer-1 can fail.
#[tokio::test]
async fn register_proof_signature_not_by_target_rejected() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    install_policy(
        &cs,
        &li,
        registry.peer_id().as_str(),
        &IssuerPolicyData {
            mode: MODE_OPEN.into(),
            ..Default::default()
        },
    );

    let owner = Keypair::generate(); // the peer the name should bind to
    let attacker = Keypair::generate(); // signs the request with the WRONG key
    let req = mk_request("billslab.com", owner.peer_id().as_str(), b"n1");
    // Signed by `attacker`, not by `owner` (= target_peer_id) → proof fails.
    let result = reg_handler(&cs, &li, &registry)
        .handle(&register_ctx(req, &attacker))
        .await
        .unwrap();
    // 401, not 403: layer-1 is an authentication result (the requester failed
    // to prove key control), where 403 is layer-2's `not_entitled` (proof
    // accepted, policy says no). Was 403 until 2026-08-10; go and py both
    // answer 401 and the spec pins neither, so rust was the sole outlier.
    assert_eq!(result.status, 401, "non-target signer must be rejected");
}

// REG-REGISTER-POLICY-1 — allowlist: a non-listed target → not_entitled; an
// allow-listed target → issued + resolvable through the peer-issued backend.
#[tokio::test]
async fn register_policy_allowlist() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    let rid = registry.peer_id().as_str().to_string();
    let allowed = Keypair::generate();
    let blocked = Keypair::generate();
    install_policy(
        &cs,
        &li,
        &rid,
        &IssuerPolicyData {
            mode: MODE_ALLOWLIST.into(),
            allowlist: Some(vec![allowed.peer_id().as_str().to_string()]),
            ..Default::default()
        },
    );
    let handler = reg_handler(&cs, &li, &registry);

    // Non-listed target → not_entitled (403).
    let rej = handler
        .handle(&register_ctx(
            mk_request("blocked.com", blocked.peer_id().as_str(), b"nb"),
            &blocked,
        ))
        .await
        .unwrap();
    assert_eq!(rej.status, 403);
    let rej_map = decode_result(&rej);
    assert_eq!(
        result_field(&rej_map, "code").and_then(|v| v.as_text()),
        Some("not_entitled")
    );

    // Allow-listed target → issued, and resolvable end-to-end.
    let ok = handler
        .handle(&register_ctx(
            mk_request("billslab.com", allowed.peer_id().as_str(), b"na"),
            &allowed,
        ))
        .await
        .unwrap();
    assert_eq!(ok.status, 200);
    // §6a.9 step 3 `[RULED 2026-08-12]` — register-request's OWN result type,
    // with `status: "bound"` discriminating the branch. Both halves are
    // cross-peer-observable and neither was carried before the ruling: the
    // type was `system/protocol/status` and the status field was absent.
    assert_eq!(
        ok.result.entity_type,
        entity_types::TYPE_REGISTRY_REGISTER_RESULT
    );
    assert_eq!(
        result_field(&decode_result(&ok), "status").and_then(|v| v.as_text()),
        Some("bound")
    );
    let bh = binding_hash_of(&ok);

    let resolved = peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "billslab.com")
        .expect("resolvable");
    assert!(resolved.is_resolved());
    assert_eq!(resolved.binding, Some(bh));
    assert_eq!(
        resolved.peer_id.as_deref(),
        Some(allowed.peer_id().as_str())
    );
}

/// `REG-NAME-CONSTRAINTS-GRAMMAR-1` through the **admission gate** — the half
/// that is observable on the wire, and the half that decides `403
/// not_entitled` versus a signed, published binding.
///
/// `name_constraints_uses_the_closed_dispatch_grammar` pins the matcher; this
/// pins that the matcher is what `register-request` actually consults. core-go
/// measured exactly this shape against us over the wire
/// (`registry_issuer.name_constraints_grammar` row 1: policy `"a?c"`, request
/// `abc` → **200 on this peer**, expected 403) — so the in-tree half alone
/// would not have caught it, and a matcher test alone would not catch a future
/// edit that stops calling it.
///
/// Row 4 is here too: under the POSIX matcher `a[b` was an *unterminated
/// class* and the literal name `a[b` was refused by the very policy naming it.
/// No pattern is invalid now, so it admits.
#[tokio::test]
async fn name_constraints_admission_reads_the_pattern_as_literal_bytes() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    install_policy(
        &cs,
        &li,
        registry.peer_id().as_str(),
        &IssuerPolicyData {
            mode: MODE_OPEN.into(),
            name_constraints: Some("a?c".into()),
            ..Default::default()
        },
    );
    let handler = reg_handler(&cs, &li, &registry);

    // Row 1 — `?` is a literal, so `abc` is OUTSIDE the constraint. This
    // returned 200 until 1.15.
    let owner = Keypair::generate();
    let rej = handler
        .handle(&register_ctx(
            mk_request("abc", owner.peer_id().as_str(), b"nc-1"),
            &owner,
        ))
        .await
        .unwrap();
    assert_eq!(rej.status, 403, "`?` is a literal — `abc` is not `a?c`");
    assert_eq!(
        result_field(&decode_result(&rej), "code").and_then(|v| v.as_text()),
        Some("not_entitled")
    );

    // …and the literal name the policy names is admitted.
    let ok = handler
        .handle(&register_ctx(
            mk_request("a?c", owner.peer_id().as_str(), b"nc-2"),
            &owner,
        ))
        .await
        .unwrap();
    assert_eq!(
        ok.status, 200,
        "the literal name `a?c` is what `a?c` admits"
    );

    // Row 4 — a "malformed" class is just literal bytes. Fresh registry: the
    // policy is whole-replace and the name is a different one.
    let (cs2, li2) = stores();
    let reg2 = IdentityKeypair::Ed25519(Keypair::generate());
    install_policy(
        &cs2,
        &li2,
        reg2.peer_id().as_str(),
        &IssuerPolicyData {
            mode: MODE_OPEN.into(),
            name_constraints: Some("a[b".into()),
            ..Default::default()
        },
    );
    let h2 = reg_handler(&cs2, &li2, &reg2);
    let ok2 = h2
        .handle(&register_ctx(
            mk_request("a[b", owner.peer_id().as_str(), b"nc-3"),
            &owner,
        ))
        .await
        .unwrap();
    assert_eq!(
        ok2.status, 200,
        "no pattern is invalid — `a[b` stores and admits its own literal, with no 5xx"
    );
}

// REG-REGISTER-REPLAY-1 — a re-submitted request (same requester + nonce) is
// rejected. `open` policy, so the only difference from the first call is the
// seen-nonce marker.
#[tokio::test]
async fn register_replay_rejected() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    install_policy(
        &cs,
        &li,
        registry.peer_id().as_str(),
        &IssuerPolicyData {
            mode: MODE_OPEN.into(),
            ..Default::default()
        },
    );
    let handler = reg_handler(&cs, &li, &registry);
    let owner = Keypair::generate();

    let first = handler
        .handle(&register_ctx(
            mk_request("billslab.com", owner.peer_id().as_str(), b"nonce-1"),
            &owner,
        ))
        .await
        .unwrap();
    assert_eq!(first.status, 200, "first registration succeeds");

    // Replay the same nonce (a fresh name so name_taken can't be the cause).
    let replay = handler
        .handle(&register_ctx(
            mk_request("other.com", owner.peer_id().as_str(), b"nonce-1"),
            &owner,
        ))
        .await
        .unwrap();
    assert_eq!(replay.status, 409);
    let map = decode_result(&replay);
    assert_eq!(
        result_field(&map, "code").and_then(|v| v.as_text()),
        Some("replay")
    );
}

// `manual` mode: a valid request queues as pending_review rather than
// auto-issuing.
//
// The policy is now installed **explicitly**. This test previously installed
// none and relied on the handler defaulting to `manual` — §6a.9.2 rules that
// unset is not a mode, so an unarmed registry answers 404 curated-only
// instead (see `register_against_an_unarmed_registry_is_curated_only_404`).
// That is the behaviour change, not a test fix.
#[tokio::test]
async fn register_manual_queues_pending_review() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    let rid = registry.peer_id().as_str().to_string();
    let owner = Keypair::generate();
    install_policy(
        &cs,
        &li,
        &rid,
        &IssuerPolicyData {
            mode: MODE_MANUAL.into(),
            ..Default::default()
        },
    );
    let request = mk_request("billslab.com", owner.peer_id().as_str(), b"nm");
    let request_hash = request.content_hash;
    let result = reg_handler(&cs, &li, &registry)
        .handle(&register_ctx(request, &owner))
        .await
        .unwrap();
    // 202, not 200: nothing was signed, so "done" is the wrong answer.
    assert_eq!(result.status, 202);
    // §6a.9 `[RULED 2026-08-12]` — the carrier is register-request's own result
    // type, not `system/protocol/status` (rejected on structure) and not
    // `system/protocol/error` (an error entity on a success status).
    assert_eq!(
        result.result.entity_type,
        entity_types::TYPE_REGISTRY_REGISTER_RESULT
    );
    let map = decode_result(&result);
    assert_eq!(
        result_field(&map, "status").and_then(|v| v.as_text()),
        Some("pending_review")
    );
    // REG-PENDING-HANDLE-1 (§6a.9.3). The distinctness half: a hash the client
    // computed before it dispatched is not a handle.
    let pending_hash = pending_hash_of(&result);
    assert_ne!(
        pending_hash, request_hash,
        "pending_hash must name the STORED entity, not the request"
    );
    // The resolvability half — the reason §6a.9.3 exists. Before the schema
    // landed, a handle naming nothing fetchable was indistinguishable from a
    // conformant one, so this is the assertion that has teeth.
    let body = cs.get(&pending_hash).expect("pending_hash resolves");
    let pb = PendingBindingData::from_entity(&body).expect("a pending-binding");
    assert_eq!(pb.status, "pending_review");
    assert_eq!(pb.name, "billslab.com");
    assert_eq!(pb.target_peer_id, owner.peer_id().as_str());
    assert!(pb.binding_hash.is_none());
    // The by-request pointer resolves to the same body.
    assert_eq!(
        li.get(&crate::pending_by_request_path(
            &rid,
            owner.peer_id().as_str(),
            "billslab.com"
        )),
        Some(pending_hash)
    );
    // Nothing was published.
    assert!(li
        .get(&crate::by_name_pointer_path(&rid, "billslab.com"))
        .is_none());
}

// ---------------------------------------------------------------------------
// REG-PENDING-DECIDE-1 (§6a.9.3) — the operator decisions
// ---------------------------------------------------------------------------

fn pending_hash_of(r: &entity_handler::HandlerResult) -> Hash {
    let map = decode_result(r);
    let b = result_field(&map, "pending_hash")
        .and_then(|v| v.as_bytes())
        .expect("pending_hash present");
    Hash::from_bytes(b).unwrap()
}

/// Queue one request in `manual` mode and hand back its head hash.
async fn queue_one(
    cs: &Arc<dyn ContentStore>,
    li: &Arc<dyn LocationIndex>,
    registry: &IdentityKeypair,
    owner: &Keypair,
    name: &str,
    nonce: &[u8],
) -> Hash {
    queue_one_ttl(cs, li, registry, owner, name, nonce, 86_400_000).await
}

/// [`queue_one`] with an explicit `requested_ttl`.
///
/// The supersession vectors need two queued requests whose **bodies differ**.
/// `nonce` alone will not do it: §6a.9.3's `pending-binding` schema carries no
/// nonce, so two retries of one intent inside a single millisecond encode to
/// identical bytes and content-address to one body. That is correct — one head,
/// one hash — but it makes supersession unobservable, so these vectors vary a
/// field the schema actually carries.
async fn queue_one_ttl(
    cs: &Arc<dyn ContentStore>,
    li: &Arc<dyn LocationIndex>,
    registry: &IdentityKeypair,
    owner: &Keypair,
    name: &str,
    nonce: &[u8],
    ttl: u64,
) -> Hash {
    let req = RegisterRequestData {
        name: name.into(),
        target_peer_id: owner.peer_id().as_str().to_string(),
        transports: vec![Value::Text("tcp://billslab.com:9000".into())],
        requested_ttl: Some(ttl),
        nonce: nonce.to_vec(),
        issued_at: crate::log::now_ms(),
    }
    .to_entity()
    .unwrap();
    let result = reg_handler(cs, li, registry)
        .handle(&register_ctx(req, owner))
        .await
        .unwrap();
    assert_eq!(result.status, 202);
    pending_hash_of(&result)
}

fn decision_ctx(op: &str, pending_hash: Hash, reason: Option<&str>) -> HandlerContext {
    let mut fields = vec![(
        text("pending_hash"),
        Value::Bytes(pending_hash.to_bytes().to_vec()),
    )];
    if let Some(r) = reason {
        fields.push((text("reason"), text(r)));
    }
    ctx(op, fields)
}

async fn manual_registry() -> (
    Arc<dyn ContentStore>,
    Arc<dyn LocationIndex>,
    IdentityKeypair,
    String,
    Keypair,
) {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    let rid = registry.peer_id().as_str().to_string();
    install_policy(
        &cs,
        &li,
        &rid,
        &IssuerPolicyData {
            mode: MODE_MANUAL.into(),
            ..Default::default()
        },
    );
    (cs, li, registry, rid, Keypair::generate())
}

// approve issues a binding that resolves by name AND leaves an `approved` head
// carrying the binding_hash.
#[tokio::test]
async fn approve_issues_the_binding_and_leaves_an_approved_head() {
    let (cs, li, registry, rid, owner) = manual_registry().await;
    let ph = queue_one(&cs, &li, &registry, &owner, "billslab.com", b"q1").await;

    let res = reg_handler(&cs, &li, &registry)
        .handle(&decision_ctx("approve-request", ph, None))
        .await
        .unwrap();
    assert_eq!(res.status, 200);
    assert_eq!(
        res.result.entity_type,
        entity_types::TYPE_REGISTRY_REGISTER_RESULT
    );
    let map = decode_result(&res);
    assert_eq!(
        result_field(&map, "status").and_then(|v| v.as_text()),
        Some("bound")
    );
    let binding_hash = binding_hash_of(&res);

    // The binding resolves by name end-to-end.
    let resolved = peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "billslab.com")
        .expect("resolvable");
    assert!(resolved.is_resolved());
    assert_eq!(resolved.binding, Some(binding_hash));

    // …and the head is `approved`, carrying the binding it produced. The head
    // MOVED: the decision writes a new body rather than mutating the queued one.
    let head = li
        .get(&crate::pending_by_request_path(
            &rid,
            owner.peer_id().as_str(),
            "billslab.com",
        ))
        .expect("pointer still resolves");
    assert_ne!(head, ph, "a decision writes a new body, replace-whole");
    let decided = PendingBindingData::from_entity(&cs.get(&head).unwrap()).unwrap();
    assert_eq!(decided.status, "approved");
    assert_eq!(decided.binding_hash, Some(binding_hash));
    // The queued body stays auditable at its own content-addressed path.
    assert!(cs.get(&ph).is_some());
}

// deny leaves a `denied` head AND publishes nothing — the negative half, which
// is the load-bearing one: a deny that silently issued would pass a check that
// only looked at the response.
#[tokio::test]
async fn deny_leaves_a_denied_head_and_publishes_nothing() {
    let (cs, li, registry, rid, owner) = manual_registry().await;
    let ph = queue_one(&cs, &li, &registry, &owner, "billslab.com", b"q2").await;

    let res = reg_handler(&cs, &li, &registry)
        .handle(&decision_ctx("deny-request", ph, Some("not entitled")))
        .await
        .unwrap();
    assert_eq!(res.status, 200);
    assert_eq!(
        result_field(&decode_result(&res), "status").and_then(|v| v.as_text()),
        Some("denied")
    );

    // Nothing signed, nothing published — assert the NAME does not resolve.
    assert!(li
        .get(&crate::by_name_pointer_path(&rid, "billslab.com"))
        .is_none());
    let resolved = peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "billslab.com");
    assert!(resolved.is_none_or(|r| !r.is_resolved()));

    // Deny is NOT a delete: the head persists, or a requester polling a vanished
    // pointer could not tell `denied` from `never received`.
    let head = li
        .get(&crate::pending_by_request_path(
            &rid,
            owner.peer_id().as_str(),
            "billslab.com",
        ))
        .expect("a denied request keeps a reachable head");
    let decided = PendingBindingData::from_entity(&cs.get(&head).unwrap()).unwrap();
    assert_eq!(decided.status, "denied");
    assert_eq!(decided.reason.as_deref(), Some("not entitled"));
    assert!(decided.binding_hash.is_none());
}

// A second decision on either outcome is 409 already_decided — approve and deny
// are not idempotent-by-replay, and re-approving would mint a second binding for
// one request.
#[tokio::test]
async fn a_second_decision_is_409_already_decided() {
    let (cs, li, registry, rid, owner) = manual_registry().await;
    let h = reg_handler(&cs, &li, &registry);

    for (first, second, name, nonce) in [
        ("approve-request", "approve-request", "one.com", b"q3a"),
        ("approve-request", "deny-request", "two.com", b"q3b"),
        ("deny-request", "deny-request", "three.com", b"q3c"),
        ("deny-request", "approve-request", "four.com", b"q3d"),
    ] {
        let ph = queue_one(&cs, &li, &registry, &owner, name, nonce).await;
        assert_eq!(
            h.handle(&decision_ctx(first, ph, None))
                .await
                .unwrap()
                .status,
            200,
            "first decision {first}"
        );
        // The decision moved the head, so replaying the ORIGINAL handle names a
        // superseded body and would measure supersession instead. Re-read the
        // current head and decide that.
        let head = li
            .get(&crate::pending_by_request_path(
                &rid,
                owner.peer_id().as_str(),
                name,
            ))
            .expect("head survives a decision");
        let again = h.handle(&decision_ctx(second, head, None)).await.unwrap();
        assert_eq!(again.status, 409, "{first} then {second}");
        assert_eq!(
            result_field(&decode_result(&again), "code").and_then(|v| v.as_text()),
            Some("already_decided")
        );
    }
}

// A superseded head is NOT decidable — the hole that a first draft of this
// handler had. Supersession moves only the pointer, so the old `pending_review`
// body stays fetchable forever; deciding it would issue a binding on terms the
// operator's queue no longer shows.
#[tokio::test]
async fn a_superseded_head_is_not_decidable() {
    let (cs, li, registry, _rid, owner) = manual_registry().await;
    let first = queue_one_ttl(
        &cs,
        &li,
        &registry,
        &owner,
        "billslab.com",
        b"s1",
        3_600_000,
    )
    .await;
    let _second = queue_one_ttl(
        &cs,
        &li,
        &registry,
        &owner,
        "billslab.com",
        b"s2",
        86_400_000,
    )
    .await;

    // Fixture teeth: the superseded body is still there, so the refusal below
    // is about decidability and not about a missing entity.
    assert!(
        cs.get(&first).is_some(),
        "supersession must move only the pointer"
    );

    let res = reg_handler(&cs, &li, &registry)
        .handle(&decision_ctx("approve-request", first, None))
        .await
        .unwrap();
    assert_eq!(res.status, 404, "approving a superseded head");
    // Nothing was issued.
    assert!(li
        .get(&crate::by_name_pointer_path(
            registry.peer_id().as_str(),
            "billslab.com"
        ))
        .is_none());
}

// A superseding request leaves exactly ONE head for the (target, name) pair.
// Retries carry a fresh nonce by construction, so without replace-whole an
// operator's queue fills with duplicates of a single intent.
#[tokio::test]
async fn a_superseding_request_leaves_exactly_one_head() {
    let (cs, li, registry, rid, owner) = manual_registry().await;
    let first = queue_one_ttl(
        &cs,
        &li,
        &registry,
        &owner,
        "billslab.com",
        b"n1",
        3_600_000,
    )
    .await;
    let second = queue_one_ttl(
        &cs,
        &li,
        &registry,
        &owner,
        "billslab.com",
        b"n2",
        86_400_000,
    )
    .await;
    assert_ne!(first, second, "a re-submitted request is a distinct body");

    let pointer = crate::pending_by_request_path(&rid, owner.peer_id().as_str(), "billslab.com");
    assert_eq!(li.get(&pointer), Some(second), "the pointer repoints");

    // Exactly one head for the pair — enumerated the way an operator would,
    // which is also why §6a.9.3 defines no `list-pending` operation.
    let heads = li.list(&crate::pending_by_request_prefix(&rid));
    assert_eq!(heads.len(), 1, "one head per (target_peer_id, name)");
}

// §6a.9.3 retention `[SHOULD]` — a DECIDED head's pointer is collected once the
// window elapses; a `pending_review` head is NEVER collected, because expiring
// live queue state silently drops a request no operator has seen.
#[tokio::test]
async fn retention_collects_decided_heads_and_never_live_ones() {
    let (cs, li, registry, rid, owner) = manual_registry().await;

    // Decided, and eligible: a 1 ms window is elapsed by the time the next
    // queue-path sweep runs.
    let decided = queue_one(&cs, &li, &registry, &owner, "decided.com", b"r1").await;
    reg_handler(&cs, &li, &registry)
        .handle(&decision_ctx("deny-request", decided, None))
        .await
        .unwrap();
    // Still live at this point — nothing has swept yet.
    let denied_pointer =
        crate::pending_by_request_path(&rid, owner.peer_id().as_str(), "decided.com");
    assert!(li.get(&denied_pointer).is_some());

    // A later queue triggers the opportunistic sweep.
    let live = queue_one_ttl(
        &cs,
        &li,
        &registry,
        &Keypair::generate(),
        "live.com",
        b"r2",
        60_000,
    )
    .await;
    // The window is compared as `now - queued_at < window`, so the elapsed time
    // must actually exceed it or the sweep is a no-op and this test would pass
    // for the wrong reason.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let handler = reg_handler(&cs, &li, &registry).with_pending_retention(1);
    let sweeper = Keypair::generate();
    handler
        .handle(&register_ctx(
            mk_request("sweep.com", sweeper.peer_id().as_str(), b"r3"),
            &sweeper,
        ))
        .await
        .unwrap();

    // The decided head's POINTER is gone…
    assert!(
        li.get(&denied_pointer).is_none(),
        "a decided head past its window should be collected"
    );
    // …but its BODY stays content-addressed and auditable.
    assert!(
        cs.get(&decided).is_some(),
        "retention removes the pointer, never the body"
    );
    // And the live queue is untouched, however old it gets.
    assert!(cs.get(&live).is_some());
    let live_heads: Vec<_> = li
        .list(&crate::pending_by_request_prefix(&rid))
        .into_iter()
        .filter_map(|e| cs.get(&e.hash))
        .filter_map(|ent| PendingBindingData::from_entity(&ent).ok())
        .filter(|p| p.status == "pending_review")
        .collect();
    assert_eq!(
        live_heads.len(),
        2,
        "pending_review heads are never GC-eligible"
    );
}

// 404 when pending_hash names no stored pending-binding.
#[tokio::test]
async fn a_decision_on_an_unknown_handle_is_404() {
    let (cs, li, registry, _rid, _owner) = manual_registry().await;
    let bogus = Entity::new(
        entity_types::TYPE_PROTOCOL_STATUS,
        to_ecf(&Value::Map(vec![])),
    )
    .unwrap()
    .content_hash;
    let res = reg_handler(&cs, &li, &registry)
        .handle(&decision_ctx("approve-request", bogus, None))
        .await
        .unwrap();
    assert_eq!(res.status, 404);
    assert_eq!(
        result_field(&decode_result(&res), "code").and_then(|v| v.as_text()),
        Some("not_found")
    );
}

// §6a.9.3 `[MUST]` — the queue is not a reservation. If the name went to another
// peer between queue and approval, approving anyway would silently overwrite a
// live binding.
#[tokio::test]
async fn approving_a_name_taken_since_queueing_is_409_name_taken() {
    let (cs, li, registry, rid, owner) = manual_registry().await;
    let ph = queue_one(&cs, &li, &registry, &owner, "billslab.com", b"q5").await;

    // Someone else takes the name in the meantime. Only the body + by-name
    // pointer are seeded: the collision check reads the bound target, and
    // signature verification is a different vector's subject.
    let other = Keypair::generate();
    let taken = BindingData {
        name: "billslab.com".into(),
        kind: KIND_PEER_ISSUED.into(),
        target_peer_id: other.peer_id().as_str().to_string(),
        transports: vec![],
        issued_at: crate::log::now_ms(),
        ttl: None,
        supersedes: None,
        issuer_attestation: None,
        metadata: None,
    }
    .to_entity()
    .unwrap();
    let taken_hash = taken.content_hash;
    cs.put(taken).unwrap();
    li.set(&by_name_pointer_path(&rid, "billslab.com"), taken_hash);

    let res = reg_handler(&cs, &li, &registry)
        .handle(&decision_ctx("approve-request", ph, None))
        .await
        .unwrap();
    assert_eq!(res.status, 409);
    assert_eq!(
        result_field(&decode_result(&res), "code").and_then(|v| v.as_text()),
        Some("name_taken")
    );
    // The head is untouched — a refused decision is not a decision.
    let head = li
        .get(&crate::pending_by_request_path(
            &rid,
            owner.peer_id().as_str(),
            "billslab.com",
        ))
        .unwrap();
    assert_eq!(head, ph);
}

// `open` mode: a free name is first-come-first-serve; a second target claiming
// the same name is rejected name_taken.
#[tokio::test]
async fn register_open_name_taken() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    install_policy(
        &cs,
        &li,
        registry.peer_id().as_str(),
        &IssuerPolicyData {
            mode: MODE_OPEN.into(),
            ..Default::default()
        },
    );
    let handler = reg_handler(&cs, &li, &registry);
    let first = Keypair::generate();
    let second = Keypair::generate();

    let ok = handler
        .handle(&register_ctx(
            mk_request("dup.com", first.peer_id().as_str(), b"a"),
            &first,
        ))
        .await
        .unwrap();
    assert_eq!(ok.status, 200);

    let taken = handler
        .handle(&register_ctx(
            mk_request("dup.com", second.peer_id().as_str(), b"b"),
            &second,
        ))
        .await
        .unwrap();
    assert_eq!(taken.status, 409);
    assert_eq!(
        result_field(&decode_result(&taken), "code").and_then(|v| v.as_text()),
        Some("name_taken")
    );
}

// :revoke-request emits a registry-signed revocation that the peer-issued
// backend honors (the resolved binding is then excluded → chain dead-ends).
#[tokio::test]
async fn register_then_revoke_excludes() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    let rid = registry.peer_id().as_str().to_string();
    install_policy(
        &cs,
        &li,
        &rid,
        &IssuerPolicyData {
            mode: MODE_OPEN.into(),
            ..Default::default()
        },
    );
    let handler = reg_handler(&cs, &li, &registry);
    let owner = Keypair::generate();

    let issued = handler
        .handle(&register_ctx(
            mk_request("billslab.com", owner.peer_id().as_str(), b"r1"),
            &owner,
        ))
        .await
        .unwrap();
    let bh = binding_hash_of(&issued);
    assert!(
        peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "billslab.com")
            .map(|r| r.is_resolved())
            .unwrap_or(false)
    );

    // Revoke it, signed by the binding's target → resolve dead-ends (fail-closed).
    let revoked = handler
        .handle(&signed_op_ctx(
            "revoke-request",
            TYPE_REVOKE_REQUEST,
            vec![(text("binding_hash"), Value::Bytes(bh.to_bytes().to_vec()))],
            &owner,
        ))
        .await
        .unwrap();
    assert_eq!(revoked.status, 200);
    assert!(peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "billslab.com").is_none());
}

// :renew-request issues a successor binding (supersedes-chain) the by-name
// pointer now points at, with the new TTL.
#[tokio::test]
async fn register_then_renew_supersedes() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    let rid = registry.peer_id().as_str().to_string();
    install_policy(
        &cs,
        &li,
        &rid,
        &IssuerPolicyData {
            mode: MODE_OPEN.into(),
            ..Default::default()
        },
    );
    let handler = reg_handler(&cs, &li, &registry);
    let owner = Keypair::generate();

    let issued = handler
        .handle(&register_ctx(
            mk_request("billslab.com", owner.peer_id().as_str(), b"n"),
            &owner,
        ))
        .await
        .unwrap();
    let old = binding_hash_of(&issued);

    let renewed = handler
        .handle(&signed_op_ctx(
            "renew-request",
            TYPE_RENEW_REQUEST,
            renew_fields(old, b"rn1"),
            &owner,
        ))
        .await
        .unwrap();
    assert_eq!(renewed.status, 200);
    let new = binding_hash_of(&renewed);
    assert_ne!(old, new, "renew issues a fresh successor binding");

    // The by-name pointer + resolve now follow the successor.
    let resolved =
        peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "billslab.com").unwrap();
    assert_eq!(resolved.binding, Some(new));
    let body = cs.get(&new).unwrap();
    let binding = BindingData::from_entity(&body).unwrap();
    assert_eq!(binding.supersedes, Some(old));
    assert_eq!(binding.ttl, Some(172_800_000));
}

// ---------------------------------------------------------------------------
// REG-REVOKE-PROOF-1 / REG-RENEW-PROOF-1 — layer 1 binds all three write ops
// (§6a.9 `[RULED 2026-08-11]`).
//
// rust shipped `revoke` and `renew` with NO requester verification: any peer
// that could reach the registry could permanently revoke any binding in it,
// and revocation is monotonic, so there is no undo. §6a.9 named a proof vector
// for `register` and none for these two, and all three impls implemented
// against the vector list rather than the prose.
//
// Both vectors require BOTH halves (GUIDE-CONFORMANCE §2.4a): refused AND
// nothing published. The acceptance half is `register_then_revoke_excludes` /
// `register_then_renew_supersedes` above — which used to send an UNSIGNED
// request and pass, which is precisely what "a check that asserts only
// acceptance certifies the hole" means.
// ---------------------------------------------------------------------------

/// Issue a binding to `owner` under an `open` policy, returning its hash.
async fn issued_binding(
    cs: &Arc<dyn ContentStore>,
    li: &Arc<dyn LocationIndex>,
    registry: &IdentityKeypair,
    owner: &Keypair,
) -> Hash {
    install_policy(
        cs,
        li,
        registry.peer_id().as_str(),
        &IssuerPolicyData {
            mode: MODE_OPEN.into(),
            ..Default::default()
        },
    );
    let issued = reg_handler(cs, li, registry)
        .handle(&register_ctx(
            mk_request("billslab.com", owner.peer_id().as_str(), b"sec"),
            owner,
        ))
        .await
        .unwrap();
    assert_eq!(issued.status, 200);
    binding_hash_of(&issued)
}

// REG-REVOKE-PROOF-1, negative half — an unsigned revoke is refused and emits
// no revocation. This is the denial-of-name: `stranger` never held the name.
#[tokio::test]
async fn revoke_proof_unsigned_rejected_and_publishes_nothing() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    let rid = registry.peer_id().as_str().to_string();
    let owner = Keypair::generate();
    let bh = issued_binding(&cs, &li, &registry, &owner).await;

    let refused = reg_handler(&cs, &li, &registry)
        .handle(&ctx(
            "revoke-request",
            vec![(text("binding_hash"), Value::Bytes(bh.to_bytes().to_vec()))],
        ))
        .await
        .unwrap();

    assert_eq!(refused.status, 401, "layer-1 is an authentication failure");
    assert_eq!(
        result_field(&decode_result(&refused), "code").and_then(|v| v.as_text()),
        Some("signature_invalid")
    );
    // The negative half: no revocation was published, by either index.
    assert!(
        li.get(&crate::revocation_by_target_path(&rid, &bh))
            .is_none(),
        "a refused revoke published a revocation"
    );
    // And the name still resolves — the actual harm this prevents.
    assert!(
        peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "billslab.com")
            .map(|r| r.is_resolved())
            .unwrap_or(false),
        "a refused revoke still killed the name"
    );
}

// REG-REVOKE-PROOF-1, wrong-signer half — a *validly signed* request from a
// peer who is not the binding's target is still refused. Without this, an
// impl that checked "is there a signature" instead of "is it the target's"
// would pass the unsigned case above.
#[tokio::test]
async fn revoke_proof_wrong_signer_rejected_and_publishes_nothing() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    let rid = registry.peer_id().as_str().to_string();
    let owner = Keypair::generate();
    let stranger = Keypair::generate();
    let bh = issued_binding(&cs, &li, &registry, &owner).await;

    let refused = reg_handler(&cs, &li, &registry)
        .handle(&signed_op_ctx(
            "revoke-request",
            TYPE_REVOKE_REQUEST,
            vec![(text("binding_hash"), Value::Bytes(bh.to_bytes().to_vec()))],
            &stranger,
        ))
        .await
        .unwrap();

    assert_eq!(refused.status, 401);
    assert!(
        li.get(&crate::revocation_by_target_path(&rid, &bh))
            .is_none(),
        "a stranger's signature revoked someone else's binding"
    );
    assert!(
        peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "billslab.com")
            .map(|r| r.is_resolved())
            .unwrap_or(false)
    );
}

// REG-RENEW-PROOF-1, negative half — an unsigned renew is refused and issues
// no successor binding. Replay defense is not authorization: the nonce check
// stopped a *captured* renew being re-run while leaving a *fresh unsigned* one
// from any peer accepted.
#[tokio::test]
async fn renew_proof_unsigned_rejected_and_publishes_nothing() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    let rid = registry.peer_id().as_str().to_string();
    let owner = Keypair::generate();
    let bh = issued_binding(&cs, &li, &registry, &owner).await;

    let refused = reg_handler(&cs, &li, &registry)
        .handle(&ctx("renew-request", renew_fields(bh, b"rn-unsigned")))
        .await
        .unwrap();

    assert_eq!(refused.status, 401);
    assert_eq!(
        result_field(&decode_result(&refused), "code").and_then(|v| v.as_text()),
        Some("signature_invalid")
    );
    // No successor was published — the by-name pointer still names the original.
    let resolved =
        peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "billslab.com").unwrap();
    assert_eq!(
        resolved.binding,
        Some(bh),
        "a refused renew published a successor binding"
    );
    // ...and it did not burn the real target's nonce space either.
    assert!(li
        .get(&crate::register_nonce_path(
            &rid,
            owner.peer_id().as_str(),
            b"rn-unsigned"
        ))
        .is_none());
}

// REG-RENEW-PROOF-1, wrong-signer half.
#[tokio::test]
async fn renew_proof_wrong_signer_rejected_and_publishes_nothing() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    let rid = registry.peer_id().as_str().to_string();
    let owner = Keypair::generate();
    let stranger = Keypair::generate();
    let bh = issued_binding(&cs, &li, &registry, &owner).await;

    let refused = reg_handler(&cs, &li, &registry)
        .handle(&signed_op_ctx(
            "renew-request",
            TYPE_RENEW_REQUEST,
            renew_fields(bh, b"rn-stranger"),
            &stranger,
        ))
        .await
        .unwrap();

    assert_eq!(refused.status, 401);
    let resolved =
        peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "billslab.com").unwrap();
    assert_eq!(resolved.binding, Some(bh));
}

// Renew IS replay-defended (§6a.9's discriminator) — a second renew reusing a
// seen nonce is refused even when the signature is valid.
#[tokio::test]
async fn renew_replay_same_nonce_rejected() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    let owner = Keypair::generate();
    let bh = issued_binding(&cs, &li, &registry, &owner).await;
    let handler = reg_handler(&cs, &li, &registry);

    let first = handler
        .handle(&signed_op_ctx(
            "renew-request",
            TYPE_RENEW_REQUEST,
            renew_fields(bh, b"rn-dup"),
            &owner,
        ))
        .await
        .unwrap();
    assert_eq!(first.status, 200);

    let replayed = handler
        .handle(&signed_op_ctx(
            "renew-request",
            TYPE_RENEW_REQUEST,
            renew_fields(bh, b"rn-dup"),
            &owner,
        ))
        .await
        .unwrap();
    assert_eq!(replayed.status, 409);
    assert_eq!(
        result_field(&decode_result(&replayed), "code").and_then(|v| v.as_text()),
        Some("replay")
    );
}

// ---------------------------------------------------------------------------
// §6a.9.2 policy management — set-issuer-policy / get-issuer-policy
// `[RATIFIED 2026-08-10]`
// ---------------------------------------------------------------------------

/// A ctx whose params IS the given entity (the §6a.9.2 ops take a
/// `system/registry/issuer-policy` entity, or nothing at all).
fn policy_ctx(op: &str, params: Entity) -> HandlerContext {
    let execute = Entity::new(entity_types::TYPE_EXECUTE, to_ecf(&Value::Map(vec![]))).unwrap();
    HandlerContext::builder(execute, params)
        .operation(op.to_string())
        .build()
}

/// The cohort convention for an input-less op: an empty `primitive/map`. A
/// zero-value params entity is refused `400 invalid_params` by the envelope
/// layer before it ever reaches a handler, so `get-issuer-policy` must be
/// callable this way and not merely "with no params".
fn no_params_ctx(op: &str) -> HandlerContext {
    policy_ctx(
        op,
        Entity::new("primitive/map", to_ecf(&Value::Map(vec![]))).unwrap(),
    )
}

fn err_code(r: &entity_handler::HandlerResult) -> Option<String> {
    result_field(&decode_result(r), "code")
        .and_then(|v| v.as_text())
        .map(|s| s.to_string())
}

/// §6a.9.2 — set stores the policy and get returns it **as written**.
#[tokio::test]
async fn set_issuer_policy_round_trips_through_get() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    let handler = reg_handler(&cs, &li, &registry);

    let want = IssuerPolicyData {
        mode: MODE_ALLOWLIST.into(),
        allowlist: Some(vec!["peer-a".into()]),
        default_ttl: Some(3_600_000),
        // §6a.9.1 v1.11 — REQUIRED on any policy that can reach *approve*.
        max_ttl: Some(86_400_000),
        ..Default::default()
    };

    // Authored by hand rather than via `want.to_entity()`, and carrying a
    // field this decoder does not know. That is what makes the byte-fidelity
    // assertion below discriminating: an entity our own encoder WOULD
    // reproduce cannot tell "stored verbatim" apart from "decoded and
    // re-encoded" — both produce identical bytes, so the check passes either
    // way and proves nothing. A peer written against another impl is the real
    // source of such an entity; unknown fields are MUST-ignore (ADR-0002),
    // not license to drop them on the floor by round-tripping through a
    // struct that has no room for them.
    let submitted = Entity::new(
        entity_types::TYPE_REGISTRY_ISSUER_POLICY,
        to_ecf(&Value::Map(vec![
            (text("allowlist"), Value::Array(vec![text("peer-a")])),
            (text("default_ttl"), entity_ecf::integer(3_600_000)),
            (text("max_ttl"), entity_ecf::integer(86_400_000)),
            (text("mode"), text(MODE_ALLOWLIST)),
            (text("zz_unknown_field"), text("must survive")),
        ])),
    )
    .unwrap();
    assert_ne!(
        submitted.content_hash,
        want.to_entity().unwrap().content_hash,
        "the submitted entity must be one our own encoder would NOT reproduce, \
         or this test cannot observe a re-encode"
    );

    let set = handler
        .handle(&policy_ctx("set-issuer-policy", submitted.clone()))
        .await
        .unwrap();
    assert_eq!(set.status, 200, "set-issuer-policy is a ratified operation");
    assert_eq!(
        set.result.content_hash, submitted.content_hash,
        "§6a.9.2 — the output is `the stored policy, as written`"
    );

    let got = handler
        .handle(&no_params_ctx("get-issuer-policy"))
        .await
        .unwrap();
    assert_eq!(got.status, 200);
    assert_eq!(
        got.result.content_hash, submitted.content_hash,
        "get returned different bytes than set was handed — the policy was \
         decoded and re-encoded somewhere, which drops unknown fields and \
         changes the entity's identity"
    );
    assert_eq!(IssuerPolicyData::from_entity(&got.result).unwrap(), want);
}

/// §6a.9.2 `[MUST]` — set replaces the policy **whole**. An absent optional
/// field means *unset*, not *unchanged*: merge semantics would make the
/// result depend on write order, which two peers cannot reconstruct.
#[tokio::test]
async fn set_issuer_policy_replaces_whole() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    let handler = reg_handler(&cs, &li, &registry);

    // Arm with a policy carrying BOTH optional fields...
    let full = IssuerPolicyData {
        mode: MODE_ALLOWLIST.into(),
        allowlist: Some(vec!["peer-a".into()]),
        name_constraints: Some("*.lab".into()),
        default_ttl: Some(3_600_000),
        max_ttl: Some(86_400_000),
    };
    handler
        .handle(&policy_ctx("set-issuer-policy", full.to_entity().unwrap()))
        .await
        .unwrap();

    // ...then write a bare `open` dropping the other optionals. `default_ttl`
    // is no longer optional for a live policy (CAP registry D11), so it rides
    // along with a DIFFERENT value — the replace property is now shown by that
    // value changing rather than by clearing, since a merge would keep the
    // first one.
    let bare = IssuerPolicyData {
        mode: MODE_OPEN.into(),
        default_ttl: Some(7_200_000),
        max_ttl: Some(86_400_000),
        ..Default::default()
    };
    let set = handler
        .handle(&policy_ctx("set-issuer-policy", bare.to_entity().unwrap()))
        .await
        .unwrap();
    assert_eq!(set.status, 200);

    let got = handler
        .handle(&no_params_ctx("get-issuer-policy"))
        .await
        .unwrap();
    let stored = IssuerPolicyData::from_entity(&got.result).unwrap();
    assert_eq!(stored.mode, MODE_OPEN);
    assert_eq!(
        stored.allowlist, None,
        "allowlist survived a whole-replace — that is merge semantics"
    );
    assert_eq!(
        stored.name_constraints, None,
        "name_constraints survived a whole-replace — that is merge semantics"
    );
    assert_eq!(
        stored.default_ttl,
        Some(7_200_000),
        "default_ttl not replaced whole — a merge would have kept 3_600_000"
    );
}

/// D11 (CAP registry, arch 2026-08-18) — a live-registration policy with a null
/// `default_ttl` MUST be refused `400` and MUST NOT be stored.
///
/// Such a policy can only mint null-ttl bindings, which D3 now makes
/// unresolvable — so it is a registry armed to produce nothing a conformant
/// resolver will accept. The refusal belongs HERE and not at register-time: a
/// 400 at register bills the requester for an operator misconfiguration, and
/// the operator's field lives on this entity. Same move §6a.9.2 already makes
/// for `domain-control`.
///
/// The second assertion is the load-bearing one — a 400 that stored the policy
/// anyway passes a status-only check.
#[tokio::test]
async fn set_issuer_policy_null_default_ttl_rejected_and_not_stored() {
    for mode in [MODE_OPEN, MODE_ALLOWLIST, MODE_MANUAL] {
        let (cs, li) = stores();
        let registry = IdentityKeypair::Ed25519(Keypair::generate());
        let handler = reg_handler(&cs, &li, &registry);

        let policy = IssuerPolicyData {
            mode: mode.into(),
            allowlist: Some(vec!["peer-a".into()]),
            default_ttl: None,
            ..Default::default()
        };
        let set = handler
            .handle(&policy_ctx(
                "set-issuer-policy",
                policy.to_entity().unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(
            set.status, 400,
            "mode {mode:?}: a null default_ttl can only mint bindings D3 refuses"
        );

        // Nothing stored — `get` must still report unset.
        let got = handler
            .handle(&no_params_ctx("get-issuer-policy"))
            .await
            .unwrap();
        assert_eq!(
            got.status, 404,
            "mode {mode:?}: the rejected policy was stored anyway"
        );
    }
}

/// D12 — the backstop: a null-`default_ttl` policy seeded OUT OF BAND (CLI flag,
/// direct tree write, or predating D11) must not mint, and must not queue.
///
/// D11 guards the door; §6a.9.2's store-first rule means the door is not the
/// only way in. Refusing rather than substituting an implementation-chosen
/// default is the point — a synthesized default is the §6a.9.2
/// default-synthesis mistake on a security-relevant field, and would let two
/// registries answer identically-stored policies with different binding
/// lifetimes.
#[tokio::test]
async fn out_of_band_null_default_ttl_policy_refuses_at_register() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    let handler = reg_handler(&cs, &li, &registry);

    // Seed directly, bypassing D11 — this is the state D12 exists for.
    let policy = IssuerPolicyData {
        mode: MODE_OPEN.into(),
        default_ttl: None,
        ..Default::default()
    };
    let entity = policy.to_entity().unwrap();
    let hash = entity.content_hash;
    cs.put(entity).unwrap();
    li.set(
        &crate::issuer_policy_path(registry.peer_id().as_str()),
        hash,
    );

    // The request must OMIT requested_ttl — that is the only way the resolved
    // ttl reaches null. A request supplying its own ttl is unaffected by D12
    // and is asserted below as the control.
    let owner = Keypair::generate();
    let no_ttl = RegisterRequestData {
        name: "billslab.com".into(),
        target_peer_id: owner.peer_id().as_str().into(),
        transports: vec![Value::Text("tcp://billslab.com:9000".into())],
        requested_ttl: None,
        nonce: b"n1".to_vec(),
        issued_at: crate::log::now_ms(),
    }
    .to_entity()
    .unwrap();
    let out = handler.handle(&register_ctx(no_ttl, &owner)).await.unwrap();
    assert_eq!(
        out.status, 403,
        "a request resolving to a null ttl must be refused, not minted"
    );

    // And nothing was bound or queued.
    assert!(
        li.get(&by_name_pointer_path(
            registry.peer_id().as_str(),
            "billslab.com"
        ))
        .is_none(),
        "a null-ttl binding was minted anyway"
    );

    // Control: the same seeded policy still issues for a request that supplies
    // its own ttl. D12 refuses the null resolution, not the policy's existence —
    // a guard that rejected every register would pass the assertions above
    // while proving nothing.
    let out2 = handler
        .handle(&register_ctx(
            mk_request("other.example", owner.peer_id().as_str(), b"n2"),
            &owner,
        ))
        .await
        .unwrap();
    assert_eq!(
        out2.status, 200,
        "a request carrying requested_ttl must still issue under the same policy"
    );
}

/// §6a.9.2 — `domain-control` MUST be refused `400 unsupported_mode` and
/// **not stored**, rather than arming a mode the issuer cannot enforce.
///
/// The second assertion is the load-bearing one: a 400 that stored the
/// policy anyway passes a status-only check.
#[tokio::test]
async fn set_issuer_policy_refuses_domain_control_and_does_not_store_it() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    let handler = reg_handler(&cs, &li, &registry);

    let dc = IssuerPolicyData {
        mode: MODE_DOMAIN_CONTROL.into(),
        ..Default::default()
    };
    let set = handler
        .handle(&policy_ctx("set-issuer-policy", dc.to_entity().unwrap()))
        .await
        .unwrap();
    assert_eq!(set.status, 400);
    assert_eq!(err_code(&set).as_deref(), Some("unsupported_mode"));

    let got = handler
        .handle(&no_params_ctx("get-issuer-policy"))
        .await
        .unwrap();
    assert_eq!(
        got.status, 404,
        "domain-control was refused but stored anyway — the registry is now \
         armed into a mode it cannot enforce"
    );
}

/// §6a.9.2 — the 400 on `set` does not replace the register path's 501 on a
/// **stored** `domain-control` policy. The two bind different acts: the 400
/// refuses to arm the mode, and a policy predating that refusal still has to
/// be answered when a request arrives against it.
#[tokio::test]
async fn stored_domain_control_policy_still_answers_501_on_register() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    let handler = reg_handler(&cs, &li, &registry);
    // Written directly, as an operator's pre-ratification policy would be —
    // `set-issuer-policy` would refuse to author it.
    install_policy(
        &cs,
        &li,
        registry.peer_id().as_str(),
        &IssuerPolicyData {
            mode: MODE_DOMAIN_CONTROL.into(),
            ..Default::default()
        },
    );

    let owner = Keypair::generate();
    let out = handler
        .handle(&register_ctx(
            mk_request("billslab.com", owner.peer_id().as_str(), b"n1"),
            &owner,
        ))
        .await
        .unwrap();
    assert_eq!(out.status, 501);
    assert_eq!(err_code(&out).as_deref(), Some("unsupported_mode"));
}

/// §6a.9.2 — **unset is not a mode.** With no policy stored, `get` answers
/// 404 and MUST NOT synthesize a default `open`, which would silently turn a
/// curated registry into a first-come-first-serve one.
#[tokio::test]
async fn get_issuer_policy_unset_is_404() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    let handler = reg_handler(&cs, &li, &registry);

    let got = handler
        .handle(&no_params_ctx("get-issuer-policy"))
        .await
        .unwrap();
    assert_eq!(got.status, 404);
    assert_eq!(err_code(&got).as_deref(), Some("not_found"));
}

/// §6a.9.2 — the same "unset is not a mode" rule on the **register** path: an
/// unarmed registry is a conformant curated-only registry (§6a.8) and does
/// not run live registration at all.
///
/// This is the negative half that a `get`-only check walks past. The request
/// below is fully valid — correct layer-1 signature, fresh nonce, free name —
/// so the ONLY thing that can reject it is the absent policy. Under the
/// previous default it was admitted and a binding was issued.
#[tokio::test]
async fn register_against_an_unarmed_registry_is_curated_only_404() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    let handler = reg_handler(&cs, &li, &registry);

    let owner = Keypair::generate();
    let out = handler
        .handle(&register_ctx(
            mk_request("billslab.com", owner.peer_id().as_str(), b"n1"),
            &owner,
        ))
        .await
        .unwrap();
    assert_eq!(
        out.status, 404,
        "an unarmed registry issued a binding — unset was treated as a mode"
    );
    assert_eq!(err_code(&out).as_deref(), Some("not_found"));

    // And nothing was published: no by-name pointer for the name.
    assert!(
        li.get(&crate::by_name_pointer_path(
            registry.peer_id().as_str(),
            "billslab.com"
        ))
        .is_none(),
        "a curated-only refusal still wrote a binding pointer"
    );
}

/// §6a.9.2 — `set-issuer-policy` is the wire arming path, so the arm →
/// register sequence must work end-to-end against a peer that started with no
/// policy at all. This is what makes the `registry_issuer` conformance
/// category reachable for an impl with no CLI arming flag.
#[tokio::test]
async fn set_issuer_policy_arms_a_registry_that_then_issues() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    let handler = reg_handler(&cs, &li, &registry);

    let armed = handler
        .handle(&policy_ctx(
            "set-issuer-policy",
            IssuerPolicyData {
                mode: MODE_OPEN.into(),
                // D11: a live-registration policy MUST define default_ttl.
                default_ttl: Some(3_600_000),
                // v1.11: …and max_ttl, bounding the requester's own number.
                max_ttl: Some(86_400_000),
                ..Default::default()
            }
            .to_entity()
            .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(armed.status, 200);

    let owner = Keypair::generate();
    let out = handler
        .handle(&register_ctx(
            mk_request("billslab.com", owner.peer_id().as_str(), b"n1"),
            &owner,
        ))
        .await
        .unwrap();
    assert_eq!(out.status, 200, "wire-armed registry must issue");
    let bound = binding_hash_of(&out);
    let binding = BindingData::from_entity(&cs.get(&bound).unwrap()).unwrap();
    assert_eq!(binding.target_peer_id, owner.peer_id().as_str());
}

/// §6a.9.2 — a mode the issuer cannot enforce is refused at the door whatever
/// its spelling, not just the named `domain-control`.
#[tokio::test]
async fn set_issuer_policy_refuses_an_unknown_mode() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    let handler = reg_handler(&cs, &li, &registry);

    let bogus = IssuerPolicyData {
        mode: "first-come-first-served".into(),
        ..Default::default()
    };
    let set = handler
        .handle(&policy_ctx("set-issuer-policy", bogus.to_entity().unwrap()))
        .await
        .unwrap();
    assert_eq!(set.status, 400);
    assert_eq!(err_code(&set).as_deref(), Some("unsupported_mode"));

    // Not stored — the registry stays unarmed rather than armed into a mode
    // the register path would have to reject on every request.
    let got = handler
        .handle(&no_params_ctx("get-issuer-policy"))
        .await
        .unwrap();
    assert_eq!(got.status, 404);
}

/// §6a.9.2 — the ops are typed. A `set` carrying something that is not a
/// `system/registry/issuer-policy` entity is refused rather than stored,
/// which would leave `get` returning a policy that cannot be decoded.
#[tokio::test]
async fn set_issuer_policy_rejects_a_foreign_entity_type() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    let handler = reg_handler(&cs, &li, &registry);

    let wrong = Entity::new(
        entity_types::TYPE_PROTOCOL_STATUS,
        to_ecf(&Value::Map(vec![(text("mode"), text(MODE_OPEN))])),
    )
    .unwrap();
    let set = handler
        .handle(&policy_ctx("set-issuer-policy", wrong))
        .await
        .unwrap();
    assert_eq!(set.status, 400);
    assert_eq!(err_code(&set).as_deref(), Some("invalid_params"));

    let got = handler
        .handle(&no_params_ctx("get-issuer-policy"))
        .await
        .unwrap();
    assert_eq!(
        got.status, 404,
        "a refused set must not have armed anything"
    );
}

// ---------------------------------------------------------------------------
// §6a.9.1 the TTL ceiling and the renew cascade `[MUST, v1.9/v1.10/v1.11]`
// ---------------------------------------------------------------------------

/// Read the `ttl` off an issued binding body.
fn binding_ttl(cs: &Arc<dyn ContentStore>, h: Hash) -> Option<u64> {
    BindingData::from_entity(&cs.get(&h).expect("binding stored"))
        .unwrap()
        .ttl
}

/// `REG-TTL-CEILING-1` — `set-issuer-policy` refuses a live policy with no
/// `max_ttl`, and one whose `default_ttl` exceeds it. **With the control**,
/// because a rejection row without its acceptance control passes trivially
/// against a peer that rejects everything.
#[tokio::test]
async fn reg_ttl_ceiling_1() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    let handler = reg_handler(&cs, &li, &registry);

    // Absent max_ttl on a live mode → 400.
    let no_ceiling = IssuerPolicyData {
        mode: MODE_OPEN.into(),
        default_ttl: Some(3_600_000),
        ..Default::default()
    };
    let r = handler
        .handle(&policy_ctx(
            "set-issuer-policy",
            no_ceiling.to_entity().unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(
        r.status, 400,
        "a live policy with no max_ttl MUST be refused"
    );
    assert!(
        li.get(&issuer_policy_path(registry.peer_id().as_str()))
            .is_none(),
        "a refused policy MUST NOT be stored"
    );

    // default_ttl > max_ttl → 400. The policy is self-contradictory: the
    // registry's own fallback would be clamped by its own ceiling.
    let inverted = IssuerPolicyData {
        mode: MODE_OPEN.into(),
        default_ttl: Some(90_000_000),
        max_ttl: Some(86_400_000),
        ..Default::default()
    };
    let r = handler
        .handle(&policy_ctx(
            "set-issuer-policy",
            inverted.to_entity().unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(r.status, 400, "default_ttl above max_ttl MUST be refused");

    // Control — both present, default_ttl <= max_ttl, accepted.
    let ok = IssuerPolicyData {
        mode: MODE_OPEN.into(),
        default_ttl: Some(3_600_000),
        max_ttl: Some(86_400_000),
        ..Default::default()
    };
    let r = handler
        .handle(&policy_ctx("set-issuer-policy", ok.to_entity().unwrap()))
        .await
        .unwrap();
    assert_eq!(
        r.status, 200,
        "a policy with both, correctly ordered, is accepted"
    );
}

/// `REG-TTL-CLAMP-1` — `register-request` and `renew-request` each carrying a
/// `ttl` above `max_ttl` are both **accepted `200`**, and both issued bindings
/// carry **exactly `max_ttl`**.
///
/// The clamp is asserted on the *binding's* value, not on the response code,
/// **because a peer that refuses instead of clamping also returns a non-`200`
/// and would otherwise be indistinguishable.** Refusing is the wrong side by
/// §6a.9.2's own reasoning: it bills a well-formed request for a policy the
/// requester cannot read, and teaches requesters to probe for the ceiling.
#[tokio::test]
async fn reg_ttl_clamp_1() {
    const CEILING: u64 = 86_400_000; // 1 day
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    install_policy(
        &cs,
        &li,
        registry.peer_id().as_str(),
        &IssuerPolicyData {
            mode: MODE_OPEN.into(),
            default_ttl: Some(3_600_000),
            max_ttl: Some(CEILING),
            ..Default::default()
        },
    );
    let handler = reg_handler(&cs, &li, &registry);
    let owner = Keypair::generate();

    // register — requested_ttl is a year, well above the ceiling.
    let mut req = RegisterRequestData {
        name: "billslab.com".into(),
        target_peer_id: owner.peer_id().as_str().to_string(),
        transports: vec![Value::Text("tcp://billslab.com:9000".into())],
        requested_ttl: Some(31_536_000_000),
        nonce: b"clamp-reg".to_vec(),
        issued_at: crate::log::now_ms(),
    };
    let r = handler
        .handle(&register_ctx(req.to_entity().unwrap(), &owner))
        .await
        .unwrap();
    assert_eq!(r.status, 200, "above the ceiling is CLAMPED, not refused");
    let registered = binding_hash_of(&r);
    assert_eq!(
        binding_ttl(&cs, registered),
        Some(CEILING),
        "the issued binding carries exactly max_ttl"
    );

    // renew — same shape, on the binding just issued.
    let renew = signed_op_ctx(
        "renew-request",
        TYPE_RENEW_REQUEST,
        vec![
            (
                text("binding_hash"),
                Value::Bytes(registered.to_bytes().to_vec()),
            ),
            (text("ttl"), entity_ecf::integer(31_536_000_000)),
            (text("nonce"), Value::Bytes(b"clamp-renew".to_vec())),
            (
                text("issued_at"),
                entity_ecf::integer(crate::log::now_ms() as i64),
            ),
        ],
        &owner,
    );
    let r = handler.handle(&renew).await.unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(
        binding_ttl(&cs, binding_hash_of(&r)),
        Some(CEILING),
        "renew clamps to the same ceiling"
    );

    // The clamp does not touch a request already under the ceiling.
    req.name = "under.example".into();
    req.requested_ttl = Some(1_000);
    req.nonce = b"clamp-under".to_vec();
    let r = handler
        .handle(&register_ctx(req.to_entity().unwrap(), &owner))
        .await
        .unwrap();
    assert_eq!(binding_ttl(&cs, binding_hash_of(&r)), Some(1_000));
}

/// Arm a curated registry that has issued one binding, and return
/// `(handler, owner, binding_hash)`.
async fn curated_with_one_binding(
    cs: &Arc<dyn ContentStore>,
    li: &Arc<dyn LocationIndex>,
    registry: &IdentityKeypair,
    policy: &IssuerPolicyData,
    requested_ttl: Option<u64>,
) -> (RegisterRequestHandler, Keypair, Hash) {
    install_policy(
        cs,
        li,
        registry.peer_id().as_str(),
        &IssuerPolicyData {
            mode: MODE_OPEN.into(),
            default_ttl: Some(3_600_000),
            max_ttl: Some(86_400_000),
            ..Default::default()
        },
    );
    let handler = reg_handler(cs, li, registry);
    let owner = Keypair::generate();
    let req = RegisterRequestData {
        name: "billslab.com".into(),
        target_peer_id: owner.peer_id().as_str().to_string(),
        transports: vec![Value::Text("tcp://billslab.com:9000".into())],
        requested_ttl,
        nonce: b"seed".to_vec(),
        issued_at: crate::log::now_ms(),
    };
    let r = handler
        .handle(&register_ctx(req.to_entity().unwrap(), &owner))
        .await
        .unwrap();
    assert_eq!(r.status, 200, "seed binding issued");
    let h = binding_hash_of(&r);
    // Now swap in the policy the vector actually wants to test against.
    install_policy(cs, li, registry.peer_id().as_str(), policy);
    (handler, owner, h)
}

fn renew_ctx_with(binding: Hash, ttl: Option<u64>, nonce: &[u8], key: &Keypair) -> HandlerContext {
    let mut fields = vec![
        (
            text("binding_hash"),
            Value::Bytes(binding.to_bytes().to_vec()),
        ),
        (text("nonce"), Value::Bytes(nonce.to_vec())),
        (
            text("issued_at"),
            entity_ecf::integer(crate::log::now_ms() as i64),
        ),
    ];
    if let Some(t) = ttl {
        fields.push((text("ttl"), entity_ecf::integer(t as i64)));
    }
    signed_op_ctx("renew-request", TYPE_RENEW_REQUEST, fields, key)
}

/// `REG-RENEW-TTL-CASCADE-1` — three rows against a curated registry whose
/// stored policy has no `default_ttl`.
///
/// Row (b) is the one that fails against **both** a null-minting peer and a
/// refusing peer; row (c) is the one that fails against a peer that
/// implemented inherit-first. Together they pin that step 2 (the operator's
/// current intent) outranks step 3 (the registry's own prior signed act) —
/// *"an operator who lowers `default_ttl` sees renewals pick it up"*.
#[tokio::test]
async fn reg_renew_ttl_cascade_1() {
    const PREDECESSOR_TTL: u64 = 7_200_000;

    // (a) renew WITH an explicit ttl → accepted, successor carries it.
    {
        let (cs, li) = stores();
        let registry = IdentityKeypair::Ed25519(Keypair::generate());
        let (handler, owner, seed) = curated_with_one_binding(
            &cs,
            &li,
            &registry,
            &IssuerPolicyData {
                mode: MODE_OPEN.into(),
                max_ttl: Some(86_400_000),
                ..Default::default()
            },
            Some(PREDECESSOR_TTL),
        )
        .await;
        let r = handler
            .handle(&renew_ctx_with(seed, Some(1_800_000), b"a", &owner))
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(
            binding_ttl(&cs, binding_hash_of(&r)),
            Some(1_800_000),
            "step 1"
        );
    }

    // (b) renew OMITTING ttl against a policy with no default_ttl →
    //     accepted, successor carries THE SUPERSEDED BINDING's ttl.
    {
        let (cs, li) = stores();
        let registry = IdentityKeypair::Ed25519(Keypair::generate());
        let (handler, owner, seed) = curated_with_one_binding(
            &cs,
            &li,
            &registry,
            &IssuerPolicyData {
                mode: MODE_OPEN.into(),
                max_ttl: Some(86_400_000),
                ..Default::default()
            },
            Some(PREDECESSOR_TTL),
        )
        .await;
        let r = handler
            .handle(&renew_ctx_with(seed, None, b"b", &owner))
            .await
            .unwrap();
        assert_eq!(r.status, 200, "MUST NOT refuse for a missing ttl");
        assert_eq!(
            binding_ttl(&cs, binding_hash_of(&r)),
            Some(PREDECESSOR_TTL),
            "step 3 — recovered from the registry's own prior signed act, not invented"
        );
    }

    // (c) the same renew against a policy that DOES carry default_ttl →
    //     successor carries the POLICY's value, not the predecessor's.
    {
        let (cs, li) = stores();
        let registry = IdentityKeypair::Ed25519(Keypair::generate());
        let (handler, owner, seed) = curated_with_one_binding(
            &cs,
            &li,
            &registry,
            &IssuerPolicyData {
                mode: MODE_OPEN.into(),
                default_ttl: Some(600_000),
                max_ttl: Some(86_400_000),
                ..Default::default()
            },
            Some(PREDECESSOR_TTL),
        )
        .await;
        let r = handler
            .handle(&renew_ctx_with(seed, None, b"c", &owner))
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(
            binding_ttl(&cs, binding_hash_of(&r)),
            Some(600_000),
            "step 2 outranks step 3 — current operator intent over history"
        );
    }
}

/// `REG-RENEW-TTL-NULLPRED-1` `[v1.10]` — a peer-issued binding with
/// `ttl: null` written **directly to the tree**, renewed with no `ttl`
/// against a policy with no `default_ttl`: `403 policy_rejected`, nothing
/// published.
///
/// **The control is `REG-RENEW-TTL-CASCADE-1` row (b), which must still
/// return `200`** — without it this row passes against a peer that refuses
/// every ttl-less renew.
///
/// This is the branch that is unreachable on any conformant path and is
/// required precisely for that reason: *"an unreachable branch that is
/// asserted rather than enforced is how the shape it forbids gets minted."*
#[tokio::test]
async fn reg_renew_ttl_nullpred_1() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    let IdentityKeypair::Ed25519(ref registry_kp) = registry else {
        unreachable!("constructed Ed25519 one line up")
    };
    let rid = registry.peer_id().as_str().to_string();
    let owner = Keypair::generate();

    // The two-stage shape: write the bad binding straight to the tree, the
    // way a seed, an out-of-band tool, or a peer predating the rule would.
    publish_binding(
        &cs,
        &li,
        &rid,
        registry_kp,
        "billslab.com",
        owner.peer_id().as_str(),
        crate::log::now_ms(),
        None, // ttl: null — the shape §6a.3 forbids and no conformant mint produces
    );
    let seed = li
        .get(&crate::by_name_pointer_path(&rid, "billslab.com"))
        .expect("binding bound by name");
    assert_eq!(
        binding_ttl(&cs, seed),
        None,
        "the predecessor really is null-ttl"
    );

    install_policy(
        &cs,
        &li,
        &rid,
        &IssuerPolicyData {
            mode: MODE_OPEN.into(),
            max_ttl: Some(86_400_000),
            ..Default::default()
        },
    );
    let handler = reg_handler(&cs, &li, &registry);
    let before = li.list(&format!("/{}/system/registry/binding/", rid)).len();

    let r = handler
        .handle(&renew_ctx_with(seed, None, b"np", &owner))
        .await
        .unwrap();
    assert_eq!(r.status, 403, "all three cascade steps null MUST refuse");
    let code = result_field(&decode_result(&r), "code")
        .and_then(|v| v.as_text().map(|s| s.to_string()))
        .unwrap_or_default();
    assert_eq!(code, "policy_rejected");
    assert_eq!(
        li.list(&format!("/{}/system/registry/binding/", rid)).len(),
        before,
        "MUST publish nothing — no successor binding, no pointer move"
    );
    assert_eq!(
        li.get(&crate::by_name_pointer_path(&rid, "billslab.com")),
        Some(seed),
        "the by-name pointer still names the predecessor"
    );
    // …and the refusal did not burn the requester's nonce: the retry that
    // succeeds once the operator fixes the policy must not come back as a
    // replay.
    assert!(
        li.get(&crate::register_nonce_path(
            &rid,
            owner.peer_id().as_str(),
            b"np"
        ))
        .is_none(),
        "a refused renew publishes nothing, and that includes the nonce marker"
    );
}

/// `REG-TTL-RESOLVER-CEILING-1` `[v1.16]` — the resolver-side ceiling vector,
/// all four rows, against a chain entry carrying `hints.max_ttl`.
///
/// **This is R-5 on the cohort ledger and it is new for every seat.** The two
/// pre-existing TTL vectors test the *issuer* side; nothing tested the clamp
/// that protects a **consumer**, which is how four seats put the ceiling in
/// three different config keys with no instrument noticing (arch `d3752ca`,
/// GAP 2 → §4's `resolver_chain[].hints.max_ttl`).
///
/// Row (a)'s hash half is also pinned by
/// `resolver_ceiling_does_not_move_the_binding_hash` — deliberately, and this
/// one is written self-contained anyway: a vector row a reader has to
/// reassemble from two tests is a row nobody can check against the table.
///
/// **Row (d) — the sticky binding — is the row an implementation passes by
/// accident and fails on inspection**, because `min` over a null has no
/// natural answer. Arch ruled it in this peer's shape: the ceiling bounds *how
/// long a value may be honored*, so applying it only where a bound already
/// exists leaves exactly the unbounded case uncovered.
///
/// **Reported, not asserted:** the row's *"or `pinned`"* half is unreachable
/// here by construction. §4.1 step 1 returns a pinned binding from
/// `synthesize_pin` **before** the chain is consulted, so no
/// `resolver_chain[]` entry — and therefore no `hints.max_ttl` — is in scope
/// for a pin. Routed rather than worked around; `local-name` is the sticky
/// kind this peer can drive through the ceiling.
#[tokio::test]
async fn reg_ttl_resolver_ceiling_1() {
    let (cs, li) = stores();
    let registry_kp = Keypair::generate();
    let rid = registry_kp.peer_id().as_str().to_string();
    let target = Keypair::generate().peer_id().as_str().to_string();
    cs.put(registry_kp.peer_entity().unwrap()).unwrap();
    let issued = 86_400_000; // 1 day, as issued
    publish_binding(
        &cs,
        &li,
        &rid,
        &registry_kp,
        "billslab.com",
        &target,
        crate::log::now_ms(),
        Some(issued),
    );
    let ceiling = |ms: i64| {
        pi_entry(
            &rid,
            Some(Value::Map(vec![(text("max_ttl"), entity_ecf::integer(ms))])),
        )
    };
    let resolve = |entry: &ResolverChainEntry| {
        crate::resolver::apply_resolver_ceiling(
            crate::peer_issued::resolve_one(&cs, &li, entry, "billslab.com").expect("resolves"),
            entry,
        )
    };

    // (a) ttl ABOVE the ceiling → effective lifetime is exactly max_ttl, and
    //     the binding's content hash is UNCHANGED. Assert the hash, not only
    //     the number: a resolver that rewrites the binding to carry the
    //     clamped value moves its address and invalidates every signature
    //     over it.
    let bare = pi_entry(&rid, None);
    let unclamped = resolve(&bare);
    let a = ceiling(3_600_000);
    let clamped = resolve(&a);
    assert_eq!(clamped.ttl, Some(3_600_000), "(a) effective lifetime");
    assert_eq!(clamped.binding, unclamped.binding, "(a) hash unchanged");
    assert_eq!(
        binding_ttl(&cs, clamped.binding.unwrap()),
        Some(issued),
        "(a) the stored body still carries the ISSUED value"
    );

    // (b) ttl BELOW the ceiling → returned untouched.
    let b = ceiling(999_000_000);
    assert_eq!(resolve(&b).ttl, Some(issued), "(b) untouched");

    // (c) `max_ttl: 0` behaves IDENTICALLY to an absent `hints` — the
    //     binding's own ttl survives. Asserted against the absent-hints
    //     result, not just against the number, because "identical to absent"
    //     is the rule and a peer could special-case 0 to some other value.
    let c = ceiling(0);
    assert_eq!(resolve(&c).ttl, unclamped.ttl, "(c) 0 is undeclared");
    assert_eq!(resolve(&c).ttl, Some(issued));

    // (d) a STICKY binding (no `ttl`) resolves with effective lifetime
    //     max_ttl. Driven end-to-end through `:resolve` rather than through
    //     `apply_resolver_ceiling` directly — the arm is only worth anything
    //     if the chain actually reaches it.
    let (cs2, li2) = stores();
    let pet = LocalNameHandler::new(cs2.clone(), li2.clone(), PEER.into());
    pet.handle(&ctx(
        "bind",
        vec![
            (text("name"), text("sticky")),
            (text("target_peer_id"), text("z6MkSticky")),
        ],
    ))
    .await
    .unwrap();
    let cfg = ResolverConfigData {
        resolver_chain: vec![ResolverChainEntry {
            backend_kind: "local-name".into(),
            backend_id: PEER.into(),
            priority: 0,
            accepted_trust_anchors: vec![],
            hints: Some(Value::Map(vec![(
                text("max_ttl"),
                entity_ecf::integer(1_800_000),
            )])),
        }],
        ..Default::default()
    };
    install_config(&cs2, &li2, &cfg);
    let r = registry(&cs2, &li2)
        .handle(&ctx("resolve", vec![(text("name"), text("sticky"))]))
        .await
        .unwrap();
    let res = decode_result(&r);
    assert_eq!(
        result_field(&res, "status").unwrap().as_text(),
        Some("resolved"),
        "(d) the sticky binding still resolves"
    );
    assert_eq!(
        result_field(&res, "ttl").and_then(|v| v.as_integer()),
        Some(1_800_000i64.into()),
        "(d) a binding with no ttl takes the ceiling as its lifetime — `min` \
         over a null has no natural answer, and leaving it absent is the one \
         case a ceiling exists to bound"
    );
}

/// The **resolver's** ceiling (§6a.9.1 `[MUST when present]`) —
/// `min(binding.ttl, local_max)`, computed at resolution and **never written
/// back**. Row (a) of `REG-TTL-RESOLVER-CEILING-1`; kept alongside the named
/// vector because arch's fold quotes this test by name.
///
/// The load-bearing assertion is the *binding hash*, not the number: if a
/// refactor ever rewrote the binding to carry the clamped TTL, the content
/// address would move and every signature over it would stop verifying.
/// **That is the property that would rot silently** — asserting the clamped
/// number alone would not catch it.
#[test]
fn resolver_ceiling_does_not_move_the_binding_hash() {
    let (cs, li) = stores();
    let registry_kp = Keypair::generate();
    let rid = registry_kp.peer_id().as_str().to_string();
    let target = Keypair::generate().peer_id().as_str().to_string();
    cs.put(registry_kp.peer_entity().unwrap()).unwrap();
    publish_binding(
        &cs,
        &li,
        &rid,
        &registry_kp,
        "billslab.com",
        &target,
        crate::log::now_ms(),
        Some(86_400_000), // 1 day, issued
    );

    let unclamped =
        crate::peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "billslab.com")
            .expect("resolves");
    assert_eq!(unclamped.ttl, Some(86_400_000));

    let hints = Value::Map(vec![(text("max_ttl"), entity_ecf::integer(3_600_000))]);
    let entry = pi_entry(&rid, Some(hints));
    let clamped = crate::resolver::apply_resolver_ceiling(
        crate::peer_issued::resolve_one(&cs, &li, &entry, "billslab.com").expect("resolves"),
        &entry,
    );

    assert_eq!(
        clamped.ttl,
        Some(3_600_000),
        "honoured lifetime is min(ttl, local_max)"
    );
    assert_eq!(
        clamped.binding, unclamped.binding,
        "the binding is byte-identical clamped and unclamped — a use bound, not a re-issue"
    );
    assert_eq!(
        binding_ttl(&cs, clamped.binding.unwrap()),
        Some(86_400_000),
        "and the stored body still carries the ISSUED value"
    );

    // A ceiling above the binding's own ttl changes nothing.
    let generous = pi_entry(
        &rid,
        Some(Value::Map(vec![(
            text("max_ttl"),
            entity_ecf::integer(999_000_000),
        )])),
    );
    let r = crate::resolver::apply_resolver_ceiling(
        crate::peer_issued::resolve_one(&cs, &li, &generous, "billslab.com").expect("resolves"),
        &generous,
    );
    assert_eq!(r.ttl, Some(86_400_000));

    // `0` is DROPPED, not honoured: honoured literally it expires every
    // binding instantly and the operator sees "no binding for this name" —
    // indistinguishable from a bad signature or a revocation.
    let zero = pi_entry(
        &rid,
        Some(Value::Map(vec![(text("max_ttl"), entity_ecf::integer(0))])),
    );
    let r = crate::resolver::apply_resolver_ceiling(
        crate::peer_issued::resolve_one(&cs, &li, &zero, "billslab.com").expect("resolves"),
        &zero,
    );
    assert_eq!(r.ttl, Some(86_400_000), "a zero ceiling is dropped");
}

/// `approve-request` is the **third** producer of peer-issued bindings, and
/// no routing named it. It owes the same cascade and the same ceiling, read
/// from the policy that is live **now** rather than the one that was live
/// when the request was queued.
#[tokio::test]
async fn approve_request_applies_the_ceiling_live_not_as_queued() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    let rid = registry.peer_id().as_str().to_string();
    install_policy(
        &cs,
        &li,
        &rid,
        &IssuerPolicyData {
            mode: MODE_MANUAL.into(),
            default_ttl: Some(3_600_000),
            max_ttl: Some(86_400_000),
            ..Default::default()
        },
    );
    let handler = reg_handler(&cs, &li, &registry);
    let owner = Keypair::generate();

    // Queue a request asking for a year.
    let req = RegisterRequestData {
        name: "billslab.com".into(),
        target_peer_id: owner.peer_id().as_str().to_string(),
        transports: vec![Value::Text("tcp://billslab.com:9000".into())],
        requested_ttl: Some(31_536_000_000),
        nonce: b"queued".to_vec(),
        issued_at: crate::log::now_ms(),
    };
    let queued = handler
        .handle(&register_ctx(req.to_entity().unwrap(), &owner))
        .await
        .unwrap();
    assert_eq!(queued.status, 202, "manual mode queues");
    let pending_hash = result_field(&decode_result(&queued), "pending_hash")
        .and_then(|v| v.as_bytes())
        .map(|b| Hash::from_bytes(b).unwrap())
        .expect("pending_hash");

    // The operator LOWERS the ceiling before approving.
    install_policy(
        &cs,
        &li,
        &rid,
        &IssuerPolicyData {
            mode: MODE_MANUAL.into(),
            default_ttl: Some(600_000),
            max_ttl: Some(1_800_000),
            ..Default::default()
        },
    );

    let approved = handler
        .handle(&ctx(
            "approve-request",
            vec![(
                text("pending_hash"),
                Value::Bytes(pending_hash.to_bytes().to_vec()),
            )],
        ))
        .await
        .unwrap();
    assert_eq!(approved.status, 200);
    assert_eq!(
        binding_ttl(&cs, binding_hash_of(&approved)),
        Some(1_800_000),
        "approve signs under the ceiling the operator set, not the one at queue time"
    );
}

// ---------------------------------------------------------------------------
// §4.3 `[v1.18]` — `set-resolver-config` / `get-resolver-config`, and the
// §4.1 step 2 name-disclosure MUST that finally has a surface to bind to.
//
// Arch ruled 1.18 on the derivation, not on the cohort: a distribution's
// artifact is extended by parties it will never see, so a safety property that
// does not survive extension is not one a shipper can be held to. That is what
// makes the check KIND-SCOPED, and the kind-scoped row is the one no
// resolve-time observable can settle — the absence of a request is name-blind
// under either reading. It has to be measured at the write.
// ---------------------------------------------------------------------------

use crate::resolver::{disclosure_violations, pattern_matches_unscoped_name};

/// A `system/registry/set-resolver-config-request` carrying `cfg_entity`
/// nested and, when `ack`, the operator's acknowledgement.
///
/// The acknowledgement is a key of THIS entity and never of the config —
/// which is exactly what `the_acknowledgement_cannot_be_forged_into_the_config`
/// exercises from the other side.
fn set_config_request(cfg_entity: &Entity, ack: bool) -> Entity {
    let data: Value = ciborium::from_reader(cfg_entity.data.as_slice()).unwrap();
    let nested = Value::Map(vec![
        (
            text("content_hash"),
            Value::Bytes(cfg_entity.content_hash.to_bytes().to_vec()),
        ),
        (text("data"), data),
        (text("type"), text(&cfg_entity.entity_type)),
    ]);
    let mut fields = vec![(text("config"), nested)];
    if ack {
        fields.push((text("acknowledge_name_disclosure"), Value::Bool(true)));
    }
    Entity::new(
        entity_types::TYPE_REGISTRY_SET_RESOLVER_CONFIG_REQUEST,
        to_ecf(&Value::Map(fields)),
    )
    .unwrap()
}

fn set_config_ctx(cfg: &ResolverConfigData, ack: bool) -> HandlerContext {
    policy_ctx(
        "set-resolver-config",
        set_config_request(&cfg.to_entity().unwrap(), ack),
    )
}

fn chain_entry(kind: &str, priority: u32) -> ResolverChainEntry {
    ResolverChainEntry {
        backend_kind: kind.into(),
        backend_id: "x".into(),
        priority,
        accepted_trust_anchors: vec![],
        hints: None,
    }
}

fn dispatch(pattern: &str, kinds: &[&str]) -> DispatchRule {
    DispatchRule {
        pattern: pattern.into(),
        backend_kinds: kinds.iter().map(|k| k.to_string()).collect(),
    }
}

/// The §4.3 control: a **scoped** rule naming a transmitting kind is accepted,
/// and `get` returns the stored bytes byte-for-byte.
///
/// Byte-identity is asserted on the *hash*, not on the decoded fields: a peer
/// that re-encodes through `ResolverConfigData::to_entity` produces the same
/// fields under a different address, and would silently drop every key this
/// codec does not model.
#[tokio::test]
async fn set_resolver_config_stores_the_submitted_bytes_and_get_returns_them() {
    let (cs, li) = stores();
    let handler = registry(&cs, &li);
    let cfg = ResolverConfigData {
        resolver_chain: vec![chain_entry("local-name", 0), chain_entry("did-web", 1)],
        name_format_dispatch: vec![dispatch("did:web:*", &["did-web"])],
        ..Default::default()
    };
    let submitted = cfg.to_entity().unwrap();

    let set = handler.handle(&set_config_ctx(&cfg, false)).await.unwrap();
    assert_eq!(
        set.status, 200,
        "a scoped `did:web:*` rule discloses nothing — the user named the authority"
    );
    assert_eq!(set.result.content_hash, submitted.content_hash);

    let got = handler
        .handle(&no_params_ctx("get-resolver-config"))
        .await
        .unwrap();
    assert_eq!(got.status, 200);
    assert_eq!(
        got.result.content_hash, submitted.content_hash,
        "the round-trip is byte-exact, not field-equivalent"
    );
    assert_eq!(got.result.data, submitted.data);

    // **The row that makes byte-exactness observable.** Against a config this
    // codec fully models, storing the submitted bytes and re-encoding through
    // `ResolverConfigData::to_entity` produce the same address, so a re-encode
    // is an invisible defect. A config carrying a key we do not model — a
    // forward-compat field, the shape §4.2 exists to permit — separates them:
    // a re-encoding peer silently drops it and returns a different hash.
    let with_unknown_key = Entity::new(
        entity_types::TYPE_REGISTRY_RESOLVER_CONFIG,
        to_ecf(&Value::Map(vec![
            (
                text("name_format_dispatch"),
                Value::Array(vec![Value::Map(vec![
                    (
                        text("backend_kinds"),
                        Value::Array(vec![text("local-name")]),
                    ),
                    (text("pattern"), text("*")),
                ])]),
            ),
            (
                text("resolver_chain"),
                Value::Array(vec![Value::Map(vec![
                    (text("backend_id"), text("x")),
                    (text("backend_kind"), text("local-name")),
                    (text("priority"), entity_ecf::integer(0)),
                ])]),
            ),
            (text("schema_version_2027"), entity_ecf::integer(2)),
        ])),
    )
    .unwrap();
    let set = handler
        .handle(&policy_ctx(
            "set-resolver-config",
            set_config_request(&with_unknown_key, false),
        ))
        .await
        .unwrap();
    assert_eq!(set.status, 200);
    let got = handler
        .handle(&no_params_ctx("get-resolver-config"))
        .await
        .unwrap();
    assert_eq!(
        got.result.content_hash, with_unknown_key.content_hash,
        "a key this codec does not model MUST survive the write — the stored \
         entity is the operator's bytes, not our re-encoding of them"
    );
}

/// `get-resolver-config` is `404` when unset, and MUST NOT synthesize the
/// local-name-only default `meta_resolve` runs with.
///
/// That default is what the resolver *does* with no config; it is not what an
/// operator *wrote*. Returning it would report a configuration that does not
/// exist — §6a.9.2's "unset is not a mode", one operation over.
#[tokio::test]
async fn get_resolver_config_is_404_when_unset_and_synthesizes_nothing() {
    let (cs, li) = stores();
    let got = registry(&cs, &li)
        .handle(&no_params_ctx("get-resolver-config"))
        .await
        .unwrap();
    assert_eq!(got.status, 404);
    assert_eq!(err_code(&got).as_deref(), Some("not_found"));
}

/// Door 1 — a broad rule naming a name-transmitting kind is refused `403
/// policy_rejected`, **with every violation listed**, not the first.
#[tokio::test]
async fn a_broad_dispatch_rule_naming_a_transmitting_kind_is_refused() {
    let (cs, li) = stores();
    let handler = registry(&cs, &li);
    let cfg = ResolverConfigData {
        resolver_chain: vec![chain_entry("local-name", 0), chain_entry("did-web", 1)],
        name_format_dispatch: vec![dispatch("*", &["did-web", "dns-txt"])],
        ..Default::default()
    };
    let r = handler.handle(&set_config_ctx(&cfg, false)).await.unwrap();
    assert_eq!(r.status, 403);
    assert_eq!(err_code(&r).as_deref(), Some("policy_rejected"));

    let msg = result_field(&decode_result(&r), "message")
        .and_then(|v| v.as_text())
        .unwrap_or_default()
        .to_string();
    assert!(
        msg.contains("did-web") && msg.contains("dns-txt"),
        "every violation, not the first — an operator repairing a chain wants \
         the whole list. got: {msg}"
    );
}

/// **The kind-scoped discriminator `[MUST, v1.17/v1.18]`.** A broad `*` rule
/// naming `did-web` is refused even though the chain holds **no** `did-web`
/// entry.
///
/// This is the single row that separates the two readings, and it cannot be
/// measured at resolution: with no `did-web` backend in the chain, a
/// chain-scoped peer and a kind-scoped peer emit exactly the same traffic
/// (none). Mutation: make `disclosure_violations`' door 1 also require a
/// matching `resolver_chain` entry and this test — alone — goes red.
///
/// The reason it is the conservative direction and not merely the strict one:
/// a false positive costs the operator one edit against a config that is
/// presently harmless, while a false negative arms silent, irreversible
/// disclosure of every bare name the moment an unrelated chain entry appears.
#[tokio::test]
async fn the_disclosure_check_is_kind_scoped_not_chain_scoped() {
    let (cs, li) = stores();
    let cfg = ResolverConfigData {
        resolver_chain: vec![chain_entry("local-name", 0)],
        name_format_dispatch: vec![dispatch("*", &["did-web"])],
        ..Default::default()
    };
    let r = registry(&cs, &li)
        .handle(&set_config_ctx(&cfg, false))
        .await
        .unwrap();
    assert_eq!(
        r.status, 403,
        "a shipped artifact's safety must survive a downstream operator adding \
         the backend later — an extension the shipper can never re-review"
    );
    assert_eq!(err_code(&r).as_deref(), Some("policy_rejected"));
}

/// Door 2 — an **absent** `name_format_dispatch` with a transmitting kind in
/// the chain is refused: the filter is disabled, every kind is eligible for
/// every name, and there is no catch-all row to inspect.
///
/// This door is the one that reads the chain, and it must: with no rules there
/// is nothing else to read.
#[tokio::test]
async fn an_absent_dispatch_list_with_a_transmitting_kind_in_the_chain_is_refused() {
    let (cs, li) = stores();
    let cfg = ResolverConfigData {
        resolver_chain: vec![chain_entry("did-web", 0)],
        ..Default::default()
    };
    let r = registry(&cs, &li)
        .handle(&set_config_ctx(&cfg, false))
        .await
        .unwrap();
    assert_eq!(r.status, 403);
    assert_eq!(err_code(&r).as_deref(), Some("policy_rejected"));

    // …and the same empty list with only safe kinds is fine. Without this arm
    // the row above would also pass against a peer that refuses every
    // dispatch-less config.
    let safe = ResolverConfigData {
        resolver_chain: vec![chain_entry("local-name", 0), chain_entry("peer-issued", 1)],
        ..Default::default()
    };
    let ok = registry(&cs, &li)
        .handle(&set_config_ctx(&safe, false))
        .await
        .unwrap();
    assert_eq!(
        ok.status, 200,
        "`peer-issued` is name-blind by §6a.4 — the banned property is name \
         transmission, not remoteness"
    );
}

/// **No partial application `[MUST]`** — a refusal writes nothing, and the
/// following `get` returns the *previous* bytes.
#[tokio::test]
async fn a_refusal_writes_nothing_and_get_returns_the_prior_bytes() {
    let (cs, li) = stores();
    let handler = registry(&cs, &li);
    let good = ResolverConfigData {
        resolver_chain: vec![chain_entry("local-name", 0)],
        name_format_dispatch: vec![dispatch("*", &["local-name"])],
        ..Default::default()
    };
    assert_eq!(
        handler
            .handle(&set_config_ctx(&good, false))
            .await
            .unwrap()
            .status,
        200
    );
    let baseline = good.to_entity().unwrap().content_hash;

    let bad = ResolverConfigData {
        resolver_chain: vec![chain_entry("did-web", 0)],
        name_format_dispatch: vec![dispatch("*", &["did-web"])],
        ..Default::default()
    };
    assert_eq!(
        handler
            .handle(&set_config_ctx(&bad, false))
            .await
            .unwrap()
            .status,
        403
    );

    let got = handler
        .handle(&no_params_ctx("get-resolver-config"))
        .await
        .unwrap();
    assert_eq!(got.status, 200);
    assert_eq!(
        got.result.content_hash, baseline,
        "the stored config moved on a REFUSAL — a refusal MUST write nothing"
    );
}

/// The operator `MAY`, honored: the **same** config that was refused is stored
/// byte-exact when the write carries `acknowledge_name_disclosure`.
///
/// Without this row a peer that refuses unconditionally — deleting the
/// override it was granted — scores identically to a conformant one.
#[tokio::test]
async fn the_operator_acknowledgement_stores_the_refused_config_byte_exact() {
    let (cs, li) = stores();
    let handler = registry(&cs, &li);
    let cfg = ResolverConfigData {
        resolver_chain: vec![chain_entry("did-web", 0)],
        name_format_dispatch: vec![dispatch("*", &["did-web"])],
        ..Default::default()
    };
    assert_eq!(
        handler
            .handle(&set_config_ctx(&cfg, false))
            .await
            .unwrap()
            .status,
        403,
        "unacknowledged: refused"
    );
    let acked = handler.handle(&set_config_ctx(&cfg, true)).await.unwrap();
    assert_eq!(
        acked.status, 200,
        "acknowledged: the operator's own peer, their call"
    );

    let got = handler
        .handle(&no_params_ctx("get-resolver-config"))
        .await
        .unwrap();
    assert_eq!(
        got.result.content_hash,
        cfg.to_entity().unwrap().content_hash
    );
}

/// **The acknowledgement is an act, not a byte `[MUST]`.** A config entity
/// carrying `acknowledge_name_disclosure: true` *inside its own data* is still
/// refused — the flag is read from the operation's params and nowhere else.
///
/// This is the whole reason §4.3 exists as an operation rather than a field: a
/// field is written by whoever writes the bytes, so a distribution could set
/// it and defeat the rule it is meant to bound, and it would move a
/// content-addressed type's hash to carry a claim it cannot secure.
#[tokio::test]
async fn the_acknowledgement_cannot_be_forged_into_the_config_entity() {
    let (cs, li) = stores();
    // Hand-built so the forged key really is in the config's own bytes —
    // `ResolverConfigData::to_entity` has no way to emit it.
    let forged = Entity::new(
        entity_types::TYPE_REGISTRY_RESOLVER_CONFIG,
        to_ecf(&Value::Map(vec![
            (text("acknowledge_name_disclosure"), Value::Bool(true)),
            (
                text("name_format_dispatch"),
                Value::Array(vec![Value::Map(vec![
                    (text("backend_kinds"), Value::Array(vec![text("did-web")])),
                    (text("pattern"), text("*")),
                ])]),
            ),
            (
                text("resolver_chain"),
                Value::Array(vec![Value::Map(vec![
                    (text("backend_id"), text("x")),
                    (text("backend_kind"), text("did-web")),
                    (text("priority"), entity_ecf::integer(0)),
                ])]),
            ),
        ])),
    )
    .unwrap();
    let r = registry(&cs, &li)
        .handle(&policy_ctx(
            "set-resolver-config",
            set_config_request(&forged, false),
        ))
        .await
        .unwrap();
    assert_eq!(
        r.status, 403,
        "a flag inside the bytes is not an act by an identified, capability-gated actor"
    );
}

/// §4.2 `[MUST, v1.14]` — an **unknown** backend kind is not a
/// name-transmitting kind and MUST NOT be treated as one.
///
/// Refusing a config because a broad rule names a kind this build does not
/// recognize rejects a deployment authored against a *newer* vocabulary, which
/// is the case §4.2 exists to permit. The control below is the same config
/// with a declared kind, so the row measures the vocabulary and not the shape.
#[tokio::test]
async fn an_unknown_backend_kind_is_not_name_transmitting() {
    let (cs, li) = stores();
    let future_kind = ResolverConfigData {
        resolver_chain: vec![chain_entry("some-2027-backend", 0)],
        name_format_dispatch: vec![dispatch("*", &["some-2027-backend"])],
        ..Default::default()
    };
    assert_eq!(
        registry(&cs, &li)
            .handle(&set_config_ctx(&future_kind, false))
            .await
            .unwrap()
            .status,
        200,
        "an undeclared kind consults nothing this build can reach and discloses nothing"
    );

    let declared = ResolverConfigData {
        resolver_chain: vec![chain_entry("consensus-anchored", 0)],
        name_format_dispatch: vec![dispatch("*", &["consensus-anchored"])],
        ..Default::default()
    };
    assert_eq!(
        registry(&cs, &li)
            .handle(&set_config_ctx(&declared, false))
            .await
            .unwrap()
            .status,
        403,
        "control — the same shape with a DECLARED transmitting kind is refused"
    );
}

/// **The §4.1a recommended default list is the fixture that pins is-broad.**
///
/// A distribution SHOULD ship this list and the catch-all MUST lives *inside*
/// it, so every non-catch-all row has to classify **narrow** or the
/// recommended list would violate its own MUST. Row 3 is decisive: `*.eth`
/// names `consensus-anchored`, a transmitting kind, so a classifier that reads
/// `*.eth` as broad refuses the exact list §4.1a recommends.
///
/// We derive the classifier from this table rather than from any shell-glob
/// convention — and this test is the derivation, executable.
#[test]
fn the_recommended_default_dispatch_list_satisfies_its_own_catch_all_must() {
    let list = ResolverConfigData {
        resolver_chain: vec![
            chain_entry("local-name", 0),
            chain_entry("did-web", 1),
            chain_entry("dns-txt", 2),
            chain_entry("consensus-anchored", 3),
        ],
        name_format_dispatch: vec![
            dispatch("did:web:*", &["did-web"]),
            dispatch("did:key:*", &["self-certifying"]),
            dispatch("*.eth", &["consensus-anchored"]),
            dispatch("*@*.*", &["dns-txt", "well-known-url"]),
            dispatch("*@*", &["peer-issued"]),
            dispatch(
                "*",
                &[
                    "local-name",
                    "self-certifying",
                    "out-of-band",
                    "peer-issued",
                ],
            ),
        ],
        ..Default::default()
    };
    assert!(
        disclosure_violations(&list).is_empty(),
        "the list a distribution SHOULD ship must not violate the MUST inside it: {:?}",
        disclosure_violations(&list)
    );

    // Each marker, and the shapes that carry none of them.
    for narrow in ["did:web:*", "did:key:*", "*.eth", "*@*.*", "*@*"] {
        assert!(!pattern_matches_unscoped_name(narrow), "{narrow} is scoped");
    }
    for broad in ["*", "a*", "*.*"] {
        assert!(
            pattern_matches_unscoped_name(broad),
            "{broad} reaches a bare name — `*.*`'s suffix is a star, not a \
             literal, so it matches `alice.bob` as readily as a domain"
        );
    }
}

/// §4.1b's classifier, rule by rule `[MUST, v1.19]` — the grammar that replaced
/// the predicate §4.1 step 2 had been turning on with no definition.
///
/// **Two of these rows moved when the ruling landed, and both are rows the
/// ruling itself names as a seat's divergence.** `alice` / `a.b` are NARROW by
/// rule (a) — we classified any pattern free of `@` and `:` as broad, so an
/// exact literal came out broad. `*.lab` is BROAD — we accepted any literal
/// dotted suffix, and *"the line is not 'does a literal exist' but 'does the
/// literal identify an authority or a naming system'"*, which is enumerated in
/// §4.1b.1 (`.eth`, and nothing else, growing only by spec revision).
///
/// **Rewriting a test's expectation destroys its value as evidence**, so the
/// witness for this table is not this test: it is
/// `REG-DISPATCH-CONFIG-REFUSED-1` row 7, which drives the five diverging
/// patterns through `set-resolver-config` from core-go's harness. This test is
/// the unit-level statement of the same rule, and the four `assert!`s below are
/// grouped by the rule each row exercises so a future edit has to say which
/// rule it thinks it is changing.
#[test]
fn the_v1_19_broad_classifier_follows_the_four_rules() {
    // (a) no `*` — matches exactly one name, so it is a routing decision the
    // operator wrote out. This is the row that moved.
    for narrow in ["a.b", "alice", "alice.eth", "alice.lab", "billslab.com"] {
        assert!(
            !pattern_matches_unscoped_name(narrow),
            "{narrow} has no `*` — rule (a) makes it narrow whatever it looks like"
        );
    }
    // (b) a literal `@` anywhere — the user named an authority.
    for narrow in ["*@*", "*@*.*", "*@example.org", "alice@*"] {
        assert!(!pattern_matches_unscoped_name(narrow), "{narrow}: rule (b)");
    }
    // (c) the literal head before the FIRST `*` ends in `:` — a scheme prefix.
    // `:` anywhere is not the rule: in `*:foo` the `:` sits behind a leading
    // star, so nothing constrains the head and the pattern reaches bare names.
    assert!(!pattern_matches_unscoped_name("did:web:*"), "rule (c)");
    assert!(!pattern_matches_unscoped_name("did:key:*"), "rule (c)");
    assert!(
        pattern_matches_unscoped_name("*:foo"),
        "`*:foo` has a `:` but not in its head — rule (c) does not fire"
    );
    // (d) ends in an enumerated typed suffix (§4.1b.1). `.eth` is the whole
    // list; an unrecognized suffix leaves the pattern broad, which is the
    // fail-safe direction.
    assert_eq!(
        crate::resolver::ENUMERATED_TYPED_SUFFIXES,
        &[".eth"],
        "the suffix list grows ONLY by spec revision — admitting one is a \
         privacy decision, not an implementation choice"
    );
    assert!(!pattern_matches_unscoped_name("*.eth"), "rule (d)");
    assert!(!pattern_matches_unscoped_name("alice*.eth"), "rule (d)");
    assert!(
        pattern_matches_unscoped_name("*.lab"),
        "`.lab` is not enumerated — this is the row the ruling names, and \
         reading it narrow discloses a namespace nobody reviewed"
    );
    assert!(
        pattern_matches_unscoped_name("*.e*"),
        "a trailing `*` means the pattern does not END in a fixed suffix"
    );
    // Otherwise broad.
    for broad in ["*", "a*", "*.*", "*.com", "*b*"] {
        assert!(pattern_matches_unscoped_name(broad), "{broad} is broad");
    }
}

/// Row 7 of `REG-DISPATCH-CONFIG-REFUSED-1`, driven in-tree at the surface the
/// wire check drives it at: five patterns that each name `did-web` with a
/// `did-web` chain entry present, so the ONLY thing deciding 200 vs 403 is the
/// §4.1b classification.
#[tokio::test]
async fn classifier_rows_decide_set_resolver_config_the_way_row_7_drives_them() {
    for (pattern, refused) in [
        ("*.*", true),
        ("*.e*", true),
        ("*.eth", false),
        ("a.b", false),
        ("*.lab", true),
    ] {
        let (cs, li) = stores();
        let handler = registry(&cs, &li);
        let cfg = ResolverConfigData {
            resolver_chain: vec![chain_entry("local-name", 0), chain_entry("did-web", 1)],
            name_format_dispatch: vec![dispatch(pattern, &["did-web"])],
            ..Default::default()
        };
        let r = handler.handle(&set_config_ctx(&cfg, false)).await.unwrap();
        if refused {
            assert_eq!(r.status, 403, "row 7 {pattern}: a BROAD pattern discloses");
            assert_eq!(
                err_code(&r).as_deref(),
                Some("policy_rejected"),
                "{pattern}"
            );
            assert_eq!(
                handler
                    .handle(&no_params_ctx("get-resolver-config"))
                    .await
                    .unwrap()
                    .status,
                404,
                "row 7 {pattern}: a refusal writes nothing"
            );
        } else {
            assert_eq!(
                r.status, 200,
                "row 7 {pattern}: a NARROW pattern discloses nothing and MUST be accepted"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// §4.3 pin-delta `[MUST, v1.19]` — `system/capability/registry-pin`
//
// Row 8 of `REG-DISPATCH-CONFIG-REFUSED-1`, pinned HERE and deliberately not on
// the wire. The row's discriminator is the *encoding* of "pin authority", and
// §5 names `registry-pin` descriptively only — every seat enforces by grant
// scope, so each has to invent an encoding, and a shared harness minting one
// seat's would 403 a conformant peer that chose another (`entity-core-go`
// spec-issue `2026-08-20-a`). We take go's encoding rather than a third one.
// ---------------------------------------------------------------------------

/// A capability whose grants cover the registry handler for `operations`.
fn registry_cap(operations: &[&str]) -> entity_capability::CapabilityToken {
    entity_capability::CapabilityToken {
        grants: vec![entity_capability::GrantEntry {
            handlers: entity_capability::PathScope::new(vec![format!("/{PEER}/system/registry")]),
            resources: entity_capability::PathScope::new(vec![format!(
                "/{PEER}/system/registry/*"
            )]),
            operations: entity_capability::IdScope::new(
                operations.iter().map(|o| o.to_string()).collect(),
            ),
            peers: None,
            constraints: None,
            allowances: None,
        }],
        granter: entity_capability::Granter::Single(Hash::zero()),
        grantee: Hash::zero(),
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    }
}

fn set_config_ctx_as(
    cfg: &ResolverConfigData,
    cap: entity_capability::CapabilityToken,
) -> HandlerContext {
    let execute = Entity::new(entity_types::TYPE_EXECUTE, to_ecf(&Value::Map(vec![]))).unwrap();
    HandlerContext::builder(
        execute,
        set_config_request(&cfg.to_entity().unwrap(), false),
    )
    .operation("set-resolver-config".to_string())
    .caller_capability(cap)
    .build()
}

fn pinned(name: &str, target: &str) -> PinnedBinding {
    PinnedBinding {
        name: name.into(),
        target_peer_id: target.into(),
        reason: None,
    }
}

/// The pin-delta MUST, all four dispositions.
///
/// **A pin is the most privileged row in the file** — §4.1 step 1 answers a
/// pinned name *before* the step-2 disclosure filter and *before* the §6a.9.1
/// resolver ceiling — so a `registry-configure` grant that could write it would
/// let the less specific authority write the more privileged row.
///
/// The four rows are the whole rule, and three of them are what keep the check
/// from being a blanket refusal: the byte-identical write goes through on
/// configure alone, the pin+configure caller is not blocked, and the local
/// owner (who presents no capability at all, because they are the root
/// authority) is unaffected.
#[tokio::test]
async fn a_pin_change_needs_registry_pin_and_a_refusal_writes_nothing() {
    let (cs, li) = stores();
    let handler = registry(&cs, &li);
    let configure_only = || registry_cap(&["set-resolver-config", "get-resolver-config"]);
    let configure_and_pin =
        || registry_cap(&["set-resolver-config", "get-resolver-config", "pin-bindings"]);

    let base = ResolverConfigData {
        resolver_chain: vec![chain_entry("local-name", 0)],
        pinned_bindings: vec![pinned("alice", "z6MkAlice")],
        ..Default::default()
    };
    // Seed out-of-band (§6a.9.2's store-first door), so the FIRST measured
    // write is already a delta rather than the create.
    install_config(&cs, &li, &base);
    let stored_hash = base.to_entity().unwrap().content_hash;

    // Row 8a — pins differ, configure-only → 403 not_entitled, nothing written.
    let moved = ResolverConfigData {
        pinned_bindings: vec![pinned("alice", "z6MkAttacker")],
        ..base.clone()
    };
    let r = handler
        .handle(&set_config_ctx_as(&moved, configure_only()))
        .await
        .unwrap();
    assert_eq!(r.status, 403, "a pin change on a configure-only grant");
    assert_eq!(err_code(&r).as_deref(), Some("not_entitled"));
    let got = handler
        .handle(&no_params_ctx("get-resolver-config"))
        .await
        .unwrap();
    assert_eq!(
        got.result.content_hash, stored_hash,
        "and nothing was written — the refusal precedes the store touch"
    );

    // Row 8b — the SAME write with pin authority → 200. Without this row a peer
    // that refuses every pin-carrying write scores identically.
    let r = handler
        .handle(&set_config_ctx_as(&moved, configure_and_pin()))
        .await
        .unwrap();
    assert_eq!(r.status, 200, "configure + pin writes the pin");
    assert_eq!(
        r.result.content_hash,
        moved.to_entity().unwrap().content_hash
    );

    // Row 8c — a byte-identical pin list needs only `registry-configure`, even
    // though the rest of the config changes. This is the row that separates the
    // delta from "any write that mentions pins".
    let elsewhere = ResolverConfigData {
        resolver_chain: vec![chain_entry("local-name", 0), chain_entry("peer-issued", 1)],
        ..moved.clone()
    };
    let r = handler
        .handle(&set_config_ctx_as(&elsewhere, configure_only()))
        .await
        .unwrap();
    assert_eq!(
        r.status, 200,
        "the pin list is unchanged, so configure alone suffices"
    );

    // Row 8d — the local owner presents NO capability (they are the root
    // authority, not a grantee), and is unaffected.
    let owner_moved = ResolverConfigData {
        pinned_bindings: vec![pinned("bob", "z6MkBob")],
        ..elsewhere.clone()
    };
    let r = handler
        .handle(&set_config_ctx(&owner_moved, false))
        .await
        .unwrap();
    assert_eq!(r.status, 200, "no caller capability is the local owner");
}

/// Adding the FIRST pin to a config that had none is a change, and dropping the
/// last one is too — the predicate is not "both sides have pins".
///
/// And the empty encodings are one fact: our encoder omits `pinned_bindings`
/// when the list is empty, an operator MAY write `[]`, and demanding pin
/// authority to move between those two spellings would be a refusal with
/// nothing behind it (the same absent-is-empty rule the wire uses for every
/// optional array).
#[tokio::test]
async fn the_pin_delta_covers_the_empty_edges_but_not_the_empty_spelling() {
    let (cs, li) = stores();
    let handler = registry(&cs, &li);
    let configure_only = || registry_cap(&["set-resolver-config", "get-resolver-config"]);

    let no_pins = ResolverConfigData {
        resolver_chain: vec![chain_entry("local-name", 0)],
        ..Default::default()
    };
    install_config(&cs, &li, &no_pins);

    // none → one is a change.
    let first_pin = ResolverConfigData {
        pinned_bindings: vec![pinned("alice", "z6MkAlice")],
        ..no_pins.clone()
    };
    let r = handler
        .handle(&set_config_ctx_as(&first_pin, configure_only()))
        .await
        .unwrap();
    assert_eq!(r.status, 403, "the first pin is a pin change");
    assert_eq!(err_code(&r).as_deref(), Some("not_entitled"));

    // absent vs. an explicitly-encoded empty array is NOT a change.
    let explicit_empty = Entity::new(
        entity_types::TYPE_REGISTRY_RESOLVER_CONFIG,
        to_ecf(&Value::Map(vec![
            (text("log_cache_hits"), Value::Bool(false)),
            (text("pinned_bindings"), Value::Array(vec![])),
            (text("resolution_log_capacity"), entity_ecf::integer(1024)),
            (
                text("resolver_chain"),
                Value::Array(vec![Value::Map(vec![
                    (text("backend_id"), text("x")),
                    (text("backend_kind"), text("local-name")),
                    (text("priority"), entity_ecf::integer(0)),
                ])]),
            ),
        ])),
    )
    .unwrap();
    let execute = Entity::new(entity_types::TYPE_EXECUTE, to_ecf(&Value::Map(vec![]))).unwrap();
    let r = handler
        .handle(
            &HandlerContext::builder(execute, set_config_request(&explicit_empty, false))
                .operation("set-resolver-config".to_string())
                .caller_capability(configure_only())
                .build(),
        )
        .await
        .unwrap();
    assert_eq!(
        r.status, 200,
        "absent and `[]` are the same fact — no pin authority is owed for a spelling"
    );

    // one → none is a change, in the other direction.
    install_config(&cs, &li, &first_pin);
    let r = handler
        .handle(&set_config_ctx_as(&no_pins, configure_only()))
        .await
        .unwrap();
    assert_eq!(r.status, 403, "removing the last pin is a pin change");
}

/// The delta is over the **raw bytes**, so a pin entry carrying a key this
/// codec does not model cannot be rewritten under a configure-only grant.
///
/// This is the row a decoded comparison cannot pass, and it is the reason the
/// predicate is byte-level rather than a `Vec<PinnedBinding>` compare: the
/// decoded form sees `{name, target_peer_id, reason}` and nothing else, so a
/// forward-compat field (§4.2's own shape) could be changed — or a pin's whole
/// meaning altered by one — while the diff reports "no change". A fail-open on
/// the most privileged row in the file.
#[tokio::test]
async fn a_pin_field_this_codec_does_not_model_still_counts_as_a_pin_change() {
    let (cs, li) = stores();
    let handler = registry(&cs, &li);

    let with_key = |value: &str| {
        Entity::new(
            entity_types::TYPE_REGISTRY_RESOLVER_CONFIG,
            to_ecf(&Value::Map(vec![
                (
                    text("pinned_bindings"),
                    Value::Array(vec![Value::Map(vec![
                        (text("name"), text("alice")),
                        (text("pin_policy_2027"), text(value)),
                        (text("target_peer_id"), text("z6MkAlice")),
                    ])]),
                ),
                (
                    text("resolver_chain"),
                    Value::Array(vec![Value::Map(vec![
                        (text("backend_id"), text("x")),
                        (text("backend_kind"), text("local-name")),
                        (text("priority"), entity_ecf::integer(0)),
                    ])]),
                ),
            ])),
        )
        .unwrap()
    };
    let stored = with_key("sticky");
    let h = cs.put(stored.clone()).unwrap();
    li.set(&crate::resolver_config_path(PEER), h);

    let execute = Entity::new(entity_types::TYPE_EXECUTE, to_ecf(&Value::Map(vec![]))).unwrap();
    let r = handler
        .handle(
            &HandlerContext::builder(execute, set_config_request(&with_key("revocable"), false))
                .operation("set-resolver-config".to_string())
                .caller_capability(registry_cap(&["set-resolver-config"]))
                .build(),
        )
        .await
        .unwrap();
    assert_eq!(
        r.status, 403,
        "the two configs decode to the SAME PinnedBinding — only the bytes differ, \
         and the bytes are what §4.3 says the predicate is over"
    );
    assert_eq!(err_code(&r).as_deref(), Some("not_entitled"));
    assert_eq!(
        handler
            .handle(&no_params_ctx("get-resolver-config"))
            .await
            .unwrap()
            .result
            .content_hash,
        stored.content_hash,
        "and nothing was written"
    );
}

/// **R-27 clause 2 `[MUST]`** — `pin-bindings` is a capability-check
/// discriminator and MUST NOT be dispatchable.
///
/// Both halves, because either alone is satisfiable by accident: it is absent
/// from the advertised operation table (what `bootstrap_handler` publishes as
/// this handler's contract), **and** an EXECUTE naming it is refused rather
/// than silently routed. Arch pinned this clause because it is *"the one place
/// a seat could diverge into a new wire surface"* — an operation name that is
/// checkable but not callable is unusual enough that a seat might expose it,
/// and exposing it adds an undeclared operation to the registry handler.
#[tokio::test]
async fn pin_bindings_is_a_discriminator_and_not_a_dispatchable_operation() {
    let (cs, li) = stores();
    let handler = registry(&cs, &li);

    assert!(
        !handler.operations().contains(&crate::OP_PIN_BINDINGS),
        "`pin-bindings` MUST NOT appear in the advertised operation table — a \
         peer that answers an operation it does not advertise is inconsistent \
         with its own published interface, and one that ADVERTISES this is \
         declaring a wire surface the ruling says does not exist"
    );

    let r = handler
        .handle(&no_params_ctx(crate::OP_PIN_BINDINGS))
        .await
        .unwrap();
    assert_eq!(
        r.status, 400,
        "an EXECUTE naming `pin-bindings` MUST be refused — nothing routes to it"
    );
    assert_eq!(err_code(&r).as_deref(), Some("unknown_operation"));
}

/// **R-27 clause 4 `[MUST]`** — capability checks precede config validation, and
/// the observable is the *code*, not the status.
///
/// The discriminating config both **changes pins** and **discloses** (a broad
/// `*` rule naming a transmitting kind), submitted with configure-only
/// authority and no acknowledgement. Both refusals are `403`, so a peer that
/// validates first is invisible to any check that reads only the status: it
/// answers `policy_rejected` where the ruling requires `not_entitled`.
///
/// **The reason is an information leak, not tidiness.** §4.3's refusal body is
/// deliberately verbose — *"every violation, not the first"*, because an
/// operator repairing a chain wants the whole list — so validating first hands
/// a config-shaped disclosure to a caller with no authority to change anything.
/// Authorize, then validate.
///
/// The second assertion is the control that keeps this from passing for the
/// wrong reason: the *same* disclosing config, with the pin list left
/// byte-identical, MUST still reach validation and answer `policy_rejected`. A
/// peer that simply always answers `not_entitled` fails it.
#[tokio::test]
async fn an_unauthorized_pin_change_answers_not_entitled_before_it_answers_policy_rejected() {
    let (cs, li) = stores();
    let handler = registry(&cs, &li);
    let configure_only = || registry_cap(&["set-resolver-config", "get-resolver-config"]);

    let base = ResolverConfigData {
        resolver_chain: vec![chain_entry("local-name", 0), chain_entry("did-web", 1)],
        pinned_bindings: vec![pinned("alice", "z6MkAlice")],
        name_format_dispatch: vec![dispatch("did:web:*", &["did-web"])],
        ..Default::default()
    };
    install_config(&cs, &li, &base);

    // Both faults at once: the pin moves AND the dispatch rule goes broad.
    let both = ResolverConfigData {
        pinned_bindings: vec![pinned("alice", "z6MkAttacker")],
        name_format_dispatch: vec![dispatch("*", &["did-web"])],
        ..base.clone()
    };
    let r = handler
        .handle(&set_config_ctx_as(&both, configure_only()))
        .await
        .unwrap();
    assert_eq!(r.status, 403);
    assert_eq!(
        err_code(&r).as_deref(),
        Some("not_entitled"),
        "authorization precedes validation (R-27 clause 4) — answering \
         `policy_rejected` here would enumerate every disclosure violation in \
         the submitted config to a caller who cannot change any of them"
    );

    // Control — same disclosure, pins untouched: validation IS reached.
    let disclosure_only = ResolverConfigData {
        name_format_dispatch: vec![dispatch("*", &["did-web"])],
        ..base.clone()
    };
    let r = handler
        .handle(&set_config_ctx_as(&disclosure_only, configure_only()))
        .await
        .unwrap();
    assert_eq!(r.status, 403);
    assert_eq!(
        err_code(&r).as_deref(),
        Some("policy_rejected"),
        "a caller authorized for what it is changing still gets the full \
         violation list — the ordering gates the leak, it does not remove it"
    );
}

/// A config whose `content_hash` lies is refused `400` (V7 §1.8
/// validate-on-receipt).
///
/// The envelope layer validates the **params** entity; a nested entity inside
/// its `data` is opaque bytes to it, so this is the only place the claim is
/// checked — and our `ContentStore::put` keys on the *claimed* hash, so a lie
/// would file the bytes under one key while the location index points at
/// another, and the config just accepted would read back `404`.
#[tokio::test]
async fn a_config_whose_content_hash_lies_is_refused() {
    let (cs, li) = stores();
    let real = ResolverConfigData {
        resolver_chain: vec![chain_entry("local-name", 0)],
        ..Default::default()
    }
    .to_entity()
    .unwrap();
    let lying = Entity {
        entity_type: real.entity_type.clone(),
        data: real.data.clone(),
        content_hash: Hash::compute("x", b"not-this-config"),
    };
    let handler = registry(&cs, &li);
    let r = handler
        .handle(&policy_ctx(
            "set-resolver-config",
            set_config_request(&lying, false),
        ))
        .await
        .unwrap();
    assert_eq!(r.status, 400);
    assert_eq!(
        handler
            .handle(&no_params_ctx("get-resolver-config"))
            .await
            .unwrap()
            .status,
        404,
        "and nothing was written"
    );
}

/// **At load: surface it, never normalize it, never refuse to start `[MUST,
/// v1.17]`** — driven through the door §4.3 deliberately leaves open, a raw
/// tree-write that carries no acknowledgement.
///
/// All four halves of the rule are asserted, because three of them are
/// invisible if you only check the fourth:
/// - the resolve still **runs** (refusing to start would delete the operator
///   `MAY` — a peer that will not boot on a config the operator deliberately
///   wrote has revoked the override it was granted);
/// - the chain is **not narrowed** in memory (silent normalization makes the
///   operator's stored bytes lie);
/// - the stored entity is **not rewritten** (reading is not writing, at any
///   configuration surface — a rewrite moves the hash and republishes the
///   operator's intent as the peer's);
/// - and the condition **is** surfaced.
#[tokio::test]
async fn a_seeded_violating_config_is_surfaced_at_load_not_refused_or_normalized() {
    let (cs, li) = stores();
    let pet = LocalNameHandler::new(cs.clone(), li.clone(), PEER.into());
    pet.handle(&ctx(
        "bind",
        vec![
            (text("name"), text("seeded")),
            (text("target_peer_id"), text("z6MkSeeded")),
        ],
    ))
    .await
    .unwrap();

    // The out-of-band seed: written straight to the tree, so it bypasses
    // `set-resolver-config` and carries no acknowledgement.
    let cfg = ResolverConfigData {
        resolver_chain: vec![chain_entry("local-name", 0), chain_entry("did-web", 1)],
        name_format_dispatch: vec![dispatch("*", &["local-name", "did-web"])],
        ..Default::default()
    };
    install_config(&cs, &li, &cfg);
    let seeded_hash = cfg.to_entity().unwrap().content_hash;

    let handler = registry(&cs, &li);
    let r = handler
        .handle(&ctx("resolve", vec![(text("name"), text("seeded"))]))
        .await
        .unwrap();
    assert_eq!(
        result_field(&decode_result(&r), "status")
            .unwrap()
            .as_text(),
        Some("resolved"),
        "the peer runs on the operator's bytes — surfacing is not refusing"
    );
    assert_eq!(
        li.get(&crate::resolver_config_path(PEER)),
        Some(seeded_hash),
        "the stored config was not rewritten by the act of reading it"
    );

    let (hash, violations) = handler
        .last_config_diagnostic()
        .expect("a violating stored config MUST be surfaced at load");
    assert_eq!(hash, seeded_hash);
    assert_eq!(violations.len(), 1);
    assert!(violations[0].contains("did-web"));
}

/// The other side of the surfacing: a clean stored config leaves no
/// diagnostic. Without this row, a peer that surfaces unconditionally — a
/// permanent warning nobody can act on — would pass the row above.
#[tokio::test]
async fn a_clean_stored_config_surfaces_nothing_at_load() {
    let (cs, li) = stores();
    let cfg = ResolverConfigData {
        resolver_chain: vec![chain_entry("local-name", 0), chain_entry("did-web", 1)],
        name_format_dispatch: vec![
            dispatch("*", &["local-name"]),
            dispatch("did:web:*", &["did-web"]),
        ],
        ..Default::default()
    };
    install_config(&cs, &li, &cfg);
    let handler = registry(&cs, &li);
    handler
        .handle(&ctx("resolve", vec![(text("name"), text("nobody"))]))
        .await
        .unwrap();
    assert!(handler.last_config_diagnostic().is_none());
}

/// `REG-TTL-CEILING-REREAD-1` (§6a.9.1 `[v1.17]`), in-tree — the resolver
/// ceiling is **read at resolution**, not latched at start.
///
/// One handler, three resolutions of one bound name, with the config rewritten
/// through `set-resolver-config` between them: `hints.max_ttl` absent →
/// present → lower. A peer that caches the config at construction passes
/// resolve 1 and fails 2 and 3.
///
/// The vector was **not constructible before §4.3** — with only a raw
/// tree-write there was no wire-reachable way to rewrite the config mid-process,
/// which is why it arrives in the same packet as the operations.
#[tokio::test]
async fn the_resolver_ceiling_tracks_the_stored_config_across_rewrites() {
    let (cs, li) = stores();
    let pet = LocalNameHandler::new(cs.clone(), li.clone(), PEER.into());
    pet.handle(&ctx(
        "bind",
        vec![
            (text("name"), text("reread")),
            (text("target_peer_id"), text("z6MkReread")),
        ],
    ))
    .await
    .unwrap();
    let handler = registry(&cs, &li);

    let with_ceiling = |ms: Option<i64>| ResolverConfigData {
        resolver_chain: vec![ResolverChainEntry {
            backend_kind: "local-name".into(),
            backend_id: PEER.into(),
            priority: 0,
            accepted_trust_anchors: vec![],
            hints: ms.map(|ms| Value::Map(vec![(text("max_ttl"), entity_ecf::integer(ms))])),
        }],
        ..Default::default()
    };
    async fn ttl_now(h: &RegistryHandler) -> Option<i64> {
        let r = h
            .handle(&ctx("resolve", vec![(text("name"), text("reread"))]))
            .await
            .unwrap();
        let map = decode_result(&r);
        assert_eq!(
            result_field(&map, "status").unwrap().as_text(),
            Some("resolved"),
            "constructibility — the ceiling is unobservable if the name does not resolve"
        );
        result_field(&map, "ttl")
            .and_then(|v| v.as_integer())
            .map(|i| i64::try_from(i).unwrap())
    }

    for (ms, want) in [
        (None, None),
        (Some(60_000), Some(60_000)),
        (Some(30_000), Some(30_000)),
    ] {
        assert_eq!(
            handler
                .handle(&set_config_ctx(&with_ceiling(ms), false))
                .await
                .unwrap()
                .status,
            200
        );
        assert_eq!(
            ttl_now(&handler).await,
            want,
            "the surfaced lifetime MUST track the currently-stored config, \
             not the one this handler booted with (hints.max_ttl = {ms:?})"
        );
    }
}

/// The params type is checked at the door: `set-resolver-config` takes its own
/// request type, and a bare `resolver-config` entity is not it.
#[tokio::test]
async fn set_resolver_config_refuses_a_bare_config_entity_as_params() {
    let (cs, li) = stores();
    let cfg = ResolverConfigData {
        resolver_chain: vec![chain_entry("local-name", 0)],
        ..Default::default()
    };
    let r = registry(&cs, &li)
        .handle(&policy_ctx("set-resolver-config", cfg.to_entity().unwrap()))
        .await
        .unwrap();
    assert_eq!(r.status, 400);
    assert_eq!(err_code(&r).as_deref(), Some("invalid_params"));
}
