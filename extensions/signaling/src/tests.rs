//! Tests for the connection node.
//!
//! The §1.1 bucket pins are **pinned in advance precisely because the server
//! role is single-impl** (§1.2) — one implementation cannot disagree with
//! itself, so nothing downstream will surface a wrong answer. These tests are
//! that pin made executable. Each of the three names the pin it holds.
//!
//! What these tests **cannot** do is validate the §2.2 key derivation. That is
//! settled by three independently-written clients meeting or failing to meet at
//! this server in a live cross-impl run (`validate-peer -category signaling`),
//! not by same-side round-trips here — a same-side test passes with the wrong
//! shape too, because encoder and decoder agree.

use std::sync::Arc;

use entity_entity::Entity;
use entity_handler::{Handler, HandlerContext};

use crate::core::{CoreError, Limits, OfferOutcome, RendezvousKey, SignalingCore};
use crate::data::{advertisement_from_params, CollectRequest, CollectResult, OfferRequest};
use crate::handler::SignalingHandler;
use crate::{key, pool, PoolMember, SKEW_FANOUT};
use crate::{
    CODE_BUCKET_FULL, CODE_INVALID_PARAMS, CODE_MESSAGE_TOO_LARGE, CODE_UNKNOWN_OPERATION,
    LOBBY_DEFAULT, OP_ADVERTISE, OP_COLLECT, OP_OFFER, RENDEZVOUS_KEY_LEN,
};

const T0: i64 = 1_700_000_000_000;

/// A key built from a filler byte. The node derives nothing from key contents,
/// so tests need no real §2.2 derivation — that is the point of mode-blindness.
fn key(fill: u8) -> RendezvousKey {
    RendezvousKey::from_slice(&[fill; RENDEZVOUS_KEY_LEN]).expect("33 bytes")
}

// ---------------------------------------------------------------------------
// §1.1 pin 1 — collect is non-destructive
// ---------------------------------------------------------------------------

/// A `pair` bucket is collected by both sides and re-read on retry. A draining
/// read would make the second collect lose the peer's offer — a silent
/// handshake failure indistinguishable from the peer never having offered.
#[test]
fn pin1_collect_is_non_destructive() {
    let core = SignalingCore::new("test:1");
    core.offer(key(1), b"candidates", T0).unwrap();

    for attempt in 0..3 {
        let got = core.collect(&key(1), T0);
        assert_eq!(
            got,
            vec![b"candidates".to_vec()],
            "collect #{} must still see the offer — TTL is the only reaper",
            attempt
        );
    }
}

/// Absence and not-yet-offered are the same state to a rendezvous: a peer
/// polling ahead of its counterpart is the normal case, not a fault.
#[test]
fn collect_unknown_key_is_empty_not_an_error() {
    let core = SignalingCore::new("test:1");
    assert!(core.collect(&key(9), T0).is_empty());
}

// ---------------------------------------------------------------------------
// §1.1 pin 2 — offer appends, deduplicated by content hash
// ---------------------------------------------------------------------------

/// `lobby` and `tag` are inherently multi-party; replace would make the last
/// writer erase everyone.
#[test]
fn pin2_offer_appends_for_multiple_parties() {
    let core = SignalingCore::new("test:1");
    core.offer(key(2), b"peer-a", T0).unwrap();
    core.offer(key(2), b"peer-b", T0).unwrap();
    core.offer(key(2), b"peer-c", T0).unwrap();

    let got = core.collect(&key(2), T0);
    assert_eq!(got.len(), 3, "a key holds a set, not a single slot");
    assert!(got.contains(&b"peer-a".to_vec()));
    assert!(got.contains(&b"peer-c".to_vec()));
}

/// Dedup by content digest makes a peer's retry idempotent rather than an
/// accumulation — the property that lets a client re-offer freely after a
/// timeout, which §1.1 pin 3 requires it to be prepared to do.
#[test]
fn pin2_duplicate_offer_is_idempotent() {
    let core = SignalingCore::new("test:1");
    assert_eq!(
        core.offer(key(3), b"same", T0).unwrap(),
        OfferOutcome::Stored
    );
    assert_eq!(
        core.offer(key(3), b"same", T0 + 5).unwrap(),
        OfferOutcome::Duplicate
    );
    assert_eq!(core.collect(&key(3), T0).len(), 1);
}

// ---------------------------------------------------------------------------
// §1.1 pin 4 — collect returns deposit order, oldest first
// ---------------------------------------------------------------------------

/// **A cross-peer pin wearing the costume of an implementation detail.**
///
/// A reader scans a bucket for the first message it can act on
/// (`PROPOSAL-CONNECTIVITY-SIGNALING-AND-PUNCH` §3.2). Two impls scanning in
/// different orders therefore answer *different peers* out of one shared `lobby`
/// bucket — and both look correct in isolation, because each is internally
/// consistent. That is the §2.2 silent-never-meet shape yet again, which is why
/// the order is pinned by the spec rather than left to the container type.
///
/// Concretely: this is what stops a future `HashSet<Deposit>` "cleanup" from
/// looking like a free win. Dedup already happens on the digest, so a set is a
/// plausible refactor — and it would silently randomize the order.
#[test]
fn pin4_collect_returns_deposit_order_oldest_first() {
    let core = SignalingCore::new("test:1");
    // Offered a millisecond apart so the ordering under test is deposit order,
    // not something that happens to coincide with it.
    for (i, msg) in [b"first", b"secon", b"third", b"fourt"].iter().enumerate() {
        core.offer(key(4), msg.as_slice(), T0 + i as i64).unwrap();
    }

    assert_eq!(
        core.collect(&key(4), T0 + 10),
        vec![
            b"first".to_vec(),
            b"secon".to_vec(),
            b"third".to_vec(),
            b"fourt".to_vec(),
        ],
    );
}

/// The order survives the two things that would perturb it: a duplicate
/// re-offer must not move a message to the back, and messages aging out of the
/// front must not reorder the survivors behind them.
///
/// Both matter to a real handshake. A peer re-offers while polling (§1.1 pin 3
/// makes it prepare to), and a `lobby` bucket is continuously aging — so a
/// bucket that only holds its order when untouched holds nothing useful.
#[test]
fn pin4_order_survives_dedup_and_expiry() {
    let core = SignalingCore::new("test:1");
    // TTL is 60 s (§1.1 pin 6), so each of these expires 60 s after its offer:
    // old → T0+60s, mid → T0+80s, young → T0+100s.
    let (old, mid, young) = (T0, T0 + 20_000, T0 + 40_000);
    core.offer(key(5), b"old", old).unwrap();
    core.offer(key(5), b"mid", mid).unwrap();
    core.offer(key(5), b"young", young).unwrap();

    // A retry of the *oldest* message is a `Duplicate` and must not re-seat it
    // at the back — which is exactly what a naive remove-then-push would do.
    assert_eq!(
        core.offer(key(5), b"old", T0 + 50_000).unwrap(),
        OfferOutcome::Duplicate
    );
    assert_eq!(
        core.collect(&key(5), T0 + 50_000),
        vec![b"old".to_vec(), b"mid".to_vec(), b"young".to_vec()],
        "a deduplicated re-offer must not move the message to the back"
    );

    // `old` ages out at T0+60s; the survivors keep their relative order.
    assert_eq!(
        core.collect(&key(5), T0 + 70_000),
        vec![b"mid".to_vec(), b"young".to_vec()]
    );
    // …and then `mid` does too, at T0+80s.
    assert_eq!(core.collect(&key(5), T0 + 90_000), vec![b"young".to_vec()]);
}

// ---------------------------------------------------------------------------
// §1.1 pin 3 — TTL is advisory to peers, binding on the node
// ---------------------------------------------------------------------------

/// The node reaps on its own TTL regardless of what a peer believes.
#[test]
fn pin3_ttl_is_binding_on_the_node() {
    let core = SignalingCore::new("test:1");
    let ttl = core.limits().bucket_ttl_ms;
    core.offer(key(4), b"stale", T0).unwrap();

    assert_eq!(core.collect(&key(4), T0 + ttl - 1).len(), 1);
    assert!(
        core.collect(&key(4), T0 + ttl).is_empty(),
        "at expiry the deposit is gone whether or not the reaper has run"
    );
}

/// Correctness must not depend on the reaper having run, or a node under load
/// would serve stale rendezvous. The reaper is memory reclaim only.
#[test]
fn expiry_is_enforced_on_read_not_by_the_reaper() {
    let core = SignalingCore::new("test:1");
    let ttl = core.limits().bucket_ttl_ms;
    core.offer(key(5), b"stale", T0).unwrap();

    // Never call reap(): the read path alone must hide the expired deposit.
    assert!(core.collect(&key(5), T0 + ttl + 1).is_empty());
    assert_eq!(
        core.key_count(),
        1,
        "still resident — nothing reaped it yet"
    );

    assert_eq!(core.reap(T0 + ttl + 1), 1);
    assert_eq!(core.key_count(), 0, "reap drops the now-empty key too");
}

/// A re-offer after expiry is a fresh `Stored`, not a `Duplicate` — otherwise a
/// peer retrying past the TTL would be told "already there" about a message
/// nothing will ever return to its counterpart.
#[test]
fn reoffer_after_expiry_stores_again() {
    let core = SignalingCore::new("test:1");
    let ttl = core.limits().bucket_ttl_ms;
    core.offer(key(6), b"msg", T0).unwrap();
    assert_eq!(
        core.offer(key(6), b"msg", T0 + ttl + 1).unwrap(),
        OfferOutcome::Stored
    );
    assert_eq!(core.collect(&key(6), T0 + ttl + 1).len(), 1);
}

// ---------------------------------------------------------------------------
// Mode-blindness (§1) — one code path, four derived keys
// ---------------------------------------------------------------------------

/// The four key modes are *entirely* peer-side derivation. Four different keys
/// exercise the same code path and never see each other's deposits; the node
/// cannot tell which mode produced any of them.
#[test]
fn node_is_mode_blind_keys_are_isolated() {
    let core = SignalingCore::new("test:1");
    // Stand-ins for keys a peer would derive in pair / tag / secret / lobby mode.
    for (i, mode) in ["pair", "tag", "secret", "lobby"].iter().enumerate() {
        core.offer(key(i as u8 + 10), mode.as_bytes(), T0).unwrap();
    }
    for (i, mode) in ["pair", "tag", "secret", "lobby"].iter().enumerate() {
        assert_eq!(
            core.collect(&key(i as u8 + 10), T0),
            vec![mode.as_bytes().to_vec()],
            "each derived key is its own bucket"
        );
    }
    assert_eq!(core.key_count(), 4);
}

// ---------------------------------------------------------------------------
// Key width (§2.2.1 — the check that catches an otherwise-correct SHA-384 impl)
// ---------------------------------------------------------------------------

/// The 33-byte fixed-format check. §7 of the staging handoff calls the floating
/// format code the load-bearing defect: a SHA-384-home peer would otherwise
/// derive a 49-byte key, occupy a bucket its SHA-256 counterpart never looks in,
/// and **silently never meet** it. Rejecting the width loudly at the edge is
/// what turns that into a visible failure.
#[test]
fn wrong_width_key_is_rejected_loudly() {
    assert!(matches!(
        RendezvousKey::from_slice(&[0u8; 49]),
        Err(CoreError::InvalidKeyLength { got: 49 })
    ));
    assert!(matches!(
        RendezvousKey::from_slice(&[0u8; 32]),
        Err(CoreError::InvalidKeyLength { got: 32 })
    ));
    assert!(RendezvousKey::from_slice(&[0u8; RENDEZVOUS_KEY_LEN]).is_ok());
}

// ---------------------------------------------------------------------------
// §1.1 pin 5 — size bounds, and refuse rather than evict
// ---------------------------------------------------------------------------

/// The numbers are **8 KiB per blob, 32 blobs per bucket**, and they are pinned
/// rather than left to the operator for a cross-impl reason: *a limit the client
/// does not know is a reject boundary*. A Go client offering 64 KiB at a node
/// that stops at 4 KiB sees a rendezvous miss, not the size refusal it actually
/// got — so the value has to be one number every impl can assume, published in
/// `advertise` for the deployment that moves it.
#[test]
fn pin5_default_bounds_are_8kib_and_32() {
    let limits = Limits::default();
    assert_eq!(limits.max_message_bytes, 8192);
    assert_eq!(limits.max_messages_per_key, 32);
    // §1.1 pin 6, published in the same advertisement.
    assert_eq!(limits.bucket_ttl_ms, 60_000);

    // A §4-sized handshake (~1 KB) fits with 8× headroom — the point of the
    // number, not a coincidence worth leaving unasserted.
    let core = SignalingCore::new("test:1");
    assert_eq!(
        core.offer(key(30), &vec![0u8; 1024], T0).unwrap(),
        OfferOutcome::Stored
    );
    // And the boundary itself is inclusive: exactly 8 KiB is accepted.
    assert_eq!(
        core.offer(key(30), &vec![1u8; 8192], T0).unwrap(),
        OfferOutcome::Stored
    );
    assert!(matches!(
        core.offer(key(30), &vec![2u8; 8193], T0),
        Err(CoreError::MessageTooLarge {
            got: 8193,
            max: 8192
        })
    ));
}

/// **Refuse, never evict.** An over-size blob is not truncated and a full bucket
/// does not make room — because eviction reproduces exactly the silent
/// never-meet this surface exists to prevent: the evicted peer believes it is at
/// the key and waits out its timeout. A refusal is the opposite failure — loud,
/// attributable, and retryable — which is why every §1.1 pin lands on it.
#[test]
fn pin5_a_full_bucket_refuses_rather_than_evicting() {
    let core = SignalingCore::with_limits(
        "test:1",
        Limits {
            max_messages_per_key: 3,
            ..Limits::default()
        },
    );
    for i in 0..3u8 {
        core.offer(key(31), &[i], T0).unwrap();
    }

    assert!(matches!(
        core.offer(key(31), b"one-too-many", T0),
        Err(CoreError::BucketFull { max: 3 })
    ));

    // The incumbents are all still there — nothing was evicted to make room,
    // and the newcomer deposited nothing.
    assert_eq!(
        core.collect(&key(31), T0),
        vec![vec![0u8], vec![1u8], vec![2u8]],
        "a full bucket must refuse the newcomer, never evict an incumbent"
    );
}

/// Both bounds carry their own error code onto the wire, so a client can tell
/// "my message is too big" (fix it and retry) from "this bucket is contended"
/// (back off and retry). Collapsing them into one status would leave a peer
/// retrying an 9 KiB blob forever.
#[tokio::test]
async fn pin5_bounds_surface_as_named_codes() {
    let core = Arc::new(SignalingCore::with_limits(
        "test:1",
        Limits {
            max_message_bytes: 16,
            max_messages_per_key: 1,
            ..Limits::default()
        },
    ));
    let handler = SignalingHandler::new(core, "peer1");

    let too_big = OfferRequest {
        rendezvous_key: key(32),
        message: vec![0u8; 17],
    };
    let res = handler
        .handle(&ctx(OP_OFFER, too_big.to_entity().unwrap()))
        .await
        .unwrap();
    assert_eq!(res.status, 400, "the offerer can fix this one itself");
    assert_eq!(error_code(&res), CODE_MESSAGE_TOO_LARGE);

    let fits = |m: &[u8]| OfferRequest {
        rendezvous_key: key(32),
        message: m.to_vec(),
    };
    handler
        .handle(&ctx(OP_OFFER, fits(b"a").to_entity().unwrap()))
        .await
        .unwrap();
    let res = handler
        .handle(&ctx(OP_OFFER, fits(b"b").to_entity().unwrap()))
        .await
        .unwrap();
    assert_eq!(
        res.status, 429,
        "contention is a back-off, not a bad request"
    );
    assert_eq!(error_code(&res), CODE_BUCKET_FULL);
}

// ---------------------------------------------------------------------------
// Limits — every refusal happens before any state change
// ---------------------------------------------------------------------------

#[test]
fn oversized_message_is_refused_and_deposits_nothing() {
    let core = SignalingCore::with_limits(
        "test:1",
        Limits {
            max_message_bytes: 8,
            ..Limits::default()
        },
    );
    assert!(matches!(
        core.offer(key(7), b"far too long", T0),
        Err(CoreError::MessageTooLarge { got: 12, max: 8 })
    ));
    assert!(
        core.collect(&key(7), T0).is_empty(),
        "a refused offer must leave the bucket untouched"
    );
}

#[test]
fn bucket_and_node_capacity_are_bounded() {
    let core = SignalingCore::with_limits(
        "test:1",
        Limits {
            max_messages_per_key: 2,
            max_keys: 2,
            ..Limits::default()
        },
    );
    core.offer(key(8), b"a", T0).unwrap();
    core.offer(key(8), b"b", T0).unwrap();
    assert!(matches!(
        core.offer(key(8), b"c", T0),
        Err(CoreError::BucketFull { max: 2 })
    ));

    core.offer(key(20), b"a", T0).unwrap();
    assert!(matches!(
        core.offer(key(21), b"a", T0),
        Err(CoreError::CapacityExhausted { max: 2 })
    ));
}

/// An expired bucket must not hold capacity hostage — otherwise a node would
/// wedge at `max_keys` until the reaper happened to run.
#[test]
fn expired_bucket_frees_its_own_capacity() {
    let core = SignalingCore::with_limits(
        "test:1",
        Limits {
            max_messages_per_key: 1,
            ..Limits::default()
        },
    );
    let ttl = core.limits().bucket_ttl_ms;
    core.offer(key(22), b"old", T0).unwrap();
    assert!(core.offer(key(22), b"new", T0).is_err());
    assert_eq!(
        core.offer(key(22), b"new", T0 + ttl + 1).unwrap(),
        OfferOutcome::Stored
    );
}

// ---------------------------------------------------------------------------
// Entity codecs (the wrapped surface's wire shapes)
// ---------------------------------------------------------------------------

/// Same-side round-trip. This proves the codec is self-consistent and **nothing
/// more** — the shape is settled cross-impl, per `AGENTS.md`.
#[test]
fn offer_and_collect_params_round_trip() {
    let req = OfferRequest {
        rendezvous_key: key(33),
        message: b"opaque candidate blob".to_vec(),
    };
    let decoded = OfferRequest::from_params(&req.to_entity().unwrap().data).unwrap();
    assert_eq!(decoded, req);

    let cr = CollectRequest {
        rendezvous_key: key(34),
    };
    assert_eq!(
        CollectRequest::from_params(&cr.to_entity().unwrap().data).unwrap(),
        cr
    );

    let res = CollectResult {
        messages: vec![b"one".to_vec(), b"two".to_vec()],
    };
    assert_eq!(
        CollectResult::from_params(&res.to_entity().unwrap().data).unwrap(),
        res
    );
}

/// A key of the wrong width must fail at the codec edge too, not just in the
/// core — the wrapped surface is where a foreign client's bytes arrive.
#[test]
fn offer_params_reject_wrong_width_key() {
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (entity_ecf::text("message"), entity_ecf::bytes(vec![1, 2])),
        (
            entity_ecf::text("rendezvous_key"),
            entity_ecf::bytes(vec![0u8; 32]),
        ),
    ]));
    assert!(OfferRequest::from_params(&data).is_err());
}

#[test]
fn advertisement_round_trips_with_bare_limits_map() {
    let core = SignalingCore::new("signal.example:4040");
    let ad = core.advertise();
    let entity = crate::data::advertisement_to_entity(&ad).unwrap();
    assert_eq!(advertisement_from_params(&entity.data).unwrap(), ad);
}

/// §2.2 Finding B: `lobby` must name an actual constant, or two peers on the
/// same open node each invent a different input and never share a bucket. A
/// node that does not override it emits **no `lobby` key at all** (absent, not
/// null), and peers fall back to `LOBBY_DEFAULT`.
#[test]
fn advertisement_omits_lobby_unless_the_pool_overrides_it() {
    let core = SignalingCore::new("signal.example:4040");
    assert_eq!(core.advertise().lobby, None);
    assert_eq!(core.lobby_constant(), LOBBY_DEFAULT);

    let entity = crate::data::advertisement_to_entity(&core.advertise()).unwrap();
    let decoded: entity_ecf::Value = ciborium::from_reader(entity.data.as_slice()).unwrap();
    assert!(
        !decoded
            .into_map()
            .unwrap()
            .iter()
            .any(|(k, _)| k.as_text() == Some("lobby")),
        "the key must be absent, not present-and-null"
    );
}

#[test]
fn advertisement_carries_an_overridden_lobby_constant() {
    let core = SignalingCore::new("signal.example:4040").with_lobby("lobby:chess-club");
    let ad = core.advertise();
    assert_eq!(ad.lobby.as_deref(), Some("lobby:chess-club"));
    assert_eq!(core.lobby_constant(), "lobby:chess-club");

    let entity = crate::data::advertisement_to_entity(&ad).unwrap();
    assert_eq!(advertisement_from_params(&entity.data).unwrap(), ad);
}

/// Setting the override *to* the default is the same fact as not overriding, so
/// it must not become a second wire shape for it.
#[test]
fn explicitly_setting_the_default_lobby_is_normalized_to_absent() {
    let core = SignalingCore::new("signal.example:4040").with_lobby(LOBBY_DEFAULT);
    assert_eq!(core.advertise().lobby, None);
}

// ---------------------------------------------------------------------------
// The handler — dispatch over the core, reimplementing nothing
// ---------------------------------------------------------------------------

fn ctx(operation: &str, params: Entity) -> HandlerContext {
    let execute = Entity::new("system/execute", entity_ecf::to_ecf(&entity_ecf::text("x")))
        .expect("execute entity");
    HandlerContext::builder(execute, params)
        .operation(operation)
        .build()
}

fn empty_params() -> Entity {
    Entity::new(
        "system/signaling/empty",
        entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![])),
    )
    .expect("params entity")
}

fn error_code(result: &entity_handler::HandlerResult) -> String {
    let v: entity_ecf::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
    v.into_map()
        .unwrap()
        .iter()
        .find(|(k, _)| k.as_text() == Some("code"))
        .and_then(|(_, v)| v.as_text())
        .unwrap_or_default()
        .to_string()
}

#[tokio::test]
async fn handler_offer_then_collect_reaches_the_same_core() {
    let core = Arc::new(SignalingCore::new("test:1"));
    let handler = SignalingHandler::new(core.clone(), "peer1");

    let offer = OfferRequest {
        rendezvous_key: key(40),
        message: b"blob".to_vec(),
    };
    let res = handler
        .handle(&ctx(OP_OFFER, offer.to_entity().unwrap()))
        .await
        .unwrap();
    assert_eq!(res.status, 200);

    // The deposit is visible on the core directly — the handler added no state
    // of its own, which is the §2.1 property this test exists to hold.
    assert_eq!(core.collect(&key(40), now()), vec![b"blob".to_vec()]);

    let collect = CollectRequest {
        rendezvous_key: key(40),
    };
    let res = handler
        .handle(&ctx(OP_COLLECT, collect.to_entity().unwrap()))
        .await
        .unwrap();
    assert_eq!(res.status, 200);
    assert_eq!(
        CollectResult::from_params(&res.result.data)
            .unwrap()
            .messages,
        vec![b"blob".to_vec()]
    );
}

/// `reflect` is **not served here, by design** (§1.4, ruling 2026-07-28) — and
/// it is an ordinary unknown operation, not a distinct refusal.
///
/// The distinction is the whole ruling. A 501 would say "this verb exists and
/// this node can't do it yet," inviting a client to keep a `reflect` code path
/// warm against the day it starts answering. It never will on this surface:
/// `reflect` reports a transport-level address, which is the exact layer the
/// entity wrapper exists to abstract away, and even fully plumbed it could only
/// report the TCP/WS mapping of an already-established connection while the
/// punch needs the UDP one. So it answers the wrong question, and the honest
/// wire response is the one any unknown verb gets.
#[tokio::test]
async fn reflect_is_an_unknown_operation_on_the_wrapped_surface() {
    let handler = SignalingHandler::new(Arc::new(SignalingCore::new("test:1")), "peer1");
    let res = handler
        .handle(&ctx("reflect", empty_params()))
        .await
        .unwrap();
    assert_eq!(res.status, 400);
    assert_eq!(error_code(&res), CODE_UNKNOWN_OPERATION);
}

#[tokio::test]
async fn handler_advertise_publishes_the_cores_limits() {
    let core = Arc::new(SignalingCore::new("signal.example:4040"));
    let handler = SignalingHandler::new(core.clone(), "peer1");
    let res = handler
        .handle(&ctx(OP_ADVERTISE, empty_params()))
        .await
        .unwrap();
    assert_eq!(res.status, 200);
    assert_eq!(
        advertisement_from_params(&res.result.data).unwrap(),
        core.advertise()
    );
}

#[tokio::test]
async fn handler_rejects_malformed_params_and_unknown_operations() {
    let handler = SignalingHandler::new(Arc::new(SignalingCore::new("test:1")), "peer1");

    let res = handler
        .handle(&ctx(OP_OFFER, empty_params()))
        .await
        .unwrap();
    assert_eq!(res.status, 400);
    assert_eq!(error_code(&res), CODE_INVALID_PARAMS);

    let res = handler.handle(&ctx("punch", empty_params())).await.unwrap();
    assert_eq!(res.status, 400);
    assert_eq!(error_code(&res), CODE_UNKNOWN_OPERATION);
}

/// The declared surface is exactly the **three** core verbs (§1, §1.4) and the
/// handler declares an **empty** internal scope: it writes no entities and
/// dispatches nowhere, so it should not hold the default wildcard grant. That is
/// what keeps §0's "introduces, never carries" auditable rather than asserted.
///
/// `reflect`'s absence belongs in *this* assertion specifically, because this
/// list is what `bootstrap_handler` writes into the interface entity — it is how
/// a peer learns what the node serves. Advertising a verb that answers with an
/// error would read to the caller as a broken node rather than a wrong surface.
#[test]
fn handler_declares_three_verbs_and_needs_no_authority() {
    let handler = SignalingHandler::new(Arc::new(SignalingCore::new("test:1")), "peer1");
    assert_eq!(handler.operations(), &["offer", "collect", "advertise"]);
    assert_eq!(handler.pattern(), "/peer1/system/signaling");
    assert_eq!(handler.internal_scope(), Some(Vec::new()));
}

// ---------------------------------------------------------------------------
// §2.2 key derivation — the client-side pin
// ---------------------------------------------------------------------------

/// §2.2.1's stage bisect, asserted against the spec's own published bytes.
///
/// These are the two stages §2.2.1 prints in full; the final key digest is
/// **deliberately not published** ("which bytes are correct is settled by the
/// impls meeting or failing to meet in a live cross-impl run, not by one
/// author's oracle"), so this asserts exactly what exists and no more. Two impls
/// that disagree compare these lines and learn immediately whether they differ
/// on the concatenation or on the framing.
#[test]
fn stage_bisect_matches_the_published_bytes() {
    let payload = key::rendezvous_payload(key::MODE_TAG, b"chess");
    assert_eq!(
        hex(&payload),
        "656e746974793a7264763a76311f7461671f6368657373",
        "payload = \"entity:rdv:v1\" 1F \"tag\" 1F \"chess\""
    );

    // cbor bstr(payload): 23 bytes → minimal-length head 0x57.
    let cbor = entity_ecf::to_ecf(&entity_ecf::bytes(payload.clone()));
    assert_eq!(cbor[0], 0x57, "minimal-length bstr head for 23 bytes");
    assert_eq!(&cbor[1..], &payload[..]);
}

/// Every key is 33 bytes with a leading `0x00`. §2.2.1 calls this "the one that
/// catches a real bug in an otherwise-correct implementation" — a SHA-384-home
/// impl passes every other differential property and still never meets anyone.
#[test]
fn every_key_is_33_bytes_at_the_sha256_floor() {
    for k in [
        key::pair_key("alice", "bob"),
        key::tag_key("chess"),
        key::secret_key("correct-horse-battery-staple"),
        key::lobby_key(LOBBY_DEFAULT),
    ] {
        assert_eq!(k.as_bytes().len(), 33);
        assert_eq!(k.as_bytes()[0], 0x00, "format code is the SHA-256 floor");
    }
}

/// Differential property 1 — order independence. A missing or non-byte-wise
/// sort means each peer derives its own key and neither ever sees the other.
#[test]
fn pair_is_order_independent() {
    assert_eq!(key::pair_key("alice", "bob"), key::pair_key("bob", "alice"));
}

/// Differential property 2 — pair disambiguation. Bare concatenation makes
/// `sorted("ab","c")` and `sorted("a","bc")` both yield `abc`, so two
/// *different* pairs would collide into one bucket.
#[test]
fn pair_separator_disambiguates_different_pairs() {
    assert_ne!(key::pair_key("ab", "c"), key::pair_key("a", "bc"));
}

/// Differential property 3 — case sensitivity. A failure means the impl
/// case-folds.
#[test]
fn tags_are_case_sensitive() {
    assert_ne!(key::tag_key("chess"), key::tag_key("Chess"));
}

/// Differential property 4 — no Unicode normalization. §2.2.1 names this "the
/// likeliest accidental import — many string libs do it by default." NFC vs NFD
/// "café" are different byte sequences and MUST stay different keys: the core's
/// byte-preservation discipline applied to a string two peers each supply
/// independently.
#[test]
fn no_unicode_normalization() {
    let nfc = "caf\u{00E9}"; // é as one code point
    let nfd = "cafe\u{0301}"; // e + combining acute
    assert_ne!(nfc.as_bytes(), nfd.as_bytes(), "test inputs must differ");
    assert_ne!(key::tag_key(nfc), key::tag_key(nfd));
}

/// Differential property 5 — mode separation. A failure means the mode tag is
/// missing from the payload, and a public `tag` would collide with a `secret`
/// of the same string — turning a discovery convenience into a disclosure.
#[test]
fn modes_are_separated() {
    assert_ne!(key::tag_key("x"), key::secret_key("x"));
    assert_ne!(key::tag_key("x"), key::lobby_key("x"));
    assert_ne!(key::secret_key("x"), key::lobby_key("x"));
}

/// The node stores under whatever the client derived, and `pair` from either
/// side reaches the same bucket. This is the whole mechanism in one test.
#[test]
fn two_peers_meet_at_a_pair_key() {
    let core = SignalingCore::new("test:1");
    // Alice offers under her ordering; Bob collects under his.
    core.offer(key::pair_key("alice", "bob"), b"alice-candidates", T0)
        .unwrap();
    let got = core.collect(&key::pair_key("bob", "alice"), T0);
    assert_eq!(got, vec![b"alice-candidates".to_vec()]);
}

// ---------------------------------------------------------------------------
// §3.1 pool selection — the second silent-never-meet
// ---------------------------------------------------------------------------

/// Three interchangeable members in **one tier** — the ordinary pool shape.
/// `priority` partitions before the hash runs (§3.1.1), so a pool whose members
/// sat at three different tiers would exercise the partition step and never the
/// hash. Tiering gets its own tests below.
fn test_pool() -> Vec<PoolMember> {
    vec![
        PoolMember::new("https://sig-a.example", 10),
        PoolMember::new("https://sig-b.example", 10),
        PoolMember::new("https://sig-c.example", 10),
    ]
}

/// The MUST: both peers independently pick the same member for a shared key.
#[test]
fn both_peers_converge_on_one_member() {
    let pool = test_pool();
    let alice_view = key::pair_key("alice", "bob");
    let bob_view = key::pair_key("bob", "alice");
    assert_eq!(
        pool::select(&alice_view, &pool),
        pool::select(&bob_view, &pool)
    );
}

/// Selection within a tier must NOT collapse to one member — that is the trap
/// §3.1 names, and an impl that "works" by always picking the first member would
/// pass a naive convergence test while being wrong. Across many keys the tier
/// must actually spread, or it is not sharding at all.
#[test]
fn selection_spreads_across_the_tier() {
    let pool = test_pool();
    let mut seen = std::collections::BTreeSet::new();
    for i in 0..64 {
        let k = key::tag_key(&format!("room-{}", i));
        seen.insert(pool::select(&k, &pool).unwrap().endpoint.clone());
    }
    assert_eq!(
        seen.len(),
        3,
        "every member should own part of the key space; got {:?}",
        seen
    );
}

/// **`priority` partitions; it does not weight** (§3.1.1). The lower tier wins
/// outright for *every* key — not more often, but always.
///
/// The distinction is the whole ruling. "Weight the hash" was the alternative
/// and it was withdrawn because a weighting function is itself unpinned bytes:
/// two impls would each write a defensible one and split every pair, stacking a
/// second silent-never-meet on the first. A partition has nothing left to
/// disagree about.
#[test]
fn priority_partitions_before_the_hash_runs() {
    let tiered = vec![
        PoolMember::new("https://primary.example", 10),
        PoolMember::new("https://backup-a.example", 20),
        PoolMember::new("https://backup-b.example", 20),
    ];

    for i in 0..64 {
        let k = key::tag_key(&format!("room-{}", i));
        assert_eq!(
            pool::select(&k, &tiered).unwrap().endpoint,
            "https://primary.example",
            "a lone tier-10 member takes every key; a weighted hash would leak \
             some of them to tier 20"
        );
    }

    // And the skew fallback must not become a back door into the higher tier:
    // one member in the winning tier means one choice, however large the fanout.
    let k = key::tag_key("room-0");
    assert_eq!(pool::select_top(&k, &tiered, SKEW_FANOUT).len(), 1);
}

/// It is the lowest tier **present**, not a fixed tier number — so withdrawing
/// every tier-10 member fails the pool over to tier 20 rather than selecting
/// nothing. That is what makes tiering usable for failover instead of only for
/// preference, and it is the case an impl reading "lowest priority" as "priority
/// 0" would get wrong.
#[test]
fn the_winning_tier_is_the_lowest_one_present() {
    let backups_only = vec![
        PoolMember::new("https://backup-a.example", 20),
        PoolMember::new("https://backup-b.example", 20),
        PoolMember::new("https://last-resort.example", 30),
    ];

    let mut seen = std::collections::BTreeSet::new();
    for i in 0..64 {
        let k = key::tag_key(&format!("room-{}", i));
        seen.insert(pool::select(&k, &backups_only).unwrap().endpoint.clone());
    }
    assert_eq!(
        seen,
        ["https://backup-a.example", "https://backup-b.example"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        "tier 20 is the lowest present and shards between its two members; \
         tier 30 stays unused"
    );
}

/// **Highest weight wins** — the direction, asserted against the construction
/// rather than restated.
///
/// Worth its own test because "argmax" is one character from "argmin" and both
/// converge perfectly well *within* an impl. A Rust node picking the maximum and
/// a Go client picking the minimum split every pair, and neither's own test
/// suite notices. This is the assertion that would catch it.
#[test]
fn the_highest_weight_wins_and_ties_break_to_the_lower_endpoint() {
    use sha2::{Digest, Sha256};

    let pool = test_pool();
    let k = key::tag_key("room-weight-direction");

    // Recompute §3.1.1's construction independently of `pool.rs`.
    let expected = pool
        .iter()
        .max_by(|a, b| {
            let wa: [u8; 32] = Sha256::new()
                .chain_update(k.as_bytes())
                .chain_update(a.endpoint.as_bytes())
                .finalize()
                .into();
            let wb: [u8; 32] = Sha256::new()
                .chain_update(k.as_bytes())
                .chain_update(b.endpoint.as_bytes())
                .finalize()
                .into();
            // Highest weight; a tie goes to the *lower* endpoint, so invert the
            // endpoint comparison under `max_by`.
            wa.cmp(&wb).then_with(|| b.endpoint.cmp(&a.endpoint))
        })
        .unwrap();

    assert_eq!(pool::select(&k, &pool), Some(expected));

    // The operand order is half the pin: k ‖ endpoint, not endpoint ‖ k. The two
    // digests differ, so an impl that concatenated the other way would select a
    // different member for this key.
    let forward: [u8; 32] = Sha256::new()
        .chain_update(k.as_bytes())
        .chain_update(b"https://sig-a.example")
        .finalize()
        .into();
    let reversed: [u8; 32] = Sha256::new()
        .chain_update(b"https://sig-a.example")
        .chain_update(k.as_bytes())
        .finalize()
        .into();
    assert_ne!(forward, reversed);
}

/// Selection is by endpoint identity, not list order — a reordered
/// advertisement must not move any key.
#[test]
fn selection_is_stable_under_reordering() {
    let pool = test_pool();
    let mut shuffled = pool.clone();
    shuffled.reverse();
    for i in 0..32 {
        let k = key::tag_key(&format!("room-{}", i));
        assert_eq!(pool::select(&k, &pool), pool::select(&k, &shuffled));
    }
}

/// §3.1's stale-pool-skew SHOULD: with `top-2`, two peers whose pools differ by
/// a single member still share a choice, so the handshake survives an
/// advertisement that is one scaling event out of date.
#[test]
fn top_2_covers_a_single_member_pool_delta() {
    let fresh = test_pool();
    let mut stale = fresh.clone();
    stale.pop(); // the stale peer has not seen sig-c yet

    for i in 0..64 {
        let k = key::tag_key(&format!("room-{}", i));
        let a: Vec<_> = pool::select_top(&k, &fresh, SKEW_FANOUT)
            .iter()
            .map(|m| &m.endpoint)
            .cloned()
            .collect();
        let b: Vec<_> = pool::select_top(&k, &stale, SKEW_FANOUT)
            .iter()
            .map(|m| &m.endpoint)
            .cloned()
            .collect();
        assert!(
            a.iter().any(|e| b.contains(e)),
            "top-{} sets must intersect for key {}: {:?} vs {:?}",
            SKEW_FANOUT,
            i,
            a,
            b
        );
    }
}

/// `select_top(.., 1)` and `select` share one total order — otherwise the skew
/// fallback's first choice would disagree with the primary selection.
#[test]
fn select_and_select_top_agree() {
    let pool = test_pool();
    for i in 0..32 {
        let k = key::tag_key(&format!("room-{}", i));
        assert_eq!(
            pool::select_top(&k, &pool, 1).first().copied(),
            pool::select(&k, &pool)
        );
    }
}

/// An empty pool is `None`, not a default — a deployment advertising no
/// signaling service offers no rendezvous, and the caller must say so.
#[test]
fn empty_pool_selects_nothing() {
    assert!(pool::select(&key::tag_key("x"), &[]).is_none());
}

// ---------------------------------------------------------------------------
// Client ↔ handler ↔ core — the Stage-1 loop end to end
// ---------------------------------------------------------------------------

/// Routes an EXECUTE straight into the handler, standing in for the cross-peer
/// dispatch chain. What it deliberately does **not** model is the capability
/// check and the network — this exercises the verb path, not admission. The
/// admission story is the dispatcher's, and it is the same one every handler
/// gets (see `handler.rs`).
struct DirectDispatcher(SignalingHandler);

#[async_trait::async_trait]
impl entity_handler::Dispatcher for DirectDispatcher {
    async fn execute(
        &self,
        _handler: &str,
        operation: &str,
        params: Entity,
        _opts: entity_handler::ExecuteOptions,
    ) -> Result<entity_handler::HandlerResult, entity_handler::HandlerError> {
        self.0.handle(&ctx(operation, params)).await
    }
}

/// The whole Stage-1 mechanism in one test: two peers derive the same `pair`
/// key from opposite orderings, one offers, the other collects, and neither
/// ever told the node which mode it was using.
#[tokio::test]
async fn two_peers_rendezvous_through_the_client() {
    let core = Arc::new(SignalingCore::new("test:1"));
    let dispatcher = DirectDispatcher(SignalingHandler::new(core.clone(), "node1"));

    let alice = crate::SignalingClient::new(&dispatcher, "node1");
    let bob = crate::SignalingClient::new(&dispatcher, "node1");

    alice
        .offer(key::pair_key("alice", "bob"), b"alice-candidates")
        .await
        .unwrap();

    // Bob derives from his own ordering and finds her.
    let got = bob.collect(&key::pair_key("bob", "alice")).await.unwrap();
    assert_eq!(got, vec![b"alice-candidates".to_vec()]);

    // Bob answers; both now see both offers — collect removed nothing.
    bob.offer(key::pair_key("bob", "alice"), b"bob-candidates")
        .await
        .unwrap();
    let alice_view = alice.collect(&key::pair_key("alice", "bob")).await.unwrap();
    assert_eq!(alice_view.len(), 2);
    assert!(alice_view.contains(&b"bob-candidates".to_vec()));
}

/// A re-offer after a timeout is idempotent all the way through the client.
#[tokio::test]
async fn client_retry_is_idempotent() {
    let core = Arc::new(SignalingCore::new("test:1"));
    let dispatcher = DirectDispatcher(SignalingHandler::new(core.clone(), "node1"));
    let client = crate::SignalingClient::new(&dispatcher, "node1");
    let k = key::tag_key("chess");

    for _ in 0..3 {
        client.offer(k, b"same-candidates").await.unwrap();
    }
    assert_eq!(client.collect(&k).await.unwrap().len(), 1);
}

/// **The client has no `reflect` method** (§1.4). This is a compile-time fact,
/// so what is testable is the shape of the hole: a caller reaching for it by
/// hand gets `Refused { status: 400 }`, the ordinary unknown-operation answer.
///
/// Worth an executable assertion rather than a comment, because the deletion is
/// the kind of change a future contributor "restores" while wiring up the
/// unwrapped surface — at which point `reflect` would exist on *both* surfaces,
/// answering the TCP/WS mapping on one and the UDP mapping on the other. Two
/// answers to one verb is the §2.1 divergence, arrived at by helpfulness.
#[tokio::test]
async fn the_client_offers_no_reflect_and_a_hand_rolled_one_is_unknown() {
    let core = Arc::new(SignalingCore::new("test:1"));
    let dispatcher = DirectDispatcher(SignalingHandler::new(core, "node1"));

    let res = <DirectDispatcher as entity_handler::Dispatcher>::execute(
        &dispatcher,
        "entity://node1/system/signaling",
        "reflect",
        empty_params(),
        entity_handler::ExecuteOptions::default(),
    )
    .await
    .unwrap();

    assert_eq!(res.status, 400);
    assert_eq!(error_code(&res), CODE_UNKNOWN_OPERATION);
}

/// The client reads back the node's published limits and lobby constant — the
/// facts a peer needs before deriving a `lobby` key or sizing its retries.
#[tokio::test]
async fn client_reads_the_advertisement() {
    let core = Arc::new(SignalingCore::new("signal.example:4050").with_lobby("lobby:chess-club"));
    let dispatcher = DirectDispatcher(SignalingHandler::new(core.clone(), "node1"));
    let client = crate::SignalingClient::new(&dispatcher, "node1");

    let ad = client.advertise().await.unwrap();
    assert_eq!(ad.endpoint, "signal.example:4050");
    assert_eq!(ad.lobby.as_deref(), Some("lobby:chess-club"));
    assert_eq!(ad.limits.bucket_ttl_ms, core.limits().bucket_ttl_ms);

    // And the constant it publishes is the one a peer must derive with — using
    // LOBBY_DEFAULT here would land in a bucket nobody on this pool uses.
    assert_ne!(
        key::lobby_key(ad.lobby.as_deref().unwrap()),
        key::lobby_key(LOBBY_DEFAULT)
    );
}

// ---------------------------------------------------------------------------
// §3 coordination messages — what actually rides through the node
// ---------------------------------------------------------------------------

use crate::coordination::{
    self, punch_delay, Candidate, CollectedMessage, ConnectRequest, ConnectResponse, Nonce,
    PunchSync, CANDIDATE_HOST, CANDIDATE_RELAY, CANDIDATE_SRFLX, PUNCH_DELAY_FLOOR_MS,
    SUBSTRATE_TCP,
};

fn candidates_for(who: &str) -> Vec<Candidate> {
    vec![
        Candidate::new(
            CANDIDATE_HOST,
            SUBSTRATE_TCP,
            format!("192.168.1.5:{}", who.len()),
            1,
        ),
        Candidate::new(CANDIDATE_SRFLX, SUBSTRATE_TCP, "203.0.113.7:51820", 2),
    ]
}

#[test]
fn coordination_messages_round_trip() {
    let nonce = Nonce(vec![7u8; 16]);
    let req = ConnectRequest {
        initiator: "alice".into(),
        candidates: candidates_for("alice"),
        nonce: nonce.clone(),
    };
    assert_eq!(
        ConnectRequest::from_entity_bytes(&req.to_entity().unwrap().data).unwrap(),
        req
    );

    let resp = ConnectResponse {
        responder: "bob".into(),
        candidates: candidates_for("bob"),
        nonce: nonce.clone(),
    };
    assert_eq!(
        ConnectResponse::from_entity_bytes(&resp.to_entity().unwrap().data).unwrap(),
        resp
    );

    // A *delay*, not an instant (§4.1) — 250 ms from receipt, not a moment in
    // 2023. The old vector here was `1_700_000_000_500`, and that it round-tripped
    // is exactly the point: a same-side test cannot tell the two apart.
    let sync = PunchSync {
        nonce,
        fire_at: 250,
    };
    assert_eq!(
        PunchSync::from_entity_bytes(&sync.to_entity().unwrap().data).unwrap(),
        sync
    );
}

// ---------------------------------------------------------------------------
// §4.1 `fire_at` — the clock domain and encoding (pinned 2026-07-28, MUST;
// §9 conformance MUST #5)
//
// This block exists because §4.1 says the failure it prevents "passes every
// same-host test": both peers read the same clock, so a wall-clock encoding
// round-trips perfectly and connects perfectly — until the two peers are on
// different machines, where the clock skew is silently added to a window
// measured in milliseconds. Nothing above catches it, so these test the
// *representation* rather than the behavior.
// ---------------------------------------------------------------------------

/// `fire_at` is a CBOR **uint** (major type 0). Asserted on the bytes, not
/// through the decoder, because the decoder agrees with whatever the encoder
/// wrote — the same-side blindness the whole §2.2/§4.1 family of pins is about.
///
/// This is the check that fails the moment someone widens the field back to a
/// signed type to hold "the agreed instant".
#[test]
fn fire_at_encodes_as_a_cbor_uint() {
    let data = PunchSync {
        nonce: Nonce(vec![3u8; 16]),
        fire_at: 250,
    }
    .to_entity()
    .unwrap()
    .data;

    assert_eq!(data[0], 0xa2, "expected a 2-entry map");

    // ECF sorts map keys length-first (RFC 8949 §4.2.1), so `nonce` precedes
    // `fire_at` — located rather than offset-indexed so the assertion survives a
    // nonce of a different length.
    let key = [&[0x67u8][..], b"fire_at"].concat();
    let at = data
        .windows(key.len())
        .position(|w| w == key)
        .expect("fire_at key present");
    let value = &data[at + key.len()..];

    // 0x18 = major 0 (unsigned), 1-byte argument. Major 1 (negative) would be
    // 0x38 here, which is what a peer encoding a signed delta emits; a signed
    // encoder handed a *positive* 250 still emits 0x18, so the
    // negative-rejection test below covers the half this one cannot.
    assert_eq!(value[0], 0x18, "fire_at must be a CBOR uint (major 0)");
    assert_eq!(value[1], 250);
}

/// A negative `fire_at` is refused at decode, not clamped.
///
/// The realistic source is not malice but a peer computing `target - now` with a
/// clock that disagrees, or subtracting in the wrong direction — both produce a
/// delay that has already elapsed. §4.1's floor (`d ≥ rtt/2`) exists to stop
/// that window from having passed on arrival; a negative value is the degenerate
/// case, and there is no reading of it that is safe to act on.
#[test]
fn a_negative_fire_at_is_refused_not_clamped() {
    let hostile = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (entity_ecf::text("fire_at"), entity_ecf::integer(-250)),
        (
            entity_ecf::text("nonce"),
            entity_ecf::Value::Bytes(vec![3u8; 16]),
        ),
    ]));
    // Named in the assertion so the test cannot pass because some *other* field
    // failed to decode — the failure has to be about `fire_at`.
    match PunchSync::from_entity_bytes(&hostile) {
        Err(crate::SignalingError::Decode(m)) => assert!(m.contains("fire_at"), "wrong field: {m}"),
        other => panic!("a negative fire_at must be refused, got {other:?}"),
    }
}

/// The §4.1 MUST: `d ≥ rtt/2`, the one-way carrier latency.
///
/// Below it, B's fire time has already elapsed when the sync lands and the two
/// sides never overlap — the punch fails while every individual step reports
/// success. Held across the whole range rather than at the default, because the
/// `d` value is an explicitly local tunable (§4.1, §9): the property has to
/// survive someone changing the floor, which is sanctioned, without changing the
/// derivation, which is not.
#[test]
fn punch_delay_never_falls_below_one_way_carrier_latency() {
    for rtt in [0u64, 1, 60, 250, 251, 500, 4_000, 60_000] {
        let d = punch_delay(rtt);
        assert!(d >= rtt / 2, "rtt {rtt}: d {d} < one-way {}", rtt / 2);
        assert!(
            d >= rtt,
            "rtt {rtt}: d {d} — max(rtt, floor) implies d >= rtt"
        );
        assert!(
            d >= PUNCH_DELAY_FLOOR_MS,
            "rtt {rtt}: d {d} below the floor"
        );
    }
}

/// The floor governs a fast carrier; the RTT governs a slow one. Two peers on a
/// LAN-fast carrier both land on the floor, which is what keeps `d` from
/// collapsing toward zero and leaving no room for the sync to arrive.
#[test]
fn punch_delay_is_the_floor_when_the_carrier_is_fast() {
    assert_eq!(punch_delay(0), PUNCH_DELAY_FLOOR_MS);
    assert_eq!(punch_delay(PUNCH_DELAY_FLOOR_MS - 1), PUNCH_DELAY_FLOOR_MS);
    assert_eq!(
        punch_delay(PUNCH_DELAY_FLOOR_MS + 1),
        PUNCH_DELAY_FLOOR_MS + 1
    );
    assert_eq!(punch_delay(4_000), 4_000);
}

/// The blob carries the type, so a mixed bucket is dispatchable. Without this a
/// reader has no way to tell a request from a response — the two differ only in
/// one field name.
#[test]
fn blob_round_trip_preserves_the_message_type() {
    let req = ConnectRequest {
        initiator: "alice".into(),
        candidates: candidates_for("alice"),
        nonce: Nonce(vec![1u8; 16]),
    };
    let blob = coordination::to_blob(&req.to_entity().unwrap());
    assert!(matches!(
        coordination::classify_blob(&blob),
        CollectedMessage::Request(r) if r.initiator == "alice"
    ));
}

/// A bucket may hold anything — other pairs' traffic, or a message type from a
/// newer impl. MUST-ignore: skip it, never fail the poll.
#[test]
fn unrecognized_blobs_classify_as_unknown_not_an_error() {
    assert_eq!(
        coordination::classify_blob(b"not an entity at all"),
        CollectedMessage::Unknown
    );

    let alien = Entity::new(
        "system/nat/some-future-message",
        entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![])),
    )
    .unwrap();
    assert_eq!(
        coordination::classify_blob(&coordination::to_blob(&alien)),
        CollectedMessage::Unknown
    );
}

/// §4's dial plan: `host` → `srflx` → `relay`, then priority. The order *is* the
/// plan ("first pair that completes a connectivity check wins"), and it must be
/// total — two peers ordering differently cross at different candidates and
/// waste attempts.
#[test]
fn candidates_order_host_then_srflx_then_relay() {
    let unordered = vec![
        Candidate::new(CANDIDATE_RELAY, SUBSTRATE_TCP, "relay.example:3478", 1),
        Candidate::new(CANDIDATE_SRFLX, SUBSTRATE_TCP, "203.0.113.7:51820", 5),
        Candidate::new(CANDIDATE_HOST, SUBSTRATE_TCP, "192.168.1.5:4040", 9),
        Candidate::new(CANDIDATE_SRFLX, SUBSTRATE_TCP, "203.0.113.7:51821", 2),
    ];
    let ordered = coordination::order_for_dialing(&unordered);
    let kinds: Vec<&str> = ordered.iter().map(|c| c.candidate_type.as_str()).collect();
    assert_eq!(
        kinds,
        vec![
            CANDIDATE_HOST,
            CANDIDATE_SRFLX,
            CANDIDATE_SRFLX,
            CANDIDATE_RELAY
        ]
    );
    // Within srflx, lower priority first.
    assert_eq!(ordered[1].priority, 2);
}

/// An unknown candidate class sorts last rather than being dropped — a peer that
/// learns a new class from a newer impl should still try what it understands.
#[test]
fn unknown_candidate_class_sorts_last_and_survives() {
    let mixed = vec![
        Candidate::new("quantum-tunnel", SUBSTRATE_TCP, "??", 0),
        Candidate::new(CANDIDATE_HOST, SUBSTRATE_TCP, "192.168.1.5:4040", 9),
    ];
    let ordered = coordination::order_for_dialing(&mixed);
    assert_eq!(ordered.len(), 2, "nothing is dropped");
    assert_eq!(ordered[0].candidate_type, CANDIDATE_HOST);
    assert_eq!(ordered[1].candidate_type, "quantum-tunnel");
}

/// The multi-party filter, which is where a naive impl breaks. In `lobby`/`tag`
/// the bucket is shared and `collect` is non-destructive, so a poll returns:
/// your own offer, the answer you want, and strangers' traffic. Both filters —
/// nonce echo and not-my-peer-id — are load-bearing.
#[test]
fn find_response_ignores_own_offers_and_strangers() {
    let mine = Nonce(vec![1u8; 16]);
    let theirs = Nonce(vec![2u8; 16]);

    let bucket = vec![
        // My own request, which I re-read every poll.
        CollectedMessage::Request(ConnectRequest {
            initiator: "alice".into(),
            candidates: vec![],
            nonce: mine.clone(),
        }),
        // A stranger's exchange in the same lobby.
        CollectedMessage::Response(ConnectResponse {
            responder: "carol".into(),
            candidates: vec![],
            nonce: theirs,
        }),
        // Something from the future.
        CollectedMessage::Unknown,
        // The one I actually want.
        CollectedMessage::Response(ConnectResponse {
            responder: "bob".into(),
            candidates: candidates_for("bob"),
            nonce: mine.clone(),
        }),
    ];

    let found = coordination::find_response(&bucket, &mine, "alice").expect("bob's answer");
    assert_eq!(found.responder, "bob");
}

/// A peer must not answer its own request — it would "succeed" at meeting
/// itself, which is confusing to debug and trivially preventable.
#[test]
fn find_request_skips_my_own() {
    let bucket = vec![
        CollectedMessage::Request(ConnectRequest {
            initiator: "alice".into(),
            candidates: vec![],
            nonce: Nonce(vec![1u8; 16]),
        }),
        CollectedMessage::Request(ConnectRequest {
            initiator: "bob".into(),
            candidates: candidates_for("bob"),
            nonce: Nonce(vec![2u8; 16]),
        }),
    ];
    assert_eq!(
        coordination::find_request(&bucket, "alice")
            .unwrap()
            .initiator,
        "bob"
    );
    assert!(coordination::find_request(&[], "alice").is_none());
}

/// A response carrying someone else's nonce is not mine, even from the right
/// peer — two concurrent exchanges between the same pair must not cross.
#[test]
fn find_response_requires_the_nonce_echo() {
    let bucket = vec![CollectedMessage::Response(ConnectResponse {
        responder: "bob".into(),
        candidates: vec![],
        nonce: Nonce(vec![9u8; 16]),
    })];
    assert!(coordination::find_response(&bucket, &Nonce(vec![1u8; 16]), "alice").is_none());
}

/// The full §4 step-2 exchange through the real client and handler: Alice
/// initiates, Bob finds her request and responds, Alice picks his answer out of
/// the bucket by nonce. The node moved four opaque blobs and understood none.
#[tokio::test]
async fn candidate_exchange_completes_through_the_carrier() {
    let core = Arc::new(SignalingCore::new("test:1"));
    let dispatcher = DirectDispatcher(SignalingHandler::new(core.clone(), "node1"));
    let alice = crate::SignalingClient::new(&dispatcher, "node1");
    let bob = crate::SignalingClient::new(&dispatcher, "node1");
    let k = key::pair_key("alice", "bob");

    let nonce = alice
        .initiate(k, "alice", candidates_for("alice"))
        .await
        .unwrap();

    let bob_sees = bob.collect_messages(&k).await.unwrap();
    let request = coordination::find_request(&bob_sees, "bob").expect("bob finds alice's request");
    assert_eq!(request.initiator, "alice");
    bob.respond(k, "bob", &request, candidates_for("bob"))
        .await
        .unwrap();

    let alice_sees = alice.collect_messages(&k).await.unwrap();
    let response = coordination::find_response(&alice_sees, &nonce, "alice")
        .expect("alice finds bob's answer");
    assert_eq!(response.responder, "bob");
    assert_eq!(response.candidates, candidates_for("bob"));

    // The node holds one bucket with both messages and decoded neither.
    assert_eq!(core.key_count(), 1);
    assert_eq!(core.collect(&k, now()).len(), 2);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn now() -> i64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
