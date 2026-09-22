//! ⛔ **`CORE-PREADMISSION-REFUSAL-1` — a refused frame is ANSWERED, not
//! dropped and not bare-closed** (`ENTITY-CORE-PROTOCOL` §4.11, `0.8.2.25`),
//! **over a socket**.
//!
//! # What §4.11 is, and why it is one section rather than five
//!
//! A **pre-admission refusal** is the refusal of an inbound frame *before it
//! becomes an admitted request*. §4.9(c)'s deliver-or-signal rule is scoped to
//! *"every request the peer admits"* and therefore reaches none of them, which
//! is why the obligation is stated separately:
//!
//! > A peer that refuses a frame pre-admission **MUST** put a coded
//! > EXECUTE_RESPONSE on the wire — correlated by `request_id` where the id is
//! > available, otherwise a **best-effort coded frame** carrying no correlation.
//! > **Whether the peer closes afterwards is its own choice.**
//!
//! The class had **five homes at four strengths** before `0.8.2.25` — §4.6
//! forbidding the bare close, §5.2a forbidding the drop *and* the close,
//! §4.10(a) permitting the close, §3.3 **requiring** it with no coded frame at
//! all, and the framing arm stated nowhere. Three implementations produced three
//! different caller-observable answers to one input, and **ours was the silent
//! one**: `connection.rs` logged a warning and `continue`d, so a malformed frame
//! got no response and no close and the caller blocked to its own §6.11(c)
//! deadline. §4.11 makes the drop and the bare close **two distinct
//! non-conformances**, and names the drop the weaker of the two precisely
//! because nothing surfaces it.
//!
//! # ⭐ Why every row here crosses a socket
//!
//! Because there is nothing else to test. Every arm is a property of the
//! **frame-read loop** — what the peer does with bytes that never become a
//! request — and no in-process `HandlerContext` exists at the point where it
//! happens. An in-tree row here is not a weaker vector, it is not a vector at
//! all. That is also why arm (c) and arm (a)'s truncated form are driven
//! **pre-handshake**: a forged length prefix cannot be sent through any endpoint
//! API, so the rows that need one write raw bytes at a `memory_transport_pair`
//! as the first thing the connection ever sees.
//!
//! # The four dispositions, and why the split is where it is
//!
//! | arm | input | answer | connection |
//! |---|---|---|---|
//! | (a) framing | a WHOLE frame whose payload is not an envelope | `400 invalid_request` | **survives** |
//! | (a') truncated | a length prefix whose payload never arrives | `400 invalid_request` | closes |
//! | (b) root type | a well-formed envelope rooted at a third type | `400 invalid_request` | **survives** |
//! | (c) oversize | a length prefix past `DEFAULT_MAX_FRAME_SIZE` | `413 payload_too_large` | closes |
//!
//! **The close is not a style choice and it is not §4.11's `[MUST]` either — it
//! tracks whether the STREAM is still synchronized.** (a) and (b) read a whole
//! frame, so the next read lands on a real boundary and there is nothing to
//! resynchronize by closing; (a') and (c) consumed a prefix whose payload was
//! never taken off the wire, so the next read would land mid-frame. Getting this
//! backwards in either direction is a defect: close on (a)/(b) and you spend
//! every admitted in-flight request on the multiplexed connection (arm (f));
//! continue on (a')/(c) and the peer reinterprets the tail of one frame as the
//! head of the next.
//!
//! # ⚠ The code belongs to the CAUSE, not to the class
//!
//! §4.11 is explicit that one code for the class *"would answer an honest caller
//! under the wrong reason and send them to the wrong layer"*, and the four
//! remedies really are different: `413` says shrink the payload, `400
//! invalid_request` says fix the bytes, `400 hash_mismatch` says re-key the
//! `included` map, `401` says re-authenticate. So **row (c) asserting `413` is
//! not decoration** — it is the row that fails a peer which answers the right
//! *class* under one blanket code. `400 non_canonical_ecf` is ruled out on the
//! framing arm for the same reason: `ENTITY-CBOR-ENCODING` §6.3 defines that
//! code for CBOR **tag-policy** violations, and *"your bytes are truncated"* is
//! not *"re-encode without the tag."*
//!
//! ⚠ **Pre-`0.8.2.26` that was stated as a flat prohibition and it was too
//! wide.** §4.11's framing row read *"un-parseable, truncated or
//! **non-canonical** CBOR"*, so a tag on a data field satisfied that row and
//! §6.3's MUST **simultaneously and incompatibly** — it is non-canonical, it is
//! detected at decode, and it never becomes an Envelope. `.26`'s `DR-3`
//! partitions them instead of ranking them: bytes that **do not decode at all**
//! are the framing arm, bytes that **do decode and carry a forbidden tag** are
//! §6.3's, and the second is a pre-admission refusal owing the frame obligation
//! like any other member (arm (5a), the last two rows in this file). The
//! original sentence survives for the sub-case it was always true of — the
//! truncated one — and the rows below assert it there.
//!
//! Every assertion reads the decoded **`code` key**, never a substring of the
//! body — a code is `(status, field, spelling)` and a byte scan measures only
//! the last.
//!
//! # Mutations RUN, and which rows reddened
//!
//! Eight mutations, each **run** and each recorded by the rows it reddened —
//! not by "verified", which is indistinguishable from a mutation nobody
//! executed. `(hs)` is the handshake emission site, `(est)` the message loop's.
//!
//! | # | mutation | rows reddened |
//! |---|---|---|
//! | 1 | restore the silent `continue` on the decode arm | (a) framing · (f) in-flight |
//! | 2 | restore the bare `Err` on the **message loop's** read arm | (c) est · (a') est |
//! | 3 | delete the wrong-root-type gate | (b) |
//! | 4 | `preadmission_disposition` → one blanket `400 invalid_request` | (c) hs · (c) est |
//! | 5 | framing arm `continue` → `return` (close on refusal) | (a) framing · (f) in-flight |
//! | 6 | `is_clean_eof` widened to any `UnexpectedEof` | (a') hs |
//! | 7 | `is_clean_eof` → `false` | clean-disconnect control |
//! | 8 | `read_frame` drops the phase distinction (truncation → plain EOF) | (a') hs · (a') est |
//!
//! # ⭐ Two of these were written down WRONG before they were run, and the
//! corrections are the useful part
//!
//! **Mutation 2 was the finding.** It was predicted to redden the oversize and
//! truncated rows. It reddened **nothing at all** against the original six-row
//! file — because those rows drive the *handshake* frame reads, and the
//! `(status, code)` table is shared between the two sites while the **emission
//! is not**. `write_preadmission_refusal` and `send_preadmission_refusal` are
//! different code on different socket halves, and restoring the exact
//! pre-`0.8.2.25` bare close on the message loop left a green suite. That is
//! what the tapping proxy above exists for, and it is this repo's own rule
//! arriving from the other direction: *a rule satisfiable at two sites needs a
//! mutation per site, and a site whose mutation reddens nothing owes a row that
//! observes it directly.*
//!
//! **Mutation 1 was predicted to leave the in-flight row green.** It does not,
//! and the reason is worth keeping rather than tidying away: the arm-(f) row
//! asserts *both* that the refusal is answered and that the admitted request
//! survives, so an answer-side mutation reddens it too. Mutations 1 and 5 are
//! therefore **not** disjoint from each other — 5 is the survival mutation and 1
//! is the answer mutation, and both rows carry both assertions. What is disjoint
//! is the partition by **arm**: {1,5} → the framing/in-flight pair, {3} → root
//! type, {4} → the per-cause code table, {2,6,7,8} → the read-phase arms. No
//! single mutation reddens across those groups, which is what separates *this
//! peer answers the class* from *this peer answers one member of it*.
//!
//! Two greens that are worth naming rather than reading as slack. The
//! blanket-code mutation (4) leaves (a), (a') and (b) green **because
//! `invalid_request` genuinely is their code** — only the oversize arm can tell
//! a per-cause table from a per-class one, which is why that row has to exist
//! even though `413` was already a MUST before `0.8.2.25`. And the root-type
//! mutation (3) leaves (a) green because a third-typed root *decodes perfectly*:
//! the two guards refuse disjoint inputs, so neither can ever witness the other.

use std::sync::Arc;

use entity_peer::{connection, remote, transport, PeerBuilder, PeerShared};
use entity_wire::{
    decode_envelope, encode_envelope, read_frame, write_frame, DEFAULT_MAX_FRAME_SIZE,
};

/// A refusal as the caller sees it: the status and the decoded `code` key.
#[derive(Debug, PartialEq, Eq)]
struct Coded {
    status: u32,
    code: String,
}

fn coded_from_response(resp: &entity_protocol::ParsedResponse) -> Coded {
    let val: ciborium::Value =
        ciborium::from_reader(resp.result.data.as_slice()).unwrap_or(ciborium::Value::Null);
    Coded {
        status: resp.status,
        code: val
            .as_map()
            .and_then(|m: &Vec<(ciborium::Value, ciborium::Value)>| {
                m.iter().find(|(k, _)| k.as_text() == Some("code"))
            })
            .and_then(|(_, v)| v.as_text())
            .unwrap_or_default()
            .to_string(),
    }
}

fn server() -> (Arc<PeerShared>, String) {
    let peer = PeerBuilder::new()
        .identity_keypair(entity_crypto::IdentityKeypair::Ed25519(
            entity_crypto::Keypair::from_seed([0xA1u8; 32]),
        ))
        .build()
        .expect("server builds");
    let pid = peer.peer_id().to_string();
    let shared = peer.shared();
    peer.start_engines(&shared);
    (shared, pid)
}

// ---------------------------------------------------------------------------
// Group A — raw bytes, pre-handshake
// ---------------------------------------------------------------------------

/// Write `bytes` verbatim as the first thing a connection ever sees, then read
/// whatever the peer answers.
///
/// **Raw, deliberately.** These rows forge a length *prefix*, which no endpoint
/// API can express — `dispatch_raw` frames what it is handed, so a caller using
/// it can never produce the input arm (c) is about. This is the raw-frame
/// injection `entity-core-go` records as owed by their validate harness; it
/// exists here.
///
/// Returns `None` when the peer answered nothing at all — which is the
/// **silent-drop** and **bare-close** shape, and is the failure these rows are
/// written to report as a failure rather than as a hang. The timeout is short
/// and explicit for the same reason: against the default request deadline the
/// drop reads as a slow suite rather than as a defect.
async fn raw_first_frame(bytes: Vec<u8>, shared: Arc<PeerShared>) -> Option<Coded> {
    let (mut client, srv) = transport::memory_transport_pair();
    let handshake = tokio::spawn(async move {
        // Returns Err after writing the refusal on every row here — the
        // connection closes, which §4.11 leaves to the peer and which is not
        // what these rows measure.
        let _ = connection::handle_connection(srv, shared).await;
    });

    use tokio::io::AsyncWriteExt as _;
    client
        .writer
        .write_all(&bytes)
        .await
        .expect("the dialer can write its first bytes");
    client.writer.flush().await.expect("flush");

    let answered = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        read_frame(&mut client.reader, DEFAULT_MAX_FRAME_SIZE),
    )
    .await;
    handshake.abort();

    let frame = match answered {
        // A timeout is the silent drop; an `Err` is the bare close. §4.11 makes
        // them distinct non-conformances, and both are `None` to this helper
        // because both leave the caller with nothing to act on — the rows below
        // say which one they got from the message.
        Err(_) | Ok(Err(_)) => return None,
        Ok(Ok(f)) => f,
    };
    let env = decode_envelope(&frame).expect("the refusal is a decodable envelope");
    let resp = entity_protocol::parse_execute_response(&env)
        .expect("the refusal is an EXECUTE_RESPONSE (§4.11's emission shape)");
    Some(coded_from_response(&resp))
}

/// Arm (c) — an oversize frame is `413 payload_too_large`, coded, before the
/// close (§4.10(a) + §4.11).
///
/// The prefix claims 32 MiB against `DEFAULT_MAX_FRAME_SIZE`'s 16 MiB and the
/// body is four bytes: the whole point of §4.10(a) is that the refusal happens
/// **at the length prefix**, before anything is buffered, so a fixture that
/// actually sent 32 MiB would be testing a different sentence (and allocating
/// 32 MiB to do it).
///
/// ⭐ **This is the row that holds the per-cause table honest.** Every other arm
/// in this file answers `400 invalid_request`, so a peer that collapsed §4.11
/// into a single class-wide code would pass all of them. Only this row fails.
#[tokio::test]
async fn an_oversize_frame_is_answered_413_before_the_close() {
    let (shared, _pid) = server();
    let mut bytes = (32u32 * 1024 * 1024).to_be_bytes().to_vec();
    bytes.extend_from_slice(b"\x00\x00\x00\x00");

    let got = raw_first_frame(bytes, shared).await.expect(
        "§4.11: an oversize frame MUST be answered with a coded frame. Nothing \
         came back, which is the bare close this peer shipped until 0.8.2.25 — \
         indistinguishable to the caller from a network fault, and the two \
         remedies are opposite",
    );
    assert_eq!(
        got,
        Coded {
            status: 413,
            code: "payload_too_large".to_string()
        },
        "§4.10(a) names this code, and §4.11 requires it rather than the \
         class's generic one: `413` tells the caller to shrink the payload, \
         which is a different instruction from `400 invalid_request`'s fix \
         your bytes"
    );
}

/// Arm (a') — a frame that starts and does not finish is `400 invalid_request`,
/// coded, before the close.
///
/// ⚠ **The fixture's second half is load-bearing: the write half must be
/// DROPPED.** Without it the server's payload read simply pends, nothing is
/// refused, and the row would time out against a perfectly conformant peer. The
/// input this arm is about is *EOF part-way through a frame*, not *a slow
/// sender* — §4.10's own text keeps those apart, and the §6.11(c) deadline is
/// what answers the second.
///
/// ⭐ **And this row is why `read_frame` had to change.** `read_exact` reports
/// "the peer hung up between frames" and "the peer sent three bytes and
/// vanished" as the same `UnexpectedEof`, so the phase — the only thing that
/// distinguishes an ordinary disconnect from a §4.11 member — is unavailable to
/// the caller. The clean-disconnect control below is the other half of that
/// claim.
#[tokio::test]
async fn a_truncated_frame_is_answered_400_invalid_request() {
    let (shared, _pid) = server();
    let mut bytes = 64u32.to_be_bytes().to_vec();
    bytes.extend_from_slice(b"only ten b");

    let (mut client, srv) = transport::memory_transport_pair();
    let handshake = tokio::spawn(async move {
        let _ = connection::handle_connection(srv, shared).await;
    });
    use tokio::io::AsyncWriteExt as _;
    client
        .writer
        .write_all(&bytes)
        .await
        .expect("partial frame");
    client.writer.flush().await.expect("flush");
    // EOF mid-frame — the input this arm exists for.
    //
    // ⚠ `shutdown()`, never `drop()`. `tokio::io::split` keeps the underlying
    // duplex alive through the OTHER half, so dropping the write half delivers
    // **no EOF at all** and the server's payload read simply pends — which is
    // indistinguishable from a conformant peer that has not answered yet. The
    // first draft of this row used `drop` and failed as `Elapsed(())` against
    // the correct implementation; the clean-disconnect control below used it too
    // and was passing for that reason rather than for its own.
    client.writer.shutdown().await.expect("half-close");

    let frame = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        read_frame(&mut client.reader, DEFAULT_MAX_FRAME_SIZE),
    )
    .await
    .expect("§4.11: a truncated frame MUST be answered, not silently dropped")
    .expect("§4.11: a truncated frame MUST be answered, not bare-closed");
    handshake.abort();

    let env = decode_envelope(&frame).expect("decodable refusal");
    let resp = entity_protocol::parse_execute_response(&env).expect("an EXECUTE_RESPONSE");
    assert_eq!(
        coded_from_response(&resp),
        Coded {
            status: 400,
            code: "invalid_request".to_string()
        },
        "§4.11's framing row: truncated bytes are `invalid_request`. NOT \
         `non_canonical_ecf` — that is `ENTITY-CBOR-ENCODING` §6.3's code for a \
         tag on a data field, which `0.8.2.26` `DR-3` partitions away from this \
         arm rather than merely forbidding here (see the arm-(5a) rows at the \
         end of this file) — and NOT `413`, which would send the caller to \
         shrink a payload that was the right size"
    );
}

/// ⚠ **CONTROL for the arm above, and it is the one that could not be written
/// before `read_frame` learned the difference.**
///
/// A caller that connects and disconnects **at a frame boundary** owes nothing —
/// it is an ordinary disconnect, not a refusal — and a peer that answers it is
/// emitting a `400` at a socket that is already gone and calling a normal client
/// lifecycle a protocol violation.
///
/// Without this row the truncated arm is satisfiable by *"answer `400` on any
/// `UnexpectedEof`"*, which is one character of diff away and wrong. Verified by
/// running exactly that mutation: widening `is_clean_eof` to match any
/// `UnexpectedEof` leaves the truncated row **green** and reddens nothing, while
/// narrowing it to `false` reddens **this** row alone.
#[tokio::test]
async fn a_clean_disconnect_at_a_frame_boundary_is_not_a_refusal() {
    let (shared, _pid) = server();
    let (client, srv) = transport::memory_transport_pair();
    let handshake = tokio::spawn(async move {
        let _ = connection::handle_connection(srv, shared).await;
    });

    let mut reader = client.reader;
    // EOF with zero bytes sent — a clean boundary. `shutdown()` for the reason
    // spelled out at the truncated row: a dropped half of a `tokio::io::split`
    // signals nothing, so `drop` here would make this row pass whether or not
    // the peer distinguishes anything.
    let mut writer = client.writer;
    use tokio::io::AsyncWriteExt as _;
    writer.shutdown().await.expect("clean half-close");

    let answered = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        read_frame(&mut reader, DEFAULT_MAX_FRAME_SIZE),
    )
    .await;
    handshake.abort();

    let spoke = matches!(answered, Ok(Ok(_)));
    assert!(
        !spoke,
        "a peer that connects and leaves without sending a byte has refused \
         nothing; §4.11 is about frames this peer REFUSES, and answering an \
         ordinary disconnect makes every client lifecycle look like a protocol \
         violation"
    );
}

// ---------------------------------------------------------------------------
// Group A2 — raw bytes on an ESTABLISHED connection, through a tapping proxy
// ---------------------------------------------------------------------------

/// A byte-level man-in-the-middle between a real dialer and a real acceptor.
///
/// # ⭐ Why this exists, and it was found by a mutation rather than by review
///
/// The oversize and truncated arms have **two** emission sites in this tree, not
/// one: `write_preadmission_refusal` at the two handshake frame reads, and
/// `send_preadmission_refusal` through the serial writer channel in the message
/// loop. They share `preadmission_disposition` — so the `(status, code)` table is
/// measured once and covers both — but the *emission* is different code on a
/// different socket half at a different point in the connection's life.
///
/// Group A's rows drive only the **handshake** site, because that is the one a
/// test can reach by writing bytes at a fresh `memory_transport_pair`. Restoring
/// the bare `Err` on the message loop's read arm — the exact pre-`0.8.2.25`
/// behaviour, the bare close §4.11 names as a non-conformance — left **all six**
/// of the original rows green. The site was unobserved, and a green suite said
/// otherwise.
///
/// A forged length prefix cannot go through `dispatch_raw`, which frames what it
/// is handed. So the connection is built through a proxy: the dialer performs a
/// genuine handshake end to end, and afterwards the test writes arbitrary bytes
/// straight at the acceptor and reads whatever comes back. This is the
/// raw-frame injection `entity-core-go` records as owed by their validate
/// harness, on an established connection rather than a fresh one.
struct Tap {
    /// Raw bytes → the acceptor, bypassing the dialer entirely.
    inject: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    /// Every frame the acceptor sent back, in order.
    seen: Arc<tokio::sync::Mutex<Vec<Vec<u8>>>>,
}

impl Tap {
    /// Wait for the acceptor to send one more frame than `already`, or give up.
    async fn next_frame_after(&self, already: usize) -> Option<Vec<u8>> {
        for _ in 0..500 {
            {
                let seen = self.seen.lock().await;
                if seen.len() > already {
                    return Some(seen[already].clone());
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        None
    }
    async fn frame_count(&self) -> usize {
        self.seen.lock().await.len()
    }
}

/// Stand a real acceptor up behind a tap and hand back an established dialer.
async fn tapped_pair() -> (remote::RemoteConnection, Tap, String) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let (shared, pid) = server();
    // dialer <-> proxy, and proxy <-> acceptor.
    let (dialer_side, proxy_to_dialer) = transport::memory_transport_pair();
    let (proxy_to_server, server_side) = transport::memory_transport_pair();

    tokio::spawn(async move {
        let _ = connection::handle_connection(server_side, shared).await;
    });

    let to_server = Arc::new(tokio::sync::Mutex::new(proxy_to_server.writer));
    let (inject, mut inject_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let seen: Arc<tokio::sync::Mutex<Vec<Vec<u8>>>> = Arc::new(tokio::sync::Mutex::new(Vec::new()));

    // dialer → acceptor, byte for byte. Byte-level rather than frame-level on
    // purpose: the proxy must not normalize anything the dialer writes, or it
    // would be testing the proxy's framing instead of the peer's.
    let up = to_server.clone();
    let mut from_dialer = proxy_to_dialer.reader;
    tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            match from_dialer.read(&mut buf).await {
                // The dialer went away. Propagate the EOF rather than merely
                // stopping: `tokio::io::split` halves signal nothing on drop, so
                // without this the acceptor's read just pends and a row testing
                // "EOF part-way through a frame" would time out against a
                // perfectly conformant peer. Same trap as the Group A rows'
                // `shutdown()`, one layer out.
                Ok(0) | Err(_) => {
                    let mut w = up.lock().await;
                    let _ = w.shutdown().await;
                    break;
                }
                Ok(n) => {
                    let mut w = up.lock().await;
                    if w.write_all(&buf[..n]).await.is_err() || w.flush().await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Injection shares the write half with the copy task, so a forged prefix
    // cannot land in the middle of one of the dialer's own frames.
    let inj = to_server.clone();
    tokio::spawn(async move {
        while let Some(bytes) = inject_rx.recv().await {
            let mut w = inj.lock().await;
            let _ = w.write_all(&bytes).await;
            let _ = w.flush().await;
        }
    });

    // acceptor → dialer, recorded. Frame-level here because the recording is the
    // whole point and the acceptor only ever writes whole frames.
    let mut from_server = proxy_to_server.reader;
    let mut to_dialer = proxy_to_dialer.writer;
    let tapped = seen.clone();
    tokio::spawn(async move {
        while let Ok(f) = read_frame(&mut from_server, DEFAULT_MAX_FRAME_SIZE).await {
            tapped.lock().await.push(f.clone());
            if write_frame(&mut to_dialer, &f).await.is_err() {
                break;
            }
        }
    });

    let client =
        entity_crypto::IdentityKeypair::Ed25519(entity_crypto::Keypair::from_seed([0xA4u8; 32]));
    let endpoint =
        remote::perform_connect(dialer_side, &client, entity_hash::HASH_ALGORITHM_SHA256)
            .await
            .expect("a genuine handshake, end to end, through the tap");

    (endpoint, Tap { inject, seen }, pid)
}

fn coded_from_frame(frame: &[u8]) -> Coded {
    let env = decode_envelope(frame).expect("the refusal is a decodable envelope");
    let resp = entity_protocol::parse_execute_response(&env)
        .expect("§4.11's emission shape is an EXECUTE_RESPONSE");
    coded_from_response(&resp)
}

/// Arm (c) **on an established connection** — `413 payload_too_large`, coded,
/// through the message loop rather than the handshake.
///
/// ⚠ **This row and its Group A twin are two sites, not one row driven twice.**
/// `preadmission_disposition` is shared, so the code table is measured once; the
/// emission is not. Verified: restoring the bare `Err` on the message loop's
/// read arm reddens **this** row and leaves every Group A row green, and the
/// converse holds for the handshake site.
#[tokio::test]
async fn an_oversize_frame_on_an_established_connection_is_answered_413() {
    let (endpoint, tap, _pid) = tapped_pair().await;
    let before = tap.frame_count().await;

    let mut bytes = (32u32 * 1024 * 1024).to_be_bytes().to_vec();
    bytes.extend_from_slice(b"\x00\x00\x00\x00");
    tap.inject.send(bytes).expect("inject");

    let frame = tap.next_frame_after(before).await.expect(
        "§4.10(a) + §4.11: an oversize frame on an ESTABLISHED connection MUST \
         be answered with a coded frame before the close. Nothing came back, \
         which is the bare close — and note that the handshake-phase rows stay \
         green against it, because they are a different emission site",
    );
    assert_eq!(
        coded_from_frame(&frame),
        Coded {
            status: 413,
            code: "payload_too_large".to_string()
        },
    );
    drop(endpoint);
}

/// Arm (a') **on an established connection** — a truncated frame is
/// `400 invalid_request`, coded, and the peer then closes because the stream is
/// desynchronized.
#[tokio::test]
async fn a_truncated_frame_on_an_established_connection_is_answered_400() {
    let (endpoint, tap, _pid) = tapped_pair().await;
    let before = tap.frame_count().await;

    // A prefix promising 4096 bytes, followed by ten — and then the injector
    // simply stops. The acceptor is left mid-frame.
    let mut bytes = 4096u32.to_be_bytes().to_vec();
    bytes.extend_from_slice(b"only ten b");
    tap.inject.send(bytes).expect("inject");
    // Closing the dialer's half is what turns "a slow sender" into "EOF
    // part-way through a frame" — the input this arm is about. §4.10's own
    // §6.11(c) deadline answers the first and MUST NOT answer this.
    drop(endpoint);

    let frame = tap
        .next_frame_after(before)
        .await
        .expect("§4.11: a truncated frame MUST be answered, not bare-closed");
    assert_eq!(
        coded_from_frame(&frame),
        Coded {
            status: 400,
            code: "invalid_request".to_string()
        },
        "the framing row's code — NOT `413`, which would tell an honest caller \
         to shrink a payload that was the right size"
    );
}

// ---------------------------------------------------------------------------
// Group B — an established, multiplexed connection
// ---------------------------------------------------------------------------

/// Arms (a), (b) and (f) on a real handshake.
///
/// `dispatch_raw` is the injection point: it registers a demux entry under the
/// `request_id` it is handed and writes the bytes it is handed **verbatim** as
/// one frame. Both refusals here are uncorrelated (`request_id: ""`, which is
/// §4.11's *"best-effort coded frame carrying no correlation"*), so the rows
/// register under `""` and read the answer that comes back on it.
async fn established_refusal(payload: Vec<u8>) -> (Option<Coded>, bool) {
    use remote::RemoteEndpoint as _;
    use transport::{Connector as _, MemoryConnector, MemoryListener, MemoryTransportRegistry};

    let registry = MemoryTransportRegistry::new();
    let (shared, pid) = server();
    let listener = MemoryListener::bind(pid.clone(), registry.clone()).unwrap();
    let shared_run = shared.clone();
    let task = tokio::spawn(async move {
        let _ = entity_peer::server::run(listener, shared_run).await;
    });
    tokio::task::yield_now().await;

    let client =
        entity_crypto::IdentityKeypair::Ed25519(entity_crypto::Keypair::from_seed([0xA2u8; 32]));
    let conn = MemoryConnector::new(registry.clone())
        .connect(&format!("memory://{}", pid))
        .await
        .expect("connect");
    let endpoint = remote::perform_connect(conn, &client, entity_hash::HASH_ALGORITHM_SHA256)
        .await
        .expect("handshake");

    let refusal = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        endpoint.dispatch_raw(String::new(), payload),
    )
    .await
    .ok()
    .and_then(|r| r.ok())
    .map(|resp| coded_from_response(&resp));

    // ⭐ **Arm (f), the arm nothing else implies.** The refusal must not take the
    // connection with it: on a multiplexed connection a bare close destroys
    // every unrelated ADMITTED request, which §4.9(c) forbids for each of them
    // independently. Without this half, "refuses the frame" and "kills the
    // stream" produce the same observation for the refused frame itself, and
    // only one of the two is conformant.
    let params = entity_entity::Entity::new(
        "system/params",
        entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![])),
    )
    .unwrap();
    let survived = remote::send_execute(
        &endpoint,
        &client,
        &format!("/{}/system/tree", pid),
        "get",
        &params,
        Some(&entity_capability::ResourceTarget {
            targets: vec![format!("/{}/system/type/", pid)],
            exclude: vec![],
        }),
        None,
        None,
        &std::collections::HashMap::new(),
        None,
    )
    .await
    .is_ok();

    task.abort();
    (refusal, survived)
}

/// Arm (a) — a whole frame whose payload is not an envelope is answered
/// `400 invalid_request`, and the connection **survives**.
///
/// ⛔ **This is the row for the defect this seat actually shipped.** The framing
/// arm was a `tracing::warn!` and a `continue`: no response, no close, and the
/// caller blocked to its own §6.11(c) deadline. It is the *silent* disposition
/// of the three-way split — go bare-closed, py answered — and §4.11 names it the
/// weaker of the two non-conformances precisely because nothing surfaces it. The
/// mutation restoring it fails this row as a **timeout**, not an assertion,
/// which is exactly the shape that let it ship.
#[tokio::test]
async fn an_undecodable_frame_is_answered_and_the_connection_survives() {
    // Valid CBOR framing is not required and not wanted: these bytes are the
    // "never becomes an Envelope" population by construction.
    let (refusal, survived) =
        established_refusal(b"\xff\xff\xff\xff not an envelope".to_vec()).await;

    let got = refusal.expect(
        "§4.11: an un-parseable frame MUST be answered. A timeout here is the \
         silent drop — fail-closed and unobservable to the caller and to every \
         instrument",
    );
    assert_eq!(
        got,
        Coded {
            status: 400,
            code: "invalid_request".to_string()
        },
        "§4.11's framing row. Specifically NOT `hash_mismatch`, which is the \
         adjacent §5.2a arm's code: nothing here was ever hashed, and §4.11 \
         calls a code that is merely in the right family still wrong"
    );
    assert!(
        survived,
        "arm (f): the frame decoded as nothing, but it decoded WHOLE — the \
         stream is synchronized on the next boundary, so there is nothing to \
         resynchronize by closing, and closing would spend every admitted \
         in-flight request on this multiplexed connection"
    );
}

/// Arm (b) — a well-formed envelope whose root is neither EXECUTE nor
/// EXECUTE_RESPONSE is answered `400 invalid_request` (§3.3 + §4.11).
///
/// ⚠ **This arm and arm (a) cannot witness each other**, which is why both rows
/// exist. A third-typed root *decodes perfectly*: it sails past the framing
/// guard and is refused by a different one. Deleting the root-type gate leaves
/// arm (a) green; restoring the silent `continue` leaves this one green. Two
/// guards that refuse different inputs tell you nothing about each other.
///
/// ⭐ **§3.3 is the sentence that MOVED, and it moved the furthest of the five.**
/// It used to *mandate the bare close* here, with no coded frame in it at all —
/// the one member of the class whose stated requirement was itself one of the
/// two non-conformances §4.11 now names. We had no gate at all, so the frame
/// fell through to `dispatch_request` and came back as whatever the verification
/// path happened to mint.
#[tokio::test]
async fn a_third_root_type_is_answered_400_invalid_request() {
    // A `system/hello` root post-handshake: a real entity type, correctly
    // encoded, in a position §3.3 admits only two types for.
    let hello = entity_entity::Entity::new(
        entity_types::TYPE_HELLO,
        entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![])),
    )
    .expect("hello entity");
    let frame = encode_envelope(&entity_entity::Envelope::new(hello));

    let (refusal, survived) = established_refusal(frame).await;

    let got = refusal.expect(
        "§3.3 as rewritten at 0.8.2.25: a third-typed root MUST be answered \
         `400 invalid_request` before any close",
    );
    assert_eq!(
        got,
        Coded {
            status: 400,
            code: "invalid_request".to_string()
        },
        "§4.11's root-type row. A peer with no gate here answers whatever its \
         verification path mints for a root carrying no `uri` — which is a \
         code in the right family for the wrong reason"
    );
    assert!(
        survived,
        "the frame decoded whole, so the same arm-(f) reasoning binds as for \
         the framing arm: §3.3's pre-0.8.2.25 close is now the peer's choice, \
         and on a multiplexed connection it is the wrong one"
    );
}

/// ⭐ **Arm (f) proper — a refusal arriving while an admitted request is
/// genuinely IN FLIGHT does not cost that request its response.**
///
/// The rows above assert the connection is usable *afterwards*, which is the
/// weaker claim: it cannot separate "the refusal did not disturb the in-flight
/// work" from "the refusal happened to finish first." Here the real request is
/// registered and its future left un-awaited — so it is, by construction, still
/// pending in the demux — and only then is the garbage frame injected. Both are
/// awaited at the end.
///
/// §4.11 calls this *"the arm that cannot be inferred from the others"* and
/// records that it **has never been driven**. It is driven here.
#[tokio::test]
async fn a_refusal_does_not_cancel_an_admitted_request_in_flight() {
    use remote::RemoteEndpoint as _;
    use transport::{Connector as _, MemoryConnector, MemoryListener, MemoryTransportRegistry};

    let registry = MemoryTransportRegistry::new();
    let (shared, pid) = server();
    let listener = MemoryListener::bind(pid.clone(), registry.clone()).unwrap();
    let shared_run = shared.clone();
    let task = tokio::spawn(async move {
        let _ = entity_peer::server::run(listener, shared_run).await;
    });
    tokio::task::yield_now().await;

    let client =
        entity_crypto::IdentityKeypair::Ed25519(entity_crypto::Keypair::from_seed([0xA3u8; 32]));
    let conn = MemoryConnector::new(registry.clone())
        .connect(&format!("memory://{}", pid))
        .await
        .expect("connect");
    let endpoint = remote::perform_connect(conn, &client, entity_hash::HASH_ALGORITHM_SHA256)
        .await
        .expect("handshake");

    let params = entity_entity::Entity::new(
        "system/params",
        entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![])),
    )
    .unwrap();

    // Admitted request, registered and NOT yet awaited. The bindings are hoisted
    // out of the call because the future borrows them and must outlive the
    // statement — the whole point of this row is that it stays pending.
    let uri = format!("/{}/system/tree", pid);
    let resource = entity_capability::ResourceTarget {
        targets: vec![format!("/{}/system/type/", pid)],
        exclude: vec![],
    };
    let extra = std::collections::HashMap::new();
    let admitted = remote::send_execute(
        &endpoint,
        &client,
        &uri,
        "get",
        &params,
        Some(&resource),
        None,
        None,
        &extra,
        None,
    );
    tokio::pin!(admitted);

    // The refusal lands on the same connection while the above is pending.
    let refusal = endpoint.dispatch_raw(String::new(), b"\xde\xad\xbe\xef garbage".to_vec());

    let (refused, served) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        futures_util::future::join(refusal, admitted),
    )
    .await
    .expect("neither half may hang");

    task.abort();

    assert!(
        refused.is_ok(),
        "the refusal itself is still answered (§4.11's `[MUST]`)"
    );
    assert!(
        served.is_ok(),
        "arm (f): an admitted request in flight on a multiplexed connection \
         MUST still receive its response. A peer that closes on a \
         pre-admission refusal fails every one of them at once, which §4.9(c) \
         forbids for each of them independently"
    );
}

// ---------------------------------------------------------------------------
// Arm (5a) — the TAG-POLICY refusal (`0.8.2.26` `DR-3`).
// ---------------------------------------------------------------------------

/// Build a `system/hello`-rooted envelope whose root `data` is `{"a": <inner>}`,
/// where `inner` is spliced in **raw**.
///
/// The pair this produces is the whole point: two frames that differ in exactly
/// the tag head and nothing else — same root type, same field, same nesting,
/// both self-consistently hashed over their own bytes. A row built from two
/// independently-authored fixtures cannot tell *"the tag was detected"* from
/// *"the second fixture was malformed in some other way."*
fn envelope_with_raw_inner(inner: &[u8]) -> Vec<u8> {
    let base = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
        entity_ecf::text("a"),
        entity_ecf::text("placeholder"),
    )]));
    let data = entity_wire::cbor_map_set_raw(&base, "a", inner).expect("splice");
    let root = entity_entity::Entity::new(entity_types::TYPE_HELLO, data).expect("root entity");
    encode_envelope(&entity_entity::Envelope::new(root))
}

/// ⛔ **`0.8.2.26` `DR-3` — bytes that DO decode and carry a CBOR tag are the
/// tag-policy arm, `400 non_canonical_ecf`, NOT the framing arm.**
///
/// `.26` partitions an input §4.11's framing row used to swallow whole:
///
/// | input | code |
/// |---|---|
/// | bytes that do not decode into CBOR at all | `400 invalid_request` |
/// | bytes that decode, carrying a major-type-6 item in a data-field position | `400 non_canonical_ecf` |
///
/// and says the second *"is a pre-admission refusal governed by this section's
/// frame obligation like any other member"* — so it owes a coded frame, and a
/// silent drop or a bare close is non-conformant for it exactly as for arm (a).
///
/// ⚠ **The relay said this seat does not move for `.26`, and measured here it
/// does.** The obligation itself is older than `.26` — `ENTITY-CBOR-ENCODING`
/// §6.3 has said *"MUST reject any received protocol frame containing a CBOR tag
/// on a data field … Implementations MUST NOT silently strip tags, MUST NOT
/// preserve them through forwarding"* since it was written. What `.26` adds is
/// the arm's **identity**: a row in §4.11's table, a line in the §9.1 profile,
/// and the frame obligation. Measured at `86e313b`, before any edit: this peer
/// ran **no tag check on any inbound path**. `cbor_item_end` treated major 6 as
/// an ordinary item and walked past it (`6 => cbor_item_end(data, after_head)`),
/// and `decode_entity` takes `data` as a raw slice by construction, so a tagged
/// frame decoded, admitted, and was answered on its merits.
///
/// ⭐ **And the §5.4 byte-fidelity fix two commits back MOVED WHICH PROHIBITION
/// WE VIOLATE, without touching this code.** Before `23513a0`, `to_ecf` on the
/// forward path dropped tags — §6.3's *"MUST NOT silently strip"*. After it,
/// `data` rides as raw bytes — §6.3's *"MUST NOT preserve them through
/// forwarding"*. Neither disposition is the one §6.3 asks for, and the fix
/// swapped one for the other with a green suite either way, because no row in
/// this tree drove a tag. **A validator we shipped had zero callers:**
/// `is_canonical_ecf` carries a complete strict-ECF arm for major 6 and lives
/// only in `cmd/wire-conformance`, scoring `decode_reject` *vectors* — the
/// standing *validator-with-no-consumer* shape, and the same one the
/// `storage-substitute-http` handler had.
///
/// # Why the control is the same bytes minus the tag
///
/// The untagged twin is the existing arm-(b) input — a third-typed root — and it
/// answers `400 invalid_request`. That is what makes this row a discriminator
/// rather than an assertion that *some* refusal happens: **the tag check must
/// fire AHEAD of the root-type gate**, which is where §4.11's own pseudocode
/// puts it (tag rejection sits between the decode and *"Validate root entity
/// hash"*). If the tag arm answered `invalid_request` the tag was never seen and
/// the root-type gate refused it for its own reason — which is precisely the
/// pre-fix observation.
#[tokio::test]
async fn a_cbor_tag_in_a_data_field_is_refused_non_canonical_ecf_not_invalid_request() {
    // Tag 0 (date/time string) on a tstr: legal, IANA-registered, semantically
    // coherent CBOR. The frame is refused by POLICY, not because the bytes are
    // broken — which is the whole distinction `.26` drew.
    let untagged = [0x61u8, b'x']; // "x"
    let tagged = [0xc0u8, 0x61, b'x']; // 0("x")

    let (control, control_survived) = established_refusal(envelope_with_raw_inner(&untagged)).await;
    let (refusal, survived) = established_refusal(envelope_with_raw_inner(&tagged)).await;

    assert_eq!(
        control.expect("the untagged twin must be answered"),
        Coded {
            status: 400,
            code: "invalid_request".to_string()
        },
        "control: with no tag present these bytes are arm (b) — a third-typed \
         root. If this row ever reports `non_canonical_ecf` the scan is firing \
         on something that is not a tag"
    );
    assert!(control_survived);

    let got = refusal.expect(
        "§4.11 arm (5a): a tagged frame is a pre-admission refusal and MUST be \
         answered with a coded frame. A timeout here is the silent drop",
    );
    assert_eq!(
        got,
        Coded {
            status: 400,
            code: "non_canonical_ecf".to_string()
        },
        "`ENTITY-CBOR-ENCODING` §6.3 + §4.11's tag-policy row. \
         `invalid_request` here is the PRE-FIX answer and it is the framing \
         arm's code: it says *your bytes are broken* where the caller's actual \
         remedy is *re-encode without the tag*, and §4.11 calls a code that is \
         merely in the right family still wrong"
    );
    assert!(
        survived,
        "the bytes DECODED — this is (a1)-shaped, not (a2): the length prefix \
         completed and the frame was consumed whole, so the stream is \
         synchronized and arm (f) binds. `.26` exempts only the truncated half"
    );
}

/// §6.3's nesting clause: *"Detection covers any CBOR major-type-6 item
/// appearing anywhere within an entity's `data` field at any nesting depth."*
///
/// ⚠ **This row is not implied by the one above and cannot be inferred from
/// it.** A check placed at the top of `data` — the obvious reading of *"a
/// data-field position"* — passes the row above and fails this one, and that
/// shallow check is the cheap implementation somebody reaches for precisely
/// because `decode_entity` holds `data` as one opaque slice. The depth here is
/// three (`data` → map → array → tag).
#[tokio::test]
async fn a_tag_nested_deep_inside_data_is_refused_at_every_depth() {
    // {"a": [ 0("x") ]}  — the tag is two containers below the data field.
    let nested = [0x81u8, 0xc0, 0x61, b'x'];
    let (refusal, survived) = established_refusal(envelope_with_raw_inner(&nested)).await;

    assert_eq!(
        refusal.expect("a nested tag MUST be answered"),
        Coded {
            status: 400,
            code: "non_canonical_ecf".to_string()
        },
        "§6.3 detection is at every nesting depth, not at the top of `data`"
    );
    assert!(survived);
}
