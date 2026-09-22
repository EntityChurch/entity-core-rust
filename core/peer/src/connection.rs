//! Per-connection handshake + message loop.

use std::collections::HashMap;
use std::sync::Arc;

use crate::durability;
use crate::transport::Connection as TransportConnection;
use crate::{PeerError, PeerShared};
use entity_entity::{EntityUri, Envelope};
use entity_handler::{
    ExecuteFn, ExecuteOptions, HandlerContext, HandlerError, STATUS_AUTH_FAILED,
    STATUS_BAD_REQUEST, STATUS_CONFLICT, STATUS_FORBIDDEN, STATUS_INTERNAL_ERROR, STATUS_NOT_FOUND,
    STATUS_NOT_SUPPORTED, STATUS_PAYLOAD_TOO_LARGE,
};
use entity_protocol::{
    build_error_response, build_execute_response, build_execute_response_full, Connection,
};
use entity_wire::{
    decode_envelope, encode_envelope, read_frame, write_frame, DEFAULT_MAX_FRAME_SIZE,
};

/// Put a **§4.11 pre-admission refusal** on the wire (0.8.2.25).
///
/// A pre-admission refusal is the refusal of an inbound frame *before it becomes
/// an admitted request*, so §4.9(c)'s deliver-or-signal rule — scoped to *"every
/// request the peer admits"* — reaches none of them, and §4.11 states the
/// obligation separately:
///
/// > A peer that refuses a frame pre-admission **MUST** put a coded
/// > EXECUTE_RESPONSE on the wire, correlated by `request_id` where the id is
/// > available and otherwise as a best-effort coded frame carrying no
/// > correlation. Whether the peer closes afterwards is its own choice.
///
/// # ⛔ One function, because the class had FIVE homes and FOUR strengths
///
/// That is the finding 0.8.2.25 is built on: §4.6 forbade the bare close, §5.2a
/// forbade the drop *and* the close, §4.10(a) permitted the close, §3.3
/// **required** it with no coded frame at all, and the framing arm was stated
/// nowhere — three of them giving the same reason in nearly the same words, none
/// cross-referencing another, and three independent implementations producing
/// three different caller-observable answers to one input. **Patching the
/// instances is what produced the divergence**, so the emission lives here once
/// and every arm calls it. A `match` arm that hand-rolls its own refusal is a
/// second copy, and a second copy is how the four strengths happened.
///
/// # The code belongs to the CAUSE, not to the class
///
/// Callers pass `(status, code)`; this function has no opinion on them and must
/// not acquire one. §4.11 is explicit that a single code for the class *"would
/// answer an honest caller under the wrong reason and send them to the wrong
/// layer"* — `413` says shrink the payload, `400 invalid_request` says fix the
/// bytes, `400 hash_mismatch` says re-key the `included` map, `401` says
/// re-authenticate. Four remedies.
///
/// # Best-effort, and the failure mode is deliberate
///
/// Goes out through the serial writer channel like every other response on this
/// connection — the socket is owned by the writer task. A closed channel means
/// the writer is already gone, i.e. the connection is over, and there is nothing
/// to answer to; a failure to *build* the envelope likewise leaves nothing to
/// send. Both are swallowed on purpose: this is the best-effort half of §4.11,
/// and a refusal that panicked while refusing would be worse than the drop it
/// replaces.
fn send_preadmission_refusal(
    resp_tx: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    request_id: &str,
    status: u32,
    code: &str,
    message: &str,
) {
    if let Ok(resp) = build_error_response(request_id, status, code, message) {
        let _ = resp_tx.send(encode_envelope(&resp));
    }
}

/// The §4.11 refusal for the **pre-`Established`** phase, written straight at
/// the socket (0.8.2.25).
///
/// Same obligation, different plumbing, and the difference is why this exists as
/// a second function rather than a second copy of the emission. The serial
/// writer task — and therefore `resp_tx` — is only created once the handshake
/// completes, so the two hello/authenticate frame reads have nothing to send
/// through and must write the half they own directly. Everything a caller
/// decides is still `(status, code)`.
///
/// ⚠ **The handshake frames are in the class.** §4.11's table lists the
/// connect-auth arm as a member (§4.6: *"a bare close is non-conformant"*), and
/// a frame that does not decode at all is the same class one step earlier — the
/// initiator is mid-handshake, so a silent EOF reads to it as *"this peer is
/// down"* rather than *"your hello was malformed"*. Both of these sites
/// bare-closed until 0.8.2.25.
///
/// Arm (f) does not arise here: pre-`Established` there are no admitted requests
/// to destroy, so the caller closes afterwards and §4.11 leaves that to it.
async fn write_preadmission_refusal<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    request_id: &str,
    status: u32,
    code: &str,
    message: &str,
) {
    if let Ok(resp) = build_error_response(request_id, status, code, message) {
        let _ = write_frame(writer, &encode_envelope(&resp)).await;
    }
}

/// The `(status, code)` §4.11 assigns a [`entity_wire::WireError`] arising at a
/// frame read or an envelope decode — the class's two mechanical arms.
///
/// Shared by the handshake sites and the message loop so the two phases cannot
/// answer the same bytes differently, which is the intra-implementation form of
/// the very divergence §4.11 was written to close. `IncludedKeyMismatch` is
/// deliberately **absent**: §5.2a's arm is only reachable post-handshake and
/// carries a real `request_id`, so it is answered at its own site with the
/// correlation this function cannot supply.
/// Is this the one read failure §4.11 does **not** reach — EOF at a frame
/// boundary?
///
/// ⚠ **The distinction is made in `read_frame` and can only be made there.**
/// `read_exact` reports "the peer hung up between frames" and "the peer sent
/// three bytes of a length prefix and vanished" as the same `UnexpectedEof`, and
/// once the error is in the caller's hands the phase is gone. So `read_frame`
/// returns [`entity_wire::WireError::TruncatedFrame`] for the second and a plain
/// `Io(UnexpectedEof)` only for the first, and this predicate reads that
/// verdict rather than re-deriving it. Widening it to *"any `UnexpectedEof`"*
/// would silently restore the bare close on every truncated frame, which is the
/// mutation the truncation row exists to catch.
fn is_clean_eof(e: &entity_wire::WireError) -> bool {
    matches!(e, entity_wire::WireError::Io(io) if io.kind() == std::io::ErrorKind::UnexpectedEof)
}

fn preadmission_disposition(e: &entity_wire::WireError) -> (u32, &'static str) {
    match e {
        // §4.10(a). Detected at the length prefix — nothing was buffered.
        entity_wire::WireError::FrameTooLarge { .. } => {
            (STATUS_PAYLOAD_TOO_LARGE, "payload_too_large")
        }
        // §4.11 arm (5a) — the **tag-policy** row (0.8.2.26 `DR-3`).
        //
        // ⚠ This arm is what the comment below used to deny. Pre-`.26` §4.11's
        // framing row read *"un-parseable, truncated or **non-canonical**
        // CBOR"* and then forbade `non_canonical_ecf` on it by name, so one
        // input satisfied two MUSTs incompatibly: a tag on a data field is
        // non-canonical, is detected at decode, and never becomes an Envelope.
        // `.26` partitions them instead of ranking them — **bytes that do not
        // decode at all** are the framing arm, **bytes that decode and carry a
        // forbidden tag** are §6.3's — and says the second *"is a
        // pre-admission refusal governed by this section's frame obligation
        // like any other member"*, which is why it routes through this same
        // function and not through a private emission.
        entity_wire::WireError::CborTag { .. } => (STATUS_BAD_REQUEST, "non_canonical_ecf"),
        // §4.11's framing row, and the code is `invalid_request` **because the
        // bytes did not decode** — not merely because nothing else matched.
        // The neighbouring code `non_canonical_ecf` is the arm directly above:
        // `ENTITY-CBOR-ENCODING` §6.3 defines it for CBOR tag-policy
        // violations, and *"your bytes are truncated"* is not *"re-encode
        // without the tag."* The code selects the caller's remedy, so a code in
        // the right family is still the wrong code.
        _ => (STATUS_BAD_REQUEST, "invalid_request"),
    }
}

/// Handle a single connection: handshake then message loop.
///
/// Accepts any transport's Connection (TCP, WebSocket, memory, etc.).
/// The wire codec (read_frame/write_frame) works over any AsyncRead/AsyncWrite.
#[tracing::instrument(
    level = "debug",
    skip_all,
    fields(transport = conn.transport_type, remote = %conn.remote_addr),
)]
pub async fn handle_connection(
    conn: TransportConnection,
    shared: Arc<PeerShared>,
) -> Result<(), PeerError> {
    // §6.7.1's accept-side path starts here: the transport source of this
    // connection, captured before the halves are split out. It is scoped around
    // each dispatch below and is visible ONLY to `system/network`'s
    // observe-address — see `entity_network::accept_source` for why it is not a
    // HandlerContext field.
    #[cfg(feature = "network")]
    let accept_source_addr = conn.remote_addr.clone();
    let (mut reader, mut writer) = (conn.reader, conn.writer);

    let mut conn = Connection::new(shared.keypair.peer_id());
    // §4.5: advertise this peer's negotiation surface (home format
    // preference order + key_type accept-set + own key_type for the
    // mutual-verifiability gate). `process_hello` resolves the active
    // `content_hash_format` from this against the initiator's hello.
    conn.set_local_advertisement(
        shared.config.home_hash_format,
        shared.keypair.key_type().label(),
    );

    // --- Phase 1+2: Receive remote hello → send our hello response ---
    tracing::debug!("awaiting remote hello");
    // §4.11 (0.8.2.25): both halves of this read are pre-admission refusals and
    // both bare-closed before. A clean EOF at the frame boundary is NOT one —
    // that is a caller that connected and went away, and it owes nothing — which
    // is the distinction `read_frame` now makes for us via `TruncatedFrame`.
    let frame = match read_frame(&mut reader, DEFAULT_MAX_FRAME_SIZE).await {
        Ok(f) => f,
        Err(e) => {
            if !is_clean_eof(&e) {
                let (status, code) = preadmission_disposition(&e);
                write_preadmission_refusal(&mut writer, "", status, code, &e.to_string()).await;
            }
            return Err(PeerError::ConnectionError(format!("read hello: {}", e)));
        }
    };
    let hello_envelope = match decode_envelope(&frame) {
        Ok(e) => e,
        Err(e) => {
            let (status, code) = preadmission_disposition(&e);
            write_preadmission_refusal(&mut writer, "", status, code, &e.to_string()).await;
            return Err(PeerError::ConnectionError(format!("decode hello: {}", e)));
        }
    };

    // v7.66 §4.4 surface 6 — handshake errors MUST surface as a wire
    // EXECUTE_RESPONSE (e.g., `400 unsupported_key_type` for an unknown
    // remote `key_type`) rather than a transport-level EOF. Build the
    // error response from the inbound request_id, send it on the wire,
    // THEN return the error to close the connection cleanly.
    // FM-1 (§4.2 / §4.6 step 1): discriminate the frame's OPERATION before
    // treating it as a hello. Without this the TCP path hands a pre-hello
    // `authenticate` to `build_hello_response_envelope` and reports the failure
    // as `400 handshake_failed`. Same refusal as the http-live path — one
    // helper, because both transports carried the identical defect.
    //
    // Ordered below the row-10 refusal, which is checked first; the two are
    // disjoint (`authenticate` is an implemented operation) so this is
    // presentation, not precedence.

    // CE-1 (§4.2 rule 3 / §5.2a, restated by 0.8.2.5): a frame that is not a
    // connect EXECUTE at all. FIRST, because it is the only one of the four
    // that looks at the URI's AUTHORITY — the three below all read a
    // re-qualified path and so read `entity://{them}/system/protocol/connect`
    // as our own connect surface.
    if let Some(refusal) =
        pre_establishment_execute_refusal(&hello_envelope, shared.keypair.peer_id().as_str())
    {
        let frame = encode_envelope(&refusal);
        let _ = write_frame(&mut writer, &frame).await;
        return Err(PeerError::ConnectionError(
            "EXECUTE before the connection was established".into(),
        ));
    }
    // §4.7 row 10 (FM-2): an operation this connect handler does not implement
    // is refused by NAME, ahead of the state match, in every state.
    if let Some(refusal) =
        unknown_connect_operation_refusal(&hello_envelope, shared.keypair.peer_id().as_str())
    {
        let frame = encode_envelope(&refusal);
        let _ = write_frame(&mut writer, &frame).await;
        return Err(PeerError::ConnectionError(
            "unknown connect operation on the first frame".into(),
        ));
    }
    if let Some(refusal) = prehello_authenticate_refusal(&hello_envelope) {
        let frame = encode_envelope(&refusal);
        let _ = write_frame(&mut writer, &frame).await;
        return Err(PeerError::ConnectionError(
            "authenticate before hello: no nonce has been issued on this connection".into(),
        ));
    }
    // §4.7 out-of-order row → 409. Third and last, because both refusals above
    // claim inputs that would otherwise land here: an unimplemented name is not
    // out of order, and a pre-hello `authenticate` is pinned to 401 by row 6.
    // What reaches this in `AwaitingHello` is `ping` — implemented, and a
    // keepalive for a connection that does not exist yet.
    if let Some(refusal) = out_of_order_connect_operation_refusal(
        &hello_envelope,
        shared.keypair.peer_id().as_str(),
        "hello",
    ) {
        let frame = encode_envelope(&refusal);
        let _ = write_frame(&mut writer, &frame).await;
        return Err(PeerError::ConnectionError(
            "connect operation out of order where hello was expected".into(),
        ));
    }

    let hello_response = match build_hello_response_envelope(&hello_envelope, &mut conn) {
        Ok(env) => env,
        Err(e) => {
            // 0.8.2.5 retired `handshake_failed`; the residual class is
            // §4.7's `invalid_request`. See `handshake_error_envelope`.
            let err_env = handshake_error_envelope(&hello_envelope, &e, "invalid_request");
            let frame = encode_envelope(&err_env);
            let _ = write_frame(&mut writer, &frame).await;
            return Err(PeerError::ConnectionError(format!("process hello: {}", e)));
        }
    };
    let response_frame = encode_envelope(&hello_response);
    write_frame(&mut writer, &response_frame)
        .await
        .map_err(|e| PeerError::ConnectionError(format!("write hello response: {}", e)))?;

    // --- Phase 3+4: Receive authenticate → send authenticate response ---
    tracing::debug!("awaiting remote authenticate");
    // §4.11 again, at the handshake's SECOND frame — same reason and same shape
    // as the hello read above. `AwaitingAuthenticate` is still pre-`Established`,
    // so the initiator is still in a state where a silent close is
    // indistinguishable from the peer being down.
    let frame = match read_frame(&mut reader, DEFAULT_MAX_FRAME_SIZE).await {
        Ok(f) => f,
        Err(e) => {
            if !is_clean_eof(&e) {
                let (status, code) = preadmission_disposition(&e);
                write_preadmission_refusal(&mut writer, "", status, code, &e.to_string()).await;
            }
            return Err(PeerError::ConnectionError(format!(
                "read authenticate: {}",
                e
            )));
        }
    };
    let auth_envelope = match decode_envelope(&frame) {
        Ok(e) => e,
        Err(e) => {
            let (status, code) = preadmission_disposition(&e);
            write_preadmission_refusal(&mut writer, "", status, code, &e.to_string()).await;
            return Err(PeerError::ConnectionError(format!(
                "decode authenticate: {}",
                e
            )));
        }
    };

    // CE-1 again, at the handshake's SECOND frame. `AwaitingAuthenticate` is
    // still pre-`Established` — a hello has been exchanged but no signer has
    // been verified — so §4.2 rule 3 binds here exactly as it binds the first
    // frame. Same order and same reason: the authority check comes first.
    if let Some(refusal) =
        pre_establishment_execute_refusal(&auth_envelope, shared.keypair.peer_id().as_str())
    {
        let frame = encode_envelope(&refusal);
        let _ = write_frame(&mut writer, &frame).await;
        return Err(PeerError::ConnectionError(
            "EXECUTE where authenticate was expected: the connection is not established".into(),
        ));
    }
    // §4.7 row 10 again, at the handshake's SECOND frame. The unknown-operation
    // refusal is state-independent, so it binds `AwaitingAuthenticate` exactly
    // as it binds `AwaitingHello` — and this is the arm that would otherwise
    // report a nonsense operation name as `401 authentication_failed`, because
    // `process_authenticate` rejects a non-`authenticate` frame as a failed
    // authenticate rather than as an unimplemented name.
    if let Some(refusal) =
        unknown_connect_operation_refusal(&auth_envelope, shared.keypair.peer_id().as_str())
    {
        let frame = encode_envelope(&refusal);
        let _ = write_frame(&mut writer, &frame).await;
        return Err(PeerError::ConnectionError(
            "unknown connect operation where authenticate was expected".into(),
        ));
    }
    // §4.7 out-of-order row → 409, at the handshake's SECOND frame. This is the
    // state the spec's own example names — "a second `hello` after
    // `hello_done`" — and the one we answered `400 authentication_failed`,
    // because `process_authenticate` rejects a non-`authenticate` frame as a
    // failed authenticate rather than as a misordered one. No carve-out
    // competes for precedence here: `prehello_authenticate_refusal` is scoped
    // to `AwaitingHello` by its own contract, and an `authenticate` in THIS
    // state is exactly the frame we are waiting for.
    if let Some(refusal) = out_of_order_connect_operation_refusal(
        &auth_envelope,
        shared.keypair.peer_id().as_str(),
        "authenticate",
    ) {
        let frame = encode_envelope(&refusal);
        let _ = write_frame(&mut writer, &frame).await;
        return Err(PeerError::ConnectionError(
            "connect operation out of order where authenticate was expected".into(),
        ));
    }

    let auth_response =
        match build_authenticate_response_envelope(&auth_envelope, &mut conn, &shared) {
            Ok(env) => env,
            Err(e) => {
                let err_env = handshake_error_envelope(&auth_envelope, &e, "authentication_failed");
                let frame = encode_envelope(&err_env);
                let _ = write_frame(&mut writer, &frame).await;
                return Err(PeerError::ConnectionError(format!(
                    "process authenticate: {}",
                    e
                )));
            }
        };
    let auth_frame = encode_envelope(&auth_response);
    write_frame(&mut writer, &auth_frame)
        .await
        .map_err(|e| PeerError::ConnectionError(format!("write auth response: {}", e)))?;

    // `remote_peer_id` is now populated on conn after authenticate.
    let remote_peer_id = conn
        .remote_peer_id
        .clone()
        .expect("remote_peer_id set after process_authenticate");
    // The remote's authored identity hash — guaranteed Some after
    // `process_authenticate`. Hoisted to the loop scope: both the reentry
    // endpoint (below) and the §6.5 reentry-grant intercept (in the message
    // loop) need it.
    let remote_identity_hash = conn
        .remote_identity_hash
        .expect("remote identity hash set after authenticate");
    tracing::info!("handshake complete with {}", remote_peer_id);

    // --- Message loop ---
    //
    // V7 §4.8 (v7.48) — inbound frame processing concurrency invariant.
    // The inbound frame reader MUST NOT block on outbound dispatch on the
    // same connection. Dispatch is spawned; the writer half lives in its
    // own task and serializes outbound frames through an mpsc channel.
    // Concurrency is bounded by a semaphore (MAY clause).
    tracing::debug!(remote_peer = %remote_peer_id, "entering message loop");

    let (resp_tx, mut resp_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

    // Writer task: drains the response channel and writes frames serially.
    let writer_peer_id = remote_peer_id.clone();
    crate::runtime::spawn(async move {
        while let Some(frame) = resp_rx.recv().await {
            tracing::trace!(remote_peer = %writer_peer_id, response_size = frame.len(), "sending response");
            if let Err(e) = write_frame(&mut writer, &frame).await {
                tracing::warn!(remote_peer = %writer_peer_id, error = %e, "writer task: write failed; closing");
                break;
            }
        }
    });

    // Bound dispatch concurrency. The §4.8 MAY clause permits this; the
    // bound keeps a flood of inbound EXECUTEs from spawning unbounded
    // dispatch tasks. The number is intentionally generous — the goal is
    // backpressure, not serialization.
    let dispatch_sem = Arc::new(tokio::sync::Semaphore::new(64));

    // --- §6.11(b) reentry endpoint over this accepted connection ---
    //
    // GUIDE-CONFORMANCE §7a / V7 §6.11(b): a handler dispatching back to the
    // peer that dialed us must reuse THIS socket — that peer may run no
    // listener (the validator's B-role-no-listener case). Register a
    // bidirectional endpoint sharing the serial writer channel (`resp_tx`)
    // and a demux table (`reentry_pending`); the read loop below routes
    // inbound EXECUTE_RESPONSE frames into that table. `get_or_connect`
    // falls back to this endpoint when the peer has no dialable transport.
    let reentry_pending = crate::remote::new_pending();
    // Held as the concrete type as well as the trait object: the teardown below
    // must tell *this* endpoint its connection is over, which is an inherent
    // call. `RemoteEndpoint` deliberately grows no teardown method — nothing
    // outside the loop that owns a connection may declare it finished.
    let mut reentry_concrete: Option<Arc<crate::remote::InboundReentryEndpoint>> = None;
    let reentry_endpoint: Option<Arc<dyn crate::remote::RemoteEndpoint>> = {
        // `remote_identity_hash` hoisted above (guaranteed Some after auth).
        // Placeholder connection cap (never read on the reentry path —
        // dispatch always supplies the explicit §7a.2a cap). Prefer the
        // connection cap we just minted; fall back to our identity entity.
        let placeholder_cap = match auth_response
            .included
            .values()
            .find(|e| e.entity_type == entity_types::TYPE_CAP_TOKEN)
        {
            Some(c) => Some(c.clone()),
            None => shared.keypair.peer_entity().ok(),
        };
        match placeholder_cap {
            Some(cap) => {
                let concrete = Arc::new(crate::remote::InboundReentryEndpoint::new(
                    remote_peer_id.to_string(),
                    remote_identity_hash,
                    cap,
                    resp_tx.clone(),
                    reentry_pending.clone(),
                ));
                let endpoint: Arc<dyn crate::remote::RemoteEndpoint> = concrete.clone();
                reentry_concrete = Some(concrete);
                shared
                    .remote
                    .register_inbound(remote_peer_id.as_str(), endpoint.clone());
                Some(endpoint)
            }
            None => {
                tracing::warn!(
                    remote_peer = %remote_peer_id,
                    "reentry: could not build endpoint cap; reentry disabled for this connection"
                );
                None
            }
        }
    };
    // Tear down the reentry endpoint whenever this connection loop exits
    // (clean EOF, read error, or task abort). Two responsibilities:
    //   1. `connection_over()` — drop the endpoint's writer handle, so a
    //      reentry dispatch arriving AFTER the loop ends fails at once instead
    //      of at the request deadline, and the socket's write half is released
    //      (that handle is what keeps the writer task, and the write half it
    //      owns, alive).
    //   2. Clear `reentry_pending` so any in-flight reentry caller resolves
    //      immediately with a connection error. Mirrors the dialer-side
    //      `spawn_reader_loop`, which marks and clears in the same order and
    //      covers the same two cases.
    //
    // **It deliberately does NOT deregister the endpoint any more**, and that
    // reversal is the fix, not an omission. This teardown is the acceptor's
    // half of a §6.5 link — the offerer rule decides which side dials, so one
    // vanished counterpart is a dead `RemoteConnection` on one browser and a
    // dead accepted connection on the other. Deregistering here evicted the
    // binding, and `demote_peer_on_transport_error` fires only while the failed
    // endpoint is *still* bound: the eviction disarmed the demotion the next
    // dispatch was about to trigger, and with the registration gone
    // `get_or_connect` then missed the inbound fallback and failed at
    // resolution, with no endpoint to demote either. Nothing ever wrote
    // `suspect`. Measured in `entity-browser-rust`'s `make e2e-webrtc-vanish`:
    // the acceptor half never noticed at all while the dialer half noticed in
    // 0.5s — bimodal by handshake role.
    //
    // Leaving it registered is safe because it now fails fast: the next
    // dispatch gets a transport error, the §A1 seam evicts and demotes, and the
    // one after that re-establishes. `register_inbound` is an unconditional
    // insert, so a reconnect from the same peer replaces it — which is also why
    // dropping the old `Arc::ptr_eq` teardown check costs nothing: the state is
    // now per-endpoint, so an older connection's teardown cannot touch a newer
    // connection the way a map removal could.
    //
    // Stated cost: a peer that dialed us, went away, and is never dispatched at
    // again leaves one endpoint husk in the registry until it reconnects. It
    // holds no channel and no socket — see `connection_over` — and it is the
    // same bargain the outbound pool already makes with a dead
    // `RemoteConnection`.
    struct ReentryGuard {
        endpoint: Option<Arc<crate::remote::InboundReentryEndpoint>>,
        pending: crate::remote::Pending,
    }
    impl Drop for ReentryGuard {
        fn drop(&mut self) {
            // Mark first, then clear — the two halves must not leave a gap for
            // a caller that lands between them.
            if let Some(ep) = &self.endpoint {
                ep.connection_over();
            }
            self.pending.lock().unwrap().clear();
        }
    }
    // §6.5 mutual minting: keep a handle to the reentry endpoint so the message
    // loop's `reentry-grant` intercept can install the reciprocal capability the
    // dialer mints for us.
    let reentry_ep_handle = reentry_endpoint;
    let _reentry_guard = ReentryGuard {
        endpoint: reentry_concrete,
        pending: reentry_pending.clone(),
    };

    loop {
        let frame = match read_frame(&mut reader, DEFAULT_MAX_FRAME_SIZE).await {
            Ok(f) => f,
            Err(entity_wire::WireError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                tracing::debug!(remote_peer = %remote_peer_id, "remote disconnected (EOF)");
                return Ok(()); // Clean disconnect
            }
            // ⛔ **§4.11 pre-admission refusal, the two arms that DESYNC the
            // stream** (0.8.2.25). Both owe a coded frame before the close;
            // what they cannot have is the `continue` the decode arm below
            // gets, because in each case the bytes the length prefix promised
            // were never consumed and the next read would land mid-frame.
            //
            // Until 0.8.2.25 both of these were a bare `Err` — a **bare
            // close**, which §4.11 names as one of the class's two distinct
            // non-conformances: it is indistinguishable from a network fault,
            // so the caller cannot tell a defect in its own request from a
            // defect in the path, and the two remedies are opposite.
            //
            // The code is the CAUSE's, never the class's: an oversize frame is
            // §4.10(a)'s `413 payload_too_large` and a truncated one is the
            // framing arm's `400 invalid_request`. `413` on a truncated frame
            // would send an honest caller to shrink a payload that was the
            // right size, and that is the mistake §4.11 exists to forbid.
            // A genuine transport break — reset, broken pipe, TLS failure. NOT a
            // §4.11 member: the class is about frames *this peer refuses*, and
            // there is no refusal here and nobody left to answer. Kept as its own
            // arm rather than folded into the refusal below, because answering a
            // dead socket with `400 invalid_request` would blame the caller's
            // bytes for the network's failure — and would swallow the error the
            // caller of `handle_connection` uses to distinguish the two.
            Err(entity_wire::WireError::Io(e)) => {
                return Err(PeerError::ConnectionError(format!("read frame: {}", e)));
            }
            Err(e) => {
                let (status, code) = preadmission_disposition(&e);
                tracing::warn!(
                    remote_peer = %remote_peer_id,
                    error = %e,
                    status, code,
                    "pre-admission refusal at the frame read (§4.11)"
                );
                // Uncorrelated by construction, for BOTH arms. The oversize arm
                // refuses at the length prefix, so the body — and the
                // `request_id` inside it — was never read; the truncated arm
                // never got a whole body to look in. §4.11 provides for exactly
                // this with its *"otherwise a best-effort coded frame carrying no
                // correlation"*.
                send_preadmission_refusal(&resp_tx, "", status, code, &e.to_string());
                return Ok(());
            }
        };

        tracing::trace!(remote_peer = %remote_peer_id, frame_size = frame.len(), "received frame");

        let envelope = match decode_envelope(&frame) {
            Ok(e) => {
                // GUIDE-INSPECTABILITY v1.2 §2.1 #5 wire-recv hook —
                // success path with the envelope's request_id.
                let req_id = extract_request_id(&e).unwrap_or_default();
                fire_wire_hooks(
                    &shared,
                    crate::WireDirection::Recv,
                    &req_id,
                    &frame,
                    remote_peer_id.as_str(),
                );
                e
            }
            Err(e) => {
                // §2.1 #5 wire-recv hook — failure path. Per spec "every
                // inbound frame" — malformed frames fire with empty
                // request_id. This is the F-CIMP-7-class observability
                // case (bytes-on-wire diverged from expected shape) the
                // wire recorder exists to catch.
                fire_wire_hooks(
                    &shared,
                    crate::WireDirection::Recv,
                    "",
                    &frame,
                    remote_peer_id.as_str(),
                );

                // ⛔ **A mis-keyed `included` map is ANSWERED, not dropped**
                // (§5.2a decode-boundary corollary + §4.1, 0.8.2.23).
                //
                // Every other decode failure lands in the `continue` below and
                // that is right: un-parseable bytes carry no `request_id`, so
                // there is nothing to address a refusal to. This one is
                // different and was being treated the same. The envelope is
                // structurally *fine* — the root decodes, the request_id is
                // sitting in it — and only the `included` keying is wrong, so
                // §4.1's "every EXECUTE receives a response" binds and §5.2a
                // names the answer.
                //
                // What we shipped instead was a **silent drop**: no response, no
                // close, the caller blocked until its own timeout. That is
                // fail-closed and unobservable, which is the weaker of the two
                // dispositions core-go's `ROUTING-2026-09-13-f` finding (1) asks
                // arch to choose between — their peer at least closes the
                // connection. A caller cannot tell a refusal from a lost frame,
                // and no conformance vector can score a peer that answers
                // nothing.
                //
                // The connection stays up deliberately. The far side sent one
                // bad envelope, not a bad stream; tearing down a multiplexed
                // connection would take every unrelated in-flight request with
                // it, and §5.2a's corollary contemplates a coded answer
                // precisely so it need not.
                if let entity_wire::WireError::IncludedKeyMismatch { .. } = e {
                    // Root-only decode: the part of the envelope that is not in
                    // question. Nothing but `request_id` is read from it —
                    // `decode_envelope_root` says why at its own definition.
                    let request_id = entity_wire::decode_envelope_root(&frame)
                        .ok()
                        .and_then(|root| {
                            let value: ciborium::Value =
                                ciborium::from_reader(root.data.as_slice()).ok()?;
                            value.as_map()?.iter().find_map(|(k, v)| {
                                (k.as_text() == Some("request_id"))
                                    .then(|| v.as_text().map(String::from))
                                    .flatten()
                            })
                        })
                        .unwrap_or_default();
                    tracing::warn!(
                        remote_peer = %remote_peer_id,
                        request_id = %request_id,
                        error = %e,
                        "refusing envelope: included entry filed under a foreign hash (§1.8)"
                    );
                    // Through `send_preadmission_refusal` like every other arm of
                    // the class (0.8.2.25). This arm predates §4.11 and had its
                    // own inlined emission; §4.11's whole finding is that the
                    // class was specified five times at four strengths because
                    // each instance answered locally, so the emission is one
                    // function now and the arms differ only in `(status, code)`.
                    send_preadmission_refusal(
                        &resp_tx,
                        &request_id,
                        STATUS_BAD_REQUEST,
                        "hash_mismatch",
                        &e.to_string(),
                    );
                    continue;
                }

                // ⛔ **§4.11's framing arm — the SILENT DROP this seat shipped**
                // (0.8.2.25). The comment above used to end here with *"every
                // other decode failure lands in the `continue` below and that is
                // right: un-parseable bytes carry no `request_id`, so there is
                // nothing to address a refusal to."* The premise is true and the
                // conclusion does not follow. §4.11 answers it directly: where
                // the id is unavailable the refusal goes out as a **best-effort
                // coded frame carrying no correlation** — an uncorrelated answer
                // is worth strictly more than none, because a drop is
                // unobservable to the caller until its own §6.11(c) deadline and
                // unobservable to every instrument forever.
                //
                // This was the *silent* half of the three-way split arch measured
                // across the ground-up seats: go bare-closed, we dropped, py
                // answered. §4.11 makes the drop and the bare close two distinct
                // non-conformances rather than one, and ours was the weaker of
                // the two precisely because nothing surfaces it.
                //
                // The code comes from `preadmission_disposition`, which reads the
                // **cause** rather than the arm: `invalid_request` where the
                // bytes did not decode, and **`non_canonical_ecf` where they did
                // and carried a CBOR tag** (§4.11 arm (5a), 0.8.2.26 `DR-3` —
                // that arm reaches here too, because a tagged frame is consumed
                // whole and is therefore `(a1)`-shaped). Specifically **not**
                // `hash_mismatch` (that is the arm three blocks up — nothing on
                // the framing path was ever hashed): *"your bytes are
                // truncated"* is not *"re-key the map"* and is not *"re-encode
                // without the tag"* either.
                //
                // ⚠ The connection SURVIVES, and that is arm (f) of
                // `CORE-PREADMISSION-REFUSAL-1` — the arm nothing else implies.
                // The frame was read WHOLE (the length prefix was honoured and
                // `len` bytes were consumed), so the stream is still synchronized
                // on the next boundary; only the payload is garbage. Tearing the
                // connection down here would fail every unrelated **admitted**
                // request in flight on this multiplexed connection, which §4.9(c)
                // forbids for each of them independently. Contrast the two
                // `read_frame` arms above, which close because the stream there
                // is genuinely desynchronized.
                let (status, code) = preadmission_disposition(&e);
                tracing::warn!(remote_peer = %remote_peer_id, error = %e, status, code, "refusing undecodable frame (§4.11 framing arm)");
                send_preadmission_refusal(
                    &resp_tx,
                    "",
                    status,
                    code,
                    &format!("frame is not a decodable ECF envelope: {e}"),
                );
                continue;
            }
        };

        // §6.11(b) reentry: an inbound EXECUTE_RESPONSE is the reply to an
        // outbound EXECUTE this peer originated back over the accepted
        // connection (via InboundReentryEndpoint). Route it to the waiting
        // dispatcher instead of treating it as a request (which would error).
        if envelope.root.entity_type == entity_types::TYPE_EXECUTE_RESPONSE {
            match entity_protocol::parse_execute_response(&envelope) {
                Ok(resp) => {
                    let rid = resp.request_id.clone();
                    let sender = reentry_pending.lock().unwrap().remove(&rid);
                    match sender {
                        Some(tx) => {
                            let _ = tx.send(resp);
                        }
                        None => tracing::warn!(
                            remote_peer = %remote_peer_id,
                            request_id = %rid,
                            "reentry: EXECUTE_RESPONSE with no pending waiter — dropped"
                        ),
                    }
                }
                Err(e) => tracing::warn!(
                    remote_peer = %remote_peer_id,
                    error = %e,
                    "reentry: failed to parse inbound EXECUTE_RESPONSE — dropped"
                ),
            }
            continue;
        }

        // §6.5 mutual minting: an inbound `reentry-grant` connect-EXECUTE carries
        // the reciprocal capability the dialer minted FOR us (granter = the
        // dialer, grantee = us). Intercept it before generic dispatch — like the
        // EXECUTE_RESPONSE branch above — and install it on our reentry endpoint,
        // giving this acceptor authority to originate back over this same §6.5
        // channel. Self-verifying (the enclosed cap's granter must be the peer we
        // authenticated); the narrow connection grant never has to authorize it.
        // Normative text: `PROPOSAL-SYMMETRIC-REENTRY-MUTUAL-MINTING` in
        // `entity-system-architecture`. (Our in-tree copy of that name is the
        // implementation record — dev history, not part of the source mirror.)
        if envelope.root.entity_type == entity_types::TYPE_EXECUTE {
            if let Ok(fields) = entity_protocol::decode_execute_fields(&envelope.root.data) {
                if fields.operation == "reentry-grant" {
                    accept_reentry_grant(
                        &envelope,
                        remote_peer_id.as_str(),
                        remote_identity_hash,
                        reentry_ep_handle.as_ref(),
                    );
                    continue;
                }
            }
        }

        // ⛔ **§3.3 / §4.11 arm (b) — a root that is neither EXECUTE nor
        // EXECUTE_RESPONSE is REFUSED, and the refusal is coded** (0.8.2.25).
        //
        // §3.3 is the sentence that moved: it used to read *"a frame whose root
        // entity is neither EXECUTE nor EXECUTE_RESPONSE is invalid and the peer
        // MUST close the connection"* — a bare close **mandated**, with no coded
        // frame anywhere in it — and 0.8.2.25 rewrites it to *"MUST answer `400
        // invalid_request` before closing"*, with §4.11 as its normative home and
        // the close demoted to the peer's own choice.
        //
        // We had **no gate here at all**, which is a third disposition again: a
        // third-typed root fell through to `dispatch_request`, where
        // `decode_execute_fields` fails on a root carrying no `uri`/`operation`
        // and the answer comes back as whatever the verification path happens to
        // mint. A code that is *merely in the right family* is still wrong —
        // §4.11's own words for the adjacent arm — and arm (b) of
        // `CORE-PREADMISSION-REFUSAL-1` reads the decoded `code` key.
        //
        // Placement is load-bearing: **after** the EXECUTE_RESPONSE reentry
        // branch and the `reentry-grant` intercept, both of which `continue` out
        // above, so the three admissible shapes on an established connection are
        // exactly the ones already consumed. It is also **before** dispatch, so
        // no third-typed root ever reaches verification.
        //
        // The connection survives, for the same reason and with the same
        // authority as the framing arm above: this frame decoded WHOLE, so the
        // stream is synchronized and §4.9(c) forbids spending the in-flight
        // admitted requests on it.
        if envelope.root.entity_type != entity_types::TYPE_EXECUTE {
            tracing::warn!(
                remote_peer = %remote_peer_id,
                root_type = %envelope.root.entity_type,
                "refusing frame whose root is neither EXECUTE nor EXECUTE_RESPONSE (§3.3)"
            );
            // Best-effort correlation: the root DID decode here, unlike the
            // framing arm, so a `request_id` may be sitting in it and a
            // correlated refusal is worth more to the caller than an
            // uncorrelated one. §4.11 asks for the id "where it is available".
            let request_id = extract_request_id(&envelope).unwrap_or_default();
            send_preadmission_refusal(
                &resp_tx,
                &request_id,
                STATUS_BAD_REQUEST,
                "invalid_request",
                &format!(
                    "root entity is `{}`, which is neither EXECUTE nor EXECUTE_RESPONSE",
                    envelope.root.entity_type
                ),
            );
            continue;
        }

        // Spawn dispatch — the §4.8 invariant fix. Each frame's handler runs
        // concurrently with subsequent reads; the writer task serializes
        // responses back onto the wire.
        let shared_task = shared.clone();
        let resp_tx_task = resp_tx.clone();
        let sem_task = dispatch_sem.clone();
        let remote_peer_id_task = remote_peer_id.clone();
        // Only the network feature reads it; without that feature there is no
        // observe-address responder to reflect anything.
        #[cfg(feature = "network")]
        let accept_source_task = accept_source_addr.clone();
        crate::runtime::spawn(async move {
            let _permit = match sem_task.acquire_owned().await {
                Ok(p) => p,
                Err(_) => return, // semaphore closed → shutting down
            };
            let dispatch = dispatch_request(
                &envelope,
                shared_task.clone(),
                Some(remote_peer_id_task.as_str()),
            );
            // Scoped per request, not per connection: the source belongs to the
            // connection the request arrived on, which is exactly the fact
            // §6.7.1 reflects.
            #[cfg(feature = "network")]
            let response_envelope =
                entity_network::accept_source::scope(accept_source_task.clone(), dispatch).await;
            #[cfg(not(feature = "network"))]
            let response_envelope = dispatch.await;
            let response_frame = encode_envelope(&response_envelope);
            // §2.1 #5 wire-send hook. Fires before pushing the frame onto
            // the writer channel — the envelope is in scope so request_id
            // is recoverable.
            let send_req_id = extract_request_id(&response_envelope).unwrap_or_default();
            fire_wire_hooks(
                &shared_task,
                crate::WireDirection::Send,
                &send_req_id,
                &response_frame,
                remote_peer_id_task.as_str(),
            );
            if resp_tx_task.send(response_frame).is_err() {
                tracing::debug!(remote_peer = %remote_peer_id_task, "writer task gone; dropping response");
            }
        });
    }
}

/// Build the hello-response envelope for a received hello EXECUTE.
///
/// Used by both the stream transports (TCP / WS / memory) inside
/// [`handle_connection`] and by the HTTP-live transport via
/// [`dispatch_session_envelope`]. Mutates `conn.state` from
/// `AwaitingHello` to `AwaitingAuthenticate` on success.
/// §4.2 / §4.6 step 1 / §4.7 row 6 (FM-1) — the pre-hello `authenticate`
/// refusal, in ONE place because both transports had the same defect.
///
/// §4.2's third pre-authorization rule + §5.2a — a **non-connect** EXECUTE
/// arriving before the connection is established is **401
/// `authentication_failed`**; the same frame naming a **foreign namespace** is
/// **400 `invalid_request`**.
///
/// **Call this only in a pre-`Established` state.** Unlike
/// [`unknown_connect_operation_refusal`] it is emphatically *not*
/// state-independent — hoisting it above a state match would refuse every
/// legitimate authenticated EXECUTE on an established connection with a 401.
/// The rule's own subject is "arriving before the handshake completes."
///
/// **It was ruled at 0.8.1 and every one of the three ground-up seats missed
/// it for two releases.** We answered `400 handshake_failed`: the frame is not
/// a connect frame, so none of the three refusals below claim it, and it fell
/// through to `build_hello_response_envelope`, failed there as a non-hello, and
/// exited via `handshake_error_envelope`'s catch-all. go answered `403
/// connection_required` and py `403 capability_denied` — the blanket 403 that
/// §4.2's F32 amendment *retired* at 0.8.1, replacing it with the auth/authz
/// discriminator. The input carries no verified signer at all, so §5.2a makes
/// it **auth-class**: 403 asserts an authorization decision was made about an
/// authenticated caller, which is simply false about this frame.
///
/// `0.8.2.5` restates the rule as a note under §4.7 — a pointer, not a second
/// registry — because §4.7 is the table an implementer is reading when the
/// input arrives, and the rule is written in the vocabulary of
/// *pre-authorization*, which is not reachable from the vocabulary of
/// *connection state*. That note also names `connection_required` and
/// `handshake_failed` non-conformant outright; see
/// [`handshake_error_envelope`] for the second half of that sweep.
///
/// **Address before authentication, and the order is the load-bearing part.**
/// A foreign-namespace EXECUTE is refused *as an address* — §6.5 step 3 calls
/// that "a gate, not an ordering preference" and says it "never becomes an
/// authorization question", and §4.7's `invalid_request` paragraph names "an
/// EXECUTE naming a foreign namespace (§1.4)" as a member of its class on this
/// very surface. So the peer check runs first and answers `400
/// invalid_request`; only an EXECUTE addressed to *us* reaches the 401. Both
/// codes are reachable from this one function on purpose: a test that varies
/// only the namespace is what distinguishes this fix from a blanket relabel of
/// the catch-all, which would answer 401 for both.
///
/// The peer check also has to precede the connect-path check rather than follow
/// it, and that is the escalation shape `dispatch_request`'s §1.4 gate is
/// commented against: `extract_handler_path` drops the authority from
/// `entity://{them}/system/protocol/connect` and `qualify_path` re-attaches
/// **ours**, so a foreign-qualified connect URI reads as our own connect
/// surface to every helper below. Ours is the only pre-`Established` check that
/// looks at the authority, so it is the only place that can refuse it.
fn pre_establishment_execute_refusal(envelope: &Envelope, local_pid: &str) -> Option<Envelope> {
    let fields = entity_protocol::decode_execute_fields(&envelope.root.data).ok()?;

    let target_peer = EntityUri::extract_peer(&fields.uri, local_pid);
    if target_peer != local_pid {
        return Some(
            build_error_response(
                &fields.request_id,
                STATUS_BAD_REQUEST,
                "invalid_request",
                &format!(
                    "handler uri targets peer {}, which is not this peer (§1.4; §4.7's \
                     invalid_request class names the foreign namespace)",
                    target_peer
                ),
            )
            .unwrap_or_else(|_| Envelope::new(envelope.root.clone())),
        );
    }

    // Our own connect surface — §4.7's rows own every refusal on it, including
    // the three helpers below. This is the sole reason this function returns
    // `None` for anything addressed to us.
    if EntityUri::qualify_path(EntityUri::extract_handler_path(&fields.uri), local_pid)
        == format!("/{}/{}", local_pid, entity_protocol::CONNECT_PATH)
    {
        return None;
    }

    Some(
        build_error_response(
            &fields.request_id,
            STATUS_AUTH_FAILED,
            "authentication_failed",
            "EXECUTE on a non-connect path before the connection is established: no \
             handshake has run, so the request carries no verified signer (§4.2 \
             pre-authorization rule 3; §5.2a auth-class; §4.7's 0.8.2.5 note)",
        )
        .unwrap_or_else(|_| Envelope::new(envelope.root.clone())),
    )
}

/// Returns `Some(401 invalid_nonce)` when this frame is a connect-EXECUTE whose
/// operation is `authenticate`. Call it only where the connection is still
/// `AwaitingHello`; there, an `authenticate` is definitionally one that arrived
/// before any nonce was issued.
///
/// **The code string was the symptom; dispatch-on-state was the defect.** Both
/// entry points matched on `conn.state` and never looked at the frame's
/// operation, so a pre-hello `authenticate` was handed to the *hello* path,
/// failed there as a non-hello (`connect.rs`, "expected operation hello"), and
/// exited through `handshake_error_envelope`'s catch-all as **`400
/// handshake_failed`** — a code that appears nowhere in the spec corpus, so
/// non-conformant under any reading of §4.7's MUST-emit contract. Renaming the
/// code at the catch-all would have produced a conformant pair over an incorrect
/// path, and would have reported "invalid nonce" for a genuinely malformed
/// `hello` too. So the discrimination happens on the OPERATION, ahead of the
/// state match, and the catch-all keeps its meaning.
///
/// Why 401 and not a 4xx state-conflict: §4.6 step 1 and §4.7 row 6 pin this
/// input to `401 invalid_nonce`, and §4.7 says outright it is **not** the
/// out-of-order row. A captured `authenticate` replayed onto a fresh connection
/// IS this input — the attack the nonce exists to stop — so it is an
/// authentication failure, not a malformed request. Same status the Hardening
/// block pins for the same-connection replay, which we already emit from
/// `dispatch_request`'s RT-6 intercept. Every OTHER out-of-order connect
/// operation is untouched and still exits through the catch-all.
fn prehello_authenticate_refusal(envelope: &Envelope) -> Option<Envelope> {
    let fields = entity_protocol::decode_execute_fields(&envelope.root.data).ok()?;
    if fields.operation != "authenticate" || !Connection::is_connect_path(&fields.uri) {
        return None;
    }
    Some(
        build_error_response(
            &fields.request_id,
            STATUS_AUTH_FAILED,
            "invalid_nonce",
            "authenticate received before a hello nonce was issued on this connection",
        )
        .unwrap_or_else(|_| Envelope::new(envelope.root.clone())),
    )
}

/// §4.7 row 10, unknown-operation half — **400 `invalid_request`**.
///
/// Returns `Some` when this frame is a connect-path EXECUTE naming an operation
/// outside [`entity_protocol::CONNECT_OPERATIONS`]. State-independent by
/// construction, which is the whole point: arch's ruling is *"a name the
/// responder does not implement, **in any state**"*, so this runs ahead of every
/// state match rather than inside one — the same shape, and the same reason, as
/// [`prehello_authenticate_refusal`] one function up.
///
/// **The two helpers are disjoint and the order between them is immaterial:**
/// `authenticate` is a known operation, so this never fires on FM-1's input.
///
/// We emitted **`400 handshake_failed`** — the same code-with-no-corpus-entry
/// FM-1 found on the neighbouring row, reached the same way: the frame was
/// handed to the hello path, failed there as a non-hello, and exited through
/// `handshake_error_envelope`'s catch-all. Wrong under *every* reading of §4.7.
///
/// **On the value, stated because it is contested and we are landing it early.**
/// §4.7 row 10 as it stands in the landed text (0.8.2.3) names an unknown
/// connect operation as `connection_sequence_error`. Arch **ruled** that row on
/// 2026-09-01 (`ROUTING-2026-09-01-c` §2, derived in
/// `PROPOSAL-CONNECT-SURFACE-RECONCILIATION` §4): the row is two failures, and
/// an unknown *name* is not an ordering error — `connection_sequence_error`
/// tells a client its sequencing was wrong when its operation name was, which
/// fails the contract the table exists to provide. The **ruling** is what this
/// code implements; the **fold** is FM-2 Edit D, still DRAFT, gated on
/// confirmations from us and py that have nothing to do with row 10. Our earlier
/// note here said this row *"gets no discriminating behaviour until it is
/// ruled"* — that condition is met, and `entity-core-py` and `entity-core-go`
/// already emits and gates it. (`entity-core-py` does **not** — it answers
/// `connection_sequence_error`, so it owes this row too; we are the second seat
/// here, not the last.) If the fold moves the value, one constant below and one
/// constant in the test change; nothing else does.
///
/// `local_pid` is taken rather than assumed because a connect EXECUTE reaches
/// this in **two spellings**, and the peer-relative one is only the handshake's.
/// Pre-hello the initiator does not know our peer-id so it sends
/// `system/protocol/connect`; post-Established a client sends the fully
/// qualified `/{pid}/system/protocol/connect` (§4.3 permits either). Testing
/// with `Connection::is_connect_path` — which only strips an `entity://`
/// scheme — matches the first and **silently misses the second**, so the
/// post-Established arm would have refused nothing at all. Found by probing
/// whether a real `ping` reached this function, not by reading it.
fn unknown_connect_operation_refusal(envelope: &Envelope, local_pid: &str) -> Option<Envelope> {
    let fields = entity_protocol::decode_execute_fields(&envelope.root.data).ok()?;
    let qualified =
        EntityUri::qualify_path(EntityUri::extract_handler_path(&fields.uri), local_pid);
    if qualified != format!("/{}/{}", local_pid, entity_protocol::CONNECT_PATH)
        || entity_protocol::CONNECT_OPERATIONS.contains(&fields.operation.as_str())
    {
        return None;
    }
    Some(
        build_error_response(
            &fields.request_id,
            STATUS_BAD_REQUEST,
            "invalid_request",
            &format!(
                "system/protocol/connect implements no operation {:?} (§4.7 row 10, \
                 unknown-operation half)",
                fields.operation
            ),
        )
        .unwrap_or_else(|_| Envelope::new(envelope.root.clone())),
    )
}

/// §4.7's out-of-order row — **409 `connection_sequence_error`** — for the
/// pre-Established handshake states.
///
/// Returns `Some` when this frame is a connect-path EXECUTE naming an operation
/// the responder DOES implement, arriving in a handshake state that forbids it.
/// `expected` is the one operation this state accepts.
///
/// **This is the fold's other half, and nobody routed it.** 0.8.2.4 split the
/// old out-of-order row in two: the unknown-*name* half became `400
/// invalid_request` ([`unknown_connect_operation_refusal`], which we landed),
/// and the state half kept `connection_sequence_error` but its status **moved
/// 400 → 409**, matching `connection_already_established` in the row directly
/// above it. The relay we were sent named only the `protocols` item and said
/// *"rows 1 and 10 as you built them are conformant; nothing you shipped
/// moves"* — both true, and neither covers this, because we had never shipped
/// this row at all. It is a §9.1 conformance line ("an operation the responder
/// implements, arriving in a forbidden state, emits 409
/// `connection_sequence_error`"), found by recomputing the fold against our own
/// tree rather than by reading the delta we were handed.
///
/// **What we emitted instead was a pair in no row of §4.7.** A second `hello`
/// arriving where `authenticate` was expected is an operation we implement, so
/// the row-10 helper passes it through by construction; it then reached
/// `process_authenticate`, failed there as a non-`authenticate`
/// (`ProtocolError::Invalid`), and exited through `handshake_error_envelope` —
/// whose status comes from the error (400) and whose code comes from that call
/// site's default (`authentication_failed`). **`400 authentication_failed`
/// appears in no row of the table**, and it reads to the caller as "your
/// credentials failed" when the credentials were never examined. That is the
/// identical defect shape FM-1 fixed one row over and the one `entity-core-py`
/// was corrected for at `400 invalid_nonce`: §4.7 obligates the **pair**, so a
/// right code under a wrong status is non-conformant too.
///
/// **Precedence, and each step of it is pinned by a spec sentence rather than
/// by convenience.** This runs AFTER both existing refusals and the order is
/// load-bearing, not presentation:
///
/// 1. An operation we do not implement is not out of order at all — "it exists
///    in no state", so [`unknown_connect_operation_refusal`] wins and answers
///    `400 invalid_request`. Running this helper first would report a
///    *sequencing* failure for a frame whose defect is its *name*.
/// 2. A pre-hello `authenticate` IS an implemented operation in a forbidden
///    state, so it would land here — and §4.7 says outright it is **not** the
///    out-of-order row, pinning it to `401 invalid_nonce` (§4.2, §4.6 step 1,
///    row 6). [`prehello_authenticate_refusal`] therefore keeps precedence, and
///    this helper is never called in `AwaitingHello` with `authenticate`.
///    That carve-out is the reason `expected` is a parameter instead of this
///    function deriving the state itself: the two forbidden-in-`AwaitingHello`
///    operations take different rows, and only one of them is ours.
///
/// Post-Established is not this function's surface — `dispatch_request` owns
/// those two rows (`connection_already_established` for a second `hello`, `401
/// invalid_nonce` for a replayed `authenticate`) and already emits both.
///
/// The membership test is `CONNECT_OPERATIONS`, the same single inventory the
/// row-10 helper and `bootstrap_handler` read, so "an operation the responder
/// implements" has exactly one spelling in this tree.
fn out_of_order_connect_operation_refusal(
    envelope: &Envelope,
    local_pid: &str,
    expected: &str,
) -> Option<Envelope> {
    let fields = entity_protocol::decode_execute_fields(&envelope.root.data).ok()?;
    let qualified =
        EntityUri::qualify_path(EntityUri::extract_handler_path(&fields.uri), local_pid);
    if qualified != format!("/{}/{}", local_pid, entity_protocol::CONNECT_PATH)
        || fields.operation == expected
        || !entity_protocol::CONNECT_OPERATIONS.contains(&fields.operation.as_str())
    {
        return None;
    }
    Some(
        build_error_response(
            &fields.request_id,
            STATUS_CONFLICT,
            "connection_sequence_error",
            &format!(
                "connect operation {:?} is not accepted in this connection state; \
                 expected {:?} (§4.7 out-of-order row)",
                fields.operation, expected
            ),
        )
        .unwrap_or_else(|_| Envelope::new(envelope.root.clone())),
    )
}

pub(crate) fn build_hello_response_envelope(
    hello_envelope: &Envelope,
    conn: &mut Connection,
) -> Result<Envelope, PeerError> {
    let (our_hello, hello_request_id) = conn
        .process_hello(hello_envelope)
        .map_err(PeerError::Protocol)?;
    tracing::debug!(request_id = %hello_request_id, "received remote hello, building hello response");

    let our_hello_entity = our_hello
        .to_entity()
        .map_err(|e| PeerError::ConnectionError(format!("build hello entity: {}", e)))?;
    let hello_response = build_execute_response(&hello_request_id, 200, our_hello_entity)
        .map_err(|e| PeerError::ConnectionError(format!("build hello response: {}", e)))?;
    Ok(hello_response)
}

/// §6.5 mutual minting: validate an inbound `reentry-grant` and install the
/// reciprocal capability on our acceptor endpoint, giving us originating
/// authority back over this connection. Best-effort — a malformed or
/// mis-granted frame is logged and dropped, leaving us without originating
/// authority (the pre-mutual-minting state), never breaking the connection.
/// Normative text: `PROPOSAL-SYMMETRIC-REENTRY-MUTUAL-MINTING` in
/// `entity-system-architecture`.
fn accept_reentry_grant(
    envelope: &Envelope,
    remote_peer_id: &str,
    remote_identity_hash: entity_hash::Hash,
    endpoint: Option<&Arc<dyn crate::remote::RemoteEndpoint>>,
) {
    let endpoint = match endpoint {
        Some(ep) => ep,
        None => return, // reentry disabled for this connection — nothing to hold it
    };
    // The reciprocal cap is the sole capability-token carried in `included`.
    let cap = match envelope
        .included
        .values()
        .find(|e| e.entity_type == entity_types::TYPE_CAP_TOKEN)
    {
        Some(c) => c.clone(),
        None => {
            tracing::warn!(
                remote_peer = %remote_peer_id,
                "§6.5 reentry-grant: no capability token in included — dropped"
            );
            return;
        }
    };
    // Structural integrity: the claimed content hash must recompute (a
    // substituted entity would otherwise index under the wrong hash).
    if cap.validate().is_err() {
        tracing::warn!(
            remote_peer = %remote_peer_id,
            "§6.5 reentry-grant: capability failed hash validation — dropped"
        );
        return;
    }
    // The grant MUST be authored (granter) by the peer we authenticated. A cap
    // with any other granter is useless anyway — the far side verifies
    // `granter == its own identity` at use-time — but rejecting here keeps the
    // authority we store honest and attributable.
    match entity_capability::CapabilityToken::from_entity(&cap) {
        Ok(token) => match token.granter {
            entity_capability::Granter::Single(g) if g == remote_identity_hash => {}
            _ => {
                tracing::warn!(
                    remote_peer = %remote_peer_id,
                    "§6.5 reentry-grant: granter is not the connected peer — dropped"
                );
                return;
            }
        },
        Err(e) => {
            tracing::warn!(
                remote_peer = %remote_peer_id,
                error = %e,
                "§6.5 reentry-grant: capability decode failed — dropped"
            );
            return;
        }
    }
    // Fail-fast on the granter signature, here at acceptance, instead of letting
    // the far side's chain walk be the only thing that ever checks it. An
    // unverifiable grant can authorize nothing, so installing it only trades this
    // named local drop for a `403 missing_signature` one dispatch later — at the
    // cross-peer seam, where it is hardest to attribute. Same three checks the
    // §5.5 walk runs on a single-sig root link (signature present for this
    // target, signer == granter, signature verifies under the granter's key),
    // and nothing more: the grantee/attenuation legs of the walk need entities
    // this frame does not carry.
    if let Err(reason) = verify_grant_signature(envelope, &cap, remote_identity_hash) {
        tracing::warn!(
            remote_peer = %remote_peer_id,
            reason = %reason,
            "§6.5 reentry-grant: granter signature did not verify — dropped"
        );
        return;
    }
    // Only the cap is retained. Its supporting entities (the granter signature
    // and identity) travel in this grant frame and are consumed by the
    // `verify_grant_signature` check just above — they are deliberately NOT
    // stored for re-injection, because we wield this cap **by reference**: the
    // envelope's `capability` hash is the reference, and the granter resolves
    // the cap from the ledger it minted it into (arch `cbe9dff`).
    endpoint.set_originating_capability(cap);
    tracing::info!(
        remote_peer = %remote_peer_id,
        "§6.5: accepted reciprocal reentry grant — this acceptor may now originate"
    );
}

/// The single-sig signature leg of the §5.5 chain walk, run at grant-acceptance
/// time on the reciprocal cap. Returns the reason on failure so the caller logs
/// something attributable. Deliberately not `verify_capability_chain`: that also
/// resolves the *grantee* identity out of `included`, and the grantee here is
/// **us** — our own identity entity is not in a grant the dialer authored, so
/// the full walk would reject every well-formed grant.
fn verify_grant_signature(
    envelope: &Envelope,
    cap: &entity_entity::Entity,
    granter_hash: entity_hash::Hash,
) -> Result<(), &'static str> {
    let sig =
        entity_entity::find_signature_for_target(envelope.included.values(), &cap.content_hash)
            .ok_or("no signature entity targets the capability")?;
    let sig_data =
        entity_types::SignatureData::from_entity(sig).map_err(|_| "signature decode failed")?;
    if sig_data.signer != granter_hash {
        return Err("signer is not the granter");
    }
    let granter_entity = envelope
        .included
        .get(&granter_hash)
        .ok_or("granter identity entity absent from included")?;
    let granter = entity_types::PeerData::from_entity(granter_entity)
        .map_err(|_| "granter identity decode failed")?;
    let key_type = entity_crypto::KeyType::from_label(&granter.key_type)
        .map_err(|_| "unallocated key_type")?;
    entity_crypto::verify_for_key_type(
        key_type,
        &granter.public_key,
        &cap.content_hash.to_bytes(),
        &sig_data.signature,
    )
    .map_err(|_| "signature does not verify under the granter's key")
}

/// The §4.4 initial-scope assembly: the grants this peer issues a counterpart
/// that dials **in** — the resolver's answer (EXTENSION-ROLE §4.7) or the static
/// floor, unioned with any matching `system/capability/policy/{peer}` entry.
///
/// **One assembly, two callers** (arch ruling 2026-08-05, EXTENSION-SIGNALING
/// §6.5 (b) *Contents*): the §6.6 handshake below, and the §6.5 (b) reciprocal
/// mint in [`crate::remote::build_reentry_grant_envelope`]. The reciprocal grant
/// is *the grant the minting peer would issue this counterpart as an inbound
/// dialer* — the assembled set, **not** the flat `default_connection_grants`
/// floor. Minting the bare floor while an inbound dialer receives the assembled
/// set gives the establishment whose justification is *symmetry* asymmetric
/// authority; both impls shipped that defect and `entity-core-go` measured it.
///
/// The mirror is symmetric **construction**, not identical grant sets: each peer
/// runs its own assembly against the counterpart, so A→B and B→A differ exactly
/// as A's and B's policy tables differ. That is correct — authority is
/// target-owned. There is no separate reciprocal-narrowing pass: the §4.4 union
/// happens here, once, in the one policy table.
///
/// A second copy of this logic is how the two directions drifted apart in the
/// first place, so the extraction is the fix as much as the call site is.
pub(crate) fn assemble_inbound_grants(
    shared: &Arc<PeerShared>,
    grantee_hash: &entity_hash::Hash,
    remote_peer_id: &entity_crypto::PeerId,
) -> Vec<entity_capability::GrantEntry> {
    // Resolver-first, static fallback. Matches the recognize-on-attestation
    // handoff §7 / Go's reference.
    let static_fallback = || {
        if shared.config.debug_open_grants {
            tracing::warn!("using debug open grants — all operations permitted");
            entity_capability::debug_open_grants()
        } else {
            entity_capability::default_connection_grants()
        }
    };
    let mut grants = if let Some(resolver) = shared.grant_resolver.as_ref() {
        match resolver(remote_peer_id, grantee_hash) {
            Some(g) => {
                tracing::debug!(
                    grant_count = g.len(),
                    "grant resolver returned connection grants"
                );
                g
            }
            None => static_fallback(),
        }
    } else {
        static_fallback()
    };
    // V7.62 §4.4 policy-table consultation: union the SHOULD floor with
    // any matched `system/capability/policy/{peer_pattern}` entry for
    // the connecting peer. Conditional on the capability handler being
    // registered (no-op when absent — backward-compat for peers without
    // the §6.2 handler).
    if shared
        .handler_registry
        .get(&format!("/{}/system/capability", shared.peer_id))
        .is_some()
    {
        if let Some(extras) =
            lookup_capability_policy_grants(shared, grantee_hash, remote_peer_id.as_str())
        {
            tracing::debug!(
                added = extras.len(),
                "§4.4 union: policy entry added grants to initial scope"
            );
            grants.extend(extras);
        }
    }
    // §3 advertisement discipline: a peer MUST NOT grant authority it does not
    // advertise it serves (arch ruling 2026-08-05). Applied here, once, so the
    // §6.6 handshake and the §6.5 (b) reciprocal mint filter identically.
    //
    // Skipped under `debug_open_grants`, which is documented as bypassing all
    // authorization scoping — its wildcard handler scope is covered by no
    // single registered handler, so filtering would empty it. A posture that
    // already says "never use in production" does not get a second, subtler
    // production-only guarantee layered under it.
    if shared.config.debug_open_grants {
        return grants;
    }
    let advertised = advertised_served_scope(shared);
    let before = grants.len();
    grants.retain(|entry| {
        entity_capability::advertisement_covers(&advertised, entry, shared.peer_id.as_str())
    });
    if grants.len() != before {
        tracing::debug!(
            dropped = before - grants.len(),
            retained = grants.len(),
            "§3 advertisement filter dropped uncovered grant entries"
        );
    }
    grants
}

/// The **advertised served-scope** this peer filters its §4.4 assembly
/// against: one grant entry per registered handler, naming that handler with
/// the other three axes unconstrained.
///
/// **The unexpressed axes are unconstrained, not empty.** A handler manifest
/// says which handler and (here) which operations; it says nothing about
/// resources or peers. Reading an unexpressed axis as *empty* would make the
/// §4.4 floor filter itself away — its first entry carries
/// `resources: [system/type/*, system/handler/*]` — so *unconstrained* is the
/// only reading under which the ruling has a fixed point.
///
/// **`operations` is `*` deliberately, and it is the one place we did not
/// build to our own reading.** Our interface entities *do* express an
/// operations list, so constraining that axis is the more faithful reading of
/// "MUST NOT grant authority it does not advertise it serves". `entity-core-go`
/// (`advertisedServedScope`, `core/peer/peer.go`) advertises `*` and routes the
/// per-handler narrowing through a handler-declared `MaxScope` instead. The
/// filter only ever *drops*, so a stricter reading here would hand a
/// counterpart strictly less authority than a Go peer in the same
/// configuration — an observable cross-impl divergence in grant contents, for a
/// question arch has not ruled on. Converged and routed rather than shipped.
///
/// Evaluated at assembly time, which is the only time the assembly exists: a
/// handler registered a second later was not advertised when the grant was
/// authored, and the grant is not retroactively widened.
fn advertised_served_scope(shared: &Arc<PeerShared>) -> Vec<entity_capability::GrantEntry> {
    let qualified_prefix = format!("/{}/", shared.peer_id);
    shared
        .handler_registry
        .patterns()
        .into_iter()
        .map(|pattern| {
            // Registry keys are peer-qualified (`/{peer_id}/system/tree`);
            // grant handler scopes are bare (`system/tree`) and canonicalize
            // to the qualified form. Compare in the bare frame so both sides
            // canonicalize under `local_peer_id` identically.
            let bare = pattern
                .strip_prefix(&qualified_prefix)
                .unwrap_or(&pattern)
                .to_string();
            entity_capability::GrantEntry {
                handlers: entity_capability::PathScope::new(vec![bare]),
                resources: entity_capability::PathScope::new(vec!["*".into()]),
                operations: entity_capability::IdScope::new(vec!["*".into()]),
                peers: None,
                constraints: None,
                allowances: None,
            }
        })
        .collect()
}

/// Build the authenticate-response envelope for a received authenticate
/// EXECUTE.
///
/// Per spec §4.4, the response carries an EXECUTE_RESPONSE whose
/// `result` is a `system/capability/grant` and whose `included` map
/// has the capability token entity + local identity + capability
/// signature. The capability is built from the configured grant
/// resolver (EXTENSION-ROLE §4.7 initial-grant policy) with a static
/// fallback (debug_open_grants in dev, otherwise default_connection_
/// grants).
///
/// Mutates `conn.state` from `AwaitingAuthenticate` to `Established`
/// on success and sets `conn.remote_peer_id` + `conn.remote_public_key`.
pub(crate) fn build_authenticate_response_envelope(
    auth_envelope: &Envelope,
    conn: &mut Connection,
    shared: &Arc<PeerShared>,
) -> Result<Envelope, PeerError> {
    let (remote_peer_id, auth_request_id) = conn
        .process_authenticate(auth_envelope)
        .map_err(PeerError::Protocol)?;

    tracing::info!("authenticated remote peer: {}", remote_peer_id);

    // §4.5a item 1a: the local identity is authored at the ECFv1-SHA-256 floor
    // whatever the active format — the one exception to item 1's
    // author-under-the-active-format rule. The granter reference we mint is
    // therefore the same bytes the remote derives from our peer-id, on this
    // connection and every other.
    let active_format = conn.active_hash_format;
    let local_identity = shared
        .keypair
        .peer_entity()
        .map_err(|e| PeerError::ConnectionError(format!("build identity: {}", e)))?;

    // V7 §1.8 (v7.69): the cap `grantee` is the remote's **authored**
    // identity `content_hash` — the `signature.signer` we just verified in
    // `process_authenticate` — NOT a re-derivation under our local format.
    // Re-deriving would manufacture a second content_hash for one identity
    // and break the `grantee == author` equality on a cross-format
    // connection (the precise §1.8 violation v7.69 names). Under §4.5a the
    // active format is one value for the connection, so the authored remote
    // identity is already in `active_format`.
    let grantee_hash = conn
        .remote_identity_hash
        .ok_or_else(|| PeerError::ConnectionError("remote identity hash not captured".into()))?;

    // Connection grants — the §4.4 assembly, shared with the §6.5 (b)
    // reciprocal mint (see `assemble_inbound_grants`).
    let grants = assemble_inbound_grants(shared, &grantee_hash, &remote_peer_id);
    let now_ms = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // R6 (PROPOSAL §9 rulings) — session+capability as tree entity.
    //
    // Granter side: I'm being dialed. After authenticating remote, I
    // mint (or reuse, per R3a) the connection-handshake cap and record
    // it as `minted_capability` on
    // `/{local_peer_id}/system/peer/session/{remote_peer_id}`.
    //
    // Flow: probe the session path; on hit with `minted_capability`
    // pointing to a live cap whose grants match what we'd grant now,
    // reuse the cap entity. Otherwise mint fresh + write/update the
    // session entity (preserving any pre-existing `held_capability`
    // from a prior outbound dial to this peer).
    //
    // §9.1 R6-a (reconciliation with §7.1 #2, load-bearing):
    // `minted_capability` is granter bookkeeping (R3a idempotency
    // anchor), NOT a back-delivery cap. Back-direction delivery uses
    // `deliver_token`, unchanged.
    // v7.64 §1.4: path-segment is hex of remote's `system/peer` content_hash.
    let session_path = format!(
        "/{}/{}",
        shared.peer_id,
        crate::session_entity::PeerSession::relative_path(&grantee_hash)
    );
    let existing_session = shared.tree.get(&session_path).and_then(|e| {
        match crate::session_entity::PeerSession::from_entity(&e) {
            Ok(s) => Some(s),
            Err(err) => {
                tracing::warn!(
                    path = %session_path,
                    error = %err,
                    "R6: existing session entity failed to decode; minting fresh"
                );
                None
            }
        }
    });
    let reused_cap_entity = existing_session.as_ref().and_then(|session| {
        let minted = session.minted_capability.as_ref()?;
        let cap_entity = shared.content_store.get(&minted.hash)?;
        if !cap_is_live(&cap_entity, now_ms) {
            return None;
        }
        // §4.5a item 5: a cap chain has a self-consistent content_hash_format
        // and does not cross format boundaries. A cached cap minted under a
        // format other than this connection's active format MUST NOT be
        // reused — mint fresh under the active format.
        if cap_entity.content_hash.algorithm != active_format {
            tracing::debug!(
                path = %session_path,
                cached = cap_entity.content_hash.algorithm,
                active = active_format,
                "R6/§4.5a: cached cap format != connection active; minting fresh"
            );
            return None;
        }
        let cached_token = entity_capability::CapabilityToken::from_entity(&cap_entity).ok()?;
        // Grants-changed check (§9.1 R6-e — mint fresh + overwrite).
        if cached_token.grants != grants {
            tracing::debug!(
                path = %session_path,
                "R6: cached session grants differ from current; minting fresh"
            );
            return None;
        }
        tracing::debug!(
            grantee = %remote_peer_id,
            token = %cap_entity.content_hash,
            "R6: reusing minted cap via session entity"
        );
        Some(cap_entity)
    });

    let cap_entity = if let Some(entity) = reused_cap_entity {
        entity
    } else {
        let cap_token = entity_capability::CapabilityToken {
            grants,
            granter: entity_capability::Granter::Single(local_identity.content_hash),
            grantee: grantee_hash,
            parent: None,
            created_at: now_ms,
            expires_at: None,
            not_before: None,
            delegation_caveats: None,
        };
        let cap_entity = cap_token
            .to_entity_with_format(active_format)
            .map_err(|e| PeerError::ConnectionError(format!("build cap token: {}", e)))?;
        // Persist the cap entity in the content store so future
        // session-entity hits resolve. Put failure is logged + ignored
        // (forces re-mint next handshake; correctness preserved).
        if let Err(e) = shared.content_store.put(cap_entity.clone()) {
            tracing::warn!(
                error = %e,
                "R6: content_store.put(cap_entity) failed; next handshake will remint"
            );
        }
        // Build the minted-cap reference (root cap ⇒ chain length 1).
        let minted_ref = crate::session_entity::CapabilityRef {
            hash: cap_entity.content_hash,
            chain: vec![cap_entity.content_hash],
        };
        // Preserve any pre-existing held_capability from an earlier
        // outbound dial to this peer (§9.1 R6-a — one entity per peer,
        // two cap fields, populated from whichever direction handshook).
        let session_to_write = match existing_session {
            Some(prior) => prior.with_minted(minted_ref, now_ms),
            None => crate::session_entity::PeerSession::new_minted(
                remote_peer_id.to_string(),
                grantee_hash,
                conn.remote_public_key.as_ref().map(|pk| pk.to_vec()),
                minted_ref,
                now_ms,
                None,
            ),
        };
        if let Err(e) = shared.tree.put(&session_path, session_to_write.to_entity()) {
            tracing::warn!(
                path = %session_path,
                error = %e,
                "R6: tree.put(session_entity) failed; next handshake will remint"
            );
        }
        cap_entity
    };

    // Amendment 12 §A3: `connected` on establish (§6.2), responder side —
    // written as the connection capability is granted (cap-reuse and
    // fresh-mint paths both land here). The dialer's mirror write is in
    // remote.rs `get_or_connect` / lib.rs `connect_to`. No `connection`
    // path ref: the responder records no system/connection entity (it
    // holds no dialable address for the remote — ruling C establish
    // writes are dialer-side).
    crate::liveness::write_connected_status(
        shared.content_store.as_ref(),
        shared.location_index.as_ref(),
        shared.peer_id.as_str(),
        remote_peer_id.as_str(),
        &grantee_hash,
        None,
    );

    let cap_sig_bytes = shared.keypair.sign(&cap_entity.content_hash.to_bytes());
    let cap_sig_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (
            entity_ecf::text("algorithm"),
            entity_ecf::text(shared.keypair.key_type().label()),
        ),
        (
            entity_ecf::text("signature"),
            entity_ecf::Value::Bytes(cap_sig_bytes),
        ),
        (
            entity_ecf::text("signer"),
            entity_ecf::Value::Bytes(local_identity.content_hash.to_bytes().to_vec()),
        ),
        (
            entity_ecf::text("target"),
            entity_ecf::Value::Bytes(cap_entity.content_hash.to_bytes().to_vec()),
        ),
    ]));
    let cap_sig_entity = entity_entity::Entity::new_with_format(
        entity_entity::TYPE_SIGNATURE,
        cap_sig_data,
        active_format,
    )
    .map_err(|e| PeerError::ConnectionError(format!("build cap sig: {}", e)))?;

    let grant_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
        entity_ecf::text("token"),
        entity_ecf::Value::Bytes(cap_entity.content_hash.to_bytes().to_vec()),
    )]));
    let grant_entity = entity_entity::Entity::new_with_format(
        entity_types::TYPE_CAP_GRANT,
        grant_data,
        active_format,
    )
    .map_err(|e| PeerError::ConnectionError(format!("build grant: {}", e)))?;

    let mut auth_response = build_execute_response(&auth_request_id, 200, grant_entity)
        .map_err(|e| PeerError::ConnectionError(format!("build auth response: {}", e)))?;
    auth_response.include(cap_entity);
    auth_response.include(local_identity);
    auth_response.include(cap_sig_entity);

    Ok(auth_response)
}

/// Decide whether a cap-token entity is still live at `now_ms`.
/// Treats decode failure or absent token as not-live (forces a fresh
/// mint). `expires_at == None` ⇒ no expiry ⇒ live. `not_before` is
/// respected: a token whose `not_before` is in the future is treated
/// as not-live (would be rejected on use anyway).
fn cap_is_live(entity: &entity_entity::Entity, now_ms: u64) -> bool {
    if entity.entity_type != entity_types::TYPE_CAP_TOKEN {
        return false;
    }
    let token = match entity_capability::CapabilityToken::from_entity(entity) {
        Ok(t) => t,
        Err(_) => return false,
    };
    if let Some(expires_at) = token.expires_at {
        if now_ms >= expires_at {
            return false;
        }
    }
    if let Some(not_before) = token.not_before {
        if now_ms < not_before {
            return false;
        }
    }
    true
}

/// One-envelope-in, one-envelope-out router that routes by the
/// session's [`Connection`] state. This is the entry point for
/// request/response transports (HTTP) where each request is a
/// separate POST and the session is correlated by an out-of-band ID
/// (e.g., `X-Entity-Session`).
///
/// - `AwaitingHello` → [`build_hello_response_envelope`]
/// - `AwaitingAuthenticate` → [`build_authenticate_response_envelope`]
/// - `Established` → [`dispatch_request`] (the standard
///   post-handshake dispatch path TCP / WS also use)
///
/// Handshake errors are converted to error response envelopes so the
/// HTTP layer still returns a wire-decodable body; the caller decides
/// whether to evict the session (e.g., on auth failure).
#[cfg(all(feature = "http-live", not(target_arch = "wasm32")))]
pub(crate) async fn dispatch_session_envelope(
    envelope: &Envelope,
    conn: &mut Connection,
    shared: Arc<PeerShared>,
) -> Envelope {
    use entity_protocol::ConnectionState;
    let request_id = extract_request_id(envelope).unwrap_or_else(|| "unknown".to_string());
    // §4.7 row 10 (FM-2): hoisted OUT of the state match, not repeated inside
    // its arms — the refusal is on the operation's name, which no state makes
    // implemented. Covers `Established` too, where the connect intercept in
    // `dispatch_request` would otherwise hand an unknown name to generic §5.2
    // verification and report `401 authentication_failed` for a caller that had
    // just authenticated. The TCP path checks at both of its frame reads.
    if let Some(refusal) =
        unknown_connect_operation_refusal(envelope, shared.keypair.peer_id().as_str())
    {
        return refusal;
    }
    let result = match conn.state {
        // FM-1: the operation is discriminated ahead of the state match — see
        // `prehello_authenticate_refusal`. The TCP path does the same thing at
        // the same point in its own handshake.
        // The §4.7 out-of-order row (409) is checked per-arm rather than
        // hoisted like row 10, because "forbidden" is exactly what the state
        // decides — the expected operation IS the arm. In `AwaitingHello` the
        // row-6 carve-out keeps precedence over it, same order as the TCP path.
        //
        // CE-1 (§4.2 rule 3 / §5.2a) is checked PER-ARM and deliberately NOT
        // hoisted beside row 10, even though that would be tidier: its subject
        // is "arriving before the handshake completes", so hoisting it above
        // this match would refuse every legitimate authenticated EXECUTE on an
        // `Established` connection with a 401. The two pre-`Established` arms
        // are its whole surface; `Established` hands the frame to
        // `dispatch_request`, which runs the §1.4 gate and real verification.
        ConnectionState::AwaitingHello => {
            match pre_establishment_execute_refusal(envelope, shared.keypair.peer_id().as_str()) {
                Some(refusal) => return refusal,
                None => match prehello_authenticate_refusal(envelope) {
                    Some(refusal) => return refusal,
                    None => match out_of_order_connect_operation_refusal(
                        envelope,
                        shared.keypair.peer_id().as_str(),
                        "hello",
                    ) {
                        Some(refusal) => return refusal,
                        None => build_hello_response_envelope(envelope, conn),
                    },
                },
            }
        }
        ConnectionState::AwaitingAuthenticate => {
            match pre_establishment_execute_refusal(envelope, shared.keypair.peer_id().as_str()) {
                Some(refusal) => return refusal,
                None => match out_of_order_connect_operation_refusal(
                    envelope,
                    shared.keypair.peer_id().as_str(),
                    "authenticate",
                ) {
                    Some(refusal) => return refusal,
                    None => build_authenticate_response_envelope(envelope, conn, &shared),
                },
            }
        }
        ConnectionState::Established => {
            let session_peer_id = conn.remote_peer_id.as_ref().map(|p| p.as_str().to_string());
            return dispatch_request(envelope, shared, session_peer_id.as_deref()).await;
        }
    };
    match result {
        Ok(env) => env,
        Err(e) => {
            tracing::warn!(request_id = %request_id, error = %e, "handshake step failed");
            // v7.66 §4.4 surface 6: shared with the TCP path
            // (`accept_connection`); inner ProtocolError variants
            // (unsupported_key_type, unsupported_content_hash_format)
            // surface via their dedicated registry codes.
            let _ = request_id; // moved into handshake_error_envelope via inbound
                                // 0.8.2.5: `invalid_request`, not `handshake_failed`.
            handshake_error_envelope(envelope, &e, "invalid_request")
        }
    }
}

/// Dispatch a request: verify -> resolve handler -> dispatch -> build response.
#[tracing::instrument(
    level = "debug",
    skip_all,
    fields(
        entity_type = %envelope.root.entity_type,
        request_id = tracing::field::Empty,
        status = tracing::field::Empty,
    ),
)]
/// The verification-failure response, extracted verbatim so both the first
/// attempt and the §7a.2a supplied retry produce byte-identical errors.
fn verification_error_response(
    envelope: &Envelope,
    request_id: &str,
    e: entity_protocol::ProtocolError,
) -> Envelope {
    let status = e.wire_status_code();
    // v7.66 §4.4 surface 6: registry-entry codes win over the
    // generic verification_failed default. AGILITY-UNKNOWN-1 +
    // FORMAT-CODE-INTERPRETATION-1 + CAP-FREEZE-1 assert on the
    // dedicated codes returned via `wire_error_code()`.
    let code = e.wire_error_code().unwrap_or("verification_failed");
    tracing::warn!(request_id = %request_id, status = status, error = %e, "request verification failed");
    build_error_response(request_id, status, code, &e.to_string())
        .unwrap_or_else(|_| Envelope::new(envelope.root.clone()))
}

pub(crate) async fn dispatch_request(
    envelope: &Envelope,
    shared: Arc<PeerShared>,
    session_peer_id: Option<&str>,
) -> Envelope {
    // Extract request_id for error responses
    let request_id = extract_request_id(envelope).unwrap_or_else(|| "unknown".to_string());
    tracing::Span::current().record("request_id", request_id.as_str());

    tracing::debug!(
        request_id = %request_id,
        entity_type = %envelope.root.entity_type,
        included_count = envelope.included.len(),
        "received request"
    );

    // Trace-level dump of EXECUTE fields for debugging
    if tracing::enabled!(tracing::Level::TRACE) {
        if let Ok(val) = ciborium::from_reader::<ciborium::Value, _>(envelope.root.data.as_slice())
        {
            if let Some(map) = val.as_map() {
                let keys: Vec<&str> = map.iter().filter_map(|(k, _)| k.as_text()).collect();
                tracing::trace!(
                    request_id = %request_id,
                    fields = ?keys,
                    "EXECUTE data fields"
                );
            }
        }
    }

    // RT-6 (§4.6, bucket-B): the issued handshake nonce is single-use. A
    // same-connection `authenticate` replay MUST be rejected `401
    // invalid_nonce`. `dispatch_request` only ever runs post-Established (the
    // pre-Established hello/authenticate exchange in `handle_connection` /
    // `dispatch_session_envelope` never reaches here), so ANY envelope
    // arriving here targeting the connect handler's `authenticate` operation
    // is definitionally a replay — reject it before generic verification,
    // not after. This MUST run pre-verification: the oracle's replay resends
    // the bare connect-EXECUTE shape (`uri`/`operation`/`request_id` only, no
    // `author`/`capability` — the same shape `build_connect_execute` used for
    // the original pre-Established authenticate), which `verify_request_with_ctx`
    // would otherwise reject first with `401 authentication_failed` (missing
    // author) — silently masking the replay as a generic auth failure and
    // never reaching a post-verification special case (confirmed on the wire
    // by `entity-core-go` `docs/validation/reports/`
    // `2026-07-27-0.8.1-bucketB-revalidation-after-sibling-fixes.md`; a
    // same-side test using a fully-authenticated EXECUTE didn't catch this
    // because it never exercises the bare-shape path). `decode_execute_fields`
    // only requires `uri`/`operation`/`request_id` (mandatory), so it
    // succeeds regardless of whether `author`/`capability` are present.
    if let Ok(fields) = entity_protocol::decode_execute_fields(&envelope.root.data) {
        let local_pid = shared.keypair.peer_id();
        let bare_path = EntityUri::extract_handler_path(&fields.uri);
        let handler_path = EntityUri::qualify_path(bare_path, local_pid.as_str());
        if handler_path == format!("/{}/{}", local_pid.as_str(), entity_protocol::CONNECT_PATH) {
            // §4.7's two post-established connect rows. Both are reached only
            // here — `dispatch_request` runs exclusively post-Established, so
            // the state is implied by the call site rather than re-tested.
            match fields.operation.as_str() {
                "authenticate" => {
                    return build_error_response(
                        &fields.request_id,
                        STATUS_AUTH_FAILED,
                        "invalid_nonce",
                        "handshake nonce already consumed on this connection",
                    )
                    .unwrap_or_else(|_| Envelope::new(envelope.root.clone()));
                }
                // §4.7 row 9 → **409 `connection_already_established`**. A
                // second `hello` on an established connection is a sequence /
                // state conflict, not an authentication failure: the caller IS
                // authenticated, and it is asking to redo a handshake that
                // already completed. Without this arm the frame fell through to
                // generic §5.2 verification, which rejected the bare connect-
                // EXECUTE shape (no `author`) as `401 authentication_failed` —
                // a wrong status AND a wrong code, and one that reads to the
                // caller as "your credentials failed" when they did not.
                //
                // Scope: this arm fires on `hello` only. §4.7's row 10 was
                // routed as spec-issue 2026-09-01-b and RULED on 2026-09-01 —
                // it is two failures, and the unknown-operation half is the
                // `_` arm below, not this one.
                "hello" => {
                    return build_error_response(
                        &fields.request_id,
                        STATUS_CONFLICT,
                        "connection_already_established",
                        "the connection handshake has already completed on this connection",
                    )
                    .unwrap_or_else(|_| Envelope::new(envelope.root.clone()));
                }
                // §4.7 row 10, unknown-operation half — **400 `invalid_request`**
                // (`unknown_connect_operation_refusal`, which owns the reasoning
                // and the DRAFT-status caveat).
                //
                // The `_` arm previously fell through to generic §5.2
                // verification, where the bare connect-EXECUTE shape carries no
                // `author` — so an unimplemented operation name was reported as
                // `401 authentication_failed`, the same wrong-class answer row 9
                // was fixed for one arm over.
                //
                // **`ping` is still not a membership arm here**, and it is now
                // SERVED here rather than falling through to verification.
                //
                // Membership is decided in exactly one place — the helper reads
                // `CONNECT_OPERATIONS`, which is the list `bootstrap_handler`
                // advertises. Naming `ping` as a `match` arm beside `hello` /
                // `authenticate` would key the refusal on *"not hello and not
                // authenticate"* in one place and on `CONNECT_OPERATIONS` in
                // another, and the two drift the first time an operation is
                // added. Measured: with a `"ping" => {}` arm here, mutating the
                // helper's membership test to `matches!(op, "hello" |
                // "authenticate")` is **unobservable**.
                //
                // So: the helper refuses, or the operation is advertised and we
                // answer it. The `match` below is a SERVING table, not a second
                // membership test — it never decides refusal, and its fallback
                // is §3.3's 501 row, which is the honest answer for an operation
                // we advertise and do not implement.
                //
                // **Pre-verification (0.8.2.6 §4.2 Q2, ruled 2026-09-03).** We
                // shipped this after `verify_request`, reading §5.1 (*"every
                // authenticated EXECUTE MUST include `author` and
                // `capability`"*) as the general rule and §4.2 as its exception.
                // It is the other way round: §3.3 line 773 excepts the
                // connection path with **no state qualifier**, and §5.1 is
                // scoped to *authenticated* EXECUTE — the class that exception
                // defines. An unauthenticated post-handshake `ping` MUST be
                // served. `dispatch_request` runs exclusively post-`Established`
                // on both transports (TCP via `handle_connection`, http-live via
                // `dispatch_session_envelope`'s `Established` arm), so the
                // pre-`Established` out-of-order rows are unaffected — they are
                // refused before the frame ever reaches this function.
                //
                // What it cost us while we had it backwards: core-go's
                // `pingServedOnceEstablished` applicability control pings
                // unauthenticated, we answered non-200, and their §4.7 409 row
                // recorded `served=false` and **skipped** against us — a scored
                // row silently disabled by our own reading.
                _ => {
                    if let Some(refusal) =
                        unknown_connect_operation_refusal(envelope, local_pid.as_str())
                    {
                        return refusal;
                    }
                    return match fields.operation.as_str() {
                        "ping" => build_pong_response(envelope, &fields.request_id),
                        other => build_error_response(
                            &fields.request_id,
                            STATUS_NOT_SUPPORTED,
                            "unsupported_operation",
                            &format!(
                                "system/protocol/connect advertises {:?} and this peer does \
                                 not implement it (§3.3 501 row)",
                                other
                            ),
                        )
                        .unwrap_or_else(|_| Envelope::new(envelope.root.clone())),
                    };
                }
            }
        }
    }

    // Verify the request — V7.62 closeout F2 wires §5.2 Step 4
    // `is_revoked` into verify_request. `supports_revocation = true`
    // because Rust ships the full marker mechanism (capability handler
    // writes markers at `system/capability/revocations/{root_hash_hex}`
    // on revoke). The MUST-level wire-in is what makes wire-only-cap
    // revocation operationally real — markers alone aren't enough.
    let pid_string = shared.keypair.peer_id().as_str().to_string();
    let verify_ctx = entity_protocol::VerifyContext::new(&pid_string).with_revocation(true);
    let store = shared.content_store.clone();
    let li = shared.location_index.clone();
    // Q1 phase (2), the half the first pass missed: the REVOCATION resolver
    // needs the supplied triple too, not just the verification envelope.
    //
    // `verify_request_with_ctx` runs two walks over the same leaf. The first
    // reads `envelope.included` directly; the second is `is_revoked`, which
    // re-walks the chain through THIS closure — and on an unresolvable chain
    // it returns `true` (verify.rs, "Err(_) => return true"), i.e. a cap we
    // cannot resolve is reported REVOKED. Augmenting only the envelope
    // therefore turns a references-only frame into `403 capability_revoked`:
    // the chain verifies, and then the revocation walk cannot see the cap we
    // ourselves minted, because it lives in the minted ledger and was never
    // written to our content store.
    //
    // Measured, not theorised: entity-core-go flipped its sender and V3
    // direction B went 200 -> 403 `capability revoked`, bisected against the
    // same node with the flip as the only variable.
    //
    // Seeded here rather than inside the retry so BOTH attempts share one
    // resolver. That does not weaken the additive property: this map is read
    // only by the revocation walk, the first verification attempt still sees
    // the unaugmented envelope, and the entities added are exactly the ones
    // we minted AND delivered under the cap this frame names.
    //
    // The frame's root `capability` field IS the reference (§6.5 Carriage), so
    // it is the ledger's resolution key. Resolving by the *session* peer-id
    // alone — which is what this did until arch's 2026-08-07 ruling — holds only
    // while the wielder is the very peer we delivered to, and resolves nothing
    // the moment the cap is wielded by a delegate.
    let wielded_cap = entity_protocol::decode_execute_fields(&envelope.root.data)
        .ok()
        .and_then(|f| f.capability);
    let mut included_for_resolve = envelope.included.clone();
    if let Some(bundle) = shared
        .minted_reentry_grants
        .lock()
        .unwrap()
        .supply(wielded_cap.as_ref(), session_peer_id)
    {
        for e in bundle {
            included_for_resolve.entry(e.content_hash).or_insert(e);
        }
    }
    let resolve = |h: &entity_hash::Hash| {
        // Store-first then envelope `included` fallback per V7 §5.1
        // convention for revocation lookups.
        store
            .get(h)
            .or_else(|| included_for_resolve.get(h).cloned())
    };
    let locate = |path: &str| li.get(path);
    let li_for_scan = shared.location_index.clone();
    let capability_path_for = |h: &entity_hash::Hash| {
        entity_protocol::capability_path_for_scan(h, &pid_string, |prefix| {
            li_for_scan
                .list(prefix)
                .into_iter()
                .map(|e| (e.path, e.hash))
                .collect()
        })
    };
    // Q1 phase (2) — the references-only wielding path.
    //
    // The ruled shape lets an acceptor wield our §6.5 (b) reciprocal grant by
    // *reference*: it sends the §7a.2a triple as hashes and we, the granter,
    // resolve them. Rust's chain walk resolves from `envelope.included` only
    // (`verify::verify_capability_chain`), so a references-only frame fails
    // here — and, per `entity-core-go`'s finding, it fails as
    // `missing_signature` at the chain walk rather than as a missing cap,
    // because a sender that merely drops the supporting set still inlines the
    // cap itself. That partial shape is what any impl flipping by "stop
    // attaching the chain" will actually emit, so the receiver has to supply
    // whatever is missing rather than assume the whole triple is.
    //
    // Retry-on-failure rather than pre-augment, and that ordering is the
    // additive property: an envelope carrying the currently-shipped inlined
    // chain verifies on the first attempt and never reaches this path, so
    // landing this ahead of the flag day cannot move the shipped shape. Only a
    // frame that would otherwise have been **rejected** gets a second look, and
    // it gets it against entities we ourselves minted and delivered to this
    // exact peer — never a general store lookup (see
    // `PeerShared::minted_reentry_grants`). Nothing here can make a forged
    // signature verify; it can only stop us from demanding our own entities back.
    let supplied_envelope;
    let mut envelope: &Envelope = envelope;
    // The three resolver closures are borrowed rather than moved because the
    // supplied retry below calls them a second time; `&F` satisfies the same
    // `Fn` bounds. Clippy's suggestion to drop the `&` is correct only for a
    // single call site.
    #[allow(clippy::needless_borrows_for_generic_args)]
    let verified = match entity_protocol::verify_request_with_ctx(
        envelope,
        &verify_ctx,
        &resolve,
        &locate,
        &capability_path_for,
    ) {
        Ok(v) => v,
        Err(first_err) => {
            let supply = shared
                .minted_reentry_grants
                .lock()
                .unwrap()
                .supply(wielded_cap.as_ref(), session_peer_id)
                .filter(|bundle| {
                    // Only worth a retry if the bundle actually adds something
                    // the envelope did not already carry.
                    bundle
                        .iter()
                        .any(|e| !envelope.included.contains_key(&e.content_hash))
                });
            match supply {
                Some(bundle) => {
                    let mut augmented = envelope.clone();
                    for e in bundle {
                        augmented
                            .included
                            .entry(e.content_hash)
                            .or_insert_with(|| e.clone());
                    }
                    supplied_envelope = augmented;
                    envelope = &supplied_envelope;
                    match entity_protocol::verify_request_with_ctx(
                        envelope,
                        &verify_ctx,
                        &resolve,
                        &locate,
                        &capability_path_for,
                    ) {
                        Ok(v) => {
                            tracing::debug!(
                                request_id = %request_id,
                                remote_peer = ?session_peer_id,
                                "§7a.2a: supplied the reentry grant we minted for this peer — \
                                 references-only wielding verified"
                            );
                            v
                        }
                        Err(e) => return verification_error_response(envelope, &request_id, e),
                    }
                }
                None => return verification_error_response(envelope, &request_id, first_err),
            }
        }
    };

    // V7 §6.5: envelope.included signature ingestion. Runs after
    // verify_request (included entities structurally validated) and
    // BEFORE handler resolution. Universal across kernel / substrate /
    // identity / extension ops; substrate handlers can rely on
    // signatures being bound at canonical V7 paths by the time they run.
    if let Err(e) = crate::ingest::ingest_envelope_signatures(
        &envelope.included,
        shared.content_store.as_ref(),
        shared.location_index.as_ref(),
    ) {
        let (status, code) = match e {
            crate::ingest::IngestError::SignaturePathConflict { .. } => {
                (STATUS_BAD_REQUEST, "signature_path_conflict")
            }
            crate::ingest::IngestError::Io(_) => (500, "ingest_io_error"),
        };
        tracing::warn!(
            request_id = %verified.request_id,
            status = status,
            error = %e,
            "envelope signature ingestion failed"
        );
        return build_error_response(&verified.request_id, status, code, &e.to_string())
            .unwrap_or_else(|_| Envelope::new(envelope.root.clone()));
    }

    // Check for deliver_to early for logging purposes
    let has_deliver_to = extract_deliver_to(&envelope.root).is_some();
    let has_deliver_token = extract_deliver_token(&envelope.root).is_some();
    tracing::debug!(
        request_id = %verified.request_id,
        uri = %verified.uri,
        operation = %verified.operation,
        author = %verified.author_hash,
        deliver_to = has_deliver_to,
        deliver_token = has_deliver_token,
        "request verified"
    );

    let local_pid = shared.keypair.peer_id();

    // §1.4 / §6.5 step 3 (PD-1h) — INBOUND DISPATCH ROUTING GATE.
    //
    // An inbound EXECUTE whose HANDLER URI names a peer that is not us is
    // refused *as an address*, `400 invalid_request`, before the path is
    // interpreted and before any handler is resolved. §6.5 step 3 calls this a
    // "gate, not an ordering preference" and forbids the shape we had: strip
    // the foreign peer id, resolve the local handler at the remainder, and let
    // §5.2 Dimension 4 decide. That path is a privilege escalation, not merely
    // a wrong status — `extract_handler_path` drops the authority from
    // `entity://{them}/system/tree` and `qualify_path` re-attaches OURS, so the
    // request runs against our handler, and Dimension 4 *allows* it outright
    // whenever the presented grant happens to carry a matching `peers` scope.
    // Measured live by entity-core-go before this landed: foreign handler uri →
    // 200, local control → 200 (all three ground-up impls).
    //
    // It must run BEFORE `validate_path_input`: the refusal precedes the
    // interpretation, so a malformed foreign address is reported as the foreign
    // address it is. And the code is `invalid_request`, never `404
    // handler_not_found` (§6.2 — false: we HAVE the handler, we are refusing the
    // address) and never `403 capability_denied` (§5.2a pre-dispatch row — there
    // is no authorization verdict here, the request never reaches authorization).
    //
    // Scope: the handler uri only, NOT the resource target. A `system/tree:put`
    // at `entity://{local}/system/tree` carrying `targets: ["/{them}/…"]` is the
    // §1.4 universal-address-space slot — a LOCAL write into the region our own
    // store holds for them — and stays conformant. That is the `resources`
    // dimension; this is the address.
    //
    // Inbound only. `make_execute_fn` (§1.4 internal dispatch) never routes
    // through here and returns at its own `is_remote` branch, so a handler's
    // follow-mirror sub-dispatch is untouched.
    //
    // Reads `EntityUri::extract_peer` — the §5.2 `extract_peer` Dimension 4
    // reads at the call site below. One implementation on purpose: a routing
    // concept spelled twice is a fork nobody sees until a peer does.
    let target_peer = EntityUri::extract_peer(&verified.uri, local_pid.as_str());
    if target_peer != local_pid.as_str() {
        tracing::warn!(
            request_id = %verified.request_id,
            uri = %verified.uri,
            target_peer = %target_peer,
            "inbound EXECUTE targets a foreign namespace — refused at canonicalization"
        );
        return build_error_response(
            &verified.request_id,
            STATUS_BAD_REQUEST,
            "invalid_request",
            &format!(
                "handler uri targets peer {}, which is not this peer",
                target_peer
            ),
        )
        .unwrap_or_else(|_| Envelope::new(envelope.root.clone()));
    }

    // V1: Validate and qualify handler path (R12)
    let bare_path = EntityUri::extract_handler_path(&verified.uri);

    // Pre-qualify validation: reject ./, ../, empty segments
    if let Err(msg) = EntityUri::validate_path_input(bare_path) {
        return build_error_response(
            &verified.request_id,
            STATUS_BAD_REQUEST,
            "invalid_path",
            &msg,
        )
        .unwrap_or_else(|_| Envelope::new(envelope.root.clone()));
    }

    let handler_path_owned = EntityUri::qualify_path(bare_path, local_pid.as_str());
    let handler_path = handler_path_owned.as_str();

    // Post-qualify validation: verify absolute path structure
    if let Err(msg) = EntityUri::validate_absolute_path(handler_path) {
        return build_error_response(
            &verified.request_id,
            STATUS_BAD_REQUEST,
            "invalid_path",
            &msg,
        )
        .unwrap_or_else(|_| Envelope::new(envelope.root.clone()));
    }
    // EXTENSION-NETWORK §5.1 keepalive is NOT handled here any more. It used
    // to sit at this point — signature+capability VERIFIED, then exempted from
    // the handler-scope grant check below — on the reading that §4.2's
    // pre-authorization was scoped to the pre-`Established` states. Arch ruled
    // the other way on 2026-09-03 (0.8.2.6 §4.2 Q2) and the intercept moved
    // ahead of `verify_request`, into the connect block near the top of this
    // function. Every connect-path row this function owns is now decided in
    // that one block, before verification; nothing about the connect surface
    // is reachable from here.
    //
    // RT-6's `authenticate` intercept has run pre-verification since 0.8.1 —
    // see the comment there for why (the oracle's replay shape fails generic
    // verification before ever reaching a post-verification check). The ping
    // move is the same lesson arriving at the neighbouring operation.
    let handler_authorized = verified.capability.grants.iter().any(|grant| {
        entity_capability::matches_scope(
            handler_path,
            &grant.handlers.include,
            &grant.handlers.exclude,
            local_pid.as_str(),
        )
    });
    if !handler_authorized {
        tracing::warn!(
            request_id = %verified.request_id,
            handler_path = %handler_path,
            operation = %verified.operation,
            "handler scope authorization denied"
        );
        // v1.19 canonical 403 code: `capability_denied` (V7 §3.3 line 736).
        // WB-27 v1.20 §3.10.3: bind a `rejected`-variant marker when this is
        // a chain dispatch; mirror via ErrorData.rejected_marker.
        return build_capability_denied_response(
            &shared,
            envelope,
            &verified.request_id,
            &verified.author_hash,
            handler_path,
            "capability does not grant access to this handler",
        );
    }

    // Resolve handler
    let resolved = match entity_handler::resolve_handler(
        handler_path,
        shared.content_store.as_ref(),
        shared.location_index.as_ref(),
        &shared.handler_registry,
    ) {
        Some(r) => r,
        None => {
            tracing::warn!(
                request_id = %verified.request_id,
                handler_path = %handler_path,
                "no handler found for path"
            );
            return build_error_response(
                &verified.request_id,
                STATUS_NOT_FOUND,
                "handler_not_found",
                &format!("no handler for path: {}", handler_path),
            )
            .unwrap_or_else(|_| Envelope::new(envelope.root.clone()));
        }
    };

    tracing::debug!(
        request_id = %verified.request_id,
        handler = %resolved_handler_name(&resolved),
        pattern = %resolved.pattern,
        suffix = %resolved.suffix,
        operation = %verified.operation,
        compiled = resolved.handler.is_some(),
        "handler resolved"
    );

    // V2: Parse, qualify, and validate resource target paths (R12)
    let resource_target = match extract_resource_target(&envelope.root) {
        Some(mut rt) => {
            let pid = shared.keypair.peer_id();
            let mut qualified_targets = Vec::with_capacity(rt.targets.len());
            for t in &rt.targets {
                // Pre-qualify validation
                if let Err(msg) = EntityUri::validate_path_input(t) {
                    return build_error_response(
                        &verified.request_id,
                        STATUS_BAD_REQUEST,
                        "invalid_resource_path",
                        &msg,
                    )
                    .unwrap_or_else(|_| Envelope::new(envelope.root.clone()));
                }
                let qualified = EntityUri::qualify_path(t, pid.as_str());
                // Post-qualify validation on non-pattern targets
                if !qualified.contains('*') {
                    if let Err(msg) = EntityUri::validate_absolute_path(&qualified) {
                        return build_error_response(
                            &verified.request_id,
                            STATUS_BAD_REQUEST,
                            "invalid_resource_path",
                            &msg,
                        )
                        .unwrap_or_else(|_| Envelope::new(envelope.root.clone()));
                    }
                }
                qualified_targets.push(qualified);
            }
            rt.targets = qualified_targets;
            // §5.2 subject rule (0.8.2.20): narrow `targets` to the EFFECTIVE
            // set here, at the one boundary every inbound EXECUTE crosses, so
            // no handler downstream can be handed a target the authorizer
            // skipped. `effective_targets` is the same function
            // `check_resource_scope` iterates and the same one
            // `require_single_resource_path` calls — applying it twice is a
            // no-op (it is idempotent), and applying it HERE is what makes the
            // rule structural instead of an obligation re-discharged at ~20
            // handlers with no gate. `exclude` is deliberately KEPT: §5.2's
            // pattern arm reads the caller's exclude to decide whether a
            // wildcard target may overlap a grant exclude, so dropping it here
            // would silently delete that check — the shape core-go hit from
            // the other direction when its normalizer rebuilt the struct
            // without the field.
            //
            // 0.8.2.21 made `effective_targets` return the RAW survivor rather
            // than the canonical one. That is a no-op **at this boundary and
            // only here**, because the loop above already replaced every entry
            // with `qualify_path`'s output — so "raw" and "canonical" are the
            // same string by the time this line runs. The handler still sees
            // absolute targets; what changed is that the narrowing no longer
            // *performs* the qualification, it inherits it.
            //
            // ⛔ **But the projection MUST NOT be lossy about its own EMPTINESS
            // `[MUST]` (§3.3, 0.8.2.24 — N6), and THIS is the site where that
            // bites, not the handler.** Narrowing `targets:[P] exclude:[P]` to
            // `[]` destroys the one fact N6 turns into a branch: downstream it is
            // then indistinguishable from a caller who sent no `resource` at all,
            // and the handler takes the ABSENT-CASE behaviour — on `system/tree:get`
            // the §4.10 listing arm, in answer to a request for one excluded path.
            //
            // **Measured, and it is why a handler-only fix is not implementable
            // here:** with `core/tree` already splitting the two empties, a wire
            // EXECUTE carrying `targets:[qA] exclude:[qA]` still answered `200` —
            // the handler's `SelfExcluded` arm was **unreachable**, because this
            // line had already erased its input. 0.8.2.20's structural boundary
            // narrowing and 0.8.2.24's two-empties split are the same field read
            // twice, and the first silently deletes the second unless the empty
            // case is exempted here. Any seat that adopted the boundary narrowing
            // has this; a seat that only ever narrowed inside the handler does not.
            //
            // So: narrow when narrowing leaves something, keep the pair when it
            // would not. The effective set is identical either way —
            // `effective_targets` is idempotent and is what both
            // `check_resource_scope` and `entity_handler::single_effective_target`
            // call — so nothing downstream computes a different subject. What
            // changes is only that the handler can still tell WHICH empty it has.
            //
            // ⚠ The residual, stated rather than implied: in the all-excluded case
            // a NON-conformant handler indexing `targets[0]` sees the excluded
            // path. That is the `F68`/`CP-12a` shape this boundary exists to
            // prevent — and it is bounded to the one case where the only
            // conformant answer is a refusal, which every consumer of the single
            // derivation now gives without reading a target at all. Narrowing to
            // `[]` does not close it either: a handler willing to index
            // `targets[0]` unguarded would read `targets[0]` of an empty vec and
            // panic, or fall through to an absent-case it was never asked for.
            // The enforcement is `entity_handler::single_effective_target`, and
            // this line is defence in depth for the arity cases above it.
            //
            // Pinned END TO END by `core/peer/tests/two_empties_vector.rs`, which
            // crosses a real socket — the in-process rows in `core/tree` cannot
            // see this line at all.
            let effective = entity_capability::effective_targets(Some(&rt), pid.as_str());
            if !effective.is_empty() {
                rt.targets = effective;
            }
            Some(rt)
        }
        None => None,
    };
    let params = extract_params_entity(&envelope.root);

    if let Some(ref rt) = resource_target {
        tracing::debug!(
            request_id = %verified.request_id,
            targets = ?rt.targets,
            "resource target"
        );
    }
    tracing::trace!(
        request_id = %verified.request_id,
        params_type = %params.entity_type,
        params_hash = %params.content_hash,
        params_size = params.data.len(),
        "params entity"
    );

    // Check permission (§5.4) — capability must authorize this operation+handler+resource.
    // Returns the matching grant so handlers can inspect constraints.
    //
    // PR-8 (§5.5): the cap's peer-relative resource patterns canonicalize
    // against the *granter's* namespace, not the verifier's. Resolve the leaf
    // cap's granter peer_id from `envelope.included` (guaranteed present —
    // `verify_request` validated the chain). A foreign-granted bare-`*` cap
    // thus canonicalizes to the granter's namespace and cannot reach this
    // peer's resources. Fail-closed (deny) if the granter is unresolvable.
    let local_pid = shared.keypair.peer_id();
    let matching_grant = match entity_capability::resolve_granter_peer_id(
        &verified.capability.granter,
        local_pid.as_str(),
        |h| envelope.included.get(h),
    ) {
        Some(granter_peer_id) => entity_capability::check_permission_with_grant(
            &verified.operation,
            &resolved.pattern,
            // §5.2: `target_peer = extract_peer(execute.data.uri, local)` — NOT
            // `local`. Passing `local` here made a grant scoped
            // `peers: {include: [local]}` — or absent, which defaults to the
            // same — authorize a dispatch into a FOREIGN namespace, since the
            // dimension then compared local against local and always matched.
            //
            // This MUST read `verified.uri`, not `handler_path`: `handler_path`
            // is `extract_handler_path` + `qualify_path`, and the first of those
            // *strips* the authority from an `entity://{peer}/...` URI so the
            // second re-qualifies it to the local peer. Deriving the target peer
            // from it would reconstruct the very escalation this fixes, and
            // would do it invisibly — the absolute-path form `/{peer}/...`
            // survives that round-trip, so only the `entity://` form would leak.
            &EntityUri::extract_peer(&verified.uri, local_pid.as_str()),
            resource_target.as_ref(),
            &verified.capability,
            local_pid.as_str(),
            &granter_peer_id,
        ),
        None => None,
    };
    if matching_grant.is_none() {
        tracing::warn!(
            request_id = %verified.request_id,
            handler = %resolved_handler_name(&resolved),
            operation = %verified.operation,
            resource = ?resource_target.as_ref().map(|r| &r.targets),
            "operation permission denied"
        );
        // v1.19 canonical 403 code + WB-27 v1.20 marker bind for chain dispatches.
        return build_capability_denied_response(
            &shared,
            envelope,
            &verified.request_id,
            &verified.author_hash,
            handler_path,
            "capability does not grant permission for this operation",
        );
    }

    // Extract bounds from the EXECUTE entity (§5.9)
    let bounds = extract_bounds(&envelope.root);

    // Build context and dispatch
    let included: HashMap<entity_hash::Hash, entity_entity::Entity> = envelope
        .included
        .iter()
        .map(|(h, e)| (*h, e.clone()))
        .collect();
    // Load + validate handler grant from tree (§6.8, §6.9, §S2/§S3). See
    // `load_local_handler_grant` for the full check ladder: granter equality,
    // signature verification, temporal validity. A failed check yields
    // `(None, None)`, which engages the §7.1 fail-closed path on entity-
    // native dispatch and drops any compiled-handler authority claim from a
    // transferred subtree.
    //
    // Loaded BEFORE `make_execute_fn` because it is also the §5.2 resource
    // ceiling for any sub-dispatch this handler performs (D1) — the handler
    // about to run is the deputy.
    let bare_pattern = entity_entity::EntityUri::strip_peer_prefix(&resolved.pattern);
    let (handler_grant, handler_grant_hash) = load_local_handler_grant(
        bare_pattern,
        shared.location_index.as_ref(),
        shared.content_store.as_ref(),
        local_pid.as_str(),
        shared.identity_hash,
        shared.keypair.key_type(),
        &shared.keypair.public_key_bytes(),
    );

    let execute_fn = make_execute_fn(
        shared.clone(),
        Some(verified.author_hash),
        included.clone(),
        bounds.clone(),
        // V7 §6.8 / proposal §6.2: original caller's verified capability is the
        // attribution context for any sub-dispatches the handler performs.
        Some(verified.capability.clone()),
        DispatchCeiling::Handler(handler_grant.clone().map(Box::new)),
    );

    let mut builder = HandlerContext::builder(envelope.root.clone(), params)
        .caller_capability(verified.capability)
        .pattern(resolved.pattern.clone())
        .suffix(resolved.suffix.clone())
        .author(verified.author_hash)
        .request_id(verified.request_id.clone())
        .operation(verified.operation.clone())
        .execute_fn(execute_fn.clone())
        .included(included)
        .capability_hash(verified.capability_hash)
        // PROPOSAL-CONVERGENT-MIRRORING §2.3 D4: this is the inbound wire
        // dispatch entry — receiver-local ops use this signal to refuse
        // cross-peer invocation.
        .is_external(true);
    // RELAY §2.2: the placement identity for a relay :put is the authenticated
    // connection peer, not the wire-author. Threaded from the verified
    // handshake `remote_peer_id`.
    if let Some(sp) = session_peer_id {
        builder = builder.session_peer_id(sp);
    }
    if let Some(g) = handler_grant {
        builder = builder.handler_grant(g);
    }
    if let Some(rt) = resource_target {
        builder = builder.resource_target(rt);
    }
    if let Some(mg) = matching_grant {
        builder = builder.matching_grant(mg);
    }
    if let Some(hgh) = handler_grant_hash {
        builder = builder.handler_grant_hash(hgh);
    }
    if let Some(b) = bounds {
        builder = builder.bounds(b);
    }
    let ctx = builder.build();

    // --- Durability contract (EXTENSION-DURABILITY v0.1, exploratory) ---
    // The request is accepted for processing (verified, handler resolved and
    // authorized). Reconcile any durability marker against the receiver's
    // policy at acceptance (§4). A `deliver_to` makes the durable write
    // asynchronous (the inbox path), so the verdict reports a `committed`
    // promise observable at `(author, request_id)` (§6) rather than a
    // synchronous `applied` level.
    let durability_cbor: Option<Vec<u8>> =
        match durability::extract_durability_request(&envelope.root) {
            Some(dreq) => {
                // §5/§8 / Amendment 1 — `(author, request_id)` dedup. A
                // replayed durable request whose pair matches a previously
                // preserved entry returns 409 with the prior handle echoed.
                // Probe is BEFORE reconcile + handler dispatch so the second
                // request never re-executes (the §5 invariant — no silent
                // double-execution).
                let dedup_key = (
                    verified.author_hash.to_string(),
                    verified.request_id.clone(),
                );
                if let Some(prior_handle) = shared
                    .preserved_requests
                    .lock()
                    .ok()
                    .and_then(|guard| guard.get(&dedup_key).cloned())
                {
                    tracing::info!(
                        request_id = %verified.request_id,
                        prior_handle = %prior_handle,
                        "durability dedup hit — returning 409 with prior handle"
                    );
                    let dur = durability::DurabilityResult {
                        requested: dreq.level.clone(),
                        applied: "stored".to_string(),
                        committed: None,
                        max_available: None,
                        reason: Some(durability::REASON_DUPLICATE_REQUEST_ID.to_string()),
                        handle: Some(prior_handle.clone()),
                    };
                    let err_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
                        (
                            entity_ecf::text("code"),
                            entity_ecf::text(durability::REASON_DUPLICATE_REQUEST_ID),
                        ),
                        (
                            entity_ecf::text("message"),
                            entity_ecf::text(format!(
                                "durable (author, request_id) already preserved at {}",
                                prior_handle
                            )),
                        ),
                    ]));
                    let err = entity_entity::Entity::new(entity_types::TYPE_ERROR, err_data)
                        .unwrap_or_else(|_| envelope.root.clone());
                    return build_execute_response_full(
                        &verified.request_id,
                        entity_handler::STATUS_CONFLICT,
                        err,
                        HashMap::new(),
                        Some(dur.to_cbor()),
                    )
                    .unwrap_or_else(|_| Envelope::new(envelope.root.clone()));
                }

                let mut verdict =
                    durability::reconcile(&dreq, &shared.config.durability_policy, has_deliver_to);
                if verdict.refused() {
                    // §5/§8 — a required durability precondition could
                    // not be met. The operation is **not performed**: refuse
                    // at acceptance, before the handler runs and before any
                    // delivery is spawned. Safe to retry elsewhere, no
                    // double-execution.
                    tracing::warn!(
                        request_id = %verified.request_id,
                        requested = %verdict.result.requested,
                        "durability required but unmet — refusing at acceptance (412)"
                    );
                    let err_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
                        (
                            entity_ecf::text("code"),
                            entity_ecf::text(durability::REASON_REQUIRED_UNMET),
                        ),
                        (
                            entity_ecf::text("message"),
                            entity_ecf::text(
                                "required durability level could not be met; \
                                 operation not performed",
                            ),
                        ),
                    ]));
                    let err = entity_entity::Entity::new(entity_types::TYPE_ERROR, err_data)
                        .unwrap_or_else(|_| envelope.root.clone());
                    return build_execute_response_full(
                        &verified.request_id,
                        verdict.status,
                        err,
                        HashMap::new(),
                        Some(verdict.result.to_cbor()),
                    )
                    .unwrap_or_else(|_| Envelope::new(envelope.root.clone()));
                }
                // §6 preservation: when the verdict claims durable storage
                // on the synchronous path, write-ahead the originating EXECUTE
                // into the inbox namespace so `(author, request_id)` is a
                // working lookup. The deliver_to path preserves via the inbox
                // handler's own write-ahead (handle_receive at L99-104 of
                // extensions/inbox/src/lib.rs) — don't double-preserve.
                if verdict.preserve() && !has_deliver_to {
                    match preserve_durable_request(&envelope.root, &verified.request_id, &shared) {
                        Some(path) => {
                            // §6 / Amendment 1 — the sender follows the handle.
                            // Also record in the dedup index so a replay of
                            // the same `(author, request_id)` returns 409
                            // (§5 / Amendment 1).
                            if let Ok(mut guard) = shared.preserved_requests.lock() {
                                guard.insert(dedup_key.clone(), path.clone());
                            }
                            verdict.result.handle = Some(path);
                        }
                        None => {
                            // Preservation failed — downgrade observably rather
                            // than overclaim `applied` (§5 invariant).
                            tracing::warn!(
                                request_id = %verified.request_id,
                                "durability preservation failed — downgrading applied to none"
                            );
                            verdict.result.applied = "none".to_string();
                            verdict.result.committed = None;
                            verdict.result.reason =
                                Some(durability::REASON_NO_DURABLE_STORE.to_string());
                        }
                    }
                }
                // For the deliver_to / async path: predict where the inbox
                // handler's write-ahead will land. The inbox handler stores
                // at `{deliver_to.uri}/{request_id}` (see
                // `extensions/inbox/src/lib.rs::handle_receive` L99-104).
                // The handle is the address the sender polls (may 404 until
                // commit completes — that's the §6 contract).
                if has_deliver_to && verdict.result.handle.is_none() {
                    if let Some(spec) = extract_deliver_to(&envelope.root) {
                        if !verified.request_id.is_empty() {
                            verdict.result.handle = Some(format!(
                                "{}/{}",
                                spec.uri.trim_end_matches('/'),
                                verified.request_id
                            ));
                        }
                    }
                }
                Some(verdict.result.to_cbor())
            }
            None => None,
        };

    // --- Async delivery detection (INBOX spec §4.5) ---
    // If deliver_to is present, validate deliver_token and return 202 immediately.
    // Process the handler asynchronously and deliver the result to the inbox.
    if let Some(deliver_to) = extract_deliver_to(&envelope.root) {
        // INBOX spec §2.3: deliver_token MUST be present when deliver_to is present
        let deliver_token_hash = match extract_deliver_token(&envelope.root) {
            Some(h) if h != entity_hash::Hash::zero() => h,
            _ => {
                tracing::warn!(
                    request_id = %verified.request_id,
                    "deliver_to present but deliver_token missing"
                );
                return build_error_response(
                    &verified.request_id,
                    STATUS_BAD_REQUEST,
                    "missing_deliver_token",
                    "deliver_to field present but deliver_token is missing",
                )
                .unwrap_or_else(|_| Envelope::new(envelope.root.clone()));
            }
        };

        // deliver_token entity must be in included
        if !envelope
            .included
            .iter()
            .any(|(h, _)| *h == deliver_token_hash)
        {
            tracing::warn!(
                request_id = %verified.request_id,
                deliver_token = %deliver_token_hash,
                "deliver_token entity not in envelope included"
            );
            return build_error_response(
                &verified.request_id,
                STATUS_BAD_REQUEST,
                "missing_deliver_token",
                "deliver_token entity not in envelope included",
            )
            .unwrap_or_else(|_| Envelope::new(envelope.root.clone()));
        }

        tracing::debug!(
            request_id = %verified.request_id,
            deliver_uri = %deliver_to.uri,
            deliver_operation = %deliver_to.operation,
            "async delivery: returning 202, processing in background"
        );

        // Row 2 of the back-direction-authority taxonomy (PROPOSAL-SYMMETRIC-
        // REENTRY-MUTUAL-MINTING §3, arch ruling 2026-08-05): the delivery we
        // are about to make back to the caller is authorized by the caller's own
        // `deliver_token` — granter = the caller (it owns the inbox), grantee =
        // us — and by nothing else. Capture it, with the entities its chain
        // needs (its signature, and the granter identity), so the delivery
        // dispatch can author under it instead of falling through to whatever
        // connection authority happens to exist. `default_connection_grants`
        // never covered `system/inbox receive`, so the fall-through could not
        // have been right; and on a §6.11(b) return path there may be no
        // connection grant at all. `entity-core-go` found and fixed the same
        // shape in `deliverToInbox`.
        let delivery_auth: Option<(entity_entity::Entity, HashMap<entity_hash::Hash, _>)> =
            envelope
                .included
                .get(&deliver_token_hash)
                .cloned()
                .map(|token| {
                    let mut bundle: HashMap<entity_hash::Hash, entity_entity::Entity> =
                        HashMap::new();
                    if let Some(sig) = entity_entity::find_signature_for_target(
                        envelope.included.values(),
                        &deliver_token_hash,
                    ) {
                        bundle.insert(sig.content_hash, sig.clone());
                    }
                    if let Ok(fields) = entity_capability::CapabilityToken::from_entity(&token) {
                        if let entity_capability::Granter::Single(granter) = fields.granter {
                            if let Some(id) = envelope.included.get(&granter) {
                                bundle.insert(id.content_hash, id.clone());
                            }
                        }
                    }
                    (token, bundle)
                });

        // Spawn async processing task
        let request_id_owned = verified.request_id.clone();
        let handler_name = resolved_handler_name(&resolved).to_string();
        let shared_for_delivery = shared.clone();
        crate::runtime::spawn(async move {
            process_async_delivery(
                ctx,
                &deliver_to,
                &execute_fn,
                &request_id_owned,
                &handler_name,
                shared_for_delivery,
                delivery_auth,
            )
            .await;
        });

        // Return 202 immediately (EXTENSION-INBOX §4.5). When a durability
        // marker was present, the 202 also carries the durability verdict —
        // the durable inbox write completes asynchronously and is observable
        // at `(author, request_id)` (EXTENSION-DURABILITY §5/§6).
        return build_202_response(&verified.request_id, durability_cbor)
            .unwrap_or_else(|_| Envelope::new(envelope.root.clone()));
    }

    // --- Synchronous dispatch (normal path) ---
    tracing::debug!(
        request_id = %verified.request_id,
        handler = %resolved_handler_name(&resolved),
        operation = %verified.operation,
        compiled = resolved.handler.is_some(),
        "dispatching to handler"
    );

    // Build the target URI once — used for both dispatch hook events.
    // pattern + suffix matches v1.2 §2.1 #3's `target_uri` field.
    let target_uri = if ctx.suffix.is_empty() {
        ctx.pattern.clone()
    } else if ctx.pattern.ends_with('/') || ctx.suffix.starts_with('/') {
        format!("{}{}", ctx.pattern, ctx.suffix)
    } else {
        format!("{}/{}", ctx.pattern, ctx.suffix)
    };

    // GUIDE-INSPECTABILITY v1.2 §2.1 #3 entry hook. Fires at the
    // dispatcher↔handler-body boundary, before the handler is invoked.
    // Covers both compiled and entity-native dispatch paths because both
    // converge through this match.
    //
    // Hot-path bypass: inline `is_empty()` check avoids the per-dispatch
    // String/clone overhead when no hooks are registered — the common
    // production case.
    if !shared.dispatch_hooks.is_empty() {
        fire_dispatch_hooks(
            &shared,
            &crate::DispatchEvent {
                target_uri: target_uri.clone(),
                operation: ctx.operation.clone(),
                params_hash: ctx.params.content_hash,
                request_id: ctx.request_id.clone(),
                timestamp_ms: dispatch_event_timestamp_ms(),
                phase: crate::DispatchPhase::Entry,
            },
        );
    }

    // V7 §6.5 — compiled handlers in the registry take priority over tree-walked
    // entity-native handlers. resolve_handler already encoded this priority:
    //   - resolved.handler = Some → compiled implementation, dispatch directly.
    //   - resolved.handler = None → tree-only manifest, route entity-native via
    //                               compute evaluator (V7 §6.6, PROPOSAL §1).
    let handler_result = match &resolved.handler {
        Some(handler) => handler.handle(&ctx).await,
        None => {
            #[cfg(feature = "compute")]
            {
                dispatch_tree_only_handler(&resolved, &ctx, shared.clone()).await
            }
            #[cfg(not(feature = "compute"))]
            {
                // Tree-only manifest but compute feature disabled — there's no
                // way to evaluate it. Per V7 §6.6 the manifest is unreachable
                // without the evaluator; treat as not-implemented.
                let _ = (&resolved, &ctx, &shared);
                Err(HandlerError::Internal(
                    "tree-only handler requires the compute feature".to_string(),
                ))
            }
        }
    };

    // §2.1 #3 exit hook. Fires immediately after the handler returns,
    // before response construction. `response_hash` is the result-entity
    // content hash on success; `Hash::zero()` on Err (no result entity
    // produced yet).
    let (exit_status, exit_response_hash) = match &handler_result {
        Ok(r) => (r.status, r.result.content_hash),
        Err(e) => (handler_error_slot(e).0, entity_hash::Hash::zero()),
    };
    if !shared.dispatch_hooks.is_empty() {
        fire_dispatch_hooks(
            &shared,
            &crate::DispatchEvent {
                target_uri,
                operation: ctx.operation.clone(),
                params_hash: ctx.params.content_hash,
                request_id: ctx.request_id.clone(),
                timestamp_ms: dispatch_event_timestamp_ms(),
                phase: crate::DispatchPhase::Exit {
                    status: exit_status,
                    response_hash: exit_response_hash,
                },
            },
        );
    }

    match handler_result {
        Ok(result) => {
            tracing::debug!(
                request_id = %verified.request_id,
                handler = %resolved_handler_name(&resolved),
                operation = %verified.operation,
                status = result.status,
                result_type = %result.result.entity_type,
                included_count = result.included.len(),
                "handler completed"
            );
            // Attach the durability verdict when the request carried a
            // durability marker (EXTENSION-DURABILITY §8 — always answer observably).
            build_execute_response_full(
                &verified.request_id,
                result.status,
                result.result,
                result.included,
                durability_cbor,
            )
            .unwrap_or_else(|_| Envelope::new(envelope.root.clone()))
        }
        Err(e) => {
            tracing::warn!(
                request_id = %verified.request_id,
                handler = %resolved_handler_name(&resolved),
                operation = %verified.operation,
                error = %e,
                "handler error"
            );
            // §3.3's status + code slots. One inventory — see
            // `handler_error_slot`, which the two dispatch-hook exit records
            // below also read, so the status a hook observes and the status the
            // caller receives cannot drift apart.
            let (status, code) = handler_error_slot(&e);
            match durability_cbor {
                // EXTENSION-DURABILITY §8 — even on a handler error, a durability marker is
                // answered observably (the status reports the failure).
                Some(dur) => {
                    let err_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
                        (entity_ecf::text("code"), entity_ecf::text(code)),
                        (entity_ecf::text("message"), entity_ecf::text(e.to_string())),
                    ]));
                    let err = entity_entity::Entity::new(entity_types::TYPE_ERROR, err_data)
                        .unwrap_or_else(|_| envelope.root.clone());
                    build_execute_response_full(
                        &verified.request_id,
                        status,
                        err,
                        HashMap::new(),
                        Some(dur),
                    )
                }
                None => build_error_response(&verified.request_id, status, code, &e.to_string()),
            }
            .unwrap_or_else(|_| Envelope::new(envelope.root.clone()))
        }
    }
}

/// Stable display name for a resolved handler — used in tracing / log fields.
/// Compiled handlers report `Handler::name()`; tree-only manifests fall back
/// to the matched pattern (e.g., `system/validate/entity-native/multi`).
fn resolved_handler_name(resolved: &entity_handler::ResolvedHandler) -> &str {
    resolved
        .handler
        .as_ref()
        .map(|h| h.name())
        .unwrap_or(resolved.pattern.as_str())
}

/// Wall-clock timestamp in Unix milliseconds for `DispatchEvent.timestamp_ms`.
/// Mirrors `extensions/continuation::capture_failure_timestamp_ms`; uses
/// `web_time` so the timestamp is consistent native/wasm32.
fn dispatch_event_timestamp_ms() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Fire all registered dispatch hooks in order. Each closure receives the
/// event by reference; per security audit §2 the hook MUST snapshot any
/// fields it retains. Rust's borrow checker enforces non-retention of the
/// `&DispatchEvent` itself.
///
/// Hot-path bypass: callers wrap construction of the `DispatchEvent` so
/// when `dispatch_hooks` is empty the only work is this one branch +
/// the unconditional event-struct construction (which the optimizer is
/// likely to elide if no hook reads it). For a fully zero-cost bypass,
/// inline the `is_empty()` check at the call site before building the
/// event — see the dispatch sites in `dispatch_request` and
/// `make_execute_fn` for the pattern.
fn fire_dispatch_hooks(shared: &Arc<PeerShared>, event: &crate::DispatchEvent) {
    if shared.dispatch_hooks.is_empty() {
        return;
    }
    for (_name, hook) in &shared.dispatch_hooks {
        hook(event);
    }
}

/// Fire all registered wire hooks. Skips the hot-path overhead (frame
/// clone, timestamp call) entirely when no hooks are registered — the
/// common case in production.
///
/// `request_id` is supplied by the caller — passed empty when the
/// envelope hasn't been (successfully) decoded yet (handshake frames,
/// frames that fail `decode_envelope`). Per GUIDE-INSPECTABILITY v1.2
/// §2.1 #5 "every inbound / outbound frame" — malformed-frame
/// observation is the wire recorder's reason for existing (F-CIMP-7
/// class: bytes-on-the-wire diverged from expected shape).
fn fire_wire_hooks(
    shared: &Arc<PeerShared>,
    direction: crate::WireDirection,
    request_id: &str,
    frame: &[u8],
    peer_address: &str,
) {
    if shared.wire_hooks.is_empty() {
        return;
    }
    let event = crate::WireEvent {
        direction,
        request_id: request_id.to_string(),
        frame_bytes: frame.to_vec(),
        peer_address: peer_address.to_string(),
        timestamp_ms: dispatch_event_timestamp_ms(),
    };
    for (_name, hook) in &shared.wire_hooks {
        hook(&event);
    }
}

/// Process an async delivery: execute handler, wrap result, deliver to inbox.
/// Per INBOX spec §4.1 and §4.5.
/// If deliver_to targets a remote peer, uses outbound connection to deliver.
/// `delivery_auth` is the caller's `deliver_token` and the entities its chain
/// needs (signature + granter identity) — taxonomy row 2, the authority for the
/// delivery leg. `None` only if the token vanished between validation and here,
/// in which case the dispatch falls back to connection authority and will fail
/// closed at the far side, which is the correct outcome.
#[allow(clippy::too_many_arguments)]
async fn process_async_delivery(
    ctx: HandlerContext,
    deliver_to: &DeliverySpec,
    execute_fn: &ExecuteFn,
    original_request_id: &str,
    handler_name: &str,
    shared: std::sync::Arc<PeerShared>,
    delivery_auth: Option<(
        entity_entity::Entity,
        HashMap<entity_hash::Hash, entity_entity::Entity>,
    )>,
) {
    // Execute the handler via execute_fn (internal dispatch).
    // We re-dispatch to the same handler+operation with the same params.
    // This skips wire auth, which is appropriate since we already verified
    // the original request before spawning this task.
    let handler_path = ctx.pattern.clone();
    let operation = ctx.operation.clone();
    let params = ctx.params.clone();
    let opts = ExecuteOptions {
        resource: ctx.resource_target.clone(),
        request_id: Some(ctx.request_id.clone()),
        ..Default::default()
    };
    let result = execute_fn(handler_path, operation, params, opts).await;

    let (status, result_entity) = match result {
        Ok(r) => {
            tracing::debug!(
                request_id = %original_request_id,
                handler = %handler_name,
                status = r.status,
                "async delivery: handler completed"
            );
            (r.status, r.result)
        }
        Err(e) => {
            tracing::warn!(
                request_id = %original_request_id,
                handler = %handler_name,
                error = %e,
                "async delivery: handler error, dropping delivery"
            );
            return;
        }
    };

    // Build InboxDeliveryData entity (INBOX spec §2.1)
    // The result field carries the handler's result as a full inline entity
    // {content_hash, data, type} — preserving entity identity through the
    // delivery chain. Embedded directly as a CBOR map (not wrapped in a byte
    // string) to match Go's cbor.RawMessage semantics.
    // NOTE: Spec says "primitive/any" for result — spec gap on whether this
    // should be the inline entity or just data. Using inline entity because
    // downstream continuations need type+hash for entity operations (tree.put).
    let result_data_val: entity_ecf::Value =
        ciborium::from_reader(result_entity.data.as_slice()).unwrap_or(entity_ecf::Value::Null);
    let result_inline = entity_ecf::Value::Map(vec![
        (
            entity_ecf::text("content_hash"),
            entity_ecf::Value::Bytes(result_entity.content_hash.to_bytes().to_vec()),
        ),
        (entity_ecf::text("data"), result_data_val),
        (
            entity_ecf::text("type"),
            entity_ecf::text(&result_entity.entity_type),
        ),
    ]);
    let delivery_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (
            entity_ecf::text("original_request_id"),
            entity_ecf::text(original_request_id),
        ),
        (entity_ecf::text("result"), result_inline),
        (
            entity_ecf::text("status"),
            entity_ecf::integer(status as i64),
        ),
    ]));
    let delivery_entity =
        match entity_entity::Entity::new(entity_types::TYPE_INBOX_DELIVERY, delivery_data) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(
                    request_id = %original_request_id,
                    error = %e,
                    "async delivery: failed to build delivery entity"
                );
                return;
            }
        };

    // Check if deliver_to targets a remote peer
    let local_pid = shared.keypair.peer_id();
    let is_remote = crate::remote::is_remote_uri(&deliver_to.uri, local_pid.as_str());

    if is_remote {
        // Remote delivery: resolve address, connect, send authenticated EXECUTE
        tracing::debug!(
            request_id = %original_request_id,
            deliver_uri = %deliver_to.uri,
            "async delivery: remote delivery"
        );

        let remote_peer_id = match crate::remote::extract_peer_id_from_uri(&deliver_to.uri) {
            Some(pid) => pid,
            None => {
                tracing::warn!(
                    request_id = %original_request_id,
                    deliver_uri = %deliver_to.uri,
                    "async delivery: cannot extract peer_id from remote URI"
                );
                return;
            }
        };

        // List what transport profiles we have for debugging. Per
        // §6.5 Amendment 2 + V7 §1.4 v7.64, profiles live at
        // `/{local}/system/peer/transport/{peer_id_hex}/{profile-id}` —
        // narrow the prefix to the remote peer's slot. Identity-form PIDs
        // derive the hex locally; SHA-256-form (Ed448 canonical) recovers
        // it from the cached session entity (v7.67 Phase 2). This block is
        // diagnostics-only — `get_or_connect` below re-resolves through the
        // same path — so a miss here just skips the debug log, never aborts.
        let remote_hex = match crate::remote::resolve_peer_id_hex(
            &remote_peer_id,
            shared.content_store.as_ref(),
            shared.location_index.as_ref(),
            local_pid.as_str(),
        ) {
            Some(h) => h,
            None => {
                tracing::debug!(
                    request_id = %original_request_id,
                    remote_peer = %remote_peer_id,
                    "async delivery: no cached {{peer_id_hex}} for remote yet; get_or_connect will surface the resolution error"
                );
                String::new()
            }
        };
        let transport_prefix = format!(
            "/{}/system/peer/transport/{}/",
            local_pid.as_str(),
            remote_hex
        );
        let transport_entries = shared.location_index.list(&transport_prefix);
        tracing::debug!(
            request_id = %original_request_id,
            remote_peer = %remote_peer_id,
            transport_entries = transport_entries.len(),
            transport_paths = ?transport_entries.iter().map(|e| &e.path).collect::<Vec<_>>(),
            "async delivery: resolving transport address"
        );

        let conn: std::sync::Arc<dyn crate::remote::RemoteEndpoint> =
            match crate::remote::get_or_connect(
                &shared.remote,
                &remote_peer_id,
                &shared.keypair,
                shared.content_store.as_ref(),
                shared.location_index.as_ref(),
                local_pid.as_str(),
                shared.connector.as_ref(),
                shared.config.home_hash_format,
                Some(shared.clone()),
            )
            .await
            {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(
                        request_id = %original_request_id,
                        remote_peer = %remote_peer_id,
                        error = %e,
                        "async delivery: remote connection failed"
                    );
                    return;
                }
            };

        // Class G / F-WB28: connection is multiplexed; concurrent dispatches
        // proceed without serializing on per-connection state. No outer lock.

        // Send the delivery as an authenticated EXECUTE to the remote inbox
        let resource = entity_capability::ResourceTarget {
            targets: vec![deliver_to.uri.clone()],
            exclude: vec![],
        };

        // Taxonomy row 2: the delivery authors under the caller's `deliver_token`
        // (granter = the caller, grantee = us, scoped to `system/inbox receive`
        // at exactly this `deliver_to` URI), carrying that token's own chain —
        // never under the connection grant, which does not cover `system/inbox`
        // and may not exist at all on a §6.11(b) return path.
        let no_chain = std::collections::HashMap::new();
        let (dispatch_cap, chain_bundle) = match delivery_auth {
            Some((ref token, ref bundle)) => (Some(token), bundle),
            None => (None, &no_chain),
        };
        match crate::remote::send_execute(
            conn.as_ref(),
            &shared.keypair,
            &deliver_to.uri,
            &deliver_to.operation,
            &delivery_entity,
            Some(&resource),
            None, // delivery dispatch — no nested deliver_to
            dispatch_cap,
            chain_bundle,
            None, // async delivery of a finished result — no chain bounds
        )
        .await
        {
            Ok(resp) => {
                tracing::debug!(
                    request_id = %original_request_id,
                    remote_peer = %remote_peer_id,
                    status = resp.status,
                    "async delivery: remote delivery completed"
                );
            }
            Err(e) => {
                tracing::warn!(
                    request_id = %original_request_id,
                    remote_peer = %remote_peer_id,
                    error = %e,
                    "async delivery: remote delivery failed, removing pooled connection"
                );
                // §8.2 direct-send seam: same §A1 demotion as the §10-step-1
                // dispatch site (guarded eviction + suspect write).
                crate::liveness::demote_peer_on_transport_error(
                    &shared,
                    &remote_peer_id,
                    &conn,
                    &e.to_string(),
                );
            }
        }
    } else {
        // Local delivery: dispatch through internal execute_fn
        let opts = ExecuteOptions {
            resource: Some(entity_capability::ResourceTarget {
                targets: vec![deliver_to.uri.clone()],
                exclude: vec![],
            }),
            request_id: Some(format!("dlv-{}", original_request_id)),
            ..Default::default()
        };

        tracing::debug!(
            request_id = %original_request_id,
            deliver_uri = %deliver_to.uri,
            deliver_operation = %deliver_to.operation,
            "async delivery: local delivery to inbox"
        );

        match execute_fn(
            "system/inbox".to_string(),
            deliver_to.operation.clone(),
            delivery_entity,
            opts,
        )
        .await
        {
            Ok(r) => {
                tracing::debug!(
                    request_id = %original_request_id,
                    status = r.status,
                    "async delivery: inbox delivery completed"
                );
            }
            Err(e) => {
                tracing::warn!(
                    request_id = %original_request_id,
                    error = %e,
                    "async delivery: inbox delivery failed"
                );
            }
        }
    }
}

/// Write-ahead persist the originating EXECUTE into the local inbox namespace
/// at `(author, request_id)` so a downstream `(author, request_id)` lookup
/// can find it (EXTENSION-DURABILITY §6 / Scenario 5). Mirrors Go's `preserveDurableRequest`
/// in `core/protocol/durability.go`. Best-effort: returns `false` on store
/// failure so the dispatcher can downgrade `applied` observably rather than
/// overclaim (EXTENSION-DURABILITY §5 invariant).
fn preserve_durable_request(
    execute_entity: &entity_entity::Entity,
    request_id: &str,
    shared: &Arc<PeerShared>,
) -> Option<String> {
    if request_id.is_empty() {
        return None;
    }
    let hash = match shared.content_store.put(execute_entity.clone()) {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(
                request_id = %request_id,
                error = %e,
                "durability: content store put failed"
            );
            return None;
        }
    };
    let path = format!(
        "/{}/system/inbox/{}",
        shared.keypair.peer_id().as_str(),
        request_id
    );
    shared.location_index.set(&path, hash);
    tracing::debug!(
        request_id = %request_id,
        path = %path,
        hash = %hash,
        "durability: preserved originating EXECUTE in inbox namespace"
    );
    Some(path)
}

/// Build a 202 Accepted response for async delivery acknowledgement (INBOX spec §4.5).
pub fn build_202_response(
    request_id: &str,
    durability_cbor: Option<Vec<u8>>,
) -> Result<Envelope, entity_protocol::ProtocolError> {
    let null_entity = entity_entity::Entity {
        entity_type: "primitive/null".to_string(),
        data: vec![0xf6], // CBOR null
        content_hash: entity_hash::Hash::compute("primitive/null", &[0xf6]),
    };
    build_execute_response_full(
        request_id,
        202,
        null_entity,
        HashMap::new(),
        durability_cbor,
    )
}

/// Build an ExecuteFn closure for handler-to-handler dispatch.
///
/// The closure captures PeerShared and resolves + dispatches to handlers.
/// Internal dispatch inherits the parent's author/capability context.
/// Dispatch a tree-only handler — `resolved.handler` is `None`, but the tree
/// has a `system/handler` manifest at `resolved.pattern`. Per V7 §6.6 the
/// manifest's `expression_path` field is the entity-native dispatch target.
///
/// §7.1 fail-closed: handler grant MUST be **present** before invoking the
/// evaluator — otherwise the expression would run with no capability ceiling.
/// Presence is the check; **emptiness is not** — §6.8 blesses the empty grant
/// (a pure-functional handler needs no impure authority, and an empty scope
/// covers nothing, so every impure op fails its own per-op check). §6.1's
/// "and non-empty" is the defect, ruled so in
/// `PROPOSAL-CAPABILITY-EMPTY-GRANTS-AND-POLICY-WITHDRAWAL` §1 — see the
/// guard's own comment below, which this once contradicted.
///
/// If the manifest has no `expression_path`, dispatch fails 404 — the manifest
/// is malformed (per V7 §3.7 `expression_path` is the only entry point an
/// installed-but-uncompiled handler has).
#[cfg(feature = "compute")]
async fn dispatch_tree_only_handler(
    resolved: &entity_handler::ResolvedHandler,
    ctx: &HandlerContext,
    shared: Arc<PeerShared>,
) -> Result<entity_handler::HandlerResult, HandlerError> {
    let manifest = match resolved.manifest.as_ref() {
        Some(m) => m,
        None => {
            // Defensive: resolve_handler only returns handler=None when manifest
            // was found in the tree, so this branch shouldn't be reachable.
            return Ok(entity_handler::HandlerResult::error(
                STATUS_NOT_FOUND,
                make_error_response_entity(
                    "handler_not_found",
                    &format!("No handler manifest at {}", resolved.pattern),
                ),
            ));
        }
    };

    let expression_path = match entity_compute::extract_expression_path(manifest) {
        Some(p) => p,
        None => {
            // Tree manifest exists but declares no implementation. Compiled
            // code would have been required for this pattern; return 404 so
            // callers see the same shape as a missing handler.
            return Ok(entity_handler::HandlerResult::error(
                STATUS_NOT_FOUND,
                make_error_response_entity(
                    "handler_not_found",
                    &format!(
                        "Manifest at {} declares no expression_path and has no compiled implementation",
                        resolved.pattern
                    ),
                ),
            ));
        }
    };

    // §7.1 (CRITICAL): handler grant MUST be present (and validated by
    // load_local_handler_grant) before invoking the evaluator. Without this,
    // the expression would run with no capability ceiling — equivalent to
    // escalation.
    //
    // §S3: empty `grants` is valid — a pure-functional handler (no impure
    // authority) is a registered handler. The expression runs; per-op
    // capability checks (lookup/tree, apply, store) fail naturally because
    // an empty scope covers nothing. Distinct from a missing/invalid grant,
    // which is fail-closed here.
    let grant = match ctx.handler_grant.as_ref() {
        Some(g) => g,
        None => {
            // v1.19 canonical 403 code — single rule per EXTENSION-CONTINUATION
            // §3.10.5 (`{reason}` = `result.data.code` verbatim).
            return Ok(entity_handler::HandlerResult::error(
                STATUS_FORBIDDEN,
                make_error_response_entity(
                    "capability_denied",
                    &format!(
                        "Entity-native handler at {} has no usable handler grant",
                        resolved.pattern
                    ),
                ),
            ));
        }
    };

    // PROPOSAL §4 (E3): bare-primitive results from the evaluator are wrapped
    // at the dispatch boundary using the operation's declared output_type.
    // Look up the type from the handler's interface entity now so the unwrap
    // path can apply it. Defaults to `primitive/any` when absent.
    let output_type = lookup_operation_output_type(
        manifest,
        &ctx.operation,
        shared.content_store.as_ref(),
        shared.location_index.as_ref(),
        shared.keypair.peer_id().as_str(),
    );

    tracing::debug!(
        pattern = %resolved.pattern,
        expression_path = %expression_path,
        output_type = ?output_type,
        "entity-native dispatch"
    );

    entity_compute::dispatch_entity_native(
        &expression_path,
        grant,
        shared.content_store.clone(),
        shared.location_index.clone(),
        shared.keypair.peer_id().as_str(),
        ctx,
        output_type.as_deref(),
    )
}

/// Look up `operations[op].output_type` on the handler's interface entity.
/// Returns `None` when the manifest has no interface ref, the interface entity
/// is missing, or the operation/output_type field isn't declared.
#[cfg(feature = "compute")]
fn lookup_operation_output_type(
    manifest: &entity_entity::Entity,
    operation: &str,
    content_store: &dyn entity_store::ContentStore,
    location_index: &dyn entity_store::LocationIndex,
    local_peer_id: &str,
) -> Option<String> {
    use entity_ecf::ValueExt;
    let data: ciborium::Value = ciborium::from_reader(manifest.data.as_slice()).ok()?;
    let interface_path = data.get("interface").and_then(|v| v.as_text())?;
    let qualified = if interface_path.starts_with('/') {
        interface_path.to_string()
    } else {
        format!("/{}/{}", local_peer_id, interface_path)
    };
    let iface_hash = location_index.get(&qualified)?;
    let iface = content_store.get(&iface_hash)?;
    let iface_data: ciborium::Value = ciborium::from_reader(iface.data.as_slice()).ok()?;
    let operations = iface_data.get("operations")?;
    let op_spec = operations.get(operation)?;
    op_spec
        .get("output_type")
        .and_then(|v| v.as_text())
        .map(String::from)
}

/// Build a minimal error entity for entity-native dispatch fail-closed paths.
///
/// Deliberately NOT `#[cfg(feature = "compute")]`: §5.2's resource-dimension
/// denial on the in-process path (D1) builds its 403 body with this, and that
/// check is a security invariant of the dispatch core, not of the compute
/// extension. Gating it would have made the guard compile away for any build
/// without `compute` — the feature-gate hazard where a cfg'd symbol reads as an
/// absent surface.
/// The §3.3 status + `code` slot a `HandlerError` variant lands in — **one
/// inventory, read by every site that answers a handler error**.
///
///   `InvalidParams` → 400 `invalid_params`  (the caller sent malformed data;
///                                            a DEFINED specific 400 code)
///   `NotSupported`  → 501 `unsupported_operation`  (§3.3's 501 row default)
///   `Internal`      → 500 `internal_error`         (§3.3's 500 row default)
///
/// **This is the peer's whole generic 500/501 surface.** Every handler in the
/// workspace that returns `HandlerError::{Internal, NotSupported}` is answered
/// from here, so a minted spelling in this function is a minted spelling on
/// every extension at once. It emitted `handler_error` and `not_supported`
/// until 0.8.2.7, both codes in no spec code set.
///
/// **Extracted because there were THREE copies of this match and only one of
/// them carried the codes** — the other two mapped the status alone for the
/// dispatch-hook exit record. That is the *"a closed set that decides behaviour
/// belongs in one constant, read by every site"* rule from `AGENTS.md`, and the
/// split is precisely why arch's cohort census missed this site: it censused
/// the `STATUS_INTERNAL_ERROR` spelling and the code here is neither `internal`
/// nor near that constant. A second copy is what silently absorbs a mutation.
///
/// §3.3's 500 row is stated in the spec (§3b) as **not oracle-drivable** — a
/// conformant peer cannot be made to fail internally on demand over the wire —
/// so no cross-impl check will ever reach this. `handler_error_slot_is_the_one
/// _inventory` in `lib.rs` is the only instrument the row will ever have.
pub(crate) fn handler_error_slot(e: &HandlerError) -> (u32, &'static str) {
    match e {
        HandlerError::InvalidParams(_) => (STATUS_BAD_REQUEST, "invalid_params"),
        HandlerError::NotSupported(_) => (STATUS_NOT_SUPPORTED, "unsupported_operation"),
        HandlerError::Internal(_) => (STATUS_INTERNAL_ERROR, "internal_error"),
    }
}

fn make_error_response_entity(code: &str, message: &str) -> entity_entity::Entity {
    let data = entity_ecf::cbor_map! {
        "code" => entity_ecf::text(code),
        "message" => entity_ecf::text(message)
    };
    entity_entity::Entity::new("compute/error", entity_ecf::to_ecf(&data)).expect("error entity")
}

/// Path under which `create_handler_grant` binds a handler grant in the tree
/// (`system/capability/grants/{pattern}`). The grant's signature lives
/// separately at the §3.5 invariant-pointer path `system/signature/{grant_hash}`
/// (v7.74 §3.4 CONVERGENT ruling; see [`entity_hash::invariant_signature_path`])
/// — looked up from the grant's content hash at dispatch, not from the pattern.
fn handler_grant_path(local_pid: &str, bare_pattern: &str) -> String {
    format!("/{}/system/capability/grants/{}", local_pid, bare_pattern)
}

/// Load and validate a handler grant from the tree.
///
/// V7 §6.2 + §6.8 + spec-gap-handler-grant-authority §S2/§S3 enforcement:
///
/// - **§S2(a) granter equality.** Cross-peer subtree transfer (revision pull,
///   manual import) drags foreign-issued grants along; we MUST NOT honor
///   them. Direct equality check on `granter` against the local peer's
///   identity hash.
/// - **§S2(b) signature verification.** The signature entity is stored at a
///   sibling tree path by `create_handler_grant` and verified here against
///   the local peer's pubkey. Without this, an attacker with path-write
///   capability could craft a grant carrying `granter = local_identity_hash`
///   that was never actually issued by the peer.
/// - **§S2(c) temporal validity.** `not_before` and `expires_at` are
///   honored — grants in the future or past are rejected.
/// - **§S3 empty grants are valid.** A pure-functional handler may have no
///   impure authority; per-op cap checks fail naturally for impure ops.
///   This function neither asserts nor rejects on `grants.is_empty()` — that
///   policy lives one level up at the dispatch site.
///
/// On any check failure, returns `(None, None)` and logs at warn level so
/// the dispatcher fails closed: entity-native dispatch returns 403, compiled
/// handlers receive `None` in `HandlerContext.handler_grant`.
fn load_local_handler_grant(
    bare_pattern: &str,
    location_index: &dyn entity_store::LocationIndex,
    content_store: &dyn entity_store::ContentStore,
    local_pid: &str,
    local_identity_hash: entity_hash::Hash,
    local_key_type: entity_crypto::KeyType,
    local_pubkey: &[u8],
) -> (
    Option<entity_capability::CapabilityToken>,
    Option<entity_hash::Hash>,
) {
    let grant_path = handler_grant_path(local_pid, bare_pattern);
    let cap_hash = match location_index.get(&grant_path) {
        Some(h) => h,
        None => return (None, None),
    };
    let cap_entity = match content_store.get(&cap_hash) {
        Some(e) => e,
        None => return (None, None),
    };
    let token = match entity_capability::CapabilityToken::from_entity(&cap_entity) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(grant_path = %grant_path, error = %e, "handler grant decode failed");
            return (None, None);
        }
    };

    // §S2(a): granter equality. Cheapest check, runs first.
    // Handler self-grants are always single-sig; multi-sig granters are
    // unexpected here (handler bootstrap doesn't issue multi-sig caps).
    let token_granter_single = match &token.granter {
        entity_capability::Granter::Single(h) => *h,
        entity_capability::Granter::Multi(_) => {
            tracing::warn!(
                grant_path = %grant_path,
                "handler grant rejected: multi-sig granter on handler self-grant"
            );
            return (None, None);
        }
    };
    if token_granter_single != local_identity_hash {
        tracing::warn!(
            grant_path = %grant_path,
            granter = %token_granter_single,
            local = %local_identity_hash,
            "handler grant rejected: granter is not the local peer (§S2)"
        );
        return (None, None);
    }

    // §S2(c): temporal validity. `created_at` is informational; the gates
    // are `not_before` (future) and `expires_at` (past). Both are optional.
    let now_ms = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    if let Some(nb) = token.not_before {
        if now_ms < nb {
            tracing::warn!(
                grant_path = %grant_path,
                not_before = nb, now = now_ms,
                "handler grant rejected: not yet valid (§S2)"
            );
            return (None, None);
        }
    }
    if let Some(exp) = token.expires_at {
        if now_ms >= exp {
            tracing::warn!(
                grant_path = %grant_path,
                expires_at = exp, now = now_ms,
                "handler grant rejected: expired (§S2)"
            );
            return (None, None);
        }
    }

    // §S2(b): signature verification. v7.74 §3.4: the sig is bound at the
    // §3.5 invariant-pointer path `system/signature/{grant_hash}`, keyed by
    // this grant's content hash — without it we can't distinguish a
    // peer-issued grant from one a path-write attacker forged.
    let sig_path = entity_hash::invariant_signature_path(local_pid, &cap_hash);
    let sig_hash = match location_index.get(&sig_path) {
        Some(h) => h,
        None => {
            tracing::warn!(
                grant_path = %grant_path, sig_path = %sig_path,
                "handler grant rejected: signature missing (§S2)"
            );
            return (None, None);
        }
    };
    let sig_entity = match content_store.get(&sig_hash) {
        Some(e) => e,
        None => {
            tracing::warn!(
                grant_path = %grant_path, sig_hash = %sig_hash,
                "handler grant rejected: signature entity missing from store (§S2)"
            );
            return (None, None);
        }
    };
    let sig_data = match entity_types::SignatureData::from_entity(&sig_entity) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(grant_path = %grant_path, error = %e, "handler grant rejected: signature decode failed (§S2)");
            return (None, None);
        }
    };
    if sig_data.target != cap_hash {
        tracing::warn!(
            grant_path = %grant_path,
            sig_target = %sig_data.target,
            cap_hash = %cap_hash,
            "handler grant rejected: signature does not target this grant (§S2)"
        );
        return (None, None);
    }
    if sig_data.signer != local_identity_hash {
        tracing::warn!(
            grant_path = %grant_path,
            signer = %sig_data.signer,
            "handler grant rejected: signer is not the local peer (§S2)"
        );
        return (None, None);
    }
    if entity_crypto::verify_for_key_type(
        local_key_type,
        local_pubkey,
        &cap_hash.to_bytes(),
        &sig_data.signature,
    )
    .is_err()
    {
        tracing::warn!(
            grant_path = %grant_path,
            "handler grant rejected: signature verification failed (§S2)"
        );
        return (None, None);
    }

    (Some(token), Some(cap_hash))
}

/// Who is dispatching, and therefore what bounds §5.2's resource dimension on
/// the in-process branch (PROPOSAL-DISPATCH-AUTHORIZATION-FRAME D1).
///
/// This is a three-state fact and collapsing it to `Option<CapabilityToken>`
/// gets it wrong in one direction or the other: `None` has to mean *deny* for a
/// grantless handler and *allow* for the peer's own SDK entry points, which are
/// opposite answers to the same value.
#[derive(Clone)]
pub enum DispatchCeiling {
    /// The peer itself is dispatching — `Peer::execute_with_options`, the
    /// engine, the network link. The local peer is the root authority over its
    /// own namespace and presents no capability to itself, exactly as the wire
    /// path expects a *caller* to and an owner not to. There is no deputy to
    /// attenuate against, so the dimension does not bind.
    PeerRoot,
    /// A handler is dispatching. Its own grant is the ceiling. `None` is a
    /// handler holding no valid grant, which denies every resource-carrying
    /// sub-dispatch — a dispatcher that can prove no authority over any
    /// resource naming one is the escalation, not a special case.
    Handler(Option<Box<entity_capability::CapabilityToken>>),
}

/// §1.4 *"The enforcement point, and the authority it runs against"*
/// (PD-2, **as corrected at 0.8.2.19**): may this locally-originated
/// sub-dispatch **leave the peer**?
///
/// **ONE GATE AND ONE EXEMPTION.** The executing handler's grant decides, on
/// all four dimensions (§6.8). A valid credential minted **by the target peer**
/// relaxes **Dimension 4 (`peers`) and only Dimension 4**, to the peers that
/// credential covers. *The target answers **where**; the handler's grant still
/// answers **what**.*
///
/// **This function used to be two arms, and that was a confused-deputy hole
/// (F67).** The presented arm verified a target-minted credential on its own
/// four dimensions and `return true`d **before the handler grant was ever
/// consulted**. Because the credential arrives as a caller-supplied param — the
/// §7a.1 scaffold reads it straight out of `params` — a caller holding a copy of
/// any `target → this peer` capability could steer **any** handler on this peer
/// past its own grant. The caller cannot wield the credential itself (the leaf
/// `grantee` is us), which is precisely what makes it a confused deputy, with
/// the ceiling that was supposed to bound it removed by name. `entity-core-
/// keystone` found it; go, py and this tree had all implemented the identical
/// bypass, and two of the three (this one included) had written design prose
/// defending it. The prose is gone with the branch.
///
/// **The structure is the fix, not the condition.** The credential check is a
/// **predicate that produces a bit** ([`presented_credential_relaxes_peers`]),
/// never an authorizer, and the bit feeds one call to
/// [`entity_capability::check_permission_relax_peers`]. There is no code path
/// by which a credential authorizes alone: reinstating F67 requires adding a
/// new early return, which is exactly what
/// `a_target_minted_credential_does_not_lift_a_handler_grant_that_does_not_cover_the_op`
/// exists to redden.
///
/// **`PeerRoot` is out of scope by the provenance test, not by exemption**
/// (§1.4, restated 0.8.2.19). The test is *does this dispatch spend a handler's
/// grant, or the peer's own root authority?* A peer originating as itself has no
/// delegated authority to confine and could mint any grant the check would test
/// against, so a sender-side check constrains nothing there. **This is not the
/// "no caller was on the stack" exemption the spec forbids** — an autonomous
/// origination that spends a handler's grant (a timer, a continuation advance, a
/// subscription delivery) is IN scope and must arrive here as
/// `Handler(..)`. See `docs/status/` for the one class in this tree still
/// classified `PeerRoot` against that rule (subscription delivery) and why it is
/// routed rather than flipped unilaterally.
///
/// **Disjoint from §6.2's confused-deputy prohibition, not an exception to it.**
/// That rule forbids re-spending the *propagated caller capability* at a target
/// the caller chose. A target-minted credential is a different object with a
/// different granter — but that only answers the second half of §6.8, and the
/// first half (*the decision is made on the executing handler's grant*) is the
/// operative one, which is why the relaxation is scoped to Dimension 4.
/// `parent_caller_capability` is deliberately **not** a candidate here.
///
/// **Both candidate sources are target-minted.** `opts.capability` is the
/// explicit one (a continuation's scoped `dispatch_capability`). The session's
/// `held_capability` is the standing one — *"the cap remote granted me at
/// handshake"* (`session_entity`, R6-a), granter = target, grantee = local by
/// construction. Both are verified on their own terms rather than trusted for
/// their provenance; a capability failing any check **relaxes nothing** and the
/// handler grant gates unrelaxed.
///
/// Framing note, and it is the half that is easy to get backwards — §1.4 now
/// pins it **per arm** (0.8.2.19 / E3). A presented credential is evaluated
/// **end to end in the target's frame**: it was minted by the target, so its
/// `resources` canonicalize against the target's peer id (§5.5a / PR-8's
/// per-link granter frame) and an absent `peers` defaults to
/// `{include: [target]}` — which is what makes an ordinary handshake cap, naming
/// no peers at all, cover a dispatch *at the peer that issued it*. The same
/// argument is passed to the chain walk, where it decides §5.5's root-trust rule
/// rather than a canonicalization; using our own peer id there rejects every
/// target-issued credential outright. **The handler grant is the opposite and
/// generalizing the credential's frame to it is E3's named failure:** the grant
/// is local, so both sides canonicalize in the LOCAL frame — canonicalize its
/// `handlers` pattern against the target and Dimension 1 never matches for any
/// foreign target, refusing even a handler legitimately scoped
/// `peers: {include: [target]}`. Both directions were measured, not reasoned.
#[allow(clippy::too_many_arguments)]
fn outbound_sub_dispatch_authorized(
    shared: &PeerShared,
    ceiling: &DispatchCeiling,
    presented: Option<&entity_entity::Entity>,
    included: &HashMap<entity_hash::Hash, entity_entity::Entity>,
    handler_pattern: &str,
    operation: &str,
    target_peer: &str,
    resource: Option<&entity_capability::ResourceTarget>,
    local_pid: &str,
) -> bool {
    // --- The exemption bit: does a target-minted credential relax Dim 4? ----
    //
    // The target's identity hash is derived, never read off the connection:
    // §1.4 rejects keying this on "the connection the request arrived on"
    // because that makes an authority question turn on a transport predicate.
    // `resolve_peer_id_hex` derives it from the PeerID itself for identity-form
    // PIDs and falls back to state we already hold for SHA-256-form ones.
    let target_identity_hex = crate::remote::resolve_peer_id_hex(
        target_peer,
        shared.content_store.as_ref(),
        shared.location_index.as_ref(),
        local_pid,
    );

    let mut candidates: Vec<entity_entity::Entity> = Vec::new();
    if let Some(cap) = presented {
        candidates.push(cap.clone());
    }
    // The standing handshake credential, if this peer holds one for the target.
    if let Some(ref hex) = target_identity_hex {
        let session_path = format!("/{}/system/peer/session/{}", local_pid, hex);
        if let Some(held) = shared
            .location_index
            .get(&session_path)
            .and_then(|h| shared.content_store.get(&h))
            .and_then(|e| crate::session_entity::PeerSession::from_entity(&e).ok())
            .and_then(|s| s.held_capability)
            .and_then(|c| shared.content_store.get(&c.hash))
        {
            candidates.push(held);
        }
    }

    // A bit, not a verdict. Nothing below consults `candidates` again.
    let relax_peers = candidates.iter().any(|cand| {
        presented_credential_relaxes_peers(
            shared,
            cand,
            included,
            handler_pattern,
            operation,
            target_peer,
            resource,
        )
    });

    // --- The gate: the executing handler's grant ---------------------------
    match ceiling {
        // Out of scope by the §1.4 provenance test — this dispatch spends the
        // peer's own root authority, not a handler's grant. See the doc comment;
        // this is NOT the "nobody was on the stack" exemption the spec forbids.
        DispatchCeiling::PeerRoot => true,
        DispatchCeiling::Handler(Some(grant)) => {
            if relax_peers {
                // Dimensions 1-3 unconditional, Dimension 4 relaxed to the peers
                // the credential covers — which the credential has already been
                // checked to do, in its own frame, above.
                entity_capability::check_permission_relax_peers(
                    operation,
                    handler_pattern,
                    resource,
                    grant,
                    local_pid,
                )
            } else {
                entity_capability::check_permission(
                    operation,
                    handler_pattern,
                    target_peer,
                    resource,
                    grant,
                    local_pid,
                )
            }
        }
        // **A credential is not a grant** (§9.1, 0.8.2.19). With no handler grant
        // there is nothing to supply Dimensions 1-3, so a valid target-minted
        // credential does not rescue this: `relax_peers` is deliberately not read
        // on this arm. Fail-closed, as on the local branch.
        DispatchCeiling::Handler(None) => false,
    }
}

/// §1.4's presented-credential verifications (0.8.2.19). Every one already
/// existed in this tree; this is a composition, not new machinery.
///
/// **This is a predicate, not an authorizer.** Its `true` means exactly *"§1.4's
/// one exemption applies: Dimension 4 of the executing handler's grant is
/// relaxed to the peers this credential covers."* It never means *authorized* —
/// see [`outbound_sub_dispatch_authorized`] for what F67 was and why the return
/// type is the fix.
///
/// Returns `false` — *"not presented authority"*, never an error — for any
/// failure, because §1.4's disposition for a credential failing any of these is
/// that it **relaxes nothing and the handler grant gates unrelaxed**, not that
/// the dispatch is refused outright.
#[allow(clippy::too_many_arguments)]
fn presented_credential_relaxes_peers(
    shared: &PeerShared,
    cap_entity: &entity_entity::Entity,
    included: &HashMap<entity_hash::Hash, entity_entity::Entity>,
    handler_pattern: &str,
    operation: &str,
    target_peer: &str,
    resource: Option<&entity_capability::ResourceTarget>,
) -> bool {
    let token = match entity_capability::CapabilityToken::from_entity(cap_entity) {
        Ok(t) => t,
        Err(_) => return false,
    };

    // (a) The authority `granter`-roots at the TARGET peer (§3.6).
    //
    // §1.4 says *"granter resolves to the target peer's identity"*, and read at
    // the LEAF that sentence forbids attenuation — which is the one narrowing
    // move the chain model exists for. A peer handed a broad connection grant by
    // the target and re-attenuating it to a single operation before spending it
    // presents a leaf whose granter is ITSELF; that is strictly safer than
    // spending the root, and the leaf-equality reading refuses exactly it. Our
    // own `follow(Continuation)` standing leg is that shape
    // (`mint_cross_peer_chain_capability` — re-attenuate the handshake grant),
    // and it is what measured the difference: leaf-equality reddened it while
    // the reentry row stayed green, because that row's cap happens to be a root.
    //
    // The property that actually holds is about the chain's ROOT, and the
    // enforcing construct is named rather than described: §5.5 root-trust in
    // `verify_capability_chain` below, whose `local_peer_id` argument is passed
    // as `target_peer` — a single-sig root whose granter is not the target
    // fails `NotLocalPeer`, and a multi-sig root the target did not sign fails
    // M6. So (a) is not a separate check here; it is the frame argument at (c),
    // and moving that argument back to our own peer id is what would silently
    // remove it.
    //
    // The target's derived identity hex is still load-bearing one frame up: it
    // is how the standing handshake credential is located, so an underivable
    // target identity yields no session candidate at all.

    // (b) `grantee` resolves to the LOCAL peer's identity.
    if token.grantee != shared.identity_hash {
        return false;
    }

    // (c) Valid: chain-verified, unexpired, unrevoked (§5.5; §6.2's *Capability
    //     validity* rule already binds this at sub-dispatch).
    //
    // The chain is walked against the same sources the outbound bundler uses —
    // the presented entity itself, the parent envelope's `included`, then the
    // local store — so a chain that will travel with the EXECUTE is a chain that
    // verifies here.
    let resolve = |h: &entity_hash::Hash| -> Option<entity_entity::Entity> {
        if h == &cap_entity.content_hash {
            return Some(cap_entity.clone());
        }
        included
            .get(h)
            .cloned()
            .or_else(|| shared.content_store.get(h))
    };
    let mut bundle =
        match entity_protocol::collect_chain_bundle(&cap_entity.content_hash, resolve, |p| {
            shared.location_index.get(p)
        }) {
            Ok(b) => b.into_iter().collect::<std::collections::BTreeMap<_, _>>(),
            Err(_) => return false,
        };
    // Verify against the SAME set the far side will: `collect_chain_bundle`
    // finds a detached §5.5 signature only through the location index, and a
    // §7a.2a signature rides in-band — it is in `included` and bound at no
    // local path. The outbound branch merges `included` into `chain_bundle`
    // for exactly this reason (V7 §3.3 v7.51), so verifying without the merge
    // measures a bundle that never travels: `MissingSignature` here on a
    // capability the recipient verifies fine. Bundle entries win on collision —
    // the chain walk's own resolution is authoritative for the links.
    for (h, ent) in included.iter() {
        bundle.entry(*h).or_insert_with(|| ent.clone());
    }
    // The GRANTER'S frame, not ours — see the framing note on the caller, and
    // note this argument decides more than canonicalization here. §5.5's
    // root-trust rule is *"the single-sig root's granter must be the local
    // peer"*, which is correct for a capability rooted in OUR authority and
    // exactly wrong for one the target minted: passing our own peer id rejects
    // every target-issued credential with `NotLocalPeer`, which is the shape
    // this arm exists to accept. Revocation qualifies its §5.1 marker paths the
    // same way, so a marker we hold for the target's namespace (V7 §1.4
    // Category A — a mirrored foreign subtree) is the one consulted; the
    // authoritative check still runs at the target on receipt.
    if entity_protocol::verify_capability_chain(&cap_entity.content_hash, &bundle, target_peer)
        .is_err()
    {
        return false;
    }

    // (c2) §1.4 *"Root granter under multi-signature"* `[MUST]` (0.8.2.19 / E3).
    //
    // The root-granter rule — *"the chain's ROOT `granter` resolves to the
    // target peer's identity"* — is undefined for a §3.6 `multi-granter`, and
    // M3 makes multi-signature root-ONLY, so a K-of-N-rooted credential is
    // exactly where it lands. Passing `target_peer` as the frame above does not
    // answer it: on a multi-sig root §5.5's root-trust becomes M6, which asks
    // whether the frame peer is *among* the signers and signed — i.e. *"the
    // target is one constituent of the group"*. 0.8.2.19 rules that
    // insufficient. **A K-of-N root is a GROUP's authority, and treating a
    // constituent as the granter would let any one signer's target confer the
    // group's grant.** The credential satisfies the check only when the target's
    // identity IS the multi-granter, which no `system/peer` identity can be — so
    // this is deliberate under-acceptance, stated at the code because a reader
    // who finds M6 already passing will otherwise conclude the case is handled.
    //
    // Fails closed on an unwalkable chain for the same reason `is_revoked` does:
    // "relaxes nothing" is the safe answer, and `verify_capability_chain` has
    // already walked this chain successfully one statement up.
    match entity_protocol::collect_authority_chain(&cap_entity.content_hash, |h| {
        bundle.get(h).cloned()
    }) {
        Ok(chain) => match chain.last() {
            Some((_, root_fields)) => {
                if matches!(root_fields.granter, entity_capability::Granter::Multi(_)) {
                    return false;
                }
            }
            None => return false,
        },
        Err(_) => return false,
    }

    if entity_protocol::is_revoked(
        &cap_entity.content_hash,
        target_peer,
        // Same three sources as the bundler's resolver, and for the same reason:
        // a §7a.2a capability arrives in-band and is in NEITHER the store nor
        // `included` under its own hash until it is folded in. Resolving without
        // the presented entity itself makes `collect_authority_chain` fail, and
        // `is_revoked` fails closed on an unwalkable chain — so the leaf would
        // read as REVOKED and every in-band presented capability would fall to
        // the ambient arm. (Measured: that is what reddened
        // `dispatch_outbound_reentry_with_in_band_authority` before this arm
        // named the entity.)
        |h| {
            if h == &cap_entity.content_hash {
                return Some(cap_entity.clone());
            }
            shared
                .content_store
                .get(h)
                .or_else(|| included.get(h).cloned())
        },
        |p| shared.location_index.get(p),
        // A capability the target minted for us is a wire-only cap from this
        // peer's side — it has no canonical local storage path, so the
        // path-binding half of §5.1 does not apply and the marker check does.
        |_| None,
    ) {
        return false;
    }

    // (d) Coverage: the credential MUST *additionally* cover the request on its
    //     OWN four dimensions, evaluated in the granter's frame — see the
    //     framing note on `outbound_sub_dispatch_authorized`. "Additionally" is
    //     the whole of it: this is a second bound on top of the handler grant,
    //     never a substitute for it.
    entity_capability::check_permission(
        operation,
        handler_pattern,
        target_peer,
        resource,
        &token,
        target_peer,
    )
}

/// `ceiling` bounds §5.2's resource dimension for sub-dispatches made through
/// the returned `execute_fn` — see [`DispatchCeiling`] and the check on the
/// local branch below.
pub fn make_execute_fn(
    shared: Arc<PeerShared>,
    author: Option<entity_hash::Hash>,
    included: HashMap<entity_hash::Hash, entity_entity::Entity>,
    parent_bounds: Option<entity_handler::Bounds>,
    parent_caller_capability: Option<entity_capability::CapabilityToken>,
    ceiling: DispatchCeiling,
) -> ExecuteFn {
    Arc::new(
        move |handler_path: String,
              operation: String,
              params: entity_entity::Entity,
              opts: ExecuteOptions| {
            let shared = shared.clone();
            let author = author;
            let mut included = included.clone();
            let parent_bounds = parent_bounds.clone();
            // §6.13(b) seam: fold any explicit `opts.included` authority chain
            // into the dispatch's included set at a single point so BOTH the
            // remote branch (merged into the outbound envelope's `included` via
            // `chain_bundle`) and the local branch (threaded into the child
            // context's `included`) carry it. Used when the chain rides in-band
            // (GUIDE-CONFORMANCE §7a.2a) rather than in the local store, where
            // `collect_chain_bundle` cannot reach it. Content-addressed dedup —
            // entries already present are not duplicated; empty for ordinary
            // dispatch (no behavior change).
            for ent in &opts.included {
                included
                    .entry(ent.content_hash)
                    .or_insert_with(|| ent.clone());
            }
            // V7 §6.8 / proposal §6.2: caller_capability propagates unchanged through
            // sub-dispatch chains so history transitions record the original external
            // caller, not the intermediate handler.
            let parent_caller_capability = parent_caller_capability.clone();
            let ceiling = ceiling.clone();
            Box::pin(async move {
                let local_pid = shared.keypair.peer_id();
                let is_remote = crate::remote::is_remote_uri(&handler_path, local_pid.as_str());

                tracing::debug!(
                    handler_path = %handler_path,
                    operation = %operation,
                    params_type = %params.entity_type,
                    remote = is_remote,
                    "internal dispatch"
                );

                // --- Remote dispatch: send EXECUTE to remote peer ---
                if is_remote {
                    let remote_peer_id = crate::remote::extract_peer_id_from_uri(&handler_path)
                        .ok_or_else(|| {
                            HandlerError::Internal(format!(
                                "cannot extract peer_id from remote URI: {}",
                                handler_path
                            ))
                        })?;

                    // EXTENSION-CONTINUATION §3.6 step 5 / §4.2 case 3 / §4.3:
                    // a continuation dispatch carries its scoped
                    // `dispatch_capability` (opts.capability) as the EXECUTE
                    // capability — never a silent fallback to the broad
                    // connection grant (V7 §6.8 — the cross-peer silent-
                    // escalation Amendment-2's recipe step 2 forbids). Its full
                    // authority chain (persisted locally at install, §3.2 step 5)
                    // is bundled into the dispatched envelope's `included` so the
                    // verifying peer can validate it to a root it recognizes
                    // (§4.3 chain transport — the general V7 §3.1/§3.2 rule
                    // places only the leaf). Ordinary internal dispatch (no
                    // opts.capability) is unchanged: None + empty bundle.
                    let empty_bundle = std::collections::HashMap::new();
                    // Chain resolution reads the **in-band** authority first,
                    // then the local store. §3.2 step 5 persists an installed
                    // chain locally, and a store-only resolver serves every
                    // such dispatch correctly — but GUIDE-CONFORMANCE §7a.2a
                    // hands the chain to the dispatcher *in params* (cap +
                    // granter identity + signature), and those entities are
                    // deliberately not in this peer's store. Resolving only
                    // against the store made §4.3's MUST unsatisfiable on that
                    // path: the bundler could not reach a chain it was
                    // physically holding, and every reentrant dispatch-outbound
                    // died at `chain_unreachable` → 502 (core-go's
                    // `origination.dispatch_outbound_reentry`, established
                    // 2026-08-14-e; ours, introduced with the §4.3 fail-closed
                    // at deb5127).
                    //
                    // Reading them here is transport assembly, not an authority
                    // decision: `included` is exactly what would have travelled
                    // to B anyway (it is merged into `chain_bundle` below), and
                    // B verifies every signature and link itself (V7 §5.5).
                    //
                    // ORDERING, and it is load-bearing: this block runs BEFORE
                    // the PD-2 outbound check below, not after. §4.3's
                    // `chain_unreachable` is a statement about a chain the
                    // dispatcher physically cannot assemble, and it must keep
                    // its precedence — a cap whose granter identity resolves
                    // nowhere also fails PD-2's presented arm (it cannot be
                    // shown to be target-minted), so running PD-2 first turns
                    // every §4.3 refusal into a 403 and silently retires the
                    // control that proves the fail-closed still bites
                    // (`unresolvable_granter_identity_still_fails_the_bundle`).
                    // Both refusals happen before the dial either way.
                    let resolve_chain = |h: &entity_hash::Hash| -> Option<entity_entity::Entity> {
                        if let Some(cap) = opts.capability.as_ref() {
                            if &cap.content_hash == h {
                                return Some(cap.clone());
                            }
                        }
                        included
                            .get(h)
                            .cloned()
                            .or_else(|| shared.content_store.get(h))
                    };
                    let (dispatch_cap, mut chain_bundle) = match opts.capability.as_ref() {
                        Some(cap) => match entity_protocol::collect_chain_bundle(
                            &cap.content_hash,
                            resolve_chain,
                            |p| shared.location_index.get(p),
                        ) {
                            Ok(bundle) => (Some(cap), bundle),
                            Err(e) => {
                                // EXTENSION-CONTINUATION v1.22 §4.3: a bundler
                                // that cannot resolve a chain link — or the
                                // `system/peer` identity of any granter or
                                // grantee in it — MUST fail HERE with
                                // `chain_unreachable` rather than dispatch an
                                // incomplete bundle. The prior behaviour sent
                                // the leaf alone and let B fail closed; that is
                                // not an escalation, but it is non-conformant
                                // and it moved a defect the dispatcher can see
                                // (and name) into a 401 on the far side that
                                // reads as the target's problem.
                                tracing::warn!(
                                    cap = %cap.content_hash,
                                    error = %e,
                                    "continuation dispatch: authority chain or a \
                                     granter/grantee identity is unresolvable; \
                                     refusing to dispatch an incomplete bundle"
                                );
                                return Err(HandlerError::Internal(
                                    "chain_unreachable".to_string(),
                                ));
                            }
                        },
                        None => (None, empty_bundle),
                    };

                    // §1.4 "The enforcement point, and the authority it runs
                    // against" (0.8.2.17 — PD-2). BEFORE the dial, not merely
                    // before the send: a sub-dispatch the peer may not make is
                    // not a reason to open a connection to the peer it may not
                    // reach. `handler_pattern` is the requested handler with the
                    // peer prefix stripped — the same bare form a grant's
                    // `handlers` scope is written in, so both sides canonicalize
                    // into one frame.
                    //
                    // This replaces the reasoning the old code carried at the
                    // local branch: *"the remote branch sends an EXECUTE that the
                    // receiving peer authorizes through its own dispatch_request
                    // check, so the dimension binds there already."* It does not.
                    // The far peer authorizes against what it granted US; it
                    // cannot see whether our handler was steered into asking, and
                    // Dimension 4 is the ceiling on exactly that.
                    let bare_handler = entity_entity::EntityUri::strip_peer_prefix(
                        entity_entity::EntityUri::extract_handler_path(&handler_path),
                    );
                    if !outbound_sub_dispatch_authorized(
                        shared.as_ref(),
                        &ceiling,
                        opts.capability.as_ref(),
                        &included,
                        bare_handler,
                        &operation,
                        &remote_peer_id,
                        opts.resource.as_ref(),
                        local_pid.as_str(),
                    ) {
                        tracing::warn!(
                            handler_path = %handler_path,
                            operation = %operation,
                            target_peer = %remote_peer_id,
                            "outbound sub-dispatch denied: the executing handler's \
                             grant does not authorize it, and a target-minted \
                             credential relaxes Dimension 4 only (§1.4 PD-2, \
                             0.8.2.19)"
                        );
                        return Ok(entity_handler::HandlerResult::error(
                            STATUS_FORBIDDEN,
                            make_error_response_entity(
                                "capability_denied",
                                &format!(
                                    "no authority to sub-dispatch {} at peer {}",
                                    operation, remote_peer_id
                                ),
                            ),
                        ));
                    }

                    let conn: std::sync::Arc<dyn crate::remote::RemoteEndpoint> =
                        crate::remote::get_or_connect(
                            &shared.remote,
                            &remote_peer_id,
                            &shared.keypair,
                            shared.content_store.as_ref(),
                            shared.location_index.as_ref(),
                            local_pid.as_str(),
                            shared.connector.as_ref(),
                            shared.config.home_hash_format,
                            // §6.11(b): if this connection has to be freshly
                            // dialed, give its reader a reentry dispatch context
                            // so deliveries the remote pushes back reach us.
                            Some(shared.clone()),
                        )
                        .await
                        .map_err(|e| {
                            HandlerError::Internal(format!(
                                "remote connection to {}: {}",
                                remote_peer_id, e
                            ))
                        })?;

                    // Class G / F-WB28: multiplexed connection — no per-conn lock.
                    // Concurrent dispatches proceed via per-request oneshot demux.

                    let resource = opts.resource.as_ref();

                    // Per CONTINUATION §3.5 step 4 + INBOX §4.5: if deliver_to is set,
                    // include it on the wire EXECUTE so the remote peer handles delivery
                    // asynchronously (returns 202, delivers result to inbox directly).
                    // generate_internal_deliver_token is implementation-defined (§8.4).
                    // We generate a scoped token after handshake since INBOX §5.1
                    // requires grantee = remote peer identity.
                    let deliver_to_params = if let Some(ref dt) = opts.deliver_to {
                        match crate::remote::generate_deliver_token(
                            &shared.keypair,
                            conn.remote_identity_hash(),
                            &dt.uri,
                            &dt.operation,
                        ) {
                            Ok(p) => Some(p),
                            Err(e) => {
                                tracing::warn!(
                                    deliver_uri = %dt.uri,
                                    error = %e,
                                    "internal dispatch: failed to generate deliver_token, falling back to sync"
                                );
                                None
                            }
                        }
                    } else {
                        None
                    };

                    // V7 §3.3 v7.51: request-side envelope-`included` preservation.
                    // When an internal sub-dispatch is forwarded to a remote peer,
                    // the parent envelope's `included` map MUST travel with the
                    // forwarded EXECUTE — otherwise downstream continuations
                    // (e.g. EXTENSION-CONTINUATION `deref_included` over an
                    // `include_payload`-bundled entity) cannot resolve hash refs
                    // the parent put there. Merge into the existing extra-included
                    // bundle (envelope.include dedupes on hash, so capability-chain
                    // entries already present are not duplicated).
                    for (h, ent) in included.iter() {
                        chain_bundle.entry(*h).or_insert_with(|| ent.clone());
                    }

                    // §3.11 / bounds-propagation Delta 1: the cross-peer EXECUTE
                    // MUST carry `system/bounds` (chain_id/chain_depth/ttl/budget)
                    // — the pre-fix remote branch dropped them, so a cross-peer
                    // continuation chain had nothing accumulating. Same child
                    // bounds the local branch installs: explicit `opts.bounds`
                    // override (a continuation advance passes its §3.6-step-6
                    // bounds here, chain_depth already incremented), else the
                    // decremented parent bounds (§5.9), else none.
                    let wire_bounds = match opts.bounds.clone() {
                        Some(b) => Some(b),
                        None => match parent_bounds {
                            Some(ref pb) => Some(pb.decrement().map_err(|_| {
                                HandlerError::Internal("ttl_exhausted".to_string())
                            })?),
                            None => None,
                        },
                    };

                    let resp = match crate::remote::send_execute(
                        conn.as_ref(),
                        &shared.keypair,
                        &handler_path,
                        &operation,
                        &params,
                        resource,
                        deliver_to_params.as_ref(),
                        dispatch_cap,
                        &chain_bundle,
                        wire_bounds.as_ref(),
                    )
                    .await
                    {
                        Ok(r) => r,
                        Err(e) => {
                            // Transport error on a connection we believed active
                            // (§10 step 1): evict the dead conn from the pool AND
                            // demote peer liveness to suspect (Amendment 12 §A1),
                            // idempotently under the no-clobber guard.
                            crate::liveness::demote_peer_on_transport_error(
                                &shared,
                                &remote_peer_id,
                                &conn,
                                &e.to_string(),
                            );
                            return Err(HandlerError::Internal(format!(
                                "remote execute to {}: {}",
                                remote_peer_id, e
                            )));
                        }
                    };

                    // §6.5 envelope-signature ingestion over **any received
                    // envelope carrying an `included` map** (0.8.2.19 / E4).
                    //
                    // D7 (0.8.2.18) extended ingestion from the inbound EXECUTE
                    // to the connect/authenticate response — the *initial-grant*
                    // carrier — and left the **runtime** one unbound. §6.2 says
                    // which carrier is the deliberate one: the capability
                    // handler is *"the runtime entry point for in-band
                    // capability management, while §4.4 covers initial-grant
                    // delivery"*, and its `request`/`delegate` result envelope
                    // carries the same three entities — the issued token, its
                    // signature at the §3.5 invariant-pointer path, and the
                    // granter identity. An `EXECUTE_RESPONSE` is neither an
                    // inbound EXECUTE nor a connect response, so nothing here
                    // reached it.
                    //
                    // So a peer that goes and ACQUIRES a target-minted credential
                    // in order to make a presented-authority sub-dispatch
                    // acquired it with its signature bound at no path — the
                    // identical defect the connect-response ingest closed one
                    // surface earlier, and invisible for the same reason: the
                    // far side verifies against its own store, where its own
                    // signature is bound.
                    //
                    // Best-effort, matching the connect-response site: a
                    // conflict is logged, not propagated. A `signature_path_
                    // conflict` on a *response* has no envelope to reject — the
                    // request already succeeded at the far peer — and turning it
                    // into a dispatch error would fail a call whose result is
                    // valid.
                    if !resp.included.is_empty() {
                        let ingest_set: std::collections::BTreeMap<
                            entity_hash::Hash,
                            entity_entity::Entity,
                        > = resp.included.iter().map(|(h, e)| (*h, e.clone())).collect();
                        if let Err(e) = crate::ingest::ingest_envelope_signatures(
                            &ingest_set,
                            shared.content_store.as_ref(),
                            shared.location_index.as_ref(),
                        ) {
                            tracing::warn!(
                                remote_peer = %remote_peer_id,
                                error = %e,
                                "EXECUTE_RESPONSE signature ingestion failed; a \
                                 capability issued in this response may not verify \
                                 locally (§6.5, 0.8.2.19)"
                            );
                        }
                    }

                    tracing::debug!(
                        handler_path = %handler_path,
                        remote_peer = %remote_peer_id,
                        status = resp.status,
                        has_deliver_to = opts.deliver_to.is_some(),
                        "internal dispatch: remote completed"
                    );

                    return Ok(entity_handler::HandlerResult {
                        status: resp.status,
                        result: resp.result,
                        // PROPOSAL §2: thread envelope.included from the
                        // remote response back into the HandlerResult so
                        // internal callers see the same subtree an external
                        // caller would have seen.
                        included: resp.included,
                    });
                }

                // --- Local dispatch ---
                // V1: Normalize, validate, and qualify handler path (R12)
                let bare = EntityUri::extract_handler_path(&handler_path);
                EntityUri::validate_path_input(bare).map_err(HandlerError::InvalidParams)?;
                let qualified = EntityUri::qualify_path(bare, local_pid.as_str());
                EntityUri::validate_absolute_path(&qualified)
                    .map_err(HandlerError::InvalidParams)?;

                // Resolve handler
                //
                // R2 (INBOX §3.6 option 3): local-dispatch
                // missing-handler returns the same shape as the wire-dispatch
                // missing-handler path at `dispatch_envelope` (see line ~485) —
                // 404 sync `HandlerResult` carrying a `system/protocol/error`
                // entity with `code: "handler_not_found"`. Previously this site
                // produced `Err(HandlerError::Internal("no handler for: <path>"))`,
                // which the SDK boundary flattened to `SdkError::HandlerError(_)`
                // — losing both the 404 status and the substrate code. The
                // VERIFICATION-R2 memo confirmed the wire path was conformant;
                // this aligns the local path so internal callers (SDK
                // `dispatch_execute`, recursive sub-dispatch) see the same
                // 4xx-bearing HandlerResult an external caller would.
                let resolved = match entity_handler::resolve_handler(
                    &qualified,
                    shared.content_store.as_ref(),
                    shared.location_index.as_ref(),
                    &shared.handler_registry,
                ) {
                    Some(r) => r,
                    None => {
                        tracing::warn!(handler_path = %handler_path, "internal dispatch: no handler found");
                        return Ok(entity_handler::HandlerResult::error(
                            entity_handler::STATUS_NOT_FOUND,
                            entity_handler::error_entity(
                                "handler_not_found",
                                &format!("no handler for path: {}", handler_path),
                            ),
                        ));
                    }
                };

                tracing::debug!(
                    handler = %resolved_handler_name(&resolved),
                    pattern = %resolved.pattern,
                    operation = %operation,
                    compiled = resolved.handler.is_some(),
                    "internal dispatch: handler resolved"
                );

                // Build a synthetic EXECUTE entity for the child context.
                // Per spec §3.4, params is an inline entity {content_hash, data, type}
                // — **spliced by `encode_entity`, which embeds `data` raw**
                // (§5.4). The `ciborium::from_reader` + `to_ecf` form this
                // replaces re-encoded the caller's params on every in-process
                // sub-dispatch, so an entity riding in params (a `tree:merge`
                // `source_envelope`, a §7a.2a reentry capability) was rewritten
                // once per hop. `extract_params_entity` is the matching read
                // half; the two are a pair and neither alone is enough.
                let execute_data = entity_wire::cbor_map_set_raw(
                    &entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
                        (entity_ecf::text("operation"), entity_ecf::text(&operation)),
                        (entity_ecf::text("request_id"), entity_ecf::text("internal")),
                        (entity_ecf::text("uri"), entity_ecf::text(&handler_path)),
                    ])),
                    "params",
                    &entity_wire::encode_entity(&params),
                )
                .map_err(|e| HandlerError::Internal(e.to_string()))?;
                let execute = entity_entity::Entity::new(entity_types::TYPE_EXECUTE, execute_data)
                    .map_err(|e| HandlerError::Internal(e.to_string()))?;

                // V2: Qualify and validate resource targets (R12)
                let resource_target = match opts.resource {
                    Some(mut rt) => {
                        let pid = shared.keypair.peer_id();
                        let mut qualified = Vec::with_capacity(rt.targets.len());
                        for t in &rt.targets {
                            EntityUri::validate_path_input(t)
                                .map_err(HandlerError::InvalidParams)?;
                            let q = EntityUri::qualify_path(t, pid.as_str());
                            if !q.contains('*') {
                                EntityUri::validate_absolute_path(&q)
                                    .map_err(HandlerError::InvalidParams)?;
                            }
                            qualified.push(q);
                        }
                        rt.targets = qualified;
                        // §5.2 subject rule (0.8.2.20) — the same narrowing the
                        // boundary has always applied here, because the effective
                        // set is a property of the REQUEST, not of whether a
                        // capability was checked: a reduction that lived only in
                        // the authorizer would give the same request a different
                        // arity answer depending on whether one was presented.
                        // It is the second of the two layers
                        // `the_dispatch_boundary_hands_the_handler_only_the_effective_targets`
                        // exists to observe, and it is unchanged.
                        //
                        // ⛔ **But the projection MUST NOT be lossy about its own
                        // EMPTINESS `[MUST]` (§3.3, 0.8.2.24 — N6).** Narrowing
                        // `targets:[P] exclude:[P]` to `[]` destroys the one fact
                        // N6 turns into a branch: it is then indistinguishable
                        // from a caller who named nothing, and the handler takes
                        // the ABSENT-CASE behaviour — on `tree:get`, a listing of
                        // the tree in answer to a request for one excluded path.
                        //
                        // **This seam and the INBOUND WIRE one are the same
                        // defect, and both are exempted identically.** A first
                        // pass here claimed the wire path was safe because
                        // `extract_resource_target` returns the raw pair — that
                        // read stopped one statement short. `dispatch_request`
                        // narrows again immediately after qualifying, and the
                        // wire vector proved it: with `core/tree`'s split already
                        // landed, a real EXECUTE carrying `targets:[qA]
                        // exclude:[qA]` still answered `200`, because the
                        // handler's `SelfExcluded` arm was unreachable. The two
                        // sites are kept in step deliberately; a seam that
                        // narrows and one that does not is how the same request
                        // gets two answers depending on which door it came in.
                        //
                        // So: narrow when narrowing leaves something, and leave
                        // the pair intact when it would not. The effective set is
                        // identical either way — `effective_targets` is what both
                        // `check_resource_scope` and
                        // `entity_handler::single_effective_target` call, and it
                        // is idempotent — so nothing downstream computes a
                        // different subject. What changes is only that the
                        // handler can still tell WHICH empty it has.
                        //
                        // ⚠ The residual is the same one stated at the inbound
                        // site, and is bounded the same way: a non-conformant
                        // consumer indexing `targets[0]` sees the excluded path,
                        // in the one case whose only conformant answer is a
                        // refusal. `entity_handler::single_effective_target` is
                        // the enforcement; this is defence in depth for the
                        // arity cases.
                        let effective =
                            entity_capability::effective_targets(Some(&rt), pid.as_str());
                        if !effective.is_empty() {
                            rt.targets = effective;
                        }
                        Some(rt)
                    }
                    None => None,
                };

                // §5.2 resource dimension — D1 of PROPOSAL-DISPATCH-AUTHORIZATION-FRAME.
                //
                // The conditional in §5.2's pseudocode is `resource_target is not
                // null`. It is a test on the FIELD, not on the door: there is no
                // wire-entry predicate and no `is_sub_dispatch` flag anywhere in
                // §5.2, so an in-process sub-dispatch carrying a resource is
                // checked exactly like a wire dispatch carrying one. This branch
                // previously ran NO capability check of any dimension.
                //
                // The ceiling is the DISPATCHING handler's grant — the deputy's
                // own authority — not the child's install grant (that is
                // `child_handler_grant` below, which authorizes the callee to
                // exist, never the caller to reach a path). This is the
                // confused-deputy shape: a handler granted `app/*` that
                // sub-dispatches `system/handler:register` with a
                // caller-influenced resource target must not install at `pwn`.
                // §6.2 assigns `register`/`unregister`'s install-path
                // authorization to this check and to nothing else, and `register`
                // ALWAYS carries a resource (§3.2 path-as-resource) — so a path
                // that skips it leaves handler installation authorized by nothing.
                //
                // Scoped to the local branch: the remote branch runs its own
                // four-dimension check at `outbound_sub_dispatch_authorized`
                // (§1.4, 0.8.2.17 — PD-2), which binds Dimension 4 as well and
                // has a second authority arm this one does not need. This
                // paragraph used to read *"the receiving peer authorizes through
                // its own dispatch_request check, so the dimension binds there
                // already"* — that is the reasoning PD-2 withdraws. The far peer
                // authorizes against what it granted us; it cannot see that our
                // handler was steered into asking.
                //
                // Fail-closed when the deputy holds no grant at all: a dispatch
                // that names a resource while its dispatcher can prove no
                // authority over any resource is the escalation, not a special
                // case. (§6.8 empty grants stay valid — an empty `grants` array
                // is a present grant that covers nothing, and it correctly denies
                // here rather than being absent.)
                if let Some(ref rt) = resource_target {
                    let target_peer = EntityUri::extract_peer(&qualified, local_pid.as_str());
                    let allowed = match ceiling {
                        // The peer dispatching in its own namespace as root.
                        DispatchCeiling::PeerRoot => true,
                        DispatchCeiling::Handler(Some(ref grant)) => {
                            entity_capability::check_permission(
                                &operation,
                                &resolved.pattern,
                                &target_peer,
                                Some(rt),
                                grant,
                                local_pid.as_str(),
                            )
                        }
                        DispatchCeiling::Handler(None) => false,
                    };
                    if !allowed {
                        tracing::warn!(
                            handler_path = %qualified,
                            operation = %operation,
                            targets = ?rt.targets,
                            "sub-dispatch denied: §5.2 resource dimension"
                        );
                        return Ok(entity_handler::HandlerResult::error(
                            STATUS_FORBIDDEN,
                            make_error_response_entity(
                                "capability_denied",
                                &format!(
                                    "capability does not grant {} on {} for the requested resource",
                                    operation, qualified
                                ),
                            ),
                        ));
                    }
                }
                // Ruling 9 / F1: `{step_index}` is the originating request ID,
                // and a CONSTANT SENTINEL IS NOT CONFORMANT. This default was
                // the literal `"internal"`, so every handler-to-handler
                // dispatch shared one id and every marker they produced
                // collided at `.../{chain}/internal/...`. A dispatch that has
                // no id needs a real one, not a name for the category.
                // (Callers that can name the dispatch better still should —
                // `ExecuteOptions::request_id`.)
                let request_id = opts
                    .request_id
                    .unwrap_or_else(|| format!("internal-{:016x}", rand::random::<u64>()));

                // Bounds: explicit override from opts, or decrement parent bounds (§5.9)
                let child_bounds = if let Some(b) = opts.bounds {
                    Some(b)
                } else if let Some(ref pb) = parent_bounds {
                    match pb.decrement() {
                        Ok(b) => Some(b),
                        Err(_) => {
                            return Err(HandlerError::Internal("ttl_exhausted".to_string()));
                        }
                    }
                } else {
                    None
                };

                // Load + validate child handler's grant from tree (§6.8, §S2/§S3).
                // Same check ladder as the wire dispatch path —
                // see load_local_handler_grant.
                //
                // Loaded before `child_execute_fn` because the child is the
                // deputy for anything IT sub-dispatches, so this is the §5.2
                // resource ceiling one level down (D1).
                let child_bare = entity_entity::EntityUri::strip_peer_prefix(&resolved.pattern);
                let (child_handler_grant, child_grant_hash) = load_local_handler_grant(
                    child_bare,
                    shared.location_index.as_ref(),
                    shared.content_store.as_ref(),
                    local_pid.as_str(),
                    shared.identity_hash,
                    shared.keypair.key_type(),
                    &shared.keypair.public_key_bytes(),
                );

                // The child is the deputy for anything IT sub-dispatches, and for
                // the spawned delivery re-dispatch further down — both need this
                // after `child_handler_grant` is moved into the context builder.
                let delivery_ceiling_grant = child_handler_grant.clone();

                // Build child context — params entity passed directly (already parsed)
                let child_execute_fn = make_execute_fn(
                    shared.clone(),
                    author,
                    included.clone(),
                    child_bounds.clone(),
                    parent_caller_capability.clone(),
                    DispatchCeiling::Handler(child_handler_grant.clone().map(Box::new)),
                );

                let log_name = resolved_handler_name(&resolved).to_string();

                // V7 §6.8 / proposal §6.2: caller_capability propagates from the
                // outer dispatch context so history records the original external
                // caller. Internal dispatch — matching_grant intentionally absent
                // (no capability constraints); capability_hash intentionally
                // absent (this is sub-dispatch, not a fresh caller-attributable
                // request).
                let mut builder = HandlerContext::builder(execute, params)
                    .pattern(resolved.pattern.clone())
                    .suffix(resolved.suffix.clone())
                    .request_id(request_id.clone())
                    .operation(operation.clone())
                    .execute_fn(child_execute_fn)
                    .included(included.clone());
                if let Some(g) = child_handler_grant {
                    builder = builder.handler_grant(g);
                }
                if let Some(c) = parent_caller_capability.clone() {
                    builder = builder.caller_capability(c);
                }
                if let Some(rt) = resource_target {
                    builder = builder.resource_target(rt);
                }
                if let Some(a) = author {
                    builder = builder.author(a);
                }
                if let Some(hgh) = child_grant_hash {
                    builder = builder.handler_grant_hash(hgh);
                }
                if let Some(b) = child_bounds {
                    builder = builder.bounds(b);
                }
                // Standing-model O1: the reactive-delivery-trigger classification
                // is declared per-dispatch by the caller (e.g. the inbox route)
                // and threaded onto the child context here — never inherited from
                // the parent, mirroring `is_external`. A bare internal dispatch
                // leaves it false.
                builder = builder.reactive_trigger(opts.reactive_trigger);
                let ctx = builder.build();

                // EXTENSION-INBOX §4.3 (v5.6, PROPOSAL-CONTENT-INGEST-PASS-THROUGH
                // D1): handler-initiated sub-dispatch with deliver_to
                // MUST follow the same async-spawning semantics as a wire-entry
                // EXECUTE with deliver_to, regardless of whether the target URI is
                // local or remote. Prior to this codification, the local-local
                // case silently dropped deliver_to, breaking any continuation
                // chain whose middle step targeted a local URI.
                //
                // The remote branch above (`if is_remote`) already packs
                // deliver_to into the wire EXECUTE; the wire-entry path on the
                // far side spawns async. The local-local case is what this
                // branch handles.
                if let Some(ref dt) = opts.deliver_to {
                    // ExecuteOptions carries entity_handler::DeliverySpec;
                    // process_async_delivery expects connection::DeliverySpec.
                    // Same shape, distinct types — bridge by field-wise copy.
                    let dt = DeliverySpec {
                        uri: dt.uri.clone(),
                        operation: dt.operation.clone(),
                    };
                    let request_id_for_delivery = request_id.clone();
                    let log_name_for_delivery = log_name.clone();
                    let shared_for_delivery = shared.clone();
                    // Build a fresh execute_fn for the spawned task —
                    // process_async_delivery re-dispatches via it. The ctx already
                    // owns its own execute_fn for any sub-dispatch the handler
                    // initiates; this one is for the delivery routing.
                    let delivery_execute_fn = make_execute_fn(
                        shared.clone(),
                        author,
                        included.clone(),
                        None, // bounds reset for the spawned re-dispatch
                        parent_caller_capability.clone(),
                        // Same deputy, so the same §5.2 ceiling (D1).
                        DispatchCeiling::Handler(delivery_ceiling_grant.map(Box::new)),
                    );

                    tracing::debug!(
                        handler = %log_name,
                        operation = %operation,
                        request_id = %request_id,
                        deliver_uri = %dt.uri,
                        deliver_operation = %dt.operation,
                        "internal dispatch: deliver_to set, spawning async delivery (D1)"
                    );

                    crate::runtime::spawn(async move {
                        process_async_delivery(
                            ctx,
                            &dt,
                            &delivery_execute_fn,
                            &request_id_for_delivery,
                            &log_name_for_delivery,
                            shared_for_delivery,
                            // No row-2 token to pass: a handler-initiated
                            // `deliver_to` (D1) carries no `deliver_token` —
                            // `ExecuteOptions` has no field for one — so this
                            // branch dispatches exactly as it did before. Local
                            // delivery is unaffected (no wire authority is
                            // involved); a D1 delivery whose target is REMOTE
                            // still has no row-2 authority and fails closed at
                            // the far side, unchanged. Threading the token
                            // through `ExecuteOptions` is the fix, and it is a
                            // handler-API change, not this one.
                            None,
                        )
                        .await;
                    });

                    // Return 202 Accepted synchronously. The handler runs in the
                    // spawned task; its result routes to deliver_to.uri via inbox.
                    let accepted = entity_entity::Entity::new(
                        "primitive/null",
                        vec![0xf6], // CBOR null
                    )
                    .map_err(|e| HandlerError::Internal(e.to_string()))?;
                    return Ok(entity_handler::HandlerResult {
                        status: 202,
                        result: accepted,
                        included: std::collections::HashMap::new(),
                    });
                }

                // GUIDE-INSPECTABILITY v1.2 §2.1 #3 — internal dispatch is its own
                // dispatcher↔handler-body boundary (peer.execute() / handler-to-
                // handler dispatch). Fire entry + exit hooks symmetric to the wire
                // dispatch site in dispatch_request.
                let internal_target_uri = if ctx.suffix.is_empty() {
                    ctx.pattern.clone()
                } else if ctx.pattern.ends_with('/') || ctx.suffix.starts_with('/') {
                    format!("{}{}", ctx.pattern, ctx.suffix)
                } else {
                    format!("{}/{}", ctx.pattern, ctx.suffix)
                };
                if !shared.dispatch_hooks.is_empty() {
                    fire_dispatch_hooks(
                        &shared,
                        &crate::DispatchEvent {
                            target_uri: internal_target_uri.clone(),
                            operation: ctx.operation.clone(),
                            params_hash: ctx.params.content_hash,
                            request_id: ctx.request_id.clone(),
                            timestamp_ms: dispatch_event_timestamp_ms(),
                            phase: crate::DispatchPhase::Entry,
                        },
                    );
                }

                // V7 §6.5: compiled handlers take priority; tree-only manifests fall
                // back to entity-native dispatch through the compute evaluator.
                let result = match &resolved.handler {
                    Some(handler) => handler.handle(&ctx).await,
                    None => {
                        #[cfg(feature = "compute")]
                        {
                            dispatch_tree_only_handler(&resolved, &ctx, shared.clone()).await
                        }
                        #[cfg(not(feature = "compute"))]
                        {
                            Err(HandlerError::Internal(
                                "tree-only handler requires the compute feature".to_string(),
                            ))
                        }
                    }
                };

                let (internal_status, internal_response_hash) = match &result {
                    Ok(r) => (r.status, r.result.content_hash),
                    Err(e) => (handler_error_slot(e).0, entity_hash::Hash::zero()),
                };
                if !shared.dispatch_hooks.is_empty() {
                    fire_dispatch_hooks(
                        &shared,
                        &crate::DispatchEvent {
                            target_uri: internal_target_uri,
                            operation: ctx.operation.clone(),
                            params_hash: ctx.params.content_hash,
                            request_id: ctx.request_id.clone(),
                            timestamp_ms: dispatch_event_timestamp_ms(),
                            phase: crate::DispatchPhase::Exit {
                                status: internal_status,
                                response_hash: internal_response_hash,
                            },
                        },
                    );
                }

                match &result {
                    Ok(r) => tracing::debug!(
                        handler = %log_name,
                        operation = %operation,
                        request_id = %request_id,
                        status = r.status,
                        result_type = %r.result.entity_type,
                        "internal dispatch: completed"
                    ),
                    Err(e) => tracing::warn!(
                        handler = %log_name,
                        operation = %operation,
                        request_id = %request_id,
                        error = %e,
                        "internal dispatch: handler error"
                    ),
                }
                result
            })
        },
    )
}

/// Extract the params entity from an EXECUTE entity's data (§3.4).
/// Params is an inline entity map {content_hash, data, type}.
/// Answer a §5.1 keepalive ping with a `system/network/pong` (§5.3):
/// echo the ping's `timestamp`/`sequence`, add the responder's clock as
/// `server_time`. Malformed params (missing/non-uint fields) get 400 —
/// a conforming pinger always sends both §5.2 fields.
fn build_pong_response(envelope: &Envelope, request_id: &str) -> Envelope {
    let params = extract_params_entity(&envelope.root);
    let decoded: Option<(u64, u64)> = (|| {
        let value: ciborium::Value = ciborium::from_reader(params.data.as_slice()).ok()?;
        let map = value.into_map().ok()?;
        let field = |key: &str| -> Option<u64> {
            map.iter().find_map(|(k, v)| match (k, v) {
                (ciborium::Value::Text(t), ciborium::Value::Integer(i)) if t == key => {
                    u64::try_from(*i).ok()
                }
                _ => None,
            })
        };
        Some((field("timestamp")?, field("sequence")?))
    })();
    let Some((timestamp, sequence)) = decoded else {
        return build_error_response(
            request_id,
            STATUS_BAD_REQUEST,
            "invalid_params",
            "ping params must carry uint timestamp + sequence (§5.2)",
        )
        .unwrap_or_else(|_| Envelope::new(envelope.root.clone()));
    };
    let server_time = crate::liveness::now_ms();
    // Alphabetic key order (ECF determinism): sequence, server_time,
    // timestamp.
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (
            entity_ecf::text("sequence"),
            entity_ecf::Value::Integer(sequence.into()),
        ),
        (
            entity_ecf::text("server_time"),
            entity_ecf::Value::Integer(server_time.into()),
        ),
        (
            entity_ecf::text("timestamp"),
            entity_ecf::Value::Integer(timestamp.into()),
        ),
    ]));
    match entity_entity::Entity::new("system/network/pong", data) {
        Ok(pong) => build_execute_response(request_id, 200, pong)
            .unwrap_or_else(|_| Envelope::new(envelope.root.clone())),
        Err(e) => build_error_response(
            request_id,
            500,
            "internal_error",
            &format!("pong construction: {}", e),
        )
        .unwrap_or_else(|_| Envelope::new(envelope.root.clone())),
    }
}

fn extract_params_entity(execute: &entity_entity::Entity) -> entity_entity::Entity {
    let default = || {
        entity_entity::Entity::new(
            "primitive/null",
            entity_ecf::to_ecf(&entity_ecf::Value::Null),
        )
        .unwrap_or_else(|_| entity_entity::Entity {
            entity_type: "primitive/null".to_string(),
            data: vec![0xf6], // CBOR null
            content_hash: entity_hash::Hash::zero(),
        })
    };

    // ⛔ **RAW SLICE, not a decoded `Value`.** This is the dispatch boundary
    // every handler's `ctx.params` comes through, and it used to rebuild
    // `data` with `entity_ecf::to_ecf(ev)` — a full decode + ECF re-encode of
    // the caller's params payload. §5.4 byte fidelity forbids that for an
    // entity's `data`, and params routinely *carries* entities: `tree:merge`'s
    // `source_envelope`, and GUIDE-CONFORMANCE §7a.2a's in-band reentry
    // capability / granter / signature, which `cbor_map_field_raw`'s own doc
    // comment says "MUST round-trip without a decode+re-encode cycle".
    //
    // ⚠ **This is why a handler-side fix alone is dead code**, and it is the
    // same shape as `0.8.2.24` N6: `to_ecf` sorts map keys, normalizes
    // non-minimal integer and length encodings, folds indefinite-length items
    // to definite and **drops tags**, so by the time a handler read
    // `ctx.params.data` the bytes had already been rewritten. An in-process row
    // that builds `HandlerContext` by hand cannot see it — the boundary is not
    // in the picture. `core/tree`'s merge rows are the floor;
    // `params_data_survives_the_dispatch_boundary_byte_for_byte` is the row
    // that crosses the socket.
    //
    // `decode_entity_parts` rather than `decode_entity`: §3.4's inline params
    // entity is written `{content_hash, data, type}` by every producer here,
    // but a `content_hash` is not load-bearing for dispatch and a peer that
    // omits it should still be served.
    let Some(params_raw) = entity_wire::cbor_map_field_raw(&execute.data, "params") else {
        return default();
    };
    match entity_wire::decode_entity_parts(params_raw) {
        Ok((entity_type, entity_data)) => {
            entity_entity::Entity::new(&entity_type, entity_data).unwrap_or_else(|_| default())
        }
        Err(_) => default(),
    }
}

/// Extract resource target from an EXECUTE entity's data (best-effort).
fn extract_resource_target(
    execute: &entity_entity::Entity,
) -> Option<entity_capability::ResourceTarget> {
    let value: ciborium::Value = ciborium::from_reader(execute.data.as_slice()).ok()?;
    let map = value.as_map()?;
    for (k, v) in map {
        if k.as_text() == Some("resource") {
            let resource_map = v.as_map()?;
            let mut targets = Vec::new();
            let mut exclude = Vec::new();
            for (rk, rv) in resource_map {
                match rk.as_text() {
                    Some("targets") => {
                        if let Some(arr) = rv.as_array() {
                            for item in arr {
                                if let Some(s) = item.as_text() {
                                    targets.push(s.to_string());
                                }
                            }
                        }
                    }
                    Some("exclude") => {
                        if let Some(arr) = rv.as_array() {
                            for item in arr {
                                if let Some(s) = item.as_text() {
                                    exclude.push(s.to_string());
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            if !targets.is_empty() {
                return Some(entity_capability::ResourceTarget { targets, exclude });
            }
        }
    }
    None
}

/// A delivery specification (per spec §3.11: system/delivery-spec).
#[derive(Debug, Clone)]
pub struct DeliverySpec {
    pub uri: String,
    pub operation: String,
}

// ---------------------------------------------------------------------------
// WB-27 / Class B — dispatcher-side `rejected` chain-error marker
//
// EXTENSION-CONTINUATION v1.20 §3.10.3: when the dispatcher refuses an inbound
// EXECUTE on cap-check AND that EXECUTE is a chain dispatch (Bounds.chain_id
// present per §3.10.3 scope), the dispatcher MUST bind a `rejected`-variant
// marker at the v1.20 path scheme + return ErrorData.rejected_marker as the
// mirror pointer per §3.10.4.
//
// Authority per §3.10.7: behavioral, not mechanism. Rust realizes the named
// `core/chain-errors` component-owned authority via direct local-store ops
// (the dispatcher's local-write surface doesn't traverse a cap-check). Same
// runtime mechanism as the continuation engine's `write_lost_error_marker`.
// ---------------------------------------------------------------------------

/// Build a `403 capability_denied` response envelope, binding the rejected-
/// variant chain-error marker on the way out when this is a chain dispatch.
/// Returns the response envelope; the marker hash (when bound) rides on
/// `ErrorData.rejected_marker` per v1.20 §3.10.4.
fn build_capability_denied_response(
    shared: &PeerShared,
    envelope: &Envelope,
    request_id: &str,
    author_hash: &entity_hash::Hash,
    handler_path: &str,
    message: &str,
) -> Envelope {
    let marker_hash =
        try_bind_rejected_marker(shared, envelope, request_id, author_hash, handler_path);
    entity_protocol::build_error_response_with_marker(
        request_id,
        STATUS_FORBIDDEN,
        "capability_denied",
        message,
        marker_hash,
    )
    .unwrap_or_else(|_| Envelope::new(envelope.root.clone()))
}

/// CONTINUATION v1.23 §3.4 A.1 self-collection, run from the dispatcher's
/// marker-bind path and throttled to once a minute per peer.
///
/// Best-effort and non-reactive: it removes observations out of this peer's own
/// tree under its own authority, and can never affect a dispatch.
///
/// Feature-gated on `continuation`, which is where the sweep lives — a build
/// without it still binds `rejected` markers and has no collector for them.
/// That is a real gap and it is stated rather than hidden: the sweep cannot be
/// lifted into a shared crate without adding an extension-to-extension edge the
/// crate DAG forbids (`AGENTS.md` — only four such edges are permitted), and
/// `network`, which is what pulls the reactive stack in, already implies
/// `continuation`. A `--no-default-features` peer that dispatches chains and
/// denies caps is the exposed configuration.
pub(crate) fn maybe_collect_chain_error_markers(shared: &PeerShared) {
    #[cfg(feature = "continuation")]
    {
        use std::sync::atomic::Ordering;

        let now_ms = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        const THROTTLE_MS: u64 = 60_000;

        // Claim the window before sweeping, so concurrent denials on different
        // connections do not each pay for a scan.
        let last = shared.last_marker_collect_ms.load(Ordering::Relaxed);
        if last != 0 && now_ms.saturating_sub(last) < THROTTLE_MS {
            return;
        }
        if shared
            .last_marker_collect_ms
            .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return; // another dispatch took this window
        }

        let retention = entity_continuation::retention_from_config(
            &shared.content_store,
            &shared.location_index,
            shared.peer_id.as_str(),
        )
        .unwrap_or(entity_continuation::DEFAULT_MARKER_RETENTION_MS);
        let collected = entity_continuation::collect_expired_markers(
            &shared.content_store,
            &shared.location_index,
            shared.peer_id.as_str(),
            retention,
            now_ms,
        );
        if collected > 0 {
            tracing::debug!(
                collected,
                retention_ms = retention,
                "v1.23 §3.4 A.1: dispatcher collected expired chain-error marker(s)"
            );
        }
    }
    #[cfg(not(feature = "continuation"))]
    let _ = shared;
}

/// Bind a rejected-variant marker when the rejected EXECUTE is a chain
/// dispatch. Returns `None` when the EXECUTE doesn't carry a `chain_id`
/// (per §3.10.3 scope — ordinary 403s have no marker) or when the bind
/// itself fails (logged via `tracing::warn!` per §3.10.8).
fn try_bind_rejected_marker(
    shared: &PeerShared,
    envelope: &Envelope,
    request_id: &str,
    author_hash: &entity_hash::Hash,
    handler_path: &str,
) -> Option<entity_hash::Hash> {
    let bounds = extract_bounds(&envelope.root)?;
    let chain_id = bounds.chain_id?;
    if chain_id.is_empty() {
        return None;
    }
    // CONTINUATION v1.23 §3.4 A.1: the binder is the collector, and this is a
    // binder. Before the bind, for the reason the continuation handler sweeps
    // before its own (a marker whose ORIGINATION timestamp already predates the
    // window must not be removed by the call that wrote it).
    //
    // Not deferrable to the continuation handler's sweep: that one runs on
    // continuation *advance*, and the peer this matters most for is one being
    // hammered with denied chain dispatches — caller-driven, unbounded, and
    // quite possibly never advancing a continuation of its own.
    maybe_collect_chain_error_markers(shared);
    // §3.10.6 timestamp-capture discipline: captured at failure-origination
    // (here — the dispatcher's cap-rejection IS the failure observation).
    let timestamp = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let requesting_peer_id = resolve_author_peer_id(envelope, author_hash);

    // Both coordinates come off the wire, and this marker is bound precisely
    // BECAUSE the sender's cap check failed — an unauthorized caller reaches
    // here by construction, so nothing upstream vetted these. Sanitize before
    // either value names a path segment (§1.4 / round-2 ruling 1). Sanitized
    // once, ahead of the body, so a marker's recorded coordinate always
    // matches where it is actually bound.
    //
    // The PATH gets the sanitized form; the BODY keeps the original
    // (§3.10.6's pinned schema, round-2 ruling 2). That split is what makes
    // collapsing lossless: an operator reading the marker that exists to
    // observe a hostile failure can still answer "what did the attacker
    // send?", which hashing the coordinate could not.
    let chain_id_segment = entity_entity::sanitize_path_segment(
        &chain_id,
        entity_entity::SENTINEL_UNSPECIFIED_CHAIN_ID,
    );
    let step_index_segment = entity_entity::sanitize_path_segment(
        request_id,
        entity_entity::SENTINEL_UNSPECIFIED_STEP_INDEX,
    );

    // §3.10.6 body fields (rejected kind): reason, timestamp, chain_id,
    // step_index, requesting_peer_id, attempted_uri. `chain_id` and
    // `step_index` hold the ORIGINALS — the body is the record, the path is
    // an index.
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (
            entity_ecf::text("attempted_uri"),
            entity_ecf::text(handler_path),
        ),
        (entity_ecf::text("chain_id"), entity_ecf::text(&chain_id)),
        (
            entity_ecf::text("reason"),
            entity_ecf::text("capability_denied"),
        ),
        (
            entity_ecf::text("requesting_peer_id"),
            entity_ecf::text(&requesting_peer_id),
        ),
        (entity_ecf::text("step_index"), entity_ecf::text(request_id)),
        (
            entity_ecf::text("timestamp"),
            entity_ecf::integer(timestamp as i64),
        ),
    ]));
    let entity = match entity_entity::Entity::new("system/runtime/chain-error-lost", data) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "WB-27: rejected-marker entity build FAILED");
            return None;
        }
    };
    let marker_hash = entity.content_hash;
    let marker_path = format!(
        "/{}/system/runtime/chain-errors/rejected/{}/{}/capability_denied/{}",
        shared.peer_id.as_str(),
        chain_id_segment,
        step_index_segment,
        marker_hash.to_hex(),
    );
    match shared.content_store.put(entity) {
        Ok(h) => {
            shared.location_index.set(&marker_path, h);
            Some(marker_hash)
        }
        Err(e) => {
            // §3.10.8 bind failure visibility.
            tracing::warn!(
                path = %marker_path,
                error = %e,
                "WB-27: rejected-marker store put FAILED",
            );
            None
        }
    }
}

/// Look up the author's peer_id (base58) from envelope.included by author
/// content hash. Falls back to the hash's hex form when the identity isn't
/// in the envelope — marker is informational so a fallback is fine.
fn resolve_author_peer_id(envelope: &Envelope, author_hash: &entity_hash::Hash) -> String {
    if let Some(identity) = envelope.find_included(author_hash) {
        if let Ok(v) = ciborium::from_reader::<ciborium::Value, _>(identity.data.as_slice()) {
            if let Some(map) = v.as_map() {
                for (k, val) in map {
                    if k.as_text() == Some("peer_id") {
                        if let Some(s) = val.as_text() {
                            return s.to_string();
                        }
                    }
                }
            }
        }
    }
    author_hash.to_hex()
}

/// Extract bounds from an EXECUTE entity's data (§3.11, §5.9).
///
/// Bounds is an inline entity at the `bounds` key with type `system/bounds`
/// and data containing optional ttl, budget, chain_id, visited.
pub fn extract_bounds(execute: &entity_entity::Entity) -> Option<entity_handler::Bounds> {
    let value: ciborium::Value = ciborium::from_reader(execute.data.as_slice()).ok()?;
    let map = value.as_map()?;
    for (k, v) in map {
        if k.as_text() == Some("bounds") {
            // Bounds is an inline entity {type, data, content_hash}
            // We want the data field decoded as a map
            let bounds_map = v.as_map()?;
            // Find the data field — it's CBOR bytes containing the bounds map
            for (bk, bv) in bounds_map {
                if bk.as_text() == Some("data") {
                    let data_bytes = bv.as_bytes()?;
                    let data_value: ciborium::Value =
                        ciborium::from_reader(data_bytes.as_slice()).ok()?;
                    return decode_bounds_data(&data_value);
                }
            }
            // Fallback: maybe bounds is encoded directly as a map (not inline entity)
            return decode_bounds_data(v);
        }
    }
    None
}

fn decode_bounds_data(value: &ciborium::Value) -> Option<entity_handler::Bounds> {
    let map = value.as_map()?;
    let mut bounds = entity_handler::Bounds::default();
    for (k, v) in map {
        match k.as_text() {
            Some("ttl") => {
                if let Some(i) = v.as_integer() {
                    bounds.ttl = u64::try_from(i).ok();
                }
            }
            Some("budget") => {
                if let Some(i) = v.as_integer() {
                    bounds.budget = u64::try_from(i).ok();
                }
            }
            Some("cascade_depth") => {
                if let Some(i) = v.as_integer() {
                    bounds.cascade_depth = u64::try_from(i).ok();
                }
            }
            Some("chain_depth") => {
                // Causal continuation-advancement depth, inherited across the
                // peer boundary (PROPOSAL-CONTINUATION-BOUNDS-PROPAGATION §4;
                // the §3.11 wire field beside cascade_depth). The receiver
                // initializes its local chain from this value.
                if let Some(i) = v.as_integer() {
                    bounds.chain_depth = u64::try_from(i).ok();
                }
            }
            Some("chain_id") => {
                if let Some(s) = v.as_text() {
                    bounds.chain_id = Some(s.to_string());
                }
            }
            Some("parent_chain_id") => {
                if let Some(s) = v.as_text() {
                    bounds.parent_chain_id = Some(s.to_string());
                }
            }
            Some("visited") => {
                if let Some(arr) = v.as_array() {
                    bounds.visited = arr
                        .iter()
                        .filter_map(|x| x.as_text().map(|s| s.to_string()))
                        .collect();
                }
            }
            _ => {}
        }
    }
    Some(bounds)
}

/// Extract deliver_to from an EXECUTE entity's data (§3.2).
pub fn extract_deliver_to(execute: &entity_entity::Entity) -> Option<DeliverySpec> {
    let value: ciborium::Value = ciborium::from_reader(execute.data.as_slice()).ok()?;
    let map = value.as_map()?;
    for (k, v) in map {
        if k.as_text() == Some("deliver_to") {
            let dt_map = v.as_map()?;
            let mut uri = None;
            let mut operation = "receive".to_string(); // default per spec
            for (dk, dv) in dt_map {
                match dk.as_text() {
                    Some("uri") => uri = dv.as_text().map(|s| s.to_string()),
                    Some("operation") => {
                        if let Some(s) = dv.as_text() {
                            operation = s.to_string();
                        }
                    }
                    _ => {}
                }
            }
            if let Some(uri) = uri {
                return Some(DeliverySpec { uri, operation });
            }
        }
    }
    None
}

/// Extract deliver_token hash from an EXECUTE entity's data (INBOX spec §2.3).
pub fn extract_deliver_token(execute: &entity_entity::Entity) -> Option<entity_hash::Hash> {
    let value: ciborium::Value = ciborium::from_reader(execute.data.as_slice()).ok()?;
    let map = value.as_map()?;
    for (k, v) in map {
        if k.as_text() == Some("deliver_token") {
            let bytes = v.as_bytes()?;
            return entity_hash::Hash::from_bytes(bytes).ok();
        }
    }
    None
}

/// V7 §4.4 v7.64 dual-form policy-table consultation at handshake time.
/// Resolution order: (1) hex form `system/capability/policy/{caller_peer_hex}`,
/// (2) Base58 form `system/capability/policy/{caller_peer_id_base58}`, (3)
/// `system/capability/policy/default`. The Base58 form is the V7 §3.6
/// v7.65 lazy-canonicalization site — operator may pre-configure a policy
/// using a pasted Base58 handle before any handshake with that peer; the
/// dual-form mechanism resolves it at handshake time when the pubkey
/// becomes available.
///
/// On a Base58-form hit the handler canonicalizes the entry (writes hex,
/// deletes Base58 — V7 §3.6 v7.65 §1117: idempotent via the v7.64
/// self-healing dual-form policy machinery, whose semantic narrows to
/// legacy-decode under v7.65). The `remote_peer_id_base58` passed here is
/// the canonical-form Base58 derived from the now-known pubkey per §1.5
/// v7.65 (Ed25519 → identity-multihash).
///
/// Closeout F8: fallback segment was `*` in v7.62; renamed to the literal
/// `default` to remove the glyph collision with `*`-as-glob.
fn lookup_capability_policy_grants(
    shared: &Arc<PeerShared>,
    remote_identity_hash: &entity_hash::Hash,
    remote_peer_id_base58: &str,
) -> Option<Vec<entity_capability::GrantEntry>> {
    let remote_hex = remote_identity_hash.to_hex();
    let by_hex = format!(
        "/{}/system/capability/policy/{}",
        shared.peer_id, remote_hex
    );
    if let Some(g) = decode_policy_grants_at(shared, &by_hex) {
        return Some(g);
    }
    let by_b58 = format!(
        "/{}/system/capability/policy/{}",
        shared.peer_id, remote_peer_id_base58
    );
    if let Some(g) = decode_policy_grants_at(shared, &by_b58) {
        // V7 §3.6 v7.65 lazy-canonicalization event: rebind under
        // canonical hex form. Idempotent + self-healing — concurrent
        // handshakes race to the same end state.
        if let Some(h) = shared.location_index.get(&by_b58) {
            shared.location_index.set(&by_hex, h);
            shared.location_index.remove(&by_b58);
            tracing::debug!(
                from = %by_b58,
                to = %by_hex,
                "V7 §3.6 v7.65: canonicalized pending-canonicalization \
                 Base58-form policy entry to canonical hex form"
            );
        }
        return Some(g);
    }
    let by_default = format!(
        "/{}/system/capability/policy/{}",
        shared.peer_id,
        entity_capability::POLICY_FALLBACK_SEGMENT
    );
    decode_policy_grants_at(shared, &by_default)
}

fn decode_policy_grants_at(
    shared: &Arc<PeerShared>,
    path: &str,
) -> Option<Vec<entity_capability::GrantEntry>> {
    let h = shared.location_index.get(path)?;
    let entity = shared.content_store.get(&h)?;
    if entity.entity_type != entity_types::TYPE_CAP_POLICY_ENTRY {
        return None;
    }
    let val: ciborium::Value = ciborium::de::from_reader(entity.data.as_slice()).ok()?;
    let map = val.as_map()?;
    for (k, v) in map {
        if k.as_text() == Some("grants") {
            let arr = v.as_array()?;
            let mut out = Vec::with_capacity(arr.len());
            for entry in arr {
                let g = entity_capability::decode_grant_entry(entry).ok()?;
                out.push(g);
            }
            return Some(out);
        }
    }
    None
}

/// Build an EXECUTE_RESPONSE error envelope for a handshake-phase
/// failure, routing the structured inner `ProtocolError` (when present)
/// through `wire_error_code()` so the wire surface matches the V7 §4.7
/// error registry (e.g., `400 unsupported_key_type` for v7.66 §4.4
/// surface 6) rather than collapsing to the generic `default_code`
/// catch-all. `default_code` is used when the error has no registry
/// entry — a malformed `hello`, for instance.
///
/// **That residual code is `invalid_request`, and it used to be
/// `handshake_failed` (0.8.2.5).** The note 0.8.2.5 added under §4.7 says
/// flatly *"Implementations MUST NOT emit `connection_required` or
/// `handshake_failed`"* — the justification it gives is that both are "minted
/// codes in no spec code set", which is a property of the code wherever it is
/// emitted, not of the one input the note was written about. The precedent it
/// cites is `invalid_signature`, a spelling §4.7 retired everywhere rather
/// than at one site. So the sweep is the whole call-site set, not just CE-1's.
///
/// `invalid_request` is the positive rule for what is left: §4.7 defines it as
/// *"a well-formed frame whose content the responder cannot act on as a
/// request"* and §3.3 names it the default 400 code. A `hello` whose params
/// are not a hello is exactly that.
///
/// **This retired a control, and the retirement is the point rather than a
/// side effect.** `prehello_authenticate_is_invalid_nonce_on_both_transports`
/// rows 5+6 pinned this default to `handshake_failed` precisely so that
/// "fixing" a §4.7 row by relabelling the catch-all would go red. That
/// discriminator is gone — the catch-all and row 10 now share a code because
/// the ruling says they are the same class — so the rows were rewritten to
/// assert what still discriminates: the residual is `(400, invalid_request)`
/// and specifically not row 6's `(401, invalid_nonce)`, not the out-of-order
/// row's `(409, connection_sequence_error)`, and not CE-1's `(401,
/// authentication_failed)`. Written down rather than quietly dropped, per the
/// charter entry on a control a re-route can retire without touching it.
fn handshake_error_envelope(inbound: &Envelope, err: &PeerError, default_code: &str) -> Envelope {
    let request_id = extract_request_id(inbound).unwrap_or_else(|| "unknown".to_string());
    let (status, code, message) = match err {
        PeerError::Protocol(pe) => (
            pe.wire_status_code(),
            pe.wire_error_code().unwrap_or(default_code).to_string(),
            pe.to_string(),
        ),
        PeerError::ConnectionError(s) | PeerError::BuildError(s) => {
            (STATUS_BAD_REQUEST, default_code.to_string(), s.clone())
        }
    };
    build_error_response(&request_id, status, &code, &message)
        .unwrap_or_else(|_| Envelope::new(inbound.root.clone()))
}

/// Extract request_id from an EXECUTE entity's data (best-effort).
fn extract_request_id(envelope: &Envelope) -> Option<String> {
    let value: ciborium::Value = ciborium::from_reader(envelope.root.data.as_slice()).ok()?;
    let map = value.as_map()?;
    for (k, v) in map {
        if k.as_text() == Some("request_id") {
            return v.as_text().map(|s| s.to_string());
        }
    }
    None
}

#[cfg(test)]
mod reentry_grant_tests {
    use super::*;
    use entity_crypto::{IdentityKeypair, Keypair};

    const FMT: u8 = 0x00;

    fn kp(seed: u8) -> IdentityKeypair {
        IdentityKeypair::Ed25519(Keypair::from_seed([seed; 32]))
    }

    fn identity_hash(kp: &IdentityKeypair) -> entity_hash::Hash {
        kp.peer_entity().unwrap().content_hash
    }

    /// These four are acceptance-side (signature) tests, so the grant *set* is
    /// not what they measure — the floor stands in for whatever
    /// `assemble_inbound_grants` would return on a live dialer. The Contents
    /// ruling is measured on the wire instead, by
    /// `test_s65_reciprocal_grant_is_the_assembled_inbound_grant`.
    fn grant_from(dialer: &IdentityKeypair, grantee: entity_hash::Hash) -> Envelope {
        crate::remote::build_reentry_grant_envelope(
            dialer,
            grantee,
            FMT,
            entity_capability::default_connection_grants(),
        )
        .unwrap()
    }

    fn cap_of(envelope: &Envelope) -> entity_entity::Entity {
        envelope
            .included
            .values()
            .find(|e| e.entity_type == entity_types::TYPE_CAP_TOKEN)
            .expect("grant carries its capability")
            .clone()
    }

    /// The producer's own frame satisfies the acceptance check — the pin that
    /// keeps `build_reentry_grant_envelope` and this verifier from drifting
    /// apart (they are the two halves of one cross-peer contract, and only a
    /// test that runs both catches a divergence before a live channel does).
    #[test]
    fn a_well_formed_grant_passes_acceptance() {
        let dialer = kp(70);
        let acceptor = kp(71);
        let envelope = grant_from(&dialer, identity_hash(&acceptor));
        let cap = cap_of(&envelope);
        assert!(verify_grant_signature(&envelope, &cap, identity_hash(&dialer)).is_ok());
    }

    /// A grant whose signature was stripped is refused at acceptance instead of
    /// being installed and failing `403 missing_signature` at first originate.
    #[test]
    fn a_grant_stripped_of_its_signature_is_refused() {
        let dialer = kp(72);
        let acceptor = kp(73);
        let mut envelope = grant_from(&dialer, identity_hash(&acceptor));
        let cap = cap_of(&envelope);
        envelope
            .included
            .retain(|_, e| e.entity_type != entity_entity::TYPE_SIGNATURE);
        assert!(verify_grant_signature(&envelope, &cap, identity_hash(&dialer)).is_err());
    }

    /// A signature that is well-formed and correctly targeted but signs under a
    /// key that is not the granter's does not verify. This is the case the
    /// structural checks (hash validation, granter == the authenticated peer)
    /// cannot see: the cap names the right granter and the signature names the
    /// right target — only the cryptography disagrees.
    #[test]
    fn a_grant_signed_by_someone_else_is_refused() {
        let dialer = kp(74);
        let acceptor = kp(75);
        let impostor = kp(76);
        let envelope = grant_from(&dialer, identity_hash(&acceptor));
        let cap = cap_of(&envelope);

        // Re-sign the same cap with the impostor's key, still claiming the
        // dialer as `signer` — the shape a forged grant would take.
        let sig_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("algorithm"),
                entity_ecf::text(impostor.key_type().label()),
            ),
            (
                entity_ecf::text("signature"),
                entity_ecf::Value::Bytes(impostor.sign(&cap.content_hash.to_bytes())),
            ),
            (
                entity_ecf::text("signer"),
                entity_ecf::Value::Bytes(identity_hash(&dialer).to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("target"),
                entity_ecf::Value::Bytes(cap.content_hash.to_bytes().to_vec()),
            ),
        ]));
        let forged =
            entity_entity::Entity::new_with_format(entity_entity::TYPE_SIGNATURE, sig_data, FMT)
                .unwrap();
        let mut forged_envelope = envelope.clone();
        forged_envelope
            .included
            .retain(|_, e| e.entity_type != entity_entity::TYPE_SIGNATURE);
        forged_envelope.include(forged);

        assert!(verify_grant_signature(&forged_envelope, &cap, identity_hash(&dialer)).is_err());
    }

    /// A grant from a peer other than the one we authenticated fails the signer
    /// leg — the local mirror of the `granter == connected peer` structural
    /// check, at the signature level.
    #[test]
    fn a_grant_attributed_to_another_peer_is_refused() {
        let dialer = kp(77);
        let acceptor = kp(78);
        let stranger = kp(79);
        let envelope = grant_from(&dialer, identity_hash(&acceptor));
        let cap = cap_of(&envelope);
        assert!(verify_grant_signature(&envelope, &cap, identity_hash(&stranger)).is_err());
    }
}

#[cfg(test)]
mod marker_injection_tests {
    use super::*;

    /// Ruling 13 / the `security.marker_path_injection_contained` probe.
    ///
    /// Go found a tree node literally named `..` in Rust's marker tree, put
    /// there by an unauthorized peer, and confirmed it with `probe-peer`
    /// before reporting
    /// (`entity-core-go` `docs/validation/reports/`
    /// `2026-07-16-marker-path-injection-cohort.md`). This drives the same
    /// shape at the binding site.
    ///
    /// What makes this sharp rather than an input-validation nit: the
    /// rejected marker is bound BECAUSE the sender's cap check failed, so an
    /// unauthorized caller reaches this site by construction. No capability
    /// is required to choose where the entity lands.
    ///
    /// The escape is NOT the leading-`../` form `clean_path` rejects — these
    /// values land in the MIDDLE of the path, where a normalizer resolves the
    /// interior `..` and walks the marker back OUT of the sink. So the
    /// assertion is on the CLEANED path: `sink/{X}/..` is inside the sink by
    /// string prefix while naming somewhere else.
    #[tokio::test]
    async fn rejected_marker_contains_wire_supplied_coordinates() {
        let peer = crate::PeerBuilder::new()
            .keypair(entity_crypto::Keypair::from_seed([0x9c; 32]))
            .build()
            .unwrap();
        let shared = peer.shared();
        let local_pid = shared.peer_id.as_str().to_string();

        // The probe's exact hostile values, in both wire-supplied coordinates.
        let hostile = "../../../../authority/keys";
        let bounds_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("chain_id"),
            entity_ecf::text(hostile),
        )]));
        let bounds_entity =
            entity_entity::Entity::new("system/execution-bounds", bounds_data).unwrap();
        let execute_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("bounds"),
            entity_ecf::Value::Map(vec![
                (
                    entity_ecf::text("data"),
                    entity_ecf::Value::Bytes(bounds_entity.data.clone()),
                ),
                (
                    entity_ecf::text("type"),
                    entity_ecf::text("system/execution-bounds"),
                ),
            ]),
        )]));
        let root = entity_entity::Entity::new("system/execute", execute_data).unwrap();
        let envelope = Envelope::new(root);
        let author = entity_hash::Hash::compute("test", b"unauthorized-peer");

        let bound = try_bind_rejected_marker(
            &shared,
            &envelope,
            hostile, // request_id -> {step_index}
            &author,
            "system/capability",
        );
        assert!(bound.is_some(), "a chain dispatch's 403 MUST bind a marker");

        let sink = format!("/{}/system/runtime/chain-errors/", local_pid);
        let paths: Vec<String> = shared
            .location_index
            .list(&sink)
            .into_iter()
            .map(|e| e.path)
            .collect();
        assert_eq!(paths.len(), 1, "expected exactly one marker: {:?}", paths);

        // The load-bearing assertion: contained under CLEANING, not merely
        // prefixed. Pre-fix this bound at `.../rejected/../../../../authority/keys/...`,
        // which cleans out of the sink entirely.
        let cleaned = EntityUri::clean_path(&paths[0]);
        assert!(
            cleaned.starts_with(&sink),
            "MARKER PATH INJECTION: a wire-supplied coordinate escaped the \
             chain-errors sink.\n  bound at:    {}\n  resolves to: {}",
            paths[0],
            cleaned,
        );
        // And no node named `..` anywhere in it — the shape probe-peer sees.
        assert!(
            !cleaned.split('/').any(|seg| seg == ".." || seg == "."),
            "a dot token survived as a path segment: {}",
            cleaned,
        );

        // Round-2 ruling 1: the hostile coordinates COLLAPSE to their
        // per-coordinate sentinels rather than hashing to a fresh node each.
        assert!(
            cleaned.contains(entity_entity::SENTINEL_UNSPECIFIED_CHAIN_ID),
            "hostile chain_id must collapse to its sentinel: {cleaned}"
        );
        assert!(
            cleaned.contains(entity_entity::SENTINEL_UNSPECIFIED_STEP_INDEX),
            "hostile step_index must collapse to its sentinel: {cleaned}"
        );

        // Round-2 ruling 2, and the reason collapsing is lossless: the BODY
        // recovers what the path collapsed. Without this the operator reading
        // the marker that exists to observe a hostile failure cannot answer
        // "what did the attacker send?" — which is exactly the one-way loss
        // that got the hashing rule reversed.
        let marker = shared
            .content_store
            .get(&bound.unwrap())
            .expect("marker entity missing from the store");
        let body: ciborium::Value = ciborium::from_reader(marker.data.as_slice()).unwrap();
        let field = |key: &str| -> Option<String> {
            match &body {
                ciborium::Value::Map(m) => m.iter().find_map(|(k, v)| match (k, v) {
                    (ciborium::Value::Text(t), ciborium::Value::Text(s)) if t == key => {
                        Some(s.clone())
                    }
                    _ => None,
                }),
                _ => None,
            }
        };
        assert_eq!(
            field("chain_id").as_deref(),
            Some(hostile),
            "the body MUST carry the original chain_id verbatim"
        );
        assert_eq!(
            field("step_index").as_deref(),
            Some(hostile),
            "the body MUST carry the original step_index (request id) verbatim"
        );

        // §3.10.6's registry, asserted as a set. The registry exists so that
        // equivalent markers hash-equal cross-impl; a field renamed here
        // silently breaks the §3.10.4 mirror-pointer walk against Go and
        // Python, and NO same-seat test would notice — every seat only ever
        // reads its own markers. Go shipped four divergent names for exactly
        // that reason. This is the assertion that would have caught it.
        let names: std::collections::BTreeSet<String> = match &body {
            ciborium::Value::Map(m) => m
                .iter()
                .filter_map(|(k, _)| match k {
                    ciborium::Value::Text(t) => Some(t.clone()),
                    _ => None,
                })
                .collect(),
            _ => panic!("marker body is not a CBOR map"),
        };
        let reserved: std::collections::BTreeSet<String> = [
            // Reserved across both kinds.
            "reason",
            "timestamp",
            "chain_id",
            "step_index",
            // Reserved on the `rejected` kind.
            "requesting_peer_id",
            "attempted_uri",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            names, reserved,
            "rejected-marker body drifted from the §3.10.6 registry"
        );
    }
}
