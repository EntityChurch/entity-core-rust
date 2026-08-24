//! The main-thread half of the §6.5 negotiation: one `RTCPeerConnection` per
//! `negotiation_id`, driven on behalf of a worker that cannot touch it.
//!
//! # Why the broker owns this
//!
//! `RTCPeerConnection` is `[Exposed=Window]` in the W3C IDL — main-thread only
//! on **every** engine. The worker holds the carrier and the signing identity
//! and runs the §10 dispatcher that decides to negotiate, so the worker drives
//! and the main thread executes. Each call arrives as a `ControlMessage` and is
//! answered by exactly one reply carrying the same `request_id`.
//!
//! # This is a sibling of `handle_open_channel`, not a reuse of it
//!
//! `handle_open_channel` structurally assumes **both** ends are registered
//! peers: it looks up `target_peer`, denies with "no such peer" if absent, and
//! routes `port2` to the target's control port as an `IncomingChannel`. That
//! path is peer-to-peer symmetric.
//!
//! The WebRTC far end is not a registered peer — it is a remote browser reached
//! over a data channel. So this handler is **broker-as-terminus**: no
//! target-peer lookup, no `IncomingChannel`, the broker **keeps** `port2` and
//! pumps `RTCDataChannel` ⇄ `port2` itself, and transfers only `port1` to the
//! requesting worker. `entity-browser-rust` verified that constraint against
//! `broker.rs` before any of this was written.
//!
//! # Testability, stated plainly
//!
//! Nothing in this file is exercised by `make test`. It is `web_sys` calls into
//! a browser API that does not exist in the test environment, and this repo has
//! no wasm-in-browser test runner. The parts that *could* be pure were pushed
//! out of it deliberately — `sdp_digest` and `verified_sdp_from_bytes` live
//! outside the wasm32 gate in `entity_peer::transport` and carry the
//! `[security — MUST]`. What remains here is glue whose first real exercise is
//! S5, and per §11.5.1 nothing before S5 is evidence that any of it works.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use entity_peer::transport::{
    verified_sdp_from_bytes, ControlMessage, WireIceServer, WireLocalCandidate,
};
use js_sys::{Array, Object, Uint8Array};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    MessageChannel, MessageEvent, MessagePort, RtcConfiguration, RtcDataChannel,
    RtcDataChannelEvent, RtcDataChannelInit, RtcDataChannelState, RtcDataChannelType,
    RtcIceCandidate, RtcIceCandidateInit, RtcPeerConnection, RtcPeerConnectionIceEvent, RtcSdpType,
    RtcSessionDescriptionInit,
};

/// Sessions live per control port, because `negotiation_id` is allocated per
/// `ControlPortClient`. Keying them globally would let two workers collide on
/// the same id and drive each other's `RTCPeerConnection`.
pub(crate) type Sessions = Rc<RefCell<HashMap<u64, Rc<WebRtcSession>>>>;

/// The label both sides must agree on for the negotiated data channel. Only
/// the offerer creates it; the answerer receives it via `ondatachannel`.
const CHANNEL_LABEL: &str = "entity";

/// Event closures held for a session's lifetime.
///
/// These are retained, never dropped early: a `MessagePort.onmessage` slot
/// still pointing at a dropped closure invalidates the JS function, which is
/// the same footgun the broker's one-handler-per-port design exists to avoid.
///
/// `Rc` because the buffering handler ([`attach_inbox`]) is installed from
/// inside the `ondatachannel` closure, which runs long before `&self` is
/// reachable and must still park its closure somewhere that outlives it.
type MessageClosures = Rc<RefCell<Vec<Closure<dyn FnMut(MessageEvent)>>>>;

/// Frames that arrived on the data channel before `wait_open` wired the
/// `MessagePort` pump. See [`attach_inbox`] for why this must exist.
type Inbox = Rc<RefCell<Vec<Vec<u8>>>>;

pub(crate) struct WebRtcSession {
    pc: RtcPeerConnection,
    /// Candidates gathered since the last drain. Trickle is the sole candidate
    /// path in §6.5, so the ICE agent pushes here and `WebRtcDrainCandidates`
    /// takes the batch.
    gathered: Rc<RefCell<Vec<WireLocalCandidate>>>,
    /// Set once the channel exists — by us if we offered, by `ondatachannel`
    /// if we answered.
    channel: Rc<RefCell<Option<RtcDataChannel>>>,
    /// Retained for the lifetime of the session; dropping a closure while the
    /// event handler slot still points at it invalidates the JS function.
    _on_ice: Closure<dyn FnMut(RtcPeerConnectionIceEvent)>,
    _on_datachannel: Closure<dyn FnMut(RtcDataChannelEvent)>,
    /// Pump closures, retained for the same reason. Populated at channel-open.
    pumps: MessageClosures,
    /// Frames caught between the channel becoming known and the pump being
    /// wired, drained into the port in arrival order by `wait_open`.
    inbox: Inbox,
    /// The broker's own end of the `MessageChannel`. Held for the session's
    /// life: dropping it closes the port and tears down the pump the instant
    /// `wait_open` returns.
    kept_ports: RefCell<Vec<MessagePort>>,
}

impl WebRtcSession {
    /// Mint an `RTCPeerConnection` and start collecting trickled candidates.
    ///
    /// # `ice_servers` — and what an empty one means
    ///
    /// Provisioned per `PROTOCOL_VERSION` v11 (`InitParams.webrtc.ice_servers`)
    /// and delivered on the `WebRtcOpen` that asks for this connection, so the
    /// values reach the `RTCConfiguration` from the same source of truth the
    /// worker was provisioned with — main/worker skew is not merely avoided
    /// here, it has nowhere to enter.
    ///
    /// **Empty is legal and is not a missing value.** With no ICE servers the
    /// browser's agent gathers **host candidates only**: correct and
    /// sufficient for S5 rung 1 (two browsers, one host or one LAN), and no
    /// path at all between two NAT'd browsers. Nothing is substituted in that
    /// case — a built-in public STUN default would enroll a third party on the
    /// operator's behalf, silently, so the emptiness stays visible instead.
    ///
    /// **S5 rung-2 implication, unchanged:** two real browser peers across
    /// NATs provisioned with no ICE servers fail by gathering nothing useful
    /// rather than by erroring. That is the browser's G4-equivalent — operator
    /// STUN infra — not a defect in this file.
    pub(crate) fn new(ice_servers: &[WireIceServer]) -> Result<Rc<Self>, String> {
        let cfg = RtcConfiguration::new();
        if !ice_servers.is_empty() {
            cfg.set_ice_servers(&ice_servers_to_js(ice_servers));
        }
        let pc = RtcPeerConnection::new_with_configuration(&cfg)
            .map_err(|e| format!("RTCPeerConnection::new failed: {e:?}"))?;

        let gathered: Rc<RefCell<Vec<WireLocalCandidate>>> = Rc::new(RefCell::new(Vec::new()));
        let gathered_for_ice = gathered.clone();
        let on_ice = Closure::<dyn FnMut(RtcPeerConnectionIceEvent)>::new(
            move |ev: RtcPeerConnectionIceEvent| {
                // A null candidate is end-of-gathering, not a candidate.
                let Some(c) = ev.candidate() else { return };
                gathered_for_ice.borrow_mut().push(WireLocalCandidate {
                    candidate: c.candidate(),
                    sdp_mid: c.sdp_mid().unwrap_or_default(),
                    sdp_mline_index: c.sdp_m_line_index().unwrap_or(0) as u64,
                    // Absent stays absent. `addIceCandidate` on the far side
                    // reads an empty string as a real ufrag, so an empty one
                    // is normalized to None rather than carried as "".
                    username_fragment: reflect_string(&c, "usernameFragment")
                        .filter(|s| !s.is_empty()),
                });
            },
        );
        pc.set_onicecandidate(Some(on_ice.as_ref().unchecked_ref()));

        let pumps: MessageClosures = Rc::new(RefCell::new(Vec::new()));
        let inbox: Inbox = Rc::new(RefCell::new(Vec::new()));

        let channel: Rc<RefCell<Option<RtcDataChannel>>> = Rc::new(RefCell::new(None));
        let channel_for_dc = channel.clone();
        let inbox_for_dc = inbox.clone();
        let pumps_for_dc = pumps.clone();
        let on_datachannel =
            Closure::<dyn FnMut(RtcDataChannelEvent)>::new(move |ev: RtcDataChannelEvent| {
                let dc = ev.channel();
                dc.set_binary_type(RtcDataChannelType::Arraybuffer);
                // **This is the answerer's exposure point.** `ondatachannel` is
                // the first instant this side knows the channel exists, and the
                // offerer — which created it and is the §7.4.1 initiator — may
                // already be writing HELLO. Catch from here, not from
                // `wait_open`.
                attach_inbox(&dc, &inbox_for_dc, &pumps_for_dc);
                *channel_for_dc.borrow_mut() = Some(dc);
            });
        pc.set_ondatachannel(Some(on_datachannel.as_ref().unchecked_ref()));

        Ok(Rc::new(Self {
            pc,
            gathered,
            channel,
            _on_ice: on_ice,
            _on_datachannel: on_datachannel,
            pumps,
            inbox,
            kept_ports: RefCell::new(Vec::new()),
        }))
    }

    /// `createOffer` + `setLocalDescription`, returning the **finalized** local
    /// description.
    ///
    /// The offerer creates the data channel *before* creating the offer —
    /// without it the SDP carries no `m=application` section and the answerer
    /// never fires `ondatachannel`.
    pub(crate) async fn create_offer(&self) -> Result<String, String> {
        let init = RtcDataChannelInit::new();
        init.set_ordered(true);
        let dc = self
            .pc
            .create_data_channel_with_data_channel_dict(CHANNEL_LABEL, &init);
        dc.set_binary_type(RtcDataChannelType::Arraybuffer);
        // Symmetric with the answerer's `ondatachannel` catch. The offerer is
        // normally the one that writes first (§7.4.1 initiator), so this side is
        // far less exposed — but "less exposed" is a timing argument, and the
        // whole point of the inbox is not to rest on one.
        attach_inbox(&dc, &self.inbox, &self.pumps);
        *self.channel.borrow_mut() = Some(dc);

        let offer = JsFuture::from(self.pc.create_offer())
            .await
            .map_err(|e| format!("createOffer failed: {e:?}"))?;
        let sdp = sdp_of(&offer)?;

        let desc = RtcSessionDescriptionInit::new(RtcSdpType::Offer);
        desc.set_sdp(&sdp);
        JsFuture::from(self.pc.set_local_description(&desc))
            .await
            .map_err(|e| format!("setLocalDescription(offer) failed: {e:?}"))?;

        self.finalized_local_sdp()
    }

    /// Apply a remote offer, then answer it. Returns the **finalized** local
    /// description.
    pub(crate) async fn create_answer(&self, remote_offer_sdp: &str) -> Result<String, String> {
        let remote = RtcSessionDescriptionInit::new(RtcSdpType::Offer);
        remote.set_sdp(remote_offer_sdp);
        JsFuture::from(self.pc.set_remote_description(&remote))
            .await
            .map_err(|e| format!("setRemoteDescription(offer) failed: {e:?}"))?;

        let answer = JsFuture::from(self.pc.create_answer())
            .await
            .map_err(|e| format!("createAnswer failed: {e:?}"))?;
        let sdp = sdp_of(&answer)?;

        let desc = RtcSessionDescriptionInit::new(RtcSdpType::Answer);
        desc.set_sdp(&sdp);
        JsFuture::from(self.pc.set_local_description(&desc))
            .await
            .map_err(|e| format!("setLocalDescription(answer) failed: {e:?}"))?;

        self.finalized_local_sdp()
    }

    pub(crate) async fn accept_answer(&self, remote_answer_sdp: &str) -> Result<(), String> {
        let remote = RtcSessionDescriptionInit::new(RtcSdpType::Answer);
        remote.set_sdp(remote_answer_sdp);
        JsFuture::from(self.pc.set_remote_description(&remote))
            .await
            .map_err(|e| format!("setRemoteDescription(answer) failed: {e:?}"))?;
        Ok(())
    }

    pub(crate) async fn add_remote_candidate(
        &self,
        candidate: &str,
        sdp_mid: &str,
        sdp_mline_index: u64,
        username_fragment: Option<&str>,
    ) -> Result<(), String> {
        let init = RtcIceCandidateInit::new(candidate);
        init.set_sdp_mid(Some(sdp_mid));
        init.set_sdp_m_line_index(Some(sdp_mline_index as u16));
        // `usernameFragment` has no typed setter in this web-sys version, so it
        // is set reflectively. Set ONLY when present: writing `undefined` or ""
        // is not the same as omitting the key, and `addIceCandidate` treats an
        // empty ufrag as a real one.
        if let Some(u) = username_fragment {
            js_sys::Reflect::set(
                &init,
                &JsValue::from_str("usernameFragment"),
                &JsValue::from_str(u),
            )
            .map_err(|e| format!("setting usernameFragment failed: {e:?}"))?;
        }
        let c = RtcIceCandidate::new(&init)
            .map_err(|e| format!("RTCIceCandidate::new failed: {e:?}"))?;
        JsFuture::from(
            self.pc
                .add_ice_candidate_with_opt_rtc_ice_candidate(Some(&c)),
        )
        .await
        .map_err(|e| format!("addIceCandidate failed: {e:?}"))?;
        Ok(())
    }

    pub(crate) fn drain_candidates(&self) -> Vec<WireLocalCandidate> {
        std::mem::take(&mut *self.gathered.borrow_mut())
    }

    /// The ICE/connection verdict, read at failure time and appended to every
    /// `wait_open` error.
    ///
    /// Without it, "data channel closed before it opened" names a symptom whose
    /// causes are disjoint: `ice=failed` means no candidate pair was ever
    /// nominated (a trickle problem — the remote candidates did not land);
    /// `ice=connected`/`completed` with a dead channel means the pair was fine
    /// and DTLS/SCTP is at fault; `ice=checking` means the window simply closed
    /// too early. `entity-browser-rust`'s rung-1 offerer reported the closed
    /// channel with nothing here to say which — and their bare-WebRTC control
    /// passing on the same bridge with candidates in the SDP is only *evidence*
    /// for the first, where this is a direct reading.
    ///
    /// Read rather than observed: a state-change subscription would say *when*
    /// it turned, but the terminal state is what picks the branch, and it costs
    /// two getters instead of two more retained closures.
    fn state_summary(&self) -> String {
        format!(
            "ice={:?}, conn={:?}",
            self.pc.ice_connection_state(),
            self.pc.connection_state()
        )
    }

    /// The SDP this peer will actually present — `localDescription.sdp` *after*
    /// `setLocalDescription`, never the raw `createOffer()` output.
    ///
    /// That distinction is what makes "the fingerprint the receiver binds
    /// equals the fingerprint we negotiate" structural rather than incidental
    /// (arch, §6.5 build-time guidance). In practice `a=fingerprint` is already
    /// present and stable from `createOffer`, which is exactly why reading it
    /// from the wrong place would go unnoticed.
    fn finalized_local_sdp(&self) -> Result<String, String> {
        self.pc
            .local_description()
            .map(|d| d.sdp())
            .ok_or_else(|| "no localDescription after setLocalDescription".to_string())
    }

    /// Wait for the data channel to open, then hand back the port whose far
    /// end the broker pumps.
    ///
    /// Returns `port1` for transfer to the worker; `port2` stays here, wired to
    /// the `RTCDataChannel`. The worker turns `port1` into an ordinary
    /// `Connection` with `connection_from_port` — unchanged code, which is why
    /// the channel handoff needed almost nothing new.
    pub(crate) async fn wait_open(&self, timeout_ms: u64) -> Result<MessagePort, String> {
        let deadline_ticks = timeout_ms.div_ceil(POLL_INTERVAL_MS);
        let mut waited = 0u64;
        loop {
            let ready = {
                let ch = self.channel.borrow();
                match ch.as_ref() {
                    Some(dc) if dc.ready_state() == RtcDataChannelState::Open => true,
                    Some(dc) if dc.ready_state() == RtcDataChannelState::Closed => {
                        return Err(format!(
                            "data channel closed before it opened ({})",
                            self.state_summary()
                        ))
                    }
                    _ => false,
                }
            };
            if ready {
                break;
            }
            if waited >= deadline_ticks {
                return Err(format!(
                    "data channel did not open within {timeout_ms}ms (§6.5 negotiation window; {})",
                    self.state_summary()
                ));
            }
            waited += 1;
            gloo_timers::future::TimeoutFuture::new(POLL_INTERVAL_MS as u32).await;
        }

        let dc = self
            .channel
            .borrow()
            .clone()
            .ok_or_else(|| "data channel vanished".to_string())?;

        let channel = MessageChannel::new().map_err(|e| format!("MessageChannel: {e:?}"))?;
        let for_worker = channel.port1();
        let ours = channel.port2();

        // RTCDataChannel -> port: inbound frames toward the worker.
        let ours_for_dc = ours.clone();
        let dc_to_port = Closure::<dyn FnMut(MessageEvent)>::new(move |ev: MessageEvent| {
            let Some(bytes) = frame_bytes(ev.data()) else {
                return;
            };
            let _ = ours_for_dc.post_message(&bytes);
        });
        dc.set_onmessage(Some(dc_to_port.as_ref().unchecked_ref()));

        // Flush whatever the inbox caught before this pump existed, in arrival
        // order and ahead of every live frame.
        //
        // **Ordering is guaranteed by the event loop, not by luck.** Everything
        // from the `set_onmessage` above to the end of this drain runs in one
        // synchronous block with no `await`, so no `message` event can be
        // dispatched into the middle of it. Buffered frames are therefore posted
        // strictly before any frame the new pump will ever see.
        //
        // Posting into `ours` before the worker has started `port1` is safe and
        // is how this design already works: a `MessagePort` queues until the
        // receiving end calls `start()`, which the worker does in
        // `connection_from_port`.
        for frame in std::mem::take(&mut *self.inbox.borrow_mut()) {
            let arr = Uint8Array::new_with_length(frame.len() as u32);
            arr.copy_from(&frame);
            let _ = ours.post_message(&arr);
        }

        // port -> RTCDataChannel: outbound frames from the worker.
        let dc_for_port = dc.clone();
        let port_to_dc = Closure::<dyn FnMut(MessageEvent)>::new(move |ev: MessageEvent| {
            let data = ev.data();
            let bytes = match data.dyn_into::<Uint8Array>() {
                Ok(a) => a.to_vec(),
                Err(_) => return,
            };
            if dc_for_port.ready_state() == RtcDataChannelState::Open {
                let _ = dc_for_port.send_with_u8_array(&bytes);
            }
        });
        ours.set_onmessage(Some(port_to_dc.as_ref().unchecked_ref()));
        ours.start();

        // Retain both closures AND our end of the channel for the session's
        // life. Dropping `ours` here would close the port and tear down the
        // pump the moment this function returned.
        self.pumps.borrow_mut().push(dc_to_port);
        self.pumps.borrow_mut().push(port_to_dc);
        self.kept_ports.borrow_mut().push(ours);

        Ok(for_worker)
    }

    pub(crate) fn close(&self) {
        self.pc.close();
    }
}

/// Catch inbound frames from the moment the channel is known until `wait_open`
/// swaps in the real pump.
///
/// **Without this, frames in that window are lost outright.** An
/// `RTCDataChannel` dispatches `message` events; it does not queue them, so an
/// event with no listener is dropped rather than deferred — unlike a
/// `MessagePort`, which queues until `start()`. The channel is known at
/// `ondatachannel` (answerer) or at `create_data_channel` (offerer), but the
/// pump is only wired inside `wait_open`, which `negotiate` calls on its *next*
/// tick — up to a full poll interval later. The far side, seeing `open`, writes
/// immediately into that gap.
///
/// Observed as exactly that: one rung-1 run where both peers logged the channel
/// open, the initiator logged `sent hello`, and the responder logged
/// `received frame = 0` and then failed its reentry wait. A second run on the
/// same commit worked — the tell that this is a race, not a defect of shape.
///
/// No cap on the buffer, deliberately: it defers frames that would otherwise sit
/// in the `MessagePort` queue a few milliseconds later, so it adds no exposure
/// the port queue does not already have, and a cap that silently dropped frames
/// would reintroduce the bug this exists to fix.
fn attach_inbox(dc: &RtcDataChannel, inbox: &Inbox, pumps: &MessageClosures) {
    let inbox_for_msg = inbox.clone();
    let buffering = Closure::<dyn FnMut(MessageEvent)>::new(move |ev: MessageEvent| {
        let Some(bytes) = frame_bytes(ev.data()) else {
            return;
        };
        inbox_for_msg.borrow_mut().push(bytes.to_vec());
    });
    dc.set_onmessage(Some(buffering.as_ref().unchecked_ref()));
    // Retained even after `wait_open` overwrites the handler slot: dropping a
    // closure whose slot JS may still reference is the footgun this file's
    // `pumps` vector exists to avoid.
    pumps.borrow_mut().push(buffering);
}

/// The bytes of one data-channel frame, or `None` for anything that is not one.
///
/// Shared by the buffering handler and the live pump **so the two cannot drift**.
/// If one accepted a frame shape the other rejected, a message would survive or
/// vanish depending purely on when it arrived relative to `wait_open` — the same
/// class of timing-dependent loss this whole path just fixed.
///
/// Text frames are not part of this transport; a peer sending one is
/// misconfigured, and forwarding it would corrupt the byte stream the framing
/// layer expects.
fn frame_bytes(data: JsValue) -> Option<Uint8Array> {
    if let Ok(buf) = data.clone().dyn_into::<js_sys::ArrayBuffer>() {
        return Some(Uint8Array::new(&buf));
    }
    data.dyn_into::<Uint8Array>().ok()
}

/// How often `wait_open` re-checks `readyState`.
///
/// Polled rather than event-driven because `onopen` fires exactly once and can
/// fire *before* this future is awaited — a listener installed afterwards would
/// wait forever for an event already delivered. Polling has no such race, and
/// at negotiation rate the cost is irrelevant.
const POLL_INTERVAL_MS: u64 = 25;

/// Pull `sdp` off an `RTCSessionDescriptionInit`-shaped JS value.
fn sdp_of(v: &JsValue) -> Result<String, String> {
    reflect_string(v, "sdp").ok_or_else(|| "session description carried no sdp".to_string())
}

/// Read an optional string property. `None` covers absent, `null`, `undefined`
/// and non-string alike — all of which mean "the browser did not give us one",
/// which is exactly the distinction `username_fragment` turns on.
/// Build the `RTCIceServer[]` JS array `RTCConfiguration.iceServers` wants.
///
/// Constructed by reflection rather than through `web_sys::RtcIceServer`
/// setters for one reason worth stating: `username` / `credential` are set
/// **only when present**. Writing `undefined` into them is not the same as
/// leaving them out for a TURN server, and "optional fields SHOULD be absent,
/// not null" is the same discipline the entity wire carries — it does not stop
/// applying because the consumer is a browser API.
fn ice_servers_to_js(servers: &[WireIceServer]) -> Array {
    let out = Array::new();
    for s in servers {
        let obj = Object::new();
        let urls = Array::new();
        for u in &s.urls {
            urls.push(&JsValue::from_str(u));
        }
        let _ = js_sys::Reflect::set(&obj, &JsValue::from_str("urls"), &urls);
        if let Some(u) = &s.username {
            let _ =
                js_sys::Reflect::set(&obj, &JsValue::from_str("username"), &JsValue::from_str(u));
        }
        if let Some(c) = &s.credential {
            let _ = js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("credential"),
                &JsValue::from_str(c),
            );
        }
        out.push(&obj);
    }
    out
}

fn reflect_string(v: &JsValue, key: &str) -> Option<String> {
    js_sys::Reflect::get(v, &JsValue::from_str(key))
        .ok()
        .and_then(|s| s.as_string())
}

/// Encode and post one control message, optionally transferring a port.
pub(crate) fn post_reply(
    port: &MessagePort,
    msg: &ControlMessage,
    transfer: Option<&MessagePort>,
) -> Result<(), JsValue> {
    let mut buf = Vec::new();
    ciborium::into_writer(msg, &mut buf)
        .map_err(|e| JsValue::from_str(&format!("CBOR encode failed: {e}")))?;
    let arr = Uint8Array::new_with_length(buf.len() as u32);
    arr.copy_from(&buf);
    match transfer {
        Some(p) => {
            let list = Array::new();
            list.push(p);
            port.post_message_with_transferable(&arr, &list)
        }
        None => port.post_message(&arr),
    }
}

/// Apply the §6.5 byte invariant to SDP that crossed from the worker.
///
/// The digest was computed by the side that signed or verified; a mismatch
/// means the crossing altered the bytes, and feeding altered SDP to
/// `setRemoteDescription` is exactly what would verify one description and bind
/// the DTLS fingerprint of another.
pub(crate) fn sdp_from_worker(sdp: &[u8], digest: &[u8]) -> Result<String, String> {
    verified_sdp_from_bytes(sdp, digest)
}
