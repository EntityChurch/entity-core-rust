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
type MessageClosures = RefCell<Vec<Closure<dyn FnMut(MessageEvent)>>>;

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

        let channel: Rc<RefCell<Option<RtcDataChannel>>> = Rc::new(RefCell::new(None));
        let channel_for_dc = channel.clone();
        let on_datachannel =
            Closure::<dyn FnMut(RtcDataChannelEvent)>::new(move |ev: RtcDataChannelEvent| {
                let dc = ev.channel();
                dc.set_binary_type(RtcDataChannelType::Arraybuffer);
                *channel_for_dc.borrow_mut() = Some(dc);
            });
        pc.set_ondatachannel(Some(on_datachannel.as_ref().unchecked_ref()));

        Ok(Rc::new(Self {
            pc,
            gathered,
            channel,
            _on_ice: on_ice,
            _on_datachannel: on_datachannel,
            pumps: RefCell::new(Vec::new()),
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
                        return Err("data channel closed before it opened".into())
                    }
                    _ => false,
                }
            };
            if ready {
                break;
            }
            if waited >= deadline_ticks {
                return Err(format!(
                    "data channel did not open within {timeout_ms}ms (§6.5 negotiation window)"
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
            let data = ev.data();
            let bytes = if let Ok(buf) = data.clone().dyn_into::<js_sys::ArrayBuffer>() {
                Uint8Array::new(&buf)
            } else if let Ok(arr) = data.dyn_into::<Uint8Array>() {
                arr
            } else {
                // Text frames are not part of this transport; a peer sending
                // one is misconfigured, and forwarding it would corrupt the
                // byte stream the framing layer expects.
                return;
            };
            let _ = ours_for_dc.post_message(&bytes);
        });
        dc.set_onmessage(Some(dc_to_port.as_ref().unchecked_ref()));

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
