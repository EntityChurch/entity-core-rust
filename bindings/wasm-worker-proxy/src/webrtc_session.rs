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

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;

use entity_peer::transport::{
    verified_sdp_from_bytes, ControlMessage, WireIceServer, WireLocalCandidate,
};
use js_sys::{Array, Object, Uint8Array};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    Event, MessageChannel, MessageEvent, MessagePort, RtcConfiguration, RtcDataChannel,
    RtcDataChannelEvent, RtcDataChannelInit, RtcDataChannelState, RtcDataChannelType,
    RtcIceCandidate, RtcIceCandidateInit, RtcPeerConnection, RtcPeerConnectionIceEvent,
    RtcPeerConnectionState, RtcSdpType, RtcSessionDescriptionInit,
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

/// Plain `Event` listeners on the data channel, retained for the session's
/// life for the same reason as [`MessageClosures`].
type ChannelHooks = RefCell<Vec<Closure<dyn FnMut(Event)>>>;

/// The largest single `RTCDataChannel.send()` [`PortPump`] will ever make.
///
/// A cap *below* whatever the connection negotiated, on purpose. The layer
/// above this transport is a byte stream — `PortReader` feeds `read_frame`'s
/// 4-byte-length-prefixed framing (`entity-wire`) and already carries a
/// `leftover` for a delivery that does not land on a frame boundary — so the
/// size of an individual `send()` carries **no semantics at all**. It is a pure
/// performance knob, and the cheapest thing to buy with it is that every engine
/// pair executes the same code path: Firefox↔Firefox negotiates ~1 GiB and
/// would otherwise take a splitting path no other pair takes, which is exactly
/// how a size defect stays invisible to a Firefox-only harness.
const PIECE_CEILING: usize = 64 * 1024;

/// Used when the engine will not say what it negotiated. Deliberately small:
/// 16 KiB is carried by every SCTP implementation, browser or not.
const PIECE_FALLBACK: usize = 16 * 1024;

/// Stop feeding `send()` once this much is sitting unsent, and resume at
/// [`BUFFER_LOW_WATER`].
///
/// Not a nicety. Chromium **closes the data channel** when its send buffer
/// passes 16 MiB, so an unpaced writer converts a large transfer into a
/// mid-stream teardown; 1 MiB leaves two orders of magnitude of headroom while
/// still keeping enough in flight to saturate a LAN.
const BUFFER_HIGH_WATER: u32 = 1024 * 1024;
const BUFFER_LOW_WATER: u32 = 256 * 1024;

/// The outbound half of the pump: `MessagePort` → `RTCDataChannel`.
///
/// # Why this is not one `send()` per port message
///
/// A data channel has a negotiated per-message ceiling
/// (`RTCPeerConnection.sctp.maxMessageSize`) and **the engines disagree about
/// it by four orders of magnitude**: Firefox advertises ~1 GiB and fragments
/// internally, Chromium advertises 262 144 bytes and does not, and the pair
/// takes the smaller of the two. `entity-browser-rust`'s file pull hands this
/// pump a `GET_BATCH_SIZE` response of ~4 MiB — fine to Firefox, over the
/// ceiling to Chromium — and the previous implementation neither checked the
/// size nor read the error, so the oversized `send()` threw into a discarded
/// `Result` and the byte stream simply stopped. A progress line, then silence.
///
/// Splitting needs no header and no reassembler on the far side, because the
/// far side is not reassembling messages: see [`PIECE_CEILING`].
///
/// # Why a failed send closes the channel
///
/// A dropped piece is not a lost message, it is a **hole in a byte stream** —
/// the peer's `read_exact` either blocks on a length prefix that never
/// completes or resynchronizes onto garbage. Neither is recoverable, and the
/// first is precisely the silent hang this type exists to end. Closing turns it
/// into a transport error the layers above already know how to report.
struct PortPump {
    dc: RtcDataChannel,
    /// Largest `send()` this connection will take, already clamped.
    piece: usize,
    /// Pieces awaiting a send, in strict order. Ordered delivery is the data
    /// channel's job (`init.set_ordered(true)`); keeping the *queue* ordered is
    /// ours, so nothing may ever send directly past a non-empty queue.
    queue: RefCell<VecDeque<Vec<u8>>>,
    /// Latched on the first unrecoverable send. Everything after it is dropped
    /// rather than sent into a stream that already has a hole in it.
    failed: Cell<bool>,
}

impl PortPump {
    fn new(dc: RtcDataChannel, piece: usize) -> Self {
        Self {
            dc,
            piece,
            queue: RefCell::new(VecDeque::new()),
            failed: Cell::new(false),
        }
    }

    /// Split one port message into sendable pieces and push the pump along.
    fn enqueue(&self, bytes: Vec<u8>) {
        if self.failed.get() {
            return;
        }
        {
            let mut q = self.queue.borrow_mut();
            if bytes.len() <= self.piece {
                q.push_back(bytes);
            } else {
                for piece in bytes.chunks(self.piece) {
                    q.push_back(piece.to_vec());
                }
            }
        }
        self.drain();
    }

    /// Send until the queue empties or the channel's buffer fills. Re-entered
    /// from `bufferedamountlow` when it fills.
    fn drain(&self) {
        while !self.failed.get() {
            let state = self.dc.ready_state();
            if state != RtcDataChannelState::Open {
                // Not "wait and retry": `wait_open` only wires this pump after
                // the channel is open, so anything other than Open here is a
                // channel that has since died with bytes still owed to it.
                self.fail(&format!("channel is {state:?}, not open"));
                return;
            }
            if self.dc.buffered_amount() >= BUFFER_HIGH_WATER {
                // Resumed by the `bufferedamountlow` listener in `wait_open`.
                return;
            }
            let next = self.queue.borrow_mut().pop_front();
            let Some(piece) = next else { return };
            let len = piece.len();
            if let Err(e) = self.dc.send_with_u8_array(&piece) {
                self.fail(&format!(
                    "send({len} bytes) threw {e:?} (piece limit {}, buffered {})",
                    self.piece,
                    self.dc.buffered_amount()
                ));
                return;
            }
        }
    }

    fn fail(&self, why: &str) {
        if self.failed.replace(true) {
            return;
        }
        let owed: usize = self.queue.borrow().iter().map(Vec::len).sum();
        web_sys::console::error_1(&JsValue::from_str(&format!(
            "webrtc: outbound pump failed — {why}; {owed} byte(s) undelivered, closing the channel"
        )));
        self.queue.borrow_mut().clear();
        self.dc.close();
    }
}

/// Forward one inbound frame into the port, or say why the stream just
/// developed a hole.
///
/// The inbound twin of [`PortPump::fail`], and it exists for the same reason:
/// what crosses this port is a **byte stream**, so a dropped delivery is not a
/// lost message but a gap the worker's `read_exact` waits on forever. Posting
/// into a live `MessagePort` does not realistically throw — which is precisely
/// why discarding the `Result` here would produce a hang nobody could ever
/// attribute to it. Closing the channel converts that into a transport error
/// the layers above already report.
fn post_inbound(port: &MessagePort, frame: &JsValue, dc: &RtcDataChannel) {
    if let Err(e) = port.post_message(frame) {
        web_sys::console::error_1(&JsValue::from_str(&format!(
            "webrtc: inbound post_message failed — {e:?}; closing the channel"
        )));
        dc.close();
    }
}

/// Is this `RTCPeerConnection` state terminal for the transport riding on it?
///
/// **`Disconnected` is deliberately NOT terminal**, and that is the whole
/// subtlety. The WebRTC spec makes `disconnected` *transient*: ICE may still
/// recover the same connection, and a peer behind a flaky link passes through it
/// routinely. Tearing the byte stream down there would destroy connections that
/// were about to come back — the same mistake as evicting on wake instead of
/// probing. A `disconnected` that does not recover escalates to `failed` on its
/// own via ICE consent freshness (RFC 7675), so nothing is lost by waiting for
/// the state that actually means it.
///
/// `New`/`Connecting` are pre-open and never reach here (the port pair is only
/// wired after the channel opens); they are listed rather than defaulted so a
/// future state has to be classified deliberately.
fn terminal_for_transport(state: RtcPeerConnectionState) -> bool {
    match state {
        RtcPeerConnectionState::Failed | RtcPeerConnectionState::Closed => true,
        RtcPeerConnectionState::New
        | RtcPeerConnectionState::Connecting
        | RtcPeerConnectionState::Connected
        | RtcPeerConnectionState::Disconnected => false,
        // MUST-ignore-unknown: a state this web-sys does not model is not
        // grounds for killing a working connection.
        _ => false,
    }
}

/// Tell the worker's `Connection` that this transport is over.
///
/// **A dead data channel is invisible until somebody writes to it**, and that is
/// the hole this closes. The bytes cross a `MessagePort`, which has no close
/// event and no error — so when the channel underneath dies, the worker's
/// `read_exact` simply waits, and the peer keeps the pooled binding and keeps
/// dispatching over it. Until now the two places that observe the death
/// (`PortPump::fail`, and the `close` listener in `wait_open`) wrote a console
/// line and closed the `RTCDataChannel`, neither of which the worker can see.
///
/// A zero-length frame is the close sentinel `PortReader` already surfaces as
/// EOF (`core/peer`'s `transport.rs`: *"MessagePort has no explicit close, so
/// this is how we signal half-close"*). Reaching EOF ends the reader, which
/// fails the in-flight request as a transport error and — crucially — is what
/// the §A1 seam at the dispatch caller demotes and evicts on. So this reports
/// *evidence*; it does not write liveness, which stays the kernel's to do.
///
/// **Idempotent by construction:** once the reader has EOF'd, the connection is
/// torn down and a second sentinel lands nowhere. That matters because both the
/// channel `close` and a `failed` peer connection legitimately fire for one
/// death, and neither can know whether the other already ran.
fn signal_transport_eof(port: &MessagePort, why: &str) {
    web_sys::console::log_1(&JsValue::from_str(&format!(
        "webrtc: transport is over ({why}) — signalling EOF to the worker so the \
         connection fails now rather than on the next 30s request deadline"
    )));
    if let Err(e) = port.post_message(&Uint8Array::new_with_length(0)) {
        // Non-fatal and worth saying: the worker then falls back to the
        // request deadline, which is the behaviour we had before this existed.
        web_sys::console::error_1(&JsValue::from_str(&format!(
            "webrtc: could not post the EOF sentinel — {e:?}"
        )));
    }
}

/// `RTCPeerConnection.sctp.maxMessageSize` — the largest message this
/// connection agreed to carry, i.e. the minimum of what we can send and what
/// the remote advertised in its SDP `a=max-message-size`.
///
/// Read reflectively rather than through `RtcSctpTransport`: one getter does
/// not earn a `web-sys` feature, and this file already reaches for
/// `usernameFragment` the same way. `None` covers absent, `null` and
/// `undefined` alike — all of which mean the engine will not tell us, which is
/// a fallback, not a failure.
fn negotiated_max_message_size(pc: &RtcPeerConnection) -> Option<f64> {
    let sctp = js_sys::Reflect::get(pc, &JsValue::from_str("sctp")).ok()?;
    if sctp.is_null() || sctp.is_undefined() {
        return None;
    }
    js_sys::Reflect::get(&sctp, &JsValue::from_str("maxMessageSize"))
        .ok()?
        .as_f64()
}

/// The negotiated ceiling as reported, and the piece size derived from it.
///
/// The reported value is returned alongside so the caller can log it: it is the
/// number every decision here is derived from, it differs by four orders of
/// magnitude between engines, and until now it was read nowhere in this
/// codebase. `Infinity` is a legal value (the spec's reading of a remote that
/// advertised no limit) and is exactly why this is not used raw.
fn outbound_piece_size(pc: &RtcPeerConnection) -> (Option<f64>, usize) {
    let reported = negotiated_max_message_size(pc);
    let negotiated = match reported {
        Some(v) if v.is_finite() && v >= 1.0 => v as usize,
        _ => PIECE_FALLBACK,
    };
    (reported, negotiated.clamp(1, PIECE_CEILING))
}

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
    /// Event listeners installed by `wait_open` — the data channel's
    /// `bufferedamountlow`, `error` and `close`, plus the peer connection's
    /// `connectionstatechange`.
    ///
    /// Parked on the session rather than on the [`PortPump`] they drive: each
    /// holds an `Rc<PortPump>`, so a closure stored inside the pump would be a
    /// reference cycle that survives the session.
    channel_hooks: ChannelHooks,
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
            channel_hooks: RefCell::new(Vec::new()),
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
        let dc_for_inbound = dc.clone();
        let dc_to_port = Closure::<dyn FnMut(MessageEvent)>::new(move |ev: MessageEvent| {
            let Some(bytes) = frame_bytes(ev.data()) else {
                return;
            };
            post_inbound(&ours_for_dc, &bytes, &dc_for_inbound);
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
            post_inbound(&ours, &arr, &dc);
        }

        // port -> RTCDataChannel: outbound frames from the worker, split to the
        // size this connection actually negotiated. See `PortPump`.
        let (reported_max, piece) = outbound_piece_size(&self.pc);
        web_sys::console::log_1(&JsValue::from_str(&format!(
            "webrtc: data channel open — sctp.maxMessageSize={}, outbound piece={piece} bytes",
            match reported_max {
                Some(v) => format!("{v}"),
                None => "unreported".to_string(),
            }
        )));

        let pump = Rc::new(PortPump::new(dc.clone(), piece));
        let pump_for_port = pump.clone();
        let port_to_dc = Closure::<dyn FnMut(MessageEvent)>::new(move |ev: MessageEvent| {
            let bytes = match ev.data().dyn_into::<Uint8Array>() {
                Ok(a) => a.to_vec(),
                Err(_) => return,
            };
            pump_for_port.enqueue(bytes);
        });
        ours.set_onmessage(Some(port_to_dc.as_ref().unchecked_ref()));
        ours.start();

        // Backpressure. Without a resume hook the pump parks at
        // `BUFFER_HIGH_WATER` and never restarts, which would trade the old
        // silent hang for a new one.
        dc.set_buffered_amount_low_threshold(BUFFER_LOW_WATER);
        let pump_for_low = pump.clone();
        let on_low = Closure::<dyn FnMut(Event)>::new(move |_: Event| pump_for_low.drain());
        dc.add_event_listener_with_callback("bufferedamountlow", on_low.as_ref().unchecked_ref())
            .map_err(|e| format!("bufferedamountlow listener: {e:?}"))?;

        // `error` stays diagnostics-only — it reports a fault on a channel that
        // may still be open, and is not by itself the end of the transport.
        // `close` is different and no longer merely logged: see below.
        let dc_for_err = dc.clone();
        let on_error = Closure::<dyn FnMut(Event)>::new(move |ev: Event| {
            web_sys::console::error_1(&JsValue::from_str(&format!(
                "webrtc: data channel error — {:?} (buffered {})",
                js_sys::Reflect::get(&ev, &JsValue::from_str("error")).unwrap_or(ev.clone().into()),
                dc_for_err.buffered_amount()
            )));
        });
        dc.add_event_listener_with_callback("error", on_error.as_ref().unchecked_ref())
            .map_err(|e| format!("error listener: {e:?}"))?;

        // A closed data channel never reopens, so this IS the end of the byte
        // stream — and every existing failure path already funnels here, because
        // `PortPump::fail` and `post_inbound` both end in `dc.close()`. Putting
        // the EOF on the close event rather than at each of those call sites is
        // the difference between a rule and a step someone has to remember: a
        // teardown added tomorrow inherits it without knowing it exists.
        let dc_for_close = dc.clone();
        let ours_for_close = ours.clone();
        let on_close = Closure::<dyn FnMut(Event)>::new(move |_: Event| {
            let buffered = dc_for_close.buffered_amount();
            web_sys::console::log_1(&JsValue::from_str(&format!(
                "webrtc: data channel closed (buffered {buffered} still unsent)"
            )));
            signal_transport_eof(&ours_for_close, "data channel closed");
        });
        dc.add_event_listener_with_callback("close", on_close.as_ref().unchecked_ref())
            .map_err(|e| format!("close listener: {e:?}"))?;

        // The idle death this file previously could not see at all. A NAT
        // mapping that expires, or a network that goes away, kills the
        // connection without anybody closing the channel and without any send
        // being attempted — so the data channel can sit in `open` over a
        // transport that is gone. ICE consent freshness (RFC 7675) is what
        // notices, and it surfaces here as `failed`.
        //
        // Both this and the `close` handler fire for a single death in the
        // ordinary case; `signal_transport_eof` is idempotent precisely so
        // neither has to know about the other.
        let pc_for_state = self.pc.clone();
        let ours_for_state = ours.clone();
        let on_conn_state = Closure::<dyn FnMut(Event)>::new(move |_: Event| {
            let state = pc_for_state.connection_state();
            if terminal_for_transport(state) {
                signal_transport_eof(&ours_for_state, &format!("peer connection is {state:?}"));
            }
        });
        self.pc
            .set_onconnectionstatechange(Some(on_conn_state.as_ref().unchecked_ref()));

        // Retain the closures AND our end of the channel for the session's
        // life. Dropping `ours` here would close the port and tear down the
        // pump the moment this function returned.
        self.pumps.borrow_mut().push(dc_to_port);
        self.pumps.borrow_mut().push(port_to_dc);
        self.kept_ports.borrow_mut().push(ours);
        let mut hooks = self.channel_hooks.borrow_mut();
        hooks.push(on_low);
        hooks.push(on_error);
        hooks.push(on_close);
        hooks.push(on_conn_state);
        drop(hooks);

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
