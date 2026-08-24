//! The Direct-arm half of the §6.5 negotiation: a [`WebRtcIo`] that drives a
//! main-thread [`WebRtcSession`] **in-thread**, with no broker and no
//! `ControlMessage` crossing.
//!
//! # Why this exists alongside `core/peer/worker_webrtc.rs`
//!
//! `RTCPeerConnection` is `[Exposed=Window]` — main-thread only on every engine.
//! The **Worker** arm therefore reaches it through the main-thread broker over a
//! `ControlMessage` proxy ([`crate::broker`] + [`crate::webrtc_session`], driven
//! by `entity_peer::worker_webrtc::BrowserWebRtcEstablisher`). A peer that
//! already lives on the main thread — `entity-browser-rust`'s shipped
//! **Direct/IDB** arm — has no thread gap to bridge: it owns the
//! [`WebRtcSession`] directly.
//!
//! So this is the *same* §10.3 seam and the *same* `entity_signaling::webrtc`
//! choreography as `BrowserWebRtcEstablisher`, **minus the proxy**. It is
//! strictly simpler than [`entity_peer::worker_webrtc::WorkerWebRtcIo`]: there is
//! no cross-thread crossing, so there is nothing to `sdp_digest` /
//! `verified_sdp_from_bytes` (that invariant protects bytes on the wire between
//! worker and main thread; here the bytes never leave the thread). Every
//! [`WebRtcIo`] method is a direct call on [`WebRtcSession`].
//!
//! # The one lifetime rule that is not obvious
//!
//! A [`WebRtcSession`] owns the `RTCPeerConnection`, the pump closures, and the
//! broker's end of the channel (`kept_ports`); its own doc: dropping it "tears
//! down the pump the instant `wait_open` returns." The Worker arm survives this
//! because the long-lived **broker** retains every session in its `sessions`
//! map past negotiation (removed only on an explicit `WebRtcClose`, which never
//! fires on the handed-off success path).
//!
//! **There is no broker on this arm.** So this establisher owns an equivalent
//! registry ([`Sessions`]): a negotiation's session is inserted at open and, on
//! success, **kept there for the life of the connection**. Drop it when
//! `establish_live` returns and the just-opened data channel dies microseconds
//! later — a transport bug in disguise, exactly the failure the Worker arm's own
//! `Drop` comment warns about. On failure the session is removed **and closed**
//! (this crate's `WebRtcSession` has no `Drop` that closes the `pc`).

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use entity_entity::EntityUri;
use entity_peer::carrier::PeerCarrier;
use entity_peer::live_establish::{
    EstablishCtx, HandshakeRole, LiveEstablish, LiveEstablishError, LivePath,
};
use entity_peer::transport::{connection_from_port_typed, WireIceServer};
use entity_signaling::key::pair_key;
use entity_signaling::webrtc::{
    negotiate, IceCandidate, LocalCandidate, SessionId, VerificationPolicy, WebRtcError, WebRtcIo,
    WebRtcParty,
};
use web_sys::MessagePort;

use crate::webrtc_session::{Sessions, WebRtcSession};

/// The substrate this establisher reports at the §10.3 seam — the same string
/// the Worker arm reports, so an operator correlating a seam refusal against a
/// connection kind reads one vocabulary, not two.
const SUBSTRATE_WEBRTC: &str = "webrtc";

/// Carries a `!Send` browser handle through the `Send + Sync` [`LiveEstablish`]
/// supertrait. Identical reasoning to `worker_webrtc.rs`'s `SendWrapper` and
/// `transport.rs`'s `Connection`: `LiveEstablish` relaxes only its *future* with
/// `?Send` on wasm32, but the supertrait bound is unconditional, so an
/// establisher that holds an `Rc` must assert it manually. wasm32 is
/// single-threaded, so the bound is vacuous.
struct SendWrapper<T>(T);
// SAFETY: wasm32 is single-threaded; the guard this removes could never fire.
unsafe impl<T> Send for SendWrapper<T> {}
// SAFETY: as above.
unsafe impl<T> Sync for SendWrapper<T> {}

/// A [`WebRtcIo`] whose `RTCPeerConnection` lives on this very thread. Holds an
/// `Rc` clone of the session; the authoritative retention is the establisher's
/// [`Sessions`] map (see the module lifetime rule), so this type needs no `Drop`
/// — unlike [`entity_peer::worker_webrtc::WorkerWebRtcIo`], whose `Drop` had to
/// tell the broker to close the `pc`.
struct MainThreadWebRtcIo {
    session: Rc<WebRtcSession>,
    /// Monotonic base for [`WebRtcIo::now_ms`]. `web_time::Instant`, never
    /// `Date.now()`, per the trait contract that the value never hits the wire.
    started: web_time::Instant,
    /// Every local candidate this negotiation gathered, as its raw SDP line,
    /// accumulated for [`IceObserver`].
    ///
    /// A **tee**, and it has to be one: `drain_local_candidates` is destructive
    /// by design (trickle hands each batch to the choreography and forgets it),
    /// so by the time a negotiation ends the session holds nothing and there is
    /// nowhere left to ask what was gathered.
    seen: Rc<RefCell<Vec<String>>>,
}

/// Told what one negotiation's ICE agent gathered, once, when it finishes.
///
/// # Why this exists
///
/// The gathered candidate types **are** the topology: host-only means we can
/// only reach a LAN; host+srflx with no nominated pair means this network needs
/// a relay. Without them, every reachability failure — no reflector configured,
/// reflector down, both sides restrictive, UDP blocked — reaches a user as the
/// one sentence *"that peer is not connected"*, indistinguishable from the peer
/// having closed their laptop. A consumer that cannot tell *"this network needs
/// a relay"* from *"my friend is offline"* can never point anyone at the one
/// thing that would fix it.
///
/// # Contract
///
/// - Called **exactly once per negotiation**, on success and failure alike. A
///   consumer that classifies only failures still needs the success call, to
///   clear advice it was already showing.
/// - `local_candidates` are **our own** agent's raw SDP lines. They say nothing
///   about the far side; a consumer inferring the pair from them alone will be
///   confidently wrong.
/// - Observation only. Nothing here feeds the §10.3 seam result, and this is
///   called on the negotiation path — an implementation that panics or blocks is
///   a consumer bug.
pub trait IceObserver: Send + Sync {
    fn negotiation_finished(&self, report: NegotiationReport<'_>);
}

/// One finished negotiation, as an observer sees it.
///
/// A struct rather than a parameter list because it **grows**: the first version
/// carried the local candidates and nothing else, and a consumer classifying on
/// those alone is structurally unable to tell *"the network could not carry
/// it"* from *"the far side was never there"* — two failures that are identical
/// from here and have nothing in common as advice. Measured in a real browser:
/// a chat opened against an offline peer was told *"no reflector is set up"*,
/// which is both false and unactionable, because the only fact the observer had
/// was `[Host]`.
#[derive(Debug, Clone, Copy)]
pub struct NegotiationReport<'a> {
    pub peer_id: &'a str,
    /// **Our own** agent's raw SDP candidate lines.
    pub local_candidates: &'a [String],
    pub established: bool,
    /// Did the SDP exchange complete — offerer accepted an answer, or answerer
    /// posted one? `true` means somebody was there and ICE is what failed;
    /// `false` means the exchange never closed, so **nothing about the network
    /// between the two peers was ever exercised** and no topology claim about
    /// it can be honest.
    ///
    /// `None` is *not measurable*, never `false`: a carrier error or a policy
    /// refusal fails before the negotiation loop can know either way, and a
    /// consumer reading absence as "they did not answer" would blame a peer for
    /// our own refusal.
    pub sdp_exchange_complete: Option<bool>,
    /// Counterpart ICE candidates actually fed to the agent, when the failure
    /// could say.
    ///
    /// **Deliberately not the counterpart's *message* count.** That number
    /// (`WebRtcError::Timeout::counterpart_msgs`) is skip-own-filtered against
    /// *this* negotiation's own posts, so a peer retrying at the same pair key
    /// counts its **previous** negotiation's deposits — still in the bucket for
    /// their TTL — as the counterpart's. Measured: 8 "counterpart" messages
    /// against a peer that was not running at all.
    pub remote_candidates_fed: Option<usize>,
}

#[async_trait::async_trait(?Send)]
impl WebRtcIo for MainThreadWebRtcIo {
    /// The port whose far end the session pumps against the `RTCDataChannel`.
    /// `connection_from_port_typed` turns it into an ordinary `Connection` —
    /// byte-identical to the Worker arm, which also lands a [`MessagePort`] here.
    type Channel = MessagePort;

    async fn create_offer(&self) -> Result<String, String> {
        self.session.create_offer().await
    }

    async fn create_answer(&self, remote_offer_sdp: &str) -> Result<String, String> {
        self.session.create_answer(remote_offer_sdp).await
    }

    async fn accept_answer(&self, remote_answer_sdp: &str) -> Result<(), String> {
        self.session.accept_answer(remote_answer_sdp).await
    }

    async fn drain_local_candidates(&self) -> Vec<LocalCandidate> {
        // `WebRtcSession` gathers into `transport::WireLocalCandidate`; the
        // choreography speaks `entity_signaling::LocalCandidate`. Same fields,
        // one map — no digest, because nothing crosses a thread.
        let drained = self.session.drain_candidates();
        // Tee for the observer BEFORE the mapping consumes them — this is the
        // only point where a gathered candidate is visible, and the drain is
        // destructive.
        self.seen
            .borrow_mut()
            .extend(drained.iter().map(|c| c.candidate.clone()));
        drained
            .into_iter()
            .map(|c| LocalCandidate {
                candidate: c.candidate,
                sdp_mid: c.sdp_mid,
                sdp_mline_index: c.sdp_mline_index,
                username_fragment: c.username_fragment,
            })
            .collect()
    }

    async fn add_remote_candidate(&self, candidate: &IceCandidate) -> Result<(), String> {
        // Absent stays absent: `addIceCandidate` reads an empty ufrag as a real
        // one, so `as_deref()` on the `Option` preserves the None.
        self.session
            .add_remote_candidate(
                &candidate.candidate,
                &candidate.sdp_mid,
                candidate.sdp_mline_index,
                candidate.username_fragment.as_deref(),
            )
            .await
    }

    async fn wait_open(&self, timeout_ms: u64) -> Result<Self::Channel, String> {
        self.session.wait_open(timeout_ms).await
    }

    async fn sleep_ms(&self, ms: u64) {
        gloo_timers::future::TimeoutFuture::new(ms as u32).await;
    }

    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }
}

/// The §6.5 negotiation behind the §10.3 `establish_live` seam, for a peer
/// hosted on the **main thread** (the Direct/IDB arm).
///
/// The WebRTC counterpart of
/// [`entity_peer::worker_webrtc::BrowserWebRtcEstablisher`]: same slot, same
/// obligations, same choreography — this one just owns its `RTCPeerConnection`s
/// directly instead of reaching them through the broker.
pub struct MainThreadWebRtcEstablisher {
    carrier: PeerCarrier,
    self_peer_id: String,
    poll_interval_ms: u64,
    /// Ceiling for one negotiation. The effective budget is the smaller of this
    /// and what [`EstablishCtx`] has left — §10.3's deadline is the caller's and
    /// a policy MUST NOT run past it.
    max_deadline_ms: u64,
    trust: VerificationPolicy,
    /// Handed to `WebRtcSession::new` on every open. Empty is a legal, deliberate
    /// deployment statement — host candidates only — not a missing value.
    ice_servers: Vec<WireIceServer>,
    /// Session-retention registry — the Direct-arm equivalent of the broker's
    /// `sessions` map. See the module lifetime rule: the connection a successful
    /// negotiation returns depends on its session's pumps and `kept_ports`
    /// staying alive, and only this map keeps them so.
    sessions: SendWrapper<Sessions>,
    /// Local negotiation-id source. The Worker arm draws these from the control
    /// port; on this arm they are only map keys, so a plain counter suffices.
    next_negotiation_id: AtomicU64,
    /// Optional reachability observer — see [`IceObserver`] and
    /// [`Self::with_ice_observer`]. `None` costs one branch per negotiation and
    /// keeps the tee empty.
    ice_observer: Option<Arc<dyn IceObserver>>,
}

impl MainThreadWebRtcEstablisher {
    /// Wire the §6.5 negotiation behind the seam for a main-thread peer.
    ///
    /// `trust` and `ice_servers` are required and have no defaults, for the same
    /// reasons `BrowserWebRtcEstablisher::new` states: naming the verification
    /// posture at the call site keeps "we shipped the browser leg with no
    /// identity binding" from being something a reader must infer, and an empty
    /// `ice_servers` is the LAN-only deployment saying so rather than a value to
    /// be defaulted with a STUN server nobody named.
    pub fn new(
        carrier: PeerCarrier,
        self_peer_id: impl Into<String>,
        poll_interval_ms: u64,
        max_deadline_ms: u64,
        trust: VerificationPolicy,
        ice_servers: Vec<WireIceServer>,
    ) -> Self {
        Self {
            carrier,
            self_peer_id: self_peer_id.into(),
            poll_interval_ms,
            max_deadline_ms,
            trust,
            ice_servers,
            sessions: SendWrapper(Rc::new(RefCell::new(HashMap::new()))),
            next_negotiation_id: AtomicU64::new(1),
            ice_observer: None,
        }
    }

    /// Install a reachability observer (see [`IceObserver`]).
    ///
    /// A builder method rather than a seventh argument to [`Self::new`]
    /// deliberately: observation is optional and additive, and every existing
    /// caller — the app, the worker host, the tests — should keep compiling
    /// unchanged. `new`'s required arguments are the ones whose *absence would
    /// be a silent posture decision* (`trust`, `ice_servers`); this is not one
    /// of those, because a missing observer degrades to today's behaviour
    /// exactly.
    pub fn with_ice_observer(mut self, observer: Arc<dyn IceObserver>) -> Self {
        self.ice_observer = Some(observer);
        self
    }

    /// Report one finished negotiation. Called on **every** exit path after the
    /// session exists — a consumer that only ever hears about failures cannot
    /// clear the advice it is showing when the peer finally connects.
    ///
    /// `failure` is the error the negotiation ended with, when it ended in one.
    /// Only [`WebRtcError::Timeout`] can say whether the far side ever answered
    /// — every other variant failed before the loop could know, and reports
    /// `None` rather than a `false` that reads as a claim about the counterpart.
    fn report_ice(
        &self,
        peer_id: &str,
        seen: &Rc<RefCell<Vec<String>>>,
        established: bool,
        failure: Option<&WebRtcError>,
    ) {
        let Some(obs) = &self.ice_observer else {
            return;
        };
        let (sdp_exchange_complete, remote_candidates_fed) = match failure {
            Some(WebRtcError::Timeout {
                answered,
                candidates_fed,
                ..
            }) => (Some(*answered), Some(*candidates_fed)),
            // An open data channel is an SDP exchange that completed, by
            // construction.
            None if established => (Some(true), None),
            _ => (None, None),
        };
        obs.negotiation_finished(NegotiationReport {
            peer_id,
            local_candidates: &seen.borrow(),
            established,
            sdp_exchange_complete,
            remote_candidates_fed,
        });
    }

    /// Drop a negotiation's session and close its `RTCPeerConnection`. Called on
    /// every failure path after `open`: there is no broker to reclaim it and
    /// [`WebRtcSession`] has no `Drop` that closes the `pc`, so a leaked
    /// negotiation would otherwise keep an `RTCPeerConnection` alive forever.
    fn discard_session(&self, negotiation_id: u64) {
        if let Some(s) = self.sessions.0.borrow_mut().remove(&negotiation_id) {
            s.close();
        }
    }
}

#[async_trait::async_trait(?Send)]
impl LiveEstablish for MainThreadWebRtcEstablisher {
    async fn establish_live(
        &self,
        ctx: EstablishCtx,
        peer_id: &str,
    ) -> Result<LivePath, LiveEstablishError> {
        // §6.4 skip-own — the cheap early exit that avoids minting an
        // `RTCPeerConnection` only to tear it down one call later. Not
        // load-bearing (`negotiate` returns `SelfNegotiation` for equal ids),
        // but mirrored from the Worker arm.
        if peer_id == self.self_peer_id {
            return Err(LiveEstablishError::NotAttempted {
                substrate: SUBSTRATE_WEBRTC,
                reason: "§6.4 skip-own: the target is this peer".to_string(),
            });
        }

        // Both ids must be the SAME KIND of string. Feed one canonical peer-id
        // and one of anything else and `pair_key`/`glare_role` quietly derive
        // different rendezvous buckets with no error anywhere — the failure that
        // cost the Worker arm a container harness and an encoding proof-table.
        // A silent no-rendezvous looks like a NAT problem; refusing costs one
        // negotiation that could never have succeeded.
        if !EntityUri::is_peer_id(peer_id) {
            web_sys::console::warn_1(&wasm_bindgen::JsValue::from_str(&format!(
                "§6.5 (direct): target '{peer_id}' is not a canonical base58 peer-id; \
                 refusing rather than deriving an unshareable rendezvous bucket"
            )));
            return Err(LiveEstablishError::Refused {
                substrate: SUBSTRATE_WEBRTC,
                reason: "the target is not a canonical base58 peer-id, so no shared \
                         rendezvous bucket could be derived"
                    .to_string(),
            });
        }

        // `pair` mode: both ids are known out of band, which is what makes the
        // offerer rule pre-assignable and §6.4's skip-own satisfiable.
        let key = pair_key(&self.self_peer_id, peer_id);

        // The caller's deadline wins; our ceiling only shortens it.
        let remaining_ms = ctx.remaining().as_millis().min(u64::MAX as u128) as u64;
        let deadline_ms = remaining_ms.min(self.max_deadline_ms);
        if deadline_ms == 0 {
            return Err(LiveEstablishError::NotAttempted {
                substrate: SUBSTRATE_WEBRTC,
                reason: "the seam deadline had already passed".to_string(),
            });
        }

        // Mint the `RTCPeerConnection` and register it for retention BEFORE the
        // negotiation runs — the session must outlive `establish_live` on the
        // success path (module lifetime rule).
        let negotiation_id = self.next_negotiation_id.fetch_add(1, Ordering::Relaxed);
        let session = match WebRtcSession::new(&self.ice_servers) {
            Ok(s) => s,
            Err(e) => {
                return Err(LiveEstablishError::NotAttempted {
                    substrate: SUBSTRATE_WEBRTC,
                    reason: format!("could not open an RTCPeerConnection: {e}"),
                });
            }
        };
        self.sessions
            .0
            .borrow_mut()
            .insert(negotiation_id, session.clone());

        let seen: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let io = MainThreadWebRtcIo {
            session,
            started: web_time::Instant::now(),
            seen: seen.clone(),
        };

        let session_id = SessionId::generate();
        let party = WebRtcParty {
            key,
            self_id: self.self_peer_id.clone(),
            peer_id: peer_id.to_string(),
            session_id,
            poll_interval_ms: self.poll_interval_ms,
            deadline_ms,
            trust: self.trust,
            // §6.3: taken from the carrier so "the peer the node sees" and "the
            // peer the signature proves" cannot drift — `negotiate` refuses the
            // pair if this disagrees with `self_id`.
            signer: self.carrier.identity(),
        };

        // ONE negotiation, never retried — how §7.2.1's `caller_owns_retry`
        // obligation is discharged. Polling the carrier within one negotiation
        // is part of a single third-party exchange, not a retry of it.
        let negotiated = match negotiate(&party, &self.carrier, &io).await {
            Ok(n) => n,
            Err(e) => {
                // No broker to reclaim the `pc`; do it here.
                self.discard_session(negotiation_id);
                let (label, mapped) = match &e {
                    // Policy refusal about a reachable counterpart (mixed build
                    // under `Require`, or our own two ids disagreeing) — never a
                    // NAT problem, and the variant an operator most needs told
                    // apart from one.
                    WebRtcError::VerificationUnavailable | WebRtcError::IdentitySkew { .. } => (
                        "refused (policy — NOT a NAT/connectivity failure)",
                        LiveEstablishError::Refused {
                            substrate: SUBSTRATE_WEBRTC,
                            reason: e.to_string(),
                        },
                    ),
                    // Ordinary best-effort failure — the §10.3 fall-through to
                    // relay, same contract the native punch keeps.
                    _ => (
                        "no live path",
                        LiveEstablishError::NoPath {
                            substrate: SUBSTRATE_WEBRTC,
                            reason: e.to_string(),
                        },
                    ),
                };
                web_sys::console::warn_1(&wasm_bindgen::JsValue::from_str(&format!(
                    "§6.5 (direct): negotiation to '{peer_id}' failed — {label}: {e}"
                )));
                // Report AFTER `discard_session` but BEFORE returning: the tee
                // outlives the session, and this is the failure a consumer most
                // needs to classify.
                self.report_ice(peer_id, &seen, false, Some(&e));
                return Err(mapped);
            }
        };

        // Success: the session STAYS in `self.sessions`. The `Connection` below
        // is a `MessagePort` whose far end the session pumps against the open
        // `RTCDataChannel`; dropping the session now would tear that pump down
        // before the caller could send a byte.
        web_sys::console::log_1(&wasm_bindgen::JsValue::from_str(&format!(
            "§6.5 (direct): a WebRTC data channel is OPEN to '{peer_id}' — live path established"
        )));
        // The success half of the contract. A consumer told only about failures
        // would keep showing "this network needs a relay" over a working
        // connection — the cry-wolf failure, arriving late instead of early.
        self.report_ice(peer_id, &seen, true, None);

        // §6.5 → §7.4.1, "one role assignment, not two": the peer that offered
        // is the initiator and sends HELLO; the peer that answered serves it.
        let role = if negotiated.offered {
            HandshakeRole::Initiator
        } else {
            HandshakeRole::Responder
        };
        Ok(LivePath {
            connection: connection_from_port_typed(
                negotiated.channel,
                format!("webrtc://{peer_id}"),
                "webrtc",
            ),
            role,
            // §4.4: the browser leg is §6.5 trigger (b) by construction — both
            // peers drove this seam off `party.key`, a §3 rendezvous key, and
            // the channel exists only because the two keys matched.
            established_via_rendezvous_key: true,
        })
    }
}
