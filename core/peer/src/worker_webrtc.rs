//! The worker half of the §6.5 negotiation: a [`WebRtcIo`] that proxies every
//! call to the main thread over the `ControlMessage` plane.
//!
//! # Why this direction
//!
//! `RTCPeerConnection` is `[Exposed=Window]` in the W3C IDL — main-thread only
//! on **every** engine, not a quirk of one. The carrier and the signing
//! identity live in the worker, and the §10 dispatcher that decides to
//! negotiate runs there too. So the worker is the driver and the main thread is
//! the passive owner of a resource the worker cannot touch. That inverts the
//! usual `Request`/`Response` direction, which is why this rides
//! [`ControlMessage`] instead.
//!
//! The choreography itself is **not** here — it is
//! `entity_signaling::webrtc::WebRtcParty`, built and tested natively against a
//! stub with no browser involved. This type only carries the seam across the
//! thread boundary, exactly as `MessagePortConnector` carries `open_channel`.
//!
//! # The byte invariant
//!
//! Arch's §6.5 `[security — MUST]`: the bytes **signed** equal the bytes
//! **produced**, the bytes **consumed** equal the bytes **verified**, and the
//! crossing carries the payload verbatim — no re-encode, canonicalize, or
//! reconstruct. They also flagged it **single-impl-invisible**: a
//! same-implementation run marshals identically at both ends and cannot expose
//! a mangled crossing. That is the property that hid `fire_at` and the
//! handshake role.
//!
//! Two things here make it locally detectable instead:
//!
//! 1. **SDP crosses as `Vec<u8>`, never `String`.** SDP is CRLF-sensitive, and
//!    a `String` on the crossing is an open invitation for some future helper
//!    to trim it, normalize newlines, or round-trip it through a formatter —
//!    none of which a type-checker objects to.
//! 2. **Every SDP carries a `sdp_digest`, checked by the side that consumes
//!    it.** A mismatch is refused, loudly, at negotiation rate.
//!
//! The `String` at the [`WebRtcIo`] boundary is unavoidable — the trait is
//! shared with the native-tested choreography — so the conversion happens once,
//! here, at the edge, and the digest is computed over the bytes that actually
//! cross.

use std::rc::Rc;

use entity_signaling::key::pair_key;
use entity_signaling::webrtc::{
    negotiate, IceCandidate, LocalCandidate, SessionId, WebRtcError, WebRtcIo, WebRtcParty,
};

/// Re-exported because it is a **required** argument to
/// [`BrowserWebRtcEstablisher::new`], and a caller that must name it should not
/// need a direct dependency on the signaling extension to do so. Grep for the
/// variants to find every place the migration posture is still chosen.
pub use entity_signaling::webrtc::VerificationPolicy;
use web_sys::MessagePort;

use crate::carrier::PeerCarrier;
use crate::live_establish::{EstablishCtx, LiveEstablish};
use crate::transport::{
    connection_from_port_typed, sdp_digest, verified_sdp_from_bytes, Connection, ControlMessage,
    ControlPortClient, WebRtcReply, WireIceServer,
};

/// Carries a `!Send` browser handle through a `Send + Sync` trait object.
///
/// The same device `Connection` and `Listener` already use in
/// [`crate::transport`]: both keep `Send` on *every* platform and wrap the
/// browser types that are not. `LiveEstablish` splits only its **future** with
/// `?Send` on wasm32 — the supertrait `Send + Sync` is unconditional — so an
/// establisher holding an `Rc<ControlPortClient>` needs the same treatment as
/// the `Connection` it produces.
///
/// Relaxing the supertrait instead was the alternative, and `entity-browser-rust`
/// ruled against it: it would diverge from the sibling traits and cascade
/// through every store of `dyn LiveEstablish` — including the native
/// `PeerPunchEstablisher` seam just cross-validated with `entity-core-go` — for
/// zero runtime benefit, since wasm32 is single-threaded.
struct SendWrapper<T>(T);
// SAFETY: wasm32 is single-threaded, so the bound is vacuous and the guard
// this removes could never have fired. Same reasoning as `transport.rs`.
unsafe impl<T> Send for SendWrapper<T> {}
// SAFETY: as above.
unsafe impl<T> Sync for SendWrapper<T> {}

/// A `WebRtcIo` whose `RTCPeerConnection` lives on the main thread.
pub struct WorkerWebRtcIo {
    control: Rc<ControlPortClient>,
    negotiation_id: u64,
    started: web_time::Instant,
}

impl WorkerWebRtcIo {
    /// Ask the broker to mint an `RTCPeerConnection` for this pairing.
    ///
    /// `peer_id` is explicit rather than inferred — the v6 Subscribe lesson in
    /// AGENTS.md: a peer-targeted request must never let "defaults to primary"
    /// be silent.
    /// `ice_servers` rides this message rather than configuring the broker
    /// separately, because the broker is where `RTCConfiguration` is built but
    /// the worker is where the values are provisioned. Travelling with the
    /// request that consumes them makes worker/main skew impossible rather
    /// than merely unlikely. Empty means host-candidates-only, never "default".
    pub async fn open(
        control: Rc<ControlPortClient>,
        from_peer: &str,
        peer_id: &str,
        session_id: &[u8],
        ice_servers: Vec<WireIceServer>,
    ) -> Result<Self, String> {
        let negotiation_id = control.next_negotiation_id();
        let reply = control
            .webrtc_call(|request_id| ControlMessage::WebRtcOpen {
                request_id,
                negotiation_id,
                peer_id: peer_id.to_string(),
                from_peer: from_peer.to_string(),
                session_id: session_id.to_vec(),
                ice_servers: ice_servers.clone(),
            })
            .await?;
        match reply {
            WebRtcReply::Ack => Ok(Self {
                control,
                negotiation_id,
                started: web_time::Instant::now(),
            }),
            other => Err(mismatch("Ack", &other)),
        }
    }

    /// Unwrap a `LocalSdp` reply, refusing a digest that does not cover the
    /// bytes we were handed.
    ///
    /// The check itself is [`verified_sdp_from_bytes`], which lives outside the
    /// wasm32 gate precisely so `make test` can exercise it.
    fn take_verified_sdp(reply: WebRtcReply) -> Result<String, String> {
        let WebRtcReply::LocalSdp {
            sdp,
            sdp_digest: got,
        } = reply
        else {
            return Err(mismatch("LocalSdp", &reply));
        };
        verified_sdp_from_bytes(&sdp, &got)
    }
}

fn mismatch(want: &str, got: &WebRtcReply) -> String {
    format!("control-plane reply mismatch: expected {want}, got {got:?}")
}

#[async_trait::async_trait(?Send)]
impl WebRtcIo for WorkerWebRtcIo {
    /// The port whose far end the broker pumps against the `RTCDataChannel`.
    /// `connection_from_port` turns it into an ordinary `Connection`, which is
    /// why the worker side of the channel handoff needed no new code at all.
    type Channel = MessagePort;

    async fn create_offer(&self) -> Result<String, String> {
        let reply = self
            .control
            .webrtc_call(|request_id| ControlMessage::WebRtcCreateOffer {
                request_id,
                negotiation_id: self.negotiation_id,
            })
            .await?;
        Self::take_verified_sdp(reply)
    }

    async fn create_answer(&self, remote_offer_sdp: &str) -> Result<String, String> {
        let remote = remote_offer_sdp.as_bytes().to_vec();
        let digest = sdp_digest(&remote);
        let reply = self
            .control
            .webrtc_call(|request_id| ControlMessage::WebRtcCreateAnswer {
                request_id,
                negotiation_id: self.negotiation_id,
                remote_sdp: remote.clone(),
                remote_sdp_digest: digest.clone(),
            })
            .await?;
        Self::take_verified_sdp(reply)
    }

    async fn accept_answer(&self, remote_answer_sdp: &str) -> Result<(), String> {
        let remote = remote_answer_sdp.as_bytes().to_vec();
        let digest = sdp_digest(&remote);
        let reply = self
            .control
            .webrtc_call(|request_id| ControlMessage::WebRtcAcceptAnswer {
                request_id,
                negotiation_id: self.negotiation_id,
                remote_sdp: remote.clone(),
                remote_sdp_digest: digest.clone(),
            })
            .await?;
        match reply {
            WebRtcReply::Ack => Ok(()),
            other => Err(mismatch("Ack", &other)),
        }
    }

    async fn drain_local_candidates(&self) -> Vec<LocalCandidate> {
        // Trickle is polled, not awaited (§6.5), and a failed poll is not
        // fatal to the negotiation — the next tick tries again. Returning an
        // empty batch is the honest answer to "nothing arrived."
        let reply = self
            .control
            .webrtc_call(|request_id| ControlMessage::WebRtcDrainCandidates {
                request_id,
                negotiation_id: self.negotiation_id,
            })
            .await;
        match reply {
            Ok(WebRtcReply::Candidates(list)) => list
                .into_iter()
                .map(|c| LocalCandidate {
                    candidate: c.candidate,
                    sdp_mid: c.sdp_mid,
                    sdp_mline_index: c.sdp_mline_index,
                    username_fragment: c.username_fragment,
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    async fn add_remote_candidate(&self, candidate: &IceCandidate) -> Result<(), String> {
        let reply = self
            .control
            .webrtc_call(|request_id| ControlMessage::WebRtcAddCandidate {
                request_id,
                negotiation_id: self.negotiation_id,
                candidate: candidate.candidate.clone(),
                sdp_mid: candidate.sdp_mid.clone(),
                sdp_mline_index: candidate.sdp_mline_index,
                // Absent stays absent across the crossing: `addIceCandidate`
                // reads an empty string as a real ufrag.
                username_fragment: candidate.username_fragment.clone(),
            })
            .await?;
        match reply {
            WebRtcReply::Ack => Ok(()),
            other => Err(mismatch("Ack", &other)),
        }
    }

    async fn wait_open(&self, timeout_ms: u64) -> Result<Self::Channel, String> {
        let reply = self
            .control
            .webrtc_call(|request_id| ControlMessage::WebRtcAwaitOpen {
                request_id,
                negotiation_id: self.negotiation_id,
                timeout_ms,
            })
            .await?;
        match reply {
            WebRtcReply::Channel(port) => Ok(port),
            other => Err(mismatch("Channel", &other)),
        }
    }

    async fn sleep_ms(&self, ms: u64) {
        gloo_timers::future::TimeoutFuture::new(ms as u32).await;
    }

    fn now_ms(&self) -> u64 {
        // Monotonic and never placed on the wire, per the trait contract —
        // `web_time::Instant` rather than `Date.now()` for exactly that reason.
        self.started.elapsed().as_millis() as u64
    }
}

impl Drop for WorkerWebRtcIo {
    fn drop(&mut self) {
        // Fire-and-forget: there is no useful reply, and a dropped negotiation
        // must not leave an `RTCPeerConnection` alive on the main thread
        // waiting for one.
        self.control.webrtc_post(&ControlMessage::WebRtcClose {
            negotiation_id: self.negotiation_id,
        });
    }
}

// ---------------------------------------------------------------------------
// The §10.3 seam — Worker arm
// ---------------------------------------------------------------------------

/// The §6.5 negotiation behind the §10.3 `establish_live` seam, for a peer
/// hosted in a Worker.
///
/// This is the WebRTC counterpart of [`crate::punch_establisher::PeerPunchEstablisher`]:
/// same slot, same obligations, different substrate. Native fills the slot with
/// a §7 TCP punch; a browser fills it with this, because a browser has no
/// socket to punch with.
///
/// # Worker arm only, on purpose
///
/// `entity-browser-rust`'s shipped default arm is Worker (never Direct), and S5
/// — two real browser peers over a real signaling node — runs in that arm. The
/// Direct-arm establisher (main-thread peer talking to `web_sys` with no broker
/// hop) is a genuine second implementation and is deliberately **not** built
/// here: it is not on the S5 critical path. The seam stays injectable on both
/// arms so it can land later.
///
/// # What this does not carry
///
/// The `carrier` arrives already constructed. How its configuration reaches a
/// Worker — signaling-node address, identity, and the enable decision — is the
/// `PROTOCOL_VERSION` 10 → 11 payload still being co-designed with
/// `entity-browser-rust`, and is deliberately not invented here.
pub struct BrowserWebRtcEstablisher {
    carrier: PeerCarrier,
    self_peer_id: String,
    control: SendWrapper<Rc<ControlPortClient>>,
    poll_interval_ms: u64,
    /// Ceiling for one negotiation. The effective budget is the smaller of this
    /// and what `EstablishCtx` has left — §10.3's deadline is the caller's and
    /// a policy MUST NOT run past it.
    max_deadline_ms: u64,
    trust: VerificationPolicy,
    /// Handed to the broker on every `WebRtcOpen`. Empty is a legal,
    /// deliberate deployment statement — host candidates only — not a
    /// missing value to be defaulted.
    ice_servers: Vec<WireIceServer>,
}

impl BrowserWebRtcEstablisher {
    /// Wire the §6.5 negotiation behind the seam.
    ///
    /// `trust` is a required argument and has no default, because
    /// [`VerificationPolicy`] deliberately has none. Naming the choice at the
    /// call site is what keeps "we shipped the browser leg with no identity
    /// binding" from being something a reader has to infer.
    ///
    /// [`VerificationPolicy::Require`] **is what the worker host now passes** —
    /// the §6.3 container landed, this establisher deposits sealed into it, and
    /// `entity_signaling`'s collect path mints the verified signer `Require`
    /// needs. Nothing gates it: a §6.5 counterpart is always another peer
    /// running this crate (`entity-core-go` implements no §6.5 negotiation), so
    /// the only thing `Require` refuses is a build of this crate older than the
    /// deposit flip.
    ///
    /// The argument is still worth having at *your* call site, which is why this
    /// stays a required parameter: a peer that must interoperate with a known-old
    /// build is the one case for the tolerant variant.
    ///
    /// `ice_servers` is likewise required and likewise has no default. An
    /// empty vector is the LAN-only deployment and says so on the wire; the
    /// one thing this constructor will not do is substitute a public STUN
    /// server nobody named.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        carrier: PeerCarrier,
        self_peer_id: impl Into<String>,
        control: Rc<ControlPortClient>,
        poll_interval_ms: u64,
        max_deadline_ms: u64,
        trust: VerificationPolicy,
        ice_servers: Vec<WireIceServer>,
    ) -> Self {
        Self {
            carrier,
            self_peer_id: self_peer_id.into(),
            control: SendWrapper(control),
            poll_interval_ms,
            max_deadline_ms,
            trust,
            ice_servers,
        }
    }
}

#[async_trait::async_trait(?Send)]
impl LiveEstablish for BrowserWebRtcEstablisher {
    async fn establish_live(&self, ctx: EstablishCtx, peer_id: &str) -> Option<Connection> {
        // §6.4's skip-own. Not the only guard and not load-bearing:
        // `negotiate` calls `pair_should_suppress_offer`, which returns
        // `SelfNegotiation` for equal ids and is tested natively. This is the
        // cheap early exit that avoids minting an `RTCPeerConnection` on the
        // main thread only to tear it down one call later.
        if peer_id == self.self_peer_id {
            return None;
        }

        // Both ids must be the SAME KIND of string, and this is the only place
        // that can still check.
        //
        // `pair_key` and `glare_role` consume their ids byte-exact by design.
        // Feed one canonical peer-id and one of anything else and both quietly
        // misbehave at once: the two peers derive different rendezvous buckets,
        // and — because every base58 peer-id sorts below every `ecfv1-…` hash —
        // both resolve to Impolite and both offer. The result is
        // `included_count=0` on every collect with no error anywhere, which is
        // exactly what `entity-browser-rust`'s two-browser rig spent a
        // container harness and an encoding proof-table to find.
        //
        // `extract_peer_id_from_uri` now rejects a non-peer-id authority, which
        // closes the path that produced it. This guard is here because the seam
        // takes a `&str` from any caller, and a silent no-rendezvous is the
        // worst possible failure mode for one: it looks like a NAT problem.
        // Refusing costs one negotiation that could never have succeeded.
        if !entity_entity::EntityUri::is_peer_id(peer_id) {
            tracing::warn!(
                remote_peer = %peer_id,
                "§6.5: target is not a canonical base58 peer-id; refusing rather \
                 than deriving a rendezvous bucket the counterpart cannot share"
            );
            return None;
        }

        // `pair` mode: both ids are known out of band, which is what makes the
        // offerer rule pre-assignable and §6.4's skip-own satisfiable. The
        // matchmaking modes cannot do either without §6.3's container, so S3
        // scope is `pair` — agreed with `entity-core-go`.
        let key = pair_key(&self.self_peer_id, peer_id);

        // The peer half of the node's offer/collect key log. Both ids verbatim,
        // because "what source says they are" and "what they are at runtime"
        // are exactly the two things that can disagree here — and the derived
        // key, so a peer's line can be matched byte-for-byte against the
        // rendezvous_key the node reports for the same exchange.
        tracing::debug!(
            self_peer_id = %self.self_peer_id,
            target_peer_id = %peer_id,
            rendezvous_key = ?key,
            "§6.5: derived pair rendezvous key"
        );

        // The caller's deadline wins; our ceiling only shortens it.
        let remaining_ms = ctx.remaining().as_millis().min(u64::MAX as u128) as u64;
        let deadline_ms = remaining_ms.min(self.max_deadline_ms);
        if deadline_ms == 0 {
            tracing::debug!(
                remote_peer = %peer_id,
                "§10.3: deadline already passed; not starting a §6.5 negotiation"
            );
            return None;
        }

        let session_id = SessionId::generate();
        let io = match WorkerWebRtcIo::open(
            self.control.0.clone(),
            &self.self_peer_id,
            peer_id,
            session_id.as_bytes(),
            self.ice_servers.clone(),
        )
        .await
        {
            Ok(io) => io,
            Err(e) => {
                tracing::warn!(
                    remote_peer = %peer_id,
                    error = %e,
                    "§6.5: the main thread would not open an RTCPeerConnection; \
                     no negotiation was attempted"
                );
                return None;
            }
        };

        let party = WebRtcParty {
            key,
            self_id: self.self_peer_id.clone(),
            peer_id: peer_id.to_string(),
            session_id,
            poll_interval_ms: self.poll_interval_ms,
            deadline_ms,
            trust: self.trust,
            // §6.3: every deposit is sealed under the identity the carrier
            // authenticates to the node as. Taken from the carrier rather than
            // injected separately so "the peer the node sees" and "the peer the
            // signature proves" cannot drift apart — `negotiate` refuses the
            // pair outright if this disagrees with `self_id`.
            signer: self.carrier.identity(),
        };

        // ONE negotiation, never retried — which is how §7.2.1's
        // `caller_owns_retry` obligation is discharged here.
        //
        // That obligation binds the step which contacts a THIRD PARTY, and for
        // §6.5 that is the coordination exchange against the signaling node.
        // Polling the carrier *within* one negotiation is part of that single
        // exchange, not a retry of it; re-running `negotiate` would re-post
        // offers to the node and is the thing §4.1's backoff already owns. So
        // this is unconditional rather than gated on `ctx.caller_owns_retry` —
        // the stricter behaviour is correct in both cases, and a policy that
        // retried only when the flag was clear would multiply budgets onto
        // someone else's node exactly as §7.2.1 warns.
        let port = match negotiate(&party, &self.carrier, &io).await {
            Ok(port) => port,
            // Every §6.5 failure is still "no live path" to the §10.3 seam —
            // same contract the native punch keeps, where relay is the outcome
            // of a failed traversal. What changed is that it is no longer
            // *silent*: this used to be `.ok()?`, which dropped the error on
            // the floor in the one establisher whose failures happen inside a
            // worker, where nobody can attach a debugger. Three separate hunts
            // in this arc ended at "`included_count=0`, no error anywhere";
            // two of the variants below are that condition, named.
            Err(e) => {
                match &e {
                    // The mixed-build case. Worth a `warn!` and worth spelling
                    // out, because `Require` refuses *only* a build of this
                    // crate older than the sealed-deposit flip — and a refusal
                    // on the browser leg reads as a NAT problem to everyone who
                    // has not been told otherwise. That mis-read is the
                    // recurring cost in this cohort; the line should pre-empt
                    // it rather than a routing doc having to.
                    WebRtcError::VerificationUnavailable => tracing::warn!(
                        remote_peer = %peer_id,
                        rendezvous_key = ?party.key,
                        "§6.5: counterpart's SDP carried no §6.3 container under `Require` \
                         — this is a MIXED BUILD (a peer older than the sealed-deposit \
                         flip), not a NAT or connectivity failure"
                    ),
                    // Our own two ids disagreed: bucket derived from one,
                    // identity proved by another. Refused before any deposit
                    // precisely because it is invisible at every later step.
                    WebRtcError::IdentitySkew { .. } => tracing::warn!(
                        remote_peer = %peer_id,
                        error = %e,
                        "§6.5: refusing to negotiate — the id we sort by and the key we \
                         sign with are not the same identity"
                    ),
                    // Was the one failure a peer structurally could not diagnose
                    // alone — so the line offered a dichotomy ("unshared bucket
                    // vs absent peer") and sent the reader to the node's log.
                    //
                    // `entity-browser-rust`'s rung-1 re-run then hit a case that
                    // is NEITHER: bucket shared, counterpart present and
                    // answering (the node logged all 8 messages under one key),
                    // and still no channel. The old text mis-described the very
                    // case that reached it, so the reader spent the run
                    // re-litigating rendezvous, which was already working.
                    //
                    // The error now carries the terminal state, so this says
                    // which half failed instead of offering a guess:
                    // `sdp_exchange=INCOMPLETE` with a non-empty bucket is a
                    // correlation failure, `complete` with a `channel wait`
                    // reason is ICE/DTLS. Only the genuinely empty bucket sends
                    // anyone back to the node's log.
                    WebRtcError::Timeout {
                        counterpart_msgs, ..
                    } => tracing::warn!(
                        remote_peer = %peer_id,
                        self_peer_id = %self.self_peer_id,
                        rendezvous_key = ?party.key,
                        deadline_ms,
                        error = %e,
                        hint = if *counterpart_msgs == 0 {
                            "bucket was EMPTY — rendezvous side: match this rendezvous_key \
                             against the node's offer/collect log \
                             (`RUST_LOG=entity_signaling=debug`) to tell an unshared bucket \
                             from an absent peer"
                        } else {
                            "bucket was NON-EMPTY — the counterpart was present, so this is \
                             NOT a rendezvous failure; read `sdp_exchange` and `channel wait` \
                             in the error above"
                        },
                        "§6.5: the negotiation window closed without an open data channel"
                    ),
                    WebRtcError::Carrier(_)
                    | WebRtcError::Substrate(_)
                    | WebRtcError::Coding(_) => tracing::warn!(
                        remote_peer = %peer_id,
                        rendezvous_key = ?party.key,
                        error = %e,
                        "§6.5: negotiation failed; no live path"
                    ),
                }
                return None;
            }
        };

        // The worker side of the handoff is unchanged code: the broker keeps
        // the far end and pumps the RTCDataChannel against it, so what arrives
        // here is an ordinary port.
        // Labelled `webrtc`, not `xworker`: the port is only the carrier of the
        // data channel, and at the S5 gate "which transport is this?" is the
        // first question asked of a connection.
        Some(connection_from_port_typed(
            port,
            format!("webrtc://{peer_id}"),
            "webrtc",
        ))
    }
}
