//! Main-thread broker for cross-Worker peer transport.
//!
//! Routes `OpenChannel` control messages from one Worker into
//! `IncomingChannel` notifications on another Worker, transferring a
//! fresh `MessageChannel` port pair so the two Workers can talk
//! directly afterwards. The broker stays out of the data path — it
//! only mediates connection setup.
//!
//! # Port lifecycle
//!
//! Multiple peers hosted in the same Worker share a single control
//! port — the broker holds the broker-side end, the Worker holds the
//! worker-side end. The broker installs **one** onmessage handler
//! per port (NOT per peer), keyed by JS object identity. Adding more
//! peers pointing at the same port reuses the existing handler.
//! Removing peers ref-counts via the routing map: the port's handler
//! survives until no more peers point at it.
//!
//! This design is deliberate: JS `MessagePort.onmessage` is a
//! single-valued slot. Installing one closure per peer (the earlier
//! shape) would orphan all prior closures and, worse, dropping the
//! last-set closure on `unregister_peer` would invalidate the JS
//! function the port's `onmessage` still pointed at — silently
//! killing dispatch for every other peer sharing the port.
//!
//! Source identity (`from_peer`) for routing `ChannelDenied`
//! responses now rides on the `OpenChannel` wire message instead of
//! being closure-captured — symmetric with the `to_peer` field on
//! `IncomingChannel`.
//!
//! # Consumer API
//!
//! - Consumer creates `MessagePortBroker::new()` once.
//! - For each Worker the consumer spawns, the consumer creates a
//!   `MessageChannel` and posts one port to the Worker (via the Init
//!   message's transferList) while keeping the other.
//! - For each peer the Worker hosts, the consumer calls
//!   `broker.register_peer(peer_id, port.clone())`. All registrations
//!   for the same Worker pass the same JS MessagePort (cloned —
//!   `MessagePort::clone` returns a Rust handle to the same JS
//!   object; identity is preserved).
//! - On peer deletion or Worker termination, the consumer calls
//!   `broker.unregister_peer(peer_id)`. The port's handler is removed
//!   only when no remaining peer points at it.

use crate::webrtc_session::{post_reply, sdp_from_worker, Sessions, WebRtcSession};
use entity_peer::transport::{sdp_digest, ControlMessage, CONTROL_PROTOCOL_VERSION};
use js_sys::{Object, Uint8Array};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::spawn_local;
use web_sys::{MessageChannel, MessageEvent, MessagePort};

/// Per-Worker control-port routing entry. Multiple peer-ids may map
/// to the same `PortEntry` (i.e., they live in the same Worker).
struct PortEntry {
    /// Broker-side end of the control channel for this Worker.
    port: MessagePort,
    /// One onmessage closure per port, retained while ANY peer in
    /// the routing map points at this port. The closure captures
    /// only the broker's routing map — no per-peer state — so it
    /// stays valid across add/remove churn of peers behind the port.
    _on_message: Closure<dyn FnMut(MessageEvent)>,
}

type Routing = Rc<RefCell<HashMap<String, Rc<PortEntry>>>>;

/// Main-thread broker that routes cross-Worker connection requests.
pub struct MessagePortBroker {
    /// peer-id → its hosting Worker's control-port entry. Multiple
    /// peer-ids share an `Rc<PortEntry>` value when they're in the
    /// same Worker.
    routing: Routing,
}

impl Default for MessagePortBroker {
    fn default() -> Self {
        Self::new()
    }
}

impl MessagePortBroker {
    pub fn new() -> Self {
        Self {
            routing: Rc::new(RefCell::new(HashMap::new())),
        }
    }

    /// Register a peer hosted in a Worker against the broker-side end
    /// of that Worker's control channel.
    ///
    /// Idempotent on the port-level handler: the first registration
    /// for a given port installs the onmessage handler; subsequent
    /// registrations for the same port reuse it. JS `Object.is` on
    /// the underlying JsValue determines port identity.
    pub fn register_peer(&self, peer_id: String, control_port: MessagePort) {
        let entry = self.entry_for_port(&control_port);
        self.routing.borrow_mut().insert(peer_id, entry);
    }

    /// Remove a peer's routing entry. If this was the last peer
    /// pointing at the port, the `PortEntry` (and its onmessage
    /// closure) drops, retiring the port's broker-side handler.
    /// Otherwise the port stays live for the remaining peers.
    pub fn unregister_peer(&self, peer_id: &str) -> bool {
        self.routing.borrow_mut().remove(peer_id).is_some()
        // The Rc<PortEntry> drops here if no other routing entry
        // holds it; that drops the Closure, which is fine because no
        // peer is using the port anymore.
    }

    /// Snapshot of currently-routed peer ids (debug / introspection).
    pub fn registered_peers(&self) -> Vec<String> {
        self.routing.borrow().keys().cloned().collect()
    }

    /// Find an existing `PortEntry` for `port` (by JS object
    /// identity) among the routing map's values, or build a fresh
    /// one with a newly-installed onmessage handler.
    fn entry_for_port(&self, port: &MessagePort) -> Rc<PortEntry> {
        // Linear scan of routing.values() for an existing entry whose
        // port is the same JS object. N here is the number of peers
        // currently registered — small (<100 in any realistic
        // deployment) and the hot path is connect setup, not steady
        // state.
        let port_jsv: &JsValue = port.as_ref();
        if let Some(existing) = self
            .routing
            .borrow()
            .values()
            .find(|e| Object::is(e.port.as_ref(), port_jsv))
            .cloned()
        {
            return existing;
        }

        // First time seeing this port — install the handler.
        let routing = self.routing.clone();
        // Set when this port's worker announces a control-plane version we do
        // not speak. Created before the closure so both the closure and the
        // PortEntry can observe it; a skewed port is refused for the rest of
        // its life rather than per-request.
        let skewed = Rc::new(Cell::new(false));
        let skewed_for_closure = skewed.clone();
        let port_for_closure = port.clone();
        // §6.5 negotiations, scoped to THIS port because `negotiation_id` is
        // allocated per `ControlPortClient`. A broker-global map would let two
        // workers collide on an id and drive each other's RTCPeerConnection.
        let sessions: Sessions = Rc::new(RefCell::new(HashMap::new()));
        let sessions_for_closure = sessions.clone();
        let on_message = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            let data = event.data();
            let bytes = match data.dyn_into::<Uint8Array>() {
                Ok(arr) => arr.to_vec(),
                Err(_) => return,
            };
            let msg: ControlMessage = match ciborium::from_reader(bytes.as_slice()) {
                Ok(m) => m,
                Err(_) => return,
            };
            match msg {
                ControlMessage::Hello {
                    control_protocol_version,
                } => {
                    if control_protocol_version == CONTROL_PROTOCOL_VERSION {
                        let _ = post_control(
                            &port_for_closure,
                            &ControlMessage::HelloAck {
                                control_protocol_version: CONTROL_PROTOCOL_VERSION,
                            },
                            None,
                        );
                    } else {
                        // Refuse the port outright rather than serving it and
                        // hoping the shapes happen to line up. A control plane
                        // that half-works is the silent worker-skew trap the
                        // Request/Response version ladder already exists to
                        // prevent.
                        skewed_for_closure.set(true);
                        let _ = post_control(
                            &port_for_closure,
                            &ControlMessage::ControlVersionMismatch {
                                expected: CONTROL_PROTOCOL_VERSION,
                                got: control_protocol_version,
                            },
                            None,
                        );
                    }
                }
                // Workers only originate OpenChannel toward the broker;
                // Granted/Denied/Incoming flow the other direction and
                // are dropped silently if they show up here.
                ControlMessage::OpenChannel {
                    request_id,
                    peer_id: target,
                    from_peer,
                } => {
                    if skewed_for_closure.get() {
                        let _ = post_control(
                            &port_for_closure,
                            &ControlMessage::ChannelDenied {
                                request_id,
                                reason: format!(
                                    "control-plane version skew: broker speaks {}",
                                    CONTROL_PROTOCOL_VERSION
                                ),
                            },
                            None,
                        );
                        return;
                    }
                    handle_open_channel(&routing, &from_peer, request_id, &target);
                }
                other => {
                    if skewed_for_closure.get() {
                        return;
                    }
                    handle_webrtc(&sessions_for_closure, &port_for_closure, other);
                }
            }
        });

        port.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
        port.start();

        Rc::new(PortEntry {
            port: port.clone(),
            _on_message: on_message,
        })
    }
}

/// The §6.5 sibling of [`handle_open_channel`] — **broker-as-terminus**.
///
/// Deliberately not a reuse: `handle_open_channel` looks up `target_peer`,
/// denies with "no such peer" if absent, and routes `port2` onward as an
/// `IncomingChannel`. It assumes both ends are registered peers. The WebRTC far
/// end is a remote browser, not a registered peer, so there is no lookup, no
/// `IncomingChannel`, and the broker keeps `port2` to pump the data channel
/// against — transferring only `port1`.
///
/// Every arm answers with exactly one reply carrying the request's
/// `request_id`, including failures: a call that got no reply at all would hang
/// the worker's `webrtc_call` until the port died.
fn handle_webrtc(sessions: &Sessions, port: &MessagePort, msg: ControlMessage) {
    match msg {
        ControlMessage::WebRtcOpen {
            request_id,
            negotiation_id,
            ice_servers,
            ..
        } => {
            // `peer_id` / `from_peer` / `session_id` ride the message so the
            // worker's addressing is explicit on the wire (the v6 Subscribe
            // lesson), but the broker needs none of them: it holds no routing
            // table for a counterpart that was never a registered peer.
            //
            // `ice_servers` it does need, and takes from the message rather
            // than from broker-level config: the values are provisioned into
            // the worker (v11 `InitParams.webrtc`), and a second copy held
            // here is a second thing that can be wrong. Empty means
            // host-candidates-only and nothing is substituted.
            let reply = match WebRtcSession::new(&ice_servers) {
                Ok(s) => {
                    sessions.borrow_mut().insert(negotiation_id, s);
                    ControlMessage::WebRtcAck { request_id }
                }
                Err(reason) => ControlMessage::WebRtcFailed { request_id, reason },
            };
            let _ = post_reply(port, &reply, None);
        }

        ControlMessage::WebRtcCreateOffer {
            request_id,
            negotiation_id,
        } => spawn_sdp(sessions, port, request_id, negotiation_id, |s| async move {
            s.create_offer().await
        }),

        ControlMessage::WebRtcCreateAnswer {
            request_id,
            negotiation_id,
            remote_sdp,
            remote_sdp_digest,
        } => {
            let sdp = match sdp_from_worker(&remote_sdp, &remote_sdp_digest) {
                Ok(s) => s,
                Err(reason) => {
                    let _ = post_reply(
                        port,
                        &ControlMessage::WebRtcFailed { request_id, reason },
                        None,
                    );
                    return;
                }
            };
            spawn_sdp(sessions, port, request_id, negotiation_id, |s| async move {
                s.create_answer(&sdp).await
            })
        }

        ControlMessage::WebRtcAcceptAnswer {
            request_id,
            negotiation_id,
            remote_sdp,
            remote_sdp_digest,
        } => {
            let sdp = match sdp_from_worker(&remote_sdp, &remote_sdp_digest) {
                Ok(s) => s,
                Err(reason) => {
                    let _ = post_reply(
                        port,
                        &ControlMessage::WebRtcFailed { request_id, reason },
                        None,
                    );
                    return;
                }
            };
            spawn_ack(sessions, port, request_id, negotiation_id, |s| async move {
                s.accept_answer(&sdp).await
            })
        }

        ControlMessage::WebRtcAddCandidate {
            request_id,
            negotiation_id,
            candidate,
            sdp_mid,
            sdp_mline_index,
            username_fragment,
        } => spawn_ack(
            sessions,
            port,
            request_id,
            negotiation_id,
            move |s| async move {
                s.add_remote_candidate(
                    &candidate,
                    &sdp_mid,
                    sdp_mline_index,
                    username_fragment.as_deref(),
                )
                .await
            },
        ),

        ControlMessage::WebRtcDrainCandidates {
            request_id,
            negotiation_id,
        } => {
            let reply = match session(sessions, negotiation_id) {
                Ok(s) => ControlMessage::WebRtcCandidates {
                    request_id,
                    candidates: s.drain_candidates(),
                },
                Err(reason) => ControlMessage::WebRtcFailed { request_id, reason },
            };
            let _ = post_reply(port, &reply, None);
        }

        ControlMessage::WebRtcAwaitOpen {
            request_id,
            negotiation_id,
            timeout_ms,
        } => {
            let s = match session(sessions, negotiation_id) {
                Ok(s) => s,
                Err(reason) => {
                    let _ = post_reply(
                        port,
                        &ControlMessage::WebRtcFailed { request_id, reason },
                        None,
                    );
                    return;
                }
            };
            let port = port.clone();
            spawn_local(async move {
                match s.wait_open(timeout_ms).await {
                    // ONE port transferred, not the two-peer split.
                    Ok(for_worker) => {
                        let _ = post_reply(
                            &port,
                            &ControlMessage::WebRtcChannelGranted { request_id },
                            Some(&for_worker),
                        );
                    }
                    Err(reason) => {
                        let _ = post_reply(
                            &port,
                            &ControlMessage::WebRtcFailed { request_id, reason },
                            None,
                        );
                    }
                }
            });
        }

        ControlMessage::WebRtcClose { negotiation_id } => {
            // Fire-and-forget by design: no reply, and the session must go
            // even if the worker never asks again.
            if let Some(s) = sessions.borrow_mut().remove(&negotiation_id) {
                s.close();
            }
        }

        // Broker→worker replies and the channel plane are handled elsewhere.
        _ => {}
    }
}

fn session(sessions: &Sessions, negotiation_id: u64) -> Result<Rc<WebRtcSession>, String> {
    sessions
        .borrow()
        .get(&negotiation_id)
        .cloned()
        .ok_or_else(|| format!("no negotiation {negotiation_id} on this control port"))
}

/// Run an SDP-producing call and answer with the finalized local description
/// plus its digest.
fn spawn_sdp<F, Fut>(
    sessions: &Sessions,
    port: &MessagePort,
    request_id: u64,
    negotiation_id: u64,
    f: F,
) where
    F: FnOnce(Rc<WebRtcSession>) -> Fut + 'static,
    Fut: std::future::Future<Output = Result<String, String>> + 'static,
{
    let s = match session(sessions, negotiation_id) {
        Ok(s) => s,
        Err(reason) => {
            let _ = post_reply(
                port,
                &ControlMessage::WebRtcFailed { request_id, reason },
                None,
            );
            return;
        }
    };
    let port = port.clone();
    spawn_local(async move {
        let reply = match f(s).await {
            Ok(sdp) => {
                let bytes = sdp.into_bytes();
                ControlMessage::WebRtcLocalSdpReady {
                    request_id,
                    sdp_digest: sdp_digest(&bytes),
                    sdp: bytes,
                }
            }
            Err(reason) => ControlMessage::WebRtcFailed { request_id, reason },
        };
        let _ = post_reply(&port, &reply, None);
    });
}

/// Run a call whose success carries no payload.
fn spawn_ack<F, Fut>(
    sessions: &Sessions,
    port: &MessagePort,
    request_id: u64,
    negotiation_id: u64,
    f: F,
) where
    F: FnOnce(Rc<WebRtcSession>) -> Fut + 'static,
    Fut: std::future::Future<Output = Result<(), String>> + 'static,
{
    let s = match session(sessions, negotiation_id) {
        Ok(s) => s,
        Err(reason) => {
            let _ = post_reply(
                port,
                &ControlMessage::WebRtcFailed { request_id, reason },
                None,
            );
            return;
        }
    };
    let port = port.clone();
    spawn_local(async move {
        let reply = match f(s).await {
            Ok(()) => ControlMessage::WebRtcAck { request_id },
            Err(reason) => ControlMessage::WebRtcFailed { request_id, reason },
        };
        let _ = post_reply(&port, &reply, None);
    });
}

fn handle_open_channel(routing: &Routing, from_peer: &str, request_id: u64, target_peer: &str) {
    let routing_guard = routing.borrow();
    let target = match routing_guard.get(target_peer) {
        Some(t) => t.clone(),
        None => {
            // Source's port is still in the map under from_peer —
            // post Denied back so the caller doesn't hit the
            // open_channel timeout.
            if let Some(src) = routing_guard.get(from_peer) {
                let src = src.clone();
                drop(routing_guard);
                let _ = post_control(
                    &src.port,
                    &ControlMessage::ChannelDenied {
                        request_id,
                        reason: format!("no such peer: {}", target_peer),
                    },
                    None,
                );
            }
            return;
        }
    };
    let source = match routing_guard.get(from_peer) {
        Some(s) => s.clone(),
        None => return,
    };
    drop(routing_guard);

    let channel = match MessageChannel::new() {
        Ok(c) => c,
        Err(e) => {
            let _ = post_control(
                &source.port,
                &ControlMessage::ChannelDenied {
                    request_id,
                    reason: format!("MessageChannel::new failed: {:?}", e),
                },
                None,
            );
            return;
        }
    };
    let port_for_source = channel.port1();
    let port_for_target = channel.port2();

    // Notify the listening side first so the accept queue is primed
    // before the connector resolves its open_channel future. `to_peer`
    // is the requested target id — the receiving Worker uses it to
    // dispatch to the matching local listener (multi-peer-per-Worker).
    if let Err(e) = post_control(
        &target.port,
        &ControlMessage::IncomingChannel {
            from_peer: from_peer.to_string(),
            to_peer: target_peer.to_string(),
        },
        Some(&port_for_target),
    ) {
        let _ = post_control(
            &source.port,
            &ControlMessage::ChannelDenied {
                request_id,
                reason: format!("failed to notify target: {:?}", e),
            },
            None,
        );
        return;
    }
    let _ = post_control(
        &source.port,
        &ControlMessage::ChannelGranted { request_id },
        Some(&port_for_source),
    );
}

fn post_control(
    port: &MessagePort,
    msg: &ControlMessage,
    transfer_port: Option<&MessagePort>,
) -> Result<(), JsValue> {
    let mut buf = Vec::new();
    ciborium::into_writer(msg, &mut buf)
        .map_err(|e| JsValue::from_str(&format!("CBOR encode failed: {}", e)))?;
    let arr = Uint8Array::new_with_length(buf.len() as u32);
    arr.copy_from(&buf);

    if let Some(p) = transfer_port {
        let transfer = js_sys::Array::new();
        transfer.push(p);
        port.post_message_with_transferable(&arr, &transfer)
    } else {
        port.post_message(&arr)
    }
}
