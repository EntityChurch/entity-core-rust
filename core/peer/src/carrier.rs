//! The signaling carrier — offer/collect at a node, substrate-agnostic.
//!
//! `EXTENSION-SIGNALING.md` §7.3.1 draws the line this module sits on:
//! **substrates do not interoperate; the coordination layer does.** Carrier,
//! rendezvous key, and the bucket exchange are shared by every punch substrate
//! (`tcp`, `quic`, `webrtc`); only the transport underneath differs.
//!
//! This lived inside [`crate::punch_establisher`] until the browser leg needed
//! it. That module is gated `not(target_arch = "wasm32")` because its *wiring*
//! is TCP — correctly so — and the carrier had no reason to be separate while
//! TCP was the only substrate. The WebRTC substrate (`EXTENSION-SIGNALING.md`
//! §6.5) is the second one, and it reaches its node the same way: a live
//! connection to a signaling peer, `offer` and `collect` over EXECUTE. Nothing
//! here touches a socket, so it compiles for `wasm32` and a browser peer drives
//! its SDP/ICE exchange over the identical carrier.
//!
//! The move is a relocation, not a redesign: the TCP punch constructs the same
//! carrier through [`PeerCarrier::new`] and behaves exactly as before.

use std::sync::Arc;

use entity_crypto::IdentityKeypair;
use entity_entity::Entity;
use entity_signaling::data::{CollectRequest, CollectResult, OfferRequest};
use entity_signaling::punch::{Carrier, PunchError};
use entity_signaling::RendezvousKey;

use crate::remote;
use crate::transport::Connector;

/// [`Carrier`] over a live connection to a signaling node.
///
/// # The node is dialed by address, never resolved through the tree
///
/// `get_or_connect` resolves a peer through published transport profiles — and
/// that is exactly what a NAT'd peer cannot do for the *carrier*. Resolving the
/// rendezvous service the same way you resolve a peer is circular: the whole
/// reason the carrier exists is that peer resolution has already failed. So the
/// node's address is **operator configuration** (a CLI flag / a config field),
/// the same posture Go takes, and this dials it directly.
///
/// The connection is cached and reused across the several `offer` / `collect`
/// calls one exchange makes — reconnecting per verb would triple the carrier's
/// load for no benefit.
///
/// # The cache is not the pool, so it owes its own eviction
///
/// This connection lives outside `RemoteState`, so nothing that demotes and
/// re-dials a pooled connection ever touches it. It used to be returned
/// unconditionally, which made the carrier's first transport failure permanent:
/// a phone that backgrounded, a network change, or a node restart left every
/// later §6.5 negotiation failing with `carrier refused or failed` until the
/// establisher was rebuilt — while meets, riding the pool, kept working
/// (`entity-browser-rust` `HANDOFF-2026-09-15-a` §4 H2). Two evictions, because
/// a dead connection shows up in two ways: a reader that has exited is dropped
/// **before** use (the next verb re-dials instead of failing), and any
/// transport error from a verb drops the connection it ran on — which catches
/// the socket that went silent without closing, where the reader never learns.
/// A non-200 status is an answer, not a transport failure, and keeps the
/// connection. Held by `a_carrier_redials_after_losing_the_node`.
pub struct PeerCarrier {
    node_peer_id: String,
    node_addr: String,
    keypair: Arc<IdentityKeypair>,
    connector: Arc<dyn Connector>,
    home_format: u8,
    conn: tokio::sync::Mutex<Option<Arc<remote::RemoteConnection>>>,
}

impl PeerCarrier {
    /// Wire a carrier to the operator-configured signaling node.
    ///
    /// `connector` is the platform's outbound transport — a `TcpConnector`
    /// natively, a `BrowserWebSocketConnector` in a browser. The carrier does
    /// not care which: it needs a live connection to the node, not a substrate.
    pub fn new(
        node_peer_id: impl Into<String>,
        node_addr: impl Into<String>,
        keypair: IdentityKeypair,
        connector: Arc<dyn Connector>,
        home_format: u8,
    ) -> Self {
        Self {
            node_peer_id: node_peer_id.into(),
            node_addr: node_addr.into(),
            keypair: Arc::new(keypair),
            connector,
            home_format,
            conn: tokio::sync::Mutex::new(None),
        }
    }

    /// The identity this carrier authenticates to the node as.
    ///
    /// Exposed for **one** reason: §6.3 deposits are signed, and the signature
    /// must be made by the same identity the node's session authenticated. Two
    /// sources of identity here would be two things that can skew — a peer that
    /// signs its offers as one id while the node logs `caller=` another, which
    /// is unfalsifiable from either side alone. Taking it from the carrier makes
    /// the skew unrepresentable rather than merely tested for.
    ///
    /// A handle, not the key material: `Arc` shares the one keypair the peer
    /// already holds. Nothing here serializes, exports, or logs it — the
    /// keystore remains its only durable home.
    pub fn identity(&self) -> Arc<IdentityKeypair> {
        self.keypair.clone()
    }

    async fn connection(&self) -> Result<Arc<remote::RemoteConnection>, PunchError> {
        let mut slot = self.conn.lock().await;
        if let Some(existing) = slot.as_ref() {
            if !existing.reader_ended() {
                return Ok(existing.clone());
            }
            tracing::debug!(
                node = %self.node_addr,
                "§6.5 carrier: the cached node connection's reader has ended; re-dialing"
            );
            *slot = None;
        }
        let transport = self
            .connector
            .connect(&self.node_addr)
            .await
            .map_err(|e| PunchError::Carrier(format!("dial node {}: {}", self.node_addr, e)))?;
        let conn = remote::perform_connect(transport, &self.keypair, self.home_format)
            .await
            .map_err(|e| PunchError::Carrier(format!("handshake with node: {}", e)))?;
        let conn = Arc::new(conn);
        *slot = Some(conn.clone());
        Ok(conn)
    }

    async fn execute(&self, operation: &str, params: Entity) -> Result<(u32, Entity), PunchError> {
        let conn = self.connection().await?;
        let uri = format!("/{}/{}", self.node_peer_id, entity_signaling::PATTERN);
        // `resource: None` is load-bearing — see the module doc. A resource
        // target on a signaling verb is a 403 that reads as "not granted".
        let resp = remote::send_execute(
            conn.as_ref(),
            &self.keypair,
            &uri,
            operation,
            &params,
            None,
            None,
            None,
            &std::collections::HashMap::new(),
            None,
        )
        .await;
        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                // Evict the connection this verb ran on — and only that one: a
                // concurrent verb may already have replaced it with a live dial.
                let mut slot = self.conn.lock().await;
                if slot.as_ref().is_some_and(|c| Arc::ptr_eq(c, &conn)) {
                    *slot = None;
                }
                return Err(PunchError::Carrier(format!("{}: {}", operation, e)));
            }
        };
        Ok((resp.status, resp.result))
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl Carrier for PeerCarrier {
    async fn offer(&self, key: &RendezvousKey, blob: Vec<u8>) -> Result<(), PunchError> {
        let params = OfferRequest {
            rendezvous_key: *key,
            message: blob,
        }
        .to_entity()
        .map_err(PunchError::from)?;
        let (status, result) = self.execute(entity_signaling::OP_OFFER, params).await?;
        if status != 200 {
            return Err(PunchError::Carrier(format!(
                "offer: {}",
                remote::refusal_detail(status, &result)
            )));
        }
        Ok(())
    }

    async fn collect(&self, key: &RendezvousKey) -> Result<Vec<Vec<u8>>, PunchError> {
        let params = CollectRequest {
            rendezvous_key: *key,
        }
        .to_entity()
        .map_err(PunchError::from)?;
        let (status, result) = self.execute(entity_signaling::OP_COLLECT, params).await?;
        if status != 200 {
            return Err(PunchError::Carrier(format!(
                "collect: {}",
                remote::refusal_detail(status, &result)
            )));
        }
        Ok(CollectResult::from_params(&result.data)
            .map_err(PunchError::from)?
            .messages)
    }
}

/// §6.5 rendezvous over a **real carrier and a real node** — the segment no
/// other test covers.
///
/// `entity_signaling`'s own negotiation tests drive `negotiate` against a stub
/// carrier and a shared in-memory bucket, so they prove the choreography and
/// nothing about the wire. The browser leg proves the wire and cannot run
/// outside a browser. Between them sits the piece that actually broke for
/// `entity-browser-rust`: two peers deriving a `pair` key from real peer-ids,
/// posting and collecting through a real signaling node over real TCP.
///
/// **No browser is required to test that**, which is the point — `WebRtcIo` is
/// the only thing stubbed here. If the rendezvous layer is sound, this passes
/// and their red is worker/browser-side; if it is not, this reproduces it
/// natively in a second and a half instead of a container rig.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod rendezvous_over_a_real_node {
    use super::*;
    use crate::{server, transport, PeerBuilder};
    use entity_capability::GrantEntry;
    use entity_crypto::Keypair;
    use entity_signaling::key::pair_key;
    use entity_signaling::webrtc::{
        negotiate, IceCandidate, LocalCandidate, SessionId, VerificationPolicy, WebRtcIo,
        WebRtcParty,
    };
    use std::sync::Mutex;

    fn signaling_seed() -> Vec<(String, Vec<GrantEntry>)> {
        vec![(
            "default".to_string(),
            entity_signaling::signaling_seed_grants(),
        )]
    }

    async fn start_node(seed: u8) -> (String, u16, tokio::task::JoinHandle<()>) {
        let keypair = entity_crypto::IdentityKeypair::Ed25519(Keypair::from_seed([seed; 32]));
        let peer_id = keypair.peer_id().to_string();
        let core = Arc::new(entity_signaling::SignalingCore::new(format!(
            "node:{}",
            seed
        )));
        let handler = Arc::new(entity_signaling::SignalingHandler::new(core, &peer_id));

        let peer = PeerBuilder::new()
            .identity_keypair(keypair)
            .listen_addr("127.0.0.1:0")
            .with_seed_policy(signaling_seed())
            .handler(handler)
            .build()
            .expect("node builds");
        let listener = peer.listen().await.expect("node listens");
        let port = listener.socket_addr().port();
        let shared = peer.shared();
        peer.start_engines(&shared);
        let handle = tokio::spawn(async move {
            let _ = server::run(listener, shared).await;
        });
        (peer_id, port, handle)
    }

    fn carrier_for(node_id: &str, node_port: u16, seed: u8) -> (PeerCarrier, String) {
        let keypair = entity_crypto::IdentityKeypair::Ed25519(Keypair::from_seed([seed; 32]));
        let self_id = keypair.peer_id().to_string();
        let carrier = PeerCarrier::new(
            node_id.to_string(),
            format!("127.0.0.1:{}", node_port),
            keypair,
            Arc::new(transport::TcpConnector),
            entity_hash::HASH_ALGORITHM_SHA256,
        );
        (carrier, self_id)
    }

    /// Enough of a browser to exercise the choreography: SDP is an opaque
    /// string to §6.5, so a labelled placeholder is as faithful as a real one.
    /// `wait_open` never succeeds — this test is about the rendezvous, and a
    /// channel that opened would prove nothing extra about it.
    struct StubIo {
        label: &'static str,
        candidates: Mutex<Vec<LocalCandidate>>,
        remote_seen: Mutex<Vec<IceCandidate>>,
    }

    impl StubIo {
        fn new(label: &'static str) -> Self {
            Self {
                label,
                candidates: Mutex::new(vec![LocalCandidate {
                    candidate: format!("candidate:1 1 udp 1 127.0.0.1 900 typ host {label}"),
                    sdp_mid: "0".into(),
                    sdp_mline_index: 0,
                    username_fragment: None,
                }]),
                remote_seen: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl WebRtcIo for StubIo {
        type Channel = ();

        async fn create_offer(&self) -> Result<String, String> {
            Ok(format!(
                "v=0\r\no=- {} 1 IN IP4 0.0.0.0\r\ns=-\r\n",
                self.label
            ))
        }
        async fn create_answer(&self, _remote: &str) -> Result<String, String> {
            Ok(format!(
                "v=0\r\no=- {}-answer 1 IN IP4 0.0.0.0\r\ns=-\r\n",
                self.label
            ))
        }
        async fn accept_answer(&self, _remote: &str) -> Result<(), String> {
            Ok(())
        }
        async fn drain_local_candidates(&self) -> Vec<LocalCandidate> {
            std::mem::take(&mut *self.candidates.lock().unwrap())
        }
        async fn add_remote_candidate(&self, c: &IceCandidate) -> Result<(), String> {
            self.remote_seen.lock().unwrap().push(c.clone());
            Ok(())
        }
        async fn wait_open(&self, timeout_ms: u64) -> Result<(), String> {
            tokio::time::sleep(std::time::Duration::from_millis(timeout_ms.min(20))).await;
            Err("stub channel never opens".into())
        }
        async fn sleep_ms(&self, ms: u64) {
            tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
        }
        fn now_ms(&self) -> u64 {
            web_time::SystemTime::now()
                .duration_since(web_time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64
        }
    }

    fn party(
        key: RendezvousKey,
        me: &str,
        them: &str,
        signer: Arc<entity_crypto::IdentityKeypair>,
        io_deadline: u64,
    ) -> WebRtcParty {
        WebRtcParty {
            key,
            self_id: me.to_string(),
            peer_id: them.to_string(),
            session_id: SessionId::generate(),
            poll_interval_ms: 25,
            deadline_ms: io_deadline,
            trust: VerificationPolicy::AllowUnverifiedPreContainer,
            // The carrier's own identity — the same one the node authenticated
            // this session as, which is what makes the deposits it logs and the
            // signatures they carry the same peer by construction.
            signer,
        }
    }

    /// The claim under test: two peers that address each other by canonical
    /// peer-id land in **one** bucket at a real node, and each sees the
    /// other's deposit.
    ///
    /// Asserted on what crosses the node rather than on a channel, because
    /// `wait_open` is stubbed: A must accept B's answer (or B must answer A's
    /// offer), which is only reachable if the collect that carried it was
    /// non-empty. `included_count=0` on both sides — the reported symptom —
    /// fails this test.
    ///
    /// Post-flag-day it proves a second thing for free. Every deposit is now a
    /// §6.3 container, and a candidate only reaches `add_remote_candidate` if
    /// `classify_collected` opened it — so "each peer saw the other's deposit"
    /// now means each peer **verified** a signature bound to this bucket, over
    /// a real node, over real TCP.
    #[tokio::test]
    async fn two_peers_share_one_bucket_and_see_each_other() {
        let (node_id, node_port, node_handle) = start_node(0x61).await;
        let (a_carrier, a_id) = carrier_for(&node_id, node_port, 0x62);
        let (b_carrier, b_id) = carrier_for(&node_id, node_port, 0x63);
        assert_ne!(a_id, b_id);

        // Exactly what `BrowserWebRtcEstablisher` does: each side derives the
        // key from (its own id, its target's id).
        let a_key = pair_key(&a_id, &b_id);
        let b_key = pair_key(&b_id, &a_id);
        assert_eq!(
            a_key, b_key,
            "pair_key sorts its arguments, so both sides derive one bucket"
        );

        // Exactly one may offer.
        let a_suppress =
            entity_signaling::webrtc::pair_should_suppress_offer(&a_id, &b_id).unwrap();
        let b_suppress =
            entity_signaling::webrtc::pair_should_suppress_offer(&b_id, &a_id).unwrap();
        assert_ne!(a_suppress, b_suppress);

        let a_io = StubIo::new("A");
        let b_io = StubIo::new("B");

        let a_party = party(a_key, &a_id, &b_id, a_carrier.identity(), 4_000);
        let b_party = party(b_key, &b_id, &a_id, b_carrier.identity(), 4_000);
        let (a_res, b_res) = tokio::join!(
            negotiate(&a_party, &a_carrier, &a_io),
            negotiate(&b_party, &b_carrier, &b_io),
        );

        // Both time out: the stub channel never opens. That is expected and is
        // NOT what this test measures.
        assert!(a_res.is_err() && b_res.is_err(), "stub channel never opens");

        // What it measures: the rendezvous carried. Each side fed the other's
        // trickled candidate, which it can only have obtained from a collect
        // that returned the counterpart's deposit.
        let a_saw = a_io.remote_seen.lock().unwrap().len();
        let b_saw = b_io.remote_seen.lock().unwrap().len();
        assert!(
            a_saw > 0 && b_saw > 0,
            "each peer must see the other's deposit through the node — \
             A saw {a_saw}, B saw {b_saw} (both zero is the reported rung-1 symptom)"
        );

        node_handle.abort();
    }

    /// A write half that can be cut while the read half stays open — the
    /// socket that went silent without closing, where the reader never learns.
    struct CutWriter {
        inner: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
        cut: Arc<std::sync::atomic::AtomicBool>,
    }

    impl tokio::io::AsyncWrite for CutWriter {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            if self.cut.load(std::sync::atomic::Ordering::Acquire) {
                return std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
            }
            std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
        }
        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// A connector to an in-process node whose every link the test can break,
    /// in either of the two ways a real one breaks.
    struct BreakableNodeLink {
        shared: Arc<crate::PeerShared>,
        dials: std::sync::atomic::AtomicUsize,
        servers: Mutex<Vec<tokio::task::JoinHandle<()>>>,
        cut: Mutex<Option<Arc<std::sync::atomic::AtomicBool>>>,
    }

    impl BreakableNodeLink {
        fn dials(&self) -> usize {
            self.dials.load(std::sync::atomic::Ordering::Acquire)
        }
        /// The node closes the connection: the reader sees EOF.
        fn close_from_the_node(&self) {
            for h in self.servers.lock().unwrap().drain(..) {
                h.abort();
            }
        }
        /// The connection goes silent: writes fail, the reader never ends.
        fn cut_silently(&self) {
            if let Some(c) = self.cut.lock().unwrap().as_ref() {
                c.store(true, std::sync::atomic::Ordering::Release);
            }
        }
    }

    #[async_trait::async_trait]
    impl Connector for BreakableNodeLink {
        async fn connect(
            &self,
            _addr: &str,
        ) -> Result<transport::Connection, transport::TransportError> {
            let (client, server) = transport::memory_transport_pair();
            let shared = self.shared.clone();
            self.servers.lock().unwrap().push(tokio::spawn(async move {
                let _ = crate::connection::handle_connection(server, shared).await;
            }));
            self.dials.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            let cut = Arc::new(std::sync::atomic::AtomicBool::new(false));
            *self.cut.lock().unwrap() = Some(cut.clone());
            Ok(transport::Connection {
                reader: client.reader,
                writer: Box::new(CutWriter {
                    inner: client.writer,
                    cut,
                }),
                remote_addr: client.remote_addr,
                transport_type: client.transport_type,
            })
        }
        fn transport_type(&self) -> &'static str {
            "memory"
        }
    }

    /// The carrier re-dials a node it has lost, instead of failing every §6.5
    /// negotiation for the rest of the session (`HANDOFF-2026-09-15-a` §4 H2).
    ///
    /// Two rows, one per eviction, and each is RED under the other eviction
    /// alone. **Closed by the node** asks that the *very next* verb succeed,
    /// which only the before-use `reader_ended` check can deliver — evict-on-error
    /// alone spends that verb failing. **Gone silent** keeps the reader alive, so
    /// only evict-on-error can recover, on the verb after the one that failed.
    /// Under the original unconditional cache both rows fail forever.
    #[tokio::test]
    async fn a_carrier_redials_after_losing_the_node() {
        let node_kp = entity_crypto::IdentityKeypair::Ed25519(Keypair::from_seed([0x71; 32]));
        let node_id = node_kp.peer_id().to_string();
        let core = Arc::new(entity_signaling::SignalingCore::new("node:71".to_string()));
        let node = PeerBuilder::new()
            .identity_keypair(node_kp)
            .with_seed_policy(signaling_seed())
            .handler(Arc::new(entity_signaling::SignalingHandler::new(
                core, &node_id,
            )))
            .build()
            .expect("node builds");
        let shared = node.shared();
        node.start_engines(&shared);

        let link = Arc::new(BreakableNodeLink {
            shared,
            dials: Default::default(),
            servers: Mutex::new(Vec::new()),
            cut: Mutex::new(None),
        });
        let me = entity_crypto::IdentityKeypair::Ed25519(Keypair::from_seed([0x72; 32]));
        let carrier = PeerCarrier::new(
            node_id.clone(),
            "memory:node",
            me,
            link.clone(),
            entity_hash::HASH_ALGORITHM_SHA256,
        );
        let key = pair_key("a", "b");

        carrier
            .collect(&key)
            .await
            .expect("first collect dials the node");
        assert_eq!(link.dials(), 1);

        // Row 1 — closed by the node. Wait until the reader has seen it.
        link.close_from_the_node();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !carrier.conn.lock().await.as_ref().unwrap().reader_ended() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the reader observes the node closing");
        let row1 = carrier.collect(&key).await;

        // Row 2 — the connection goes silent. One verb may fail; the next must not.
        link.cut_silently();
        let _first_after_cut = carrier.collect(&key).await;
        let row2 = carrier.collect(&key).await;

        assert!(
            row1.is_ok(),
            "closed by the node: the next verb must re-dial, got {row1:?}"
        );
        assert!(
            row2.is_ok(),
            "gone silent: the verb after a transport failure must re-dial, got {row2:?}"
        );
        assert_eq!(link.dials(), 3, "one dial per lost connection");
    }
}
