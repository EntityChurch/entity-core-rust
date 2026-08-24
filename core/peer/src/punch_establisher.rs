//! The live wiring of `EXTENSION-SIGNALING` §7 behind
//! `EXTENSION-NETWORK.md` §10.3 — rung 3.
//!
//! `extensions/signaling` owns the *choreography* and names no socket;
//! `core/peer` owns sockets and the connection pool. This module is the join:
//! it supplies the two surfaces the choreography asks for and adapts what comes
//! back into a [`Connection`](crate::transport::Connection) the §10 ladder can
//! use.
//!
//! Mirrors `relay_forwarder`: the algorithm is the extension's, the wiring that
//! touches the pool is `core/peer`'s. §10.3's layering rule requires exactly
//! this direction — *"NETWORK is below the traversal extension and cannot call
//! into it, so the substrate exposes the slot and the extension plugs the
//! algorithm."*
//!
//! # The three pieces
//!
//! | Trait | Impl here | Supplies |
//! |---|---|---|
//! | `punch::Carrier` | [`PeerCarrier`] (in [`crate::carrier`]) | `offer` / `collect` at the node, over `remote::send_execute` |
//! | `punch::PunchIo` | [`PeerPunchIo`] | `SO_REUSEPORT` dial + accept, sleep, clock |
//! | `LiveEstablish` | [`PeerPunchEstablisher`] | the §10.3 slot itself |
//!
//! # Why the carrier goes through `send_execute` and not `Dispatcher`
//!
//! Calling `system/signaling:offer` is an ordinary cross-peer EXECUTE, and the
//! `Dispatcher` trait's only implementor (`bindings/sdk::PeerContext`) sits
//! *above* `core/peer` in the crate DAG — using it here would be a cycle. So
//! this takes the same route `cmd/signaling-meet` already does: a pooled
//! connection plus `remote::send_execute`. Same wire bytes, no new edge.
//!
//! **No resource target on a signaling verb.** Signaling addresses no tree
//! resource and the node's seeded grant has an empty resource scope, so
//! attaching one is a 403 that reads exactly like "not granted" — the trap Go's
//! report named and `cmd/entity-signaling-node/tests/admission.rs` pins.
//!
//! # What is not here
//!
//! **The responder loop** (rung 4). This module is the *initiator* half, which
//! is all §10.3 asks for: the seam fires when *we* want to reach someone. A
//! peer that also wants to be *found* runs `punch::respond` from a background
//! watcher over its rendezvous keys — that needs a key-selection policy and is
//! deliberately not invented here.
//!
//! **The srflx gatherer itself.** It is built, in [`crate::srflx`], and injected
//! here through [`CandidateGatherer`] rather than baked in — see that trait for
//! why the seam exists. With no gatherer attached this advertises `host`
//! candidates only, which is enough to punch on a LAN or in process and **not**
//! enough to cross a NAT.
//!
//! **The §6.7.1 reflector** (the responder half). Go ships it and one reflector
//! serves both peers in a traversal test; Rust builds only the client.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use entity_crypto::IdentityKeypair;
use entity_signaling::coordination::{
    Candidate, VerificationPolicy, CANDIDATE_HOST, SUBSTRATE_TCP,
};
use entity_signaling::punch::{self, PunchIo, PunchParty};
use entity_signaling::{key, RendezvousKey};

use crate::carrier::PeerCarrier;
use crate::live_establish::{EstablishCtx, LiveEstablish};
use crate::transport::{Connection, Connector};

/// The §6.3 posture of the **native** punch, named once here rather than
/// defaulted inside the party.
///
/// **Both impls now seal their §6.1 deposits** — `entity-core-go` at `d56a690`,
/// this one alongside this constant — so `Require` is satisfied by any
/// counterpart running current Go or current Rust, and the vectors cross the
/// shape both ways (`42·0F`, four §6.1 rows each side).
///
/// **The live cross-impl punch has now run, and this is the line it released.**
/// The hold was narrow and explicit — vectors prove the bytes, not that a Go
/// peer and a Rust peer complete a *sealed* exchange through a real node — so
/// it needed exactly one run to discharge, and raising it first would have
/// converted a first live failure from "they disagree about X" into "one of them
/// refuses to speak".
///
/// What ran (2026-08-04, loopback, one Rust `--open` node, `cmd/signaling-punch`
/// on both seats over the CLI/JSON contract agreed with `entity-core-go`):
///
/// | Initiator | Responder | Tolerant | Under `Require` here |
/// |---|---|---|---|
/// | Rust | Go   | `verified:true` | `verified:true` |
/// | Go   | Rust | `verified:true` | `verified:true` |
///
/// **The tolerant pass alone would not have licensed this**, and that is the
/// trap worth naming: a tolerant collector admits an *unsealed* counterpart too,
/// so a green tolerant run is consistent with Go never having sealed anything.
/// `Require` is the assay rather than merely the goal — it refuses any blob
/// without a §6.3 container, so a green cross-impl run **under** it is positive
/// proof that Go's deposits are sealed and that they verify in this collector,
/// bound to the rendezvous key. That is the observation the hold was waiting
/// for, and it is only available from the strict side.
///
/// Still true, and the reason the tolerant variant was never a security hole:
/// *the key introduces, it never authorizes* — a punched connection runs the
/// full handshake and capability flow regardless, so the worst case under
/// tolerance was a wasted dial rather than an authorized stranger. `Require`
/// buys the §6.4 filters: skip-own and expected-peer now run on a proven signer
/// with no unsigned fallback, so a forged `initiator`/`responder` field cannot
/// steer a crossing.
///
/// What this refuses is a peer older than either impl's deposit flip
/// (`entity-core-go` `d56a690`, this crate `007e078`) — the mixed-build case,
/// and the one worth refusing loudly.
const PUNCH_TRUST: VerificationPolicy = VerificationPolicy::Require;

// ---------------------------------------------------------------------------
// The substrate — SO_REUSEPORT dial and accept
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Candidate gathering — injected, never baked in
// ---------------------------------------------------------------------------

/// §7.1 step 1 — how this peer learns the addresses it might be reached at.
///
/// Injected rather than implemented here for a crate-DAG reason and a design
/// one. The DAG reason: `srflx` gathering is `EXTENSION-NETWORK` §6.7.1, and
/// wiring it in unconditionally would make every punch build drag the network
/// extension. The design reason is the one that matters — a browser peer gathers
/// candidates from its own ICE agent over standard STUN, which §6.7.1 is explicit
/// is *not* the same mechanism ("a peer offering `observe-address` is not a STUN
/// reflector for a browser"). A gatherer trait is the seam where those two worlds
/// meet; a hard-coded reflector dial is not.
///
/// `crate::srflx::SrflxGatherer` is the native §6.7.1 implementation.
#[async_trait::async_trait]
pub trait CandidateGatherer: Send + Sync {
    /// The candidate set to advertise, in §6.7.3 order (`host` → `srflx` →
    /// `relay`). An `Err` is *no live path*, not a dispatch error — the §10.3
    /// seam maps it to the relay fallback.
    async fn gather(&self) -> Result<Vec<Candidate>, String>;
}

/// [`PunchIo`] over the §7.3 socket options, bound to one shared local endpoint.
///
/// `local_addr` is the endpoint whose NAT mapping the reflector observed, and
/// every dial and the accept leave from it. That is `EXTENSION-NETWORK.md`
/// §6.7.3's rule and the entire reason [`crate::reuseport`] exists — a fresh
/// ephemeral socket gets a different external port, so the `srflx` we advertised
/// would describe a hole that never opens.
pub struct PeerPunchIo {
    local_addr: SocketAddr,
    /// Outbound connection attempts issued from this endpoint — counted at the
    /// `connect` syscall, never at entry to [`PunchIo::dial`].
    ///
    /// §7.1 step 4's MUST — *both* peers fire outbound at `fire_at` — has no
    /// observable consequence on loopback, because there is no NAT mapping for a
    /// missing outbound to fail to open. A listen-only peer still gets a path
    /// and still passes every functional assertion. So the attempt is counted
    /// and asserted directly; see [`PeerPunchEstablisher::outbound_attempts`].
    outbound: Arc<AtomicU32>,
    suppress_dial: bool,
}

impl PeerPunchIo {
    pub fn new(local_addr: SocketAddr) -> Self {
        Self::counted(local_addr, Arc::new(AtomicU32::new(0)))
    }

    fn counted(local_addr: SocketAddr, outbound: Arc<AtomicU32>) -> Self {
        Self {
            local_addr,
            outbound,
            suppress_dial: false,
        }
    }

    /// Adapt a punched (or reflector-dialed) `SO_REUSEPORT` stream into the
    /// ordinary transport the §10 ladder and the handshake both take.
    pub(crate) fn wrap(stream: tokio::net::TcpStream) -> Connection {
        let remote_addr = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "<punched>".to_string());
        let (reader, writer) = tokio::io::split(stream);
        Connection {
            reader: Box::new(reader),
            writer: Box::new(writer),
            remote_addr,
            // §10.3 obligation 1: a punched connection is an ORDINARY transport,
            // not a new type. It reports `tcp` because that is what it is — the
            // entity layer must not be able to tell it apart from a dialed one.
            transport_type: "tcp",
        }
    }
}

#[async_trait::async_trait]
impl PunchIo for PeerPunchIo {
    type Conn = Connection;

    async fn dial(&self, target: &str, timeout_ms: u64) -> Result<Connection, String> {
        if self.suppress_dial {
            // The negative control. No connect leaves the host, so
            // `outbound_attempts` stays 0 and `dialed_outbound` reports false —
            // which is the regression the field exists to make visible.
            return Err("dial suppressed (negative control)".into());
        }
        let remote: SocketAddr = target
            .parse()
            .map_err(|_| format!("bad address {}", target))?;
        let fut = crate::reuseport::dial_reuseport(self.local_addr, remote, || {
            self.outbound.fetch_add(1, Ordering::Relaxed);
        });
        match tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), fut).await {
            Ok(Ok(stream)) => Ok(Self::wrap(stream)),
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("dial timed out".into()),
        }
    }

    async fn accept(&self, window_ms: u64) -> Result<Connection, String> {
        let listener =
            crate::reuseport::listen_reuseport(self.local_addr).map_err(|e| e.to_string())?;
        match tokio::time::timeout(
            std::time::Duration::from_millis(window_ms),
            listener.accept(),
        )
        .await
        {
            Ok(Ok((stream, _))) => Ok(Self::wrap(stream)),
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("no inbound path within the crossing window".into()),
        }
    }

    async fn sleep_ms(&self, ms: u64) {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }

    fn now_ms(&self) -> u64 {
        web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// The seam
// ---------------------------------------------------------------------------

/// The §10.3 registered policy: reach a peer by the §7 punch.
pub struct PeerPunchEstablisher {
    carrier: PeerCarrier,
    local_addr: SocketAddr,
    self_peer_id: String,
    outbound: Arc<AtomicU32>,
    gatherer: Option<Arc<dyn CandidateGatherer>>,
    rendezvous_key: Option<RendezvousKey>,
    suppress_dial: bool,
}

impl PeerPunchEstablisher {
    /// Wire the punch behind the seam.
    ///
    /// `local_addr` is the shared endpoint the punch binds — and, when a
    /// gatherer is attached with [`Self::with_gatherer`], the **same** endpoint
    /// its reflector dial must have used (`EXTENSION-NETWORK.md` §6.7.3 MUST).
    /// Without a gatherer this advertises `host` candidates only.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_peer_id: impl Into<String>,
        node_addr: impl Into<String>,
        self_peer_id: impl Into<String>,
        local_addr: SocketAddr,
        keypair: IdentityKeypair,
        connector: Arc<dyn Connector>,
        home_format: u8,
    ) -> Self {
        Self {
            carrier: PeerCarrier::new(node_peer_id, node_addr, keypair, connector, home_format),
            local_addr,
            self_peer_id: self_peer_id.into(),
            outbound: Arc::new(AtomicU32::new(0)),
            gatherer: None,
            rendezvous_key: None,
            suppress_dial: false,
        }
    }

    /// Attach a §7.1 step 1 candidate gatherer.
    ///
    /// **The gatherer MUST be bound to this establisher's `local_addr`**
    /// (§6.7.3): a `srflx` observed on one socket and punched from another
    /// describes a hole that never opens. Nothing here can check that — the
    /// gatherer is opaque by design — so it is the caller's obligation, and
    /// `crate::srflx::SrflxGatherer::new` takes the address for exactly this
    /// reason.
    pub fn with_gatherer(mut self, gatherer: Arc<dyn CandidateGatherer>) -> Self {
        self.gatherer = Some(gatherer);
        self
    }

    /// **Never dial** — the pre-G1 listen-only shape, as a negative control.
    ///
    /// Behind a NAT this side's hole never opens, so the counterpart's SYN
    /// reaches a closed mapping and the punch MUST fail. That failure is the
    /// only *positive* evidence a dual-NAT harness can produce that it is
    /// testing traversal at all: a harness whose negative control passes is
    /// measuring something else. Mirrors Go's `punchOpts.suppressDial`.
    ///
    /// It is deliberately here and not in `extensions/signaling` — the
    /// choreography has no business knowing a peer might refuse to fire. Go
    /// makes the same split, injecting a `suppressedDial()` at the driver.
    pub fn suppress_dial(mut self) -> Self {
        self.suppress_dial = true;
        self
    }

    /// Punch at an explicitly supplied §3 rendezvous key instead of the derived
    /// `pair` key.
    ///
    /// **The seam itself must never use this.** `establish_live` fires when the
    /// ladder wants to reach a peer, and at that moment the only key both sides
    /// can compute *without out-of-band agreement* is `pair` — which is exactly
    /// why §3.2's `pair` mode is the one the seam can use, as the derivation
    /// takes only the two peer-ids.
    ///
    /// A **driver** is the case this exists for: a harness that ran
    /// `--mode tag --input chess` on both ends has supplied precisely the
    /// out-of-band agreement the seam lacks, so `tag` / `secret` / `lobby`
    /// become reachable. See `cmd/signaling-punch`.
    pub fn with_rendezvous_key(mut self, key: RendezvousKey) -> Self {
        self.rendezvous_key = Some(key);
        self
    }

    /// The key this punch runs at — supplied, or §3.2 `pair` derived from the
    /// two peer-ids.
    fn rendezvous_key_for(&self, peer_id: &str) -> RendezvousKey {
        self.rendezvous_key
            .unwrap_or_else(|| key::pair_key(&self.self_peer_id, peer_id))
    }

    /// How many outbound connection attempts this peer's punches have issued.
    ///
    /// §7.1 step 4 requires **every** peer to fire outbound at `fire_at`,
    /// whichever end of the crossing it keeps. That requirement is invisible on
    /// loopback — a listen-only peer opens a path there just fine, which is
    /// precisely how the retracted lower-dials/higher-listens shape survived
    /// review in two implementations. Counting the attempt is the only handle a
    /// same-host test has on it.
    pub fn outbound_attempts(&self) -> u32 {
        self.outbound.load(Ordering::Relaxed)
    }

    /// This peer's candidates (§7.1 step 1).
    ///
    /// With a gatherer attached this is `host` → `srflx` [→ `relay`] and can
    /// cross a NAT. **Without one it is `host` only, and that is the honest
    /// ceiling** — such a peer punches on a LAN and in process and nowhere else.
    /// A fabricated `srflx` would be worse than none, because a candidate is a
    /// claim another peer spends its crossing budget on.
    ///
    /// A gatherer that fails yields `None`, which the callers turn into "no live
    /// path" rather than falling back to `host`-only. That is not defeatism: a
    /// peer that could not observe its own mapping has no reflexive candidate,
    /// and for a NAT'd peer that is exactly the relay case (§7.1 step 6).
    async fn local_candidates(&self, peer_id: &str) -> Option<Vec<Candidate>> {
        let Some(gatherer) = self.gatherer.as_ref() else {
            return Some(vec![Candidate::new(
                CANDIDATE_HOST,
                SUBSTRATE_TCP,
                self.local_addr.to_string(),
            )]);
        };
        match gatherer.gather().await {
            Ok(candidates) => Some(candidates),
            Err(e) => {
                tracing::debug!(remote_peer = %peer_id, error = %e, "§7.1 step 1 gather failed; no live path");
                None
            }
        }
    }
}

impl PeerPunchEstablisher {
    /// The **responder** half of §7.1 — answer a `connect-request` from
    /// `peer_id` and punch back.
    ///
    /// §10.3's seam is initiator-only by construction: it fires when *we* want
    /// to reach someone. A peer that also wants to be *reachable* must watch its
    /// rendezvous keys and answer. This is one such watch, for one counterpart.
    ///
    /// **Rung 4 is the loop around this, not a different mechanism** — what it
    /// adds is the policy question this deliberately does not answer: *which*
    /// peers to stay reachable for. `pair` keys are per-counterpart, so the
    /// answer couples to the `maintain-peer` session set, and that is a cohort
    /// decision rather than a Rust one.
    ///
    /// §7.4.1: the returned connection must be **served**, not dialed — the
    /// initiator runs the client half of the handshake.
    pub async fn respond_once(
        &self,
        ctx: EstablishCtx,
        peer_id: &str,
    ) -> Option<(Connection, String)> {
        if ctx.expired() {
            return None;
        }
        let key = self.rendezvous_key_for(peer_id);
        let party = PunchParty::new(key, self.carrier.identity(), SUBSTRATE_TCP, PUNCH_TRUST)
            .with_candidates(self.local_candidates(peer_id).await?);
        let mut io = PeerPunchIo::counted(self.local_addr, self.outbound.clone());
        io.suppress_dial = self.suppress_dial;
        match tokio::time::timeout(ctx.remaining(), punch::respond(&party, &self.carrier, &io))
            .await
        {
            Ok(Ok(found)) => Some(found),
            Ok(Err(e)) => {
                tracing::debug!(remote_peer = %peer_id, error = %e, "§7 respond found no live path");
                None
            }
            Err(_) => None,
        }
    }
}

#[async_trait::async_trait]
impl LiveEstablish for PeerPunchEstablisher {
    async fn establish_live(&self, ctx: EstablishCtx, peer_id: &str) -> Option<Connection> {
        if ctx.expired() {
            tracing::debug!(remote_peer = %peer_id, "§10.3: deadline already passed; not starting a punch");
            return None;
        }

        // §3.2 `pair` mode: the key is derived from the two peer-ids, sorted and
        // separated. Both peers compute it independently from what they already
        // know, which is exactly why `pair` is the mode the seam can use — it
        // needs no out-of-band agreement, unlike `tag` / `secret`.
        let key = self.rendezvous_key_for(peer_id);

        let mut party = PunchParty::new(key, self.carrier.identity(), SUBSTRATE_TCP, PUNCH_TRUST)
            .with_candidates(self.local_candidates(peer_id).await?);
        // §10.3 obligation 4 / §7.2.1: when §4.1's reconnect backoff owns the
        // retry, this punch gets exactly ONE carrier exchange. The crossing
        // budget is deliberately untouched.
        if ctx.caller_owns_retry {
            party = party.caller_owns_retry();
        }

        let mut io = PeerPunchIo::counted(self.local_addr, self.outbound.clone());
        io.suppress_dial = self.suppress_dial;
        // The whole traversal is bounded by the caller's deadline — §10.3's
        // cancellable-seam MUST. Dropping this future cancels every rung of it.
        let attempt = punch::initiate(&party, &self.carrier, &io, peer_id);
        match tokio::time::timeout(ctx.remaining(), attempt).await {
            Ok(Ok(conn)) => {
                tracing::debug!(remote_peer = %peer_id, addr = %conn.remote_addr, "§7 punch established a direct path");
                Some(conn)
            }
            // A §6.3 refusal is not "no live path" in the sense the rest of this
            // arm means — it is a **policy** decision this peer made about a
            // counterpart it could otherwise have reached, and under
            // `PUNCH_TRUST = Require` the only thing it refuses is a peer older
            // than the deposit flip. Left at `debug!` it presents to an operator
            // as an ordinary failed traversal, i.e. as a NAT problem; that
            // mis-read is the recurring cost in this cohort and the flip that
            // raised the policy is what makes it reachable here. Same treatment
            // as the browser leg's establisher, for the same reason.
            //
            // The **outcome** is unchanged and deliberately so: still `None`,
            // still falls through to relay per §7.1 step 6.
            Ok(Err(e @ punch::PunchError::VerificationUnavailable)) => {
                tracing::warn!(
                    remote_peer = %peer_id,
                    error = %e,
                    "§6.3: refusing the punch — the counterpart deposited no signature \
                     container under `Require`. This is a MIXED BUILD (a peer older than \
                     the §6.1 deposit flip), not a NAT or connectivity failure"
                );
                None
            }
            // Every other failure is "no live path", never an error: §7.3.1
            // pin 1 makes a substrate mismatch explicitly not a dispatch error,
            // and §7.1 step 6 makes relay the outcome of every failed punch.
            Ok(Err(e)) => {
                tracing::debug!(remote_peer = %peer_id, error = %e, "§7 punch found no live path; falling through");
                None
            }
            Err(_) => {
                tracing::debug!(remote_peer = %peer_id, "§7 punch exceeded the seam deadline");
                None
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{server, transport, PeerBuilder};
    use entity_capability::GrantEntry;
    use entity_crypto::Keypair;

    /// The node grants exactly the signaling verbs — the seeded-grant shape a
    /// real deployment uses (`signaling_seed_grants`), not a wildcard. A
    /// wildcard would hide the resource-target trap this wiring has to avoid.
    fn signaling_seed() -> Vec<(String, Vec<GrantEntry>)> {
        vec![(
            "default".to_string(),
            entity_signaling::signaling_seed_grants(),
        )]
    }

    /// A real node on a real port, built the way `cmd/entity-signaling-node`
    /// builds one — handler through the public `PeerBuilder::handler()` seam.
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

    /// Two distinct free loopback ports, released together — the punch binds
    /// them itself with `SO_REUSEPORT`.
    ///
    /// **Both probes are held at once, deliberately.** Binding and releasing one
    /// port before asking for the next lets the OS hand out the *same* port
    /// twice, and two peers sharing a local endpoint punch at their own address
    /// and never meet. That produced a ~1-in-6 flake under full-suite
    /// parallelism, presenting as the initiator exhausting its whole deadline —
    /// which reads exactly like a slow carrier and is not one.
    async fn two_free_ports() -> (SocketAddr, SocketAddr) {
        let a = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let b = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        (a.local_addr().unwrap(), b.local_addr().unwrap())
    }

    fn establisher(
        node_peer_id: &str,
        node_port: u16,
        seed: u8,
        local_addr: SocketAddr,
    ) -> (PeerPunchEstablisher, String) {
        let keypair = entity_crypto::IdentityKeypair::Ed25519(Keypair::from_seed([seed; 32]));
        let self_id = keypair.peer_id().to_string();
        let est = PeerPunchEstablisher::new(
            node_peer_id,
            format!("tcp://127.0.0.1:{}", node_port),
            self_id.clone(),
            local_addr,
            keypair,
            Arc::new(transport::TcpConnector),
            entity_hash::HASH_ALGORITHM_SHA256,
        );
        (est, self_id)
    }

    /// **Rungs 0–3, joined.** Two peers, one real signaling node, real TCP on
    /// both legs: they derive the same `pair` key, exchange candidates through
    /// the node, schedule with `fire_at`, and open a direct path with
    /// `SO_REUSEPORT`. The initiator's path arrives through the §10.3 seam.
    ///
    /// **This is loopback.** It proves the coordination and the socket
    /// choreography end to end; it does **not** prove NAT traversal, because
    /// there is no NAT and no mapping to open. Both peers advertise `host`
    /// candidates only — the srflx gatherer is unbuilt.
    ///
    /// Which is exactly why the §7.1 step 4 assertion below is on the *attempt
    /// counter* and not on the path: with no NAT present, a peer that only
    /// listened would still come away with a connection and every other
    /// assertion here would still hold. The counter is the whole of what a
    /// same-host test can say about the MUST.
    #[tokio::test]
    async fn two_peers_punch_through_a_real_node() {
        let (node_id, node_port, node_handle) = start_node(0x51).await;
        let (a_addr, b_addr) = two_free_ports().await;
        assert_ne!(a_addr, b_addr, "two peers must not share a local endpoint");

        let (a, a_id) = establisher(&node_id, node_port, 0x52, a_addr);
        let (b, b_id) = establisher(&node_id, node_port, 0x53, b_addr);

        let deadline = || {
            EstablishCtx::dispatch(web_time::Instant::now() + std::time::Duration::from_secs(20))
        };

        // B watches for A; A reaches for B through the seam.
        let (a_res, b_res) = tokio::join!(
            a.establish_live(deadline(), &b_id),
            b.respond_once(deadline(), &a_id),
        );

        // Report BOTH outcomes on failure: the initiator times out whenever the
        // responder gave up early, so asserting on the initiator alone points
        // the investigation at the wrong half.
        let (a_conn, (_b_conn, seen_initiator)) = match (a_res, b_res) {
            (Some(a), Some(b)) => (a, b),
            (a, b) => panic!(
                "punch did not complete — initiator got a path: {}, responder got a path: {}",
                a.is_some(),
                b.is_some()
            ),
        };

        assert_eq!(
            seen_initiator, a_id,
            "the responder learns which peer it met — the id whose handshake it must SERVE (§7.4.1)"
        );
        assert_eq!(
            a_conn.transport_type, "tcp",
            "§10.3 obligation 1: a punched connection is an ORDINARY transport, \
             indistinguishable to the entity layer from a dialed one"
        );

        // §7.1 step 4 (corrected 2026-08-01): each peer MUST issue an outbound
        // attempt at `fire_at`, whichever end of the crossing it keeps —
        // listening alone opens no NAT mapping. A zero on either side is the
        // non-traversing shape both implementations shipped and neither test
        // suite could see.
        assert!(
            a.outbound_attempts() > 0 && b.outbound_attempts() > 0,
            "both peers MUST fire outbound — initiator dialed {}x, responder {}x",
            a.outbound_attempts(),
            b.outbound_attempts(),
        );

        node_handle.abort();
    }

    /// A peer the carrier can never reach is "no live path", not an error
    /// (§7.1 step 6 / §7.3.1 pin 1). The ladder must be free to fall through to
    /// relay rather than fail the dispatch.
    #[tokio::test]
    async fn an_unreachable_carrier_is_no_live_path_not_an_error() {
        let (a_addr, _) = two_free_ports().await;
        // Point at a port with nothing on it.
        let (a, _) = establisher("NodeThatIsNotThere", 1, 0x54, a_addr);
        let ctx =
            EstablishCtx::dispatch(web_time::Instant::now() + std::time::Duration::from_secs(3));
        assert!(
            a.establish_live(ctx, "SomePeer").await.is_none(),
            "a dead carrier must present as no-live-path, never as a dispatch error"
        );
    }

    /// §10.3: a consultation that arrives past its deadline must not start a
    /// traversal at all — it cannot finish one, and starting spends a carrier
    /// round trip on a third party for nothing.
    #[tokio::test]
    async fn an_expired_deadline_starts_no_traversal() {
        let (a_addr, _) = two_free_ports().await;
        let (a, _) = establisher("NodeThatIsNotThere", 1, 0x55, a_addr);
        let past =
            EstablishCtx::dispatch(web_time::Instant::now() - std::time::Duration::from_secs(1));
        assert!(a.establish_live(past, "SomePeer").await.is_none());
    }
}
