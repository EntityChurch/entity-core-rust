//! `EXTENSION-NETWORK.md` §6.7.1 + §6.7.3 — the **srflx gatherer**, client half.
//!
//! A peer behind a NAT cannot name its own public address. §6.7.1's mechanism is
//! the whole of the fix: connect to a reflector, and the reflector tells you what
//! source it saw. That observation, typed as a `srflx` candidate (§6.7.3), is the
//! address a counterpart punches at.
//!
//! # This is the client half only, and that is deliberate
//!
//! The §6.7.1 **responder** — reflecting the transport source of an accepted
//! connection — is not here. `entity-core-go` ships it
//! (`ext/network/reachability.go`), live-validated under its `reachability`
//! validator category, and one reflector serves both peers in a two-peer
//! traversal test. Building a second responder here would add a component to the
//! cross-NAT gate without adding anything the gate tests. If Rust later needs to
//! *be* a reflector, that is a `system/network` handler operation and belongs in
//! `extensions/network`, not in this module.
//!
//! # The socket binding is the whole point `[§6.7.3 — MUST]`
//!
//! > *"A peer publishing a `srflx` candidate **MUST** punch from the **same local
//! > endpoint whose mapping was observed** — binding the reflector connection and
//! > the punch socket to the same local port using the platform's address/port-
//! > reuse options. A `srflx` gathered on one ephemeral socket and punched from
//! > another **is not the peer's address**: it describes a hole that will never
//! > open."*
//!
//! So [`SrflxGatherer`] dials the reflector through [`crate::reuseport`], bound to
//! the *same* `local_addr` the punch will later bind. It does not choose that
//! address; the caller supplies it, and the caller is the one that also hands it
//! to `PeerPunchEstablisher`. A gatherer that picked its own socket could not
//! honor the MUST without a channel back to the punch.
//!
//! **We differ from Go here, locally and harmlessly.** Go's `DialReflector` lets
//! the OS choose the port and *reports* the resulting local address, which the
//! punch then re-binds. Ours is told the address up front. Both satisfy the MUST —
//! it constrains the *relationship* between the two sockets, not who picks the
//! port — and taking it as a parameter is what lets a test harness pin the
//! endpoint, which the G2 driver contract needs (`--local-addr`).
//!
//! **The debugging note §6.7.3 attaches to that MUST is worth carrying:** getting
//! this wrong presents as *"the punch didn't land"*, which is indistinguishable
//! from a mistimed simultaneous open — so an implementer can spend a whole
//! debugging budget inside the timing knob, the one thing guaranteed not to be the
//! problem. On a first cross-impl punch failure, bisect against the socket binding
//! before touching `fire_at`.
//!
//! # One reflector is advisory `[§6.7.1]`
//!
//! §6.7.1 is explicit that no security decision may rest on a single observation,
//! and that agreement across *several* reflectors is what makes the fact usable —
//! disagreement being itself the signal, since a mapping that differs per
//! destination is a symmetric NAT where the punch will fail and relay is correct.
//!
//! **This gathers from one reflector**, matching Go's shape, and therefore does
//! **not** implement NAT-type detection. That is a real limit, not an oversight:
//! it is the difference between "here is my mapping" and "my mapping is stable
//! enough to be worth your crossing budget." Nothing here may be used as a
//! security input, and a multi-reflector gatherer is the natural next shape.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use entity_crypto::IdentityKeypair;
use entity_network::{
    observe_address_params, ObserveAddressResult, HANDLER_PATTERN, OP_OBSERVE_ADDRESS,
    TYPE_OBSERVE_ADDRESS_RESULT,
};
use entity_signaling::coordination::{
    Candidate, CANDIDATE_HOST, CANDIDATE_RELAY, CANDIDATE_SRFLX, SUBSTRATE_TCP,
};

use crate::punch_establisher::{CandidateGatherer, PeerPunchIo};
use crate::remote;

/// Gathers `host` → `srflx` [→ `relay`] candidates for one local endpoint.
///
/// Construct it with the **same** `local_addr` given to
/// `PeerPunchEstablisher::new` — see the module doc's §6.7.3 MUST.
pub struct SrflxGatherer {
    reflector_addr: String,
    local_addr: SocketAddr,
    keypair: IdentityKeypair,
    home_format: u8,
    relay: Option<String>,
}

impl SrflxGatherer {
    /// `reflector_addr` is a dialable `host:port` (or `tcp://host:port`) for a
    /// peer offering §6.7.1 `observe-address`.
    ///
    /// **The reflector's peer-id is not a parameter.** It is read from the
    /// completed handshake, exactly as Go does: requiring an operator to
    /// pre-supply it would add a way to get the deployment wrong for no gain,
    /// since the connection has already authenticated the remote identity by the
    /// time we address an operation to it.
    ///
    /// `relay` is an optional configured public relay address, typed through as
    /// the §6.7.3 `relay` candidate. It is operator configuration, not something
    /// discovered here.
    pub fn new(
        reflector_addr: impl Into<String>,
        local_addr: SocketAddr,
        keypair: IdentityKeypair,
        home_format: u8,
        relay: Option<String>,
    ) -> Self {
        Self {
            reflector_addr: reflector_addr.into(),
            local_addr,
            keypair,
            home_format,
            relay,
        }
    }

    /// Ask the reflector what source address it observes for `local_addr`.
    ///
    /// Public because a **driver** wants the bare observation rather than a
    /// candidate set: `cmd/signaling-punch` advertises exactly one `srflx`
    /// candidate by agreement with Go's driver, so that identical candidate
    /// sets go on the wire and a cross-impl divergence reads as a punch result
    /// instead of an advertising difference. [`Self::gather`] remains the
    /// §6.7.3-correct thing for an ordinary peer.
    pub async fn observe(&self) -> Result<String, String> {
        let remote_addr: SocketAddr = self
            .reflector_addr
            .strip_prefix("tcp://")
            .unwrap_or(&self.reflector_addr)
            .parse()
            .map_err(|_| format!("srflx: bad reflector address {}", self.reflector_addr))?;

        // §6.7.3: bound to the punch's own endpoint, not an ephemeral one.
        let stream = crate::reuseport::dial_reuseport(self.local_addr, remote_addr, || {})
            .await
            .map_err(|e| format!("srflx: dial reflector {}: {}", self.reflector_addr, e))?;

        // The reflector connection must not outlive the observation: the punch
        // re-binds `local_addr`, and although SO_REUSEPORT permits the concurrent
        // bind, leaving a live peer session on the punch's own port invites a
        // stray frame onto a socket the crossing is about to reason about.
        // `RemoteConnection` aborts its reader task on drop, which closes it.
        let conn =
            remote::perform_connect(PeerPunchIo::wrap(stream), &self.keypair, self.home_format)
                .await
                .map_err(|e| format!("srflx: handshake with reflector: {}", e))?;

        let uri = format!("/{}/{}", conn.remote_peer_id, HANDLER_PATTERN);
        let params = observe_address_params()?;
        // `resource: None` — same rule the signaling carrier follows: the
        // operation addresses no tree resource, and attaching one reads as
        // "not granted" (403) rather than as the mistake it is.
        let resp = remote::send_execute(
            &conn,
            &self.keypair,
            &uri,
            OP_OBSERVE_ADDRESS,
            &params,
            None,
            None,
            None,
            &std::collections::HashMap::new(),
            None,
        )
        .await
        .map_err(|e| format!("srflx: observe-address: {}", e))?;

        if resp.status != 200 {
            return Err(format!(
                "srflx: reflector returned status {} (want 200; §6.7.4 makes network-reflect a \
                 broad default grant, so a 403 here means the reflector narrowed it)",
                resp.status
            ));
        }
        if resp.result.entity_type != TYPE_OBSERVE_ADDRESS_RESULT {
            return Err(format!(
                "srflx: result type {:?}, want {:?} (§6.7.1)",
                resp.result.entity_type, TYPE_OBSERVE_ADDRESS_RESULT
            ));
        }
        Ok(ObserveAddressResult::from_result_data(&resp.result.data)?.observed_address)
    }

    /// The §6.7.3 candidate set for a peer with no reflector: `host` only
    /// (plus a configured `relay`, if any).
    ///
    /// **Not a degraded srflx** — a peer that cannot observe its mapping has no
    /// reflexive candidate, and for a NAT'd peer that is precisely the relay
    /// case. Fabricating an `srflx` would be worse than omitting one, because a
    /// candidate is a claim the counterpart spends its crossing budget on.
    pub fn host_only(local_addr: SocketAddr, relay: Option<&str>) -> Vec<Candidate> {
        let mut candidates = vec![Candidate::new(
            CANDIDATE_HOST,
            SUBSTRATE_TCP,
            local_addr.to_string(),
        )];
        if let Some(relay) = relay.filter(|r| !r.is_empty()) {
            candidates.push(Candidate::new(CANDIDATE_RELAY, SUBSTRATE_TCP, relay));
        }
        candidates
    }
}

#[async_trait]
impl CandidateGatherer for SrflxGatherer {
    /// §7.1 step 1 — gather.
    ///
    /// A reflector that cannot be reached is an **error**, not a silent fall
    /// back to `host`-only. The §10.3 seam maps it to "no live path" and the
    /// ladder takes the relay route, which is the right answer for a NAT'd peer
    /// with no observable mapping. A caller that genuinely wants host-only
    /// punching says so by configuring no gatherer — see [`Self::host_only`].
    async fn gather(&self) -> Result<Vec<Candidate>, String> {
        let observed = self.observe().await?;
        let mut candidates = Self::host_only(self.local_addr, self.relay.as_deref());
        candidates.push(Candidate::new(CANDIDATE_SRFLX, SUBSTRATE_TCP, observed));
        // §6.7.3 order: host → srflx → relay. `order_for_dialing` is the same
        // rank the punch applies when *choosing* a target, applied here so what
        // goes on the wire is already in preference order.
        Ok(entity_signaling::coordination::order_for_dialing(
            &candidates,
        ))
    }
}

/// Convenience: a gatherer as the `Arc<dyn CandidateGatherer>` the establisher takes.
pub fn arc(gatherer: SrflxGatherer) -> Arc<dyn CandidateGatherer> {
    Arc::new(gatherer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// §6.7.3's ordering, and the relay pass-through.
    #[test]
    fn host_only_is_host_plus_any_configured_relay() {
        let bare = SrflxGatherer::host_only(addr("10.0.0.1:900"), None);
        assert_eq!(bare.len(), 1);
        assert_eq!(bare[0].candidate_type, CANDIDATE_HOST);

        let with_relay = SrflxGatherer::host_only(addr("10.0.0.1:900"), Some("relay.example:443"));
        assert_eq!(
            with_relay
                .iter()
                .map(|c| c.candidate_type.as_str())
                .collect::<Vec<_>>(),
            vec![CANDIDATE_HOST, CANDIDATE_RELAY]
        );

        // An empty relay string is *no* relay, not a candidate with an empty
        // address — a candidate is a claim, and "" is not an address.
        let empty = SrflxGatherer::host_only(addr("10.0.0.1:900"), Some(""));
        assert_eq!(empty.len(), 1);
    }

    /// **§6.7.3's MUST, asserted where it is observable.** The reflector dial
    /// leaves from the endpoint the punch will bind — so the mapping a real
    /// reflector observes belongs to that socket and the `srflx` we advertise is
    /// an address that exists.
    ///
    /// This stands in for a reflector with a bare `TcpListener` and looks at one
    /// thing: the source address of the connection that arrives. That is
    /// precisely what a conformant responder reflects (§6.7.1 MUST 1), and on
    /// loopback it equals `local_addr` exactly, there being no NAT in between.
    /// The gather then fails at the handshake, which is fine — the dial is the
    /// whole subject.
    ///
    /// A plain `TcpStream::connect` here would source from an OS-assigned
    /// ephemeral port and this assertion is what catches it. That failure
    /// otherwise presents as *"the punch didn't land"* — indistinguishable from
    /// a mistimed `fire_at`, which is the debugging trap §6.7.3 pins in advance.
    #[tokio::test]
    async fn the_reflector_dial_leaves_from_the_punch_socket() {
        let reflector = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reflector_addr = reflector.local_addr().unwrap();

        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = probe.local_addr().unwrap();
        drop(probe);

        let observed = tokio::spawn(async move {
            let (stream, source) = reflector.accept().await.expect("reflector accepts");
            drop(stream);
            source
        });

        let keypair = IdentityKeypair::Ed25519(entity_crypto::Keypair::from_seed([0x62; 32]));
        let g = SrflxGatherer::new(
            reflector_addr.to_string(),
            local,
            keypair,
            entity_hash::HASH_ALGORITHM_SHA256,
            None,
        );
        // Expected to fail: our stand-in reflector speaks no protocol. The dial
        // has already happened by then.
        let _ = g.gather().await;

        assert_eq!(
            observed.await.unwrap(),
            local,
            "§6.7.3: the reflector MUST observe the mapping of the socket the punch \
             fires from — a srflx gathered on any other socket describes a hole that \
             never opens"
        );
    }

    /// A reflector we cannot reach yields an error, never a fabricated `srflx`.
    ///
    /// The §10.3 seam turns that into the relay fallback; a made-up mapping
    /// would instead spend a counterpart's whole crossing budget on an address
    /// that was never real.
    #[tokio::test]
    async fn an_unreachable_reflector_gathers_nothing() {
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = probe.local_addr().unwrap();
        drop(probe);

        let keypair = IdentityKeypair::Ed25519(entity_crypto::Keypair::from_seed([0x61; 32]));
        let g = SrflxGatherer::new(
            "127.0.0.1:1",
            local,
            keypair,
            entity_hash::HASH_ALGORITHM_SHA256,
            None,
        );
        let err = g.gather().await.expect_err("no reflector is listening");
        assert!(err.starts_with("srflx: dial reflector"), "got: {}", err);
    }
}
