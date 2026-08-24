//! `EXTENSION-NETWORK.md` §6.7.1 + §6.7.3 — the **srflx gatherer**, client half.
//!
//! A peer behind a NAT cannot name its own public address. §6.7.1's mechanism is
//! the whole of the fix: connect to a reflector, and the reflector tells you what
//! source it saw. That observation, typed as a `srflx` candidate (§6.7.3), is the
//! address a counterpart punches at.
//!
//! # This is the client half; the responder is `extensions/network`
//!
//! The §6.7.1 **responder** is built — `NetworkHandler::handle_observe_address`
//! — it is simply not *here*, because reflecting the transport source of an
//! accepted connection is a `system/network` handler operation, not a gatherer
//! concern.
//!
//! An earlier revision of this comment said Rust would not build a responder at
//! all. **That was wrong and is retracted.** The cohort scoped Go as the
//! reflector *for G3*, so the traversal gate would not block on standing two of
//! them up — a sound call about that gate, and not a decision about what this
//! implementation offers. Rust reflects too; a peer that can only ask other
//! peers where it is has a hole where a protocol operation should be.
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
//! [`SrflxGatherer`] gathers from **one** reflector, which is the right shape
//! for producing a candidate: "here is my mapping." It deliberately does not
//! conclude a NAT type, because that is the different claim — "my mapping is
//! stable enough to be worth your crossing budget" — and §6.7.1 forbids resting
//! it on one observation.
//!
//! [`detect_mapping`] is the multi-reflector half that may make that second
//! claim. It is a separate entry point rather than a flag on the gatherer
//! precisely so the two claims cannot be confused at a call site.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use entity_crypto::IdentityKeypair;
use entity_network::nat_type::{classify_mapping, MappingAssessment, MappingClass, Observation};
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
        observe_at(
            &self.reflector_addr,
            self.local_addr,
            &self.keypair,
            self.home_format,
        )
        .await
    }
}

/// One `observe-address` exchange, pinned to `local_addr`.
///
/// Free-standing rather than a method because [`detect_mapping`] consults
/// several reflectors on **one** keypair, and `IdentityKeypair` is deliberately
/// not `Clone` — a private key is not a thing to hand out copies of. Taking it by
/// reference is what lets the multi-reflector probe exist without weakening that.
async fn observe_at(
    reflector_addr: &str,
    local_addr: SocketAddr,
    keypair: &IdentityKeypair,
    home_format: u8,
) -> Result<String, String> {
    let remote_addr: SocketAddr = reflector_addr
        .strip_prefix("tcp://")
        .unwrap_or(reflector_addr)
        .parse()
        .map_err(|_| format!("srflx: bad reflector address {}", reflector_addr))?;

    // §6.7.3: bound to the punch's own endpoint, not an ephemeral one.
    let stream = crate::reuseport::dial_reuseport(local_addr, remote_addr, || {})
        .await
        .map_err(|e| format!("srflx: dial reflector {}: {}", reflector_addr, e))?;

    // The reflector connection must not outlive the observation: the punch
    // re-binds `local_addr`, and although SO_REUSEPORT permits the concurrent
    // bind, leaving a live peer session on the punch's own port invites a
    // stray frame onto a socket the crossing is about to reason about.
    // `RemoteConnection` aborts its reader task on drop, which closes it.
    let conn = remote::perform_connect(PeerPunchIo::wrap(stream), keypair, home_format)
        .await
        .map_err(|e| format!("srflx: handshake with reflector: {}", e))?;

    let uri = format!("/{}/{}", conn.remote_peer_id, HANDLER_PATTERN);
    let params = observe_address_params()?;
    // `resource: None` — same rule the signaling carrier follows: the
    // operation addresses no tree resource, and attaching one reads as
    // "not granted" (403) rather than as the mistake it is.
    let resp = remote::send_execute(
        &conn,
        keypair,
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

impl SrflxGatherer {

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

/// The outcome of a multi-reflector probe: the verdict plus what it cost to get.
#[derive(Debug, Clone)]
pub struct MappingDetection {
    /// The §6.7.1 verdict over whatever observations came back.
    pub assessment: MappingAssessment,
    /// The single socket every reflector was consulted from (§6.7.3).
    pub local_addr: SocketAddr,
    /// Reflectors that answered.
    pub reflector_ok: usize,
    /// Distinct reflectors asked. Duplicates are **not** counted here — see
    /// [`detect_mapping`].
    pub reflector_all: usize,
    /// One line per reflector that failed, and one per rejected duplicate.
    pub errors: Vec<String>,
}

impl MappingDetection {
    /// Whether a **conclusion was reachable** — i.e. two or more reflectors
    /// answered. This is emphatically *not* whether the verdict was favourable:
    /// a symmetric NAT correctly detected is a successful probe reporting a
    /// relay-only peer, and reports `true`.
    pub fn conclusive(&self) -> bool {
        self.reflector_ok >= 2 && self.assessment.class != MappingClass::Unknown
    }
}

/// `EXTENSION-NETWORK.md` §6.7.1 / `EXTENSION-SIGNALING.md` §9.3 — consult
/// several reflectors from one pinned socket and classify the mapping.
///
/// # The trap this signature exists to close `[§6.7.3]`
///
/// **A mapping belongs to a socket.** Consult two reflectors from two sockets
/// and a perfectly punchable cone NAT reports two different ports — the exact
/// signature of the symmetric NAT the probe is looking for. The observations are
/// well-formed, the classifier is correct, and the verdict is confidently wrong;
/// nothing downstream can catch it, because there is nothing wrong with the data.
///
/// So `local_addr` is a **parameter of the detection**, not something each dial
/// picks. Every reflector below is consulted through a [`SrflxGatherer`] built on
/// that one address. An implementation that let the OS choose per dial would look
/// simpler and be silently broken on exactly the NAT type this exists to find.
///
/// # A reflector listed twice is not agreement
///
/// Self-corroboration would satisfy the several-reflectors MUST on paper while
/// proving nothing, so duplicates are rejected rather than counted — recorded in
/// [`MappingDetection::errors`] so a report can say it happened.
///
/// Reflectors are consulted **sequentially**: they share one local port, and
/// serializing keeps each observation attributable to a completed exchange.
pub async fn detect_mapping(
    local_addr: SocketAddr,
    reflectors: &[String],
    keypair: &IdentityKeypair,
    home_format: u8,
    per_reflector_timeout: std::time::Duration,
) -> MappingDetection {
    let mut errors: Vec<String> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    let mut distinct: Vec<String> = Vec::new();

    for r in reflectors {
        let raw = r.trim();
        if raw.is_empty() {
            continue;
        }
        // Normalize before the duplicate check so `tcp://h:p` and `h:p` are the
        // same reflector — otherwise the spelling would buy a fake second vote.
        let key = raw.strip_prefix("tcp://").unwrap_or(raw).to_string();
        if seen.contains(&key) {
            errors.push(format!(
                "reflector {} listed more than once — a reflector cannot corroborate itself \
                 (§6.7.1 requires several reflectors)",
                key
            ));
            continue;
        }
        seen.push(key);
        distinct.push(raw.to_string());
    }

    let mut observations: Vec<Observation> = Vec::new();
    for reflector in &distinct {
        // `local_addr` is the pin — identical for every reflector, by
        // construction rather than by convention.
        let exchange = observe_at(reflector, local_addr, keypair, home_format);
        match tokio::time::timeout(per_reflector_timeout, exchange).await {
            Ok(Ok(observed)) => observations.push(Observation {
                reflector: reflector.clone(),
                observed,
            }),
            Ok(Err(e)) => errors.push(e),
            Err(_) => errors.push(format!(
                "srflx: reflector {} timed out after {:?}",
                reflector, per_reflector_timeout
            )),
        }
    }

    let reflector_ok = observations.len();
    MappingDetection {
        assessment: classify_mapping(&local_addr.to_string(), &observations),
        local_addr,
        reflector_ok,
        reflector_all: distinct.len(),
        errors,
    }
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

    fn probe_keypair() -> IdentityKeypair {
        IdentityKeypair::Ed25519(entity_crypto::Keypair::from_seed([0x62; 32]))
    }

    /// A reflector listed twice must not count as two. Self-corroboration would
    /// satisfy the several-reflectors MUST on paper while proving nothing, so
    /// the duplicate is rejected and *said out loud* rather than silently
    /// deduplicated — a report that quietly dropped it would read as though the
    /// operator had supplied two.
    #[tokio::test]
    async fn a_reflector_listed_twice_is_rejected_not_counted() {
        let d = detect_mapping(
            "127.0.0.1:0".parse().unwrap(),
            &[
                "127.0.0.1:1".to_string(),
                // Same reflector, different spelling: normalizing before the
                // duplicate check is what stops the spelling buying a fake vote.
                "tcp://127.0.0.1:1".to_string(),
            ],
            &probe_keypair(),
            entity_hash::HASH_ALGORITHM_SHA256,
            std::time::Duration::from_millis(500),
        )
        .await;

        assert_eq!(d.reflector_all, 1, "the duplicate must not inflate the count");
        assert!(
            d.errors.iter().any(|e| e.contains("listed more than once")),
            "the rejection must be reported: {:?}",
            d.errors
        );
    }

    /// Nothing answered, so nothing may be concluded — and `conclusive()` must
    /// report that regardless of how many reflectors were *asked*.
    #[tokio::test]
    async fn unreachable_reflectors_reach_no_conclusion() {
        let d = detect_mapping(
            "127.0.0.1:0".parse().unwrap(),
            &["127.0.0.1:1".to_string(), "127.0.0.1:2".to_string()],
            &probe_keypair(),
            entity_hash::HASH_ALGORITHM_SHA256,
            std::time::Duration::from_millis(500),
        )
        .await;

        assert_eq!(d.reflector_all, 2);
        assert_eq!(d.reflector_ok, 0);
        assert!(!d.conclusive(), "no observations cannot be a conclusion");
        assert_eq!(d.assessment.class, MappingClass::Unknown);
        assert_eq!(d.errors.len(), 2, "each failure is reported: {:?}", d.errors);
    }
}
