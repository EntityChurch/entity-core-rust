//! `EXTENSION-SIGNALING` §7 — the punch choreography.
//!
//! This is §7.1 steps 1–4 and nothing else: gather (supplied by the caller),
//! exchange over the carrier, measure and schedule, simultaneous open. It is the
//! policy that registers behind `EXTENSION-NETWORK.md` §10.3, and NETWORK owns
//! the seam and the resulting transport's obligations — pooling, §5 keepalive,
//! the handshake.
//!
//! # Nothing here names a socket
//!
//! The choreography is **substrate-agnostic** (§7.3.1: "the coordination layer
//! above — carrier, rendezvous key, candidate exchange, `fire_at`, roles — is
//! substrate-agnostic and shared by all three"). So the transport arrives
//! through [`crate::punch::PunchIo`] and the carrier through [`crate::punch::Carrier`], and this module
//! compiles without `tokio`, without sockets, and on wasm32. A browser peer
//! driving a WebRTC data channel plugs into the same two traits a native peer
//! drives TCP through.
//!
//! Time arrives the same way, for the same reason `SignalingCore` takes `now_ms`
//! as a parameter rather than owning a clock: it keeps the `fire_at` scheduling
//! exactly testable, which matters more here than anywhere else in the crate
//! because §7.2's failure mode is invisible to a same-host test.
//!
//! # The two retry counters `[§7.2.1 — MUST]`
//!
//! A punch has two nested retry layers and **they are not interchangeable**.
//! They are separate fields here, named for the layer they govern, because
//! collapsing them onto one word is what broke a working punch in another
//! implementation:
//!
//! | Layer | One attempt is | Who pays | Field |
//! |---|---|---|---|
//! | **Crossing** | one more dial at the counterpart's known candidate | only the two peers | [`crate::punch::PunchParty::crossing_retries`] |
//! | **Exchange** | fresh nonce + fresh gather + fresh carrier round trip | **third parties** — reflector, carrier | [`crate::punch::PunchParty::exchange_attempts`] |
//!
//! The §7.2.1 MUST binds the **exchange** layer only. The MUST NOT forbids
//! cutting the crossing count to satisfy it. *The distinguishing question: does
//! one more attempt send a packet to anyone other than the target peer?*
//!
//! **This binds Rust where it does not bind Go.** Go's `Establish` runs one
//! exchange by construction, so nesting is structurally impossible there. This
//! implementation loops the exchange, so a §4.1-driven consultation MUST arrive
//! with [`crate::punch::PunchParty::exchange_attempts`] set to 1 — see
//! `EstablishCtx::caller_owns_retry` on the `core/peer` side.

use async_trait::async_trait;

use crate::coordination::{
    self, punch_delay, Candidate, CollectedCoordination, CollectedMessage, ConnectRequest,
    ConnectResponse, Nonce, PunchSync, VerificationPolicy, CANDIDATE_SRFLX,
};
use crate::core::RendezvousKey;
use crate::SignalingError;

// ---------------------------------------------------------------------------
// Defaults — all §7.2 "implementation-defined", none of them interoperable
// ---------------------------------------------------------------------------

/// §7.2.1 crossing retries. Local; costs nobody but the two peers.
///
/// Several dials is the *point*: two peers fire at a scheduled instant across an
/// unsynchronized network, so the first dial landing outside the counterpart's
/// window is the expected case, not the failure case.
pub const DEFAULT_CROSSING_RETRIES: u32 = 3;

/// §7.2 exchange attempts, each with a fresh nonce. Costs the reflector and the
/// carrier — **third-party peers**, which is why the budget exists.
pub const DEFAULT_EXCHANGE_ATTEMPTS: u32 = 3;

/// Carrier poll cadence while awaiting a counterpart's blob. Matches the
/// cohort's 200 ms (Go and Python both poll at this rate).
pub const DEFAULT_POLL_MS: u64 = 200;

/// Bound on one simultaneous-open dial.
pub const DEFAULT_DIAL_TIMEOUT_MS: u64 = 2_000;

/// Bound on one whole carrier exchange (offer → matched collect).
pub const DEFAULT_EXCHANGE_TIMEOUT_MS: u64 = 15_000;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Everything a punch can fail with.
///
/// **Every variant means the same thing to the §10.3 seam: no live path.** The
/// seam maps all of them to `None` and the ladder takes the relay fallback
/// (§7.1 step 6, §7.3.1 pin 1 — *"an implementation MUST NOT treat a substrate
/// mismatch as a dispatch error"*). They are distinguished here for diagnosis,
/// never for control flow above the seam.
#[derive(Debug, thiserror::Error)]
pub enum PunchError {
    #[error("carrier refused or failed: {0}")]
    Carrier(String),
    #[error("no counterpart answered within the exchange window")]
    ExchangeTimeout,
    #[error("counterpart advertised no candidate on a substrate we share")]
    NoSharedSubstrate,
    #[error("direct path did not open after {attempts} crossing retries")]
    CrossingFailed { attempts: u32 },
    #[error("deadline passed before the punch could start")]
    DeadlineExceeded,
    /// `Require` was set and the counterpart's message arrived **without** a
    /// §6.3 container — a peer that has not flipped its deposit path yet.
    ///
    /// Raised only for a message that was otherwise ours (nonce echo matched,
    /// or a request we would have answered): an unverified stranger's blob in a
    /// shared `lobby` bucket is skipped under §6.4 like any other, and must not
    /// be able to end someone else's exchange.
    #[error("§6.3 verification is required but the counterpart's message carried no container")]
    VerificationUnavailable,
    #[error(transparent)]
    Coding(#[from] SignalingError),
}

impl PunchError {
    /// Whether another **exchange attempt** could plausibly succeed.
    ///
    /// The distinction is about who pays: a retry spends a fresh nonce at the
    /// carrier and a fresh gather at a reflector, both third-party peers
    /// (§7.2.1). A counterpart that shares no substrate with us will not have
    /// grown one by the next round trip, and a message we cannot encode will
    /// not encode differently — retrying either is pure load on someone else's
    /// node for a guaranteed second failure.
    ///
    /// Crossing failures *are* transient at this layer: the crossing itself has
    /// already spent its own local budget, and a fresh exchange re-gathers
    /// candidates, which is exactly the thing that might differ.
    pub fn is_transient(&self) -> bool {
        match self {
            PunchError::ExchangeTimeout
            | PunchError::CrossingFailed { .. }
            | PunchError::Carrier(_) => true,
            // A counterpart that deposits bare will still deposit bare on the
            // next attempt. Retrying spends a fresh nonce at someone else's
            // node for a guaranteed second refusal — §7.2.1's own rationale.
            PunchError::NoSharedSubstrate
            | PunchError::DeadlineExceeded
            | PunchError::VerificationUnavailable
            | PunchError::Coding(_) => false,
        }
    }
}

// ---------------------------------------------------------------------------
// The two injected surfaces
// ---------------------------------------------------------------------------

/// The punch's view of the rendezvous service (§4): deposit an opaque blob,
/// read a bucket back classified.
///
/// The live [`SignalingClient`](crate::SignalingClient) satisfies this, and so
/// does an in-memory stub — the node is "an opaque blob store" (§4.4), so a
/// minimal conforming store is a faithful stand-in rather than a mock.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait Carrier: Send + Sync {
    /// Deposit one coordination entity at `key`, framed per §6.2.
    async fn offer(&self, key: &RendezvousKey, blob: Vec<u8>) -> Result<(), PunchError>;
    /// Read the bucket at `key`, oldest first (§5 pin 4).
    async fn collect(&self, key: &RendezvousKey) -> Result<Vec<Vec<u8>>, PunchError>;
}

/// The substrate: how this peer opens a direct path, and what time it is.
///
/// `dial` and `accept` both operate on **the shared local endpoint whose mapping
/// the reflector observed** (§7.3 / `EXTENSION-NETWORK.md` §6.7.3). That
/// endpoint is the implementor's to hold — this module never sees an address of
/// its own, only the counterpart's.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait PunchIo: Send + Sync {
    /// The established direct path. Opaque here; `core/peer` resolves it to a
    /// transport connection.
    type Conn: Send;

    /// Open a path to `target` from the shared local endpoint, giving up after
    /// `timeout_ms`.
    async fn dial(&self, target: &str, timeout_ms: u64) -> Result<Self::Conn, String>;

    /// Accept an inbound path on the shared local endpoint within `window_ms`.
    async fn accept(&self, window_ms: u64) -> Result<Self::Conn, String>;

    /// Sleep `ms`. The punch schedules against a **delay**, never a wall clock
    /// (§7.2), so this is the only timing primitive it needs.
    async fn sleep_ms(&self, ms: u64);

    /// Milliseconds on any monotonic scale. Used solely to measure the carrier
    /// round trip for `fire_at`; never placed on the wire.
    fn now_ms(&self) -> u64;
}

// ---------------------------------------------------------------------------
// Who dials, who accepts
// ---------------------------------------------------------------------------

/// Which of this peer's two racing sockets survives the crossing.
///
/// **Not who dials.** Both peers always dial — see [`crossing_role`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossingRole {
    /// Keep the socket **we** dialed out on; drop anything we accepted.
    KeepDialed,
    /// Keep the socket we **accepted**; drop the one we dialed.
    KeepAccepted,
}

/// **The socket tiebreak: whose dialed connection survives.** Lower peer-id
/// keeps its *dialed* socket, higher keeps its *accepted* one.
///
/// # This decides which socket survives, never whether to dial `[§7.1 step 4 — MUST]`
///
/// Three layers meet at the crossing and collapsing any two of them is a bug
/// that no loopback test can see. They are:
///
/// | Layer | Rule | Decided by |
/// |---|---|---|
/// | Hole-opening | **both** peers fire outbound at `fire_at` | *nothing* — always both |
/// | Socket selection | one of the racing sockets survives | **this function** (local) |
/// | Handshake role | the initiator speaks HELLO; the responder serves | §7.4.1 (signaling role) |
///
/// §7.1 step 4, as corrected 2026-08-01: *"Each peer **MUST** issue an outbound
/// connection attempt at `fire_at`; **listening alone opens no hole**, because
/// only an outbound packet creates the local NAT mapping. A peer that merely
/// accepts (TCP-passive) never opens its own hole, so the counterpart's SYN
/// reaches a closed NAT."* An earlier revision of this file made the lower id
/// dial and the higher one *only* listen. That is non-traversing by
/// construction and it passed every test here, because loopback has no mapping
/// to open — **do not reintroduce it.**
///
/// What survives of the tiebreak is the narrower question it was always really
/// answering. Because both peers dial and both listen, **two** connections can
/// form — each side's dial landing on the other's listener — and the peers must
/// keep the same one or they hold opposite ends of different sockets. So the
/// two answers here are complementary by construction: the lower id's *dialed*
/// socket and the higher id's *accepted* socket are **the two ends of one TCP
/// connection**. Go resolves it the same way (`ext/signaling/punch.go`, `fire`),
/// which is what makes a Rust↔Go punch converge; the compare itself is local and
/// carries no wire bytes.
///
/// Independent of §7.4.1's *handshake* role, which follows the signaling role
/// regardless of which end dialed the socket that won.
pub fn crossing_role(self_peer_id: &str, counterpart_peer_id: &str) -> CrossingRole {
    if self_peer_id < counterpart_peer_id {
        CrossingRole::KeepDialed
    } else {
        CrossingRole::KeepAccepted
    }
}

/// Pick the address to punch toward from a counterpart's candidate list.
///
/// Prefers `srflx` — the NAT mapping, which is the whole point of the punch —
/// and otherwise takes the best remaining candidate in §6.7.3 dial order
/// (`host` → `srflx` → `relay`). `None` means no shared substrate.
fn dial_target(candidates: &[Candidate], substrate: &str) -> Option<String> {
    let ordered = coordination::order_for_dialing(candidates);
    let usable: Vec<&Candidate> = ordered
        .iter()
        .filter(|c| c.substrate == substrate)
        .collect();
    usable
        .iter()
        .find(|c| c.candidate_type == CANDIDATE_SRFLX)
        .or_else(|| usable.first())
        .map(|c| c.address.clone())
}

// ---------------------------------------------------------------------------
// One side's inputs
// ---------------------------------------------------------------------------

/// One peer's configuration for a punch.
pub struct PunchParty {
    /// The rendezvous key both peers derived (§3).
    pub key: RendezvousKey,
    /// The identity every deposit is sealed under (§6.3) — and the **only**
    /// source of this peer's own id.
    ///
    /// `entity-core-go` reached this shape first and the argument is theirs:
    /// a party that took an id *and* a signing key has two sources that can
    /// disagree, and the disagreement is invisible from either side alone —
    /// our own §6.5 party has to refuse the skew at runtime because it takes
    /// both. Deleting the second source makes it unrepresentable instead.
    signer: std::sync::Arc<entity_crypto::IdentityKeypair>,
    /// Derived from [`Self::signer`] once, at construction — used to skip our
    /// own bucket entries (§6.4) and to resolve the crossing tiebreak.
    self_id: String,
    /// This peer's gathered candidates (§7.1 step 1), bound to the shared local
    /// endpoint [`PunchIo`] dials from.
    pub local_candidates: Vec<Candidate>,
    /// Which §7.3 substrate this peer can actually punch on.
    pub substrate: String,
    /// §7.2.1 **crossing** retries — local, MUST NOT be cut to satisfy the
    /// exchange budget.
    pub crossing_retries: u32,
    /// §7.2 **exchange** attempts — third-party cost. MUST be 1 when the caller
    /// owns the retry (§10.3 obligation 4).
    pub exchange_attempts: u32,
    pub poll_ms: u64,
    pub dial_timeout_ms: u64,
    pub exchange_timeout_ms: u64,
    /// Whether a collected message must have passed §6.3 before this peer acts
    /// on it.
    ///
    /// Named at every call site rather than defaulted — see
    /// [`VerificationPolicy`]. Today this path deposits **bare**, so a peer that
    /// set `Require` on both sides of a Rust-to-Rust punch would refuse itself;
    /// the deposit flip for §6.1 is a cohort window that has not opened.
    pub trust: VerificationPolicy,
}

impl PunchParty {
    /// A party with the §7.2 defaults — a **standalone** consultation, which
    /// owns its own exchange budget.
    ///
    /// `trust` is a required argument and has no default, for the reason
    /// [`VerificationPolicy`] has none: a permissive posture chosen by omission
    /// is one nobody reviews.
    pub fn new(
        key: RendezvousKey,
        signer: std::sync::Arc<entity_crypto::IdentityKeypair>,
        substrate: impl Into<String>,
        trust: VerificationPolicy,
    ) -> Self {
        Self {
            self_id: signer.peer_id().to_string(),
            key,
            signer,
            local_candidates: Vec::new(),
            substrate: substrate.into(),
            crossing_retries: DEFAULT_CROSSING_RETRIES,
            exchange_attempts: DEFAULT_EXCHANGE_ATTEMPTS,
            poll_ms: DEFAULT_POLL_MS,
            dial_timeout_ms: DEFAULT_DIAL_TIMEOUT_MS,
            exchange_timeout_ms: DEFAULT_EXCHANGE_TIMEOUT_MS,
            trust,
        }
    }

    pub fn with_candidates(mut self, candidates: Vec<Candidate>) -> Self {
        self.local_candidates = candidates;
        self
    }

    /// This peer's canonical id — **derived from the signing key**, never
    /// supplied. What a counterpart reads out of our containers and what we
    /// sort by are the same string by construction.
    pub fn self_id(&self) -> &str {
        &self.self_id
    }

    /// Cap this punch at **one** carrier exchange — §10.3 obligation 4 / §7.2.1.
    ///
    /// For a consultation driven by a §4.1 reconnection continuation, where
    /// §4.1's backoff already owns re-scheduling. **Touches only the exchange
    /// counter**: the crossing count is untouched on purpose, and reducing it
    /// here would be the exact bug §7.2.1's MUST NOT names.
    pub fn caller_owns_retry(mut self) -> Self {
        self.exchange_attempts = 1;
        self
    }
}

// ---------------------------------------------------------------------------
// §7.1 — the flow
// ---------------------------------------------------------------------------

/// The initiator's flow (§7.1 steps 2–4): offer `connect-request`, await the
/// matching `connect-response`, schedule with `punch-sync`, cross.
///
/// `expected_peer_id` is the peer we intend to reach. A shared `tag` / `lobby`
/// bucket may hold anyone's answer, so a response from a different peer is
/// skipped rather than accepted (§6.4 correlate-by-identity).
///
/// The whole exchange retries up to [`PunchParty::exchange_attempts`] times with
/// a **fresh nonce** each time — that is what makes it an *exchange* attempt and
/// why the budget applies (§7.2.1).
pub async fn initiate<C: Carrier, I: PunchIo>(
    party: &PunchParty,
    carrier: &C,
    io: &I,
    expected_peer_id: &str,
) -> Result<I::Conn, PunchError> {
    let mut last = PunchError::ExchangeTimeout;
    for _ in 0..party.exchange_attempts.max(1) {
        match initiate_once(party, carrier, io, expected_peer_id).await {
            Ok(conn) => return Ok(conn),
            // **Only retry what a retry could fix.** Another exchange costs a
            // fresh nonce the carrier must store and a fresh gather against a
            // reflector — third-party load, which §7.2.1's budget exists to
            // bound. Spending it on a failure that is not transient is the
            // budget's own rationale turned inside out.
            Err(e) if e.is_transient() => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

/// Seal and deposit one §6.1 coordination entity — **every deposit, no
/// exceptions**.
///
/// §6.1 needs the container more than §6.5 did, for a reason §6.5 does not
/// have: `connect-request` and `connect-response` carry `initiator` /
/// `responder` as wire fields, so an unverified deposit lets anyone assert
/// either id — and then `await_response`'s expected-peer filter is comparing
/// against a string the attacker wrote. §6.5's payloads name nobody, so there
/// was nothing there to forge. (`entity-core-go`'s framing, and it is the right
/// one.)
///
/// The signature binds `party.key`, so this deposit verifies in this bucket and
/// in no other one it could be lifted into.
async fn deposit<C: Carrier>(
    party: &PunchParty,
    carrier: &C,
    entity: &entity_entity::Entity,
) -> Result<(), PunchError> {
    let blob = crate::envelope::seal(entity, &party.key, &party.signer)?;
    carrier.offer(&party.key, blob).await
}

async fn initiate_once<C: Carrier, I: PunchIo>(
    party: &PunchParty,
    carrier: &C,
    io: &I,
    expected_peer_id: &str,
) -> Result<I::Conn, PunchError> {
    // A fresh nonce per exchange attempt (§7.2) — this is precisely what makes
    // the retry cost the carrier something, and therefore what the budget is for.
    let nonce = Nonce::generate();

    let request = ConnectRequest {
        initiator: party.self_id.clone(),
        candidates: party.local_candidates.clone(),
        nonce: nonce.clone(),
    };
    // Round-trip timing starts at the offer and ends at the collect that returns
    // the response — §7.2: "the only latency estimate either peer has, since by
    // construction neither can yet reach the other directly."
    let sent_at = io.now_ms();
    deposit(party, carrier, &request.to_entity()?).await?;

    let response = await_response(party, carrier, io, &nonce, expected_peer_id).await?;
    let rtt_ms = io.now_ms().saturating_sub(sent_at);

    // §7.2: d = max(rtt, floor), carried as a DELAY from receipt. The initiator
    // fires `d` after *sending* the sync; the responder fires `d` after
    // *receiving* it, so the two firings cross near the middle.
    let d = punch_delay(rtt_ms);
    let sync = PunchSync {
        nonce: nonce.clone(),
        fire_at: d,
    };
    deposit(party, carrier, &sync.to_entity()?).await?;

    let target =
        dial_target(&response.candidates, &party.substrate).ok_or(PunchError::NoSharedSubstrate)?;
    io.sleep_ms(d).await;
    cross(party, io, &target, &response.responder).await
}

/// The responder's flow (§7.1): answer a `connect-request`, await its
/// `punch-sync`, cross. Returns the path and the initiator's peer-id.
///
/// The caller **serves** the resulting connection rather than dialing the
/// handshake over it: §7.4.1 pins the client half to the initiator.
pub async fn respond<C: Carrier, I: PunchIo>(
    party: &PunchParty,
    carrier: &C,
    io: &I,
) -> Result<(I::Conn, String), PunchError> {
    let request = await_request(party, carrier, io).await?;

    let response = ConnectResponse {
        responder: party.self_id.clone(),
        candidates: party.local_candidates.clone(),
        nonce: request.nonce.clone(),
    };
    deposit(party, carrier, &response.to_entity()?).await?;

    // The responder fires `d` after RECEIVING the sync (§7.2) — so the sleep
    // starts here, at the moment the poll returned it, not at any shared instant.
    let sync = await_sync(party, carrier, io, &request.nonce).await?;
    let target =
        dial_target(&request.candidates, &party.substrate).ok_or(PunchError::NoSharedSubstrate)?;
    io.sleep_ms(sync.fire_at).await;

    let conn = cross(party, io, &target, &request.initiator).await?;
    Ok((conn, request.initiator))
}

/// §7.1 step 4 — the crossing. **Both sides dial; both sides listen.**
///
/// # The outbound attempt is not optional and not conditional `[§7.1 step 4 — MUST]`
///
/// Only an outbound packet creates a local NAT mapping. A peer that merely
/// accepts never opens its own hole, so the counterpart's SYN arrives at a
/// closed NAT and the punch cannot traverse — while passing every loopback test,
/// because loopback has no mapping to open. So the dial loop below runs
/// **unconditionally on both sides**, and it is polled *first* on every wakeup:
/// returning on an accept that landed before we had issued our own outbound
/// would be the same bug wearing a race condition.
///
/// The listener runs concurrently because pure both-sides-dial completes only in
/// the narrow instant both sockets sit in `SYN_SENT` together; outside it each
/// dial is refused. That is a substrate hardening, not a substitute for firing.
///
/// # Which of the two sockets survives — and why waiting for a preferred one is wrong
///
/// **Take whichever materializes; [`crossing_role`] breaks a tie only when both
/// do.** The reason the preference must *not* be authoritative is the geometry
/// of the crossing: both peers punch from a fixed local endpoint to the
/// counterpart's fixed advertised endpoint, so there is exactly **one** possible
/// 4-tuple between them and therefore exactly **one** connection. Which local
/// socket ends up holding our end of it — the dialing one, via TCP simultaneous
/// open, or the listening one, via an ordinary accept — is the kernel's call and
/// the two peers can resolve it differently *on the same connection*. Both
/// answers are correct.
///
/// So a peer that insists on its preferred socket waits out a window for a
/// second connection that cannot exist. Concretely, on loopback both dials fuse
/// by simultaneous open, no accept ever fires, and the side that wanted its
/// accepted socket burned the whole crossing budget — 1.0 s to 7.7 s on
/// `two_peers_punch_through_a_real_node` — before falling back to the socket it
/// already had.
///
/// The tiebreak still earns its place where two connections genuinely *can*
/// form: when a counterpart's dial leaves from an endpoint other than the one it
/// advertised, the two 4-tuples differ and both may land. Then both peers see
/// both sockets, and the peer-id compare picks the same one on each side.
async fn cross<I: PunchIo>(
    party: &PunchParty,
    io: &I,
    target: &str,
    counterpart_peer_id: &str,
) -> Result<I::Conn, PunchError> {
    let retries = party.crossing_retries.max(1);
    let window = (retries as u64) * (party.dial_timeout_ms + party.poll_ms);
    let keep = crossing_role(&party.self_id, counterpart_peer_id);

    let mut dialing = core::pin::pin!(dial_loop(party, io, target, retries));
    let mut accepting = core::pin::pin!(async { io.accept(window).await.map_err(|_| ()) });
    let mut dialed: Option<Result<I::Conn, ()>> = None;
    let mut accepted: Option<Result<I::Conn, ()>> = None;

    // Hand-rolled rather than `futures::select` because this module carries no
    // futures dependency and must build for wasm32 — see the module doc.
    core::future::poll_fn(move |cx| {
        use core::future::Future;
        use core::task::Poll;

        // **Dial first, always.** This is the ordering that makes the MUST
        // above true even when the accept is ready on the very first poll: the
        // outbound is issued before any path out of this function exists.
        if dialed.is_none() {
            if let Poll::Ready(r) = dialing.as_mut().poll(cx) {
                dialed = Some(r);
            }
        }
        if accepted.is_none() {
            if let Poll::Ready(r) = accepting.as_mut().poll(cx) {
                accepted = Some(r);
            }
        }

        let (preferred, other) = match keep {
            CrossingRole::KeepDialed => (&mut dialed, &mut accepted),
            CrossingRole::KeepAccepted => (&mut accepted, &mut dialed),
        };
        // Checking the tiebreak's side first is what makes it decide the case
        // it exists for — both sockets materializing in the same wakeup. When
        // only this one has, it is simply the one we have.
        if matches!(preferred, Some(Ok(_))) {
            // Any loser is dropped with this future.
            return Poll::Ready(Ok(preferred.take().unwrap().unwrap()));
        }
        // The other socket, taken as soon as it appears rather than held while
        // we wait out a preference: one socket is one connection, and the
        // counterpart is entitled to hold that same connection through *its*
        // other socket. Waiting would be waiting for a second connection the
        // 4-tuple cannot accommodate.
        if matches!(other, Some(Ok(_))) {
            return Poll::Ready(Ok(other.take().unwrap().unwrap()));
        }
        if preferred.is_some() && other.is_some() {
            return Poll::Ready(Err(PunchError::CrossingFailed { attempts: retries }));
        }
        Poll::Pending
    })
    .await
}

/// The §7.2.1 **crossing** retry: dial the counterpart's candidate from the
/// shared local endpoint until it lands or the local budget is spent.
///
/// A refused dial is the expected case, not the failure case — the counterpart's
/// listener may simply not be up yet. Every attempt goes to the target peer's
/// own socket and to nobody else, which is exactly what keeps this budget out of
/// the third-party exchange budget.
async fn dial_loop<I: PunchIo>(
    party: &PunchParty,
    io: &I,
    target: &str,
    retries: u32,
) -> Result<I::Conn, ()> {
    for attempt in 0..retries {
        if let Ok(conn) = io.dial(target, party.dial_timeout_ms).await {
            return Ok(conn);
        }
        if attempt + 1 < retries {
            io.sleep_ms(party.poll_ms).await;
        }
    }
    Err(())
}

// ---------------------------------------------------------------------------
// Carrier polling — every read applies the §6.4 filters
// ---------------------------------------------------------------------------

async fn poll_bucket<C: Carrier, I: PunchIo>(
    party: &PunchParty,
    carrier: &C,
    io: &I,
    mut pick: impl FnMut(&[CollectedCoordination]) -> Option<PolledMessage>,
) -> Result<PolledMessage, PunchError> {
    let deadline = io.now_ms() + party.exchange_timeout_ms;
    loop {
        let blobs = carrier.collect(&party.key).await?;
        // §6.3-aware: a sealed deposit is unwrapped and verified against the
        // bucket it came from, a bare one is read as the §6.2 framing it is,
        // and a container that failed to verify is skipped **without** falling
        // back to its inner entity. See `coordination::classify_collected`.
        let messages: Vec<CollectedCoordination> = blobs
            .iter()
            .map(|b| coordination::classify_collected(b, &party.key))
            .collect();
        if let Some(found) = pick(&messages) {
            return Ok(found);
        }
        if io.now_ms() >= deadline {
            return Err(PunchError::ExchangeTimeout);
        }
        io.sleep_ms(party.poll_ms).await;
    }
}

enum PolledMessage {
    Response(Box<ConnectResponse>),
    Request(Box<ConnectRequest>),
    Sync(Box<PunchSync>),
    /// The message we were waiting for arrived, and it was **not** sealed while
    /// this party demands §6.3.
    ///
    /// Carried out of the poll rather than refused inside the `pick` closure so
    /// the refusal is loud and immediate: silently skipping it would leave the
    /// caller polling a bucket that already holds its answer, and reporting the
    /// eventual `ExchangeTimeout` as "nobody replied" — a diagnosis one word
    /// away from the truth and days away from the cause.
    Unverified,
}

async fn await_response<C: Carrier, I: PunchIo>(
    party: &PunchParty,
    carrier: &C,
    io: &I,
    nonce: &Nonce,
    expected_peer_id: &str,
) -> Result<ConnectResponse, PunchError> {
    let self_id = party.self_id.clone();
    let expected = expected_peer_id.to_string();
    let trust = party.trust;
    let found = poll_bucket(party, carrier, io, move |msgs| {
        coordination::find_response(msgs, nonce, &self_id)
            // A different peer answering our shared-bucket request is not our
            // answer — keep waiting for the one we intend to reach (§6.4).
            //
            // Against the **verified** signer when the message was sealed: the
            // whole point of this filter is that we reach the peer we meant to,
            // and pre-container it was comparing `responder` — a string the
            // answering peer chose for itself.
            .filter(|(r, signer)| {
                let who = signer.as_ref().map(|s| s.peer_id()).unwrap_or(&r.responder);
                expected.is_empty() || who == expected
            })
            // Policy applies **after** the filters, so only a message that was
            // ours to act on can raise it.
            .map(|(r, signer)| match (trust, signer) {
                (VerificationPolicy::Require, None) => PolledMessage::Unverified,
                _ => PolledMessage::Response(Box::new(r)),
            })
    })
    .await?;
    match found {
        PolledMessage::Response(r) => Ok(*r),
        PolledMessage::Unverified => Err(PunchError::VerificationUnavailable),
        _ => Err(PunchError::ExchangeTimeout),
    }
}

async fn await_request<C: Carrier, I: PunchIo>(
    party: &PunchParty,
    carrier: &C,
    io: &I,
) -> Result<ConnectRequest, PunchError> {
    let self_id = party.self_id.clone();
    let trust = party.trust;
    let found = poll_bucket(party, carrier, io, move |msgs| {
        coordination::find_request(msgs, &self_id).map(|(r, signer)| match (trust, signer) {
            (VerificationPolicy::Require, None) => PolledMessage::Unverified,
            _ => PolledMessage::Request(Box::new(r)),
        })
    })
    .await?;
    match found {
        PolledMessage::Request(r) => Ok(*r),
        PolledMessage::Unverified => Err(PunchError::VerificationUnavailable),
        _ => Err(PunchError::ExchangeTimeout),
    }
}

async fn await_sync<C: Carrier, I: PunchIo>(
    party: &PunchParty,
    carrier: &C,
    io: &I,
    nonce: &Nonce,
) -> Result<PunchSync, PunchError> {
    let want = nonce.clone();
    let trust = party.trust;
    let found = poll_bucket(party, carrier, io, move |msgs| {
        msgs.iter()
            .find_map(|c| match &c.msg {
                // `punch-sync` names no author, so the nonce echo is the whole
                // of the correlation and the signer — when there is one — is
                // the only identity in play (§6.3 step 3 has nothing to
                // compare). It still governs *when we fire*, so an unverified
                // one is refused under `Require` exactly like the others.
                CollectedMessage::Sync(s) if s.nonce == want => Some((s.clone(), c.signer.clone())),
                _ => None,
            })
            .map(|(s, signer)| match (trust, signer) {
                (VerificationPolicy::Require, None) => PolledMessage::Unverified,
                _ => PolledMessage::Sync(Box::new(s)),
            })
    })
    .await?;
    match found {
        PolledMessage::Sync(s) => Ok(*s),
        PolledMessage::Unverified => Err(PunchError::VerificationUnavailable),
        _ => Err(PunchError::ExchangeTimeout),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// Colocated rather than in `tests.rs` because the two stubs below are this
// module's own injected surfaces and have no other reader — same shape as
// `core/peer/src/reuseport.rs`.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordination::{CANDIDATE_HOST, SUBSTRATE_TCP};
    use std::sync::{Arc, Mutex};

    /// A conforming bucket, not a mock. §4.4 makes the node "an opaque blob
    /// store": append, never drain, oldest first. Every §6.4 filter the punch
    /// applies is therefore exercised against the same mixture a live node
    /// would return — including both peers' own messages.
    #[derive(Default)]
    struct MemCarrier {
        blobs: Mutex<Vec<Vec<u8>>>,
    }

    #[async_trait]
    impl Carrier for MemCarrier {
        async fn offer(&self, _key: &RendezvousKey, blob: Vec<u8>) -> Result<(), PunchError> {
            self.blobs.lock().unwrap().push(blob);
            Ok(())
        }
        async fn collect(&self, _key: &RendezvousKey) -> Result<Vec<Vec<u8>>, PunchError> {
            Ok(self.blobs.lock().unwrap().clone())
        }
    }

    /// A substrate stub with a **virtual clock**: `sleep_ms` advances time
    /// rather than waiting, so `fire_at` scheduling is asserted exactly and the
    /// suite stays instant. This is the same reason `SignalingCore` takes
    /// `now_ms` as a parameter.
    struct StubIo {
        clock_ms: Mutex<u64>,
        /// Every sleep, in order — this is how the `fire_at` delay is observed.
        slept: Mutex<Vec<u64>>,
        dial_fails: u32,
        /// No inbound path ever arrives — the shape that isolates the dial loop,
        /// since a stub accept that always succeeds would end the crossing on
        /// the first poll and hide every retry.
        accept_fails: bool,
        /// **Outbound attempts issued by this side.** The §7.1 step 4 MUST is
        /// about this counter being non-zero on *both* peers, and it is the only
        /// part of the MUST a loopback test can reach — there is no NAT here, so
        /// a listen-only build opens a path and passes everything else.
        dials: Mutex<u32>,
        accepts: Mutex<u32>,
    }

    impl StubIo {
        fn new() -> Self {
            Self {
                clock_ms: Mutex::new(1_000),
                slept: Mutex::new(Vec::new()),
                dial_fails: 0,
                accept_fails: false,
                dials: Mutex::new(0),
                accepts: Mutex::new(0),
            }
        }
        fn failing_dials(n: u32) -> Self {
            Self {
                dial_fails: n,
                ..Self::new()
            }
        }
        fn no_inbound(mut self) -> Self {
            self.accept_fails = true;
            self
        }
        fn dials(&self) -> u32 {
            *self.dials.lock().unwrap()
        }
    }

    #[async_trait]
    impl PunchIo for StubIo {
        type Conn = String;

        async fn dial(&self, target: &str, _timeout_ms: u64) -> Result<String, String> {
            let mut n = self.dials.lock().unwrap();
            *n += 1;
            if *n <= self.dial_fails {
                return Err("refused".into());
            }
            Ok(format!("dialed:{}", target))
        }

        async fn accept(&self, _window_ms: u64) -> Result<String, String> {
            *self.accepts.lock().unwrap() += 1;
            if self.accept_fails {
                return Err("no inbound path within the crossing window".into());
            }
            Ok("accepted".into())
        }

        async fn sleep_ms(&self, ms: u64) {
            self.slept.lock().unwrap().push(ms);
            *self.clock_ms.lock().unwrap() += ms;
            // Advance instantly, but **yield**. The two sides of a punch are
            // joined onto one task in these tests, and a "sleep" with no await
            // point starves the counterpart — the poll loop spins, the other
            // half never runs, and the exchange times out against a carrier
            // that was working fine. Cost one debugging round to find.
            tokio::task::yield_now().await;
        }

        fn now_ms(&self) -> u64 {
            *self.clock_ms.lock().unwrap()
        }
    }

    fn key() -> RendezvousKey {
        RendezvousKey::from_slice(&[7u8; 33]).unwrap()
    }

    fn seeded(seed: u8) -> std::sync::Arc<entity_crypto::IdentityKeypair> {
        std::sync::Arc::new(entity_crypto::IdentityKeypair::Ed25519(
            entity_crypto::Keypair::from_seed([seed; 32]),
        ))
    }

    /// A deterministic identity per label.
    ///
    /// The party derives its own id from the signing key now — there is no id
    /// to hand it — so these tests need real keypairs while keeping "alice" and
    /// "bob" as their vocabulary. **"alice" is always assigned the
    /// lower-sorting id**, because several tests assert on the crossing
    /// tiebreak and its direction is a sort over exactly these strings.
    fn kp_named(label: &str) -> std::sync::Arc<entity_crypto::IdentityKeypair> {
        let (one, two) = (seeded(1), seeded(2));
        let (lo, hi) = if one.peer_id().to_string() < two.peer_id().to_string() {
            (one, two)
        } else {
            (two, one)
        };
        match label {
            "alice" => lo,
            "bob" => hi,
            other => seeded(other.bytes().fold(3u8, |acc, b| acc.wrapping_add(b))),
        }
    }

    /// The canonical id behind a label — what a counterpart actually sees.
    ///
    /// Leaked deliberately: these ids are passed as `&str` into `join!`ed
    /// futures, and a per-call `String` would be a temporary dropped while
    /// borrowed. The label set is tiny and fixed, and this is `cfg(test)`.
    fn id_of(label: &str) -> &'static str {
        Box::leak(kp_named(label).peer_id().to_string().into_boxed_str())
    }

    /// The tolerant posture, which is what most of these exercise. Both impls
    /// now seal their §6.1 deposits, so `Require` also works between two of
    /// these parties — `require_admits_a_sealed_counterpart` is that half, and
    /// `require_refuses_a_bare_counterpart_loudly` is the other.
    fn party(label: &str, addr: &str) -> PunchParty {
        PunchParty::new(
            key(),
            kp_named(label),
            SUBSTRATE_TCP,
            VerificationPolicy::AllowUnverifiedPreContainer,
        )
        .with_candidates(vec![Candidate::new(CANDIDATE_HOST, SUBSTRATE_TCP, addr)])
    }

    /// **The choreography, end to end.** Two peers meet through one carrier:
    /// the initiator offers, the responder answers, the initiator schedules,
    /// both cross. Both come away with a path.
    ///
    /// Run concurrently on one shared bucket, so each side reads a mixture
    /// containing its own messages and must filter them out (§6.4) — the same
    /// condition a live `pair` bucket presents.
    ///
    /// **This is also where the §7.1 step 4 MUST is asserted**, and it has to be
    /// asserted explicitly: no NAT is present, so a peer that only listened
    /// would still come away with a path and this test would still be green.
    #[tokio::test]
    async fn initiator_and_responder_meet_and_cross() {
        let carrier = Arc::new(MemCarrier::default());
        // "alice" < "bob": alice keeps what it dialed, bob what it accepted —
        // the two ends of one connection (`crossing_role`). Both still dial.
        let (a, b) = (party("alice", "10.0.0.1:900"), party("bob", "10.0.0.2:900"));
        let (a_io, b_io) = (StubIo::new(), StubIo::new());

        let (a_res, b_res) = tokio::join!(
            initiate(&a, carrier.as_ref(), &a_io, id_of("bob")),
            respond(&b, carrier.as_ref(), &b_io),
        );

        let a_conn = a_res.expect("initiator");
        let (b_conn, initiator_id) = b_res.expect("responder");
        assert_eq!(
            initiator_id,
            id_of("alice"),
            "the responder learns who it met — the id the caller serves the handshake for (§7.4.1)"
        );

        // §7.1 step 4 (corrected 2026-08-01): **each** peer MUST issue an
        // outbound attempt at `fire_at`. Listening alone opens no NAT mapping,
        // so a side with zero dials is non-traversing by construction — and
        // invisible to every other assertion in this file.
        assert!(
            a_io.dials() > 0 && b_io.dials() > 0,
            "both sides MUST fire outbound at fire_at — alice dialed {}x, bob {}x; \
             a zero here is the non-traversing bug, not a passing test",
            a_io.dials(),
            b_io.dials(),
        );
        // Both also listen: that is what makes a dial land outside the narrow
        // instant both sockets are in SYN_SENT.
        assert_eq!(
            (*a_io.accepts.lock().unwrap(), *b_io.accepts.lock().unwrap()),
            (1, 1)
        );

        // And they keep opposite ends of the SAME connection, per the tiebreak.
        assert_eq!(
            a_conn, "dialed:10.0.0.2:900",
            "the lower id keeps the socket it dialed"
        );
        assert_eq!(
            b_conn, "accepted",
            "the higher id keeps the socket it accepted"
        );
    }

    /// A peer whose own dial never lands still crosses, on the socket the
    /// counterpart opened — and it does **not** wait out its preference first.
    ///
    /// Alice is the lower id, so the tiebreak would have her keep a *dialed*
    /// socket, and every dial here is refused. There is only ever one connection
    /// between two fixed endpoints, so the one that did materialize is the one
    /// bob is holding too; insisting on the preferred socket would burn the
    /// whole crossing window waiting for a second connection that cannot exist.
    #[tokio::test]
    async fn a_preferred_socket_that_never_forms_does_not_stall_the_crossing() {
        let carrier = Arc::new(MemCarrier::default());
        let (a, b) = (party("alice", "10.0.0.1:900"), party("bob", "10.0.0.2:900"));
        let a_io = StubIo::failing_dials(u32::MAX);
        let b_io = StubIo::new();

        let (a_res, _) = tokio::join!(
            initiate(&a, carrier.as_ref(), &a_io, id_of("bob")),
            respond(&b, carrier.as_ref(), &b_io),
        );
        assert_eq!(
            a_res.expect("a refused dial is not a failed crossing while the other end landed"),
            "accepted"
        );
        // Still fired outbound (§7.1 step 4) — a refused dial opens the local
        // mapping exactly as an accepted one does — and stopped as soon as it
        // held a connection rather than spending the rest of the budget.
        assert_eq!(a_io.dials(), 1);
    }

    /// §7.2: `fire_at` is a **delay from receipt**, and the responder sleeps
    /// exactly the value it was sent. A wall-clock encoding passes every
    /// same-host test, so the delay is asserted as a delay.
    #[tokio::test]
    async fn responder_sleeps_the_delay_it_was_sent() {
        let carrier = Arc::new(MemCarrier::default());
        let (a, b) = (party("alice", "10.0.0.1:900"), party("bob", "10.0.0.2:900"));
        let (a_io, b_io) = (StubIo::new(), StubIo::new());

        let (a_res, b_res) = tokio::join!(
            initiate(&a, carrier.as_ref(), &a_io, id_of("bob")),
            respond(&b, carrier.as_ref(), &b_io),
        );
        a_res.expect("initiator");
        b_res.expect("responder");

        // The last thing each side does before crossing is sleep the scheduled
        // delay. Both slept a positive delay, and the responder's is the value
        // the initiator computed and put on the wire.
        let b_slept = b_io.slept.lock().unwrap().clone();
        let a_slept = a_io.slept.lock().unwrap().clone();
        let b_fire = *b_slept.last().unwrap();
        let a_fire = *a_slept.last().unwrap();
        assert!(
            b_fire > 0,
            "the responder must fire after a delay, not instantly"
        );
        assert_eq!(
            a_fire, b_fire,
            "both sides schedule against the SAME delay value — that is what makes the \
             firings cross, and it is the number that would be a timestamp if §7.2 were \
             read wrong"
        );
    }

    /// The socket tiebreak is **complementary**: for any pair one side keeps
    /// what it dialed and the other keeps what it accepted — which is one
    /// connection, described from its two ends. Agreeing on the same one is the
    /// whole job; if the two peers picked the same *verb* they would hold
    /// different sockets, each abandoned by its far end.
    ///
    /// It decides nothing about who dials. **Both do** — that is §7.1 step 4,
    /// and it is asserted where the crossing actually runs.
    #[test]
    fn the_socket_tiebreak_names_one_connection_from_both_ends() {
        for (x, y) in [("alice", "bob"), ("bob", "alice"), ("a", "aa"), ("zz", "z")] {
            let (rx, ry) = (crossing_role(x, y), crossing_role(y, x));
            assert_ne!(
                rx, ry,
                "{x} vs {y}: the two ends must name the same connection differently"
            );
        }
        assert_eq!(crossing_role("alice", "bob"), CrossingRole::KeepDialed);
        assert_eq!(crossing_role("bob", "alice"), CrossingRole::KeepAccepted);
    }

    /// §7.2.1's MUST and MUST NOT, as one assertion.
    ///
    /// `caller_owns_retry` caps the **exchange** budget at one — the layer that
    /// costs a reflector and a carrier — and leaves the **crossing** count
    /// untouched. Cutting the crossing instead is not a conservative reading of
    /// the rule; it is the bug that broke a working punch in another
    /// implementation, and it consumes exactly as much third-party
    /// infrastructure while making the punch miss.
    #[test]
    fn caller_owned_retry_caps_the_exchange_and_never_the_crossing() {
        let standalone = party("alice", "10.0.0.1:900");
        assert_eq!(standalone.exchange_attempts, DEFAULT_EXCHANGE_ATTEMPTS);
        assert_eq!(standalone.crossing_retries, DEFAULT_CROSSING_RETRIES);

        let reconnect = party("alice", "10.0.0.1:900").caller_owns_retry();
        assert_eq!(reconnect.exchange_attempts, 1, "§10.3 obligation 4");
        assert_eq!(
            reconnect.crossing_retries, DEFAULT_CROSSING_RETRIES,
            "§7.2.1 MUST NOT — the crossing budget is local and must survive untouched"
        );
    }

    /// A crossing retry is not a failure: the counterpart's listener may not be
    /// up at the first dial. The dial loop retries within one exchange, without
    /// touching the carrier — which is exactly what makes it free of the
    /// third-party budget.
    ///
    /// Alice gets no inbound path, which is what isolates the dial loop: with a
    /// listener that always succeeds the crossing would end on the first poll
    /// and the retries would never run.
    #[tokio::test]
    async fn crossing_retries_within_one_exchange() {
        let carrier = Arc::new(MemCarrier::default());
        let (a, b) = (party("alice", "10.0.0.1:900"), party("bob", "10.0.0.2:900"));
        let a_io = StubIo::failing_dials(2).no_inbound();
        let b_io = StubIo::new();

        let (a_res, _) = tokio::join!(
            initiate(&a, carrier.as_ref(), &a_io, id_of("bob")),
            respond(&b, carrier.as_ref(), &b_io),
        );
        assert!(
            a_res.is_ok(),
            "two refused dials then success is a normal crossing"
        );
        assert_eq!(a_io.dials(), 3);
        // One exchange only: three connect-request/response/sync blobs, not nine.
        assert_eq!(
            carrier.blobs.lock().unwrap().len(),
            3,
            "a crossing retry must not spend a fresh carrier exchange (§7.2.1)"
        );
    }

    /// When neither socket materializes the crossing must **end**, not hang:
    /// the seam above maps `CrossingFailed` to "no live path" and takes the
    /// relay fallback (§7.1 step 6). Both halves run concurrently now, so this
    /// also pins that the joint wait terminates once both have given up.
    #[tokio::test]
    async fn a_crossing_where_neither_socket_forms_is_a_clean_failure() {
        let carrier = Arc::new(MemCarrier::default());
        let (a, b) = (party("alice", "10.0.0.1:900"), party("bob", "10.0.0.2:900"));
        let a = PunchParty {
            exchange_attempts: 1,
            ..a
        };
        let a_io = StubIo::failing_dials(u32::MAX).no_inbound();
        let b_io = StubIo::new();

        let (a_res, _) = tokio::join!(
            initiate(&a, carrier.as_ref(), &a_io, id_of("bob")),
            respond(&b, carrier.as_ref(), &b_io),
        );
        assert!(matches!(
            a_res.unwrap_err(),
            PunchError::CrossingFailed { attempts } if attempts == DEFAULT_CROSSING_RETRIES
        ));
        assert_eq!(
            a_io.dials(),
            DEFAULT_CROSSING_RETRIES,
            "the whole local crossing budget is spent before giving up (§7.2.1)"
        );
    }

    /// The whole exchange under `Require`, both sides — which **works now**,
    /// because both deposits are sealed.
    ///
    /// This test inverted at the flip: it used to assert that `Require` could
    /// only ever refuse, since nothing deposited a container. Two peers running
    /// this module now complete a punch with every message verified and the
    /// crossing tiebreak resolved on identities each side *proved* rather than
    /// claimed.
    #[tokio::test]
    async fn require_admits_a_sealed_counterpart_end_to_end() {
        let carrier = Arc::new(MemCarrier::default());
        let requiring = |label, addr| PunchParty {
            trust: VerificationPolicy::Require,
            ..party(label, addr)
        };
        let (a, b) = (
            requiring("alice", "10.0.0.1:900"),
            requiring("bob", "10.0.0.2:900"),
        );
        let (a_io, b_io) = (StubIo::new(), StubIo::new());

        let (a_res, b_res) = tokio::join!(
            initiate(&a, carrier.as_ref(), &a_io, id_of("bob")),
            respond(&b, carrier.as_ref(), &b_io),
        );

        assert_eq!(a_res.expect("initiator"), "dialed:10.0.0.2:900");
        let (b_conn, initiator_id) = b_res.expect("responder");
        assert_eq!(b_conn, "accepted");
        assert_eq!(
            initiator_id,
            id_of("alice"),
            "under Require the id handed back is a verified signer, not a claim"
        );
    }

    /// A counterpart that answers **bare** is refused loudly, when the answer
    /// arrives — not by timing out.
    ///
    /// The adversary is the honest one to model post-flip: a peer that reads
    /// our sealed `connect-request`, echoes its nonce, and answers unsigned.
    /// That is precisely the downgrade `Require` exists to stop, and the
    /// distinction being asserted is *how* it stops: a silent skip would leave
    /// the initiator polling a bucket that already holds its answer and then
    /// reporting "nobody replied", which reads as a NAT problem and gets
    /// diagnosed days later. It must also cost no socket work — there is
    /// nothing here worth dialing at.
    #[tokio::test]
    async fn require_refuses_a_bare_answerer_loudly() {
        /// Unwraps the initiator's sealed request and answers it **bare**.
        struct BareAnswerer {
            key: RendezvousKey,
            blobs: Mutex<Vec<Vec<u8>>>,
        }

        #[async_trait]
        impl Carrier for BareAnswerer {
            async fn offer(&self, _key: &RendezvousKey, blob: Vec<u8>) -> Result<(), PunchError> {
                self.blobs.lock().unwrap().push(blob);
                Ok(())
            }
            async fn collect(&self, _key: &RendezvousKey) -> Result<Vec<Vec<u8>>, PunchError> {
                let mut out = self.blobs.lock().unwrap().clone();
                for blob in &out.clone() {
                    if let CollectedMessage::Request(req) =
                        coordination::classify_collected(blob, &self.key).msg
                    {
                        let answer = ConnectResponse {
                            responder: id_of("bob").to_string(),
                            candidates: vec![Candidate::new(
                                CANDIDATE_HOST,
                                SUBSTRATE_TCP,
                                "10.0.0.2:900",
                            )],
                            nonce: req.nonce.clone(),
                        };
                        out.push(coordination::to_blob(&answer.to_entity().unwrap()));
                    }
                }
                Ok(out)
            }
        }

        let carrier = BareAnswerer {
            key: key(),
            blobs: Mutex::new(Vec::new()),
        };
        let a = PunchParty {
            trust: VerificationPolicy::Require,
            ..party("alice", "10.0.0.1:900")
        };
        let a_io = StubIo::new();

        let res = initiate(&a, &carrier, &a_io, id_of("bob")).await;
        assert!(
            matches!(res.unwrap_err(), PunchError::VerificationUnavailable),
            "an unsealed answer must be refused by name, not reported as a timeout"
        );
        assert_eq!(
            a_io.dials(),
            0,
            "the refusal lands before any socket work — there is nothing here to dial at"
        );
    }

    /// The responder half of the same rule: a `Require` peer does not answer a
    /// bare `connect-request` either.
    ///
    /// Asserted separately because `await_request` carries its own policy
    /// branch, and a rule enforced on one side of an exchange is a rule an
    /// attacker takes the other side of.
    #[tokio::test]
    async fn require_refuses_a_bare_request_on_the_responder_side() {
        let carrier = Arc::new(MemCarrier::default());
        // A pre-flip initiator's request: the §6.2 bare framing, no container.
        let stale = ConnectRequest {
            initiator: id_of("alice").to_string(),
            candidates: vec![Candidate::new(
                CANDIDATE_HOST,
                SUBSTRATE_TCP,
                "10.0.0.1:900",
            )],
            nonce: Nonce(vec![0x33; 16]),
        };
        carrier
            .offer(&key(), coordination::to_blob(&stale.to_entity().unwrap()))
            .await
            .unwrap();

        let b = PunchParty {
            trust: VerificationPolicy::Require,
            ..party("bob", "10.0.0.2:900")
        };
        let b_io = StubIo::new();

        let b_res = respond(&b, carrier.as_ref(), &b_io).await;
        assert!(matches!(
            b_res.unwrap_err(),
            PunchError::VerificationUnavailable
        ));
        assert_eq!(b_io.dials(), 0);
    }

    /// A refusal is **not** worth a fresh exchange: the counterpart will still
    /// be bare next time, and the retry spends a nonce at someone else's node
    /// for a guaranteed second failure (§7.2.1).
    #[test]
    fn a_verification_refusal_is_not_transient() {
        assert!(!PunchError::VerificationUnavailable.is_transient());
    }

    /// §7.3.1: a counterpart reachable only on a substrate we do not share is
    /// **not a dispatch error** — it is "no live path", which the §10.3 seam
    /// maps to the relay fallback.
    #[tokio::test]
    async fn no_shared_substrate_is_a_clean_no_live_path() {
        let carrier = Arc::new(MemCarrier::default());
        let a = party("alice", "10.0.0.1:900");
        // bob advertises only webrtc; alice punches tcp.
        let b = PunchParty::new(
            key(),
            kp_named("bob"),
            "webrtc",
            VerificationPolicy::AllowUnverifiedPreContainer,
        )
        .with_candidates(vec![Candidate::new(
            CANDIDATE_HOST,
            "webrtc",
            "webrtc-endpoint",
        )]);
        let (a_io, b_io) = (StubIo::new(), StubIo::new());

        let (a_res, _) = tokio::join!(
            initiate(&a, carrier.as_ref(), &a_io, id_of("bob")),
            respond(&b, carrier.as_ref(), &b_io),
        );
        assert!(matches!(a_res.unwrap_err(), PunchError::NoSharedSubstrate));
    }

    /// §6.4: in a shared bucket someone else's answer is not ours. A response
    /// carrying our nonce but a different responder must not be adopted — that
    /// is the correlate-by-identity filter, and skipping it would punch toward
    /// whoever answered first.
    #[tokio::test]
    async fn a_response_from_the_wrong_peer_is_not_adopted() {
        let carrier = Arc::new(MemCarrier::default());
        let a = party("alice", "10.0.0.1:900");
        // "mallory" answers instead of the expected "bob".
        let m = party("mallory", "10.0.0.9:900");
        let (a_io, m_io) = (StubIo::new(), StubIo::new());
        // Shorten alice's patience so the test ends rather than polling forever.
        let a = PunchParty {
            exchange_timeout_ms: 1_000,
            exchange_attempts: 1,
            ..a
        };

        let (a_res, _) = tokio::join!(
            initiate(&a, carrier.as_ref(), &a_io, id_of("bob")),
            respond(&m, carrier.as_ref(), &m_io),
        );
        assert!(
            matches!(a_res.unwrap_err(), PunchError::ExchangeTimeout),
            "an answer from a peer we did not intend to reach must not complete the punch"
        );
    }
}
