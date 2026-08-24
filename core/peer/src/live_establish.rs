//! `EXTENSION-NETWORK` §10.3 (Amendment 14) — the live-establishment seam.
//!
//! §10 step 3 resolves **durable** transport profiles. A peer behind NAT has no
//! dialable durable profile — its published endpoints are unreachable from
//! outside — yet it may be reachable **right now** by traversal. §10.3 names the
//! slot for that escalation, consulted at **step 3b**: after durable-profile
//! resolution has failed and **before** the §10.2 delivery fallback.
//!
//! # Why this returns a connection and not a result
//!
//! §10.3 is a separate seam from §10.2's `dispatch_fallback` precisely because
//! it returns a *connection*. On success the ladder re-enters ordinary dispatch,
//! so the connection lands in the pool and every later dispatch to that peer
//! reuses it. A seam returning a delivered result would punch a fresh hole per
//! message and hide the connection from §10 step 1.
//!
//! **Pre-handshake, deliberately.** The returned [`Connection`] is the raw
//! transport — reader/writer, no HELLO yet. That is what lets `get_or_connect`
//! run the *identical* post-connect tail it runs for a dialed socket
//! (`perform_connect_with_dispatch` → session entity → connection state →
//! liveness → pool insert → `spawn_keepalive`). §10.3 imposes two MUSTs on the
//! returned connection — that it is an ordinary transport never published as a
//! durable `system/peer/transport/*` profile, and that it runs §5 keepalive —
//! and reusing that tail is what makes both **structural rather than
//! aspirational**. A seam that returned a completed session would have to
//! re-implement pooling and keepalive inside the traversal extension, which is
//! the layering §10.3 forbids.
//!
//! # Layering
//!
//! NETWORK is **below** the traversal extension and cannot call into it, so the
//! substrate exposes the slot and the extension plugs the algorithm. This trait
//! is that slot. The v1 registered policy is `EXTENSION-SIGNALING.md` §7 — the
//! rendezvous-coordinated hole punch — whose *choreography* (candidate exchange,
//! `fire_at` scheduling, the §7.4 connectivity check) stays in
//! `extensions/signaling`, while the socket work stays here where sockets live.
//!
//! Mirrors `relay_forwarder`: the algorithm is the extension's, the wiring that
//! touches the connection pool is `core/peer`'s.
//!
//! # The additive property
//!
//! Returning `None` — including "no establisher registered at all" — makes the
//! ladder **byte-identical to the pre-seam behavior**. That is §10.3's
//! no-regression guarantee, and it is what
//! [`live_establish_unregistered_leaves_the_ladder_unchanged`] asserts.
//!
//! [`live_establish_unregistered_leaves_the_ladder_unchanged`]: crate::tests

use web_time::Instant;

use crate::transport::Connection;

/// Default budget for one traversal consultation.
///
/// §10.3 notes a traversal runs *seconds* — candidate gathering, a carrier round
/// trip, a scheduled simultaneous open, crossing retries — so this is
/// deliberately far larger than any other rung of the §10 ladder and far smaller
/// than "forever". §7.2's own defaults (`d = max(rtt, 250 ms)`, up to 3 exchange
/// attempts) fit inside it with room for a slow carrier.
///
/// A per-deployment knob on `PeerConfig` is the obvious next refinement; the
/// MUST §10.3 states is that the seam *carries* a deadline, not that the number
/// is configurable, so this stays a documented constant until a deployment needs
/// otherwise.
pub const DEFAULT_TRAVERSAL_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

/// What the caller hands the seam: a deadline, and which retry authority owns
/// this consultation.
///
/// # The deadline is a MUST
///
/// §10.3: *"`ctx` carries a deadline and is cancellable (MUST). A traversal
/// attempt takes seconds — candidate gathering, a carrier round trip, a
/// scheduled simultaneous open, retries — which is one to two orders of
/// magnitude longer than any other rung of the §10 ladder. A seam with no
/// cancellation makes an unreachable peer indistinguishable from a hung
/// dispatcher."*
///
/// **Cancellation is structural in Rust and needs no field.** Dropping the
/// future returned by [`LiveEstablish::establish_live`] cancels it at the next
/// await point — stricter than the cooperative `ctx.Done()` the spec's Go-shaped
/// signature implies, because it cannot be ignored by a policy that forgets to
/// check. So this type carries the half that *is* data — the deadline — and
/// leaves cancellation to the ownership model. A caller that wants a hard stop
/// wraps the call in `tokio::time::timeout`.
#[derive(Debug, Clone, Copy)]
pub struct EstablishCtx {
    /// When the caller stops caring. A policy MUST NOT run past it.
    pub deadline: Instant,
    /// **§10.3 obligation 4 / `EXTENSION-SIGNALING.md` §7.2.1** — whether the
    /// *caller* owns re-scheduling.
    ///
    /// `true` when this consultation came from a `maintain-peer` reconnection
    /// continuation (§4.1): the policy MUST make **exactly one** attempt at
    /// whatever step of its traversal contacts a **third party** — for §7 that
    /// is one coordination exchange — because §4.1's backoff already owns the
    /// retry and the two budgets otherwise *multiply* onto a reflector and a
    /// carrier that belong to someone else.
    ///
    /// **This constrains only the third-party-facing step.** A policy's
    /// crossing retries — more simultaneous-open dials at the counterpart's own
    /// socket — cost nobody but the two peers and MUST NOT be reduced to
    /// satisfy this. Cutting that counter instead is not a conservative
    /// reading; it broke a working punch in another implementation and is what
    /// §7.2.1 exists to prevent. The distinguishing question: *does one more
    /// attempt send a packet to anyone other than the target peer?*
    pub caller_owns_retry: bool,
}

impl EstablishCtx {
    /// A consultation driven directly by a §10 dispatch. The policy owns its
    /// own exchange budget (§7.2 — up to 3).
    pub fn dispatch(deadline: Instant) -> Self {
        Self {
            deadline,
            caller_owns_retry: false,
        }
    }

    /// A consultation from a §4.1 `maintain-peer` reconnection continuation.
    /// Exactly one third-party-facing attempt; §4.1's backoff re-schedules.
    ///
    /// Named rather than a bare bool at the call site on purpose: the two
    /// callers are the whole of §7.2.1's distinction, and a flag that can be
    /// passed wrong by transposition is a flag that eventually is.
    pub fn reconnect(deadline: Instant) -> Self {
        Self {
            deadline,
            caller_owns_retry: true,
        }
    }

    /// Time left before [`deadline`](Self::deadline), or zero if it has passed.
    pub fn remaining(&self) -> std::time::Duration {
        self.deadline
            .checked_duration_since(Instant::now())
            .unwrap_or_default()
    }

    /// Whether the deadline has passed. A policy checks this between rungs
    /// rather than starting work it cannot finish.
    pub fn expired(&self) -> bool {
        self.remaining().is_zero()
    }
}

/// The §10.3 slot: *can I reach this peer right now, by traversal?*
///
/// Consulted **once** per connection resolution. `None` means "no live path" —
/// never an error — so a failed traversal degrades to the ordinary
/// store-and-forward path rather than failing the dispatch. That posture is
/// load-bearing: a platform without the §7.3 socket options, a peer with no
/// carrier configured, and a genuinely unreachable peer must all present the
/// same way to the ladder.
///
/// # The four obligations (§10.3, all MUST)
///
/// 1. **Ordinary transport, with stream semantics.** Indistinguishable to the
///    entity layer from a dialed `tcp` connection, and never published as a
///    durable `system/peer/transport/*` profile. It MUST present reliable,
///    ordered, stream semantics — a policy that punches a raw datagram path
///    owes reliability *below* this seam, because the entity layer above it
///    layers length-prefixed framing on a stream and must not be asked to
///    re-derive it.
/// 2. **Keepalive.** A punched NAT mapping expires on silence. Satisfied here
///    by construction: a traversal connection reaches the pool only through
///    `remote::adopt_transport_connection`, which spawns the §5 loop.
/// 3. **Identity verified before the connection is used.** The §7.4
///    connectivity check — nonce plus identity binding — MUST have completed
///    before the return value enters the pool or carries an operation. *A
///    traversal returns a path to an address; only the check makes it a path to
///    the peer.* The freedom is over **where** verification runs, never whether
///    it has run by the time the ladder re-enters dispatch. Also satisfied by
///    construction here: `adopt_transport_connection` runs the handshake before
///    `insert_endpoint`, so nothing unverified can reach the pool. A policy
///    returning a *post*-handshake connection would satisfy it the other way.
/// 4. **Exactly one retry authority** — see [`EstablishCtx::caller_owns_retry`].
///
/// # Handshake factoring
///
/// This implementation returns a **pre-handshake** connection and runs the
/// handshake in the shared adopt-path used by ordinary dials. §10.3 explicitly
/// blesses both factorings ("the two reference builds split on exactly this
/// point... both are conformant") because the seam is a boundary *inside* one
/// peer, invisible across the wire.
///
/// What is **not** free to vary is *which peer* runs the client half:
/// `EXTENSION-SIGNALING.md` §7.4.1 pins it to the **initiator** — the peer whose
/// `connect-request` the responder collected. A dial establishes that role for
/// free; a punch destroys the signal, because both sides dialed. A policy
/// implementing the responder side therefore needs the *server* handshake, not
/// this crate's client one.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait LiveEstablish: Send + Sync {
    /// Attempt to establish a live transport to `peer_id` by traversal, within
    /// `ctx`'s deadline.
    async fn establish_live(&self, ctx: EstablishCtx, peer_id: &str) -> Option<Connection>;
}
