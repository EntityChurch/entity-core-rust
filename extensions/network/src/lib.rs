//! EXTENSION-NETWORK §3–§4 — the `system/network` handler (Amendment 12
//! rung 3): `maintain-peer` / `release-peer` / `status` / `close` plus the
//! internal `reconnect` / `restore-subscriptions` operations, composed on
//! the §A3 liveness floor `core/peer` already provides (status transition
//! writes + §5.4 keepalive).
//!
//! Division of labor (§A4 discipline — the handler double-builds nothing):
//!
//! - `core/peer` owns the imperative substrate: establish writes
//!   `connected`, the §A1 dispatch seam writes `suspect`, the §5.4
//!   keepalive loop writes `disconnected` and starts at every outbound
//!   pool insert.
//! - this handler owns the REACTIVE half: it installs the continuation
//!   graph that watches those writes and dials back — through the
//!   [`PeerLink`] seam `core/peer` injects at engine start (the same
//!   inversion the RELAY forwarder uses; an extension crate cannot import
//!   the peer).
//!
//! The §4.1 graph as built here (cohort-converged shape; the deliberate
//! divergences from the §4.1 pseudocode are Go's six spec-issue
//! resolutions, `entity-core-go/docs/validation/spec-issues/2026-07-15-
//! network-amendment-12-rung-3-observations.md`, reproduced independently
//! against this codebase):
//!
//! - `system/inbox/network/{peer}/on-disconnect` — standing continuation,
//!   advanced by a lifecycle subscription on `system/peer/status/{hex}`;
//!   dispatches the internal `reconnect` operation (the connect-if-needed
//!   seam; the pseudocode's `system/protocol/connect hello` target is the
//!   responder side of the handshake here too and cannot dial).
//! - `system/network/peers/{peer}/on-reconnect-backoff` — one-shot
//!   continuation re-EXECUTing `maintain-peer`; advanced by the handler
//!   after the computed §2.2 backoff delay. Lives in the §11 managed
//!   namespace, NOT under `system/inbox/*` (marker-proposal §5 discipline:
//!   error routing MUST NOT target `system/inbox/*`).
//! - `system/inbox/network/{peer}/on-reconnect` — standing continuation,
//!   advanced by a second lifecycle subscription on the same status path;
//!   dispatches the internal `restore-subscriptions` operation (§7.2
//!   first half).
//!
//! Failed reconnect dispatches deliberately carry NO `on_error`: a forward
//! non-2xx with no `on_error` binds the §3.10 lost-error marker (reason
//! `connection_failed`, keyed by RequestID) under the continuation
//! handler's own authority — the PROPOSAL-CONTINUATION-LOST-ERROR-MARKER-
//! MUST observability surface rung 3 is the named test subject for.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock, Weak};

use async_trait::async_trait;
use entity_entity::Entity;
use entity_handler::{
    ExecuteOptions, Handler, HandlerContext, HandlerError, HandlerResult, STATUS_BAD_GATEWAY,
    STATUS_BAD_REQUEST, STATUS_INTERNAL_ERROR, STATUS_NOT_FOUND, STATUS_OK,
};
use entity_hash::Hash;
use entity_store::{ContentStore, ExecutionContext, LocationIndex};

/// The handler's registration pattern (§3.1).
pub const HANDLER_PATTERN: &str = "system/network";

/// §2 type names (registered in `entity-types::register_core_types`).
pub const TYPE_MAINTAIN_REQUEST: &str = "system/network/maintain-request";
pub const TYPE_MAINTAIN_RESULT: &str = "system/network/maintain-result";
pub const TYPE_RELEASE_REQUEST: &str = "system/network/release-request";
pub const TYPE_RELEASE_RESULT: &str = "system/network/release-result";
pub const TYPE_NETWORK_STATUS: &str = "system/network/status";
pub const TYPE_CLOSE_REQUEST: &str = "system/network/close-request";
pub const TYPE_OBSERVE_ADDRESS_RESULT: &str = "system/network/observe-address-result";

// ---------------------------------------------------------------------------
// §6.7.1 observed-address reflection — the CLIENT half
// ---------------------------------------------------------------------------

/// §6.7.1 (Amendment 13). Ask a reflector what source address it sees us at.
pub const OP_OBSERVE_ADDRESS: &str = "observe-address";

/// Params for [`OP_OBSERVE_ADDRESS`] — **the operation declares no input.**
///
/// §6.7.1 MUST 1: the responder returns the transport-layer source of the
/// connection the request arrived on and *never* a value echoed from the body.
/// So there is nothing for a caller to supply, and a conformant responder reads
/// nothing here. This sends the zero-field entity Rust already uses for no-input
/// EXECUTEs (`primitive/any` over CBOR `0xa0`).
///
/// Go sends the same empty map under a `system/network/observe-address-request`
/// type name. Both interoperate — Go's manifest entry declares no `InputType`
/// and its handler never touches the body — and this side declines to mint a
/// type name the spec does not define.
pub fn observe_address_params() -> Result<Entity, String> {
    Entity::new("primitive/any", vec![0xa0]).map_err(|e| e.to_string())
}

/// The §6.7.1 accept-side channel: the transport source of the connection the
/// request arrived on.
///
/// # Why this is a task-local and not a `HandlerContext` field
///
/// §6.7.1 is unusually specific about the shape, and it is worth quoting because
/// the obvious implementation is the one it forbids:
///
/// > *"The handler answering `observe-address` needs the source address of the
/// > connection the request arrived on. A dispatch seam that extracts only the
/// > remote peer identity does not carry it, and this spec deliberately does
/// > **not** widen the general handler context to fix that — a narrow,
/// > NETWORK-scoped accept-side path from the connection to this operation is
/// > the intended shape."*
///
/// A `source_addr` on `HandlerContext` would be exactly that widening: every
/// handler in the system would gain a transport fact that only this one
/// operation may use, and the next handler to reach for it would be writing a
/// responder-side address somewhere dialer-side (MUST 2's failure).
///
/// So the path is literally this module's: `core/peer` scopes it around the
/// accept-side dispatch, nothing else can see it, and it is unset for an
/// in-process dispatch — which is why `observe-address` correctly refuses one
/// rather than inventing an address.
pub mod nat_type;

pub mod accept_source {
    tokio::task_local! {
        static ACCEPT_SOURCE: String;
    }

    /// Run `fut` with `source` visible to [`current`]. Called by the accept-side
    /// dispatch in `core/peer`, and nowhere else.
    pub async fn scope<F: std::future::Future>(source: String, fut: F) -> F::Output {
        ACCEPT_SOURCE.scope(source, fut).await
    }

    /// The transport source of the connection this request arrived on, if it
    /// arrived on one at all.
    ///
    /// `None` for an in-process dispatch — there is no observable transport
    /// source, and §6.7.1's answer to that is a refusal, not a guess.
    pub fn current() -> Option<String> {
        ACCEPT_SOURCE.try_with(|s| s.clone()).ok()
    }
}

/// The §6.7.1 result: this peer's public mapping, as **one** reflector saw it.
///
/// # This is advisory, and it is not an address to keep
///
/// §6.7.1 is explicit on both counts. *"A single reflector is advisory, never
/// trusted"* — a lying reflector feeds a peer a wrong mapping, so no security
/// decision may rest on one observation; agreement across several reflectors is
/// what makes the fact usable, and disagreement is itself the signal (a mapping
/// that differs per destination is a symmetric NAT, where a punch will likely
/// fail and relay is the right answer).
///
/// And MUST 2: it **MUST NOT be persisted** to any durable per-peer address
/// field — not `system/connection.address`, not a `system/peer/transport/*`
/// profile, not `system/peer/status`. Every durable address in the protocol is
/// *dialer-side dialable-endpoint* state; this is a *responder-side* observation
/// of an ephemeral source port, and writing it where §10 reads dialable
/// addresses corrupts dispatch for every other reader. It is read from the live
/// connection, turned into a candidate, and dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObserveAddressResult {
    /// The source `IP:port` the responder observed, e.g. `"203.0.113.7:51820"`.
    pub observed_address: String,
}

impl ObserveAddressResult {
    /// Decode the `data` of a `system/network/observe-address-result` entity.
    pub fn from_result_data(data: &[u8]) -> Result<Self, String> {
        let observed_address = decode_text_field(data, "observed_address")
            .ok_or("observe-address-result: no string `observed_address` field (§6.7.1)")?;
        if observed_address.is_empty() {
            return Err("observe-address-result: empty `observed_address` (§6.7.1)".to_string());
        }
        Ok(Self { observed_address })
    }
}

// ---------------------------------------------------------------------------
// PeerLink — the imperative seam core/peer injects (§A4: reuse, don't rebuild)
// ---------------------------------------------------------------------------

/// A boxed task for [`PeerLink::schedule`]. `Send` on native (tokio spawn),
/// `!Send` on wasm32 (browser event loop) — same split as `ExecuteFn`.
#[cfg(not(target_arch = "wasm32"))]
pub type ScheduledTask = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
#[cfg(target_arch = "wasm32")]
pub type ScheduledTask = Pin<Box<dyn Future<Output = ()> + 'static>>;

/// Facts about a live (or just-established) connection, returned by the
/// connect-if-needed seam. `identity_hash` is the remote's `system/peer`
/// content hash — the §3.13 status-path key.
#[derive(Debug, Clone)]
pub struct ConnectedPeer {
    pub peer_id: String,
    pub identity_hash: Hash,
}

/// The connection-substrate seam the network handler drives. Implemented by
/// `core/peer` over its outbound pool / dial / keepalive machinery and
/// injected via [`NetworkHandler::bind`] — the crate-DAG inversion that
/// keeps this extension importable by the peer (mirror of the RELAY
/// forwarder seam).
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait PeerLink: Send + Sync {
    /// §4.1 step 1 — connect if needed (Go `EnsureConnected` analog).
    /// Reuses the pooled binding when live; otherwise dials `address`
    /// (when given) or resolves the peer's transport profiles. The
    /// establish path writes the §3.13 `connected` status and starts
    /// keepalive AMBIENTLY (§A4 — the handler adds no second write/loop).
    async fn ensure_connected(
        &self,
        peer_id: &str,
        address: Option<&str>,
    ) -> Result<ConnectedPeer, String>;

    /// Evict the pooled outbound binding. The §5.4 keepalive loop exits by
    /// itself once the binding is gone (weak-pool discipline).
    fn evict(&self, peer_id: &str);

    /// Whether a pooled outbound binding currently exists.
    fn is_connected(&self, peer_id: &str) -> bool;

    /// The pooled binding's remote identity hash, when connected.
    fn identity_hash_of(&self, peer_id: &str) -> Option<Hash>;

    /// Dispatch a self-authored local EXECUTE as the local peer identity
    /// (Go `selfExecute` analog). Used where the propagated caller context
    /// is wrong or absent: the lifecycle subscriptions are the PEER's own
    /// (so release-peer can unsubscribe them), and the backoff-timer
    /// advance fires outside any request context.
    async fn self_execute(
        &self,
        uri: &str,
        operation: &str,
        params: Entity,
        opts: ExecuteOptions,
    ) -> Result<HandlerResult, HandlerError>;

    /// Mint + store a self-granted deliver token authorizing inbox
    /// `receive` at `deliver_uri` (granter == grantee == the local peer,
    /// no expiry — lifecycle subscriptions must survive arbitrarily long
    /// disconnects; release-peer is the deliberate teardown). Returns
    /// `(token, signature, local identity)` — the included-set triple a
    /// subscribe EXECUTE carries.
    fn mint_deliver_token(&self, deliver_uri: &str) -> Result<(Entity, Entity, Entity), String>;

    /// §4.2 terminal write on `reason=shutdown`: the relationship is
    /// deliberately over — eviction alone would leave the last transition
    /// value standing. Writes the bare `{peer_id, status: disconnected}`
    /// §3.13 entity (cohort shape) and the `closed` connection transition.
    fn write_released(&self, peer_id: &str, identity_hash: &Hash);

    /// §2.2 terminal write on retry exhaustion (ruling 6): an OPTIONAL
    /// give-up bound was reached, so the relationship is abandoned —
    /// `{status: disconnected, reason: retry-exhausted}`, preserving the
    /// episode's `failing_since` so the record says how long we tried.
    ///
    /// Not a fourth status: the §3.13 enum stays three-state and `reason`
    /// says why. Only reachable when a caller opted into a bound.
    fn write_retry_exhausted(&self, peer_id: &str, identity_hash: &Hash, failing_since: u64);

    /// §4.4 local close transition: `system/connection/{hex}` → `closed`
    /// (attachment-preserving RMW, idempotent).
    fn mark_connection_closed(&self, identity_hash: &Hash);

    /// Run `task` after `delay_ms` (the §2.2 backoff pacing timer;
    /// impl-internal bookkeeping per §12.4).
    fn schedule(&self, delay_ms: u64, task: ScheduledTask);
}

// ---------------------------------------------------------------------------
// Session bookkeeping (impl-defined per §12.4; the durable half is the tree)
// ---------------------------------------------------------------------------

/// §2.2 backoff configuration with spec defaults applied.
#[derive(Debug, Clone)]
pub struct BackoffCfg {
    pub min_ms: u64,
    pub max_ms: u64,
    pub strategy: String,
    /// OPTIONAL §2.2 bound by count: once this many retries have FIRED,
    /// the relationship is abandoned. `None` ⇒ no bound.
    pub max_attempts: Option<u64>,
    /// OPTIONAL §2.2 bound by wall-clock: once this long has passed
    /// since `failing_since`, the relationship is abandoned. `None` ⇒
    /// no bound.
    ///
    /// Both bounds default to unset, which is **retry-forever** — the
    /// normative behaviour, because a peer offline for a week and coming
    /// back is the P2P norm; "give up after N" imports a client-server
    /// assumption that does not hold here. They exist for callers who
    /// know a relationship is disposable; they are not a recommended
    /// default.
    ///
    /// Exhaustion is not a fourth status: it terminates at
    /// `disconnected` with reason `retry-exhausted` (the §3.13 enum is
    /// three-state, and `reason` is the field that says why).
    pub max_elapsed_ms: Option<u64>,
}

impl Default for BackoffCfg {
    fn default() -> Self {
        Self {
            min_ms: 1000,
            max_ms: 60000,
            strategy: "exponential".to_string(),
            max_attempts: None,
            max_elapsed_ms: None,
        }
    }
}

/// §2.2 delay before retry `k`, where `k` is **1-indexed**: `k = 1` is
/// the first retry after the failure, and `delay(0)` is 0 (no retry, no
/// wait).
///
/// ```text
/// constant     min
/// linear       min · k
/// exponential  min · 2^(k-1)
/// ```
///
/// all clamped to `max` (and `max` is raised to `min` when a config
/// inverts them, so the delay is never below `min`). Arithmetic
/// saturates rather than wrapping: a config with an absurd `min` cannot
/// make a huge `k` produce a tiny delay.
pub fn backoff_delay_ms(cfg: &BackoffCfg, k: u64) -> u64 {
    if k == 0 {
        return 0;
    }
    let min_ms = cfg.min_ms;
    let max_ms = cfg.max_ms.max(min_ms);
    let ms = match cfg.strategy.as_str() {
        "constant" => min_ms,
        "linear" => min_ms.saturating_mul(k),
        // "exponential" (default)
        _ => {
            let mut ms = min_ms;
            for _ in 1..k {
                if ms >= max_ms {
                    break;
                }
                ms = ms.saturating_mul(2);
            }
            ms
        }
    };
    ms.min(max_ms)
}

/// The §2.2 retry pacing for one failure episode — DERIVED from
/// (`failing_since`, backoff config, `now`), never stored. See
/// [`derive_retry_state`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RetryState {
    /// How many retries have already FIRED this episode: 0 in the
    /// interval between the failure and the first retry coming due.
    pub attempt: u64,
    /// When the next retry comes due, ms since epoch. `None` when
    /// `exhausted` — there is no next attempt.
    pub next_attempt_at: Option<u64>,
    /// An OPTIONAL §2.2 bound (`max_attempts` / `max_elapsed_ms`) has
    /// been reached and the relationship is abandoned. Always `false`
    /// under the default config, which is retry-forever.
    pub exhausted: bool,
}

/// Compute the retry pacing for the failure episode that began at
/// `failing_since` (ms since epoch), as of `now_ms`.
///
/// This is the whole of the retry state machine, as one pure function.
/// Nothing counts attempts, and nothing is written per attempt (§A4):
/// the k-th retry is due at a fixed offset from `failing_since`, so
/// "which retry are we on" is a question about elapsed time, answerable
/// from a stamp the tree already holds. Two things fall out of that.
/// Restart-hammering dies — a process that restarts beside a peer dead
/// for a month re-derives a large `attempt` and a max-length wait, where
/// an in-memory counter would reset to 0 and redial in `min_ms`. And
/// pacing converges: two peers reading the same `failing_since` agree on
/// the schedule without exchanging retry state.
///
/// The schedule, with `elapsed = now_ms - failing_since`:
///
/// ```text
/// elapsed_to(0)   = 0
/// elapsed_to(k)   = elapsed_to(k-1) + delay(k)
/// attempt         = max{ k : elapsed_to(k) <= elapsed }
/// next_attempt_at = failing_since + elapsed_to(attempt + 1)
/// ```
///
/// The boundary is INCLUSIVE: at exactly `elapsed_to(k)` the k-th retry
/// has fired.
///
/// Worked example — the §2.2 defaults (exponential, min 1s, max 60s).
/// Delays run 1s, 2s, 4s, 8s…; `elapsed_to` runs 1s, 3s, 7s, 15s…. At
/// `elapsed = 5s`: two retries have fired (`elapsed_to(2) = 3s <= 5s`,
/// `elapsed_to(3) = 7s > 5s`), so `attempt = 2` and the third comes due
/// at `failing_since + 7s`.
///
/// No jitter in v1 — the schedule is a deterministic function of its
/// inputs, which is what makes it testable as a vector table and
/// comparable across impls. Jitter, if it lands, is a later opt-in that
/// perturbs the output here.
///
/// `failing_since == None` means no episode (the `connected` write
/// clears the stamp), and returns the default [`RetryState`]. A
/// degenerate config whose delay works out to 0 also returns `attempt`
/// 0 with `next_attempt_at == failing_since` — always due, never counted
/// — rather than looping forever counting instantaneous retries.
pub fn derive_retry_state(cfg: &BackoffCfg, failing_since: Option<u64>, now_ms: u64) -> RetryState {
    let Some(failing_since) = failing_since else {
        return RetryState::default();
    };
    let elapsed = now_ms.saturating_sub(failing_since);
    let paced = derive_pacing(cfg, failing_since, elapsed);

    // The OPTIONAL §2.2 bounds. Unset ⇒ retry-forever, so the default
    // config never takes either branch.
    if cfg.max_attempts.is_some_and(|max| paced.attempt >= max)
        || cfg.max_elapsed_ms.is_some_and(|max| elapsed >= max)
    {
        return RetryState {
            attempt: paced.attempt,
            next_attempt_at: None,
            exhausted: true,
        };
    }
    paced
}

/// Walks the schedule; see [`derive_retry_state`] for the semantics.
fn derive_pacing(cfg: &BackoffCfg, failing_since: u64, elapsed: u64) -> RetryState {
    // The delay sequence is non-decreasing and every strategy plateaus
    // (constant from k=1; linear and exponential once they clamp at
    // max), so as soon as two consecutive delays match, the rest of the
    // schedule is arithmetic and the tail closes in one step. Without
    // that, a peer dead for a month at a 60s cap would cost ~43k
    // iterations here.
    let mut attempt = 0u64; // retries fired so far
    let mut cum = 0u64; // elapsed_to(attempt)
    let mut prev_delay = 0u64;

    for k in 1u64.. {
        let delay = backoff_delay_ms(cfg, k);
        if delay == 0 {
            return RetryState {
                attempt,
                next_attempt_at: Some(failing_since.saturating_add(cum)),
                exhausted: false,
            };
        }
        if k > 1 && delay == prev_delay {
            // Plateaued: every remaining retry costs exactly `delay`,
            // and cum <= elapsed still holds (we'd have returned
            // otherwise).
            let extra = (elapsed - cum) / delay;
            attempt += extra;
            cum = cum.saturating_add(extra.saturating_mul(delay));
            return RetryState {
                attempt,
                next_attempt_at: Some(failing_since.saturating_add(cum.saturating_add(delay))),
                exhausted: false,
            };
        }
        let next = cum.saturating_add(delay);
        if next > elapsed {
            return RetryState {
                attempt,
                next_attempt_at: Some(failing_since.saturating_add(next)),
                exhausted: false,
            };
        }
        cum = next;
        attempt = k;
        prev_delay = delay;
    }
    unreachable!("the schedule walk returns from inside the loop")
}

/// Decoded §2.1 maintain-request. `raw` preserves the original params data
/// byte-for-byte for the backoff continuation's re-EXECUTE (byte fidelity —
/// never decode+re-encode what rides the graph).
#[derive(Debug, Clone)]
struct MaintainParams {
    peer_id: String,
    address: Option<String>,
    reconnect: bool,
    resubscribe: bool,
    backoff: BackoffCfg,
    raw: Vec<u8>,
}

struct SessionState {
    params: MaintainParams,
    /// FALLBACK episode start (ms since epoch; `None` = not failing) for
    /// the derived §2.2 pacing. The AUTHORITATIVE stamp is the §3.13
    /// status entity's `failing_since`, written by the demotion seam and
    /// read back from the tree — that is the copy that survives a
    /// restart, and the one [`NetworkHandler::retry_state`] prefers.
    ///
    /// This exists because a peer that never connected has no demotion
    /// transition to stamp: a failed DIAL writes no status entity (only
    /// a transport error on an established connection does). Without a
    /// local stamp, its pacing would restart from `min_ms` on every
    /// attempt. Whether a failed dial against a MAINTAINED peer should
    /// itself write a §3.13 demotion is a real cross-impl question —
    /// logged in `docs/SPEC-AMBIGUITIES.md`; the Go seat routed the same
    /// question (`docs/validation/spec-issues/`
    /// `2026-07-16-failing-since-never-connected.md`) and holds this same
    /// interim. Until it is ruled, this keeps the never-connected curve
    /// growing without inventing a write site.
    failing_since: Option<u64>,
    /// Monotonic token for pending backoff timers: a fired timer whose
    /// captured epoch is stale (superseded schedule or teardown) bails.
    sched_epoch: u64,
    subscription_ids: Vec<String>,
    graph_installed: bool,
    /// The remote's identity hash — the status-path key. Derived from
    /// the `peer_id` at session creation (see
    /// [`identity_hash_from_peer_id`]), so the §3.13 status entity is
    /// readable with no live connection; re-confirmed from the binding
    /// on each successful establish. `None` only for a SHA-256-form
    /// `peer_id` that has never connected — its key isn't derivable
    /// from the string.
    remote_hash: Option<Hash>,
}

/// One maintained peer relationship (in-memory per §12.4; the continuation
/// graph and subscriptions live in the tree).
struct Session {
    peer_id: String,
    session_id: String,
    chain_id: String,
    state: Mutex<SessionState>,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// The `system/network` handler (§3.1).
pub struct NetworkHandler {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    local_peer_id: String,
    qualified_pattern: String,
    link: RwLock<Option<Arc<dyn PeerLink>>>,
    /// Weak self-handle for timer tasks (set by [`bind`](Self::bind)).
    self_weak: RwLock<Weak<NetworkHandler>>,
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    /// §6.7.4 per-requester budget for `observe-address`.
    reflect_limiter: ReflectLimiter,
}

/// A per-requester token budget over a fixed window (§6.7.4).
///
/// Deliberately crude: reflection is a mirror, so the limit exists to bound
/// amplification rather than to meter a resource. The numbers are local and
/// interoperate with nothing — §6.7.4 makes `network-reflect` a broad default
/// grant precisely because the operation is cheap and leaks nothing the caller
/// did not already tell us by connecting.
struct ReflectLimiter {
    window_ms: u64,
    max_per_window: u32,
    seen: Mutex<HashMap<String, (u64, u32)>>,
}

impl ReflectLimiter {
    fn new() -> Self {
        Self {
            window_ms: 1_000,
            max_per_window: 20,
            seen: Mutex::new(HashMap::new()),
        }
    }

    fn allow(&self, requester: &str) -> bool {
        let now = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let mut seen = self.seen.lock().unwrap();
        let entry = seen.entry(requester.to_string()).or_insert((now, 0));
        if now.saturating_sub(entry.0) >= self.window_ms {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= self.max_per_window
    }
}

impl NetworkHandler {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
    ) -> Self {
        let qualified_pattern = format!("/{}/{}", local_peer_id, HANDLER_PATTERN);
        Self {
            content_store,
            location_index,
            local_peer_id,
            qualified_pattern,
            reflect_limiter: ReflectLimiter::new(),
            link: RwLock::new(None),
            self_weak: RwLock::new(Weak::new()),
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Wire the imperative seam. Called once by the peer at engine start
    /// (post-construction, same wiring order as the subscription engine's
    /// delivery function); operations 500 until bound.
    pub fn bind(self: &Arc<Self>, link: Arc<dyn PeerLink>) {
        *self.link.write().unwrap() = Some(link);
        *self.self_weak.write().unwrap() = Arc::downgrade(self);
    }

    fn link(&self) -> Option<Arc<dyn PeerLink>> {
        self.link.read().unwrap().clone()
    }

    fn get_session(&self, peer_id: &str) -> Option<Arc<Session>> {
        self.sessions.lock().unwrap().get(peer_id).cloned()
    }

    /// Returns the session for `peer_id`, creating it if absent; the bool
    /// reports whether it already existed.
    fn get_or_create_session(&self, peer_id: &str, params: MaintainParams) -> (Arc<Session>, bool) {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(s) = sessions.get(peer_id) {
            return (s.clone(), true);
        }
        let session_id = new_session_id();
        let session = Arc::new(Session {
            peer_id: peer_id.to_string(),
            // §3.11: a chain_id is a SINGLE path segment — it IS a segment of
            // the §3.10.6 marker path .../lost/{chain_id}/{step_index}/...,
            // so §4.1's literal "network/maintain/{sid}" forks the marker tree
            // into extra levels. The value is opaque (nothing parses it).
            chain_id: format!("network-maintain-{}", session_id),
            session_id,
            state: Mutex::new(SessionState {
                params,
                failing_since: None,
                sched_epoch: 0,
                subscription_ids: Vec::new(),
                graph_installed: false,
                // Derived from the peer_id, NOT waited for from an
                // establish: a session created beside an already-failing
                // peer must be able to read the tree's `failing_since`
                // on its very first retry — including in a process that
                // restarted and has never seen this peer connect.
                remote_hash: identity_hash_from_peer_id(peer_id),
            }),
        });
        sessions.insert(peer_id.to_string(), session.clone());
        (session, false)
    }

    /// Removes and returns the session; a pending backoff timer that fires
    /// afterwards finds no (or a different) session and bails.
    fn drop_session(&self, peer_id: &str) -> Option<Arc<Session>> {
        self.sessions.lock().unwrap().remove(peer_id)
    }

    // --- §4.1 graph paths (qualified — location-index keys) ---------------

    fn on_disconnect_path(&self, peer_id: &str) -> String {
        format!(
            "/{}/system/inbox/network/{}/on-disconnect",
            self.local_peer_id, peer_id
        )
    }

    fn on_reconnect_path(&self, peer_id: &str) -> String {
        format!(
            "/{}/system/inbox/network/{}/on-reconnect",
            self.local_peer_id, peer_id
        )
    }

    fn backoff_path(&self, peer_id: &str) -> String {
        format!(
            "/{}/system/network/peers/{}/on-reconnect-backoff",
            self.local_peer_id, peer_id
        )
    }

    fn inbox_prefix(&self, peer_id: &str) -> String {
        format!("/{}/system/inbox/network/{}/", self.local_peer_id, peer_id)
    }

    fn managed_prefix(&self, peer_id: &str) -> String {
        format!("/{}/system/network/peers/{}/", self.local_peer_id, peer_id)
    }

    fn status_path(&self, remote_hash: &Hash) -> String {
        format!(
            "/{}/system/peer/status/{}",
            self.local_peer_id,
            remote_hash.to_hex()
        )
    }

    /// The handler's own grant hash (`system/capability/grants/system/
    /// network`, minted at bootstrap from `internal_scope`). Prefer the
    /// dispatch context's value; fall back to the tree binding for
    /// contexts assembled without it.
    fn handler_grant_hash(&self, ctx: &HandlerContext) -> Option<Hash> {
        ctx.handler_grant_hash.or_else(|| {
            self.location_index.get(&format!(
                "/{}/system/capability/grants/{}",
                self.local_peer_id, HANDLER_PATTERN
            ))
        })
    }

    /// Current §3.13 status value for a maintained peer, if recorded.
    fn read_peer_status(&self, session: &Session) -> Option<String> {
        let remote_hash = session.state.lock().unwrap().remote_hash?;
        let hash = self.location_index.get(&self.status_path(&remote_hash))?;
        let entity = self.content_store.get(&hash)?;
        decode_text_field(&entity.data, "status")
    }

    /// The §3.13 status entity's `failing_since` for a maintained peer —
    /// the authoritative, restart-surviving episode start.
    fn read_failing_since(&self, session: &Session) -> Option<u64> {
        let remote_hash = session.state.lock().unwrap().remote_hash?;
        let hash = self.location_index.get(&self.status_path(&remote_hash))?;
        let entity = self.content_store.get(&hash)?;
        decode_uint_field(&entity.data, "failing_since")
    }

    /// Derive the §2.2 pacing for the session's current failure episode
    /// as of `now_ms`, and report the episode start it used.
    ///
    /// Nothing counts attempts. The episode start is the only state, and
    /// the TREE's `failing_since` wins when present: it is durable, so a
    /// process that restarts beside a long-dead peer re-derives a large
    /// attempt count and a max-length wait instead of redialing in
    /// `min_ms`. The session's own stamp is only the fallback for a peer
    /// that never connected (see [`SessionState::failing_since`]).
    ///
    /// Returns `None` for the episode start when no episode is on record
    /// anywhere — a caller that has just observed a failure and finds
    /// none is starting one.
    fn retry_state(&self, session: &Session, now_ms: u64) -> (RetryState, Option<u64>) {
        let failing_since = self
            .read_failing_since(session)
            .or_else(|| session.state.lock().unwrap().failing_since);
        let cfg = session.state.lock().unwrap().params.backoff.clone();
        (
            derive_retry_state(&cfg, failing_since, now_ms),
            failing_since,
        )
    }
}

/// The §3.13 status-path key for a remote peer, derived from its
/// `peer_id` alone (Go `types.ComputePeerIdentityHashFromPeerID`).
///
/// A PURE derivation, deliberately: the status path must be resolvable
/// with no live connection and no prior establish, because the whole
/// point of the durable `failing_since` stamp is that a process which
/// restarts beside a long-dead peer can read back the episode it never
/// witnessed. Keying the path off a pooled binding (`identity_hash_of`)
/// would make the stamp readable only while connected — precisely when
/// it isn't needed.
///
/// `None` for a SHA-256-form `peer_id`, which is a fingerprint: the
/// public key must come from a separate exchange, so the hash is not
/// derivable from the string.
fn identity_hash_from_peer_id(peer_id: &str) -> Option<Hash> {
    let (public_key, key_type_byte) = entity_crypto::PeerId::from(peer_id).derive_public_key()?;
    let key_type = entity_crypto::KeyType::from_byte(key_type_byte).ok()?;
    entity_crypto::peer_identity_hash_with_key_type(&public_key, key_type).ok()
}

fn new_session_id() -> String {
    format!("{:016x}", rand::random::<u64>())
}

/// Monotonic-ish discriminator for handler-named request ids (ruling 9 /
/// F1 — a dispatch needs a real id, not a name for its category).
fn now_nanos() -> u128 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Handler trait impl
// ---------------------------------------------------------------------------

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for NetworkHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        match ctx.operation.as_str() {
            "maintain-peer" => self.handle_maintain_peer(ctx).await,
            "release-peer" => self.handle_release_peer(ctx).await,
            "status" => self.handle_status(ctx).await,
            "close" => self.handle_close(ctx).await,
            "reconnect" => self.handle_reconnect(ctx).await,
            "restore-subscriptions" => self.handle_restore_subscriptions(ctx).await,
            OP_OBSERVE_ADDRESS => self.handle_observe_address(ctx).await,
            other => Ok(error_result(
                STATUS_BAD_REQUEST,
                "unknown_operation",
                &format!("network handler does not support operation: {}", other),
            )),
        }
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "network"
    }

    fn operations(&self) -> &[&str] {
        // The four §3.1 operations plus the internal operations the §4.1
        // graph dispatches (`reconnect`, `restore-subscriptions`) — §A5:
        // advertise what you dispatch. `restore-subscriptions` is
        // dispatched by the spec's own pseudocode yet missing from the
        // spec's §3.1 manifest (Go spec-issue item 3, corroborated here).
        &[
            "maintain-peer",
            "release-peer",
            "status",
            "close",
            "reconnect",
            "restore-subscriptions",
        ]
    }

    /// §3.1 `internal_scope`, extended with the two entries the §4.1 graph
    /// needs at advance time (Go spec-issue item 3: the spec's own scope
    /// block cannot authorize the graph it specifies). Per §11 the
    /// continuations' `dispatch_capability` is this handler's grant, so the
    /// grant must cover the EXECUTEs the graph performs: `system/network`
    /// reconnect / maintain-peer / restore-subscriptions, and the paced
    /// `system/continuation` advance.
    fn internal_scope(&self) -> Option<Vec<entity_capability::GrantEntry>> {
        let path_scope = |paths: &[&str]| {
            entity_capability::PathScope::new(paths.iter().map(|s| s.to_string()).collect())
        };
        let id_scope = |ids: &[&str]| {
            entity_capability::IdScope::new(ids.iter().map(|s| s.to_string()).collect())
        };
        Some(vec![
            // §3.1 block.
            entity_capability::GrantEntry {
                handlers: path_scope(&["system/tree"]),
                resources: path_scope(&["system/*"]),
                operations: id_scope(&["get", "put"]),
                peers: None,
                constraints: None,
                allowances: None,
            },
            entity_capability::GrantEntry {
                handlers: path_scope(&["system/subscription"]),
                resources: path_scope(&["system/*"]),
                operations: id_scope(&["subscribe", "unsubscribe"]),
                peers: None,
                constraints: None,
                allowances: None,
            },
            entity_capability::GrantEntry {
                handlers: path_scope(&["system/protocol/connect"]),
                resources: path_scope(&["*"]),
                operations: id_scope(&["hello", "authenticate"]),
                peers: None,
                constraints: None,
                allowances: None,
            },
            // Graph-authorization additions (spec-issue item 3).
            entity_capability::GrantEntry {
                handlers: path_scope(&[HANDLER_PATTERN]),
                resources: path_scope(&[
                    HANDLER_PATTERN,
                    "system/network/*",
                    "system/inbox/network/*",
                ]),
                operations: id_scope(&[
                    "maintain-peer",
                    "release-peer",
                    "status",
                    "close",
                    "reconnect",
                    "restore-subscriptions",
                    OP_OBSERVE_ADDRESS,
                ]),
                peers: None,
                constraints: None,
                allowances: None,
            },
            entity_capability::GrantEntry {
                handlers: path_scope(&["system/continuation"]),
                resources: path_scope(&["system/network/*", "system/inbox/network/*"]),
                operations: id_scope(&["advance"]),
                peers: None,
                constraints: None,
                allowances: None,
            },
        ])
    }
}

// ---------------------------------------------------------------------------
// maintain-peer (§4.1) + the internal graph operations
// ---------------------------------------------------------------------------

impl NetworkHandler {
    /// §4.1 maintain-peer: connect if needed, install the reconnect
    /// lifecycle continuation graph + lifecycle subscriptions, return
    /// session info.
    ///
    /// Ordering nuance vs the §4.1 pseudocode (connect first, 502 with no
    /// graph on failure): that holds for the FIRST imperative call. On a
    /// re-entry for an existing session (the backoff continuation
    /// re-EXECUTing maintain-peer after a failed reconnect), a connect
    /// failure must NOT strand the retry loop — the one-shot backoff
    /// continuation is re-installed and the next delayed advance scheduled
    /// before the 502 returns.
    async fn handle_maintain_peer(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let Some(link) = self.link() else {
            return Ok(error_result(
                STATUS_INTERNAL_ERROR,
                "internal_error",
                "network handler not bound to a peer",
            ));
        };
        // Accept the declared §2.1 input type AND primitive/any: the
        // backoff continuation's re-EXECUTE arrives as primitive/any
        // (continuation params assembly is untyped); shape validation is
        // the decode below.
        if ctx.params.entity_type != TYPE_MAINTAIN_REQUEST
            && ctx.params.entity_type != "primitive/any"
        {
            return Ok(error_result(
                STATUS_BAD_REQUEST,
                "invalid_params",
                &format!(
                    "maintain-peer params must be {}, got {}",
                    TYPE_MAINTAIN_REQUEST, ctx.params.entity_type
                ),
            ));
        }
        let params = match decode_maintain_request(&ctx.params.data) {
            Ok(p) => p,
            Err(e) => {
                return Ok(error_result(
                    STATUS_BAD_REQUEST,
                    "invalid_params",
                    &format!("decode maintain-request: {}", e),
                ));
            }
        };
        if params.peer_id.is_empty() {
            return Ok(error_result(
                STATUS_BAD_REQUEST,
                "invalid_params",
                "maintain-request requires peer_id",
            ));
        }
        if params.peer_id == self.local_peer_id {
            return Ok(error_result(
                STATUS_BAD_REQUEST,
                "invalid_params",
                "cannot maintain a relationship with self",
            ));
        }
        let peer_id = params.peer_id.clone();
        let reconnect_enabled = params.reconnect;
        let resubscribe_enabled = params.resubscribe;
        let address = params.address.clone();

        let (session, existed) = self.get_or_create_session(&peer_id, params.clone());

        // 1. Connect if needed (§4.1 step 1). The establish path writes
        // the §3.13 `connected` status + connection entity and pool insert
        // starts keepalive — §4.1 steps 2 and 5 are ambient in core/peer;
        // the handler adds no second write or loop (§A4).
        match link.ensure_connected(&peer_id, address.as_deref()).await {
            Ok(conn) => {
                let mut st = session.state.lock().unwrap();
                // Recovery ends the failure episode. The establish path
                // already cleared the TREE's stamp (the `connected` write
                // omits it); this clears the never-connected fallback, so
                // the next episode starts a fresh curve rather than
                // resuming this one.
                st.failing_since = None;
                st.params = params;
                st.remote_hash = Some(conn.identity_hash);
            }
            Err(e) => {
                if existed && reconnect_enabled {
                    // Re-entry from the backoff continuation: keep the
                    // retry loop alive — re-arm the standing resident and
                    // schedule the next derived advance.
                    if let Err(arm_err) = self.arm_backoff_retry(ctx, &session, &link) {
                        tracing::warn!(
                            peer = %peer_id,
                            error = %arm_err,
                            "maintain-peer: re-arm backoff failed"
                        );
                    }
                    // 200, not 502 (arch ruling 2). maintain-peer's contract
                    // is MAINTAIN, not "connect now": with the retry armed the
                    // operation did what it promises — the relationship is
                    // being kept alive, and the peer being unreachable this
                    // instant is the condition it exists to handle, not a
                    // failure of it.
                    //
                    // 502 here also made the backoff continuation's own
                    // re-EXECUTE look like a failed chain dispatch, so the
                    // engine bound a lost marker per retry: an error record
                    // for the retry loop working correctly. With ruling 3's
                    // `on_error` on the on-disconnect trigger, this is the
                    // other half of taking a dead peer's marker tree to empty.
                    //
                    // No `status` field on the result — that would rebuild the
                    // connected/disconnected mirror §3.13 already owns.
                    tracing::debug!(
                        peer = %peer_id,
                        error = %e,
                        "maintain-peer: unreachable, retry armed — 200 (maintain, not connect-now)"
                    );
                    return self.maintain_result(&session);
                }
                if !existed {
                    // First imperative call failed — no session, no graph
                    // (§4.1 step 1's 502 contract).
                    self.drop_session(&peer_id);
                }
                // 502 stands for `reconnect: false`, where "connect now" IS
                // the whole contract and there is no retry to succeed later.
                return Ok(error_result(
                    STATUS_BAD_GATEWAY,
                    "connection_failed",
                    &format!("connect to {}: {}", peer_id, e),
                ));
            }
        }

        // 2–4. Install the continuation graph + lifecycle subscriptions
        // once per session (continuation re-puts are content-idempotent;
        // subscriptions must not accumulate).
        let graph_needed = !session.state.lock().unwrap().graph_installed;
        if graph_needed {
            let Some(grant_hash) = self.handler_grant_hash(ctx) else {
                return Ok(error_result(
                    STATUS_INTERNAL_ERROR,
                    "internal_error",
                    "network handler grant not bound",
                ));
            };
            if reconnect_enabled {
                if let Err(e) = self.install_reconnect_continuations(&session, grant_hash) {
                    return Ok(error_result(STATUS_INTERNAL_ERROR, "storage_error", &e));
                }
            }
            if resubscribe_enabled {
                if let Err(e) = self.install_resubscribe_continuation(&session, grant_hash) {
                    return Ok(error_result(STATUS_INTERNAL_ERROR, "storage_error", &e));
                }
            }
            let remote_hash = session
                .state
                .lock()
                .unwrap()
                .remote_hash
                .expect("remote_hash set on establish");
            let mut sub_ids = Vec::new();
            if reconnect_enabled {
                match self
                    .subscribe_lifecycle(&link, &remote_hash, &self.on_disconnect_path(&peer_id))
                    .await
                {
                    Ok(id) => sub_ids.push(id),
                    Err(e) => {
                        return Ok(error_result(STATUS_INTERNAL_ERROR, "internal_error", &e));
                    }
                }
            }
            if resubscribe_enabled {
                match self
                    .subscribe_lifecycle(&link, &remote_hash, &self.on_reconnect_path(&peer_id))
                    .await
                {
                    Ok(id) => sub_ids.push(id),
                    Err(e) => {
                        return Ok(error_result(STATUS_INTERNAL_ERROR, "internal_error", &e));
                    }
                }
            }
            let mut st = session.state.lock().unwrap();
            st.subscription_ids = sub_ids;
            st.graph_installed = true;
        }

        // 6. Session info (§2.4).
        self.maintain_result(&session)
    }

    /// The §2.4 `maintain-result`. Returned by BOTH maintain-peer exits that
    /// keep the relationship: a live establish, and an armed re-entry against
    /// an unreachable peer (ruling 2 — the contract is maintain, not
    /// connect-now, so both are 200 and both describe the same session).
    ///
    /// There is deliberately no `status` field: that would rebuild the
    /// connected/disconnected mirror §3.13 already owns.
    fn maintain_result(&self, session: &Session) -> Result<HandlerResult, HandlerError> {
        let sub_ids = session.state.lock().unwrap().subscription_ids.clone();
        let result_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("chain_id"),
                entity_ecf::text(&session.chain_id),
            ),
            (
                entity_ecf::text("peer_id"),
                entity_ecf::text(&session.peer_id),
            ),
            (
                entity_ecf::text("session_id"),
                entity_ecf::text(&session.session_id),
            ),
            (
                entity_ecf::text("subscriptions"),
                entity_ecf::Value::Array(sub_ids.iter().map(entity_ecf::text).collect()),
            ),
        ]));
        let result = Entity::new(TYPE_MAINTAIN_RESULT, result_data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        Ok(HandlerResult::ok(result))
    }

    /// Internal operation the on-disconnect continuation dispatches. The
    /// lifecycle subscription fires on EVERY status transition (including
    /// the establish's own `connected` write), so the operation
    /// self-guards: already-connected is a 200 no-op (Go spec-issue item
    /// 2's fix shape).
    async fn handle_reconnect(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        let Some(link) = self.link() else {
            return Ok(error_result(
                STATUS_INTERNAL_ERROR,
                "internal_error",
                "network handler not bound to a peer",
            ));
        };
        let peer_id = match decode_text_field(&ctx.params.data, "peer_id") {
            Some(p) if !p.is_empty() => p,
            _ => {
                return Ok(error_result(
                    STATUS_BAD_REQUEST,
                    "invalid_params",
                    "params require peer_id",
                ));
            }
        };
        let Some(session) = self.get_session(&peer_id) else {
            return Ok(error_result(
                STATUS_NOT_FOUND,
                "not_found",
                &format!("no maintain session for peer {}", peer_id),
            ));
        };

        if self.read_peer_status(&session).as_deref() == Some("connected") {
            return outcome_result("already-connected");
        }

        let (address, reconnect_enabled) = {
            let st = session.state.lock().unwrap();
            (st.params.address.clone(), st.params.reconnect)
        };
        match link.ensure_connected(&peer_id, address.as_deref()).await {
            Ok(_) => {
                // Recovery ends the failure episode (see maintain-peer's
                // establish branch).
                session.state.lock().unwrap().failing_since = None;
                outcome_result("reconnected")
            }
            Err(e) => {
                // Schedule the paced retry, then surface 502 — the
                // advancing continuation has no on_error, so this binds
                // the §3.10 lost-error marker (reason `connection_failed`,
                // keyed by RequestID) as the observability record.
                if reconnect_enabled {
                    if let Err(arm_err) = self.arm_backoff_retry(ctx, &session, &link) {
                        tracing::warn!(
                            peer = %peer_id,
                            error = %arm_err,
                            "reconnect: arm backoff failed"
                        );
                    }
                }
                Ok(error_result(
                    STATUS_BAD_GATEWAY,
                    "connection_failed",
                    &format!("reconnect to {}: {}", peer_id, e),
                ))
            }
        }
    }

    /// Internal §7.2 operation the on-reconnect continuation dispatches.
    /// Guarded on connected (the subscription also fires on demotions).
    ///
    /// Scope (rung 3, cohort-converged): the §7.2 FIRST half only —
    /// re-validate the deliver tokens of tree-resident subscriptions whose
    /// delivery targets the reconnected peer, dropping dead ones. The
    /// second half (re-subscribing on the REMOTE) needs a local record of
    /// outbound subscriptions no spec defines (Go spec-issue item 6, arch
    /// call pending) — skipped, not papered over.
    async fn handle_restore_subscriptions(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let _ = ctx;
        let Some(link) = self.link() else {
            return Ok(error_result(
                STATUS_INTERNAL_ERROR,
                "internal_error",
                "network handler not bound to a peer",
            ));
        };
        let peer_id = match decode_text_field(&ctx.params.data, "peer_id") {
            Some(p) if !p.is_empty() => p,
            _ => {
                return Ok(error_result(
                    STATUS_BAD_REQUEST,
                    "invalid_params",
                    "params require peer_id",
                ));
            }
        };
        let Some(session) = self.get_session(&peer_id) else {
            return Ok(error_result(
                STATUS_NOT_FOUND,
                "not_found",
                &format!("no maintain session for peer {}", peer_id),
            ));
        };
        if self.read_peer_status(&session).as_deref() != Some("connected") {
            return restore_result(0, 0, "not-connected");
        }

        let now_ms = now_ms();
        let mut retained: u64 = 0;
        let mut dropped: u64 = 0;
        let sub_prefix = format!("/{}/system/subscription/", self.local_peer_id);
        for entry in self.location_index.list(&sub_prefix) {
            let Some(sub_entity) = self.content_store.get(&entry.hash) else {
                continue;
            };
            if sub_entity.entity_type != "system/subscription" {
                continue;
            }
            let Some(deliver_uri) = decode_text_field(&sub_entity.data, "deliver_uri") else {
                continue;
            };
            if !delivery_targets_peer(&deliver_uri, &peer_id) {
                continue;
            }
            let token_alive = decode_hash_field(&sub_entity.data, "deliver_token")
                .and_then(|h| self.content_store.get(&h))
                .map(|token| {
                    // Expired-during-disconnect check (§7.2): absent
                    // expires_at = non-expiring.
                    decode_uint_field(&token.data, "expires_at")
                        .map(|exp| exp >= now_ms)
                        .unwrap_or(true)
                })
                .unwrap_or(false);
            if token_alive {
                retained += 1;
                continue;
            }
            // Token expired or missing during the disconnect — the
            // subscription is dead (§7.2); remove it so the engine stops
            // attempting it.
            if let Some(sub_id) = decode_text_field(&sub_entity.data, "subscription_id") {
                match self.unsubscribe(&link, &sub_id).await {
                    Ok(()) => dropped += 1,
                    Err(e) => {
                        tracing::warn!(
                            peer = %peer_id,
                            subscription = %sub_id,
                            error = %e,
                            "restore-subscriptions: drop failed"
                        );
                    }
                }
            }
        }
        restore_result(retained, dropped, "restored")
    }

    // --- graph installation (§11: handler-authorized managed-namespace
    //     binds; dispatch_capability = the handler grant — the F2 pattern)

    /// Writes the on-disconnect standing continuation (inbox resident —
    /// the lifecycle subscription's delivery target) and the one-shot
    /// backoff continuation (managed-namespace resident — advanced only by
    /// the handler's delayed self-advance, never via `system/inbox/*`).
    fn install_reconnect_continuations(
        &self,
        session: &Arc<Session>,
        grant_hash: Hash,
    ) -> Result<(), String> {
        let st = session.state.lock().unwrap();
        let peer_id = session.peer_id.clone();
        let mut reconnect_fields = vec![(entity_ecf::text("peer_id"), entity_ecf::text(&peer_id))];
        if let Some(addr) = &st.params.address {
            reconnect_fields.push((entity_ecf::text("address"), entity_ecf::text(addr)));
        }
        let raw = st.params.raw.clone();
        drop(st);
        let reconnect_params = entity_ecf::to_ecf(&entity_ecf::Value::Map(reconnect_fields));

        // Standing on-disconnect trigger (result_field null, remaining null),
        // carrying an `on_error` to the backoff seam (arch ruling 3).
        //
        // Without it, a failed `reconnect` is a non-2xx with no `on_error`,
        // so the engine binds a §3.10 lost-error marker per attempt — ~1,440
        // nodes/day against a peer that stays dead, for a failure that is
        // entirely expected and already handled. That was a category error:
        // the marker is for EXCEPTIONAL failure, and the fix belongs at the
        // source rather than in the marker's retention policy. A dead peer's
        // marker tree is now empty.
        //
        // Routing an `on_error` at `system/inbox/*` is correct here per ruling
        // 4 precisely because the error is MEANT to drive the next step: this
        // failure IS the retry trigger. The trap that guidance guards against
        // is unintended advancement; a chain-errors sink is for passive
        // observation, which this is not.
        let backoff_path = self.backoff_path(&peer_id);
        self.bind_continuation(
            session,
            &self.on_disconnect_path(&peer_id),
            "reconnect",
            reconnect_params,
            Some((backoff_path.as_str(), "advance")),
            grant_hash,
        )?;
        // Standing backoff resident re-EXECUTing maintain-peer with the
        // session's original request bytes (arch ruling 1).
        //
        // Was one-shot per §4.1's literal, which stalled the retry loop at 2
        // attempts on all three seats: a one-shot cannot re-arm itself, because
        // the re-install lands inside the dispatch while the advance's consume
        // runs after it and deletes the path. Ordering, not timing. Standing is
        // coherent for Rust for the same reason it is for Go — the execution
        // count was never our pacing authority; `schedule_backoff_advance`'s
        // derived §2.2 timer is, and the continuation is only the dispatch
        // vehicle it advances. Nothing consumes it, so nothing races to
        // re-create it. Residency is bounded by the session: `release-peer`
        // deletes the graph.
        self.bind_continuation(
            session,
            &self.backoff_path(&peer_id),
            "maintain-peer",
            raw,
            None,
            grant_hash,
        )
    }

    /// Writes the standing on-reconnect continuation dispatching the
    /// internal restore-subscriptions operation (§4.1 step 3 / §7).
    fn install_resubscribe_continuation(
        &self,
        session: &Arc<Session>,
        grant_hash: Hash,
    ) -> Result<(), String> {
        let peer_id = session.peer_id.clone();
        let restore_params = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("peer_id"),
            entity_ecf::text(&peer_id),
        )]));
        self.bind_continuation(
            session,
            &self.on_reconnect_path(&peer_id),
            "restore-subscriptions",
            restore_params,
            None,
            grant_hash,
        )
    }

    /// Stores a `system/continuation` entity and binds it at `path` via a
    /// handler-authorized write. The bind's `ExecutionContext` carries the
    /// W6 attribution (handler grant authorized this write).
    /// Every continuation in the §4.1 graph is STANDING
    /// (`remaining_executions` absent — arch ruling 1), so this takes no
    /// execution count: there is no longer a caller that wants one, and a
    /// one-shot cannot survive this graph anyway (the re-install lands inside
    /// the dispatch while the advance's consume runs after it).
    fn bind_continuation(
        &self,
        session: &Session,
        path: &str,
        operation: &str,
        params_bytes: Vec<u8>,
        on_error: Option<(&str, &str)>,
        grant_hash: Hash,
    ) -> Result<(), String> {
        let mut fields = vec![
            (
                entity_ecf::text("dispatch_capability"),
                entity_ecf::Value::Bytes(grant_hash.to_bytes().to_vec()),
            ),
            (entity_ecf::text("operation"), entity_ecf::text(operation)),
            (
                entity_ecf::text("params"),
                entity_ecf::Value::Bytes(params_bytes),
            ),
            (
                entity_ecf::text("resource"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("targets"),
                    entity_ecf::Value::Array(vec![entity_ecf::text(HANDLER_PATTERN)]),
                )]),
            ),
            (
                entity_ecf::text("target"),
                entity_ecf::text(HANDLER_PATTERN),
            ),
        ];
        // §3.5 `on_error` is a bare `system/delivery-spec` map — a typed
        // struct field, not an entity wrapper.
        if let Some((uri, operation)) = on_error {
            fields.push((
                entity_ecf::text("on_error"),
                entity_ecf::Value::Map(vec![
                    (entity_ecf::text("operation"), entity_ecf::text(operation)),
                    (entity_ecf::text("uri"), entity_ecf::text(uri)),
                ]),
            ));
        }
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
        let entity = Entity::new("system/continuation", data)
            .map_err(|e| format!("build continuation for {}: {}", path, e))?;
        let hash = self
            .content_store
            .put(entity)
            .map_err(|e| format!("store continuation for {}: {}", path, e))?;
        let bind_ctx = ExecutionContext {
            chain_id: Some(session.chain_id.clone()),
            capability: Some(grant_hash),
            handler_grant: Some(grant_hash),
            handler_pattern: Some(HANDLER_PATTERN.to_string()),
            operation: Some("maintain-peer".to_string()),
            ..Default::default()
        };
        self.location_index.set_with_context(path, hash, bind_ctx);
        Ok(())
    }

    /// Creates one lifecycle subscription on the remote's status path
    /// delivering to `deliver_uri`, via a self-authored subscribe (the
    /// subscriptions are the PEER's own — release-peer unsubscribes them).
    async fn subscribe_lifecycle(
        &self,
        link: &Arc<dyn PeerLink>,
        remote_hash: &Hash,
        deliver_uri: &str,
    ) -> Result<String, String> {
        let (token, token_sig, identity) = link.mint_deliver_token(deliver_uri)?;
        let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("deliver_to"),
                entity_ecf::Value::Map(vec![
                    (entity_ecf::text("operation"), entity_ecf::text("receive")),
                    (entity_ecf::text("uri"), entity_ecf::text(deliver_uri)),
                ]),
            ),
            (
                entity_ecf::text("deliver_token"),
                entity_ecf::Value::Bytes(token.content_hash.to_bytes().to_vec()),
            ),
            // The floor's demotion/establish writes are same-path
            // overwrites — every transition surfaces as "updated" (the
            // first-ever write as "created", covered too).
            (
                entity_ecf::text("events"),
                entity_ecf::Value::Array(vec![
                    entity_ecf::text("created"),
                    entity_ecf::text("updated"),
                ]),
            ),
        ]));
        let params = Entity::new("system/subscription/subscribe-params", params_data)
            .map_err(|e| format!("build subscribe params: {}", e))?;
        let opts = ExecuteOptions {
            resource: Some(entity_capability::ResourceTarget {
                targets: vec![self.status_path(remote_hash)],
                exclude: Vec::new(),
            }),
            included: vec![token, token_sig, identity],
            ..Default::default()
        };
        let res = link
            .self_execute("system/subscription", "subscribe", params, opts)
            .await
            .map_err(|e| format!("lifecycle subscribe: {}", e))?;
        if res.status != STATUS_OK {
            return Err(format!(
                "lifecycle subscribe returned {}: {}",
                res.status,
                decode_text_field(&res.result.data, "code").unwrap_or_default()
            ));
        }
        decode_text_field(&res.result.data, "subscription_id")
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "lifecycle subscribe result carried no subscription_id".to_string())
    }

    async fn unsubscribe(
        &self,
        link: &Arc<dyn PeerLink>,
        subscription_id: &str,
    ) -> Result<(), String> {
        let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("subscription_id"),
            entity_ecf::text(subscription_id),
        )]));
        let params = Entity::new("system/subscription/cancel", params_data)
            .map_err(|e| format!("build unsubscribe params: {}", e))?;
        let res = link
            .self_execute(
                "system/subscription",
                "unsubscribe",
                params,
                ExecuteOptions::default(),
            )
            .await
            .map_err(|e| e.to_string())?;
        if res.status != STATUS_OK {
            return Err(format!(
                "unsubscribe {} returned {}",
                subscription_id, res.status
            ));
        }
        Ok(())
    }

    // --- §2.2 backoff pacing (derived; impl-internal timer) ---------------

    /// Re-installs the standing backoff continuation (idempotent — the
    /// advance no longer consumes it, ruling 1) and schedules its delayed
    /// advance per the session's §2.2 backoff config.
    fn arm_backoff_retry(
        &self,
        ctx: &HandlerContext,
        session: &Arc<Session>,
        link: &Arc<dyn PeerLink>,
    ) -> Result<(), String> {
        let Some(grant_hash) = self.handler_grant_hash(ctx) else {
            return Err("network handler grant not bound".to_string());
        };
        let raw = session.state.lock().unwrap().params.raw.clone();
        // No `on_error` on the backoff resident itself: it re-EXECUTEs
        // maintain-peer, whose own failure branch re-arms and reschedules.
        // Routing its error back to `advance` would fire the next retry
        // immediately and defeat the §2.2 pacing this exists to apply.
        self.bind_continuation(
            session,
            &self.backoff_path(&session.peer_id),
            "maintain-peer",
            raw,
            None,
            grant_hash,
        )?;
        self.schedule_backoff_advance(session, link);
        Ok(())
    }

    /// The §2.2 give-up (ruling 6): an OPTIONAL bound was reached, so stop
    /// retrying and write the terminal `disconnected` + `retry-exhausted`
    /// status.
    ///
    /// The write matters as much as the stopping. Without it the loop simply
    /// goes quiet and the peer's last status stays `suspect` forever — a
    /// relationship that has been abandoned but still looks like one that is
    /// trying, which is the worst of both readings for whoever is looking.
    ///
    /// Only reachable when a caller opted into a bound; retry-forever is the
    /// normative default.
    fn abandon_relationship(
        &self,
        session: &Arc<Session>,
        link: &Arc<dyn PeerLink>,
        state: &RetryState,
        failing_since: u64,
    ) {
        // Supersede any pending timer: a fired advance after this point would
        // retry a relationship we just recorded as abandoned.
        session.state.lock().unwrap().sched_epoch += 1;
        tracing::debug!(
            peer = %session.peer_id,
            attempt = state.attempt,
            failing_since,
            "reconnect: giving up after {} attempt(s) — §2.2 retry bound reached",
            state.attempt,
        );
        let Some(remote_hash) = session.state.lock().unwrap().remote_hash else {
            // No status-path key (a SHA-256-form peer_id that never
            // connected): nothing to write the terminal status against.
            return;
        };
        link.write_retry_exhausted(&session.peer_id, &remote_hash, failing_since);
    }

    /// At the DERIVED next-attempt time, self-advance the backoff
    /// continuation, which one-shot re-EXECUTEs maintain-peer. The
    /// advance is a self-authored EXECUTE — no request context is alive
    /// when the timer fires. A fired timer whose session was released (or
    /// superseded by a newer schedule) bails on the epoch check.
    ///
    /// The schedule is DERIVED, not counted (§2.2 / §A4, rulings 7/8):
    /// the next attempt is a pure function of (`failing_since`, cfg,
    /// now), so nothing here increments and nothing is written per
    /// attempt. Opening an episode stamps `failing_since` once, which is
    /// what a later restart re-reads.
    fn schedule_backoff_advance(&self, session: &Arc<Session>, link: &Arc<dyn PeerLink>) {
        let now = now_ms();
        let (mut state, failing_since) = self.retry_state(session, now);
        let failing_since = match failing_since {
            Some(fs) => fs,
            None => {
                // No episode on record anywhere: this failure opens one.
                // Stamping it here (rather than counting) is what makes
                // the delay grow across attempts — every later attempt
                // re-derives from this instant.
                session.state.lock().unwrap().failing_since = Some(now);
                state = self.retry_state(session, now).0;
                now
            }
        };

        // The §2.2 give-up, if the caller opted into a bound (ruling 6).
        // Derived like the pacing, so nothing had to remember to record that
        // we gave up. Never taken under the default config, which is
        // retry-forever.
        let Some(next_attempt_at) = state.next_attempt_at else {
            self.abandon_relationship(session, link, &state, failing_since);
            return;
        };

        let delay_ms = next_attempt_at.saturating_sub(now);
        let epoch = {
            let mut st = session.state.lock().unwrap();
            st.sched_epoch += 1;
            st.sched_epoch
        };
        tracing::debug!(
            peer = %session.peer_id,
            attempt = state.attempt,
            failing_since,
            delay_ms,
            "reconnect: attempt failed, scheduling derived backoff retry"
        );
        let weak = self.self_weak.read().unwrap().clone();
        let link_for_task = link.clone();
        let session_for_task = session.clone();
        let backoff_path = self.backoff_path(&session.peer_id);
        link.schedule(
            delay_ms,
            Box::pin(async move {
                let Some(handler) = weak.upgrade() else {
                    return;
                };
                // Session released or replaced while the timer was pending?
                let current = handler.get_session(&session_for_task.peer_id);
                let still_current = current
                    .map(|c| Arc::ptr_eq(&c, &session_for_task))
                    .unwrap_or(false);
                if !still_current {
                    return;
                }
                if session_for_task.state.lock().unwrap().sched_epoch != epoch {
                    return; // superseded by a newer schedule
                }
                let advance_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                    entity_ecf::text("result"),
                    entity_ecf::Value::Bytes(entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![]))),
                )]));
                let Ok(advance_params) =
                    Entity::new("system/continuation/advance-request", advance_data)
                else {
                    return;
                };
                // Ruling 11: this dispatch belongs to a known chain — the
                // session's — so the handler MUST say so rather than let the
                // advance mint a fresh one per attempt. Without it, each
                // retry's marker lands under a different {chain_id} and the
                // tree forks once per attempt instead of carrying one node
                // per relationship.
                // The handler can name its own dispatch better than the
                // seam's fallback can (ruling 9 / F1) — this is the retry's
                // step, so `{step_index}` should say so. Mirrors Go's
                // `network-{operation}-{nanos}` (`ext/network/wiring.go`).
                let opts = ExecuteOptions {
                    resource: Some(entity_capability::ResourceTarget {
                        targets: vec![backoff_path.clone()],
                        exclude: Vec::new(),
                    }),
                    request_id: Some(format!("network-backoff-advance-{}", now_nanos())),
                    bounds: Some(entity_handler::Bounds {
                        chain_id: Some(session_for_task.chain_id.clone()),
                        ..Default::default()
                    }),
                    ..Default::default()
                };
                match link_for_task
                    .self_execute("system/continuation", "advance", advance_params, opts)
                    .await
                {
                    Ok(r) if r.status != STATUS_OK => {
                        tracing::debug!(
                            peer = %session_for_task.peer_id,
                            status = r.status,
                            "backoff advance returned non-200"
                        );
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::debug!(
                            peer = %session_for_task.peer_id,
                            error = %e,
                            "backoff advance dispatch failed"
                        );
                    }
                }
            }),
        );
    }
}

// ---------------------------------------------------------------------------
// release-peer (§4.2), status (§4.3), close (§4.4)
// ---------------------------------------------------------------------------

impl NetworkHandler {
    /// §4.2 release-peer: tear down the lifecycle graph and, on
    /// `reason=shutdown`, close the connection with a terminal
    /// `disconnected` write.
    async fn handle_release_peer(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let Some(link) = self.link() else {
            return Ok(error_result(
                STATUS_INTERNAL_ERROR,
                "internal_error",
                "network handler not bound to a peer",
            ));
        };
        if ctx.params.entity_type != TYPE_RELEASE_REQUEST {
            return Ok(error_result(
                STATUS_BAD_REQUEST,
                "invalid_params",
                &format!(
                    "release-peer params must be {}, got {}",
                    TYPE_RELEASE_REQUEST, ctx.params.entity_type
                ),
            ));
        }
        let peer_id = match decode_text_field(&ctx.params.data, "peer_id") {
            Some(p) if !p.is_empty() => p,
            _ => {
                return Ok(error_result(
                    STATUS_BAD_REQUEST,
                    "invalid_params",
                    "release-request requires peer_id",
                ));
            }
        };
        let reason = decode_text_field(&ctx.params.data, "reason")
            .filter(|r| !r.is_empty())
            .unwrap_or_else(|| "shutdown".to_string());

        // Forget the session first — a backoff timer firing mid-teardown
        // finds no session and bails.
        let session = self.drop_session(&peer_id);

        // Remove the lifecycle continuations — the inbox residents and the
        // managed-namespace backoff resident. Real tree deletion (the §4.2
        // pseudocode's `put null`); deletion markers are the tree layer's
        // concern.
        let mut cleaned_up: Vec<String> = Vec::new();
        for prefix in [self.inbox_prefix(&peer_id), self.managed_prefix(&peer_id)] {
            for entry in self.location_index.list(&prefix) {
                if self.location_index.remove(&entry.path).is_some() {
                    cleaned_up.push(entry.path.clone());
                }
            }
        }

        // Remove the lifecycle subscriptions (self-owned — unsubscribe
        // rides the peer's own identity).
        if let Some(session) = &session {
            let sub_ids = session.state.lock().unwrap().subscription_ids.clone();
            for id in sub_ids {
                if let Err(e) = self.unsubscribe(&link, &id).await {
                    tracing::warn!(peer = %peer_id, subscription = %id, error = %e,
                        "release-peer: unsubscribe failed");
                }
            }
        }

        // Close the connection on shutdown; idle/migration leave it (and
        // any subscriptions) for potential resumption (§4.2).
        if reason == "shutdown" {
            let remote_hash = session
                .as_ref()
                .and_then(|s| s.state.lock().unwrap().remote_hash)
                .or_else(|| link.identity_hash_of(&peer_id));
            link.evict(&peer_id);
            if let Some(hash) = remote_hash {
                // Terminal §3.13 write: this relationship is deliberately
                // over — eviction alone would leave the last transition
                // value standing.
                link.write_released(&peer_id, &hash);
            }
        }

        let result_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("cleaned_up"),
                entity_ecf::Value::Array(cleaned_up.iter().map(entity_ecf::text).collect()),
            ),
            (entity_ecf::text("peer_id"), entity_ecf::text(&peer_id)),
        ]));
        let result = Entity::new(TYPE_RELEASE_RESULT, result_data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        Ok(HandlerResult::ok(result))
    }

    /// §4.3 status: a read-model over the §3.13 `system/peer/status`
    /// entities plus session bookkeeping. `pending_count` is bare zero
    /// throughout — Rust ships no §8 outbox (Amendment 11: the bare-error
    /// terminal is conformant; rung 4 stays optional).
    /// §6.7.1 `observe-address` — tell the caller the source address we see it at.
    ///
    /// The entire mechanism is: when A connects to R, R can see the source
    /// `IP:port` its transport reported, and that observed source **is** A's
    /// public NAT mapping. R telling A what it saw is the whole thing.
    ///
    /// # The three MUSTs, and where each one lives
    ///
    /// 1. **The transport source, never a body echo.** The address comes from
    ///    [`accept_source::current`] and the request body is never read — the
    ///    operation declares no input type at all. A body-supplied address would
    ///    make this peer a laundering service that will attest to an attacker's
    ///    chosen address, and it is the same amplification seam §6.7.2 closes on
    ///    the dial-back side. *A body carrying a plausible `observed_address` is
    ///    therefore ignored, not honored — the test asserts exactly that.*
    /// 2. **Never persisted.** Nothing here writes. The observed source is read
    ///    from the live connection, encoded into the result, and dropped. It is
    ///    a *responder-side* fact, and every durable address in this protocol is
    ///    *dialer-side dialable-endpoint* state; writing an ephemeral source port
    ///    into `system/connection.address` or a transport profile produces a
    ///    routable-looking value that routes nowhere, which §10 dispatch and
    ///    `system/peer/status` then consume as dialable.
    /// 3. **Per socket.** Not enforceable here — it binds the *caller*, which
    ///    must punch from the socket it gathered on (§6.7.3). This peer simply
    ///    reports what it saw, which is what makes the caller's violation
    ///    detectable at all.
    ///
    /// # No live connection is a refusal, not a guess
    ///
    /// An in-process dispatch has no observable transport source. Returning the
    /// loopback address, or the caller's advertised one, would be inventing the
    /// single fact this operation exists to report — so it is a 400.
    async fn handle_observe_address(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        // §6.7.4: rate-limited per requester. Reflection is cheap to serve and
        // cheap to abuse as an amplifier, and the grant is deliberately broad.
        let requester = ctx
            .session_peer_id
            .clone()
            .unwrap_or_else(|| "<local>".to_string());
        if !self.reflect_limiter.allow(&requester) {
            return Ok(error_result(
                429,
                "rate_limited",
                "observe-address is rate-limited per requester (§6.7.4)",
            ));
        }

        let Some(observed) = accept_source::current() else {
            return Ok(error_result(
                STATUS_BAD_REQUEST,
                "no_transport_source",
                "observe-address requires a live accepted connection; there is no observable \
                 transport source for an in-process dispatch",
            ));
        };

        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("observed_address"),
            entity_ecf::text(&observed),
        )]));
        let result = Entity::new(TYPE_OBSERVE_ADDRESS_RESULT, data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        Ok(HandlerResult::ok(result))
    }

    async fn handle_status(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        let _ = ctx;
        // Subscription counts per delivery peer, one scan (§2.8: active
        // subscriptions delivering TO that peer).
        let mut sub_counts: HashMap<String, u64> = HashMap::new();
        let sub_prefix = format!("/{}/system/subscription/", self.local_peer_id);
        for entry in self.location_index.list(&sub_prefix) {
            let Some(sub_entity) = self.content_store.get(&entry.hash) else {
                continue;
            };
            if sub_entity.entity_type != "system/subscription" {
                continue;
            }
            if let Some(uri) = decode_text_field(&sub_entity.data, "deliver_uri") {
                if let Some(pid) = peer_from_deliver_uri(&uri) {
                    *sub_counts.entry(pid).or_insert(0) += 1;
                }
            }
        }

        let mut peers: Vec<entity_ecf::Value> = Vec::new();
        let status_prefix = format!("/{}/system/peer/status/", self.local_peer_id);
        for entry in self.location_index.list(&status_prefix) {
            let Some(status_entity) = self.content_store.get(&entry.hash) else {
                continue;
            };
            if status_entity.entity_type != "system/peer/status" {
                continue;
            }
            let Some(peer_id) = decode_text_field(&status_entity.data, "peer_id") else {
                continue;
            };
            let Some(status) = decode_text_field(&status_entity.data, "status") else {
                continue;
            };
            let session_id = self
                .get_session(&peer_id)
                .map(|s| s.session_id.clone())
                .unwrap_or_default();
            let subs = sub_counts.get(&peer_id).copied().unwrap_or(0);
            peers.push(entity_ecf::Value::Map(vec![
                (entity_ecf::text("peer_id"), entity_ecf::text(&peer_id)),
                (entity_ecf::text("pending_count"), entity_ecf::integer(0)),
                (
                    entity_ecf::text("session_id"),
                    entity_ecf::text(&session_id),
                ),
                (entity_ecf::text("status"), entity_ecf::text(&status)),
                (
                    entity_ecf::text("subscriptions"),
                    entity_ecf::integer(subs as i64),
                ),
            ]));
        }

        let result_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("maintained_peers"),
                entity_ecf::Value::Array(peers),
            ),
            (entity_ecf::text("pending_count"), entity_ecf::integer(0)),
        ]));
        let result = Entity::new(TYPE_NETWORK_STATUS, result_data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        Ok(HandlerResult::ok(result))
    }

    /// §4.4 close: best-effort remote notification, then the local §3.13
    /// close transition. Subscription disposition follows the reason
    /// (§9.1); locally there is nothing to delete on either branch —
    /// release-peer owns lifecycle teardown.
    async fn handle_close(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        let Some(link) = self.link() else {
            return Ok(error_result(
                STATUS_INTERNAL_ERROR,
                "internal_error",
                "network handler not bound to a peer",
            ));
        };
        if ctx.params.entity_type != TYPE_CLOSE_REQUEST {
            return Ok(error_result(
                STATUS_BAD_REQUEST,
                "invalid_params",
                &format!(
                    "close params must be {}, got {}",
                    TYPE_CLOSE_REQUEST, ctx.params.entity_type
                ),
            ));
        }
        let peer_id = decode_text_field(&ctx.params.data, "peer_id").unwrap_or_default();
        let reason = decode_text_field(&ctx.params.data, "reason").unwrap_or_default();
        if peer_id.is_empty() || reason.is_empty() {
            return Ok(error_result(
                STATUS_BAD_REQUEST,
                "invalid_params",
                "close-request requires peer_id and reason",
            ));
        }

        // Snapshot the identity hash BEFORE eviction (the pool is the only
        // resolver for a peer we never maintained).
        let remote_hash = self
            .get_session(&peer_id)
            .and_then(|s| s.state.lock().unwrap().remote_hash)
            .or_else(|| link.identity_hash_of(&peer_id));

        // Best-effort remote close notification (§9.2). The cohort's
        // connect handlers predate a `close` operation — an
        // unknown_operation error (or a dead transport) must not block the
        // local close.
        if link.is_connected(&peer_id) {
            let close_uri = format!("entity://{}/system/protocol/connect", peer_id);
            if let Err(e) = link
                .self_execute(
                    &close_uri,
                    "close",
                    ctx.params.clone(),
                    ExecuteOptions::default(),
                )
                .await
            {
                tracing::debug!(peer = %peer_id, error = %e,
                    "close: remote notification failed (best-effort)");
            }
        }

        // Local transition: evict the pooled binding (keepalive loop exits
        // on its next tick) and record the §3.13 close.
        link.evict(&peer_id);
        if let Some(hash) = remote_hash {
            link.mark_connection_closed(&hash);
        }

        let result_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("closed"), entity_ecf::bool_val(true)),
            (entity_ecf::text("reason"), entity_ecf::text(&reason)),
        ]));
        let result = Entity::new("primitive/any", result_data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        Ok(HandlerResult::ok(result))
    }
}

// ---------------------------------------------------------------------------
// Decode / result helpers
// ---------------------------------------------------------------------------

fn decode_maintain_request(data: &[u8]) -> Result<MaintainParams, String> {
    let val: ciborium::Value =
        ciborium::from_reader(data).map_err(|e| format!("decode params: {}", e))?;
    let map = val.as_map().ok_or("params not a map")?;

    let mut params = MaintainParams {
        peer_id: String::new(),
        address: None,
        reconnect: true,
        resubscribe: true,
        backoff: BackoffCfg::default(),
        raw: data.to_vec(),
    };
    for (k, v) in map {
        match k.as_text() {
            Some("peer_id") => {
                params.peer_id = v.as_text().unwrap_or("").to_string();
            }
            Some("address") => {
                params.address = v.as_text().map(|s| s.to_string()).filter(|s| !s.is_empty());
            }
            Some("reconnect") => {
                if let ciborium::Value::Bool(b) = v {
                    params.reconnect = *b;
                }
            }
            Some("resubscribe") => {
                if let ciborium::Value::Bool(b) = v {
                    params.resubscribe = *b;
                }
            }
            Some("backoff") => {
                if let Some(bmap) = v.as_map() {
                    for (bk, bv) in bmap {
                        match bk.as_text() {
                            Some("min_ms") => {
                                if let Some(n) = bv.as_integer() {
                                    params.backoff.min_ms = i128::from(n) as u64;
                                }
                            }
                            Some("max_ms") => {
                                if let Some(n) = bv.as_integer() {
                                    params.backoff.max_ms = i128::from(n) as u64;
                                }
                            }
                            Some("strategy") => {
                                if let Some(s) = bv.as_text() {
                                    params.backoff.strategy = s.to_string();
                                }
                            }
                            // The OPTIONAL §2.2 give-up bounds (ruling 6).
                            // Absent ⇒ retry-forever, which is the normative
                            // default: a peer offline for a week and coming
                            // back is the P2P norm.
                            Some("max_attempts") => {
                                if let Some(n) = bv.as_integer() {
                                    params.backoff.max_attempts = u64::try_from(n).ok();
                                }
                            }
                            Some("max_elapsed_ms") => {
                                if let Some(n) = bv.as_integer() {
                                    params.backoff.max_elapsed_ms = u64::try_from(n).ok();
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            // `keepalive` override: carried in `raw` for the re-EXECUTE;
            // effective keepalive values are impl-defined (§12.4) and
            // configured per-peer at build time in this impl.
            _ => {}
        }
    }
    Ok(params)
}

fn decode_text_field(data: &[u8], field: &str) -> Option<String> {
    let val: ciborium::Value = ciborium::from_reader(data).ok()?;
    let map = val.as_map()?;
    map.iter()
        .find(|(k, _)| k.as_text() == Some(field))
        .and_then(|(_, v)| v.as_text().map(|s| s.to_string()))
}

fn decode_uint_field(data: &[u8], field: &str) -> Option<u64> {
    let val: ciborium::Value = ciborium::from_reader(data).ok()?;
    let map = val.as_map()?;
    map.iter()
        .find(|(k, _)| k.as_text() == Some(field))
        .and_then(|(_, v)| v.as_integer())
        .map(|n| i128::from(n) as u64)
}

fn decode_hash_field(data: &[u8], field: &str) -> Option<Hash> {
    let val: ciborium::Value = ciborium::from_reader(data).ok()?;
    let map = val.as_map()?;
    map.iter()
        .find(|(k, _)| k.as_text() == Some(field))
        .and_then(|(_, v)| match v {
            ciborium::Value::Bytes(b) => Hash::from_bytes(b).ok(),
            _ => None,
        })
}

/// Whether a subscription's deliver URI routes to the given remote peer
/// (§7.2: `entity://{peer_id}/...`).
fn delivery_targets_peer(deliver_uri: &str, peer_id: &str) -> bool {
    deliver_uri.starts_with(&format!("entity://{}/", peer_id))
        || deliver_uri == format!("entity://{}", peer_id)
}

/// Extracts the peer id from an `entity://{peer}/...` URI.
fn peer_from_deliver_uri(uri: &str) -> Option<String> {
    let rest = uri.strip_prefix("entity://")?;
    if rest.is_empty() {
        return None;
    }
    match rest.find('/') {
        Some(i) if i > 0 => Some(rest[..i].to_string()),
        Some(_) => None,
        None => Some(rest.to_string()),
    }
}

fn outcome_result(outcome: &str) -> Result<HandlerResult, HandlerError> {
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
        entity_ecf::text("outcome"),
        entity_ecf::text(outcome),
    )]));
    let result =
        Entity::new("primitive/any", data).map_err(|e| HandlerError::Internal(e.to_string()))?;
    Ok(HandlerResult::ok(result))
}

fn restore_result(
    retained: u64,
    dropped: u64,
    outcome: &str,
) -> Result<HandlerResult, HandlerError> {
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (
            entity_ecf::text("dropped"),
            entity_ecf::integer(dropped as i64),
        ),
        (entity_ecf::text("outcome"), entity_ecf::text(outcome)),
        (
            entity_ecf::text("retained"),
            entity_ecf::integer(retained as i64),
        ),
    ]));
    let result =
        Entity::new("primitive/any", data).map_err(|e| HandlerError::Internal(e.to_string()))?;
    Ok(HandlerResult::ok(result))
}

fn error_result(status: u32, code: &str, message: &str) -> HandlerResult {
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (entity_ecf::text("code"), entity_ecf::text(code)),
        (entity_ecf::text("message"), entity_ecf::text(message)),
    ]));
    let result = Entity::new(entity_types::TYPE_ERROR, data).expect("error entity");
    HandlerResult {
        status,
        result,
        included: HashMap::new(),
    }
}

fn now_ms() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ---------------------------------------------------------------------------
// Unit vectors (the two-peer lifecycle vectors live in core/peer, which can
// compose the full reactive stack; an extension crate cannot import the peer)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // §6.7.1 observe-address — the responder half.
    //
    // The operation reflects a TRANSPORT fact, so what has to be pinned
    // is not the encoding but where the address is allowed to come from.
    // Both failures these guard against are silent: a body echo returns a
    // perfectly well-formed result carrying an attacker's address, and an
    // in-process guess returns a well-formed result carrying a fiction.
    // -----------------------------------------------------------------

    fn reflect_handler() -> NetworkHandler {
        let store = Arc::new(entity_store::MemoryContentStore::new());
        let index = Arc::new(entity_store::MemoryLocationIndex::new());
        NetworkHandler::new(store, index, "TestPeer".to_string())
    }

    fn observe_ctx(params: Entity) -> HandlerContext {
        let execute = Entity::new("system/protocol/execute", vec![0xa0]).unwrap();
        entity_handler::HandlerContext::builder(execute, params)
            .pattern(HANDLER_PATTERN)
            .operation(OP_OBSERVE_ADDRESS)
            .session_peer_id("CallerPeer")
            .build()
    }

    fn observed_of(result: &HandlerResult) -> Option<String> {
        decode_text_field(&result.result.data, "observed_address")
    }

    /// The happy path: the address reported is the one the accept-side
    /// channel carries, and the result is the §6.7.1 type.
    #[tokio::test]
    async fn reflects_the_transport_source_of_this_connection() {
        let h = reflect_handler();
        let out = accept_source::scope("203.0.113.7:51820".to_string(), async {
            h.handle(&observe_ctx(observe_address_params().unwrap()))
                .await
                .unwrap()
        })
        .await;
        assert_eq!(out.status, STATUS_OK);
        assert_eq!(out.result.entity_type, TYPE_OBSERVE_ADDRESS_RESULT);
        assert_eq!(observed_of(&out).as_deref(), Some("203.0.113.7:51820"));
    }

    /// **MUST 1 — the body is never echoed.** A request carrying a
    /// plausible `observed_address` must be ignored, not honored.
    ///
    /// Honoring it turns this peer into a laundering service: an attacker
    /// asks it to attest to an address of their choosing and hands the
    /// signed-looking answer to a third party. It is the same
    /// amplification seam §6.7.2 closes on the dial-back side, and the
    /// give-away is that a body echo passes every same-impl round-trip
    /// test — encoder and decoder agree, and the value is simply wrong.
    #[tokio::test]
    async fn a_body_supplied_address_is_ignored_not_reflected() {
        let h = reflect_handler();
        let attacker = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("observed_address"),
            entity_ecf::text("198.51.100.66:31337"),
        )]));
        let params = Entity::new("system/network/observe-address-request", attacker).unwrap();

        let out = accept_source::scope("203.0.113.7:51820".to_string(), async {
            h.handle(&observe_ctx(params)).await.unwrap()
        })
        .await;
        assert_eq!(out.status, STATUS_OK);
        assert_eq!(
            observed_of(&out).as_deref(),
            Some("203.0.113.7:51820"),
            "the reflected address MUST be the transport source, never the body's claim \
             (§6.7.1 MUST 1) — a peer that echoes this attests to any address it is handed"
        );
    }

    /// An in-process dispatch has no observable transport source, and
    /// §6.7.1's answer to that is a refusal.
    ///
    /// The tempting alternatives — loopback, or the caller's advertised
    /// address — both invent the one fact this operation exists to
    /// report, and a caller cannot tell an invented mapping from a real
    /// one until its punch silently fails.
    #[tokio::test]
    async fn no_live_connection_is_a_refusal_not_a_guess() {
        let h = reflect_handler();
        let out = h
            .handle(&observe_ctx(observe_address_params().unwrap()))
            .await
            .unwrap();
        assert_eq!(out.status, STATUS_BAD_REQUEST);
        assert_eq!(
            decode_text_field(&out.result.data, "code").as_deref(),
            Some("no_transport_source")
        );
    }

    /// **MUST 2 — never persisted.** The observation is returned and
    /// dropped; nothing durable is written.
    ///
    /// An observed source is a *responder-side* fact, while every durable
    /// address in this protocol is *dialer-side dialable-endpoint* state.
    /// The cheap fix — writing it to `system/connection.address` — stores
    /// an ephemeral source port where §10 dispatch and
    /// `system/peer/status` both read a dialable address, so it corrupts
    /// routing for every other reader.
    #[tokio::test]
    async fn the_observation_is_never_written_to_the_tree() {
        let store = Arc::new(entity_store::MemoryContentStore::new());
        let index = Arc::new(entity_store::MemoryLocationIndex::new());
        let h = NetworkHandler::new(store.clone(), index.clone(), "TestPeer".to_string());
        let before = index.list("/").len();

        let out = accept_source::scope("203.0.113.7:51820".to_string(), async {
            h.handle(&observe_ctx(observe_address_params().unwrap()))
                .await
                .unwrap()
        })
        .await;
        assert_eq!(out.status, STATUS_OK);
        assert_eq!(
            index.list("/").len(),
            before,
            "observe-address MUST NOT persist the observed address anywhere (§6.7.1 MUST 2)"
        );
    }

    /// §6.7.4: reflection is rate-limited per requester. Cheap to serve,
    /// cheap to abuse as an amplifier, and the grant is deliberately broad.
    #[tokio::test]
    async fn reflection_is_rate_limited_per_requester() {
        let h = reflect_handler();
        let statuses = accept_source::scope("203.0.113.7:51820".to_string(), async {
            let mut out = Vec::new();
            for _ in 0..40 {
                out.push(
                    h.handle(&observe_ctx(observe_address_params().unwrap()))
                        .await
                        .unwrap()
                        .status,
                );
            }
            out
        })
        .await;
        assert!(statuses.contains(&STATUS_OK));
        assert!(
            statuses.contains(&429),
            "a requester past the §6.7.4 budget must be refused, not served"
        );
    }

    fn cfg(min_ms: u64, max_ms: u64, strategy: &str) -> BackoffCfg {
        BackoffCfg {
            min_ms,
            max_ms,
            strategy: strategy.to_string(),
            ..Default::default()
        }
    }

    // ---------------------------------------------------------------
    // The §2.2 retry pacing, as a vector table (rulings 7/8).
    //
    // `derive_retry_state` is a pure function of (failing_since, backoff
    // config, now), so the whole surface tests as data: no peers, no
    // sockets, no timing flake. These vectors are also the convergence
    // artifact — the shape a sibling impl reproduces is a table of
    // inputs and outputs, not a prose description of a state machine.
    // Ported from the Go seat's `core/types/network_backoff_test.go`,
    // which is the pinned table; the two must agree value-for-value.
    //
    // Semantics pinned here (the rulings, in executable form):
    //   - k is 1-INDEXED: delay(1) is the wait before the FIRST retry.
    //   - attempt counts retries FIRED — 0 in the gap between the
    //     failure and the first retry coming due.
    //   - elapsed_to(0) = 0.
    //   - The boundary is INCLUSIVE: at exactly elapsed_to(k), retry k
    //     has fired.
    //   - No jitter in v1: same inputs, same outputs, always.
    // ---------------------------------------------------------------

    /// An arbitrary but realistic `failing_since` (ms since epoch). The
    /// derivation only ever uses `now - failing_since`, so the absolute
    /// value is immaterial — it is fixed so a failure prints a stable
    /// number.
    const FS_BASE: u64 = 1_700_000_000_000;

    /// The §2.2 default config: exponential, min 1s, max 60s.
    /// Delays:     1s, 2s, 4s, 8s, 16s, 32s, 60s (capped), 60s, …
    /// elapsed_to: 1s, 3s, 7s, 15s, 31s, 63s, 123s, 183s, …
    fn default_backoff() -> BackoffCfg {
        BackoffCfg::default()
    }

    fn strategy_cfg(strategy: &str, min_ms: u64) -> BackoffCfg {
        BackoffCfg {
            min_ms,
            strategy: strategy.to_string(),
            ..Default::default()
        }
    }

    /// `delay(k)` across every strategy, clamp, and overflow edge.
    #[test]
    fn a12_backoff_delay_vectors() {
        let d = default_backoff();
        let cases: Vec<(&str, BackoffCfg, u64, u64)> = vec![
            ("default k=0 is no wait", d.clone(), 0, 0),
            ("default k=1 is min", d.clone(), 1, 1000),
            ("default k=2 doubles", d.clone(), 2, 2000),
            ("default k=3 doubles", d.clone(), 3, 4000),
            ("default k=6 doubles", d.clone(), 6, 32000),
            ("default k=7 clamps at max", d.clone(), 7, 60000),
            ("default k=8 stays clamped", d.clone(), 8, 60000),
            ("default k=100 stays clamped", d.clone(), 100, 60000),
            (
                "constant ignores k",
                strategy_cfg("constant", 5000),
                1,
                5000,
            ),
            (
                "constant ignores k (later)",
                strategy_cfg("constant", 5000),
                9,
                5000,
            ),
            ("linear k=1", strategy_cfg("linear", 1000), 1, 1000),
            ("linear k=3", strategy_cfg("linear", 1000), 3, 3000),
            (
                "linear clamps at max",
                strategy_cfg("linear", 1000),
                100,
                60000,
            ),
            // A config with max < min is not a licence to wait less than
            // min: max is raised to min, so the delay is min flat.
            ("inverted min/max yields min", cfg(5000, 1000, ""), 1, 5000),
            ("inverted min/max stays min", cfg(5000, 1000, ""), 5, 5000),
            // Saturating arithmetic: a huge k must not wrap into a small
            // delay.
            (
                "linear cannot overflow into a short delay",
                cfg(u64::MAX / 2, u64::MAX, "linear"),
                4,
                u64::MAX,
            ),
            (
                "exponential cannot overflow into a short delay",
                cfg(u64::MAX / 2, u64::MAX, "exponential"),
                4,
                u64::MAX,
            ),
            ("degenerate zero min", cfg(0, 0, ""), 3, 0),
        ];
        for (name, c, k, want) in cases {
            assert_eq!(backoff_delay_ms(&c, k), want, "{name}: delay({k})");
        }
    }

    /// One `derive_retry_state` vector: (name, cfg, failing_since, now,
    /// want_attempt, want_next_attempt_at).
    type PacingVector = (&'static str, BackoffCfg, Option<u64>, u64, u64, Option<u64>);

    /// `derive_retry_state` across the default curve, each strategy, the
    /// restart-hammering case, and the edges.
    #[test]
    fn a12_derive_retry_state_vectors() {
        let d = default_backoff();
        let cases: Vec<PacingVector> = vec![
            // --- the default curve; elapsed_to = 1s,3s,7s,15s,31s,63s,123s
            (
                "at the failure, nothing has fired",
                d.clone(),
                Some(FS_BASE),
                FS_BASE,
                0,
                Some(FS_BASE + 1000),
            ),
            (
                "1ms before the first retry",
                d.clone(),
                Some(FS_BASE),
                FS_BASE + 999,
                0,
                Some(FS_BASE + 1000),
            ),
            (
                "exactly at the first retry (inclusive)",
                d.clone(),
                Some(FS_BASE),
                FS_BASE + 1000,
                1,
                Some(FS_BASE + 3000),
            ),
            (
                "between first and second",
                d.clone(),
                Some(FS_BASE),
                FS_BASE + 2999,
                1,
                Some(FS_BASE + 3000),
            ),
            (
                "exactly at the second",
                d.clone(),
                Some(FS_BASE),
                FS_BASE + 3000,
                2,
                Some(FS_BASE + 7000),
            ),
            // The worked example from derive_retry_state's doc comment.
            (
                "worked example: 5s elapsed",
                d.clone(),
                Some(FS_BASE),
                FS_BASE + 5000,
                2,
                Some(FS_BASE + 7000),
            ),
            (
                "exactly at the third",
                d.clone(),
                Some(FS_BASE),
                FS_BASE + 7000,
                3,
                Some(FS_BASE + 15000),
            ),
            (
                "exactly at the sixth",
                d.clone(),
                Some(FS_BASE),
                FS_BASE + 63000,
                6,
                Some(FS_BASE + 123000),
            ),
            // Crossing into the plateau: delay(7) is the first clamped delay.
            (
                "exactly at the seventh, on the plateau",
                d.clone(),
                Some(FS_BASE),
                FS_BASE + 123000,
                7,
                Some(FS_BASE + 183000),
            ),
            (
                "mid-plateau",
                d.clone(),
                Some(FS_BASE),
                FS_BASE + 150000,
                7,
                Some(FS_BASE + 183000),
            ),
            // --- constant: elapsed_to = 5s, 10s, 15s, …
            (
                "constant, before the first",
                strategy_cfg("constant", 5000),
                Some(FS_BASE),
                FS_BASE + 4999,
                0,
                Some(FS_BASE + 5000),
            ),
            (
                "constant, two fired",
                strategy_cfg("constant", 5000),
                Some(FS_BASE),
                FS_BASE + 12000,
                2,
                Some(FS_BASE + 15000),
            ),
            // --- linear: delays 1s,2s,3s,4s,5s → elapsed_to = 1s,3s,6s,10s,15s
            (
                "linear, three fired",
                strategy_cfg("linear", 1000),
                Some(FS_BASE),
                FS_BASE + 9999,
                3,
                Some(FS_BASE + 10000),
            ),
            (
                "linear, four fired (inclusive)",
                strategy_cfg("linear", 1000),
                Some(FS_BASE),
                FS_BASE + 10000,
                4,
                Some(FS_BASE + 15000),
            ),
            // --- THE restart-hammering vector.
            //
            // A peer dead for 30 days. The point is the derived delay:
            // the next retry is one max-length (60s) interval out, NOT
            // min_ms. An in-memory attempt counter reset by the restart
            // would redial in 1s here and keep doing so forever — which
            // is the bug this whole design deletes.
            //
            // elapsed_to(7) = 123000 (last pre-plateau), then 60s/retry:
            //   extra   = (2592000000 - 123000) / 60000 = 43197
            //   attempt = 7 + 43197                     = 43204
            //   cum     = 123000 + 43197*60000          = 2591943000
            //   next    = FS_BASE + 2591943000 + 60000
            (
                "a peer dead for 30 days resumes the curve, it does not hammer",
                d.clone(),
                Some(FS_BASE),
                FS_BASE + 2592000000,
                43204,
                Some(FS_BASE + 2592003000),
            ),
            // --- the OPTIONAL §2.2 bounds, while still within them:
            // pacing is unaffected. Reaching them is the exhaustion
            // table's job.
            (
                "max_attempts not yet reached",
                BackoffCfg {
                    max_attempts: Some(3),
                    ..Default::default()
                },
                Some(FS_BASE),
                FS_BASE + 3000,
                2,
                Some(FS_BASE + 7000),
            ),
            (
                "max_elapsed_ms not yet reached",
                BackoffCfg {
                    max_elapsed_ms: Some(10000),
                    ..Default::default()
                },
                Some(FS_BASE),
                FS_BASE + 3000,
                2,
                Some(FS_BASE + 7000),
            ),
            // --- edges
            (
                "no episode: failing_since unset",
                d.clone(),
                None,
                FS_BASE + 5000,
                0,
                None,
            ),
            (
                "clock skew: now before failing_since",
                d.clone(),
                Some(FS_BASE),
                FS_BASE - 10000,
                0,
                Some(FS_BASE + 1000),
            ),
            (
                "degenerate zero delay is always due, never counted",
                cfg(0, 0, ""),
                Some(FS_BASE),
                FS_BASE + 100000,
                0,
                Some(FS_BASE),
            ),
        ];
        for (name, c, failing_since, now, want_attempt, want_next) in cases {
            let got = derive_retry_state(&c, failing_since, now);
            assert_eq!(got.attempt, want_attempt, "{name}: attempt");
            assert_eq!(got.next_attempt_at, want_next, "{name}: next_attempt_at");
        }
    }

    /// The OPTIONAL §2.2 give-up bounds. Retry-forever is the normative
    /// default, so the headline vector is the one proving the default
    /// never gives up: a peer dead for a year is still retrying.
    #[test]
    fn a12_derive_retry_state_exhaustion_vectors() {
        const YEAR: u64 = 365 * 24 * 60 * 60 * 1000;
        let attempts = |n: u64| BackoffCfg {
            max_attempts: Some(n),
            ..Default::default()
        };
        let elapsed = |n: u64| BackoffCfg {
            max_elapsed_ms: Some(n),
            ..Default::default()
        };
        // (name, cfg, now, want_exhausted, want_attempt)
        let cases: Vec<(&str, BackoffCfg, u64, bool, u64)> = vec![
            // Delays 1s,2s,4s,8s…; elapsed_to 1s,3s,7s,15s,31s…
            // 525604 = the 7 pre-plateau retries + (year - 123s)/60s at
            // the cap. The number is incidental; `exhausted` staying
            // false is the point.
            (
                "default config never exhausts, even after a year",
                default_backoff(),
                FS_BASE + YEAR,
                false,
                525604,
            ),
            (
                "max_attempts=3, two fired",
                attempts(3),
                FS_BASE + 3000,
                false,
                2,
            ),
            (
                "max_attempts=3, exactly three fired",
                attempts(3),
                FS_BASE + 7000,
                true,
                3,
            ),
            // elapsed_to(5)=31s <= 60s < elapsed_to(6)=63s, so 5 fired.
            (
                "max_attempts=3, well past",
                attempts(3),
                FS_BASE + 60000,
                true,
                5,
            ),
            (
                "max_attempts=0 gives up immediately",
                attempts(0),
                FS_BASE,
                true,
                0,
            ),
            (
                "max_elapsed_ms=10s, before",
                elapsed(10000),
                FS_BASE + 9999,
                false,
                3,
            ),
            (
                "max_elapsed_ms=10s, exactly at (inclusive)",
                elapsed(10000),
                FS_BASE + 10000,
                true,
                3,
            ),
            (
                "max_elapsed_ms=10s, past",
                elapsed(10000),
                FS_BASE + 11000,
                true,
                3,
            ),
            // Whichever bound trips first wins.
            (
                "both set, attempts trips first",
                BackoffCfg {
                    max_attempts: Some(2),
                    max_elapsed_ms: Some(600000),
                    ..Default::default()
                },
                FS_BASE + 3000,
                true,
                2,
            ),
            (
                "both set, elapsed trips first",
                BackoffCfg {
                    max_attempts: Some(99),
                    max_elapsed_ms: Some(5000),
                    ..Default::default()
                },
                FS_BASE + 5000,
                true,
                2,
            ),
        ];
        for (name, c, now, want_exhausted, want_attempt) in cases {
            let got = derive_retry_state(&c, Some(FS_BASE), now);
            assert_eq!(got.exhausted, want_exhausted, "{name}: exhausted");
            assert_eq!(got.attempt, want_attempt, "{name}: attempt");
            // An exhausted episode has no next attempt: a Some here
            // would have the caller schedule a retry it just decided
            // not to make.
            if got.exhausted {
                assert_eq!(
                    got.next_attempt_at, None,
                    "{name}: exhausted next_attempt_at"
                );
            } else {
                assert!(
                    got.next_attempt_at.is_some(),
                    "{name}: live next_attempt_at"
                );
            }
        }
    }

    /// The plateau shortcut is an optimisation, so it must agree exactly
    /// with the naive schedule it replaces. This walks `elapsed_to` by
    /// hand and compares.
    #[test]
    fn a12_derive_retry_state_matches_naive_schedule() {
        // naive: the largest k with elapsed_to(k) <= elapsed, and the
        // offset of retry k+1 — the definition, one retry at a time.
        fn naive(c: &BackoffCfg, elapsed: u64) -> (u64, u64) {
            let mut cum = 0u64;
            for k in 1u64.. {
                let next = cum + backoff_delay_ms(c, k);
                if next > elapsed {
                    return (k - 1, next);
                }
                cum = next;
            }
            unreachable!()
        }
        let cfgs = [
            ("default exponential", default_backoff()),
            ("constant 5s", strategy_cfg("constant", 5000)),
            ("linear 1s", strategy_cfg("linear", 1000)),
            ("tight cap", cfg(1000, 1500, "")),
        ];
        for (name, c) in cfgs {
            for elapsed in (0..=400_000).step_by(250) {
                let (want_attempt, want_next) = naive(&c, elapsed);
                let got = derive_retry_state(&c, Some(FS_BASE), FS_BASE + elapsed);
                assert_eq!(
                    (got.attempt, got.next_attempt_at),
                    (want_attempt, Some(FS_BASE + want_next)),
                    "{name}: elapsed {elapsed} disagrees with the naive schedule"
                );
            }
        }
    }

    /// Invariants that must hold for any config, at any point in an
    /// episode.
    #[test]
    fn a12_derive_retry_state_invariants() {
        let cfgs = [
            default_backoff(),
            strategy_cfg("constant", 5000),
            strategy_cfg("linear", 1000),
            cfg(5000, 1000, ""), // inverted
            cfg(1, 3, ""),       // very tight
        ];
        for c in cfgs {
            let mut prev_attempt = 0u64;
            for elapsed in (0..=200_000).step_by(137) {
                let now = FS_BASE + elapsed;
                let got = derive_retry_state(&c, Some(FS_BASE), now);
                let next = got
                    .next_attempt_at
                    .expect("live episode has a next attempt");
                // The next retry is always still ahead: a derivation
                // that returned a due-in-the-past time would spin the
                // retry loop.
                assert!(
                    next > now,
                    "{c:?} elapsed {elapsed}: next_attempt_at {next} is not after now {now}"
                );
                // attempt only ever grows as time passes in an episode.
                assert!(
                    got.attempt >= prev_attempt,
                    "{c:?} elapsed {elapsed}: attempt went backwards, {prev_attempt} then {}",
                    got.attempt
                );
                // The wait until the next retry never exceeds one
                // max-length delay.
                let wait = next - now;
                assert!(
                    wait <= c.max_ms.max(c.min_ms),
                    "{c:?} elapsed {elapsed}: wait {wait} exceeds the max delay"
                );
                prev_attempt = got.attempt;
            }
        }
    }

    // ---------------------------------------------------------------
    // The restart-hammering seam (ruling 7).
    //
    // The vector table above proves the pure function resumes a long
    // curve. These prove the HANDLER actually feeds it the durable
    // stamp — which is the half that kills restart-hammering, and the
    // half a pure-function table cannot see.
    // ---------------------------------------------------------------

    /// A peer whose `peer_id` is derivable gets its status-path key at
    /// session creation, with no connection and no prior establish.
    ///
    /// This is load-bearing for the restart case: a process that
    /// restarts beside a long-dead peer has never seen it connect, so a
    /// `remote_hash` that only arrived on establish would leave the
    /// durable stamp unreadable exactly when it is needed, and every
    /// attempt would re-stamp `now` and redial at `min_ms` forever.
    #[test]
    fn a12_status_key_is_derivable_without_a_connection() {
        let kp = entity_crypto::Keypair::from_seed([0x71; 32]);
        assert_eq!(
            identity_hash_from_peer_id(kp.peer_id().as_str()),
            Some(kp.peer_identity_hash()),
            "the status-path key must derive from the peer_id alone"
        );
        // A fingerprint peer_id carries no embedded key: not derivable,
        // and honest about it rather than guessing a wrong path.
        assert_eq!(identity_hash_from_peer_id("not-a-peer-id"), None);
    }

    /// THE restart-hammering vector, at the handler seam: a session that
    /// has never connected, beside a status entity left by a previous
    /// process, resumes that episode's curve instead of restarting it.
    ///
    /// Without the durable read this returns `attempt = 0` and a
    /// `min_ms` delay — a fresh process redialing a month-dead peer
    /// every second, forever.
    #[test]
    fn a12_retry_pacing_resumes_from_the_trees_stamp_after_a_restart() {
        let content_store: Arc<dyn ContentStore> =
            Arc::new(entity_store::MemoryContentStore::new());
        let location_index: Arc<dyn LocationIndex> =
            Arc::new(entity_store::MemoryLocationIndex::new());
        let local = entity_crypto::Keypair::from_seed([0x72; 32]);
        let remote = entity_crypto::Keypair::from_seed([0x73; 32]);
        let remote_pid = remote.peer_id().as_str().to_string();

        let handler = NetworkHandler::new(
            content_store.clone(),
            location_index.clone(),
            local.peer_id().as_str().to_string(),
        );

        // A previous process recorded a failure episode 30 days ago and
        // exited. All that survives is the tree.
        let now = now_ms();
        let failing_since = now - 2_592_000_000;
        let status = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("failing_since"),
                entity_ecf::Value::Integer(failing_since.into()),
            ),
            (entity_ecf::text("peer_id"), entity_ecf::text(&remote_pid)),
            (entity_ecf::text("status"), entity_ecf::text("disconnected")),
        ]));
        let entity = Entity::new("system/peer/status", status).unwrap();
        let hash = content_store.put(entity).unwrap();
        location_index.set(&handler.status_path(&remote.peer_identity_hash()), hash);

        // A fresh session, as a restarted process would create: never
        // connected, no in-memory episode of its own.
        let params = MaintainParams {
            peer_id: remote_pid.clone(),
            address: None,
            reconnect: true,
            resubscribe: true,
            backoff: BackoffCfg::default(),
            raw: Vec::new(),
        };
        let (session, existed) = handler.get_or_create_session(&remote_pid, params);
        assert!(!existed, "precondition: a fresh session");
        assert_eq!(
            session.state.lock().unwrap().failing_since,
            None,
            "precondition: no in-memory episode survived the restart"
        );

        let (state, used) = handler.retry_state(&session, now);
        assert_eq!(
            used,
            Some(failing_since),
            "the tree's durable stamp must win: this is the copy that survives a restart"
        );
        // 30 days into the default curve — the numbers are the vector
        // table's `a peer dead for 30 days` row, reached through the
        // handler rather than the pure function.
        assert_eq!(
            state.attempt, 43204,
            "must resume the curve, not restart it"
        );
        let wait = state.next_attempt_at.unwrap() - now;
        assert!(
            wait > 1000,
            "a restarted process must not redial at min_ms — waited {wait}ms"
        );
        assert!(
            wait <= 60_000,
            "the wait never exceeds one max-length delay, got {wait}ms"
        );
    }

    /// The tree wins over the session's fallback stamp. The fallback
    /// exists only for a peer that never connected (no demotion
    /// transition to stamp); it must never shadow the durable copy.
    #[test]
    fn a12_tree_stamp_wins_over_the_session_fallback() {
        let content_store: Arc<dyn ContentStore> =
            Arc::new(entity_store::MemoryContentStore::new());
        let location_index: Arc<dyn LocationIndex> =
            Arc::new(entity_store::MemoryLocationIndex::new());
        let local = entity_crypto::Keypair::from_seed([0x74; 32]);
        let remote = entity_crypto::Keypair::from_seed([0x75; 32]);
        let remote_pid = remote.peer_id().as_str().to_string();
        let handler = NetworkHandler::new(
            content_store.clone(),
            location_index.clone(),
            local.peer_id().as_str().to_string(),
        );

        let now = now_ms();
        let tree_stamp = now - 63_000; // 6 retries fired on the default curve
        let status = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("failing_since"),
                entity_ecf::Value::Integer(tree_stamp.into()),
            ),
            (entity_ecf::text("peer_id"), entity_ecf::text(&remote_pid)),
            (entity_ecf::text("status"), entity_ecf::text("suspect")),
        ]));
        let hash = content_store
            .put(Entity::new("system/peer/status", status).unwrap())
            .unwrap();
        location_index.set(&handler.status_path(&remote.peer_identity_hash()), hash);

        let params = MaintainParams {
            peer_id: remote_pid.clone(),
            address: None,
            reconnect: true,
            resubscribe: true,
            backoff: BackoffCfg::default(),
            raw: Vec::new(),
        };
        let (session, _) = handler.get_or_create_session(&remote_pid, params);
        // A younger in-memory fallback that would restart the curve.
        session.state.lock().unwrap().failing_since = Some(now);

        let (state, used) = handler.retry_state(&session, now);
        assert_eq!(used, Some(tree_stamp), "the durable stamp must win");
        assert_eq!(state.attempt, 6);
    }

    /// §2.2 delay table across the three strategies, clamped to max_ms.
    #[test]
    fn backoff_delay_strategies() {
        let exp = cfg(100, 1000, "exponential");
        assert_eq!(backoff_delay_ms(&exp, 1), 100);
        assert_eq!(backoff_delay_ms(&exp, 2), 200);
        assert_eq!(backoff_delay_ms(&exp, 3), 400);
        assert_eq!(backoff_delay_ms(&exp, 5), 1000, "clamped to max");
        assert_eq!(backoff_delay_ms(&exp, 60), 1000, "no overflow at depth");

        let lin = cfg(100, 350, "linear");
        assert_eq!(backoff_delay_ms(&lin, 1), 100);
        assert_eq!(backoff_delay_ms(&lin, 3), 300);
        assert_eq!(backoff_delay_ms(&lin, 4), 350, "clamped");

        let konst = cfg(100, 1000, "constant");
        assert_eq!(backoff_delay_ms(&konst, 1), 100);
        assert_eq!(backoff_delay_ms(&konst, 9), 100);

        // max < min degrades to min (defensive, mirrors Go).
        let inverted = cfg(500, 100, "exponential");
        assert_eq!(backoff_delay_ms(&inverted, 1), 500);
    }

    /// §2.1 decode: defaults applied (reconnect/resubscribe true, §2.2
    /// backoff defaults), raw bytes preserved for the re-EXECUTE.
    #[test]
    fn maintain_request_decode_defaults() {
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("peer_id"),
            entity_ecf::text("12D3peer"),
        )]));
        let p = decode_maintain_request(&data).unwrap();
        assert_eq!(p.peer_id, "12D3peer");
        assert_eq!(p.address, None);
        assert!(p.reconnect && p.resubscribe);
        assert_eq!(p.backoff.min_ms, 1000);
        assert_eq!(p.backoff.max_ms, 60000);
        assert_eq!(p.backoff.strategy, "exponential");
        assert_eq!(p.raw, data, "raw bytes preserved verbatim");
    }

    #[test]
    fn maintain_request_decode_explicit() {
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("address"),
                entity_ecf::text("127.0.0.1:4040"),
            ),
            (
                entity_ecf::text("backoff"),
                entity_ecf::Value::Map(vec![
                    (entity_ecf::text("max_ms"), entity_ecf::integer(400)),
                    (entity_ecf::text("min_ms"), entity_ecf::integer(100)),
                    (entity_ecf::text("strategy"), entity_ecf::text("linear")),
                ]),
            ),
            (entity_ecf::text("peer_id"), entity_ecf::text("12D3peer")),
            (entity_ecf::text("reconnect"), entity_ecf::bool_val(false)),
        ]));
        let p = decode_maintain_request(&data).unwrap();
        assert_eq!(p.address.as_deref(), Some("127.0.0.1:4040"));
        assert!(!p.reconnect);
        assert!(p.resubscribe, "unset resubscribe keeps the default");
        assert_eq!(p.backoff.min_ms, 100);
        assert_eq!(p.backoff.max_ms, 400);
        assert_eq!(p.backoff.strategy, "linear");
    }

    #[test]
    fn deliver_uri_peer_extraction() {
        assert!(delivery_targets_peer("entity://abc/system/inbox/x", "abc"));
        assert!(delivery_targets_peer("entity://abc", "abc"));
        assert!(!delivery_targets_peer(
            "entity://abcd/system/inbox/x",
            "abc"
        ));
        assert!(!delivery_targets_peer("system/inbox/x", "abc"));
        assert_eq!(
            peer_from_deliver_uri("entity://abc/x").as_deref(),
            Some("abc")
        );
        assert_eq!(
            peer_from_deliver_uri("entity://abc").as_deref(),
            Some("abc")
        );
        assert_eq!(peer_from_deliver_uri("/abc/x"), None);
    }
}
