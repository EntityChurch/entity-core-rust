//! EXTENSION-NETWORK §5 — application-level keepalive (Amendment 12
//! rung 2; completes the §A3 liveness floor with rung 1).
//!
//! One loop per pooled outbound connection (spawned when the fresh
//! endpoint wins its pool slot; the loop exits when the endpoint loses
//! its binding). Each tick (§5.4): skip the ping when the connection
//! exchanged messages within the last interval (§12.2 adaptive
//! suppression — any successful exchange resets the missed counter);
//! otherwise EXECUTE `ping` on `system/protocol/connect` (§5.1) with a
//! `system/network/ping` payload and a `timeout_ms` deadline. On
//! `max_missed` consecutive misses: write `suspect`, wait the
//! `timeout_ms` grace, and if the peer hasn't recovered write
//! `disconnected` (reason `keepalive-miss`) and evict — the §5.4
//! escalation the rung-1 transport-error demotion defers to.
//!
//! §5.1 pins that transport-level pings (e.g. WebSocket RFC 6455) do
//! NOT replace this loop — a peer can be TCP-alive but
//! protocol-unresponsive; implementations MUST NOT disable app-level
//! keepalive because transport pings are active.
//!
//! **Ownership:** the loop holds the pool and its own endpoint WEAKLY.
//! The pool (`Arc<RemoteState>`) is owned by the `Peer`; when the peer
//! is dropped the upgrade fails and the loop exits — a keepalive task
//! must never keep a dropped peer's connection (or stores) alive.
//!
//! **§5.4a — the escalation outlives the binding, `[MUST]`.** What the
//! loop must NOT do is treat "my binding is gone" as "nothing is owed".
//! The §A1 transport-error demotion evicts the binding *as* it writes
//! `suspect` — one event — so a loop that returns on sight of a missing
//! binding destroys the §5.4 `suspect → disconnected` escalation at the
//! moment it becomes owed: the peer stays `suspect` forever, the
//! disconnect subscription never fires, and §4.1 reconnect never
//! triggers on the transport-error-first path (the common one). On an
//! unbound tick the loop therefore takes §5.4's own grace step first
//! and escalates from [`escalate_unbound_suspect`].
//!
//! **Liveness criterion:** any EXECUTE_RESPONSE that arrives counts as
//! protocol-liveness even if its status is non-200 — the peer
//! demonstrably received, processed, and answered a frame. Only a
//! transport error / deadline miss increments `missed`. (Keeps the
//! floor honest against peers that haven't built the ping op yet;
//! flagged for the cross-impl convergence pass.)
//!
//! **§A4 write discipline (rung-2 ruling 1):** the status entity is
//! TRANSITION-written only — keepalive successes update impl-internal
//! freshness (`RemoteEndpoint::last_activity_ms`, which §5.4 adaptive
//! suppression already needs) and MUST NOT rewrite the tree entity.
//! `last_seen` is a snapshot taken at a transition write (on a
//! demotion, the demotion's evidence — the last moment we actually
//! heard from the peer), never a cadence refresh.

use std::collections::HashMap;
use std::sync::{Arc, Weak};

use entity_crypto::IdentityKeypair;
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};

use crate::liveness::{
    demote_peer_on_keepalive_miss, episode_failing_since, now_ms, read_peer_status,
    write_peer_status,
};
use crate::peer_status::PEER_STATUS_REASON_KEEPALIVE_MISS;
use crate::peer_status::{
    PeerStatusData, PEER_STATUS_CONNECTED, PEER_STATUS_DISCONNECTED, PEER_STATUS_SUSPECT,
};
use crate::remote::{send_execute, RemoteEndpoint, RemoteState};
use crate::PeerShared;

/// §2.3 keepalive configuration (spec defaults; §12.4 makes effective
/// values impl-defined). `enabled: false` is a test/embedder escape
/// hatch only — a NETWORK-conformant peer keeps it on (§12.1).
#[derive(Debug, Clone)]
pub struct KeepaliveConfig {
    /// Ping interval, ms (§2.3 default 30000).
    pub interval_ms: u64,
    /// Pong timeout, ms (§2.3 default 10000).
    pub timeout_ms: u64,
    /// Missed pongs before failure (§2.3 default 3).
    pub max_missed: u32,
    /// Run the loop at all. Defaults to true.
    pub enabled: bool,
}

impl Default for KeepaliveConfig {
    fn default() -> Self {
        Self {
            interval_ms: 30_000,
            timeout_ms: 10_000,
            max_missed: 3,
            enabled: true,
        }
    }
}

/// Cross-platform sleep (native tokio timer / WASM gloo timer).
#[cfg(not(target_arch = "wasm32"))]
async fn sleep_ms(ms: u64) {
    tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
}
#[cfg(target_arch = "wasm32")]
async fn sleep_ms(ms: u64) {
    gloo_timers::future::TimeoutFuture::new(ms as u32).await;
}

/// Await `fut` with a deadline; `None` on timeout.
#[cfg(not(target_arch = "wasm32"))]
async fn with_deadline<F: std::future::Future>(ms: u64, fut: F) -> Option<F::Output> {
    tokio::time::timeout(std::time::Duration::from_millis(ms), fut)
        .await
        .ok()
}
#[cfg(target_arch = "wasm32")]
async fn with_deadline<F: std::future::Future>(ms: u64, fut: F) -> Option<F::Output> {
    use futures::future::{select, Either};
    let timer = gloo_timers::future::TimeoutFuture::new(ms as u32);
    futures::pin_mut!(timer);
    futures::pin_mut!(fut);
    match select(timer, fut).await {
        Either::Left(_) => None,
        Either::Right((out, _)) => Some(out),
    }
}

/// Everything one keepalive loop needs, with the pool + endpoint held
/// weakly (see the module doc's ownership rule). Stores/keypair are
/// cheap shared handles; they don't keep the peer "running".
struct KeepaliveCtx {
    pool: Weak<RemoteState>,
    endpoint: Weak<dyn RemoteEndpoint>,
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    keypair: IdentityKeypair,
    local_peer_id: String,
    peer_id: String,
    /// The remote's `system/peer` content hash — the positional key of
    /// its status entity. Captured at spawn, when the endpoint is still
    /// alive, because the §5.4a escalation writes status precisely when
    /// the endpoint is gone and cannot be asked for it.
    remote_identity_hash: Hash,
    cfg: KeepaliveConfig,
}

impl KeepaliveCtx {
    /// Upgrade the weak pair and confirm `endpoint` is still the pooled
    /// outbound binding for `peer_id`. `None` ⇒ the loop must exit (peer
    /// dropped, endpoint dropped, or binding replaced/evicted).
    fn live_binding(&self) -> Option<(Arc<RemoteState>, Arc<dyn RemoteEndpoint>)> {
        let pool = self.pool.upgrade()?;
        let endpoint = self.endpoint.upgrade()?;
        let bound = pool.get(&self.peer_id)?;
        if !Arc::ptr_eq(&bound, &endpoint) {
            return None;
        }
        Some((pool, endpoint))
    }
}

/// Spawn the §5 keepalive loop for a freshly-pooled outbound endpoint.
/// Call ONLY for the endpoint that won its pool slot (the race loser's
/// endpoint is dropped and must not ping); the loop exits by itself
/// when the endpoint stops being the pooled binding for `peer_id`.
pub(crate) fn spawn_keepalive(
    shared: &PeerShared,
    peer_id: String,
    endpoint: &Arc<dyn RemoteEndpoint>,
) {
    if !shared.config.keepalive.enabled {
        return;
    }
    let ctx = KeepaliveCtx {
        pool: Arc::downgrade(&shared.remote),
        endpoint: Arc::downgrade(endpoint),
        content_store: shared.content_store.clone(),
        location_index: shared.location_index.clone(),
        keypair: shared.keypair.clone_identity(),
        local_peer_id: shared.peer_id.as_str().to_string(),
        peer_id,
        remote_identity_hash: endpoint.remote_identity_hash(),
        cfg: shared.config.keepalive.clone(),
    };
    crate::runtime::spawn(keepalive_loop(ctx));
}

/// §5.4 `keepalive_loop`.
async fn keepalive_loop(ctx: KeepaliveCtx) {
    let cfg = ctx.cfg.clone();
    let mut missed: u32 = 0;
    let mut sequence: u64 = 0;

    loop {
        sleep_ms(cfg.interval_ms).await;

        // The loop's own no-clobber discipline: only the current pooled
        // binding pings and writes liveness. Peer dropped or binding
        // replaced/evicted → a newer connection (with its own loop) owns
        // liveness now.
        //
        // §5.4a: losing the binding does NOT end the failure episode.
        // Take §5.4's grace step before concluding anything (see
        // [`escalate_after_grace`]), then hand off or escalate.
        let Some((_pool, endpoint)) = ctx.live_binding() else {
            escalate_after_grace(&ctx).await;
            if ctx.live_binding().is_some() {
                // Our own endpoint was re-bound during the grace —
                // §5.4's `reconnected(peer_id)` branch, and nobody else
                // spawned a loop for it. Keep watching.
                missed = 0;
                continue;
            }
            return;
        };

        // §5.4 adaptive suppression: skip ping during active exchange;
        // any successful exchange resets the missed counter. Observed
        // activity is impl-internal freshness only (§A4) — the tree
        // entity is written solely on a suspect→connected recovery.
        let last_activity = endpoint.last_activity_ms();
        if last_activity != 0 && now_ms().saturating_sub(last_activity) < cfg.interval_ms {
            missed = 0;
            recover_connected(&ctx, &endpoint, last_activity);
            continue;
        }

        sequence += 1;
        if ping(&ctx, &endpoint, sequence, cfg.timeout_ms).await {
            missed = 0;
            recover_connected(&ctx, &endpoint, now_ms());
            continue;
        }

        missed += 1;
        tracing::debug!(
            remote_peer = %ctx.peer_id,
            missed = missed,
            max_missed = cfg.max_missed,
            "keepalive miss"
        );
        if missed < cfg.max_missed {
            continue;
        }

        // §5.4 escalation: suspect → grace → disconnected. The suspect
        // write happens only while we are still the bound connection —
        // but if we lost the binding between the ping and here, the §A1
        // seam demoted underneath us and §5.4a still owes the follow-up.
        if ctx.live_binding().is_none() {
            escalate_after_grace(&ctx).await;
            return;
        }
        let mut data = PeerStatusData::bare(endpoint.remote_peer_id(), PEER_STATUS_SUSPECT);
        data.reason = Some(PEER_STATUS_REASON_KEEPALIVE_MISS.to_string());
        data.last_error = Some(format!("{} consecutive keepalive misses", missed));
        data.last_seen = last_seen_snapshot(endpoint.as_ref());
        data.failing_since = episode_failing_since(
            ctx.content_store.as_ref(),
            ctx.location_index.as_ref(),
            &ctx.local_peer_id,
            &endpoint.remote_identity_hash(),
        );
        write_peer_status(
            ctx.content_store.as_ref(),
            ctx.location_index.as_ref(),
            &ctx.local_peer_id,
            &endpoint.remote_identity_hash(),
            &data,
        );

        let grace_start = now_ms();
        sleep_ms(cfg.timeout_ms).await;

        // reconnected(peer_id)? Either a re-dial replaced the binding
        // (the new connection wrote its own `connected` and runs its own
        // loop — we just exit), or traffic resumed on THIS connection
        // during the grace (recover to connected and keep looping).
        //
        // Losing the binding here means the §A1 seam evicted during our
        // grace. The grace has already elapsed, so §5.4a's escalation is
        // owed NOW — with no second sleep, and with whatever `reason`
        // opened the episode.
        let Some((pool, endpoint)) = ctx.live_binding() else {
            escalate_unbound_suspect(&ctx);
            return;
        };
        if endpoint.last_activity_ms() > grace_start {
            missed = 0;
            recover_connected(&ctx, &endpoint, endpoint.last_activity_ms());
            continue;
        }

        // Connection failed: disconnected (reason keepalive-miss) +
        // guarded eviction. The write fires the disconnect subscription
        // → the §4.1 reconnect continuation (rung 3) composes here.
        demote_peer_on_keepalive_miss(
            pool.as_ref(),
            ctx.content_store.as_ref(),
            ctx.location_index.as_ref(),
            &ctx.local_peer_id,
            &ctx.peer_id,
            &endpoint,
        );
        return;
    }
}

/// §5.4's `escalate_after_grace(peer_id, timeout_ms)` for the entry
/// point the pseudocode reaches with `not bound(peer_id)`: sleep the
/// grace, then escalate if the episode is still open.
///
/// **The sleep comes first, and that ordering is normative (§5.4a).**
/// The §A1 eviction and its `suspect` write are not one atomic event —
/// the eviction lands under the pool lock and the status write follows
/// it — so a status read taken at eviction time can still see
/// `connected` and wrongly conclude nothing is owed.
async fn escalate_after_grace(ctx: &KeepaliveCtx) {
    sleep_ms(ctx.cfg.timeout_ms).await;
    escalate_unbound_suspect(ctx);
}

/// §5.4a `[MUST]` — complete the `suspect → disconnected` escalation for
/// a peer whose connection is already gone. Returns whether it fired.
///
/// This is the write the §A1 transport-error demotion leaves owed: that
/// seam evicts the binding as it writes `suspect`, so by the time the
/// escalation comes due there is no connection to escalate *on*. The
/// escalation belongs to the failure EPISODE, not to the connection.
///
/// **The guard is the status entity, not the binding** — deliberately,
/// because there is no binding here — and §5.4a pins it as scope, not
/// defensive coding: escalate ONLY from `suspect`, i.e. only where a
/// failure episode is genuinely open. That is what keeps this off the
/// ordinary teardown paths. The §10.2 dispatch fallback and the RELAY
/// terminal hop evict WITHOUT demoting (liveness.rs, ruling E), so those
/// bindings are still `connected`; a released or shut-down peer is
/// already `disconnected`. Neither is `suspect`, so neither escalates.
/// *"An implementation that escalates on any unbound peer rather than on
/// any `suspect` peer converts this rule into a new defect."*
///
/// **`reason` is carried, not chosen (§5.4a `[MUST]`)** — the escalating
/// write repeats whatever the demotion that OPENED the episode wrote:
/// `transport-error` from the §A1 seam, `keepalive-miss` from an idle
/// miss. Re-stamping to `keepalive-miss` on the seam path would assert
/// pings that were never sent (the connection was gone before the loop
/// could send one) and would erase the only signal that distinguishes
/// the transport-first path. An absent `reason` is preserved as absent:
/// §A2 leaves it OPTIONAL to emit, and inventing one here is the same
/// overclaim in the other direction.
fn escalate_unbound_suspect(ctx: &KeepaliveCtx) -> bool {
    let Some(pool) = ctx.pool.upgrade() else {
        // The peer itself is gone; there is no tree to write a liveness
        // observation into that anyone will read.
        return false;
    };
    // §5.4's `reconnected(peer_id)`: ANY live binding (a re-dialed
    // outbound, or a §6.11(b) inbound reentry) means the peer is back
    // and whoever bound it owns liveness — it wrote its own `connected`
    // and, on the outbound path, runs its own loop.
    if pool.get(&ctx.peer_id).is_some() || pool.get_inbound(&ctx.peer_id).is_some() {
        return false;
    }

    let Some(prev) = read_peer_status(
        ctx.content_store.as_ref(),
        ctx.location_index.as_ref(),
        &ctx.local_peer_id,
        &ctx.remote_identity_hash,
    ) else {
        return false;
    };
    if prev.status != PEER_STATUS_SUSPECT {
        return false;
    }

    let mut data = PeerStatusData::bare(&ctx.peer_id, PEER_STATUS_DISCONNECTED);
    data.reason = prev.reason.clone();
    data.last_error = Some(format!(
        "connection gone and no reconnect within the {}ms §5.4 grace",
        ctx.cfg.timeout_ms
    ));
    // §A4: the demotion snapshot the opening write already took — the
    // endpoint that observed it is gone, so there is nothing fresher.
    data.last_seen = prev.last_seen;
    data.failing_since = episode_failing_since(
        ctx.content_store.as_ref(),
        ctx.location_index.as_ref(),
        &ctx.local_peer_id,
        &ctx.remote_identity_hash,
    );
    write_peer_status(
        ctx.content_store.as_ref(),
        ctx.location_index.as_ref(),
        &ctx.local_peer_id,
        &ctx.remote_identity_hash,
        &data,
    );
    // No `mark_connection_closed` here, unlike the two demotion seams:
    // whoever evicted the binding was a demotion path (that is what the
    // `suspect` guard just established) and it already flipped the §3.13
    // record. A second write would be a redundant transition on an
    // entity whose discipline is write-on-transition.
    true
}

/// One §5.1 ping EXECUTE with a `timeout_ms` deadline. Returns whether
/// the peer demonstrated protocol-liveness (any response arrived).
async fn ping(
    ctx: &KeepaliveCtx,
    endpoint: &Arc<dyn RemoteEndpoint>,
    sequence: u64,
    timeout_ms: u64,
) -> bool {
    // §5.2 ping params; alphabetic key order (ECF determinism).
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (
            entity_ecf::text("sequence"),
            entity_ecf::Value::Integer(sequence.into()),
        ),
        (
            entity_ecf::text("timestamp"),
            entity_ecf::Value::Integer(now_ms().into()),
        ),
    ]));
    let Ok(params) = entity_entity::Entity::new("system/network/ping", data) else {
        return false;
    };
    let uri = format!("/{}/{}", ctx.peer_id, entity_protocol::CONNECT_PATH);
    let no_chain = HashMap::new();
    let sent = send_execute(
        endpoint.as_ref(),
        &ctx.keypair,
        &uri,
        "ping",
        &params,
        None,
        None,
        None,
        &no_chain,
        None,
    );
    match with_deadline(timeout_ms, sent).await {
        Some(Ok(resp)) => {
            if resp.status != 200 {
                // Alive but not answering ping properly (e.g. an impl
                // that hasn't built §5 yet). Counts as liveness — see
                // the module doc's liveness criterion.
                tracing::debug!(
                    remote_peer = %ctx.peer_id,
                    status = resp.status,
                    "keepalive ping answered with non-200; counting response as liveness"
                );
            }
            true
        }
        Some(Err(e)) => {
            tracing::debug!(remote_peer = %ctx.peer_id, error = %e, "keepalive ping transport error");
            false
        }
        None => {
            tracing::debug!(remote_peer = %ctx.peer_id, timeout_ms = timeout_ms, "keepalive ping timed out");
            false
        }
    }
}

/// §A4 transition guard: pong success / observed activity writes the
/// status entity ONLY when it is a genuine suspect→connected recovery
/// ("reconnection returns to connected", §3.13) — e.g. traffic resumed
/// during the grace window, or a pong answered after a rung-1
/// transport-error suspect. When the entity already says `connected`,
/// this is a no-op: no cadence rewrite, no subscriber fan-out, no CAS
/// accretion on an idle healthy connection (rung-2 ruling 1; per-tick
/// freshness lives in `RemoteEndpoint::last_activity_ms`).
///
/// The recovery write preserves `connected_at` and snapshots
/// `last_seen = seen_ms` — the observed activity that proved recovery.
fn recover_connected(ctx: &KeepaliveCtx, endpoint: &Arc<dyn RemoteEndpoint>, seen_ms: u64) {
    let remote_hash = endpoint.remote_identity_hash();
    let path = format!(
        "/{}/{}",
        ctx.local_peer_id,
        PeerStatusData::relative_path(&remote_hash)
    );
    let existing = ctx
        .location_index
        .get(&path)
        .and_then(|h| ctx.content_store.get(&h))
        .and_then(|e| PeerStatusData::from_entity(&e).ok());
    if existing
        .as_ref()
        .is_some_and(|d| d.status == PEER_STATUS_CONNECTED)
    {
        return;
    }

    let mut data = PeerStatusData::bare(endpoint.remote_peer_id(), PEER_STATUS_CONNECTED);
    data.connected_at = existing.as_ref().and_then(|d| d.connected_at);
    data.connection = existing.as_ref().and_then(|d| d.connection.clone());
    data.last_seen = Some(seen_ms);
    write_peer_status(
        ctx.content_store.as_ref(),
        ctx.location_index.as_ref(),
        &ctx.local_peer_id,
        &remote_hash,
        &data,
    );
}

/// §A4 `last_seen` transition snapshot: the endpoint's impl-internal
/// freshness mark, as demotion evidence ("when I last heard from this
/// peer as of this transition"). Absent (`None`) when no successful
/// exchange was ever recorded — optional fields encode as absence.
pub(crate) fn last_seen_snapshot(endpoint: &dyn RemoteEndpoint) -> Option<u64> {
    match endpoint.last_activity_ms() {
        0 => None,
        ms => Some(ms),
    }
}
