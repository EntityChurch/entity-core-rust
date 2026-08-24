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
}

impl Default for BackoffCfg {
    fn default() -> Self {
        Self {
            min_ms: 1000,
            max_ms: 60000,
            strategy: "exponential".to_string(),
        }
    }
}

/// §2.2 delay for the given consecutive-failure attempt (1-based).
pub fn backoff_delay_ms(cfg: &BackoffCfg, attempt: u64) -> u64 {
    let min_ms = cfg.min_ms;
    let max_ms = cfg.max_ms.max(min_ms);
    let ms = match cfg.strategy.as_str() {
        "constant" => min_ms,
        "linear" => min_ms.saturating_mul(attempt.max(1)),
        // "exponential" (default)
        _ => {
            let mut ms = min_ms;
            for _ in 1..attempt.max(1) {
                ms = ms.saturating_mul(2);
                if ms >= max_ms {
                    break;
                }
            }
            ms
        }
    };
    ms.min(max_ms)
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
    /// Consecutive failed reconnect attempts since the last establish.
    attempt: u64,
    /// Monotonic token for pending backoff timers: a fired timer whose
    /// captured epoch is stale (superseded schedule or teardown) bails.
    sched_epoch: u64,
    subscription_ids: Vec<String>,
    graph_installed: bool,
    /// The remote's identity hash — the status-path key. Set on the first
    /// successful establish.
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
                attempt: 0,
                sched_epoch: 0,
                subscription_ids: Vec::new(),
                graph_installed: false,
                remote_hash: None,
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
                st.attempt = 0;
                st.params = params;
                st.remote_hash = Some(conn.identity_hash);
            }
            Err(e) => {
                if existed && reconnect_enabled {
                    // Re-entry from the backoff continuation: keep the
                    // retry loop alive — re-install the consumed one-shot
                    // and schedule the next delayed advance.
                    if let Err(arm_err) = self.arm_backoff_retry(ctx, &session, &link) {
                        tracing::warn!(
                            peer = %peer_id,
                            error = %arm_err,
                            "maintain-peer: re-arm backoff failed"
                        );
                    }
                } else if !existed {
                    // First imperative call failed — no session, no graph
                    // (§4.1 step 1's 502 contract).
                    self.drop_session(&peer_id);
                }
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
        let (sub_ids, _) = {
            let st = session.state.lock().unwrap();
            (st.subscription_ids.clone(), ())
        };
        let result_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("chain_id"),
                entity_ecf::text(&session.chain_id),
            ),
            (entity_ecf::text("peer_id"), entity_ecf::text(&peer_id)),
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
                session.state.lock().unwrap().attempt = 0;
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

        // Standing on-disconnect trigger (result_field null, remaining
        // null). No on_error: a failed reconnect dispatch binds the §3.10
        // lost-error marker — retry pacing is the handler's job.
        self.bind_continuation(
            session,
            &self.on_disconnect_path(&peer_id),
            "reconnect",
            reconnect_params,
            None,
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
    fn bind_continuation(
        &self,
        session: &Session,
        path: &str,
        operation: &str,
        params_bytes: Vec<u8>,
        remaining_executions: Option<u64>,
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
        if let Some(n) = remaining_executions {
            fields.push((
                entity_ecf::text("remaining_executions"),
                entity_ecf::integer(n as i64),
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

    // --- §2.2 backoff pacing (impl-internal timer + attempt counter) ------

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

    /// After the computed delay, self-advance the backoff continuation,
    /// which one-shot re-EXECUTEs maintain-peer. The advance is a
    /// self-authored EXECUTE — no request context is alive when the timer
    /// fires. A fired timer whose session was released (or superseded by a
    /// newer schedule) bails on the epoch check.
    fn schedule_backoff_advance(&self, session: &Arc<Session>, link: &Arc<dyn PeerLink>) {
        let (delay_ms, epoch, attempt) = {
            let mut st = session.state.lock().unwrap();
            st.attempt += 1;
            st.sched_epoch += 1;
            (
                backoff_delay_ms(&st.params.backoff, st.attempt),
                st.sched_epoch,
                st.attempt,
            )
        };
        tracing::debug!(
            peer = %session.peer_id,
            attempt,
            delay_ms,
            "reconnect: attempt failed, scheduling backoff retry"
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

    fn cfg(min_ms: u64, max_ms: u64, strategy: &str) -> BackoffCfg {
        BackoffCfg {
            min_ms,
            max_ms,
            strategy: strategy.to_string(),
        }
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
