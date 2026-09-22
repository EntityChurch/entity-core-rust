//! L1 dispatched subscriptions — routed through `system/subscription`.
//!
//! `PeerContext::subscribe(pattern, callback)` establishes a
//! capability-checked subscription on the local peer's subscription
//! extension. Delivery happens via an SDK-internal handler registered
//! at `/{peer_id}/system/sdk/subs/{nonce}` through
//! `PeerContext::register_handler` (§11.5), so the tree carries matching
//! interface + handler entries — the invariant R was introduced to
//! enforce.
//!
//! Lifecycle: dropping the returned [`L1SubscriptionHandle`] closes the
//! `RegisteredHandler` (reversing the tree + dispatch-index writes) and
//! fires `system/subscription:unsubscribe` asynchronously.

// SDK module — see note in src/sdk.rs about intentional public API
// items that the current binary doesn't consume.
#![allow(dead_code)]

use std::sync::Arc;

use entity_capability::{CapabilityToken, GrantEntry, IdScope, PathScope, ResourceTarget};
use entity_crypto::Keypair;
use entity_entity::{Entity, TYPE_SIGNATURE};
use entity_handler::{ExecuteOptions, HandlerContext, HandlerError, HandlerResult};
use entity_hash::Hash;
use entity_peer::PeerShared;
use entity_store::ContentStore;

use crate::register_handler::{HandlerBody, HandlerSpec, OperationSpec, RegisteredHandler};
use crate::sdk::{PeerContext, SdkError};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Options for a subscribe call, per SDK-EXTENSION-OPERATIONS §3 (v0.7)
/// `SubscribeParams`.
///
/// `Default` yields the lean shape (no payload bundling, all three
/// default events, no rate/duration/count limits) — exactly the
/// behavior the existing `PeerContext::subscribe(pattern, callback)`
/// has always had.
#[derive(Debug, Clone, Default)]
pub struct SubscribeOptions {
    /// If `true`, the subscribe handler bundles each changed entity
    /// into the notification envelope's `included` map per
    /// EXTENSION-SUBSCRIPTION §2.2 (v3.14). **Normative requirement:**
    /// the caller's capability must cover `tree:get` on the subscribed
    /// resource (EXTENSION-SUBSCRIPTION §2.3 v3.13) — otherwise the
    /// handler rejects with `403 payload_unauthorized`. Without it,
    /// subscribers receive hashes-only notifications and must
    /// `tree:get` to read each changed entity.
    pub include_payload: bool,
    /// Event types to receive. `None` (the default) selects all three
    /// — `"created"` / `"updated"` / `"deleted"`. `Some(vec!["..."])`
    /// narrows to the listed subset. Empty `Some(vec![])` is a
    /// degenerate filter that matches nothing; the engine will
    /// accept it but no notifications will fire.
    pub events: Option<Vec<String>>,
    /// Per-subscription engine limits. When `Some`, the engine
    /// applies one or more of the configured caps (max events,
    /// max duration, rate limit). See [`SubscribeLimits`].
    pub limits: Option<SubscribeLimits>,
}

/// Per-subscription delivery caps applied by the subscription engine.
/// Per EXTENSION-SUBSCRIPTION §3. When any single cap trips the
/// engine takes the spec-defined action (typically: drop or
/// unsubscribe; consult §3 for action semantics).
#[derive(Debug, Clone, Copy, Default)]
pub struct SubscribeLimits {
    /// Maximum total events delivered before the subscription is
    /// auto-cancelled. `None` = unlimited.
    pub max_events: Option<u64>,
    /// Maximum subscription lifetime in milliseconds since install.
    /// `None` = unlimited.
    pub max_duration_ms: Option<u64>,
    /// Maximum events per second (engine-defined window). `None` =
    /// unrate-limited.
    pub rate_limit: Option<u64>,
}

/// The EXTENSION-SUBSCRIPTION §2.2 event vocabulary. These are the only names a
/// built-in tree change can produce.
pub const SUBSCRIPTION_EVENTS: [&str; 3] = ["created", "updated", "deleted"];

/// Reject an event name outside §2.2's vocabulary (SA-2).
///
/// The engine is correct and needs no change: it accepts an arbitrary name and
/// filters deliveries against it. That is exactly why the wrapper must validate
/// — an unknown name is not an error anywhere downstream, it is a filter that
/// matches nothing. The caller gets a subscription that is created, returns an
/// id, and never fires for its entire lifetime, with no error at any layer.
///
/// The reachable case is a caller following the pre-fix SDK-EXTENSION-OPERATIONS
/// §3 vocabulary, which named events the extension never emitted.
/// `entity-core-py` already rejects unknown names; this closes the same gap here.
fn validate_event_vocabulary(events: &[String]) -> Result<(), SdkError> {
    if let Some(bad) = events
        .iter()
        .find(|e| !SUBSCRIPTION_EVENTS.contains(&e.as_str()))
    {
        return Err(SdkError::BadRequest {
            status: 400,
            code: Some("invalid_event_type".into()),
            message: format!(
                "unknown subscription event {bad:?}; EXTENSION-SUBSCRIPTION §2.2                  defines only {}. An unknown name would be accepted by the engine                  and match nothing, so the subscription would never fire.",
                SUBSCRIPTION_EVENTS.join(" / ")
            ),
        });
    }
    Ok(())
}

impl SubscribeOptions {
    /// Shorthand for `SubscribeOptions { include_payload: true, .. }`.
    /// Use this when the subscriber holds `tree:get` on the resource
    /// and wants the convergent-mirror recipe (SDK-EXTENSION-OPERATIONS
    /// §3 v0.7).
    pub fn with_payload() -> Self {
        Self {
            include_payload: true,
            ..Self::default()
        }
    }

    /// Builder-style helper: narrow the event types this subscription
    /// receives. Pass any subset of `"created"` / `"updated"` /
    /// `"deleted"` (per EXTENSION-SUBSCRIPTION §2.2).
    ///
    /// Unknown names are rejected at `subscribe` time — see
    /// [`validate_event_vocabulary`]. They used to pass through, which is
    /// SA-2: the engine accepts any name and filters against it, so an
    /// unknown one produced a subscription that was created, returned an
    /// id, and then never fired for its whole lifetime.
    pub fn with_events(mut self, events: Vec<String>) -> Self {
        self.events = Some(events);
        self
    }

    /// Builder-style helper: apply per-subscription delivery caps.
    pub fn with_limits(mut self, limits: SubscribeLimits) -> Self {
        self.limits = Some(limits);
        self
    }
}

/// One L1 subscription event delivered to the subscribe callback.
///
/// Decoded from the `system/subscription/notification` entity the
/// subscription engine dispatches to the SDK's delivery handler.
#[derive(Debug, Clone)]
pub struct L1SubscriptionEvent {
    /// Subscription that matched this event.
    pub subscription_id: String,
    /// Change type: `"created"`, `"updated"`, or `"deleted"`.
    pub event: String,
    /// Full qualified path of the changed entity.
    pub path: String,
    /// Post-write hash. `None` on delete.
    pub new_hash: Option<Hash>,
    /// Pre-write hash. `None` for create; `Some` for update/delete.
    pub previous_hash: Option<Hash>,
    /// The changed entity itself, bundled in-band with the notification
    /// when the subscription opted into payload delivery via
    /// [`SubscribeOptions::with_payload`] (EXTENSION-SUBSCRIPTION §2.2,
    /// PROPOSAL-CONVERGENT-MIRRORING §2). `Some` on create/update when the
    /// source resolved the entity; `None` when payload bundling was off,
    /// on a delete, or on a source-side resolution miss (in which case the
    /// subscriber may `tree:get` the `path` to materialize it).
    ///
    /// This is the field that lets a subscriber mirror a remote subtree
    /// with **no fetch round-trip** — the changed entity arrives with the
    /// notification. Without it, [`L1SubscriptionEvent`] carries only
    /// hashes and every mirror write forces a `tree:get` first.
    pub included: Option<Entity>,
}

/// Handle returned by [`PeerContext::subscribe`]. Drop to cancel:
/// unsubscribes via `system/subscription:unsubscribe` and unregisters
/// the delivery handler (both halves of the tree-paired write — tree
/// entries via `RegisteredHandler`'s close, RPC via the Drop spawn).
#[must_use = "dropping this handle cancels the L1 subscription"]
pub struct L1SubscriptionHandle {
    subscription_id: String,
    /// Shared state for the drop-time unsubscribe dispatch.
    shared: Arc<PeerShared>,
    /// The delivery handler registration — owned by this handle. Drop
    /// closes it synchronously so future events matching our subscription
    /// drop on the floor even if the unsubscribe RPC is still in flight.
    registered: RegisteredHandler,
    /// `Some(pid)` for cross-peer subscriptions (created via
    /// [`PeerContext::subscribe_at`] with a non-self peer-id); the
    /// unsubscribe RPC must dispatch through
    /// `entity://{remote_pid}/system/subscription` to reach the engine
    /// that owns the subscription, not the local one. `None` for
    /// local subscriptions (created via [`PeerContext::subscribe`]).
    remote_pid: Option<String>,
}

impl L1SubscriptionHandle {
    /// The subscription id assigned by the engine. Diagnostic; not
    /// needed for normal use (drop the handle to cancel).
    pub fn subscription_id(&self) -> &str {
        &self.subscription_id
    }

    /// The delivery handler's qualified dispatch pattern (e.g.,
    /// `/{peer_id}/system/sdk/subs/{nonce}`). Diagnostic.
    pub fn handler_pattern(&self) -> &str {
        self.registered.pattern()
    }
}

impl std::fmt::Debug for L1SubscriptionHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("L1SubscriptionHandle")
            .field("subscription_id", &self.subscription_id)
            .field("handler_pattern", &self.registered.pattern())
            .finish()
    }
}

impl Drop for L1SubscriptionHandle {
    fn drop(&mut self) {
        // Close the delivery handler immediately — synchronous,
        // so future events matching our subscription_id drop on the
        // floor even if the unsubscribe RPC is still in flight.
        self.registered.close();

        // Fire off the unsubscribe RPC. We don't await it — by the time
        // this Drop runs the caller has already discarded interest.
        let shared = self.shared.clone();
        let subscription_id = self.subscription_id.clone();
        // Cross-peer subscriptions: the engine owning the subscription
        // lives on the remote peer, so unsubscribe must be addressed
        // there. Locals dispatch to bare `system/subscription`.
        let unsub_target = match &self.remote_pid {
            Some(pid) => format!("entity://{}/system/subscription", pid),
            None => "system/subscription".to_string(),
        };
        let task = async move {
            let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                entity_ecf::text("subscription_id"),
                entity_ecf::text(&subscription_id),
            )]));
            let params = match Entity::new("system/subscription/cancel-params", params_data) {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!(error = %e, "L1 unsubscribe: build params failed");
                    return;
                }
            };
            let local_identity = shared.identity_hash;
            let execute_fn = entity_peer::connection::make_execute_fn(
                shared,
                Some(local_identity),
                std::collections::HashMap::new(),
                None,
                None,
                // The peer dispatching as itself, not as a deputy (§5.2 D1).
                entity_peer::connection::DispatchCeiling::PeerRoot,
            );
            let opts = ExecuteOptions::default();
            match execute_fn(unsub_target, "unsubscribe".into(), params, opts).await {
                Ok(r) if r.status == 200 => {
                    tracing::debug!(subscription_id = %subscription_id, "L1 unsubscribe: ok");
                }
                Ok(r) => {
                    tracing::debug!(
                        subscription_id = %subscription_id,
                        status = r.status,
                        "L1 unsubscribe: non-ok status"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        subscription_id = %subscription_id,
                        error = %e,
                        "L1 unsubscribe: failed"
                    );
                }
            }
        };

        #[cfg(not(target_arch = "wasm32"))]
        {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(task);
            } else {
                tracing::debug!(
                    subscription_id = %self.subscription_id,
                    "L1 unsubscribe: no tokio runtime; skipping RPC"
                );
            }
        }
        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(task);
    }
}

/// Handle for a **raw** subscription created by
/// [`PeerContext::subscribe_raw_at`] — delivery goes to a caller-specified
/// URI (e.g. a continuation inbox), so there is no SDK delivery handler to
/// close, only the subscription to cancel. Drop to unsubscribe (dispatches
/// `system/subscription:unsubscribe` to whichever engine owns it — remote for
/// cross-peer, local otherwise).
#[must_use = "dropping this handle cancels the raw subscription"]
pub struct RawSubscriptionHandle {
    subscription_id: String,
    shared: Arc<PeerShared>,
    remote_pid: Option<String>,
}

impl RawSubscriptionHandle {
    /// The subscription id assigned by the owning engine.
    pub fn subscription_id(&self) -> &str {
        &self.subscription_id
    }
}

impl std::fmt::Debug for RawSubscriptionHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawSubscriptionHandle")
            .field("subscription_id", &self.subscription_id)
            .field("remote_pid", &self.remote_pid)
            .finish()
    }
}

impl Drop for RawSubscriptionHandle {
    fn drop(&mut self) {
        // Fire-and-forget unsubscribe to the owning engine (remote for
        // cross-peer, local otherwise). No delivery handler to close — the
        // deliver_uri is a caller-owned handler, not an SDK-internal one.
        let shared = self.shared.clone();
        let subscription_id = self.subscription_id.clone();
        let unsub_target = match &self.remote_pid {
            Some(pid) => format!("entity://{}/system/subscription", pid),
            None => "system/subscription".to_string(),
        };
        let task = async move {
            let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                entity_ecf::text("subscription_id"),
                entity_ecf::text(&subscription_id),
            )]));
            let params = match Entity::new("system/subscription/cancel-params", params_data) {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!(error = %e, "raw unsubscribe: build params failed");
                    return;
                }
            };
            let local_identity = shared.identity_hash;
            let execute_fn = entity_peer::connection::make_execute_fn(
                shared,
                Some(local_identity),
                std::collections::HashMap::new(),
                None,
                None,
                // The peer dispatching as itself, not as a deputy (§5.2 D1).
                entity_peer::connection::DispatchCeiling::PeerRoot,
            );
            let _ = execute_fn(
                unsub_target,
                "unsubscribe".into(),
                params,
                ExecuteOptions::default(),
            )
            .await;
        };
        #[cfg(not(target_arch = "wasm32"))]
        {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(task);
            } else {
                tracing::debug!(
                    subscription_id = %self.subscription_id,
                    "raw unsubscribe: no tokio runtime; skipping RPC"
                );
            }
        }
        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(task);
    }
}

// ---------------------------------------------------------------------------
// PeerContext::subscribe — public entry point
// ---------------------------------------------------------------------------

impl PeerContext {
    /// L1 dispatched subscribe. Routes through `system/subscription` with
    /// a self-granted delivery capability.
    ///
    /// Mechanics:
    /// 1. Register an SDK-owned delivery handler at
    ///    `/{peer_id}/system/sdk/subs/{sub_id}` via `register_handler`
    ///    (§11.5) — writes the paired interface + handler tree entities
    ///    and installs the body in the dispatch index.
    /// 2. Build and sign a `CapabilityToken` granting access to the
    ///    delivery URI (self-grant: granter==grantee==local identity).
    /// 3. Call `execute("system/subscription", "subscribe", ...)` with
    ///    the token in `included`.
    /// 4. On handle drop: close the registered handler (reverses the
    ///    tree + dispatch-index writes) and dispatch `unsubscribe`.
    ///
    /// The callback fires on every matching tree-change event until the
    /// returned handle is dropped.
    ///
    /// `pattern` accepts the same syntax as the subscription extension's
    /// resource target — exact path or `{prefix}/*` for subtree.
    ///
    /// Returns an **owning** future so callers can spawn the subscribe
    /// dispatch from sync contexts (e.g., a window factory):
    /// ```ignore
    /// let sub_slot = Arc::new(Mutex::new(None));
    /// let slot = sub_slot.clone();
    /// tokio::spawn(async move {
    ///     if let Ok(h) = ctx.subscribe("...", cb).await {
    ///         *slot.lock().unwrap() = Some(h);
    ///     }
    /// });
    /// ```
    #[cfg(not(target_arch = "wasm32"))]
    pub fn subscribe<F>(
        &self,
        pattern: impl Into<String>,
        callback: F,
    ) -> impl std::future::Future<Output = Result<L1SubscriptionHandle, SdkError>> + Send + 'static
    where
        F: Fn(L1SubscriptionEvent) + Send + Sync + 'static,
    {
        self.subscribe_internal(
            pattern.into(),
            SubscribeOptions::default(),
            Arc::new(callback),
            None,
        )
    }

    /// WASM variant — same logic, no `Send` bound required for spawn_local.
    #[cfg(target_arch = "wasm32")]
    pub fn subscribe<F>(
        &self,
        pattern: impl Into<String>,
        callback: F,
    ) -> impl std::future::Future<Output = Result<L1SubscriptionHandle, SdkError>> + 'static
    where
        F: Fn(L1SubscriptionEvent) + Send + Sync + 'static,
    {
        self.subscribe_internal(
            pattern.into(),
            SubscribeOptions::default(),
            Arc::new(callback),
            None,
        )
    }

    /// Configurable subscribe — per SDK-EXTENSION-OPERATIONS §3 (v0.7),
    /// Amendment B.1. Threads `SubscribeOptions` (`include_payload`,
    /// future fields) into the dispatched `subscribe` params.
    ///
    /// `ctx.subscribe(pattern, callback)` is equivalent to
    /// `ctx.subscribe_with_options(pattern, SubscribeOptions::default(),
    /// callback)`.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn subscribe_with_options<F>(
        &self,
        pattern: impl Into<String>,
        options: SubscribeOptions,
        callback: F,
    ) -> impl std::future::Future<Output = Result<L1SubscriptionHandle, SdkError>> + Send + 'static
    where
        F: Fn(L1SubscriptionEvent) + Send + Sync + 'static,
    {
        self.subscribe_internal(pattern.into(), options, Arc::new(callback), None)
    }

    /// WASM variant — no `Send` bound.
    #[cfg(target_arch = "wasm32")]
    pub fn subscribe_with_options<F>(
        &self,
        pattern: impl Into<String>,
        options: SubscribeOptions,
        callback: F,
    ) -> impl std::future::Future<Output = Result<L1SubscriptionHandle, SdkError>> + 'static
    where
        F: Fn(L1SubscriptionEvent) + Send + Sync + 'static,
    {
        self.subscribe_internal(pattern.into(), options, Arc::new(callback), None)
    }

    /// Subscribe to changes on `peer_id`'s tree (per Godot ask D3).
    ///
    /// `peer_id` selects the engine that hosts the subscription:
    /// - If equal to this peer's id, the subscription lives locally
    ///   (equivalent to calling [`PeerContext::subscribe`]).
    /// - Otherwise the subscription is created on the remote peer's
    ///   engine; that peer must already be in this peer's connection
    ///   pool (call [`PeerContext::connect_to`] first).
    ///
    /// `pattern` is the watch pattern interpreted against the target
    /// peer's tree (e.g. `/{peer_id}/app/foo/*`).
    ///
    /// Mechanism for cross-peer: registers a local delivery handler
    /// at `system/sdk/subs/{nonce}`, expresses its qualified pattern
    /// as `entity://{local_pid}/system/sdk/subs/{nonce}` in the
    /// deliver_to URI, mints a delivery cap-token authorizing that
    /// URI, and dispatches `subscribe` to
    /// `entity://{peer_id}/system/subscription`. When the remote
    /// engine sees a matching change on its tree, it dispatches
    /// `receive` back to the local delivery URI through the existing
    /// connection (signed by the local peer's delivery token).
    ///
    /// Drop semantics: the returned handle's [`Drop`] dispatches
    /// `unsubscribe` to whichever engine owns the subscription —
    /// local for self-targeted, remote for cross-peer.
    ///
    /// **Naming note:** mirrors Go SDK's `AppPeer.SubscribeAt(peerID,
    /// pattern, opts)`. The Go convention also makes `Subscribe`
    /// delegate to `SubscribeAt(self.PeerID(), ...)`; the Rust SDK
    /// keeps `subscribe` as the primary local path today (no
    /// canonicalization-via-delegation), but the surface names align.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn subscribe_at<F>(
        &self,
        peer_id: impl Into<String>,
        pattern: impl Into<String>,
        callback: F,
    ) -> impl std::future::Future<Output = Result<L1SubscriptionHandle, SdkError>> + Send + 'static
    where
        F: Fn(L1SubscriptionEvent) + Send + Sync + 'static,
    {
        let target = peer_id.into();
        // Self-id short-circuit: local subscription, no entity:// rewriting.
        let remote = if target == self.peer_id() {
            None
        } else {
            Some(target)
        };
        self.subscribe_internal(
            pattern.into(),
            SubscribeOptions::default(),
            Arc::new(callback),
            remote,
        )
    }

    /// WASM variant of [`PeerContext::subscribe_at`].
    #[cfg(target_arch = "wasm32")]
    pub fn subscribe_at<F>(
        &self,
        peer_id: impl Into<String>,
        pattern: impl Into<String>,
        callback: F,
    ) -> impl std::future::Future<Output = Result<L1SubscriptionHandle, SdkError>> + 'static
    where
        F: Fn(L1SubscriptionEvent) + Send + Sync + 'static,
    {
        let target = peer_id.into();
        let remote = if target == self.peer_id() {
            None
        } else {
            Some(target)
        };
        self.subscribe_internal(
            pattern.into(),
            SubscribeOptions::default(),
            Arc::new(callback),
            remote,
        )
    }

    /// Cross-peer subscribe with explicit [`SubscribeOptions`] — the
    /// options-carrying counterpart to [`subscribe_at`](Self::subscribe_at)
    /// (which always uses defaults) and the cross-peer counterpart to
    /// [`subscribe_with_options`](Self::subscribe_with_options) (which is
    /// local-only). Without this, `include_payload` was unreachable for a
    /// remote subscription, so a subscriber could not receive a remote
    /// peer's changed entities in-band and was forced to `tree:get` each
    /// one — the exact fetch round-trip the convergent-mirror recipe
    /// removes. Used by [`PeerContext::follow`].
    ///
    /// **Payload authorization (cross-peer):** the *remote* engine
    /// enforces `include_payload` (EXTENSION-SUBSCRIPTION §2.3) against the
    /// capability this dispatch presents — the same authorization surface
    /// as a direct cross-peer `tree:get`. The subscribe is dispatched with
    /// the receiver-rooted connection grant (no local-rooted cap forced
    /// on), so whatever grant already authorizes the caller's cross-peer
    /// reads of `pattern` authorizes payload bundling too.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn subscribe_at_with_options<F>(
        &self,
        peer_id: impl Into<String>,
        pattern: impl Into<String>,
        options: SubscribeOptions,
        callback: F,
    ) -> impl std::future::Future<Output = Result<L1SubscriptionHandle, SdkError>> + Send + 'static
    where
        F: Fn(L1SubscriptionEvent) + Send + Sync + 'static,
    {
        let target = peer_id.into();
        let remote = if target == self.peer_id() {
            None
        } else {
            Some(target)
        };
        self.subscribe_internal(pattern.into(), options, Arc::new(callback), remote)
    }

    /// WASM variant of [`PeerContext::subscribe_at_with_options`].
    #[cfg(target_arch = "wasm32")]
    pub fn subscribe_at_with_options<F>(
        &self,
        peer_id: impl Into<String>,
        pattern: impl Into<String>,
        options: SubscribeOptions,
        callback: F,
    ) -> impl std::future::Future<Output = Result<L1SubscriptionHandle, SdkError>> + 'static
    where
        F: Fn(L1SubscriptionEvent) + Send + Sync + 'static,
    {
        let target = peer_id.into();
        let remote = if target == self.peer_id() {
            None
        } else {
            Some(target)
        };
        self.subscribe_internal(pattern.into(), options, Arc::new(callback), remote)
    }

    /// **Raw** cross-peer subscribe: deliver matching change notifications to
    /// a caller-specified `deliver_uri` (operation `receive`), with NO
    /// SDK-internal callback handler. The Rust analog of Go's
    /// `AppPeer.SubscribeRawAt`.
    ///
    /// Where [`subscribe_at`](Self::subscribe_at) registers an SDK delivery
    /// handler and fires a Rust closure, this binds the subscription's
    /// delivery straight to an existing on-tree handler — typically a
    /// **continuation inbox** — so the notification drives a substrate-side
    /// dispatch chain instead of app code. This is the trigger edge of the
    /// server-side follow chain ([`crate::follow::FollowMode::Continuation`]).
    ///
    /// `deliver_uri` is the full delivery URI the remote engine dispatches
    /// `receive` to — for cross-peer delivery back to this peer, the
    /// `entity://{local_pid}/...` form (e.g. an inbox path). A self-grant
    /// authorizing `system/inbox:receive` at that URI is minted and bundled.
    ///
    /// Drop the returned [`RawSubscriptionHandle`] to unsubscribe.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn subscribe_raw_at(
        &self,
        peer_id: impl Into<String>,
        pattern: impl Into<String>,
        deliver_uri: impl Into<String>,
        events: Vec<String>,
    ) -> impl std::future::Future<Output = Result<RawSubscriptionHandle, SdkError>> + Send + 'static
    {
        let target = peer_id.into();
        let remote = if target == self.peer_id() {
            None
        } else {
            Some(target)
        };
        self.subscribe_raw_internal(pattern.into(), deliver_uri.into(), events, remote)
    }

    /// WASM variant of [`PeerContext::subscribe_raw_at`].
    #[cfg(target_arch = "wasm32")]
    pub fn subscribe_raw_at(
        &self,
        peer_id: impl Into<String>,
        pattern: impl Into<String>,
        deliver_uri: impl Into<String>,
        events: Vec<String>,
    ) -> impl std::future::Future<Output = Result<RawSubscriptionHandle, SdkError>> + 'static {
        let target = peer_id.into();
        let remote = if target == self.peer_id() {
            None
        } else {
            Some(target)
        };
        self.subscribe_raw_internal(pattern.into(), deliver_uri.into(), events, remote)
    }

    /// Shared implementation for native + WASM. Does the synchronous
    /// setup (engine start, handler registration, grant mint) inline so
    /// that if any of those fail we haven't yet forked work into a
    /// spawned task, then returns an owning future for the async
    /// subscribe dispatch.
    ///
    /// Registers the delivery handler via `register_handler` (§11.5), so
    /// the tree carries matching interface + manifest + grant entries for
    /// the SDK-internal handler. On any failure, the `RegisteredHandler`
    /// local drops and its `Drop` impl cleans up the tree entries.
    fn subscribe_internal(
        &self,
        pattern: String,
        options: SubscribeOptions,
        callback: Arc<dyn Fn(L1SubscriptionEvent) + Send + Sync + 'static>,
        remote_pid: Option<String>,
    ) -> impl std::future::Future<Output = Result<L1SubscriptionHandle, SdkError>> + 'static {
        // --- Synchronous setup ---
        // Ensure extension engines are running — `start_engines` is
        // idempotent (guarded by an AtomicBool), so repeating here is
        // safe if the caller (or `app.rs` listener bootstrap) already
        // started them. Must run inside a tokio runtime on native: the
        // subscription engine spawns its broadcast loop as part of
        // start. Callers that lack a runtime must avoid calling
        // `subscribe` in the first place (unit tests without `#[tokio::test]`).
        let peer = self.peer();
        peer.start_engines(&self.peer_shared());

        let shared = self.peer_shared();
        // Captured synchronously (can't borrow &self across the await): used
        // as the caller capability for local include_payload authorization.
        let owner_cap = self.owner_self_cap.clone();

        // Mint a bare delivery pattern unique to this subscription. The
        // SDK-internal namespace is `system/sdk/{purpose}/{identifier}`
        // per §11.5.7 — applications must not use this prefix.
        let sub_nonce = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let bare_pattern = format!("system/sdk/subs/{}", sub_nonce);

        // Register through the SDK primitive — writes interface + handler
        // + grant tree entries and installs the body adapter into the
        // dispatch index. The returned `RegisteredHandler` owns the
        // cleanup; if any later step fails and we return Err, its Drop
        // tears down the registration automatically.
        let spec = HandlerSpec::new(
            &bare_pattern,
            "sdk_subscription_delivery",
            vec![OperationSpec::new("receive")],
        );
        let register_result = self.register_handler(spec, build_delivery_body(callback));

        // Keep mint synchronous (avoids capturing &Keypair across the
        // await boundary). On success, the owned (token_entity, token_hash)
        // move into the async block; on failure, the `registered` local
        // drops if it was produced, cleaning up.
        //
        // Local: deliver_uri is the qualified handler pattern
        //   (`/{peer_id}/system/sdk/subs/{nonce}`), dispatched locally.
        // Cross-peer: deliver_uri is the entity:// form pointing back
        //   at this peer (`entity://{peer_id}/system/sdk/subs/{nonce}`),
        //   so the remote engine's deliver_fn routes the dispatch
        //   through its outbound connection pool to this peer.
        let deliver_uri = register_result
            .as_ref()
            .map(|r| {
                if remote_pid.is_some() {
                    format!("entity://{}", r.pattern().trim_start_matches('/'))
                } else {
                    r.pattern().to_string()
                }
            })
            .unwrap_or_default();
        let mint_result = if deliver_uri.is_empty() {
            Err(SdkError::HandlerError(
                "registration failed before mint".into(),
            ))
        } else {
            mint_delivery_grant(
                peer.keypair().as_ed25519().expect(
                    "entity-sdk peers are Ed25519-only (Ed448 backends use core PeerBuilder)",
                ),
                &deliver_uri,
                delivering_engine_identity(&shared, remote_pid.as_deref()),
                peer.content_store(),
            )
        };

        async move {
            let registered = register_result?;
            let (token_entity, token_hash) = mint_result?;

            // Build the subscribe params entity. ECF-sorted output
            // is produced by `to_ecf`; field-insert order here is
            // just for readability — handler's `decode_subscribe_request`
            // does key-by-key scan.
            //
            // `events`: None → emit all three defaults (created /
            // updated / deleted) to preserve pre-v0.8 wire shape.
            // Some(vec) → emit verbatim (caller may narrow).
            // §2.2 vocabulary — validated before the mint, so an unknown name
            // fails loudly instead of yielding a never-firing subscription.
            if let Some(ref es) = options.events {
                validate_event_vocabulary(es)?;
            }
            let events_values: Vec<ciborium::Value> = match &options.events {
                None => vec![
                    entity_ecf::text("created"),
                    entity_ecf::text("updated"),
                    entity_ecf::text("deleted"),
                ],
                Some(es) => es.iter().map(entity_ecf::text).collect(),
            };
            let mut params_map: Vec<(ciborium::Value, ciborium::Value)> = vec![
                (
                    entity_ecf::text("events"),
                    entity_ecf::Value::Array(events_values),
                ),
                (
                    entity_ecf::text("deliver_to"),
                    entity_ecf::Value::Map(vec![
                        (entity_ecf::text("uri"), entity_ecf::text(&deliver_uri)),
                        (entity_ecf::text("operation"), entity_ecf::text("receive")),
                    ]),
                ),
                (
                    entity_ecf::text("deliver_token"),
                    entity_ecf::Value::Bytes(token_hash.to_bytes().to_vec()),
                ),
            ];
            // Amendment B.1 (SDK-EXT-OPS §3 v0.7 / EXTENSION-SUBSCRIPTION v3.14):
            // omit the field when the default (false) is in effect so on-the-
            // wire shape stays byte-identical to pre-v0.7 callers.
            if options.include_payload {
                params_map.push((
                    entity_ecf::text("include_payload"),
                    entity_ecf::bool_val(true),
                ));
            }
            // SubscribeOptions::limits → params.limits map. Per-field
            // optional; engine decodes via decode_limits and falls
            // back to per-cap None when a field is absent. Omit the
            // whole `limits` key when no limit is set (matches Go's
            // omitempty convention so the wire shape stays
            // byte-identical for unlimited subscriptions).
            if let Some(limits) = &options.limits {
                let mut limit_fields: Vec<(ciborium::Value, ciborium::Value)> = Vec::new();
                if let Some(n) = limits.max_duration_ms {
                    limit_fields.push((
                        entity_ecf::text("max_duration_ms"),
                        entity_ecf::integer(n as i64),
                    ));
                }
                if let Some(n) = limits.max_events {
                    limit_fields.push((
                        entity_ecf::text("max_events"),
                        entity_ecf::integer(n as i64),
                    ));
                }
                if let Some(n) = limits.rate_limit {
                    limit_fields.push((
                        entity_ecf::text("rate_limit"),
                        entity_ecf::integer(n as i64),
                    ));
                }
                if !limit_fields.is_empty() {
                    params_map.push((
                        entity_ecf::text("limits"),
                        entity_ecf::Value::Map(limit_fields),
                    ));
                }
            }
            let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(params_map));
            let params = match Entity::new("system/subscription/subscribe-params", params_data) {
                Ok(e) => e,
                Err(e) => {
                    return Err(SdkError::HandlerError(format!(
                        "build subscribe params: {}",
                        e
                    )));
                }
            };

            // Dispatch through `system/subscription:subscribe`. We go
            // direct through `make_execute_fn` here (rather than the
            // public `execute`) so we can seed the `included` map with
            // the delivery-token entity, which the subscription handler
            // requires (spec §3.1).
            let mut included = std::collections::HashMap::new();
            included.insert(token_hash, token_entity);
            let opts = ExecuteOptions {
                resource: Some(ResourceTarget {
                    targets: vec![pattern.clone()],
                    exclude: vec![],
                }),
                ..Default::default()
            };
            let local_identity = shared.identity_hash;
            // Present the peer's owner self-cap as the caller capability for
            // LOCAL subscriptions. The subscription handler's include_payload
            // authorization (EXTENSION-SUBSCRIPTION §2.3) verifies the caller's
            // cap covers `tree:get` on the subscribed resource before it will
            // bundle entity content; with no cap presented, even a peer
            // subscribing to its own tree gets `403 payload_unauthorized`.
            // The owner self-cap covers the peer's own tree, so local
            // payload subscriptions work out of the box.
            //
            // Cross-peer stays `None`: the local owner cap is local-rooted and
            // the remote would reject it for the `subscribe` op (breaking the
            // receiver-rooted connection-grant fallback). Cross-peer
            // include_payload needs a remote-honored `tree:get` grant supplied
            // by the caller — the follow-helper capability path.
            let caller_cap = if remote_pid.is_none() {
                Some(owner_cap)
            } else {
                None
            };
            let execute_fn = entity_peer::connection::make_execute_fn(
                shared.clone(),
                Some(local_identity),
                included,
                None,
                caller_cap,
                // The peer dispatching as itself, not as a deputy (§5.2 D1).
                entity_peer::connection::DispatchCeiling::PeerRoot,
            );
            // Local: dispatch to bare `system/subscription` (local engine).
            // Cross-peer: dispatch to `entity://{remote}/system/subscription`
            // so the connection pool routes to the remote engine.
            let subscribe_target = match &remote_pid {
                Some(pid) => format!("entity://{}/system/subscription", pid),
                None => "system/subscription".to_string(),
            };
            let result = execute_fn(subscribe_target, "subscribe".into(), params, opts).await;

            let result = match result {
                Ok(r) if r.status == 200 => r,
                Ok(r) => {
                    // Preserve substrate `code` + `message` from the
                    // `system/protocol/error` body (e.g., B2 returns
                    // `sensitive_path` with the operator-class explanation).
                    // Falling back to the synthetic "subscribe: <pattern>"
                    // string here loses Ruling 1's reason vocabulary.
                    return Err(SdkError::from_handler_result(
                        &r,
                        format!("subscribe: {}", pattern),
                    )
                    .unwrap_or_else(|| {
                        SdkError::HandlerError(format!("unexpected status {}", r.status))
                    }));
                }
                Err(e) => {
                    return Err(SdkError::HandlerError(e.to_string()));
                }
            };

            let subscription_id = match parse_subscription_id(&result.result) {
                Some(id) => id,
                None => {
                    return Err(SdkError::HandlerError(
                        "subscribe result missing subscription_id".into(),
                    ));
                }
            };

            Ok(L1SubscriptionHandle {
                subscription_id,
                shared,
                registered,
                remote_pid,
            })
        }
    }

    /// Shared implementation for [`subscribe_raw_at`](Self::subscribe_raw_at):
    /// mint a self-grant for `deliver_uri`, dispatch `subscribe` with that URI
    /// as the `deliver_to`, and return a lean [`RawSubscriptionHandle`]. No
    /// SDK delivery handler is registered — the caller's `deliver_uri` is the
    /// real handler (e.g. a continuation inbox).
    fn subscribe_raw_internal(
        &self,
        pattern: String,
        deliver_uri: String,
        events: Vec<String>,
        remote_pid: Option<String>,
    ) -> impl std::future::Future<Output = Result<RawSubscriptionHandle, SdkError>> + 'static {
        let peer = self.peer();
        peer.start_engines(&self.peer_shared());
        let shared = self.peer_shared();

        // Mint a delivery grant authorizing `system/inbox:receive` at
        // `deliver_uri` (synchronous — avoids capturing &Keypair across await).
        let mint_result = mint_delivery_grant(
            peer.keypair()
                .as_ed25519()
                .expect("entity-sdk peers are Ed25519-only"),
            &deliver_uri,
            delivering_engine_identity(&shared, remote_pid.as_deref()),
            peer.content_store(),
        );

        async move {
            let (token_entity, token_hash) = mint_result?;

            // §2.2 vocabulary — the raw path takes the same names and owes the
            // same check; validating only the typed entry point would leave the
            // gap open for every caller that reaches for `subscribe_raw`.
            validate_event_vocabulary(&events)?;
            let events_values: Vec<ciborium::Value> = if events.is_empty() {
                vec![
                    entity_ecf::text("created"),
                    entity_ecf::text("updated"),
                    entity_ecf::text("deleted"),
                ]
            } else {
                events.iter().map(entity_ecf::text).collect()
            };
            let params_map: Vec<(ciborium::Value, ciborium::Value)> = vec![
                (
                    entity_ecf::text("deliver_to"),
                    entity_ecf::Value::Map(vec![
                        (entity_ecf::text("operation"), entity_ecf::text("receive")),
                        (entity_ecf::text("uri"), entity_ecf::text(&deliver_uri)),
                    ]),
                ),
                (
                    entity_ecf::text("deliver_token"),
                    entity_ecf::Value::Bytes(token_hash.to_bytes().to_vec()),
                ),
                (
                    entity_ecf::text("events"),
                    entity_ecf::Value::Array(events_values),
                ),
            ];
            let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(params_map));
            let params = Entity::new("system/subscription/subscribe-params", params_data)
                .map_err(|e| SdkError::HandlerError(format!("build subscribe params: {e}")))?;

            let mut included = std::collections::HashMap::new();
            included.insert(token_hash, token_entity);
            let opts = ExecuteOptions {
                resource: Some(ResourceTarget {
                    targets: vec![pattern.clone()],
                    exclude: vec![],
                }),
                ..Default::default()
            };
            let local_identity = shared.identity_hash;
            let execute_fn = entity_peer::connection::make_execute_fn(
                shared.clone(),
                Some(local_identity),
                included,
                None,
                None,
                // The peer dispatching as itself, not as a deputy (§5.2 D1).
                entity_peer::connection::DispatchCeiling::PeerRoot,
            );
            let subscribe_target = match &remote_pid {
                Some(pid) => format!("entity://{}/system/subscription", pid),
                None => "system/subscription".to_string(),
            };
            let result = execute_fn(subscribe_target, "subscribe".into(), params, opts).await;
            let result = match result {
                Ok(r) if r.status == 200 => r,
                Ok(r) => {
                    return Err(SdkError::from_handler_result(
                        &r,
                        format!("subscribe_raw: {pattern}"),
                    )
                    .unwrap_or_else(|| {
                        SdkError::HandlerError(format!("unexpected status {}", r.status))
                    }));
                }
                Err(e) => return Err(SdkError::HandlerError(e.to_string())),
            };
            let subscription_id = parse_subscription_id(&result.result).ok_or_else(|| {
                SdkError::HandlerError("subscribe_raw result missing subscription_id".into())
            })?;
            Ok(RawSubscriptionHandle {
                subscription_id,
                shared,
                remote_pid,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Subscription introspection + escape-hatch unsubscribe
// SDK-EXTENSION-OPERATIONS §3
// ---------------------------------------------------------------------------

/// Typed view of an active subscription stored at
/// `/{peer_id}/system/subscription/{id}`. Mirrors the spec's
/// `SubscriptionInfo` (SDK-EXTENSION-OPERATIONS §3) — a minimal subset
/// of the on-tree entity. Limits + delivery details are intentionally
/// elided here; fetch the raw entity via [`PeerContext::get`] if needed.
#[derive(Debug, Clone)]
pub struct SubscriptionInfo {
    pub subscription_id: String,
    pub pattern: String,
    pub events: Vec<String>,
}

impl SubscriptionInfo {
    fn from_entity(entity: &Entity) -> Option<Self> {
        let value: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).ok()?;
        let map = match &value {
            ciborium::Value::Map(m) => m,
            _ => return None,
        };

        let mut subscription_id = String::new();
        let mut pattern = String::new();
        let mut events: Vec<String> = Vec::new();

        for (k, v) in map {
            let key = match k {
                ciborium::Value::Text(s) => s.as_str(),
                _ => continue,
            };
            match key {
                "subscription_id" => {
                    if let ciborium::Value::Text(s) = v {
                        subscription_id = s.clone();
                    }
                }
                "pattern" => {
                    if let ciborium::Value::Text(s) = v {
                        pattern = s.clone();
                    }
                }
                "events" => {
                    if let ciborium::Value::Array(arr) = v {
                        for el in arr {
                            if let ciborium::Value::Text(s) = el {
                                events.push(s.clone());
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        if subscription_id.is_empty() {
            return None;
        }
        Some(SubscriptionInfo {
            subscription_id,
            pattern,
            events,
        })
    }
}

impl PeerContext {
    /// List active subscriptions on this peer by reading
    /// `/{peer_id}/system/subscription/{id}` entities. L0 store access —
    /// sync, no capability check (subscriptions are peer-local metadata).
    ///
    /// Useful for debugging or "show all subscriptions" UI; doesn't
    /// replace [`PeerContext::subscribe`], which is the canonical way
    /// to start one.
    pub fn list_subscriptions(&self) -> Vec<SubscriptionInfo> {
        let store = self.store();
        let prefix = format!("/{}/system/subscription/", self.peer_id());
        let entries = store.list(&prefix);

        let mut subs = Vec::new();
        for entry in entries {
            let entity = match store.get(&entry.path) {
                Some(e) => e,
                None => continue,
            };
            if let Some(info) = SubscriptionInfo::from_entity(&entity) {
                subs.push(info);
            }
        }
        subs.sort_by(|a, b| a.subscription_id.cmp(&b.subscription_id));
        subs
    }

    /// Explicit unsubscribe by id — escape hatch for cases where the
    /// caller does not (or no longer) holds the [`L1SubscriptionHandle`]
    /// returned by [`PeerContext::subscribe`].
    ///
    /// Prefer dropping the handle: that closes the SDK-internal delivery
    /// handler atomically with the unsubscribe RPC. This method only
    /// dispatches the RPC; any orphaned delivery handler stays registered
    /// until process exit.
    ///
    /// Returns an owning future so it can be spawned from sync contexts.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn unsubscribe(
        &self,
        subscription_id: impl Into<String>,
    ) -> impl std::future::Future<Output = Result<(), SdkError>> + Send + 'static {
        unsubscribe_dispatch(self.peer_shared(), subscription_id.into())
    }

    /// WASM variant — no `Send` bound required for `spawn_local`.
    #[cfg(target_arch = "wasm32")]
    pub fn unsubscribe(
        &self,
        subscription_id: impl Into<String>,
    ) -> impl std::future::Future<Output = Result<(), SdkError>> + 'static {
        unsubscribe_dispatch(self.peer_shared(), subscription_id.into())
    }
}

// ---------------------------------------------------------------------------
// Scope handle — per SDK-EXTENSION-OPERATIONS §1 (v0.7), typed
// per-extension accessor. Re-exposes the introspection ops here;
// `subscribe` / `subscribe_with_options` stay flat on PeerContext
// because their callback signature carries the variance the scope
// handle cannot abstract cleanly.
// ---------------------------------------------------------------------------

/// Typed accessor for `system/subscription` operations (the subset that
/// doesn't carry a callback). Created via
/// [`PeerContext::subscription`].
///
/// `subscribe` itself stays on [`PeerContext`] (and accepts a
/// [`SubscribeOptions`]) — the callback's `Fn` + `Send + Sync` bounds
/// would have to be re-declared on each scope-handle method,
/// duplicating the API without adding any value. The handle covers
/// the non-callback ops (`list`, `unsubscribe`) so the scope-handle
/// pattern from SDK-EXT-OPS §1 is honored.
pub struct SubscriptionOps<'a> {
    ctx: &'a PeerContext,
}

impl<'a> SubscriptionOps<'a> {
    pub(crate) fn new(ctx: &'a PeerContext) -> Self {
        Self { ctx }
    }

    /// List active subscriptions on this peer. See
    /// [`PeerContext::list_subscriptions`].
    pub fn list(&self) -> Vec<SubscriptionInfo> {
        self.ctx.list_subscriptions()
    }

    /// Explicit unsubscribe by id — see [`PeerContext::unsubscribe`]
    /// for caveats (escape-hatch path, doesn't clean up delivery
    /// handler).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn unsubscribe(
        &self,
        subscription_id: impl Into<String>,
    ) -> impl std::future::Future<Output = Result<(), SdkError>> + Send + 'static {
        self.ctx.unsubscribe(subscription_id)
    }

    /// WASM variant — no `Send` bound.
    #[cfg(target_arch = "wasm32")]
    pub fn unsubscribe(
        &self,
        subscription_id: impl Into<String>,
    ) -> impl std::future::Future<Output = Result<(), SdkError>> + 'static {
        self.ctx.unsubscribe(subscription_id)
    }
}

impl PeerContext {
    /// Typed accessor for `system/subscription` operations. Per
    /// SDK-EXTENSION-OPERATIONS §1 (v0.7). Available only when the
    /// `subscription` feature is enabled.
    pub fn subscription(&self) -> SubscriptionOps<'_> {
        SubscriptionOps::new(self)
    }
}

// Deliberate `-> impl Future + 'static` rather than `async fn`: the explicit
// bound is the signature-level guarantee that this future outlives the
// borrowed accessor, so a later borrowed param fails to compile instead of
// silently producing a non-'static future the `BoxFuture<'static>` consumers
// can't take (see AGENTS.md, "SDK 'static futures").
#[allow(clippy::manual_async_fn)]
fn unsubscribe_dispatch(
    shared: Arc<PeerShared>,
    subscription_id: String,
) -> impl std::future::Future<Output = Result<(), SdkError>> + 'static {
    async move {
        let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("subscription_id"),
            entity_ecf::text(&subscription_id),
        )]));
        let params = Entity::new("system/subscription/cancel-params", params_data)
            .map_err(|e| SdkError::HandlerError(format!("build cancel-params: {}", e)))?;

        let local_identity = shared.identity_hash;
        let execute_fn = entity_peer::connection::make_execute_fn(
            shared,
            Some(local_identity),
            std::collections::HashMap::new(),
            None,
            None,
            // The peer dispatching as itself, not as a deputy (§5.2 D1).
            entity_peer::connection::DispatchCeiling::PeerRoot,
        );
        let result = execute_fn(
            "system/subscription".into(),
            "unsubscribe".into(),
            params,
            ExecuteOptions::default(),
        )
        .await
        .map_err(|e| SdkError::HandlerError(e.to_string()))?;

        if result.status == 200 {
            Ok(())
        } else {
            Err(
                SdkError::from_handler_result(&result, "unsubscribe").unwrap_or_else(|| {
                    SdkError::HandlerError(format!("unsubscribe: status {}", result.status))
                }),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Build the body closure for an SDK-internal subscription delivery handler.
/// Returned body is passed to `register_handler`; the SDK adapter wraps it
/// into the core `Handler` trait.
fn build_delivery_body(
    callback: Arc<dyn Fn(L1SubscriptionEvent) + Send + Sync + 'static>,
) -> HandlerBody {
    Arc::new(move |ctx: &HandlerContext| {
        // Synchronously extract what we need from ctx — the returned
        // future owns its captured state, so we can't borrow across await.
        let operation_is_receive = ctx.operation == "receive";
        let maybe_event = if operation_is_receive {
            // Enrich the decoded event with the changed entity when the
            // subscription opted into include_payload: the engine bundles
            // it into the delivery envelope's `included` map keyed by the
            // new hash (EXTENSION-SUBSCRIPTION §2.2), and the peer's deliver
            // closure threads that map through to this dispatch, so it
            // arrives here as `ctx.included`. Resolving it now hands the
            // subscriber the entity in-band — the convergent-mirror recipe,
            // no `tree:get` round-trip. A source-side resolution miss (or a
            // hashes-only subscription) leaves `included: None` and the
            // subscriber may fall back to a fetch.
            decode_notification(&ctx.params).map(|mut ev| {
                if let Some(h) = ev.new_hash {
                    ev.included = ctx.included.get(&h).cloned();
                }
                ev
            })
        } else {
            None
        };
        let callback = callback.clone();
        Box::pin(async move {
            if !operation_is_receive {
                let err_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                    entity_ecf::text("reason"),
                    entity_ecf::text("unknown operation"),
                )]));
                let err = Entity::new("error", err_data)
                    .map_err(|e| HandlerError::Internal(e.to_string()))?;
                return Ok(HandlerResult::error(400, err));
            }
            if let Some(event) = maybe_event {
                (callback)(event);
            }
            // Even on decode failure we return 200 — the engine already
            // committed to the delivery; surfacing an error here would
            // just log noise without helping the caller.
            let ok_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(Vec::new()));
            let ok = Entity::new("system/protocol/inbox/receipt", ok_data)
                .map_err(|e| HandlerError::Internal(e.to_string()))?;
            Ok(HandlerResult::ok(ok))
        })
    })
}

/// Decode the `system/subscription/notification` entity dispatched by
/// the subscription engine.
fn decode_notification(entity: &Entity) -> Option<L1SubscriptionEvent> {
    let value: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).ok()?;
    let map = value.as_map()?;

    let mut subscription_id = None;
    let mut event = None;
    let mut path = None;
    let mut new_hash = None;
    let mut previous_hash = None;

    for (k, v) in map {
        match k.as_text() {
            Some("subscription_id") => subscription_id = v.as_text().map(|s| s.to_string()),
            Some("event") => event = v.as_text().map(|s| s.to_string()),
            Some("uri") => path = v.as_text().map(|s| s.to_string()),
            Some("hash") => {
                if let ciborium::Value::Bytes(b) = v {
                    new_hash = Hash::from_bytes(b).ok();
                }
            }
            Some("previous_hash") => {
                if let ciborium::Value::Bytes(b) = v {
                    previous_hash = Hash::from_bytes(b).ok();
                }
            }
            _ => {}
        }
    }

    let event = event?;

    // Honor the documented contract `new_hash: None on delete`. The
    // subscription engine's notification reuses the single `hash` field for
    // two meanings: on create/update it is the NEW entity's hash, but on a
    // delete it is the REMOVED entity's OLD hash. That comes straight from
    // `remove_impl` dispatching `dispatch_event(path, prev, Some(prev), None,
    // Deleted)` (core/store) → `build_notification(.., "deleted", .., &event.hash,
    // ..)` (extensions/subscription) writing `prev` into `hash`. Reading that
    // blindly into `new_hash` makes a delete look like a write: the Worker-arm
    // host callback resolves the (content-addressed, still-present) old blob and
    // ships `Change{new_entity: Some(..)}`, so the proxy mirror re-inserts the
    // entity and the deletion never reflects (the "creates reflect, deletes
    // don't" bug). The `event`
    // string is the authoritative discriminator — clear `new_hash` on a delete.
    let new_hash = if event == "deleted" { None } else { new_hash };

    Some(L1SubscriptionEvent {
        subscription_id: subscription_id?,
        event,
        path: path?,
        new_hash,
        previous_hash,
        // Populated by the caller (`build_delivery_body`) from the dispatch
        // envelope's `included` map — this decoder only sees the
        // notification entity, not the bundled payload.
        included: None,
    })
}

/// Build + sign a self-grant capability token authorizing `deliver_uri`
/// for `receive`, store the token and its signature in the content
/// store, and return `(token_entity, token_hash)`.
/// Mint the `deliver_token` a subscriber hands the engine that will deliver to
/// it (EXTENSION-SUBSCRIPTION §1.2 / §3.1).
///
/// `delivering_engine` is the identity hash of the peer that will **originate**
/// the delivery — the remote subscription host for a cross-peer subscription,
/// and this peer itself for a local one. It becomes the token's `grantee`, and
/// that is the `0.8.2.19` Phase-1 change.
///
/// **Why the grantee is not the subscriber.** `ENTITY-CORE-PROTOCOL` §1.4 makes
/// autonomous delivery an in-scope outbound sub-dispatch, relaxed on Dimension 4
/// by *the credential the RECIPIENT armed it with* — this token. The presented
/// arm requires the leaf `grantee` to resolve to the **local** peer at the seat
/// making the dispatch, which is the delivering engine, not us. Minted as a
/// self-grant (`grantee` = the subscriber) the token is well-formed, A-rooted,
/// and **relaxes nothing**, so a host that correctly gates its delivery engine
/// would refuse every cross-peer delivery we asked for. The token was the gap,
/// not the gate.
///
/// **Phase 1 of a sequenced three-seat change, and only phase 1.** Arch's
/// ordering (`ROUTING-2026-09-10-e`): every seat MINTS the conformant shape
/// first, no seat GATES until all three do. Receivers accept either shape
/// throughout, and this seat's own admission check is unaffected — subscribe
/// runs `check_creator_authority`, which matches on the **granter** (still the
/// subscriber) and never reads `grantee`. Do not pair this with flipping
/// `DispatchCeiling::PeerRoot` in `core/peer/src/lib.rs`; that is phase 2 and it
/// is not ours to start.
///
/// `peers` stays **absent**, not `["*"]`: absent defaults to the granter's own
/// peer, which is precisely where the delivery goes, and a wildcard would make
/// the dimension this token exists to satisfy vacuous.
/// Identity hash of the peer whose engine will originate deliveries for this
/// subscription — the `grantee` of the `deliver_token` (§1.4 / `0.8.2.19`
/// phase 1; see [`mint_delivery_grant`]).
///
/// `None` for a local subscription: this peer subscribes and this peer's engine
/// delivers, so the delivering engine IS the local identity and the token is
/// legitimately a self-grant. `Some(pid)` resolves the remote's identity hash —
/// derived from the PeerID itself for identity-form pids, and from the session
/// entity learned at handshake for SHA-256-form ones, which is why this runs
/// after `connect_to` rather than at handle construction.
///
/// **Falls back to the local identity when the remote cannot be resolved**, and
/// that is deliberate: the pre-`0.8.2.19` shape. A subscribe that cannot name
/// its host's identity is not a subscribe we should refuse in phase 1, where no
/// seat gates — refusing here would turn a mint change into an availability
/// change, which is the one thing the phased ordering exists to prevent. The
/// `debug` line is the tell if a host later gates and this seat's deliveries
/// start being refused.
fn delivering_engine_identity(shared: &Arc<PeerShared>, remote_pid: Option<&str>) -> Hash {
    let Some(pid) = remote_pid else {
        return shared.identity_hash;
    };
    match entity_peer::remote::resolve_peer_identity_hash(
        pid,
        shared.content_store.as_ref(),
        shared.location_index.as_ref(),
        shared.peer_id.as_str(),
    ) {
        Some(h) => h,
        None => {
            tracing::debug!(
                remote_peer = %pid,
                "deliver_token: could not resolve the delivering engine's identity \
                 — minting the pre-0.8.2.19 self-grant shape, which relaxes nothing \
                 at a host that gates its delivery engine (§1.4)"
            );
            shared.identity_hash
        }
    }
}

fn mint_delivery_grant(
    keypair: &Keypair,
    deliver_uri: &str,
    delivering_engine: Hash,
    content_store: &Arc<dyn ContentStore>,
) -> Result<(Entity, Hash), SdkError> {
    // Identity hash: the content hash of the peer's identity entity.
    let peer_entity = keypair
        .peer_entity()
        .map_err(|e| SdkError::HandlerError(format!("build peer entity: {}", e)))?;
    let identity_hash = peer_entity.content_hash;

    let now_ms = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let token = CapabilityToken {
        grants: vec![GrantEntry {
            handlers: PathScope::new(vec!["system/inbox".into()]),
            resources: PathScope::new(vec![deliver_uri.into()]),
            operations: IdScope::new(vec!["receive".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        }],
        // A-rooted: the subscriber grants, so §1.4's root-granter-is-the-target
        // check passes at the delivering seat (the target of its dispatch is us).
        granter: entity_capability::Granter::Single(identity_hash),
        // The delivering ENGINE, not the subscriber — see the fn doc.
        grantee: delivering_engine,
        parent: None,
        created_at: now_ms,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };

    let token_entity = token
        .to_entity()
        .map_err(|e| SdkError::HandlerError(format!("encode grant: {}", e)))?;
    let token_hash = content_store
        .put(token_entity.clone())
        .map_err(|e| SdkError::HandlerError(format!("put grant: {}", e)))?;

    // Sign and store the signature entity.
    let sig_bytes = keypair.sign(&token_entity.content_hash.to_bytes());
    let sig_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (entity_ecf::text("algorithm"), entity_ecf::text("ed25519")),
        (
            entity_ecf::text("signature"),
            entity_ecf::Value::Bytes(sig_bytes.to_vec()),
        ),
        (
            entity_ecf::text("signer"),
            entity_ecf::Value::Bytes(identity_hash.to_bytes().to_vec()),
        ),
        (
            entity_ecf::text("target"),
            entity_ecf::Value::Bytes(token_entity.content_hash.to_bytes().to_vec()),
        ),
    ]));
    let sig_entity = Entity::new(TYPE_SIGNATURE, sig_data)
        .map_err(|e| SdkError::HandlerError(format!("build signature: {}", e)))?;
    content_store
        .put(sig_entity)
        .map_err(|e| SdkError::HandlerError(format!("put signature: {}", e)))?;

    Ok((token_entity, token_hash))
}

/// Parse subscription_id from a `system/subscription/result` entity.
fn parse_subscription_id(result: &Entity) -> Option<String> {
    let value: ciborium::Value = ciborium::from_reader(result.data.as_slice()).ok()?;
    let map = value.as_map()?;
    for (k, v) in map {
        if k.as_text() == Some("subscription_id") {
            return v.as_text().map(|s| s.to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk::PeerContextBuilder;
    use std::sync::Mutex;

    fn make_peer_context() -> PeerContext {
        PeerContextBuilder::new()
            .generate_keypair()
            .build()
            .expect("PeerContext build should succeed")
    }

    fn make_entity(entity_type: &str, content: &str) -> Entity {
        let data = entity_ecf::to_ecf(&entity_ecf::text(content));
        Entity::new(entity_type, data).unwrap()
    }

    /// Pump the event bridge long enough for the subscription engine to
    /// pick up a tree-change event off its broadcast and dispatch the
    /// notification back through the SDK delivery handler. 50ms has
    /// been enough in practice — the full chain is sync-ish once the
    /// event lands on the broadcast.
    async fn pump() {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    #[tokio::test]
    async fn l1_subscribe_delivers_put_as_created() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();

        let received: Arc<Mutex<Vec<L1SubscriptionEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = received.clone();

        let prefix = format!("/{}/app/test/l1subs/", pid);
        let handle = ctx
            .subscribe(format!("{}*", prefix), move |ev| {
                sink.lock().unwrap().push(ev);
            })
            .await
            .expect("subscribe should succeed");

        let target = format!("{}one", prefix);
        ctx.store().put(&target, make_entity("t", "hello")).unwrap();
        pump().await;

        let events = received.lock().unwrap().clone();
        assert_eq!(events.len(), 1, "exactly one event delivered");
        let ev = &events[0];
        assert_eq!(ev.event, "created");
        assert_eq!(ev.path, target);
        assert!(ev.new_hash.is_some());
        assert!(!handle.subscription_id().is_empty());
        // Default subscribe is hashes-only: no payload bundled.
        assert!(
            ev.included.is_none(),
            "default subscribe must not bundle the entity"
        );
    }

    /// A subscription that opts into `include_payload` receives the changed
    /// entity in-band on `L1SubscriptionEvent.included` — the
    /// convergent-mirror recipe, no `tree:get` round-trip. Exercises the
    /// full engine → deliver-closure → decode chain: the engine bundles the
    /// entity into the delivery envelope's `included` map, the peer's
    /// deliver closure threads it to the receive dispatch, and
    /// `build_delivery_body` resolves it by `new_hash` from `ctx.included`.
    #[tokio::test]
    async fn l1_subscribe_with_payload_bundles_the_changed_entity() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();

        let received: Arc<Mutex<Vec<L1SubscriptionEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = received.clone();

        let prefix = format!("/{}/app/test/l1subs_payload/", pid);
        let _handle = ctx
            .subscribe_with_options(
                format!("{}*", prefix),
                SubscribeOptions::with_payload(),
                move |ev| {
                    sink.lock().unwrap().push(ev);
                },
            )
            .await
            .expect("subscribe_with_options should succeed");

        let target = format!("{}one", prefix);
        ctx.store()
            .put(&target, make_entity("t", "payload-body"))
            .unwrap();
        pump().await;

        let events = received.lock().unwrap().clone();
        assert_eq!(events.len(), 1, "exactly one event delivered");
        let ev = &events[0];
        assert_eq!(ev.event, "created");
        assert_eq!(ev.path, target);
        let bundled = ev
            .included
            .as_ref()
            .expect("include_payload must deliver the changed entity in-band");
        assert_eq!(
            bundled.content_hash,
            ev.new_hash.expect("create carries new_hash"),
            "bundled entity's hash matches the event's new_hash"
        );
        assert_eq!(
            bundled,
            &make_entity("t", "payload-body"),
            "bundled entity is the one that was written"
        );
    }

    /// A delete must arrive as `new_hash: None`, honoring the documented
    /// `L1SubscriptionEvent` contract — even though the engine's notification
    /// reuses the single `hash` field to carry the REMOVED entity's OLD hash on
    /// a delete (build_notification + remove_impl's dispatch_event(.., Deleted)).
    /// Regression for the backend peer-delete bug: decode
    /// used to read that old hash into `new_hash`, so the Worker-arm proxy saw
    /// `Change{new_entity: Some(old_blob)}` and re-inserted the deleted entity
    /// ("creates reflect, deletes don't"). Exercises the full engine→decode
    /// chain, not decode_notification in isolation.
    #[tokio::test]
    async fn l1_subscribe_delivers_remove_with_no_new_hash() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();

        let received: Arc<Mutex<Vec<L1SubscriptionEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = received.clone();

        let prefix = format!("/{}/app/test/l1subs_del/", pid);
        let _handle = ctx
            .subscribe(format!("{}*", prefix), move |ev| {
                sink.lock().unwrap().push(ev);
            })
            .await
            .expect("subscribe should succeed");

        let target = format!("{}one", prefix);
        ctx.store().put(&target, make_entity("t", "hello")).unwrap();
        pump().await;
        assert!(ctx.store().remove(&target), "remove should drop the entry");
        pump().await;

        let events = received.lock().unwrap().clone();
        let del = events
            .iter()
            .find(|e| e.event == "deleted")
            .expect("a delete event was delivered");
        assert_eq!(del.path, target);
        assert!(
            del.new_hash.is_none(),
            "delete must carry new_hash=None (L1 contract); got {:?}",
            del.new_hash
        );
        assert!(
            del.previous_hash.is_some(),
            "delete carries the removed entity's previous_hash"
        );
    }

    #[tokio::test]
    async fn l1_subscribe_drop_cancels_delivery() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();

        let received: Arc<Mutex<Vec<L1SubscriptionEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = received.clone();

        let prefix = format!("/{}/app/test/l1subs_drop/", pid);
        let handle = ctx
            .subscribe(format!("{}*", prefix), move |ev| {
                sink.lock().unwrap().push(ev);
            })
            .await
            .expect("subscribe should succeed");

        ctx.store()
            .put(&format!("{}a", prefix), make_entity("t", "1"))
            .unwrap();
        pump().await;
        assert_eq!(received.lock().unwrap().len(), 1);

        drop(handle);
        pump().await;

        ctx.store()
            .put(&format!("{}b", prefix), make_entity("t", "2"))
            .unwrap();
        pump().await;
        assert_eq!(
            received.lock().unwrap().len(),
            1,
            "no further events after drop"
        );
    }

    #[tokio::test]
    async fn l1_subscribe_filters_non_matching_path() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();

        let received: Arc<Mutex<Vec<L1SubscriptionEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = received.clone();

        let watched = format!("/{}/app/test/l1_watched/*", pid);
        let _handle = ctx
            .subscribe(watched, move |ev| {
                sink.lock().unwrap().push(ev);
            })
            .await
            .expect("subscribe should succeed");

        ctx.store()
            .put(
                &format!("/{}/app/test/l1_other/x", pid),
                make_entity("t", "x"),
            )
            .unwrap();
        pump().await;
        assert!(received.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn l1_subscribe_handler_is_tree_declared() {
        // §11.5 invariant: the SDK-internal delivery handler is declared
        // in the tree (interface + handler entities), not just installed
        // in the dispatch index. Verifies §11.5.7's `system/sdk/` prefix.
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();

        let prefix = format!("/{}/app/test/tree_decl/", pid);
        let handle = ctx
            .subscribe(format!("{}*", prefix), |_ev| {})
            .await
            .expect("subscribe should succeed");

        let handler_path = handle.handler_pattern().to_string();
        assert!(
            handler_path.starts_with(&format!("/{}/system/sdk/subs/", pid)),
            "delivery handler under system/sdk/ prefix, got: {}",
            handler_path
        );
        let interface_path = handler_path.replacen(
            &format!("/{}/", pid),
            &format!("/{}/system/handler/", pid),
            1,
        );

        assert!(
            ctx.store().get(&handler_path).is_some(),
            "handler entity tree-declared at {}",
            handler_path
        );
        assert!(
            ctx.store().get(&interface_path).is_some(),
            "interface entity tree-declared at {}",
            interface_path
        );

        drop(handle);
        assert!(
            ctx.store().get(&handler_path).is_none(),
            "handler entity removed on drop"
        );
        assert!(
            ctx.store().get(&interface_path).is_none(),
            "interface entity removed on drop"
        );
    }

    #[tokio::test]
    async fn list_subscriptions_empty_on_fresh_peer() {
        let ctx = make_peer_context();
        assert!(ctx.list_subscriptions().is_empty());
    }

    // -- D3: subscribe_at (Godot ask, Go-symmetric naming) --
    //
    // Surface-level round-trip: A connects to B, A calls subscribe_at(B,
    // pattern), the handle carries a remote_pid so its Drop will
    // unsubscribe at B.
    //
    // Full delivery round-trip (B writes → A's callback fires) over the
    // memory transport is proven in-process by
    // `follow::tests::follow_payload_delivers_reactively_cross_peer` — it needs
    // a symmetric (rendezvous) establishment so the acceptor holds the §6.5(b)
    // reciprocal reentry grant, plus B's engines started. This test asserts
    // only the subscribe/unsubscribe surface, so it uses a plain dial.

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn subscribe_at_round_trips_to_remote_engine() {
        use entity_peer::transport::{MemoryConnector, MemoryListener, MemoryTransportRegistry};
        use entity_peer::PeerConfig;
        let reg = MemoryTransportRegistry::new();

        // `debug_open_grants` so B confers wide grants to A on connect
        // — sidesteps the cap-chain wiring (Godot's separate task #11)
        // and lets us prove the SDK surface end-to-end.
        let open_cfg = || PeerConfig {
            debug_open_grants: true,
            ..PeerConfig::default()
        };

        let ctx_a = PeerContextBuilder::new()
            .generate_keypair()
            .config(open_cfg())
            .connector(Arc::new(MemoryConnector::new(reg.clone())))
            .build()
            .expect("ctx_a build");

        let ctx_b = PeerContextBuilder::new()
            .generate_keypair()
            .config(open_cfg())
            .connector(Arc::new(MemoryConnector::new(reg.clone())))
            .build()
            .expect("ctx_b build");
        let b_pid = ctx_b.peer_id().to_string();
        let listener =
            MemoryListener::bind(b_pid.clone(), reg.clone()).expect("bind MemoryListener");
        let b_shared = ctx_b.peer_shared();
        let b_shared_for_assert = ctx_b.peer_shared();
        let server_task = tokio::spawn(async move {
            let _ = entity_peer::server::run(listener, b_shared).await;
        });

        // A must have a live connection to B for subscribe_at to reach
        // B's subscription engine.
        ctx_a
            .connect_to(&format!("memory://{b_pid}"))
            .await
            .expect("connect_to should succeed");

        // Subscribe on B's tree, pattern interpreted against B's paths.
        // The exact pattern doesn't matter for the surface assertion —
        // we just need B's engine to accept the subscribe.
        let watch = format!("/{}/app/test/cross_peer/*", b_pid);
        let handle = ctx_a
            .subscribe_at(b_pid.clone(), watch, |_ev| {})
            .await
            .expect("subscribe_at should reach B's engine");
        assert!(
            !handle.subscription_id().is_empty(),
            "subscription_id assigned by B's engine"
        );

        // List on B confirms B owns the subscription state — the engine
        // accepted + persisted it locally even though A initiated.
        let subs_on_b = ctx_b.list_subscriptions();
        assert_eq!(
            subs_on_b.len(),
            1,
            "B's engine should hold the subscription created by A"
        );
        assert_eq!(subs_on_b[0].subscription_id, handle.subscription_id());

        // --- §1.4 / 0.8.2.19 phase 1: the deliver_token B's engine will
        // --- deliver under must name B as its grantee.
        //
        // B holds the subscription, so B's copy of the token is the one that
        // matters — read it out of B's own store, not A's, so this asserts what
        // travelled rather than what we built.
        let token = {
            let sub_path = format!(
                "/{}/system/subscription/{}",
                b_pid, subs_on_b[0].subscription_id
            );
            let sub_entity = b_shared_for_assert
                .location_index
                .get(&sub_path)
                .and_then(|h| b_shared_for_assert.content_store.get(&h))
                .expect("B persisted the subscription it accepted");
            // Field-decoded rather than via `entity-subscription`'s decoder:
            // the SDK does not depend on that crate directly and the crate DAG
            // is not worth bending for one test read.
            let v: ciborium::Value =
                ciborium::from_reader(sub_entity.data.as_slice()).expect("subscription decodes");
            let token_hash = v
                .as_map()
                .and_then(|m| {
                    m.iter()
                        .find(|(k, _)| k.as_text() == Some("deliver_token"))
                        .and_then(|(_, val)| val.as_bytes())
                        .and_then(|b| Hash::from_bytes(b).ok())
                })
                .expect("subscription carries its deliver_token hash");
            b_shared_for_assert
                .content_store
                .get(&token_hash)
                .expect("B holds the deliver_token it accepted")
        };
        let cap =
            entity_capability::CapabilityToken::from_entity(&token).expect("deliver_token decodes");
        assert_eq!(
            cap.grantee, b_shared_for_assert.identity_hash,
            "EXTENSION-SUBSCRIPTION §1.2 / ENTITY-CORE-PROTOCOL §1.4: the \
             deliver_token's grantee is the DELIVERING ENGINE (B), not the \
             subscriber. Minted as a self-grant it is well-formed and A-rooted \
             and relaxes NOTHING at B, so a host that correctly gates its \
             delivery engine refuses every delivery we asked for."
        );
        assert_eq!(
            cap.granter,
            entity_capability::Granter::Single(ctx_a.peer_shared().identity_hash),
            "and it stays A-rooted — §1.4's root-granter check at B asks whether \
             the root granter is the TARGET of B's dispatch, which is A. Both \
             halves or neither: A-rooted with the wrong grantee is the shape \
             that was already here, and B-rooted with the right grantee is go's \
             non-conformant one."
        );
        for g in &cap.grants {
            assert!(
                g.peers.is_none(),
                "peers absent, not [*] — this credential exists to satisfy \
                 Dimension 4, and a wildcard makes that dimension vacuous"
            );
        }
        // **Mutations RUN, not predicted** (0.8.2.19 phase 1, 2026-09-10):
        //   `grantee: delivering_engine` → `grantee: identity_hash` (restore the
        //     self-grant) — this row reddens on the grantee assertion, and it is
        //     the only test in the crate that moves.
        //   `peers: None` → `Some(["*"])` — this row reddens on the peers
        //     assertion, and again nothing else does.
        // The two are disjoint, and the second is the one that matters most for
        // the class: a wildcard `peers` LOOKS more permissive and is actually
        // the shape that deletes the check, so a suite that only pinned the
        // grantee would have called the token conformant.
        //
        // The **control is one test down**: `subscribe_at_self_id_delegates_to_
        // local`, where the delivering engine IS the local peer, so the grantee
        // is legitimately the subscriber. Without it, "grantee = the remote"
        // reads as a rule about remoteness rather than about who delivers, and
        // the local path would be the next thing someone "fixed."

        // Drop fires unsubscribe at B (remote_pid path).
        drop(handle);
        pump().await;
        pump().await;
        let remaining = ctx_b.list_subscriptions();
        assert!(
            remaining.is_empty(),
            "B's engine should have removed subscription after A's handle drop"
        );

        server_task.abort();
    }

    #[tokio::test]
    async fn subscribe_at_self_id_delegates_to_local() {
        // Per Go SDK convention: subscribe_at(self.peer_id(), ...) is
        // equivalent to subscribe(...). The implementation
        // short-circuits to None remote_pid when the target equals
        // self, so the Drop unsubscribe stays local (no entity:// RPC
        // attempted on a remote that doesn't exist).
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let received: Arc<Mutex<Vec<L1SubscriptionEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = received.clone();

        let prefix = format!("/{}/app/test/subscribe_at_self/", pid);
        let _handle = ctx
            .subscribe_at(pid.clone(), format!("{}*", prefix), move |ev| {
                sink.lock().unwrap().push(ev);
            })
            .await
            .expect("subscribe_at(self_id, ...) should succeed via local path");

        let target = format!("{}one", prefix);
        ctx.store().put(&target, make_entity("t", "hi")).unwrap();
        pump().await;

        let events = received.lock().unwrap().clone();
        assert_eq!(events.len(), 1, "local delivery should fire exactly once");
        assert_eq!(events[0].path, target);

        // **The control for the phase-1 grantee rule** (§1.4 / 0.8.2.19). On the
        // local path the delivering engine IS this peer, so the deliver_token is
        // legitimately a self-grant: granter == grantee == us. That is not an
        // exception to the rule, it is the rule — the grantee is *whoever will
        // originate the delivery*, and remoteness is incidental.
        //
        // It earns its place by what it forbids: without it, the cross-peer row
        // above is satisfied by "always name the remote", which has no answer
        // for a local subscription and would mint a token granted to nobody.
        let shared = ctx.peer_shared();
        let sub_id = ctx
            .list_subscriptions()
            .first()
            .map(|s| s.subscription_id.clone())
            .expect("the local subscription is registered");
        let sub_entity = shared
            .location_index
            .get(&format!("/{}/system/subscription/{}", pid, sub_id))
            .and_then(|h| shared.content_store.get(&h))
            .expect("subscription entity persisted locally");
        let v: ciborium::Value =
            ciborium::from_reader(sub_entity.data.as_slice()).expect("subscription decodes");
        let token_hash = v
            .as_map()
            .and_then(|m| {
                m.iter()
                    .find(|(k, _)| k.as_text() == Some("deliver_token"))
                    .and_then(|(_, val)| val.as_bytes())
                    .and_then(|b| Hash::from_bytes(b).ok())
            })
            .expect("subscription carries its deliver_token hash");
        let cap = entity_capability::CapabilityToken::from_entity(
            &shared.content_store.get(&token_hash).expect("token stored"),
        )
        .expect("deliver_token decodes");
        assert_eq!(
            cap.grantee, shared.identity_hash,
            "local subscription: the delivering engine is this peer, so the              self-grant is the CONFORMANT shape here"
        );
        assert_eq!(
            cap.granter,
            entity_capability::Granter::Single(shared.identity_hash)
        );
    }

    #[tokio::test]
    async fn list_subscriptions_finds_active_one() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let prefix = format!("/{}/app/test/listed/", pid);

        let _handle = ctx
            .subscribe(format!("{}*", prefix), |_| {})
            .await
            .expect("subscribe should succeed");

        let subs = ctx.list_subscriptions();
        assert_eq!(subs.len(), 1, "one active subscription expected");
        let info = &subs[0];
        assert_eq!(info.pattern, format!("{}*", prefix));
        assert!(!info.subscription_id.is_empty());
    }

    #[tokio::test]
    async fn list_subscriptions_sorted_by_id() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();

        let _h1 = ctx
            .subscribe(format!("/{}/a/*", pid), |_| {})
            .await
            .unwrap();
        let _h2 = ctx
            .subscribe(format!("/{}/b/*", pid), |_| {})
            .await
            .unwrap();
        let _h3 = ctx
            .subscribe(format!("/{}/c/*", pid), |_| {})
            .await
            .unwrap();

        let subs = ctx.list_subscriptions();
        assert_eq!(subs.len(), 3);
        for pair in subs.windows(2) {
            assert!(pair[0].subscription_id <= pair[1].subscription_id);
        }
    }

    #[tokio::test]
    async fn explicit_unsubscribe_removes_from_listing() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();

        let handle = ctx
            .subscribe(format!("/{}/explicit/*", pid), |_| {})
            .await
            .expect("subscribe should succeed");
        let id = handle.subscription_id().to_string();
        assert_eq!(ctx.list_subscriptions().len(), 1);

        // Explicit unsubscribe by id removes the tree entry.
        ctx.unsubscribe(&id)
            .await
            .expect("unsubscribe should succeed");
        // Drop the handle separately — its drop will redundantly fire
        // unsubscribe (already done) but won't error.
        drop(handle);

        assert!(
            ctx.list_subscriptions().is_empty(),
            "no active subscriptions after explicit unsubscribe"
        );
    }

    // -----------------------------------------------------------------
    // SubscribeOptions + scope-handle tests (Amendment B.1, v0.7)
    // -----------------------------------------------------------------

    /// `SubscribeOptions::default()` MUST yield the lean (no payload)
    /// shape — i.e. the existing `subscribe()` API behavior. This
    /// pins the backward-compat invariant in the refactor.
    #[test]
    fn subscribe_options_default_is_lean() {
        let opts = SubscribeOptions::default();
        assert!(!opts.include_payload);
    }

    #[test]
    fn subscribe_options_with_payload_helper() {
        let opts = SubscribeOptions::with_payload();
        assert!(opts.include_payload);
    }

    /// `subscribe_with_options(pattern, default(), callback)` delivers
    /// identically to `subscribe(pattern, callback)` — proves the
    /// internal refactor preserves the existing API's behavior at the
    /// default-options path.
    #[tokio::test]
    async fn subscribe_with_options_default_delivers_like_subscribe() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();

        let received: Arc<Mutex<Vec<L1SubscriptionEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = received.clone();

        let prefix = format!("/{}/app/test/opts/", pid);
        let _handle = ctx
            .subscribe_with_options(
                format!("{}*", prefix),
                SubscribeOptions::default(),
                move |ev| {
                    sink.lock().unwrap().push(ev);
                },
            )
            .await
            .expect("subscribe_with_options should succeed");

        let target = format!("{}one", prefix);
        ctx.store().put(&target, make_entity("t", "hello")).unwrap();
        pump().await;

        let events = received.lock().unwrap().clone();
        assert_eq!(events.len(), 1, "exactly one event delivered");
        assert_eq!(events[0].event, "created");
    }

    /// `subscribe_with_options(pattern, with_payload(), callback)`
    /// reaches the handler. The handler enforces the
    /// EXTENSION-SUBSCRIPTION §2.3 read-auth check
    /// (`include_payload` requires `tree:get` cap on the resource)
    /// and may reject with `403 payload_unauthorized` when the
    /// caller's authority chain doesn't cover `tree:get` on the
    /// subscribed prefix. Either outcome proves the field is
    /// threaded through end-to-end. End-to-end payload bundling
    /// verification belongs in a cross-peer integration test
    /// (out of scope here).
    #[tokio::test]
    async fn subscribe_with_options_payload_threads_field_through() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();

        let prefix = format!("/{}/app/test/payload/", pid);
        let result = ctx
            .subscribe_with_options(
                format!("{}*", prefix),
                SubscribeOptions::with_payload(),
                |_| {},
            )
            .await;
        match &result {
            Ok(_) => {} // Handler accepted (caller has tree:get).
            Err(SdkError::Forbidden { status, .. }) => {
                // 403 = payload_unauthorized — caller lacks tree:get.
                // Proves the field reached the handler, which then
                // enforced the read-auth check (v3.13 normative).
                assert_eq!(*status, 403);
            }
            Err(SdkError::HandlerError(msg)) => {
                assert!(
                    msg.contains("payload_unauthorized") || msg.contains("403"),
                    "expected payload_unauthorized or 403, got: {}",
                    msg
                );
            }
            Err(other) => panic!("unexpected error variant: {:?}", other),
        }
    }

    /// SA-2 — an event name outside EXTENSION-SUBSCRIPTION §2.2's vocabulary is
    /// rejected at `subscribe`, not passed through.
    ///
    /// The engine is correct and unchanged: it accepts any name and filters
    /// deliveries against it. That is precisely what makes an unvalidated
    /// wrapper dangerous — an unknown name is not an error anywhere downstream,
    /// it is a filter matching nothing. Before this, the caller got a
    /// subscription that was created, returned an id, and never fired for its
    /// entire lifetime, with no error at any layer to explain the silence. The
    /// reachable case is a caller following the pre-fix SDK-EXTENSION-OPERATIONS
    /// §3 vocabulary.
    ///
    /// Teeth: delete the `validate_event_vocabulary` call in
    /// `subscribe_internal` and this returns Ok with a live, silent handle.
    #[tokio::test]
    async fn subscribe_rejects_an_event_outside_the_ss_2_2_vocabulary() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();

        let res = ctx
            .subscribe_with_options(
                format!("/{}/app/bad-vocab/*", pid),
                SubscribeOptions::default().with_events(vec!["put".into()]),
                |_ev| {},
            )
            .await;

        match res {
            Err(SdkError::BadRequest { code, .. }) => {
                assert_eq!(code.as_deref(), Some("invalid_event_type"));
            }
            Err(other) => panic!("expected invalid_event_type, got {:?}", other),
            Ok(_) => panic!(
                "an unknown event name must be refused — the engine would accept \
                 it and the subscription would never fire (SA-2)"
            ),
        }

        // Control: the §2.2 vocabulary still subscribes.
        let _handle = ctx
            .subscribe_with_options(
                format!("/{}/app/good-vocab/*", pid),
                SubscribeOptions::default().with_events(vec!["created".into(), "deleted".into()]),
                |_ev| {},
            )
            .await
            .expect("the §2.2 vocabulary must still be accepted");
    }

    /// `SubscribeOptions::with_events` narrows the event filter.
    /// Subscribing with `events: ["created"]` only and then writing
    /// + updating + deleting an entity should deliver one event
    /// (the create), not three. Proves: events vector threads from
    /// SubscribeOptions through subscribe_internal into the wire
    /// params; the engine honors it at delivery time.
    #[tokio::test]
    async fn subscribe_with_events_filter_narrows_delivery() {
        use std::sync::{Arc, Mutex};

        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let prefix = format!("/{}/app/events-filter/", pid);

        let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let events_for_cb = events.clone();
        let _h = ctx
            .subscribe_with_options(
                format!("{}*", prefix),
                SubscribeOptions::default().with_events(vec!["created".into()]),
                move |ev| {
                    events_for_cb.lock().unwrap().push(ev.event);
                },
            )
            .await
            .expect("subscribe should succeed");

        // Write (created) → update (updated) → delete (deleted).
        let path = format!("{}entity", prefix);
        let data = entity_ecf::to_ecf(&ciborium::Value::Map(vec![(
            entity_ecf::text("v"),
            entity_ecf::integer(1),
        )]));
        let e1 = Entity::new("primitive/any", data.clone()).unwrap();
        ctx.store().put(&path, e1).unwrap();
        let data2 = entity_ecf::to_ecf(&ciborium::Value::Map(vec![(
            entity_ecf::text("v"),
            entity_ecf::integer(2),
        )]));
        let e2 = Entity::new("primitive/any", data2).unwrap();
        ctx.store().put(&path, e2).unwrap();
        let _ = ctx.store().remove(&path);

        // Let the engine flush deliveries.
        for _ in 0..50 {
            if !events.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let delivered = events.lock().unwrap().clone();
        assert_eq!(
            delivered,
            vec!["created".to_string()],
            "events filter [\"created\"] should only deliver the create event"
        );
    }

    /// `SubscribeOptions::with_limits(SubscribeLimits { max_events:
    /// Some(2), .. })` should auto-cancel after 2 deliveries. Proves
    /// the limits map threads through and the engine's max_events cap
    /// fires.
    #[tokio::test]
    async fn subscribe_with_max_events_limit_caps_delivery() {
        use std::sync::{Arc, Mutex};

        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let prefix = format!("/{}/app/limits-cap/", pid);

        let count: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
        let count_for_cb = count.clone();
        let _h = ctx
            .subscribe_with_options(
                format!("{}*", prefix),
                SubscribeOptions::default().with_limits(SubscribeLimits {
                    max_events: Some(2),
                    max_duration_ms: None,
                    rate_limit: None,
                }),
                move |_| {
                    *count_for_cb.lock().unwrap() += 1;
                },
            )
            .await
            .expect("subscribe should succeed");

        // Issue 5 puts with a small sleep between each so the engine
        // has a chance to update delivered_count between events.
        // Without this serialization, all 5 events queue before any
        // single delivery completes, so the count is 0 at every
        // check_limits call.
        for i in 0..5 {
            let path = format!("{}entity-{}", prefix, i);
            let data = entity_ecf::to_ecf(&ciborium::Value::Map(vec![(
                entity_ecf::text("i"),
                entity_ecf::integer(i),
            )]));
            let e = Entity::new("primitive/any", data).unwrap();
            ctx.store().put(&path, e).unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        let delivered = *count.lock().unwrap();
        assert_eq!(
            delivered, 2,
            "max_events=2 should cap delivery; got {} events",
            delivered
        );
    }

    /// Scope handle re-exposes `list()` consistent with the flat
    /// PeerContext method.
    #[tokio::test]
    async fn subscription_scope_list_matches_flat() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();

        let _h = ctx
            .subscribe(format!("/{}/scope/*", pid), |_| {})
            .await
            .unwrap();

        let flat = ctx.list_subscriptions();
        let via_scope = ctx.subscription().list();
        assert_eq!(flat.len(), via_scope.len(), "scope.list matches flat list");
        assert_eq!(flat.len(), 1);
    }

    /// Scope handle `unsubscribe()` routes to the same dispatch as
    /// the flat method.
    #[tokio::test]
    async fn subscription_scope_unsubscribe_removes_from_listing() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();

        let handle = ctx
            .subscribe(format!("/{}/scope-rm/*", pid), |_| {})
            .await
            .unwrap();
        let id = handle.subscription_id().to_string();
        assert_eq!(ctx.subscription().list().len(), 1);

        ctx.subscription()
            .unsubscribe(&id)
            .await
            .expect("scope.unsubscribe should succeed");
        drop(handle);

        assert!(ctx.subscription().list().is_empty());
    }
}
