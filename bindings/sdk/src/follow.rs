//! `PeerContext::follow` — a packaged remote-subtree mirror.
//!
//! Following a remote peer's subtree means: whenever an entity under
//! `prefix` changes on `remote_peer_id`, that change is materialized into
//! the local store (create/update writes it; delete removes it) so a local
//! union read reflects the remote's state. This is the composition that
//! consumers otherwise hand-roll as *poll + subscribe + fetch + cache*
//! loops — the mirror recipe, packaged once.
//!
//! ## Two strategies, one surface — [`FollowMode`]
//!
//! Both are **revision-free** — following does NOT require the subtree to be
//! a revisioned/versioned system. The axis is *where* the materialization
//! runs, not the data model:
//!
//! - **[`FollowMode::Payload`]** (client-side): subscribe with
//!   `include_payload`, so the changed entity rides the notification, and the
//!   following peer writes it to the local store — **no fetch round-trip**.
//!   The mirror write runs on the following peer, so it needs a live
//!   `PeerContext`.
//! - **[`FollowMode::Continuation`]** (server-side): the subscribe/notify
//!   chain — subscribe on the remote prefix as the trigger and bind a
//!   standing continuation that materializes each change into the local tree
//!   (`tree:extract → tree:merge`, full-closure, prefix-static). Materialized
//!   on the substrate, so it survives restart and does not depend on a client
//!   callback. This is the shape of workbench-go's follow chain
//!   (`shellcmd/cmd_revision_follow.go`) with the **revision-free** tree ops
//!   substituted for `revision:fetch-diff` — the `revision:*` form there was
//!   an optimization for *revisioned* trees, never a requirement of
//!   following. Implemented behind the (default-on) `continuation` feature;
//!   without it [`PeerContext::follow`] returns a loud error rather than
//!   silently doing nothing. Bootstrap and the push-triggered standing leg are
//!   both proven cross-peer in `follow.rs`'s tests.
//!
//! (Neither mode forces revision. A `revision:fetch-diff` action is a
//! possible future optimization *within* continuation mode for subtrees that
//! happen to be revisioned — an option, never the defining mode.)
//!
//! Both strategies resolve to one [`FollowHandle`] whose `Drop` tears the
//! follow down (unsubscribe; for continuation mode, also `abandon` the
//! installed continuations), mirroring workbench-go's `unfollow`.
//!
//! ## Catch-up is the caller's job
//!
//! A subscription is event-driven only — pre-existing state does not flow
//! to a new subscriber (workbench-go's late-join finding). `follow`
//! installs the **live** path; the caller performs a bounded **catch-up**
//! pull on bind / reconnect (e.g. a one-shot listing, or a `tree:extract →
//! tree:merge` bootstrap). Keeping the two explicit is deliberate: the live
//! path never carries history, so folding catch-up into `follow` would hide
//! a correctness boundary.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use entity_capability::ResourceTarget;
use entity_entity::Entity;
use entity_handler::ExecuteOptions;
use entity_hash::Hash;
use entity_peer::PeerShared;

use crate::sdk::{build_put_params, build_remove_params, PeerContext, SdkError};
use crate::subscription::{
    L1SubscriptionEvent, L1SubscriptionHandle, RawSubscriptionHandle, SubscribeOptions,
};

/// How a [`follow`](PeerContext::follow) materializes the remote subtree.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum FollowMode {
    /// Client-side mirror: subscribe with `include_payload` and write each
    /// delivered entity into the local store at its qualified path
    /// (create/update) or remove it (delete). No fetch round-trip. The mirror
    /// write runs on the peer that installed the follow, so it needs a live
    /// `PeerContext`. Revision-free — fits per-author message logs (chat).
    #[default]
    Payload,
    /// Server-side mirror: the subscribe/notify chain. Subscribe on the
    /// remote prefix as the trigger and bind a standing continuation that
    /// materializes each change into the local tree (`tree:extract →
    /// tree:merge`). Materialized on the substrate, so it survives restart and
    /// needs no client callback. **Revision-free** — the subtree does NOT
    /// have to be a revisioned system (this is the revision-free counterpart
    /// of workbench-go's follow chain, tree ops in place of `revision:*`).
    ///
    /// Implemented behind the (default-on) `continuation` feature. Without
    /// that feature [`PeerContext::follow`] returns `Err(SdkError)` for this
    /// mode — an explicit, loud failure, never a silent no-op — so a build
    /// that omits the backend still fails loudly rather than doing nothing.
    Continuation,
}

/// Options for [`PeerContext::follow`].
#[derive(Debug, Clone, Default)]
pub struct FollowOptions {
    /// Materialization strategy. See [`FollowMode`].
    pub mode: FollowMode,
}

impl FollowOptions {
    /// Client-side payload mirror (the implemented strategy).
    pub fn payload() -> Self {
        Self {
            mode: FollowMode::Payload,
        }
    }

    /// Server-side continuation mirror — the revision-free subscribe/notify
    /// chain (not yet implemented).
    pub fn continuation() -> Self {
        Self {
            mode: FollowMode::Continuation,
        }
    }
}

/// Handle for an active follow. **Drop to tear it down.** For
/// [`FollowMode::Payload`] the wrapped [`L1SubscriptionHandle`]'s own `Drop`
/// unsubscribes; for [`FollowMode::Continuation`] dropping unsubscribes the
/// trigger AND `abandon`s the installed continuations (mirroring workbench-go's
/// `unfollow`).
#[must_use = "dropping this handle tears the follow down (unsubscribe/abandon)"]
pub struct FollowHandle {
    inner: FollowInner,
}

enum FollowInner {
    /// Client-side payload mirror: the live subscription (drop unsubscribes).
    Payload { _sub: L1SubscriptionHandle },
    /// Server-side continuation mirror: the trigger subscription plus the
    /// installed continuation paths to `abandon` on drop.
    Continuation {
        _sub: RawSubscriptionHandle,
        shared: Arc<PeerShared>,
        local_identity: Hash,
        continuation_paths: Vec<String>,
    },
}

impl std::fmt::Debug for FollowHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.inner {
            FollowInner::Payload { .. } => f.write_str("FollowHandle(Payload)"),
            FollowInner::Continuation {
                continuation_paths, ..
            } => f
                .debug_struct("FollowHandle(Continuation)")
                .field("continuations", continuation_paths)
                .finish(),
        }
    }
}

impl Drop for FollowHandle {
    fn drop(&mut self) {
        // Payload: the L1SubscriptionHandle's own Drop unsubscribes — nothing
        // more to do. Continuation: the RawSubscriptionHandle's Drop cancels
        // the trigger; here we additionally abandon each installed
        // continuation so the chain leaves no orphaned standing rules.
        if let FollowInner::Continuation {
            shared,
            local_identity,
            continuation_paths,
            ..
        } = &self.inner
        {
            for path in continuation_paths {
                let shared = shared.clone();
                let local_identity = *local_identity;
                let path = path.clone();
                let task = async move {
                    let opts = target_opts(&path);
                    let execute_fn = entity_peer::connection::make_execute_fn(
                        shared,
                        Some(local_identity),
                        HashMap::new(),
                        None,
                        None,
                    );
                    let _ = execute_fn(
                        "system/continuation".into(),
                        "abandon".into(),
                        empty_params(),
                        opts,
                    )
                    .await;
                };
                spawn(task);
            }
        }
    }
}

impl PeerContext {
    /// Mirror `remote_peer_id`'s subtree under `prefix` into the local
    /// store. Returns a [`FollowHandle`]; drop it to stop following.
    ///
    /// See the [module docs](self) for the [`FollowMode`] strategies and the
    /// live-vs-catch-up split. `prefix` is interpreted against the remote
    /// peer's tree (e.g. `/{remote}/app/chat/{conv}/messages/`); a trailing
    /// `/` is added if absent.
    ///
    /// **Pre-condition:** the local peer has an open connection to
    /// `remote_peer_id` (call `connect_to` first). For payload mode the caller
    /// must be authorized to `tree:get` the remote resource; for continuation
    /// mode, to `tree:extract` it (the cross-peer chain cap is minted from the
    /// connection grant).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn follow(
        &self,
        remote_peer_id: impl Into<String>,
        prefix: impl Into<String>,
        options: FollowOptions,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<FollowHandle, SdkError>> + Send + 'static>,
    > {
        let remote = remote_peer_id.into();
        let prefix = ensure_trailing_slash(prefix.into());
        match options.mode {
            FollowMode::Payload => Box::pin(self.follow_payload(remote, prefix)),
            #[cfg(feature = "continuation")]
            FollowMode::Continuation => Box::pin(self.follow_continuation(remote, prefix)),
            #[cfg(not(feature = "continuation"))]
            FollowMode::Continuation => Box::pin(async {
                Err(SdkError::HandlerError(
                    "FollowMode::Continuation requires the `continuation` feature".into(),
                ))
            }),
        }
    }

    /// WASM variant of [`PeerContext::follow`].
    #[cfg(target_arch = "wasm32")]
    pub fn follow(
        &self,
        remote_peer_id: impl Into<String>,
        prefix: impl Into<String>,
        options: FollowOptions,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<FollowHandle, SdkError>> + 'static>>
    {
        let remote = remote_peer_id.into();
        let prefix = ensure_trailing_slash(prefix.into());
        match options.mode {
            FollowMode::Payload => Box::pin(self.follow_payload(remote, prefix)),
            #[cfg(feature = "continuation")]
            FollowMode::Continuation => Box::pin(self.follow_continuation(remote, prefix)),
            #[cfg(not(feature = "continuation"))]
            FollowMode::Continuation => Box::pin(async {
                Err(SdkError::HandlerError(
                    "FollowMode::Continuation requires the `continuation` feature".into(),
                ))
            }),
        }
    }

    /// Client-side payload mirror: subscribe-with-payload → local write.
    #[cfg(not(target_arch = "wasm32"))]
    fn follow_payload(
        &self,
        remote: String,
        prefix: String,
    ) -> impl std::future::Future<Output = Result<FollowHandle, SdkError>> + Send + 'static {
        let writer = self.mirror_writer(remote.clone());
        let sub_fut = self.subscribe_at_with_options(
            remote,
            subtree_wildcard(&prefix),
            SubscribeOptions::with_payload(),
            move |ev| writer.apply(ev),
        );
        async move {
            Ok(FollowHandle {
                inner: FollowInner::Payload {
                    _sub: sub_fut.await?,
                },
            })
        }
    }

    /// WASM variant of `follow_payload`.
    #[cfg(target_arch = "wasm32")]
    fn follow_payload(
        &self,
        remote: String,
        prefix: String,
    ) -> impl std::future::Future<Output = Result<FollowHandle, SdkError>> + 'static {
        let writer = self.mirror_writer(remote.clone());
        let sub_fut = self.subscribe_at_with_options(
            remote,
            subtree_wildcard(&prefix),
            SubscribeOptions::with_payload(),
            move |ev| writer.apply(ev),
        );
        async move {
            Ok(FollowHandle {
                inner: FollowInner::Payload {
                    _sub: sub_fut.await?,
                },
            })
        }
    }

    /// Construct the mirror writer capturing exactly the shared state the
    /// delivery callback needs (all `Send + Sync + 'static`), so the
    /// callback never borrows `&self`.
    fn mirror_writer(&self, remote: String) -> MirrorWriter {
        let shared = self.peer_shared();
        let local_identity = shared.identity_hash;
        MirrorWriter {
            shared,
            generation: self.generation.clone(),
            local_identity,
            remote,
        }
    }
}

#[cfg(feature = "continuation")]
impl PeerContext {
    /// Server-side continuation follow — the revision-free subscribe/notify
    /// chain. Mints a cross-peer `tree:extract` cap, installs a
    /// `tree:extract → tree:merge` continuation pair, binds a raw subscription
    /// on the remote prefix as the trigger, and seeds initial state with one
    /// synchronous extract→merge bootstrap. The returned future is `Send` on
    /// native via auto-trait leakage (all captures are `Send`); [`follow`]
    /// boxes it.
    ///
    /// Nothing here assumes a revisioned subtree — the materialization is the
    /// revision-free `system/tree` extract/merge pair. See
    /// [`FollowMode::Continuation`].
    fn follow_continuation(
        &self,
        remote: String,
        prefix: String,
    ) -> impl std::future::Future<Output = Result<FollowHandle, SdkError>> + 'static {
        use crate::continuation::{ContinuationSpec, DeliverySpec};

        // --- synchronous setup (borrows &self) ---
        let shared = self.peer_shared();
        let local_identity = shared.identity_hash;
        let owner_cap = self.owner_self_cap.clone();
        let owner_cap_hash = self.owner_capability_hash();
        let local_pid = self.peer_id().to_string();

        let slug = slugify(&prefix);
        let base = format!("system/inbox/follow/{slug}");
        let extract_path = format!("/{local_pid}/{base}/extract");
        let merge_path = format!("/{local_pid}/{base}/merge");
        let extract_uri = format!("entity://{local_pid}/{base}/extract");
        let merge_uri = format!("entity://{local_pid}/{base}/merge");

        // Mint the cross-peer chain cap for tree:extract on the remote's
        // subtree, then build the two continuation entities. The extract's
        // envelope result threads into the merge's `source_envelope`.
        let built = self
            .mint_cross_peer_chain_capability(
                &remote,
                vec![entity_capability::GrantEntry {
                    handlers: entity_capability::PathScope::new(vec!["system/tree".into()]),
                    resources: entity_capability::PathScope::new(vec![format!("/{remote}/*")]),
                    operations: entity_capability::IdScope::new(vec!["extract".into()]),
                    peers: None,
                    constraints: None,
                    allowances: None,
                }],
                None,
            )
            .and_then(|cap_ent| {
                let cross_cap = cap_ent.content_hash;
                let merge_body = ContinuationSpec::new("system/tree", "merge")
                    .resource(ResourceTarget {
                        targets: vec![prefix.clone()],
                        exclude: vec![],
                    })
                    .params(merge_params_cbor(&prefix))
                    .result_field("source_envelope")
                    .dispatch_capability(owner_cap_hash)
                    .to_entity()?;
                let extract_body =
                    ContinuationSpec::new(format!("entity://{remote}/system/tree"), "extract")
                        .resource(ResourceTarget {
                            targets: vec![prefix.clone()],
                            exclude: vec![],
                        })
                        .deliver_to(DeliverySpec::receive(merge_uri.clone()))
                        .dispatch_capability(cross_cap)
                        .to_entity()?;
                Ok((merge_body, extract_body))
            });

        // Build the owning dispatch futures synchronously (only when the specs
        // built) so the async block holds no &self borrow.
        let plan = built.map(|(merge_body, extract_body)| {
            let install_merge = self.continuation().install(merge_path.clone(), merge_body);
            let install_extract = self.continuation().install(extract_path.clone(), extract_body);
            let subscribe = self.subscribe_raw_at(
                remote.clone(),
                subtree_wildcard(&prefix),
                extract_uri.clone(),
                vec![],
            );
            let bootstrap_extract = self.execute(
                format!("entity://{remote}/system/tree"),
                "extract",
                empty_params(),
                target_opts(&prefix),
            );
            (install_merge, install_extract, subscribe, bootstrap_extract)
        });

        async move {
            let (install_merge, install_extract, subscribe, bootstrap_extract) = plan?;
            // Install merge first (its inbox must exist before extract delivers
            // to it), then the cross-peer extract, then the trigger subscribe.
            install_merge.await?;
            install_extract.await?;
            let raw_sub = subscribe.await?;

            // Bootstrap: seed initial state with one synchronous extract(remote)
            // → merge(local). The standing chain covers subsequent changes.
            // Best-effort — a bootstrap miss is recovered by the next trigger.
            match bootstrap_extract.await {
                Ok(hr) if hr.status == 200 => {
                    let merge_params = bootstrap_merge_params(&hr.result, &prefix);
                    let execute_fn = entity_peer::connection::make_execute_fn(
                        shared.clone(),
                        Some(local_identity),
                        HashMap::new(),
                        None,
                        Some(owner_cap),
                    );
                    if let Err(e) = execute_fn(
                        "system/tree".into(),
                        "merge".into(),
                        merge_params,
                        target_opts(&prefix),
                    )
                    .await
                    {
                        tracing::warn!(error = %e, "follow continuation: bootstrap merge failed");
                    }
                }
                Ok(hr) => {
                    tracing::warn!(status = hr.status, "follow continuation: bootstrap extract non-200")
                }
                Err(e) => tracing::warn!(error = %e, "follow continuation: bootstrap extract failed"),
            }

            Ok(FollowHandle {
                inner: FollowInner::Continuation {
                    _sub: raw_sub,
                    shared,
                    local_identity,
                    continuation_paths: vec![extract_path, merge_path],
                },
            })
        }
    }
}

/// Ensure a prefix ends with `/` (`/p/app/x` → `/p/app/x/`). Normalizes the
/// follow prefix once, up front.
fn ensure_trailing_slash(mut prefix: String) -> String {
    if !prefix.ends_with('/') {
        prefix.push('/');
    }
    prefix
}

/// Append the subtree wildcard to a (trailing-slash) prefix for a subscribe
/// pattern (`/p/app/x/` → `/p/app/x/*`).
fn subtree_wildcard(prefix: &str) -> String {
    format!("{prefix}*")
}

/// Render a prefix as a single flat, path-safe inbox segment: strip
/// surrounding slashes and replace internal `/` with `-`
/// (`/p/app/chat/c/messages/` → `p-app-chat-c-messages`).
#[cfg(feature = "continuation")]
fn slugify(prefix: &str) -> String {
    prefix.trim_matches('/').replace('/', "-")
}

/// Static `tree:merge` params for a continuation step — `source_envelope` is
/// omitted (it is threaded in from the extract step via `result_field`).
#[cfg(feature = "continuation")]
fn merge_params_cbor(prefix: &str) -> Vec<u8> {
    entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (entity_ecf::text("source_prefix"), entity_ecf::text(prefix)),
        (entity_ecf::text("strategy"), entity_ecf::text("source-wins")),
        (entity_ecf::text("target_prefix"), entity_ecf::text(prefix)),
    ]))
}

/// `tree:merge` params for the one-shot bootstrap — the extract `envelope`
/// inlined as `source_envelope` (`{type, data}`), same shape as
/// `reconcile.rs::build_tree_merge_params`.
#[cfg(feature = "continuation")]
fn bootstrap_merge_params(envelope: &Entity, prefix: &str) -> Entity {
    let env_value: ciborium::Value =
        ciborium::de::from_reader(envelope.data.as_slice()).unwrap_or(ciborium::Value::Null);
    let source_envelope = entity_ecf::Value::Map(vec![
        (entity_ecf::text("data"), env_value),
        (
            entity_ecf::text("type"),
            entity_ecf::text(&envelope.entity_type),
        ),
    ]);
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (entity_ecf::text("source_envelope"), source_envelope),
        (entity_ecf::text("source_prefix"), entity_ecf::text(prefix)),
        (entity_ecf::text("strategy"), entity_ecf::text("source-wins")),
        (entity_ecf::text("target_prefix"), entity_ecf::text(prefix)),
    ]));
    Entity::new("system/tree/merge-params", data)
        .expect("tree merge-params entity construction is infallible")
}

/// Applies delivered subscription events to the local store as mirror
/// writes. Cheaply cloneable (Arcs + a couple owned scalars) so the
/// delivery callback can hold it without borrowing the `PeerContext`.
#[derive(Clone)]
struct MirrorWriter {
    shared: Arc<PeerShared>,
    generation: Arc<AtomicU64>,
    local_identity: Hash,
    /// Remote peer whose subtree we mirror — used for the payload-miss
    /// fetch fallback.
    remote: String,
}

impl MirrorWriter {
    /// Entry point from the subscribe callback: spawn the mirror write off
    /// the delivery worker (the callback itself must not block).
    fn apply(&self, ev: L1SubscriptionEvent) {
        let this = self.clone();
        spawn(async move {
            this.apply_async(ev).await;
        });
    }

    async fn apply_async(&self, ev: L1SubscriptionEvent) {
        let path = ev.path;

        // Delete: mirror the removal (a `tree:put` with null-entity remove
        // params — the same op the SDK's `StoreAccess::remove` uses).
        if ev.event == "deleted" {
            match build_remove_params() {
                Ok(params) => self.local_tree_put(&path, params).await,
                Err(e) => tracing::warn!(path = %path, error = %e, "follow mirror: build remove params"),
            }
            return;
        }

        // Create/update: materialize the changed entity. Prefer the in-band
        // payload (include_payload); fall back to a cross-peer fetch on a
        // source-side resolution miss so a rare miss doesn't drop the write.
        let entity = match ev.included {
            Some(entity) => Some(entity),
            None => self.fetch_remote(&path).await,
        };
        let Some(entity) = entity else {
            tracing::debug!(
                path = %path,
                "follow mirror: no entity to write (payload miss + fetch miss); \
                 catch-up will recover it"
            );
            return;
        };
        match build_put_params(&entity) {
            Ok(params) => self.local_tree_put(&path, params).await,
            Err(e) => tracing::warn!(path = %path, error = %e, "follow mirror: build put params"),
        }
    }

    /// Write `params` (put or remove) at `path` in the LOCAL store via
    /// `system/tree:put`. Self-authorized (no caller cap), matching
    /// `PeerContext::put`; a local `tree:put` fires the store's change
    /// event so local subscribers (the union read) reflect it. Bumps the
    /// generation counter on success, as `PeerContext::put` does.
    async fn local_tree_put(&self, path: &str, params: Entity) {
        let execute_fn = self.execute_fn();
        let opts = target_opts(path);
        match execute_fn("system/tree".into(), "put".into(), params, opts).await {
            Ok(r) if (200..300).contains(&r.status) => {
                self.generation.fetch_add(1, Ordering::Relaxed);
            }
            Ok(r) => tracing::warn!(path = %path, status = r.status, "follow mirror: local put non-2xx"),
            Err(e) => tracing::warn!(path = %path, error = %e, "follow mirror: local put dispatch"),
        }
    }

    /// Fetch the entity at `path` from the remote peer (payload-miss
    /// fallback). Presents no local-rooted cap — the connection grant
    /// authorizes the cross-peer read, exactly as an app-tier
    /// `execute(entity://{remote}/system/tree, get)` does.
    async fn fetch_remote(&self, path: &str) -> Option<Entity> {
        let execute_fn = self.execute_fn();
        let target = format!("entity://{}/system/tree", self.remote);
        let opts = target_opts(path);
        match execute_fn(target, "get".into(), empty_params(), opts).await {
            Ok(r) if r.status == 200 => Some(r.result),
            _ => None,
        }
    }

    /// Build a dispatch fn from the captured shared state. Caller cap is
    /// `None`: local `tree:put` self-authorizes and cross-peer `tree:get`
    /// uses the receiver-rooted connection grant (a local-rooted cap would
    /// be rejected cross-peer).
    fn execute_fn(&self) -> entity_handler::ExecuteFn {
        entity_peer::connection::make_execute_fn(
            self.shared.clone(),
            Some(self.local_identity),
            HashMap::new(),
            None,
            None,
        )
    }
}

/// `ExecuteOptions` targeting a single path via the resource.
fn target_opts(path: &str) -> ExecuteOptions {
    ExecuteOptions {
        resource: Some(ResourceTarget {
            targets: vec![path.to_string()],
            exclude: vec![],
        }),
        ..Default::default()
    }
}

/// Empty params entity for a `system/tree:get` (the path travels in the
/// resource target).
fn empty_params() -> Entity {
    Entity::new("system/empty", entity_ecf::to_ecf(&entity_ecf::Value::Null))
        .expect("empty params entity construction is infallible")
}

#[cfg(not(target_arch = "wasm32"))]
fn spawn<F: std::future::Future<Output = ()> + Send + 'static>(f: F) {
    tokio::spawn(f);
}

#[cfg(target_arch = "wasm32")]
fn spawn<F: std::future::Future<Output = ()> + 'static>(f: F) {
    wasm_bindgen_futures::spawn_local(f);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk::PeerContextBuilder;

    fn make_entity(entity_type: &str, content: &str) -> Entity {
        let data = entity_ecf::to_ecf(&entity_ecf::text(content));
        Entity::new(entity_type, data).unwrap()
    }

    #[test]
    fn prefix_normalization_helpers() {
        assert_eq!(ensure_trailing_slash("/p/app/x".into()), "/p/app/x/");
        assert_eq!(ensure_trailing_slash("/p/app/x/".into()), "/p/app/x/");
        assert_eq!(subtree_wildcard("/p/app/x/"), "/p/app/x/*");
    }

    #[cfg(feature = "continuation")]
    #[test]
    fn slugify_flattens_prefix() {
        assert_eq!(slugify("/p/app/chat/c/messages/"), "p-app-chat-c-messages");
    }

    /// A `FollowMode::Continuation` follow with no connection to the remote
    /// fails at the cross-peer cap mint (which needs the connection grant as
    /// the chain root) — a clear error, not a silent no-op.
    #[cfg(feature = "continuation")]
    #[tokio::test(flavor = "current_thread")]
    async fn follow_continuation_unconnected_remote_errs() {
        let ctx = PeerContextBuilder::new()
            .generate_keypair()
            .build()
            .expect("build");
        let pid = ctx.peer_id().to_string();
        let r = ctx
            .follow(
                "2KsomeUnconnectedRemotePeerXXXXXXXXXXXXXXXXXX".to_string(),
                format!("/{pid}/app/x/"),
                FollowOptions::continuation(),
            )
            .await;
        assert!(
            r.is_err(),
            "continuation follow must fail without a connection to the remote"
        );
    }

    /// End-to-end continuation follow: A follows B's subtree in
    /// `FollowMode::Continuation`; the mint + install (both continuations) +
    /// raw subscribe succeed, and the one-shot bootstrap (cross-peer
    /// `tree:extract` → local `tree:merge`, awaited inside `follow`) mirrors
    /// B's existing entities into A's store — proving the revision-free
    /// server-side chain assembles and materializes with no revisioned
    /// subtree. (The *standing* auto-update leg — push-triggered, dispatched
    /// under the minted chain cap — is proven in-process by
    /// `follow_continuation_standing_leg_fires_cross_peer`.)
    #[cfg(feature = "continuation")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn follow_continuation_installs_and_bootstraps_cross_peer() {
        use entity_peer::transport::{MemoryConnector, MemoryListener, MemoryTransportRegistry};
        use entity_peer::PeerConfig;
        use std::sync::Arc;

        let reg = MemoryTransportRegistry::new();
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
        let server_task = tokio::spawn(async move {
            let _ = entity_peer::server::run(listener, b_shared).await;
        });

        ctx_a
            .connect_to(&format!("memory://{b_pid}"))
            .await
            .expect("connect_to B");

        // B has existing entities under the followed prefix — the bootstrap
        // must pull these in (subscriptions never carry history).
        let prefix = format!("/{}/app/test/cfollow/", b_pid);
        ctx_b
            .store()
            .put(&format!("{prefix}m1"), make_entity("t", "from-b-1"))
            .unwrap();
        ctx_b
            .store()
            .put(&format!("{prefix}m2"), make_entity("t", "from-b-2"))
            .unwrap();

        let handle = ctx_a
            .follow(b_pid.clone(), prefix.clone(), FollowOptions::continuation())
            .await
            .expect("continuation follow installs + bootstraps");

        // Bootstrap runs inside follow(), so B's entities are mirrored by now.
        assert_eq!(
            ctx_a.store().get(&format!("{prefix}m1")).as_ref(),
            Some(&make_entity("t", "from-b-1")),
            "bootstrap mirrors m1 into A"
        );
        assert_eq!(
            ctx_a.store().get(&format!("{prefix}m2")).as_ref(),
            Some(&make_entity("t", "from-b-2")),
            "bootstrap mirrors m2 into A"
        );

        // Teardown: drop unsubscribes the trigger + abandons both continuations.
        drop(handle);
        server_task.abort();
    }

    /// The mirror-write logic (E2's core): a payload-carrying create event
    /// lands the in-band entity in the LOCAL store at its qualified path,
    /// and a delete event removes it. Exercises the write path directly
    /// (awaiting `apply_async`, no delivery timing) and — crucially — at a
    /// **foreign-namespace** path (`/{remote}/…`), the exact shape a real
    /// follow mirrors, proving the local `tree:put` authorizes a write
    /// under another peer's namespace into our own store (same op the app's
    /// `dispatch_write` uses for chat delivery).
    #[tokio::test(flavor = "current_thread")]
    async fn mirror_writer_applies_create_and_delete_cross_namespace() {
        let ctx = PeerContextBuilder::new()
            .generate_keypair()
            .build()
            .expect("build");
        // A real (valid) foreign peer-id — the mirror target lives under
        // its namespace but in OUR store. Generate a throwaway peer just
        // for its well-formed peer-id.
        let remote = PeerContextBuilder::new()
            .generate_keypair()
            .build()
            .expect("remote build")
            .peer_id()
            .to_string();
        let writer = ctx.mirror_writer(remote.clone());

        let path = format!("/{remote}/app/test/follow/msg1");
        let entity = make_entity("t", "mirrored-body");

        writer
            .apply_async(L1SubscriptionEvent {
                subscription_id: "sub".into(),
                event: "created".into(),
                path: path.clone(),
                new_hash: Some(entity.content_hash),
                previous_hash: None,
                included: Some(entity.clone()),
            })
            .await;
        assert_eq!(
            ctx.store().get(&path).as_ref(),
            Some(&entity),
            "create mirrors the in-band entity into the local store at {path}"
        );

        writer
            .apply_async(L1SubscriptionEvent {
                subscription_id: "sub".into(),
                event: "deleted".into(),
                path: path.clone(),
                new_hash: None,
                previous_hash: Some(entity.content_hash),
                included: None,
            })
            .await;
        assert!(
            ctx.store().get(&path).is_none(),
            "delete mirrors as a removal at {path}"
        );
    }

    /// A cross-peer payload follow **installs** end-to-end: A connects to B
    /// and `follow(..., Payload)` succeeds, which means B's engine accepted
    /// the cross-peer subscribe-with-payload — i.e. the `include_payload`
    /// authorization passed against the connection grant (validating that
    /// cross-peer payload needs no extra grant beyond what authorizes a
    /// cross-peer `tree:get`). This asserts only the **install**; the live
    /// **delivery** round-trip (B writes → A's callback → mirror) is proven
    /// separately and in-process by `follow_payload_delivers_reactively_cross_peer`
    /// — the memory harness *does* push, given a symmetric (rendezvous)
    /// establishment and B's engines started.
    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn follow_payload_installs_cross_peer() {
        use entity_peer::transport::{MemoryConnector, MemoryListener, MemoryTransportRegistry};
        use entity_peer::PeerConfig;
        use std::sync::Arc;

        let reg = MemoryTransportRegistry::new();
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
        let server_task = tokio::spawn(async move {
            let _ = entity_peer::server::run(listener, b_shared).await;
        });

        ctx_a
            .connect_to(&format!("memory://{b_pid}"))
            .await
            .expect("connect_to B");

        let prefix = format!("/{}/app/test/follow/", b_pid);
        let follow = ctx_a
            .follow(b_pid.clone(), prefix, FollowOptions::payload())
            .await;
        assert!(
            follow.is_ok(),
            "cross-peer payload follow should install (subscribe-with-payload \
             authorized under the connection grant): {:?}",
            follow.err()
        );

        server_task.abort();
    }

    /// A rendezvous-establishment stand-in for the memory transport: connects
    /// to `target` via `MemoryConnector` and — crucially — reports
    /// `established_via_rendezvous_key: true`, the §6.5(b) discriminator that
    /// makes the dialer mint the reciprocal reentry grant (the same fact the
    /// real WebRTC/punch establishers report). A plain dial-by-address is
    /// asymmetric and mints nothing, so the acceptor could never originate the
    /// notification back — which is exactly why a `connect_to("memory://B")`
    /// setup cannot prove reactive delivery. This is the SDK-crate analog of
    /// core/peer's `StubEstablisher::rendezvous`.
    #[cfg(not(target_arch = "wasm32"))]
    struct RendezvousStub {
        registry: std::sync::Arc<entity_peer::transport::MemoryTransportRegistry>,
        target: String,
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[async_trait::async_trait]
    impl entity_peer::live_establish::LiveEstablish for RendezvousStub {
        async fn establish_live(
            &self,
            ctx: entity_peer::live_establish::EstablishCtx,
            _peer_id: &str,
        ) -> Result<
            entity_peer::live_establish::LivePath,
            entity_peer::live_establish::LiveEstablishError,
        > {
            use entity_peer::transport::Connector;
            if ctx.expired() {
                return Err(
                    entity_peer::live_establish::LiveEstablishError::NotAttempted {
                        substrate: "memory",
                        reason: "seam deadline passed".to_string(),
                    },
                );
            }
            entity_peer::transport::MemoryConnector::new(self.registry.clone())
                .connect(&format!("memory://{}", self.target))
                .await
                .map(|connection| entity_peer::live_establish::LivePath {
                    connection,
                    role: entity_peer::live_establish::HandshakeRole::Initiator,
                    established_via_rendezvous_key: true,
                })
                .map_err(
                    |e| entity_peer::live_establish::LiveEstablishError::NoPath {
                        substrate: "memory",
                        reason: e.to_string(),
                    },
                )
        }
    }

    /// Build a follower/followed pair over one memory registry, wired for
    /// **reactive cross-peer delivery**: A (follower) dials B (followed) through
    /// the rendezvous seam so A mints the §6.5(b) reciprocal reentry grant that
    /// lets B originate notifications back over A's accepted connection; B runs
    /// a listener with its **engines started** (so its subscription delivery
    /// worker + deliver fn exist). Returns `(ctx_a, ctx_b, b_pid, server_task)`
    /// with the A→B connection already pooled for a subsequent `follow`'s
    /// subscribe to reuse. The two load-bearing facts (B's engines; rendezvous
    /// not dial-by-address) are documented on the AUDIT-1 test below.
    #[cfg(not(target_arch = "wasm32"))]
    async fn rendezvous_pair(
        reg: std::sync::Arc<entity_peer::transport::MemoryTransportRegistry>,
    ) -> (
        PeerContext,
        PeerContext,
        String,
        tokio::task::JoinHandle<()>,
    ) {
        use entity_peer::transport::{MemoryConnector, MemoryListener};
        use entity_peer::PeerConfig;
        use std::sync::Arc;

        let open_cfg = || PeerConfig {
            debug_open_grants: true,
            ..PeerConfig::default()
        };

        let ctx_b = PeerContextBuilder::new()
            .generate_keypair()
            .config(open_cfg())
            .connector(Arc::new(MemoryConnector::new(reg.clone())))
            .build()
            .expect("ctx_b build");
        let b_pid = ctx_b.peer_id().to_string();

        let ctx_a = PeerContextBuilder::new()
            .generate_keypair()
            .config(open_cfg())
            .connector(Arc::new(MemoryConnector::new(reg.clone())))
            .with_live_establish(Arc::new(RendezvousStub {
                registry: reg.clone(),
                target: b_pid.clone(),
            }))
            .build()
            .expect("ctx_a build");

        let listener =
            MemoryListener::bind(b_pid.clone(), reg.clone()).expect("bind MemoryListener");
        let b_shared = ctx_b.peer_shared();
        // Start BOTH peers' engines: B is subscribed-on by A (needs its delivery
        // worker), and A is subscribed-on by B in the bidirectional test (needs
        // its own). Starting A's here is harmless for the one-directional tests.
        ctx_a.peer().start_engines(&ctx_a.peer_shared());
        ctx_b.peer().start_engines(&b_shared);
        let server_task = tokio::spawn(async move {
            let _ = entity_peer::server::run(listener, b_shared).await;
        });

        // Establish A→B through the seam WITH A's dispatch context, so A mints +
        // sends the reciprocal reentry grant and the connection pools for reuse.
        let a_shared = ctx_a.peer_shared();
        let a_pid = ctx_a.peer_id().to_string();
        entity_peer::remote::get_or_connect(
            &a_shared.remote,
            &b_pid,
            &a_shared.keypair,
            a_shared.content_store.as_ref(),
            a_shared.location_index.as_ref(),
            &a_pid,
            a_shared.connector.as_ref(),
            a_shared.config.home_hash_format,
            Some(a_shared.clone()),
        )
        .await
        .expect("rendezvous seam establishes A→B");

        (ctx_a, ctx_b, b_pid, server_task)
    }

    /// **AUDIT-1: `follow(Payload)` delivers reactively cross-peer — isolated,
    /// no poll, no e2e.** The delivery leg the sibling
    /// `follow_payload_installs_cross_peer` explicitly did NOT cover, and whose
    /// absence pushed the chat-delivery proof out to the WebRTC e2e (where the
    /// unconditional poll masked whether `follow` itself delivered).
    ///
    /// A follows B; then — **after** the follow is live — B writes a NEW entity
    /// under the followed prefix. Nothing here polls (this is the SDK; there is
    /// no chat poll). So a mirror appearing in A's store can *only* have arrived
    /// via the subscription notification B pushed to A — dispatched `receive`
    /// back over A's accepted inbound connection (the §6.11(b) reentry
    /// endpoint), authorized by the §6.5(b) reciprocal reentry grant A minted on
    /// the symmetric establishment. It reproduces the exact establishment mode
    /// the browser's WebRTC chat channel uses (rendezvous-key → reciprocal
    /// grant), so it proves `follow(Payload)`'s reactive contribution
    /// deterministically in-process.
    ///
    /// The load-bearing setup that a naive port misses (each cost a real
    /// debugging pass):
    ///   1. **B starts its engines.** The subscription sync hook (registered at
    ///      build) matches + queues a notification, but the async delivery
    ///      worker pool that drains that queue — and the deliver fn that
    ///      dispatches `receive` — are wired only by `start_engines`. The free
    ///      `entity_peer::server::run` does NOT call it (only `Peer::run` does).
    ///   2. **A establishes via a rendezvous seam, not `connect_to`.** Only a
    ///      symmetric (rendezvous-key) establishment mints the reciprocal grant;
    ///      a dial-by-address does not, and the acceptor's originate-back fails
    ///      `no originating authority` (§7a.2a). See `RendezvousStub`.
    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn follow_payload_delivers_reactively_cross_peer() {
        use entity_peer::transport::MemoryTransportRegistry;

        let reg = MemoryTransportRegistry::new();
        let (ctx_a, ctx_b, b_pid, server_task) = rendezvous_pair(reg).await;

        let prefix = format!("/{}/app/test/follow/", b_pid);
        // Hold the handle for the whole test — dropping it unsubscribes.
        let _handle = ctx_a
            .follow(b_pid.clone(), prefix.clone(), FollowOptions::payload())
            .await
            .expect("cross-peer payload follow installs");

        // Write on B AFTER the follow is live — the reactive trigger. (A
        // subscription never carries pre-existing state, so a pre-follow write
        // would prove nothing about the live push path.)
        let target = format!("{prefix}m-live");
        let body = make_entity("t", "reactive-from-b");
        ctx_b.store().put(&target, body.clone()).unwrap();

        // Await the mirror in A's store, polling A's LOCAL store only (no
        // cross-peer traffic initiated here). If it lands, it was pushed.
        let mut mirrored = None;
        for _ in 0..40 {
            if let Some(e) = ctx_a.store().get(&target) {
                mirrored = Some(e);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        assert_eq!(
            mirrored.as_ref(),
            Some(&body),
            "follow(Payload) must mirror B's post-follow write into A's store \
             via the reactive push (no poll ran): B's engine dispatched the \
             notification back over the reciprocal-grant reentry endpoint"
        );

        server_task.abort();
    }

    /// **AUDIT-2: `follow(Continuation)`'s STANDING leg fires cross-peer.** The
    /// sibling `follow_continuation_installs_and_bootstraps_cross_peer` proved
    /// only the one-shot **bootstrap** (a synchronous `tree:extract → tree:merge`
    /// dispatched under the connection grant). This proves the **standing**
    /// chain, which is a different path in two ways the bootstrap can't cover:
    ///
    ///   1. **Push-triggered.** B writes a NEW entity *after* follow; B's engine
    ///      pushes the change notification to A's extract-continuation inbox
    ///      (`subscribe_raw_at`'s `deliver_uri`) — the same reciprocal-grant
    ///      reentry path AUDIT-1 exercises, here driving a substrate continuation
    ///      instead of a client callback.
    ///   2. **Minted cross-peer chain cap.** The standing extract dispatches
    ///      under the minted `tree:extract` chain cap
    ///      (`ContinuationSpec::dispatch_capability(cross_cap)`), NOT the
    ///      connection grant the bootstrap wielded. A mirror landing here is the
    ///      only proof that cap authorizes B's verification at standing-dispatch
    ///      time.
    ///
    /// So a post-follow write on B surfacing in A's store proves: push trigger →
    /// extract-under-chain-cap → merge → local mirror. Same rendezvous
    /// establishment as AUDIT-1 (a dial-by-address can't push the trigger at all).
    #[cfg(all(not(target_arch = "wasm32"), feature = "continuation"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn follow_continuation_standing_leg_fires_cross_peer() {
        use entity_peer::transport::MemoryTransportRegistry;

        let reg = MemoryTransportRegistry::new();
        let (ctx_a, ctx_b, b_pid, server_task) = rendezvous_pair(reg).await;

        let prefix = format!("/{}/app/test/cfollow-standing/", b_pid);

        // A pre-follow entity exercises the bootstrap; the standing leg is what
        // this test isolates, via the post-follow write below.
        ctx_b
            .store()
            .put(&format!("{prefix}m-boot"), make_entity("t", "pre-follow"))
            .unwrap();

        let _handle = ctx_a
            .follow(b_pid.clone(), prefix.clone(), FollowOptions::continuation())
            .await
            .expect("continuation follow installs + bootstraps");

        // Bootstrap should already have mirrored the pre-follow entity.
        assert_eq!(
            ctx_a.store().get(&format!("{prefix}m-boot")).as_ref(),
            Some(&make_entity("t", "pre-follow")),
            "bootstrap mirrors the pre-follow entity"
        );

        // THE STANDING TRIGGER: write a NEW entity on B after follow is live.
        // Only the standing chain (push → extract-under-chain-cap → merge) can
        // carry this into A's store — the bootstrap already ran.
        let target = format!("{prefix}m-standing");
        let body = make_entity("t", "standing-from-b");
        ctx_b.store().put(&target, body.clone()).unwrap();

        let mut mirrored = None;
        for _ in 0..60 {
            if let Some(e) = ctx_a.store().get(&target) {
                mirrored = Some(e);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        assert_eq!(
            mirrored.as_ref(),
            Some(&body),
            "follow(Continuation) STANDING leg must mirror B's post-follow write: \
             notification push → tree:extract under the minted chain cap → \
             tree:merge → local mirror"
        );

        drop(_handle);
        server_task.abort();
    }

    /// **BIDIRECTIONAL reactive delivery over ONE symmetric channel — the crux
    /// for retiring the chat poll.** Real chat is two peers each mirroring the
    /// other's append-only log over a single §6.5 WebRTC data channel. On that
    /// one channel one peer is the Initiator (dialed), the other the Responder
    /// (served) — and the reciprocal reentry grant is minted in only one
    /// direction (Initiator→Responder). The open worry (the A3 finding, where a
    /// demoted poll left one direction undelivered) is whether that
    /// one-directional *grant* means one-directional *delivery*.
    ///
    /// It does not. Over the single established connection both originations are
    /// authorized: Initiator→Responder is an ordinary client→server dispatch;
    /// Responder→Initiator rides the reentry endpoint under the reciprocal
    /// grant. So BOTH follows deliver: A (Initiator) follows B and B follows A;
    /// each writes a post-follow message; each sees the other's. This memory
    /// harness is topologically the single WebRTC channel — A dials B, B reenters
    /// over that same accepted connection — so a green here means the delivery
    /// *authorization* is symmetric and the poll's delivery role is retirable
    /// (what remains for it is establishment-retry over the real transport, a
    /// separate transport-robustness concern — the A3 lesson relocated, not
    /// contradicted).
    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn follow_payload_delivers_both_directions_one_channel() {
        use entity_peer::transport::MemoryTransportRegistry;

        let reg = MemoryTransportRegistry::new();
        let (ctx_a, ctx_b, b_pid, server_task) = rendezvous_pair(reg).await;
        let a_pid = ctx_a.peer_id().to_string();

        // A (Initiator) follows B, and B (Responder) follows A — over the one
        // channel A established. B reaches A only via the reentry endpoint.
        let a_watch = format!("/{}/app/test/bidi/", b_pid); // A mirrors B's log
        let b_watch = format!("/{}/app/test/bidi/", a_pid); // B mirrors A's log
        let _fa = ctx_a
            .follow(b_pid.clone(), a_watch.clone(), FollowOptions::payload())
            .await
            .expect("A→B follow installs");
        let _fb = ctx_b
            .follow(a_pid.clone(), b_watch.clone(), FollowOptions::payload())
            .await
            .expect("B→A follow installs (B originates the subscribe over reentry)");

        // Each writes a post-follow message under its own namespace.
        let from_b = format!("{a_watch}m-b");
        let from_a = format!("{b_watch}m-a");
        let body_b = make_entity("t", "hello-from-b");
        let body_a = make_entity("t", "hello-from-a");
        ctx_b.store().put(&from_b, body_b.clone()).unwrap();
        ctx_a.store().put(&from_a, body_a.clone()).unwrap();

        // Await BOTH mirrors, each in the other peer's local store.
        let mut got_b_at_a = None; // B's message mirrored into A
        let mut got_a_at_b = None; // A's message mirrored into B
        for _ in 0..60 {
            if got_b_at_a.is_none() {
                got_b_at_a = ctx_a.store().get(&from_b);
            }
            if got_a_at_b.is_none() {
                got_a_at_b = ctx_b.store().get(&from_a);
            }
            if got_b_at_a.is_some() && got_a_at_b.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        assert_eq!(
            got_b_at_a.as_ref(),
            Some(&body_b),
            "Responder→Initiator: B's post-follow write must reach A via reentry \
             + reciprocal grant"
        );
        assert_eq!(
            got_a_at_b.as_ref(),
            Some(&body_a),
            "Initiator→Responder: A's post-follow write must reach B via the \
             ordinary client→server dispatch over the same channel"
        );

        server_task.abort();
    }
}
