//! Typed wrapper for `system/continuation` extension operations.
//!
//! Per `SDK-EXTENSION-OPERATIONS.md §2` (v0.7): "The SDK's job is to
//! provide typed, discoverable wrappers [around `execute()`]." This
//! module is the seed of that pattern for continuations — reached via
//! [`PeerContext::continuation`].
//!
//! ## Scope
//!
//! The normative L1 surface is `install` / `advance` / `resume` /
//! `abandon` (four ops registered by the continuation handler). This
//! module exposes `install` / `resume` / `abandon` as typed wrappers
//! — `advance` is invoked by the inbox runtime on result delivery and
//! is not typically called by application code; it can be added when
//! a concrete app-tier use case emerges. The L3 pipeline-builder DSL
//! (`peer.continuation.chain()...`) is **explicitly not required** by
//! the SDK per
//! `PROPOSAL-SDK-STALENESS-SWEEP-EXTENSION-LANDINGS.md §305 row 8` —
//! that's reference-design (E7) territory and is not in scope here.
//!
//! ## Wire shape (path-as-resource)
//!
//! Per `PROPOSAL-PATH-AS-RESOURCE-HYGIENE §3.2` and the handler at
//! `entity-core-rust/extensions/continuation/src/lib.rs`, continuation
//! operations carry the suspended-continuation path as the
//! `ResourceTarget`, not as a field of the params entity. This wrapper
//! enforces that shape on every call.
//!
//! ## Feature gating
//!
//! Available only when `entity-sdk` is built with the `continuation`
//! feature enabled (which transitively pulls
//! `entity-peer/continuation`, where the handler is registered).

use crate::sdk::{PeerContext, SdkError};
use entity_capability::ResourceTarget;
use entity_entity::Entity;
use entity_handler::ExecuteOptions;
use entity_hash::Hash;

/// A `{uri, operation}` delivery spec — where a continuation delivers its
/// result (`deliver_to`) or routes a non-2xx response (`on_error`). Per
/// EXTENSION-CONTINUATION §3.5 (`system/delivery-spec`).
#[derive(Debug, Clone)]
pub struct DeliverySpec {
    pub uri: String,
    pub operation: String,
}

impl DeliverySpec {
    pub fn new(uri: impl Into<String>, operation: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            operation: operation.into(),
        }
    }

    /// The common `{uri, operation: "receive"}` case (inbox delivery).
    pub fn receive(uri: impl Into<String>) -> Self {
        Self::new(uri, "receive")
    }
}

/// Builder for a **forward** `system/continuation` entity — the install body
/// for [`ContinuationOps::install`]. The Rust analog of Go's
/// `core/types.ContinuationData` (`ToEntity`): it assembles the deferred
/// dispatch (`target` / `operation` / `resource` / `params`), the single
/// dynamic field threaded from the trigger result (`result_extract` navigates
/// the delivered result, `result_field` names where to inject it), delivery
/// routing (`deliver_to` / `on_error`), the standing-vs-bounded count
/// (`remaining_executions`; `None` = standing, fire forever), and the
/// `dispatch_capability` the handler dispatches the next link under.
///
/// This is the primitive a continuation *chain* is built from — e.g. the
/// revision-free `tree:extract → tree:merge` follow chain
/// ([`crate::follow::FollowMode::Continuation`]). Nothing here assumes a
/// revisioned subtree; the `target`/`operation` are whatever the step
/// dispatches (`tree:extract`, `tree:merge`, `tree:get`, …).
///
/// The richer transform surface (`select`, `transform_ops`, the other
/// `*_extract` fields) is intentionally omitted; `result_extract` covers the
/// single-dynamic-field chain recipe. Add the rest when a consumer needs it.
#[derive(Debug, Clone, Default)]
pub struct ContinuationSpec {
    /// Handler URI the deferred dispatch targets (e.g. `system/tree` or
    /// `entity://{remote}/system/tree`).
    pub target: String,
    /// Operation on `target` (e.g. `merge`, `extract`, `get`).
    pub operation: String,
    /// Resource target for the deferred dispatch (path-as-resource).
    pub resource: Option<ResourceTarget>,
    /// Static params as raw CBOR (`primitive/any`, spliced inline per
    /// EXTENSION-CONTINUATION §2.1 — NOT wrapped as a byte string).
    pub params: Option<Vec<u8>>,
    /// Field the extracted dynamic value is injected into before dispatch.
    pub result_field: Option<String>,
    /// Dotted path extracted from the delivered trigger result and threaded
    /// on (`result_transform.extract`).
    pub result_extract: Option<String>,
    /// Where a successful result is delivered (the next chain link).
    pub deliver_to: Option<DeliverySpec>,
    /// Where a non-2xx response is routed (a chain-error inbox) instead of
    /// silently cascading.
    pub on_error: Option<DeliverySpec>,
    /// `None` = standing (fire forever); `Some(n)` = fire n times then expire.
    pub remaining_executions: Option<u64>,
    /// Capability hash the continuation dispatches the next link under
    /// (required to dispatch; validated against the writer's authority chain
    /// at install per §3.1a). Typically the owner cap hash for a local step
    /// or a cross-peer chain cap for a remote step.
    pub dispatch_capability: Option<Hash>,
}

impl ContinuationSpec {
    /// A forward continuation dispatching `operation` on `target`.
    pub fn new(target: impl Into<String>, operation: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            operation: operation.into(),
            ..Default::default()
        }
    }

    pub fn resource(mut self, rt: ResourceTarget) -> Self {
        self.resource = Some(rt);
        self
    }

    /// Set static params from a raw CBOR encoding (`primitive/any`).
    pub fn params(mut self, cbor: Vec<u8>) -> Self {
        self.params = Some(cbor);
        self
    }

    pub fn result_field(mut self, field: impl Into<String>) -> Self {
        self.result_field = Some(field.into());
        self
    }

    pub fn result_extract(mut self, path: impl Into<String>) -> Self {
        self.result_extract = Some(path.into());
        self
    }

    pub fn deliver_to(mut self, spec: DeliverySpec) -> Self {
        self.deliver_to = Some(spec);
        self
    }

    pub fn on_error(mut self, spec: DeliverySpec) -> Self {
        self.on_error = Some(spec);
        self
    }

    pub fn remaining_executions(mut self, n: u64) -> Self {
        self.remaining_executions = Some(n);
        self
    }

    pub fn dispatch_capability(mut self, hash: Hash) -> Self {
        self.dispatch_capability = Some(hash);
        self
    }

    /// Encode as a `system/continuation` entity — the body passed to
    /// [`ContinuationOps::install`]. The wire shape matches the handler's
    /// decoder (EXTENSION-CONTINUATION §2.1); ECF canonicalizes key order,
    /// so field insertion order here is irrelevant.
    pub fn to_entity(&self) -> Result<Entity, SdkError> {
        let mut fields: Vec<(entity_ecf::Value, entity_ecf::Value)> = vec![
            (
                entity_ecf::text("operation"),
                entity_ecf::text(&self.operation),
            ),
            (entity_ecf::text("target"), entity_ecf::text(&self.target)),
        ];
        if let Some(dt) = &self.deliver_to {
            fields.push((entity_ecf::text("deliver_to"), delivery_spec_value(dt)));
        }
        if let Some(cap) = self.dispatch_capability {
            fields.push((
                entity_ecf::text("dispatch_capability"),
                entity_ecf::Value::Bytes(cap.to_bytes().to_vec()),
            ));
        }
        if let Some(oe) = &self.on_error {
            fields.push((entity_ecf::text("on_error"), delivery_spec_value(oe)));
        }
        if let Some(p) = &self.params {
            // `params` is `primitive/any` — splice the raw CBOR inline (NOT
            // wrapped as Value::Bytes, which would mis-encode as
            // primitive/bytes and break the handler + Go interop).
            let v: ciborium::Value = ciborium::from_reader(p.as_slice()).map_err(|e| {
                SdkError::HandlerError(format!("continuation params not valid CBOR: {e}"))
            })?;
            fields.push((entity_ecf::text("params"), v));
        }
        if let Some(n) = self.remaining_executions {
            fields.push((
                entity_ecf::text("remaining_executions"),
                entity_ecf::integer(n as i64),
            ));
        }
        if let Some(res) = &self.resource {
            fields.push((
                entity_ecf::text("resource"),
                encode_resource_target(res),
            ));
        }
        if let Some(rf) = &self.result_field {
            fields.push((entity_ecf::text("result_field"), entity_ecf::text(rf)));
        }
        if let Some(ex) = &self.result_extract {
            fields.push((
                entity_ecf::text("result_transform"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("extract"),
                    entity_ecf::text(ex),
                )]),
            ));
        }
        Entity::new(
            "system/continuation",
            entity_ecf::to_ecf(&entity_ecf::Value::Map(fields)),
        )
        .map_err(|e| SdkError::HandlerError(format!("build continuation entity: {e}")))
    }
}

/// Encode a `DeliverySpec` as the `{operation, uri}` map the handler decodes.
fn delivery_spec_value(d: &DeliverySpec) -> entity_ecf::Value {
    entity_ecf::Value::Map(vec![
        (entity_ecf::text("operation"), entity_ecf::text(&d.operation)),
        (entity_ecf::text("uri"), entity_ecf::text(&d.uri)),
    ])
}

/// Encode a `ResourceTarget` as `{targets: [...], exclude?: [...]}`, matching
/// the continuation handler's `encode_resource_target`.
fn encode_resource_target(rt: &ResourceTarget) -> entity_ecf::Value {
    let mut fields: Vec<(entity_ecf::Value, entity_ecf::Value)> = Vec::new();
    if !rt.exclude.is_empty() {
        fields.push((
            entity_ecf::text("exclude"),
            entity_ecf::Value::Array(rt.exclude.iter().map(entity_ecf::text).collect()),
        ));
    }
    fields.push((
        entity_ecf::text("targets"),
        entity_ecf::Value::Array(rt.targets.iter().map(entity_ecf::text).collect()),
    ));
    entity_ecf::Value::Map(fields)
}

/// Typed accessor for `system/continuation` operations.
///
/// Created via [`PeerContext::continuation`]. Borrows from the
/// `PeerContext`; futures returned by methods are `'static` (the
/// underlying `execute()` clones shared state internally).
pub struct ContinuationOps<'a> {
    ctx: &'a PeerContext,
}

impl<'a> ContinuationOps<'a> {
    pub(crate) fn new(ctx: &'a PeerContext) -> Self {
        Self { ctx }
    }

    /// Install a continuation entity at `path`. `body` MUST be an
    /// Entity of type `system/continuation` (forward) or
    /// `system/continuation/join` (join); the embedded
    /// `dispatch_capability` is validated against the writer's
    /// authority chain per `EXTENSION-CONTINUATION §3.1a` at the
    /// handler.
    ///
    /// The path is passed as the resource target (path-as-resource);
    /// `body` is the continuation entity itself, sent as params.
    ///
    /// Returns `Ok(())` on a 2xx handler status — the caller already
    /// knows the install path. The handler echoes the bare path back
    /// in its result body for clients that lost track; if a future
    /// caller needs that echo, switch to a richer return type.
    ///
    /// Returns `Err(SdkError)` for:
    /// - body whose `entity_type` is not `system/continuation` or
    ///   `system/continuation/join` (precheck, before dispatch),
    /// - `403 missing_author` / `403 embedded_cap_unauthorized` (auth chain),
    /// - `404 chain_unreachable` (auth chain cannot be walked),
    /// - any other non-2xx handler status.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn install(
        &self,
        path: impl Into<String>,
        body: Entity,
    ) -> impl std::future::Future<Output = Result<(), SdkError>> + Send + 'static {
        let path = path.into();
        let typecheck = check_install_body_type(&body);
        let opts = path_resource_opts(path);
        let fut = self
            .ctx
            .execute("system/continuation", "install", body, opts);
        async move {
            typecheck?;
            let result = fut.await?;
            check_2xx(&result, "install")
        }
    }

    /// WASM variant — no `Send` bound.
    #[cfg(target_arch = "wasm32")]
    pub fn install(
        &self,
        path: impl Into<String>,
        body: Entity,
    ) -> impl std::future::Future<Output = Result<(), SdkError>> + 'static {
        let path = path.into();
        let typecheck = check_install_body_type(&body);
        let opts = path_resource_opts(path);
        let fut = self
            .ctx
            .execute("system/continuation", "install", body, opts);
        async move {
            typecheck?;
            let result = fut.await?;
            check_2xx(&result, "install")
        }
    }

    /// Resume a suspended continuation at `path`. Optionally provide
    /// a `resolution` entity whose CBOR-encoded data is merged into
    /// the suspended params (interactive-continuation pattern); pass
    /// `None` if the suspended op needs no additional resolution.
    ///
    /// On a 2xx, returns the underlying dispatch's [`HandlerResult`]
    /// — resume delegates to the suspended target with merged params,
    /// so the result type is whatever that target's handler produces.
    ///
    /// Returns `Err(SdkError)` for transport failure or non-2xx
    /// handler status (notably `400 not_suspended` if the entity at
    /// `path` is not a suspended continuation).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn resume(
        &self,
        path: impl Into<String>,
        resolution: Option<Entity>,
    ) -> impl std::future::Future<Output = Result<entity_handler::HandlerResult, SdkError>>
           + Send
           + 'static {
        let opts = path_resource_opts(path.into());
        let params = build_resume_params(resolution);
        let fut = self
            .ctx
            .execute("system/continuation", "resume", params, opts);
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/continuation:resume")
            {
                return Err(err);
            }
            Ok(result)
        }
    }

    /// WASM variant — no `Send` bound.
    #[cfg(target_arch = "wasm32")]
    pub fn resume(
        &self,
        path: impl Into<String>,
        resolution: Option<Entity>,
    ) -> impl std::future::Future<Output = Result<entity_handler::HandlerResult, SdkError>> + 'static
    {
        let opts = path_resource_opts(path.into());
        let params = build_resume_params(resolution);
        let fut = self
            .ctx
            .execute("system/continuation", "resume", params, opts);
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/continuation:resume")
            {
                return Err(err);
            }
            Ok(result)
        }
    }

    /// Abandon a suspended continuation: delete the suspended entity
    /// at `path` and clean up delivery state. See
    /// `SDK-EXTENSION-OPERATIONS.md §2` and
    /// `EXTENSION-CONTINUATION` for the handler-side semantics.
    ///
    /// `path` is the suspended-continuation tree path (e.g.
    /// Advance a suspended continuation at `path` with a delivered
    /// result. Per `EXTENSION-CONTINUATION §3.4` — applies `result` /
    /// `status` to the suspended op and continues the chain (running
    /// any `result_transform`, dispatching the next link if forward,
    /// joining if join).
    ///
    /// **Typical caller is the inbox runtime**, not application code:
    /// when a remote peer delivers a result for a suspended op, the
    /// inbox handler fires `advance` to continue the chain. This
    /// wrapper exposes it for the rarer app-tier cases (cross-impl
    /// parity with Go's continuation client; orchestration helpers
    /// that synthesize delivery; test harnesses).
    ///
    /// `result_bytes` is the underlying op's result data (the bytes
    /// that go into the suspended continuation's params merge slot).
    /// `status` defaults to 200 when `None`.
    ///
    /// Returns the underlying dispatch's `HandlerResult` — advance
    /// dispatches the suspended target with merged result, so the
    /// returned shape is whatever that target's handler produces.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn advance(
        &self,
        path: impl Into<String>,
        result_bytes: Vec<u8>,
        status: Option<u32>,
    ) -> impl std::future::Future<Output = Result<entity_handler::HandlerResult, SdkError>>
           + Send
           + 'static {
        let params = build_advance_params(result_bytes, status);
        let opts = path_resource_opts(path.into());
        self.ctx
            .execute("system/continuation", "advance", params, opts)
    }

    /// WASM variant — no `Send` bound, future is `!Send` for
    /// `spawn_local` use.
    #[cfg(target_arch = "wasm32")]
    pub fn advance(
        &self,
        path: impl Into<String>,
        result_bytes: Vec<u8>,
        status: Option<u32>,
    ) -> impl std::future::Future<Output = Result<entity_handler::HandlerResult, SdkError>> + 'static
    {
        let params = build_advance_params(result_bytes, status);
        let opts = path_resource_opts(path.into());
        self.ctx
            .execute("system/continuation", "advance", params, opts)
    }

    /// `/{peer_id}/system/continuation/suspended/<id>`). Passed as the
    /// resource target — the params body is intentionally empty.
    ///
    /// Returns `Ok(())` on a 2xx handler status. Returns
    /// `Err(SdkError)` on transport failure, `404 not_found` (no
    /// suspended continuation at the path), or any other non-2xx.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn abandon(
        &self,
        path: impl Into<String>,
    ) -> impl std::future::Future<Output = Result<(), SdkError>> + Send + 'static {
        let opts = path_resource_opts(path.into());
        let fut = self
            .ctx
            .execute("system/continuation", "abandon", empty_params(), opts);
        async move {
            let result = fut.await?;
            check_2xx(&result, "abandon")
        }
    }

    /// WASM variant — no `Send` bound, future is `!Send` for
    /// `spawn_local` use.
    #[cfg(target_arch = "wasm32")]
    pub fn abandon(
        &self,
        path: impl Into<String>,
    ) -> impl std::future::Future<Output = Result<(), SdkError>> + 'static {
        let opts = path_resource_opts(path.into());
        let fut = self
            .ctx
            .execute("system/continuation", "abandon", empty_params(), opts);
        async move {
            let result = fut.await?;
            check_2xx(&result, "abandon")
        }
    }
}

/// Build an `ExecuteOptions` carrying the continuation path as a
/// single-target `ResourceTarget` (path-as-resource per
/// PROPOSAL-PATH-AS-RESOURCE-HYGIENE §3.2). Shared by every op in
/// this module — adding more ops below should reuse this helper.
fn path_resource_opts(path: String) -> ExecuteOptions {
    ExecuteOptions {
        resource: Some(ResourceTarget {
            targets: vec![path],
            exclude: vec![],
        }),
        ..Default::default()
    }
}

/// Construct an empty CBOR-map `primitive/any` entity for ops whose
/// params are not read (e.g. `abandon` — the resource target carries
/// the only argument).
fn empty_params() -> Entity {
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(Vec::new()));
    Entity::new("primitive/any", data)
        .expect("empty primitive/any entity construction is infallible")
}

/// Build the `advance` request body — `{result: bytes, status?: uint}`
/// per `EXTENSION-CONTINUATION §3.4`. The handler's
/// `decode_advance_request` accepts the result as either a CBOR bytes
/// blob or any CBOR value (auto-encoded to bytes). We pass it as a
/// pre-encoded bytes blob — that matches the typical inbox-delivered
/// shape and avoids surprises with CBOR value detection.
fn build_advance_params(result_bytes: Vec<u8>, status: Option<u32>) -> Entity {
    let mut fields: Vec<(ciborium::Value, ciborium::Value)> = vec![(
        entity_ecf::text("result"),
        ciborium::Value::Bytes(result_bytes),
    )];
    if let Some(s) = status {
        fields.push((entity_ecf::text("status"), entity_ecf::integer(s as i64)));
    }
    // ECF sort: result, status (already sorted).
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(fields));
    Entity::new("primitive/any", data).expect("advance-params entity construction is infallible")
}

/// Precheck the install body's entity_type. Per `EXTENSION-CONTINUATION`,
/// the install handler accepts exactly `system/continuation` (forward)
/// or `system/continuation/join`. Rejecting at the wrapper avoids a
/// round-trip with a clearer error than the handler's
/// `400 invalid_params`.
fn check_install_body_type(body: &Entity) -> Result<(), SdkError> {
    match body.entity_type.as_str() {
        "system/continuation" | "system/continuation/join" => Ok(()),
        other => Err(SdkError::HandlerError(format!(
            "continuation::install body must be of type `system/continuation` \
             or `system/continuation/join`, got `{}`",
            other
        ))),
    }
}

/// Build the resume params entity. The handler decodes `params.data`
/// as a CBOR map and looks for the `resolution` key; if present, its
/// value is taken as bytes (`Bytes` passes through; any other CBOR
/// value is re-encoded to bytes). We pass `resolution.data` (already
/// CBOR-encoded) as bytes — the handler accepts that path directly.
fn build_resume_params(resolution: Option<Entity>) -> Entity {
    let map = match resolution {
        None => Vec::new(),
        Some(entity) => vec![(
            entity_ecf::text("resolution"),
            ciborium::Value::Bytes(entity.data),
        )],
    };
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(map));
    Entity::new("primitive/any", data).expect("primitive/any entity construction is infallible")
}

fn check_2xx(result: &entity_handler::HandlerResult, op: &'static str) -> Result<(), SdkError> {
    match SdkError::from_handler_result(result, format!("system/continuation:{op}")) {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk::PeerContextBuilder;

    fn make_ctx() -> PeerContext {
        PeerContextBuilder::new()
            .generate_keypair()
            .build()
            .expect("PeerContext build should succeed")
    }

    /// Abandon against a non-existent suspended path returns a non-2xx
    /// (mapped to `Err(SdkError)`). Proves: scope handle reaches the
    /// continuation handler, the path is dispatched via resource
    /// target (handler reads `resource_target.targets[0]`), error
    /// path is mapped to `Result::Err`.
    #[tokio::test(flavor = "current_thread")]
    async fn abandon_missing_path_returns_err() {
        let ctx = make_ctx();
        let pid = ctx.peer_id().to_string();
        let missing = format!("/{}/system/continuation/suspended/does-not-exist", pid);

        let result = ctx.continuation().abandon(missing).await;
        assert!(
            result.is_err(),
            "expected Err for missing path, got {:?}",
            result
        );
    }

    /// Install with a body of the wrong entity_type is rejected at the
    /// wrapper before dispatch. Proves: typed prechecks save a
    /// round-trip + give a clearer error than the handler's
    /// `400 invalid_params`.
    #[tokio::test(flavor = "current_thread")]
    async fn install_wrong_body_type_rejected_locally() {
        let ctx = make_ctx();
        let pid = ctx.peer_id().to_string();
        let path = format!("/{}/system/continuation/suspended/x", pid);

        // Body whose entity_type is not system/continuation*.
        // Use a non-empty CBOR-encoded payload to satisfy Entity::new
        // (it rejects empty data).
        let placeholder_data = entity_ecf::to_ecf(&ciborium::Value::Map(Vec::new()));
        let bad_body = Entity::new("app/state/setting", placeholder_data).unwrap();

        let result = ctx.continuation().install(path, bad_body).await;
        match result {
            Err(SdkError::HandlerError(msg)) => {
                assert!(
                    msg.contains("system/continuation"),
                    "error should mention required type, got: {}",
                    msg
                );
                assert!(
                    msg.contains("app/state/setting"),
                    "error should mention actual type, got: {}",
                    msg
                );
            }
            other => panic!("expected HandlerError for wrong body type, got {:?}", other),
        }
    }

    /// Resume against a non-existent path returns Err. Proves: same
    /// path-as-resource dispatch as abandon, separate handler op,
    /// error mapping intact.
    #[tokio::test(flavor = "current_thread")]
    async fn resume_missing_path_returns_err() {
        let ctx = make_ctx();
        let pid = ctx.peer_id().to_string();
        let missing = format!("/{}/system/continuation/suspended/nope", pid);

        let result = ctx.continuation().resume(missing, None).await;
        assert!(
            result.is_err(),
            "expected Err for missing path, got Ok(HandlerResult(status={}))",
            result.as_ref().map(|r| r.status).unwrap_or(0)
        );
    }

    /// `build_resume_params(None)` produces an empty-map params body
    /// the handler accepts as "no resolution provided." Direct unit
    /// test of the params builder so this case is locked even if no
    /// integration test exercises it.
    #[test]
    fn build_resume_params_none_is_empty_map() {
        let params = build_resume_params(None);
        let val: ciborium::Value = ciborium::de::from_reader(params.data.as_slice())
            .expect("resume params should be valid CBOR");
        match val {
            ciborium::Value::Map(m) => assert!(m.is_empty(), "expected empty map, got {:?}", m),
            other => panic!("expected CBOR Map, got {:?}", other),
        }
    }

    /// With `Some(entity)`, the resolution key carries the entity's
    /// data as raw CBOR bytes. Mirrors `decode_resume_request`'s
    /// expected shape in the handler.
    #[test]
    fn build_resume_params_some_carries_resolution_bytes() {
        let inner = Entity::new("primitive/any", vec![0x01, 0x02, 0x03]).unwrap();
        let params = build_resume_params(Some(inner));
        let val: ciborium::Value = ciborium::de::from_reader(params.data.as_slice())
            .expect("resume params should be valid CBOR");
        let map = val.as_map().expect("expected map");
        let entry = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("resolution"))
            .expect("resolution key should be present");
        match &entry.1 {
            ciborium::Value::Bytes(b) => assert_eq!(b, &vec![0x01, 0x02, 0x03]),
            other => panic!("expected resolution bytes, got {:?}", other),
        }
    }

    /// `advance` against a non-existent path returns 200 with
    /// `advanced: false` in the result body — per `EXTENSION-
    /// CONTINUATION §3.4`, advance is idempotent: nothing to advance
    /// is a normative no-op, not an error. Probes: scope handle
    /// reaches the continuation handler at the `advance` op
    /// specifically (separate dispatch from install/resume/abandon),
    /// advance-params shape encodes correctly, no-op result decodes.
    #[tokio::test(flavor = "current_thread")]
    async fn advance_missing_path_is_noop_advanced_false() {
        let ctx = make_ctx();
        let pid = ctx.peer_id().to_string();
        let missing = format!("/{}/system/continuation/suspended/ghost", pid);

        let result = ctx
            .continuation()
            .advance(missing, vec![0x01, 0x02], None)
            .await
            .expect("advance should dispatch (no-op, not error)");
        assert!(
            (200..300).contains(&result.status),
            "expected 2xx no-op, got {}",
            result.status
        );
        // Decode the result body and verify `advanced: false`.
        let val: ciborium::Value = ciborium::de::from_reader(result.result.data.as_slice())
            .expect("advancement-result is valid CBOR");
        let map = val.as_map().expect("advancement-result is a map");
        let advanced = map
            .iter()
            .find_map(|(k, v)| {
                if k.as_text() == Some("advanced") {
                    if let ciborium::Value::Bool(b) = v {
                        Some(*b)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .expect("advancement-result carries `advanced` bool");
        assert!(!advanced, "no-op advance reports advanced=false");
    }

    /// `build_advance_params` with `None` status produces only the
    /// `result` key; with `Some` status it adds the status key.
    /// Direct unit test of the builder so the wire shape is locked.
    #[test]
    fn build_advance_params_includes_status_when_some() {
        let p1 = build_advance_params(vec![0xAA], None);
        let v1: ciborium::Value = ciborium::de::from_reader(p1.data.as_slice())
            .expect("advance params should be valid CBOR");
        let m1 = v1.as_map().expect("expected map");
        assert!(m1.iter().any(|(k, _)| k.as_text() == Some("result")));
        assert!(
            !m1.iter().any(|(k, _)| k.as_text() == Some("status")),
            "no status field when None"
        );

        let p2 = build_advance_params(vec![0xBB], Some(207));
        let v2: ciborium::Value = ciborium::de::from_reader(p2.data.as_slice())
            .expect("advance params should be valid CBOR");
        let m2 = v2.as_map().expect("expected map");
        let status_val = m2
            .iter()
            .find_map(|(k, v)| {
                if k.as_text() == Some("status") {
                    v.as_integer().map(|i| i128::from(i) as i64)
                } else {
                    None
                }
            })
            .expect("status field present when Some");
        assert_eq!(status_val, 207);
    }

    /// `check_install_body_type` accepts both continuation entity
    /// types and rejects everything else. Spec-defined at
    /// EXTENSION-CONTINUATION §3.1.
    #[test]
    fn install_body_type_check_accepts_forward_and_join_only() {
        // Non-empty CBOR data so Entity::new() succeeds — the body
        // content isn't read by the type check.
        let stub = entity_ecf::to_ecf(&ciborium::Value::Map(Vec::new()));
        let forward = Entity::new("system/continuation", stub.clone()).unwrap();
        let join = Entity::new("system/continuation/join", stub.clone()).unwrap();
        let bogus = Entity::new("primitive/any", stub).unwrap();

        assert!(check_install_body_type(&forward).is_ok());
        assert!(check_install_body_type(&join).is_ok());
        assert!(check_install_body_type(&bogus).is_err());
    }

    /// A `ContinuationSpec` builds a `system/continuation` entity the handler
    /// accepts on install — proving the builder's wire shape matches the
    /// decoder. Uses the revision-free follow chain's extract step shape
    /// (cross-peer `tree:extract`, one dynamic field, deliver to a merge
    /// inbox, on-error routed) with the owner cap as the dispatch capability
    /// so the §3.1a authority-chain check passes. No revisioned subtree
    /// involved.
    #[tokio::test(flavor = "current_thread")]
    async fn continuation_spec_builds_handler_accepted_entity() {
        let ctx = make_ctx();
        let pid = ctx.peer_id().to_string();
        let prefix = format!("/{pid}/app/x/");
        let params = entity_ecf::to_ecf(&ciborium::Value::Map(vec![(
            entity_ecf::text("source_prefix"),
            entity_ecf::text(&prefix),
        )]));
        let spec = ContinuationSpec::new(format!("entity://{pid}/system/tree"), "extract")
            .resource(ResourceTarget {
                targets: vec![prefix.clone()],
                exclude: vec![],
            })
            .params(params)
            .result_extract("uri")
            .result_field("source_prefix")
            .deliver_to(DeliverySpec::receive(format!(
                "entity://{pid}/system/inbox/follow/merge"
            )))
            .on_error(DeliverySpec::receive(format!(
                "entity://{pid}/system/inbox/follow/extract-errors"
            )))
            .dispatch_capability(ctx.owner_capability_hash());

        let body = spec.to_entity().expect("build continuation entity");
        assert_eq!(body.entity_type, "system/continuation");

        let path = format!("/{pid}/system/inbox/follow/extract");
        ctx.continuation()
            .install(path, body)
            .await
            .expect("handler accepts the ContinuationSpec-built wire shape");
    }
}
