//! The **wrapped** surface (`PROPOSAL-CONNECTION-NODE` §2) — `system/signaling`
//! as an ordinary entity handler.
//!
//! This is a thin front end and nothing more: decode params, call
//! [`SignalingCore`], encode the result. **It reimplements no verb.** That is
//! the §2.1 pin — when the unwrapped surface arrives it becomes a second front
//! end beside this one, and because neither owns the verbs, the two cannot
//! drift. A divergence between surfaces would mean someone implemented the verbs
//! twice, and *that* is the defect.
//!
//! **Where security comes from here:** the capability grant. Admission is the
//! ordinary dispatch-layer capability check against the envelope capability,
//! exactly as for every other handler — the handler body carries no cap checks
//! (matches RELAY / REGISTRY / DISCOVERY). This is the surface for the private
//! device mesh, where admission genuinely matters.
//!
//! **What this handler owns:** nothing durable. No tree writes, no content-store
//! puts, no background task. Bucket state is in-memory in the core and dies with
//! the process — §1.3, and the reason this half is unblocked while the
//! service-owning half waits on `PROPOSAL-SDK-HANDLER-OWNED-SERVICES`.

use std::sync::Arc;

use async_trait::async_trait;
use entity_ecf::{text, to_ecf, Value};
use entity_entity::Entity;
use entity_handler::{
    Handler, HandlerContext, HandlerError, HandlerResult, STATUS_BAD_REQUEST, STATUS_RATE_LIMITED,
};

use crate::core::{CoreError, SignalingCore};
use crate::data::{
    advertisement_to_entity, offer_result, CollectRequest, CollectResult, OfferRequest,
};
use crate::{
    CODE_BUCKET_FULL, CODE_CAPACITY_EXHAUSTED, CODE_INVALID_PARAMS, CODE_MESSAGE_TOO_LARGE,
    CODE_UNKNOWN_OPERATION, OPERATIONS, OP_ADVERTISE, OP_COLLECT, OP_OFFER, PATTERN,
};

/// `system/signaling` — the three core verbs over cross-peer `execute`.
///
/// **`reflect` is deliberately absent** (§1.4, ruling 2026-07-28). A call to it
/// falls through to the ordinary unknown-operation error, exactly as `frobnicate`
/// would — not a placeholder awaiting plumbing. It is the unwrapped listener's
/// verb, and no `HandlerContext` field or observed-address side channel is
/// invented here to fake it; both were on the table and both turned out
/// unnecessary once `reflect` moved off the mailbox.
pub struct SignalingHandler {
    core: Arc<SignalingCore>,
    qualified_pattern: String,
}

impl SignalingHandler {
    /// Build the handler over a core. The pattern is peer-qualified the same way
    /// every other extension does it, so dispatch resolves it by longest prefix.
    pub fn new(core: Arc<SignalingCore>, local_peer_id: &str) -> Self {
        Self {
            core,
            qualified_pattern: format!("/{}/{}", local_peer_id, PATTERN),
        }
    }

    /// The core this handler fronts — so a co-located unwrapped front end, or a
    /// test, addresses the *same* verbs rather than constructing a second core.
    pub fn core(&self) -> &Arc<SignalingCore> {
        &self.core
    }

    // -----------------------------------------------------------------------
    // offer (§1, §1.1 pin 2)
    // -----------------------------------------------------------------------

    fn handle_offer(&self, ctx: &HandlerContext, now_ms: i64) -> HandlerResult {
        let req = match OfferRequest::from_params(&ctx.params.data) {
            Ok(r) => r,
            Err(e) => return error(STATUS_BAD_REQUEST, CODE_INVALID_PARAMS, &e.to_string()),
        };

        // Which bucket, and who. See `handle_collect` for why this pair of
        // lines is the node's job and nobody else's.
        tracing::debug!(
            caller = ctx.session_peer_id.as_deref().unwrap_or("<unauthenticated>"),
            rendezvous_key = ?req.rendezvous_key,
            message_bytes = req.message.len(),
            "signaling offer: deposit"
        );

        // `Stored` and `Duplicate` are both `ok` on the wire — a retry is
        // idempotent by §1.1 pin 2, so there is nothing here for a peer to
        // branch on.
        match self.core.offer(req.rendezvous_key, &req.message, now_ms) {
            Ok(_) => match offer_result() {
                Ok(e) => HandlerResult::ok(e),
                Err(e) => internal(&e.to_string()),
            },
            Err(e) => core_error(e),
        }
    }

    // -----------------------------------------------------------------------
    // collect (§1, §1.1 pin 1)
    // -----------------------------------------------------------------------

    fn handle_collect(&self, ctx: &HandlerContext, now_ms: i64) -> HandlerResult {
        let req = match CollectRequest::from_params(&ctx.params.data) {
            Ok(r) => r,
            Err(e) => return error(STATUS_BAD_REQUEST, CODE_INVALID_PARAMS, &e.to_string()),
        };

        // Non-destructive: an unknown key is an empty list and a 200, never a
        // 404. A peer polling ahead of its counterpart is the normal case, and
        // "not there yet" must not look like an error it should give up on.
        let result = CollectResult {
            messages: self.core.collect(&req.rendezvous_key, now_ms),
        };

        // The node is the ONLY vantage point that sees both halves of a
        // rendezvous.
        //
        // Each peer can log the key it derived, but neither can see the
        // other's, so from a peer "my counterpart never showed up" and "we are
        // looking in two different buckets" are the same observation:
        // `included_count=0`. Here they are trivially distinguishable — the
        // offer line and the collect line either carry the same
        // `rendezvous_key` or they do not.
        //
        // `entity-browser-rust`'s two-browser rig spent a container harness and
        // a four-way encoding proof-table on a question these two lines answer
        // directly, and asked for exactly this. `debug!` because a busy node
        // polls at interval — enable with
        // `RUST_LOG=entity_signaling=debug`.
        tracing::debug!(
            caller = ctx.session_peer_id.as_deref().unwrap_or("<unauthenticated>"),
            rendezvous_key = ?req.rendezvous_key,
            included_count = result.messages.len(),
            "signaling collect"
        );
        match result.to_entity() {
            Ok(e) => HandlerResult::ok(e),
            Err(e) => internal(&e.to_string()),
        }
    }

    // -----------------------------------------------------------------------
    // advertise (§1)
    // -----------------------------------------------------------------------

    fn handle_advertise(&self) -> HandlerResult {
        match advertisement_to_entity(&self.core.advertise()) {
            Ok(e) => HandlerResult::ok(e),
            Err(e) => internal(&e.to_string()),
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for SignalingHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        let now = now_ms();
        Ok(match ctx.operation.as_str() {
            OP_OFFER => self.handle_offer(ctx, now),
            OP_COLLECT => self.handle_collect(ctx, now),
            OP_ADVERTISE => self.handle_advertise(),
            other => error(
                STATUS_BAD_REQUEST,
                CODE_UNKNOWN_OPERATION,
                &format!("unknown signaling operation: {}", other),
            ),
        })
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "signaling"
    }

    fn operations(&self) -> &[&str] {
        OPERATIONS
    }

    /// An **empty** internal scope — the tightest correct answer, not an
    /// omission. The node writes no entities, reads no tree, and dispatches to
    /// no other handler; its entire state is the in-memory bucket map (§1.3). A
    /// handler that needs no self-authorization should not hold the default
    /// wildcard grant, and saying so here is what keeps the "introduces, never
    /// carries" claim (§0) auditable rather than merely asserted.
    fn internal_scope(&self) -> Option<Vec<entity_capability::GrantEntry>> {
        Some(Vec::new())
    }
}

// ---------------------------------------------------------------------------
// Result helpers
// ---------------------------------------------------------------------------

fn make_error_entity(code: &str, message: &str) -> Entity {
    let data = to_ecf(&Value::Map(vec![
        (text("code"), text(code)),
        (text("message"), text(message)),
    ]));
    Entity::new(entity_types::TYPE_ERROR, data).expect("error entity")
}

fn error(status: u32, code: &str, message: &str) -> HandlerResult {
    HandlerResult::error(status, make_error_entity(code, message))
}

fn internal(message: &str) -> HandlerResult {
    error(
        entity_handler::STATUS_INTERNAL_ERROR,
        "encode_failed",
        message,
    )
}

/// Map a core refusal onto the wire.
///
/// Both capacity refusals are **429**, not a storage status. On this node rate
/// limits are the whole admission story (§2.1), and a full bucket is the same
/// message to a peer as a throttle: back off and retry. Every one of these is a
/// refusal before any state change, so retrying is safe — which is the property
/// §1.1 optimizes for throughout.
fn core_error(e: CoreError) -> HandlerResult {
    let (status, code) = match e {
        CoreError::InvalidKeyLength { .. } => (STATUS_BAD_REQUEST, CODE_INVALID_PARAMS),
        CoreError::MessageTooLarge { .. } => (STATUS_BAD_REQUEST, CODE_MESSAGE_TOO_LARGE),
        CoreError::BucketFull { .. } => (STATUS_RATE_LIMITED, CODE_BUCKET_FULL),
        CoreError::CapacityExhausted { .. } => (STATUS_RATE_LIMITED, CODE_CAPACITY_EXHAUSTED),
    };
    error(status, code, &e.to_string())
}

fn now_ms() -> i64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
