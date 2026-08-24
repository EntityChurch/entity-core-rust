//! Subscription-side chain-error marker emission per EXTENSION-SUBSCRIPTION §4.7.
//!
//! Mirrors the EXTENSION-CONTINUATION §3.10 `write_lost_error_marker` pattern.
//! Helpers (sanitize_reason_segment, peer_id_from_uri, classify_transport_failure)
//! are duplicated rather than imported because cross-extension deps beyond the
//! substrate-style three (quorum→attestation, role→attestation,
//! identity→attestation+quorum) are forbidden per CLAUDE.md. If the pattern
//! recurs in extensions/inbox or extensions/revision implementations, lift to
//! a shared core crate.

use std::sync::Arc;

use entity_entity::Entity;
use entity_hash::Hash;
use entity_store::{ContentStore, ExecutionContext, LocationIndex};

/// Reason codes for limit-suppression cases (§4.6).
pub(crate) const REASON_MAX_EVENTS_REACHED: &str = "max_events_reached";
pub(crate) const REASON_MAX_DURATION_REACHED: &str = "max_duration_reached";
pub(crate) const REASON_RATE_LIMITED: &str = "rate_limited";

/// Reason codes for capability-state failures at delivery-eligibility check.
pub(crate) const REASON_CAPABILITY_DENIED: &str = "capability_denied";

/// V7 §6.12 transport codes for terminal delivery failures.
const REASON_RECV_TIMEOUT: &str = "recv_timeout";
const REASON_CONNECTION_BROKEN: &str = "connection_broken";
const REASON_PROTOCOL_ERROR: &str = "protocol_error";

/// Path-safety sanitizer for the `{reason}` coordinate per EXTENSION-CONTINUATION
/// §3.10.5 (V7 §1.4 path-segment rules).
///
/// §3.10.5 prescribes sentinel-substitution here (raw code preserved in the
/// body's `code` field). Delegates to the shared `entity_entity::sanitize_path_segment`
/// so all three coordinates run the ONE function (arch round-2 ruling 1) — the
/// continuation twin already converged here; this was the straggler. The prior
/// hand-rolled copy additionally rejected spaces, which §1.4 explicitly permits
/// ("All other UTF-8 characters are valid in path segments") and which the
/// continuation twin passes through — a quiet de-convergence, now closed.
pub(crate) fn sanitize_reason_segment(reason: &str) -> String {
    entity_entity::sanitize_path_segment(reason, entity_entity::SENTINEL_UNSPECIFIED_ERROR)
        .to_string()
}

/// W6 attribution for a §4.7 marker bind (marker-proposal option (ii) / round-1
/// ruling 18, now MUST).
///
/// The bind is a **substrate** write: a `SyncTreeHook` / delivery worker holds
/// no chain capability and cannot 403, so F2's substrate-authority ruling
/// removed the cap's accidental containment. The subscription component's own
/// grant (`system/subscription`) authorizes the write, and the triggering
/// caller's cap rides along as `caller_capability`, noted-not-authorizing —
/// the **only** record of who caused a substrate-authorized write. Mirrors the
/// continuation twin's `write_lost_error_marker` bind context.
pub(crate) struct MarkerAttribution {
    /// Identity that initiated the request chain (preserved cascade field).
    pub author: Option<Hash>,
    /// The triggering caller's capability — noted, not authorizing.
    pub caller_capability: Option<Hash>,
    /// Correlation ID from the originating EXECUTE.
    pub request_id: Option<String>,
    /// Where the marker was bound: `"notify"` for the synchronous limit/token
    /// sites inside `on_tree_change`, `"deliver"` for the async delivery worker.
    pub operation: &'static str,
}

/// Best-effort extract the target peer ID from an absolute URI of the form
/// `entity://{peer_id}/...` or `/{peer_id}/...`.
pub(crate) fn peer_id_from_uri(uri: &str) -> Option<String> {
    if let Some(rest) = uri.strip_prefix("entity://") {
        if let Some(slash) = rest.find('/') {
            return Some(rest[..slash].to_string());
        }
        return Some(rest.to_string());
    }
    if let Some(rest) = uri.strip_prefix('/') {
        if let Some(slash) = rest.find('/') {
            return Some(rest[..slash].to_string());
        }
        return Some(rest.to_string());
    }
    None
}

/// Classify a delivery-side `HandlerError::Internal`-shaped failure into a
/// V7 §6.12 transport code. Mirrors `extensions/continuation::classify_transport_failure`
/// — pattern strings track the same message shapes used by `send_execute`.
pub(crate) fn classify_transport_failure(err_text: &str) -> &'static str {
    let lower = err_text.to_lowercase();
    if lower.contains("timed out") || lower.contains("timeout") {
        REASON_RECV_TIMEOUT
    } else if lower.contains("reader task terminated")
        || lower.contains("connection")
        || lower.contains("broken pipe")
        || lower.contains("eof")
    {
        REASON_CONNECTION_BROKEN
    } else {
        // Decode/parse/malformed plus unknown shapes both surface as
        // protocol_error per V7 §6.12 ("consumer has no other code to record"
        // fallback), matching the continuation classifier's posture.
        REASON_PROTOCOL_ERROR
    }
}

/// Capture failure-origination timestamp in Unix milliseconds.
/// Same discipline as EXTENSION-CONTINUATION v1.20 §3.10.6 — caller stamps
/// at failure-origination, not at marker-bind time, so retries of the same
/// logical event dedupe to the same content hash.
pub(crate) fn capture_failure_timestamp_ms() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Bind a `lost`-variant chain-error marker for a subscription delivery
/// failure per EXTENSION-SUBSCRIPTION §4.7.
///
/// Path scheme:
/// `/{local_peer_id}/system/runtime/chain-errors/lost/{chain_id}/{subscription_id}/{reason}/{marker_hash}`
///
/// `{step_index}` is `{subscription_id}` per §4.7 — the trigger is a tree
/// change rather than a chained EXECUTE, so no original-request-id is
/// available. `{chain_id}` is inherited from the source change's chain
/// causality per §4.5; when context propagation fails (empty `chain_id`),
/// we fall back to `subscription_id` so the marker still binds at a
/// well-formed path rather than `lost//{...}`.
///
/// Per §4.7: marker is informational — MUST NOT trigger advancement,
/// retry, or any reactive behavior beyond surfacing the failure for
/// inspect tooling and `validate-peer`'s `CAT-CHAIN-COMPLETION` check.
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_lost_error_marker(
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
    local_peer_id: &str,
    chain_id: &str,
    subscription_id: &str,
    deliver_uri: &str,
    reason: &str,
    status: u32,
    timestamp_ms: u64,
    attribution: &MarkerAttribution,
) {
    let safe_reason = sanitize_reason_segment(reason);
    let chain_id_original = if chain_id.is_empty() {
        subscription_id
    } else {
        chain_id
    };
    // `chain_id` rides in from `bounds`, and a subscription_id can be
    // caller-chosen — neither may name a path segment unvetted (§1.4 /
    // round-2 ruling 1). Sanitized once, ahead of the body, so a marker's
    // recorded coordinate always matches where it is actually bound. This site
    // is NOT reachable by Go's probe (it needs subscription setup) — Go had the
    // same defect at all three of its binding sites, so all three of ours are
    // done.
    //
    // Path gets the sanitized form; body keeps the original (round-2 ruling 2).
    let chain_id_segment = entity_entity::sanitize_path_segment(
        chain_id_original,
        entity_entity::SENTINEL_UNSPECIFIED_CHAIN_ID,
    );
    let step_index_segment = entity_entity::sanitize_path_segment(
        subscription_id,
        entity_entity::SENTINEL_UNSPECIFIED_STEP_INDEX,
    );
    let target_peer_id = peer_id_from_uri(deliver_uri).unwrap_or_default();

    let body_fields = vec![
        (
            entity_ecf::text("chain_id"),
            entity_ecf::text(chain_id_original),
        ),
        (entity_ecf::text("code"), entity_ecf::text(reason)),
        (entity_ecf::text("reason"), entity_ecf::text(&safe_reason)),
        (
            entity_ecf::text("status"),
            entity_ecf::integer(status as i64),
        ),
        (
            entity_ecf::text("step_index"),
            entity_ecf::text(subscription_id),
        ),
        (
            entity_ecf::text("target_peer_id"),
            entity_ecf::text(&target_peer_id),
        ),
        (
            entity_ecf::text("target_uri"),
            entity_ecf::text(deliver_uri),
        ),
        (
            entity_ecf::text("timestamp"),
            entity_ecf::integer(timestamp_ms as i64),
        ),
    ];
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(body_fields));
    let entity = match Entity::new("system/runtime/chain-error-lost", data) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(
                subscription_id = %subscription_id,
                reason = %safe_reason,
                error = %e,
                "subscription §4.7: lost-error marker entity build FAILED"
            );
            return;
        }
    };
    let marker_path = format!(
        "/{}/system/runtime/chain-errors/lost/{}/{}/{}/{}",
        local_peer_id,
        chain_id_segment,
        step_index_segment,
        safe_reason,
        entity.content_hash.to_hex(),
    );
    match content_store.put(entity) {
        Ok(h) => {
            // W6 attribution (ruling 18 — MUST). The subscription component's
            // own grant authorizes this substrate write; the triggering
            // caller's cap is NOTED as `caller_capability`. `set_with_context`
            // carries the split on the emit pathway so attribution-persisting
            // consumers (history's W6 rule) record who caused it — the binding
            // itself is byte-identical to a plain `set`. A `None` grant (the
            // grant not yet bootstrapped, or a foreign build) degrades to the
            // pre-W6 unattributed bind, exactly as the continuation twin.
            let component_grant = resolve_component_grant(location_index, local_peer_id);
            let bind_ctx = ExecutionContext {
                chain_id: Some(chain_id_original.to_string()),
                author: attribution.author,
                caller_capability: attribution.caller_capability,
                request_id: attribution.request_id.clone(),
                capability: component_grant,
                handler_grant: component_grant,
                handler_pattern: Some("system/subscription".to_string()),
                operation: Some(attribution.operation.to_string()),
                ..Default::default()
            };
            location_index.set_with_context(&marker_path, h, bind_ctx);
        }
        Err(e) => {
            tracing::warn!(
                path = %marker_path,
                error = %e,
                "subscription §4.7: lost-error marker bind FAILED"
            );
        }
    }
}

/// Resolve the subscription component's self-issued handler grant, bound at
/// `/{peer}/system/capability/grants/system/subscription` by §6.9 step 6
/// (`create_handler_grant`). This is the authority the marker write rides —
/// substrate authority, not a chain cap. Looked up at bind time (an exceptional
/// failure path, not a hot path) so it is robust to bootstrap ordering: the
/// engine is constructed before the grant is minted, but every marker bind
/// happens long after. `None` when the grant is absent.
fn resolve_component_grant(
    location_index: &Arc<dyn LocationIndex>,
    local_peer_id: &str,
) -> Option<Hash> {
    location_index.get(&format!(
        "/{}/system/capability/grants/system/subscription",
        local_peer_id
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use entity_store::{
        CascadeHalt, MemoryContentStore, MemoryLocationIndex, NotifyingLocationIndex, SyncTreeHook,
        TreeChangeEvent,
    };

    /// §4.7 marker bind carries the W6 attribution split (ruling 18 — MUST).
    /// The emit-pathway `ExecutionContext` MUST record `capability`/`handler_grant`
    /// = the subscription component's own grant (what AUTHORIZED the substrate
    /// write) and `caller_capability` = the triggering caller's cap (NOTED, never
    /// authorizing) — the only record of who caused the write. Observed via a
    /// capture hook on the notifying index, the same surface history's W6 rule
    /// persists from. Mirrors the continuation twin's
    /// `w6_marker_bind_carries_attribution_split`.
    #[test]
    fn w6_marker_bind_carries_attribution_split() {
        struct Capture {
            seen: std::sync::Mutex<Vec<(String, ExecutionContext)>>,
        }
        impl SyncTreeHook for Capture {
            fn on_tree_change(
                &self,
                event: &TreeChangeEvent,
                _ctx: &mut ExecutionContext,
            ) -> Result<(), CascadeHalt> {
                if let Some(c) = &event.context {
                    self.seen
                        .lock()
                        .unwrap()
                        .push((event.path.clone(), c.clone()));
                }
                Ok(())
            }
            fn name(&self) -> &str {
                "test/w6-capture"
            }
            fn handler_pattern(&self) -> &str {
                "test"
            }
        }

        let capture = Arc::new(Capture {
            seen: std::sync::Mutex::new(Vec::new()),
        });
        let notifying = Arc::new(NotifyingLocationIndex::new(
            Arc::new(MemoryLocationIndex::new()),
            Arc::new(|_evt| {}),
        ));
        notifying.register_hook(capture.clone());

        // NotifyingLocationIndex validates the first segment as a peer id
        // (§5.4), so use a well-formed 46-char Base58 id.
        let peer = "1".repeat(46);

        // Bind the subscription component's self-grant so `resolve_component_grant`
        // finds it — §6.9 step 6 mints this in a real peer.
        let component_grant = Hash::compute("test", b"w6-subscription-grant");
        notifying.set(
            &format!("/{peer}/system/capability/grants/system/subscription"),
            component_grant,
        );

        let content_store: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let location_index: Arc<dyn LocationIndex> = notifying;

        let caller_cap = Hash::compute("test", b"w6-caller-cap");
        let author = Hash::compute("test", b"w6-author");
        write_lost_error_marker(
            &content_store,
            &location_index,
            &peer,
            "chain-w6",
            "sub-w6",
            "entity://target-peer/user/inbox",
            "recv_timeout",
            0,
            7u64,
            &MarkerAttribution {
                author: Some(author),
                caller_capability: Some(caller_cap),
                request_id: Some("req-w6".to_string()),
                operation: "deliver",
            },
        );

        let seen = capture.seen.lock().unwrap();
        let (path, bind_ctx) = seen
            .iter()
            .find(|(p, _)| p.contains("/system/runtime/chain-errors/lost/chain-w6/sub-w6/"))
            .expect("marker bind fired the emit pathway with a context");
        assert!(path.contains("/recv_timeout/"), "reason segment");
        assert_eq!(
            bind_ctx.capability,
            Some(component_grant),
            "W6: the AUTHORIZING cap is the subscription component's own grant"
        );
        assert_eq!(
            bind_ctx.handler_grant,
            Some(component_grant),
            "W6: handler_grant attribution present"
        );
        assert_eq!(
            bind_ctx.caller_capability,
            Some(caller_cap),
            "W6: the triggering caller's cap is NOTED as caller_capability"
        );
        assert_eq!(bind_ctx.author, Some(author));
        assert_eq!(bind_ctx.chain_id.as_deref(), Some("chain-w6"));
        assert_eq!(bind_ctx.request_id.as_deref(), Some("req-w6"));
        assert_eq!(
            bind_ctx.handler_pattern.as_deref(),
            Some("system/subscription")
        );
        assert_eq!(bind_ctx.operation.as_deref(), Some("deliver"));
    }

    /// A `None` component grant degrades to the pre-W6 unattributed bind rather
    /// than dropping the marker — the write still lands so the failure remains
    /// observable even before the grant is bootstrapped.
    #[test]
    fn w6_absent_grant_degrades_to_unattributed_bind() {
        let content_store: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let location_index: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        // No grant bound at the canonical path.
        write_lost_error_marker(
            &content_store,
            &location_index,
            "peerx",
            "chain-x",
            "sub-x",
            "entity://t/u",
            "recv_timeout",
            0,
            1u64,
            &MarkerAttribution {
                author: None,
                caller_capability: None,
                request_id: None,
                operation: "notify",
            },
        );
        // The marker still bound under the reason prefix (terminal segment is
        // the marker hash), even with no authorizing grant to record.
        let bound = location_index
            .list("/peerx/system/runtime/chain-errors/lost/chain-x/sub-x/recv_timeout");
        assert_eq!(bound.len(), 1, "marker binds even when the grant is absent");
    }

    #[test]
    fn sanitize_returns_unspecified_for_unsafe_segments() {
        assert_eq!(sanitize_reason_segment("has/slash"), "unspecified_error");
        assert_eq!(sanitize_reason_segment(""), "unspecified_error");
        assert_eq!(sanitize_reason_segment("."), "unspecified_error");
        assert_eq!(sanitize_reason_segment(".."), "unspecified_error");
        // Control bytes collapse; a tab is one such.
        assert_eq!(sanitize_reason_segment("has\ttab"), "unspecified_error");
    }

    #[test]
    fn sanitize_passes_spaces_per_1_4() {
        // The prior hand-rolled copy rejected spaces; §1.4 permits them and the
        // continuation twin passes them through (arch round-2 ruling 1 — the
        // three coordinates run one function).
        assert_eq!(sanitize_reason_segment("has space"), "has space");
    }

    #[test]
    fn sanitize_passes_path_safe_strings() {
        assert_eq!(sanitize_reason_segment("rate_limited"), "rate_limited");
        assert_eq!(
            sanitize_reason_segment("max_events_reached"),
            "max_events_reached"
        );
        assert_eq!(sanitize_reason_segment("recv_timeout"), "recv_timeout");
    }

    #[test]
    fn peer_id_from_uri_handles_both_schemes() {
        assert_eq!(
            peer_id_from_uri("entity://peer123/path/to/thing"),
            Some("peer123".to_string())
        );
        assert_eq!(
            peer_id_from_uri("/peer123/path/to/thing"),
            Some("peer123".to_string())
        );
        assert_eq!(peer_id_from_uri("relative/path"), None);
    }

    #[test]
    fn classify_transport_failure_maps_known_strings() {
        assert_eq!(
            classify_transport_failure("request timed out"),
            "recv_timeout"
        );
        assert_eq!(
            classify_transport_failure("connection reset by peer"),
            "connection_broken"
        );
        assert_eq!(
            classify_transport_failure("decode error: malformed CBOR"),
            "protocol_error"
        );
        assert_eq!(
            classify_transport_failure("totally unknown"),
            "protocol_error"
        );
    }
}
