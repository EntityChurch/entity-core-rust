//! `system/identity:create_quorum` — creates a `system/quorum` entity at the
//! caller-supplied canonical path, per EXTENSION-IDENTITY §6.

use entity_handler::{HandlerContext, HandlerError, HandlerResult, STATUS_BAD_REQUEST};
use entity_quorum::{path_quorum, QuorumData};

use crate::data::{decode_map, field_hash_array, field_map_opt, field_string_opt, field_u64};
use crate::handler::{create_quorum_result, error, IdentityHandler};

impl IdentityHandler {
    pub(crate) async fn handle_create_quorum(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        // R-3 (cross-impl spec) / V7 §3.2 + EXTENSION-IDENTITY
        // §6: path-as-resource is MUST for all 7 identity ops. Strict
        // enforcement; no canonical-path fallback. Caller supplies the
        // canonical quorum path, e.g. `system/quorum/{quorum_id_hex}` after
        // computing the quorum_id locally.
        //
        // **`0.8.2.17` names this operation as an example of the opposite, and
        // we are deliberately not following it.** Retracting `path_required`
        // from dispatch, §3.3's 400 row says *"which operations require one is
        // stated by each operation's own specification"* and then offers
        // *"operations for which no resource is legitimate (`configure`,
        // `create_quorum`) simply do not carry the requirement."* Both named ops
        // are EXTENSION-IDENTITY's, and EXTENSION-IDENTITY §6's resource-target
        // table gives `create_quorum` → `system/quorum/{q_hex}` and `configure`
        // → `system/identity/peer-config`, under *"All ops follow path-as-
        // resource per ENTITY-CORE-PROTOCOL.md §3.2 (architectural-side MUST)."*
        //
        // The normative sentence and the parenthetical disagree, so we follow
        // the normative sentence: it points at the operation's own
        // specification, and the operation's own specification requires a
        // resource. The parenthetical is an illustration that names two
        // operations it does not own. Routed rather than silently resolved —
        // if arch rules for the parenthetical, this arm and `configure`'s in
        // `handler.rs` come out together, and `EXTENSION-IDENTITY` §6's table
        // and §1380's MUST have to move with them.
        let resource_path = match self.resource_path(ctx) {
            Some(p) => p,
            None => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "path_required",
                    "system/identity:create_quorum requires a resource target per V7 §3.2",
                ))
            }
        };
        let map = match decode_map(&ctx.params.data) {
            Ok(m) => m,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let signers = match field_hash_array(&map, "signers") {
            Ok(s) => s,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let threshold = match field_u64(&map, "threshold") {
            Ok(t) => t,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        if threshold == 0 || threshold > signers.len() as u64 {
            return Ok(error(
                STATUS_BAD_REQUEST,
                "invalid_threshold",
                "1 ≤ K ≤ |signers|",
            ));
        }
        let signer_resolution = match field_string_opt(&map, "signer_resolution") {
            Ok(v) => v,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        // R-4 (cross-impl spec): preserve `name` and
        // `metadata` from the request. Pre-R-4 Rust dropped both, causing
        // the recomputed canonical path to diverge from the caller's
        // pre-computed path → resource_target_mismatch under R-3 strict.
        // Cross-impl conformance: byte-fidelity round-trip is required.
        let name = match field_string_opt(&map, "name") {
            Ok(v) => v,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let metadata = match field_map_opt(&map, "metadata") {
            Ok(v) => v,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let q = QuorumData {
            signers,
            threshold,
            signer_resolution,
            name,
            metadata,
        };
        let entity = match q.to_entity() {
            Ok(e) => e,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "encode_failed", &e.to_string())),
        };
        let q_hash = entity.content_hash;
        if let Err(e) = self.content_store.put(entity) {
            return Ok(error(STATUS_BAD_REQUEST, "store_failed", &e.to_string()));
        }
        // R-3: caller-supplied path must match the canonical quorum path.
        // Cross-impl conformance: SDK sends canonical, handler validates.
        let canonical_path = self.qualify(&path_quorum(&q_hash));
        if resource_path != canonical_path {
            return Ok(error(
                STATUS_BAD_REQUEST,
                "resource_target_mismatch",
                &format!("expected {}, got {}", canonical_path, resource_path),
            ));
        }
        self.location_index.set(&resource_path, q_hash);
        Ok(create_quorum_result(q_hash))
    }
}
