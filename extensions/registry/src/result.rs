//! Shared handler result + error entity builders.

use std::collections::HashMap;

use entity_ecf::{text, to_ecf, Value};
use entity_entity::Entity;
use entity_handler::HandlerResult;
use entity_hash::Hash;

pub(crate) fn make_error_entity(code: &str, message: &str) -> Entity {
    let data = to_ecf(&Value::Map(vec![
        (text("code"), text(code)),
        (text("message"), text(message)),
    ]));
    Entity::new(entity_types::TYPE_ERROR, data).expect("error entity")
}

pub(crate) fn error(status: u32, code: &str, message: &str) -> HandlerResult {
    HandlerResult::error(status, make_error_entity(code, message))
}

/// Build a `system/protocol/status` result entity from CBOR map fields.
pub(crate) fn status_result(fields: Vec<(Value, Value)>) -> HandlerResult {
    status_result_with(entity_handler::STATUS_OK, fields)
}

/// [`status_result`] at an explicit non-200 success status.
pub(crate) fn status_result_with(status: u32, fields: Vec<(Value, Value)>) -> HandlerResult {
    let result = Entity::new(
        entity_types::TYPE_PROTOCOL_STATUS,
        to_ecf(&Value::Map(fields)),
    )
    .expect("status entity");
    HandlerResult {
        status,
        result,
        included: HashMap::new(),
    }
}

/// `register-request`'s own result entity — REGISTRY §6a.9 `[RULED 2026-08-12]`.
///
/// One type for both branches, with `status` discriminating: `bound` carries
/// `binding_hash`, `pending_review` carries `pending_hash`. The ruling rejects
/// `system/protocol/status` (what this handler previously returned) **on
/// structure** — a carrier with room for neither hash pushes the payload
/// somewhere else and re-opens the divergence one field down — and forbids
/// borrowing another operation's result type on payload coincidence.
pub(crate) fn register_result(status: u32, fields: Vec<(Value, Value)>) -> HandlerResult {
    let result = Entity::new(
        entity_types::TYPE_REGISTRY_REGISTER_RESULT,
        to_ecf(&Value::Map(fields)),
    )
    .expect("register-result entity");
    HandlerResult {
        status,
        result,
        included: HashMap::new(),
    }
}

/// Return an entity verbatim as the 200 result. Used where the spec makes
/// the response *the stored entity* (REGISTRY §6a.9.2's two policy ops),
/// so the caller reads back the same bytes that were written — no
/// decode-and-re-encode, which would author a second entity with a
/// different `content_hash`.
pub(crate) fn entity_result(result: Entity) -> HandlerResult {
    HandlerResult {
        status: entity_handler::STATUS_OK,
        result,
        included: HashMap::new(),
    }
}

/// `{ <key>: <bare hash> }` result (e.g. `binding_hash`).
pub(crate) fn hash_result(key: &str, hash: Hash) -> HandlerResult {
    status_result(vec![(text(key), Value::Bytes(hash.to_bytes().to_vec()))])
}
