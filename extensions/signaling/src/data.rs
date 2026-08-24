//! Entity codecs for the **wrapped** surface (`PROPOSAL-CONNECTION-NODE` §2).
//!
//! Everything here is the entity wrapper and nothing else — the translation
//! between an EXECUTE's params/result entities and the plain values
//! [`crate::core`] deals in. The core has no idea this module exists, which is
//! the §2.1 property: adding the unwrapped front end later means writing a
//! second module beside this one, never touching the verbs.
//!
//! Wire notes that bite cross-impl (`AGENTS.md`):
//! - `rendezvous_key` is a **CBOR `bstr`**, always 33 bytes. It is *not* a
//!   `system/hash` field being reused — to the node it is opaque bytes with no
//!   format byte to interpret — but it is byte-identical to the 33-byte
//!   `algorithm || digest` form the peer derives, so a client may pass its
//!   derived hash bytes straight through.
//! - `limits` is a **bare CBOR map**, not an entity wrapper: it is a field typed
//!   as a specific struct, not as `core/entity`.
//! - Absent optional fields are absent, never null.

use entity_ecf::{array, bool_val, bytes, integer, text, to_ecf, Value};
use entity_entity::Entity;

use crate::core::{Advertisement, Limits, RendezvousKey};
use crate::SignalingError;

// ---------------------------------------------------------------------------
// Entity types (§1 verb surface)
// ---------------------------------------------------------------------------
//
// There is no reflection type: `reflect` is the unwrapped listener's verb
// (§1.4) and the unwrapped surface carries no entities at all, so the shape it
// returns will be pinned by §5.1's plain protocol, not by an entity codec here.

/// `offer` params.
pub const TYPE_OFFER_REQUEST: &str = "system/signaling/offer-request";
/// `offer` result.
pub const TYPE_OFFER_RESULT: &str = "system/signaling/offer-result";
/// `collect` params.
pub const TYPE_COLLECT_REQUEST: &str = "system/signaling/collect-request";
/// `collect` result.
pub const TYPE_COLLECT_RESULT: &str = "system/signaling/collect-result";
/// `advertise` result (§4.5). The name follows §3.7's
/// `{handler-path}/{op-name}-result` rule — `advertise-result`, not
/// `advertisement`, which named the concept rather than the operation.
pub const TYPE_ADVERTISE_RESULT: &str = "system/signaling/advertise-result";

// ---------------------------------------------------------------------------
// offer
// ---------------------------------------------------------------------------

/// `offer(rendezvous_key, message)` params (§1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferRequest {
    /// 33 opaque bytes the peer derived (§2.2). Length-checked on decode so a
    /// wrong-width key fails loudly at the edge rather than inside the core.
    pub rendezvous_key: RendezvousKey,
    /// The opaque blob to deposit. The node never decodes it — it is candidate
    /// material between two peers and is none of the introducer's business.
    pub message: Vec<u8>,
}

impl OfferRequest {
    pub fn from_params(data: &[u8]) -> Result<Self, SignalingError> {
        let map = decode_map(data)?;
        Ok(Self {
            rendezvous_key: RendezvousKey::from_slice(&field_bytes(&map, "rendezvous_key")?)
                .map_err(|e| SignalingError::Decode(e.to_string()))?,
            message: field_bytes(&map, "message")?,
        })
    }

    pub fn to_entity(&self) -> Result<Entity, SignalingError> {
        let data = to_ecf(&Value::Map(vec![
            (text("message"), bytes(self.message.clone())),
            (
                text("rendezvous_key"),
                bytes(self.rendezvous_key.as_bytes().to_vec()),
            ),
        ]));
        Entity::new(TYPE_OFFER_REQUEST, data).map_err(|e| SignalingError::Encode(e.to_string()))
    }
}

/// `offer` result — `{ ok }` (§1).
///
/// A duplicate offer is `ok: true`, not a distinct wire status: §1.1 pin 2 makes
/// a retry idempotent, so from the peer's side "your message is at the key" is
/// the only fact that matters, and reporting duplicate-vs-stored would invite a
/// client to branch on something that carries no meaning for it.
pub fn offer_result() -> Result<Entity, SignalingError> {
    let data = to_ecf(&Value::Map(vec![(text("ok"), bool_val(true))]));
    Entity::new(TYPE_OFFER_RESULT, data).map_err(|e| SignalingError::Encode(e.to_string()))
}

// ---------------------------------------------------------------------------
// collect
// ---------------------------------------------------------------------------

/// `collect(rendezvous_key)` params (§1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectRequest {
    pub rendezvous_key: RendezvousKey,
}

impl CollectRequest {
    pub fn from_params(data: &[u8]) -> Result<Self, SignalingError> {
        let map = decode_map(data)?;
        Ok(Self {
            rendezvous_key: RendezvousKey::from_slice(&field_bytes(&map, "rendezvous_key")?)
                .map_err(|e| SignalingError::Decode(e.to_string()))?,
        })
    }

    pub fn to_entity(&self) -> Result<Entity, SignalingError> {
        let data = to_ecf(&Value::Map(vec![(
            text("rendezvous_key"),
            bytes(self.rendezvous_key.as_bytes().to_vec()),
        )]));
        Entity::new(TYPE_COLLECT_REQUEST, data).map_err(|e| SignalingError::Encode(e.to_string()))
    }
}

/// `collect` result — `{ messages: [<blob>, ...] }` (§1).
///
/// **The blobs themselves, as a list of `bstr` — pinned** (ruling 1,
/// 2026-07-28). An earlier §1 draft read `[<hash>, ...]`; that was residue from
/// a content-addressed sketch and cannot be implemented as written. A hash reply
/// needs a fetch surface the node structurally does not have (§1.3 pins the
/// state silhouette at TTL-reaped buckets with no bulk storage), and an
/// unwrapped client holds no entity machinery to resolve one (§5.1). It would
/// also make `collect` completable on the wrapped surface and not the unwrapped
/// one — precisely the divergence §2.1 says cannot exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectResult {
    pub messages: Vec<Vec<u8>>,
}

impl CollectResult {
    pub fn from_params(data: &[u8]) -> Result<Self, SignalingError> {
        let map = decode_map(data)?;
        let items = get_field(&map, "messages")
            .and_then(|v| v.as_array())
            .ok_or_else(|| SignalingError::Decode("missing/invalid array field messages".into()))?;
        let mut messages = Vec::with_capacity(items.len());
        for item in items {
            messages.push(
                item.as_bytes()
                    .ok_or_else(|| SignalingError::Decode("messages entry is not a bstr".into()))?
                    .to_vec(),
            );
        }
        Ok(Self { messages })
    }

    pub fn to_entity(&self) -> Result<Entity, SignalingError> {
        let items: Vec<Value> = self.messages.iter().map(|m| bytes(m.clone())).collect();
        let data = to_ecf(&Value::Map(vec![(text("messages"), array(items))]));
        Entity::new(TYPE_COLLECT_RESULT, data).map_err(|e| SignalingError::Encode(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// advertise
// ---------------------------------------------------------------------------

/// Encode an [`Advertisement`]. `limits` is a **bare map** — a field typed as a
/// specific struct, not as `core/entity`, so it gets no entity wrapper.
pub fn advertisement_to_entity(a: &Advertisement) -> Result<Entity, SignalingError> {
    let mut limits = vec![
        (
            text("max_blob_bytes"),
            integer(a.limits.max_blob_bytes as i64),
        ),
        (
            text("max_bucket_blobs"),
            integer(a.limits.max_bucket_blobs as i64),
        ),
        (text("ttl_seconds"), integer(a.limits.ttl_seconds as i64)),
    ];
    // Absent, never null: a node that does not override the default emits no
    // `lobby_constant` key at all, and a peer that sees none derives from
    // `LOBBY_DEFAULT`. ECF sorts keys, so insertion order is for readability.
    //
    // **Bytes, not text** — §4.5 types it `primitive/bytes` because it is a
    // derivation input (§3.1 hashes it verbatim), not a label to display.
    if let Some(lobby) = a.limits.lobby_constant.as_deref() {
        limits.push((text("lobby_constant"), bytes(lobby.as_bytes().to_vec())));
    }
    // `max_keys` is deliberately absent — a node-internal backstop, not one of
    // §4.5's four published limits (see `Limits::max_keys`).
    let fields = vec![
        (text("endpoint"), text(&a.endpoint)),
        (text("limits"), Value::Map(limits)),
    ];
    let data = to_ecf(&Value::Map(fields));
    Entity::new(TYPE_ADVERTISE_RESULT, data).map_err(|e| SignalingError::Encode(e.to_string()))
}

/// Decode an advertisement (client side / registry pool membership).
pub fn advertisement_from_params(data: &[u8]) -> Result<Advertisement, SignalingError> {
    let map = decode_map(data)?;
    let limits_map = get_field(&map, "limits")
        .and_then(|v| v.as_map())
        .ok_or_else(|| SignalingError::Decode("missing/invalid map field limits".into()))?;
    Ok(Advertisement {
        endpoint: field_text(&map, "endpoint")?,
        limits: Limits {
            max_blob_bytes: field_i64(limits_map, "max_blob_bytes")? as u64,
            max_bucket_blobs: field_i64(limits_map, "max_bucket_blobs")? as u64,
            ttl_seconds: field_i64(limits_map, "ttl_seconds")? as u64,
            // Absent → no override. A `lobby_constant` present but equal to the
            // default is normalized away so the decoded value compares equal to
            // a node that never set one. Non-UTF-8 bytes decode to `None`
            // rather than erroring: it is an override this peer cannot derive
            // with, and MUST-ignore says skip the field, not the message.
            lobby_constant: get_field(limits_map, "lobby_constant")
                .and_then(|v| v.as_bytes())
                .and_then(|b| std::str::from_utf8(b).ok())
                .filter(|s| *s != crate::core::LOBBY_DEFAULT)
                .map(|s| s.to_string()),
            // Never published (§4.5 has four fields); a decoding client has no
            // node keyspace of its own, so the default stands in.
            max_keys: Limits::default().max_keys,
        },
    })
}

// ---------------------------------------------------------------------------
// CBOR helpers (shape mirrors extensions/route/src/lib.rs)
// ---------------------------------------------------------------------------

fn decode_map(data: &[u8]) -> Result<Vec<(Value, Value)>, SignalingError> {
    let value: Value =
        ciborium::from_reader(data).map_err(|e| SignalingError::Decode(e.to_string()))?;
    value
        .into_map()
        .map_err(|_| SignalingError::Decode("expected CBOR map".into()))
}

fn get_field<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter().find_map(|(k, v)| {
        if k.as_text() == Some(key) {
            Some(v)
        } else {
            None
        }
    })
}

fn field_text(map: &[(Value, Value)], key: &str) -> Result<String, SignalingError> {
    get_field(map, key)
        .and_then(|v| v.as_text())
        .map(|s| s.to_string())
        .ok_or_else(|| SignalingError::Decode(format!("missing/invalid text field {}", key)))
}

fn field_bytes(map: &[(Value, Value)], key: &str) -> Result<Vec<u8>, SignalingError> {
    get_field(map, key)
        .and_then(|v| v.as_bytes())
        .map(|b| b.to_vec())
        .ok_or_else(|| SignalingError::Decode(format!("missing/invalid bstr field {}", key)))
}

fn field_i64(map: &[(Value, Value)], key: &str) -> Result<i64, SignalingError> {
    get_field(map, key)
        .and_then(|v| v.as_integer())
        .and_then(|i| i64::try_from(i).ok())
        .ok_or_else(|| SignalingError::Decode(format!("missing/invalid integer field {}", key)))
}
