//! `system/connection/{peer}` — the §3.13 operational connection-state
//! entity: "how am I attached right now" (transport + address
//! diagnostics), the read-on-demand complement to `system/peer/status`'s
//! subscribe-for-liveness "is the peer here".
//!
//! **Conformance tier (Amendment 12 rung-1 ruling C):** MUST at *full*
//! NETWORK conformance (§12.1), NOT part of the §A3 liveness floor — a
//! consumer of a floor-only peer MUST NOT assume this entity exists.
//!
//! **Write discipline** is §3.13's write-on-transition: `active` at
//! establishment (dialer side — the responder holds no dialable address
//! for the remote and records nothing, same as a §6.11(b) reentry
//! binding), `closed` at the demotion/eviction seams — never
//! per-activity. The `system/peer/status` entity references this one
//! via its `connection` path field (dialer-side writes only).

use entity_entity::Entity;
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};

/// Entity-type string for the §3.13 connection-state entity.
pub const TYPE_CONNECTION: &str = "system/connection";

/// The connection is established and dispatchable (§3.13 enum).
pub const CONNECTION_STATUS_ACTIVE: &str = "active";
/// Graceful shutdown in progress (§3.13 enum) — reserved; no Rust
/// write-site emits it yet.
pub const CONNECTION_STATUS_DRAINING: &str = "draining";
/// The connection is gone — closed or failed (§3.13 enum).
pub const CONNECTION_STATUS_CLOSED: &str = "closed";

/// Decoded `system/connection/{peer}` entity (§3.13).
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionData {
    /// Base58 string of the remote peer's `peer_id`.
    pub peer_id: String,
    /// Transport substrate label: "tcp", "websocket", "memory", ….
    pub transport: String,
    /// Remote endpoint address, e.g. "tcp://192.168.1.42:4040".
    pub address: String,
    /// One of the `CONNECTION_STATUS_*` lifecycle values.
    pub status: String,
    /// ms since epoch at establishment.
    pub established_at: u64,
    /// Negotiated parameters (protocol_version, hash_format, …).
    /// OPTIONAL; carried opaquely so a read-modify-write transition
    /// preserves whatever a previous writer recorded.
    pub parameters: Option<ciborium::Value>,
}

impl ConnectionData {
    /// Tree path under the local peer's root where this entity lives.
    /// Caller prefixes with `/{local_peer_id}/`. Same v7.64 §1.4
    /// positional encoding as the sibling status/session entities:
    /// lowercase hex of the remote peer's `system/peer` content_hash.
    pub fn relative_path(remote_identity_hash: &Hash) -> String {
        format!("{}/{}", TYPE_CONNECTION, remote_identity_hash.to_hex())
    }

    /// Encode to a `system/connection` `Entity`. CBOR-map data with
    /// keys in alphabetic order (ECF determinism); absent `parameters`
    /// is omitted entirely (true CBOR absence).
    pub fn to_entity(&self) -> Entity {
        let mut fields: Vec<(entity_ecf::Value, entity_ecf::Value)> = vec![
            (entity_ecf::text("address"), entity_ecf::text(&self.address)),
            (
                entity_ecf::text("established_at"),
                entity_ecf::Value::Integer(self.established_at.into()),
            ),
        ];
        if let Some(ref p) = self.parameters {
            fields.push((entity_ecf::text("parameters"), p.clone()));
        }
        fields.push((entity_ecf::text("peer_id"), entity_ecf::text(&self.peer_id)));
        fields.push((entity_ecf::text("status"), entity_ecf::text(&self.status)));
        fields.push((
            entity_ecf::text("transport"),
            entity_ecf::text(&self.transport),
        ));
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
        Entity::new(TYPE_CONNECTION, data).expect("entity construction for system/connection")
    }

    /// Decode a `system/connection` `Entity`. Unknown fields are
    /// ignored (MUST-ignore-unknowns).
    pub fn from_entity(entity: &Entity) -> Result<Self, ConnectionDecodeError> {
        if entity.entity_type != TYPE_CONNECTION {
            return Err(ConnectionDecodeError::UnexpectedType(
                entity.entity_type.clone(),
            ));
        }
        let value: ciborium::Value = ciborium::from_reader(entity.data.as_slice())
            .map_err(|e| ConnectionDecodeError::Cbor(e.to_string()))?;
        let map = match value {
            ciborium::Value::Map(m) => m,
            _ => return Err(ConnectionDecodeError::NotAMap),
        };
        let text = |key: &str| -> Option<String> {
            map.iter().find_map(|(k, v)| match (k, v) {
                (ciborium::Value::Text(t), ciborium::Value::Text(s)) if t == key => Some(s.clone()),
                _ => None,
            })
        };
        let uint = |key: &str| -> Option<u64> {
            map.iter().find_map(|(k, v)| match (k, v) {
                (ciborium::Value::Text(t), ciborium::Value::Integer(i)) if t == key => {
                    u64::try_from(*i).ok()
                }
                _ => None,
            })
        };
        Ok(Self {
            peer_id: text("peer_id").ok_or(ConnectionDecodeError::MissingField("peer_id"))?,
            transport: text("transport").ok_or(ConnectionDecodeError::MissingField("transport"))?,
            address: text("address").ok_or(ConnectionDecodeError::MissingField("address"))?,
            status: text("status").ok_or(ConnectionDecodeError::MissingField("status"))?,
            established_at: uint("established_at")
                .ok_or(ConnectionDecodeError::MissingField("established_at"))?,
            parameters: map.iter().find_map(|(k, v)| match k {
                ciborium::Value::Text(t) if t == "parameters" => Some(v.clone()),
                _ => None,
            }),
        })
    }
}

/// Errors decoding a connection-state entity.
#[derive(Debug, thiserror::Error)]
pub enum ConnectionDecodeError {
    /// Entity type didn't match `system/connection`.
    #[error("expected entity_type {TYPE_CONNECTION}, got {0}")]
    UnexpectedType(String),
    /// CBOR decode failed.
    #[error("cbor decode: {0}")]
    Cbor(String),
    /// Data root wasn't a CBOR map.
    #[error("connection-state data is not a CBOR map")]
    NotAMap,
    /// A required field was missing.
    #[error("connection-state missing required field: {0}")]
    MissingField(&'static str),
}

/// Transport label for the §3.13 `transport` field, derived from the
/// dial address's URL scheme ("tcp://host:port" → "tcp"). The scheme is
/// the honest per-connection value — endpoint `transport_type()` is a
/// coarser family label ("stream").
pub(crate) fn transport_label(addr: &str) -> &str {
    addr.split_once("://")
        .map_or("unknown", |(scheme, _)| scheme)
}

/// Write the §3.13 establish transition (`active`) for a freshly
/// dialed connection. Returns the tree path written (the value the
/// sibling `system/peer/status` write carries in its `connection`
/// field), or `None` when skipped. Same guards + soft-fail contract as
/// `liveness::write_peer_status`: no self-entry; a miss is
/// observability-only and never fails the connection.
pub(crate) fn write_connection_active(
    content_store: &dyn ContentStore,
    location_index: &dyn LocationIndex,
    local_peer_id: &str,
    remote_peer_id: &str,
    remote_identity_hash: &Hash,
    transport: &str,
    address: &str,
) -> Option<String> {
    if remote_peer_id == local_peer_id {
        return None;
    }
    let data = ConnectionData {
        peer_id: remote_peer_id.to_string(),
        transport: transport.to_string(),
        address: address.to_string(),
        status: CONNECTION_STATUS_ACTIVE.to_string(),
        established_at: crate::liveness::now_ms(),
        parameters: None,
    };
    let path = format!(
        "/{}/{}",
        local_peer_id,
        ConnectionData::relative_path(remote_identity_hash)
    );
    match content_store.put(data.to_entity()) {
        Ok(hash) => {
            location_index.set(&path, hash);
            tracing::debug!(path = %path, transport = %transport, "connection-state active write");
            Some(path)
        }
        Err(e) => {
            tracing::warn!(path = %path, error = %e, "connection-state active write failed");
            None
        }
    }
}

/// The §3.13 close/failure transition ("updated on close or failure"):
/// read-modify-write the existing connection entity to `closed`,
/// preserving transport/address/established_at (and any parameters) so
/// the closed record still answers "how WAS I attached". A missing
/// entity is a no-op — nothing was recorded at establish (e.g. a
/// §6.11(b) reentry binding whose dialer is the remote), so there is no
/// transition to record. Idempotent when already closed.
pub(crate) fn mark_connection_closed(
    content_store: &dyn ContentStore,
    location_index: &dyn LocationIndex,
    local_peer_id: &str,
    remote_identity_hash: &Hash,
) {
    let path = format!(
        "/{}/{}",
        local_peer_id,
        ConnectionData::relative_path(remote_identity_hash)
    );
    let Some(existing) = location_index
        .get(&path)
        .and_then(|h| content_store.get(&h))
        .and_then(|e| ConnectionData::from_entity(&e).ok())
    else {
        return;
    };
    if existing.status == CONNECTION_STATUS_CLOSED {
        return;
    }
    let mut data = existing;
    data.status = CONNECTION_STATUS_CLOSED.to_string();
    match content_store.put(data.to_entity()) {
        Ok(hash) => {
            location_index.set(&path, hash);
            tracing::debug!(path = %path, "connection-state closed write");
        }
        Err(e) => {
            tracing::warn!(path = %path, error = %e, "connection-state closed write failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ConnectionData {
        ConnectionData {
            peer_id: "12D3PeerB".to_string(),
            transport: "tcp".to_string(),
            address: "tcp://192.168.1.42:4040".to_string(),
            status: CONNECTION_STATUS_ACTIVE.to_string(),
            established_at: 1_700_000_000_000,
            parameters: None,
        }
    }

    #[test]
    fn connection_shape_round_trips() {
        let d = sample();
        let e = d.to_entity();
        assert_eq!(e.entity_type, TYPE_CONNECTION);
        let back = ConnectionData::from_entity(&e).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn connection_parameters_round_trip_opaquely() {
        let mut d = sample();
        d.parameters = Some(ciborium::Value::Map(vec![(
            ciborium::Value::Text("hash_format".into()),
            ciborium::Value::Text("v7.64".into()),
        )]));
        let back = ConnectionData::from_entity(&d.to_entity()).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn connection_relative_path_uses_remote_identity_hex() {
        let h = entity_hash::Hash::compute("test", b"remote-identity");
        let p = ConnectionData::relative_path(&h);
        assert_eq!(p, format!("system/connection/{}", h.to_hex()));
        // 66-char format-byte-included hex (v7.64 §1.4).
        assert_eq!(p.rsplit('/').next().unwrap().len(), 66);
    }

    #[test]
    fn transport_label_from_scheme() {
        assert_eq!(transport_label("tcp://h:1"), "tcp");
        assert_eq!(transport_label("ws://h:1/x"), "ws");
        assert_eq!(transport_label("memory://peer"), "memory");
        assert_eq!(transport_label("no-scheme"), "unknown");
    }

    #[test]
    fn mark_closed_preserves_attachment_fields_and_is_idempotent() {
        let cs = entity_store::MemoryContentStore::new();
        let li = entity_store::MemoryLocationIndex::new();
        let remote_hash = entity_hash::Hash::compute("test", b"remote");

        let path = write_connection_active(
            &cs,
            &li,
            "localPeer",
            "remotePeer",
            &remote_hash,
            "tcp",
            "tcp://10.0.0.7:4040",
        )
        .expect("active write");
        assert_eq!(
            path,
            format!("/localPeer/{}", ConnectionData::relative_path(&remote_hash))
        );

        mark_connection_closed(&cs, &li, "localPeer", &remote_hash);
        let closed = li
            .get(&path)
            .and_then(|h| cs.get(&h))
            .and_then(|e| ConnectionData::from_entity(&e).ok())
            .expect("closed record readable");
        assert_eq!(closed.status, CONNECTION_STATUS_CLOSED);
        assert_eq!(
            closed.transport, "tcp",
            "closed record answers how I WAS attached"
        );
        assert_eq!(closed.address, "tcp://10.0.0.7:4040");
        assert!(closed.established_at > 0);
        let h1 = li.get(&path).unwrap();

        // Idempotent under concurrent demotion: re-closing rebinds nothing.
        mark_connection_closed(&cs, &li, "localPeer", &remote_hash);
        assert_eq!(li.get(&path).unwrap(), h1);
    }

    #[test]
    fn mark_closed_missing_entity_is_noop() {
        let cs = entity_store::MemoryContentStore::new();
        let li = entity_store::MemoryLocationIndex::new();
        let remote_hash = entity_hash::Hash::compute("test", b"never-established");
        mark_connection_closed(&cs, &li, "localPeer", &remote_hash);
        assert!(li
            .get(&format!(
                "/localPeer/{}",
                ConnectionData::relative_path(&remote_hash)
            ))
            .is_none());
    }

    #[test]
    fn active_write_skips_self_entry() {
        let cs = entity_store::MemoryContentStore::new();
        let li = entity_store::MemoryLocationIndex::new();
        let remote_hash = entity_hash::Hash::compute("test", b"self");
        let written = write_connection_active(
            &cs,
            &li,
            "localPeer",
            "localPeer",
            &remote_hash,
            "tcp",
            "tcp://127.0.0.1:1",
        );
        assert!(written.is_none(), "self-entry must not be written");
    }
}
