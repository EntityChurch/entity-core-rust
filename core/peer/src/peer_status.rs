//! `system/peer/status/{peer}` — the §3.13 operational liveness entity.
//!
//! This is the sanctioned liveness home for the whole cohort: the
//! session entity (`system/peer/session`) deliberately DROPPED its own
//! `status`/`last_active` fields (session_entity.rs, §9.1 R6-b/R6-c)
//! precisely because they duplicated this entity.
//!
//! The entity lives at `/{local_peer_id}/system/peer/status/{remote_hex}`
//! (see [`PeerStatusData::relative_path`]). It is an ordinary tree
//! entity, so a write through the notifying location index fires any
//! `system/subscription` on the path — the "no poll" liveness signal
//! consumers block on (EXTENSION-NETWORK §4.1, Amendment 12 §A3: the
//! liveness slice). Writing this entity on connection state change
//! requires none of `maintain-peer`, the continuation graph, or the §8
//! outbox; those compose on top of it.
//!
//! **Canonical shape (Amendment 12 rung-1 ruling D):** the field set is
//! declared ONCE, at ENTITY-CORE-PROTOCOL §3.13 — `peer_id` (required),
//! `status` (required), `connected_at`, `last_seen`, `connection`
//! (OPTIONAL). NETWORK's put-sites are minimal writes, not exhaustive
//! shapes; a bare `{peer_id, status}` write is conformant. Do NOT
//! re-derive the shape from put-site examples. `reason`/`last_error`
//! are the Amendment 12 §A2 additive OPTIONAL fields (declaration home
//! ruled §3.13 upstream, ruling A; NETWORK owns the enum semantics +
//! recovery mapping). `failing_since` is the §A6.5 additive OPTIONAL
//! field (rulings 7/8) — the one durable input the retry pacing derives
//! from; see [`PeerStatusData::failing_since`].

use entity_entity::Entity;
use entity_hash::Hash;

/// Entity-type string for the §3.13 peer-status entity.
pub const TYPE_PEER_STATUS: &str = "system/peer/status";

/// A live connection is established (EXTENSION-NETWORK §6.2).
pub const PEER_STATUS_CONNECTED: &str = "connected";
/// A single transport error was observed on a connection believed
/// active (Amendment 12 §A1). One failure is not proof of a dead peer;
/// a consumer stops trusting "Connected" without tearing the session
/// down. The keepalive path (§5.4) escalates suspect → disconnected.
pub const PEER_STATUS_SUSPECT: &str = "suspect";
/// The peer is gone: keepalive miss (§5.4), release (§4.2), or
/// graceful close (§4.4).
pub const PEER_STATUS_DISCONNECTED: &str = "disconnected";
// NOTE: the status entity is a THREE-state enum (ENTITY-CORE-PROTOCOL
// §3.13; Amendment 12 rung-1 ruling D). "reconnecting" is NOT a
// system/peer/status value — it belongs to system/network/peer-summary
// (NETWORK §2.8), the derived status-op output. Transitions:
// (unknown) → connected → suspect → disconnected; reconnection
// returns to connected.

// Peer-status transition reasons (Amendment 12 §A2). OPTIONAL kebab
// enum: why the status last changed, so a consumer or the reconnect
// continuation can pick a recovery. A reader treats an unrecognized
// value as generic (MUST-ignore-unknowns) and falls back to backoff.
//
// Recovery mapping (§A2):
//   - transport-error, keepalive-miss → backoff-reconnect (§4.1)
//   - auth-rejected                   → re-handshake (§6.3), do NOT reuse held cap
//   - peer-shutdown, local-release    → terminal; session ended deliberately (§6.1)
//   - peer-idle, peer-migration       → preserve subscriptions; expect resume (§9.1)

/// §A2 reason: transport failure on a connection believed active.
pub const PEER_STATUS_REASON_TRANSPORT_ERROR: &str = "transport-error";
/// §A2 reason: keepalive escalation (§5.4).
pub const PEER_STATUS_REASON_KEEPALIVE_MISS: &str = "keepalive-miss";
/// §A2 reason: authentication rejected — re-handshake, do not reuse cap.
pub const PEER_STATUS_REASON_AUTH_REJECTED: &str = "auth-rejected";
/// §A2 reason: deliberate remote shutdown — terminal.
pub const PEER_STATUS_REASON_PEER_SHUTDOWN: &str = "peer-shutdown";
/// §A2 reason: idle close — preserve subscriptions, expect resume.
pub const PEER_STATUS_REASON_PEER_IDLE: &str = "peer-idle";
/// §A2 reason: peer migrating — preserve subscriptions, expect resume.
pub const PEER_STATUS_REASON_PEER_MIGRATION: &str = "peer-migration";
/// §A2 reason: local release (§4.2) — terminal.
pub const PEER_STATUS_REASON_LOCAL_RELEASE: &str = "local-release";
/// §2.2 reason: an OPTIONAL retry bound (`max_attempts` /
/// `max_elapsed_ms`) was reached and the relationship is abandoned
/// (arch ruling 6) — terminal.
///
/// Exhaustion is deliberately NOT a fourth status value: the §3.13 enum
/// stays three-state and terminates at `disconnected`, with `reason`
/// saying why. Only reachable when a caller opted into a bound —
/// retry-forever is the normative default.
pub const PEER_STATUS_REASON_RETRY_EXHAUSTED: &str = "retry-exhausted";

/// Decoded `system/peer/status/{peer}` entity (§3.13 + §A2).
///
/// All optional fields encode as true CBOR absence when `None`
/// (omitempty) — a peer that never sets them emits byte-identical
/// entities to the bare `{peer_id, status}` shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerStatusData {
    /// Base58 string of the observed remote peer's `peer_id` (the
    /// data-field identity, distinct from the hex path segment).
    pub peer_id: String,
    /// One of the `PEER_STATUS_*` lifecycle values (3-state enum).
    pub status: String,
    /// ms since epoch, when the connection was established. OPTIONAL.
    pub connected_at: Option<u64>,
    /// ms since epoch, last message received. OPTIONAL — a snapshot
    /// taken at a transition write (on a demotion, the demotion's
    /// evidence), NEVER a cadence refresh: per-tick freshness is
    /// implementation-internal (Amendment 12 §A4, rung-2 ruling 1).
    pub last_seen: Option<u64>,
    /// Path reference to the corresponding `system/connection/{peer}`
    /// entity. OPTIONAL (and NOT part of the §A3 floor — ruling C).
    pub connection: Option<String>,
    /// §A2 OPTIONAL transition reason (a `PEER_STATUS_REASON_*` value;
    /// readers treat unknown values as generic-backoff).
    pub reason: Option<String>,
    /// §A2 OPTIONAL coded/opaque detail for humans + logs, never
    /// parsed by a recovery path.
    pub last_error: Option<String>,
    /// ms since epoch of the transition out of `connected` that began
    /// the current failure episode — the single durable input the §2.2
    /// retry pacing derives from (Amendment 12 rulings 7/8). OPTIONAL;
    /// absent ⇒ not currently failing.
    ///
    /// Written ONCE, at the first demotion (`connected` → `suspect`, or
    /// straight to `disconnected`), and PRESERVED across every later
    /// demotion write in the same episode: a `suspect` → `disconnected`
    /// escalation must not re-stamp it, or the derived backoff curve
    /// restarts at `min_ms` every time the peer fails a little harder.
    /// The `connected` write omits it, which clears it — recovery ends
    /// the episode.
    ///
    /// It is deliberately the ONLY retry state that exists: `attempt`
    /// and `next_attempt_at` are DERIVED from (failing_since, backoff
    /// cfg, now) — never stored, never written per attempt (§A4: the
    /// status entity is transition-written only). Because it is durable
    /// in the tree rather than an in-memory counter, a peer that
    /// restarts beside a long-dead remote resumes the curve where it
    /// left off instead of hammering from `min_ms`.
    pub failing_since: Option<u64>,
}

/// Errors decoding a peer-status entity.
#[derive(Debug, thiserror::Error)]
pub enum PeerStatusDecodeError {
    /// Entity type didn't match `system/peer/status`.
    #[error("expected entity_type {TYPE_PEER_STATUS}, got {0}")]
    UnexpectedType(String),
    /// CBOR decode failed.
    #[error("cbor decode: {0}")]
    Cbor(String),
    /// Data root wasn't a CBOR map.
    #[error("peer-status data is not a CBOR map")]
    NotAMap,
    /// A required field was missing.
    #[error("peer-status missing required field: {0}")]
    MissingField(&'static str),
}

impl PeerStatusData {
    /// Minimal conformant write shape: `{peer_id, status}` (ruling D).
    pub fn bare(peer_id: impl Into<String>, status: impl Into<String>) -> Self {
        Self {
            peer_id: peer_id.into(),
            status: status.into(),
            connected_at: None,
            last_seen: None,
            connection: None,
            reason: None,
            last_error: None,
            failing_since: None,
        }
    }

    /// Tree path under the local peer's root where this status lives.
    /// Caller prefixes with `/{local_peer_id}/`.
    ///
    /// Format: `system/peer/status/{peer_id_hex}` — the same v7.64 §1.4
    /// positional encoding as the sibling session/transport entities:
    /// lowercase hex of the remote peer's `system/peer` content_hash.
    pub fn relative_path(remote_identity_hash: &Hash) -> String {
        format!("{}/{}", TYPE_PEER_STATUS, remote_identity_hash.to_hex())
    }

    /// Encode to a `system/peer/status` `Entity`. CBOR-map data with
    /// keys in alphabetic order (ECF determinism); `None` optionals are
    /// omitted entirely (true CBOR absence).
    pub fn to_entity(&self) -> Entity {
        let mut fields: Vec<(entity_ecf::Value, entity_ecf::Value)> = Vec::new();

        // Insert in alphabetic order.
        if let Some(at) = self.connected_at {
            fields.push((
                entity_ecf::text("connected_at"),
                entity_ecf::Value::Integer(at.into()),
            ));
        }
        if let Some(ref c) = self.connection {
            fields.push((entity_ecf::text("connection"), entity_ecf::text(c)));
        }
        if let Some(fs) = self.failing_since {
            fields.push((
                entity_ecf::text("failing_since"),
                entity_ecf::Value::Integer(fs.into()),
            ));
        }
        if let Some(ref le) = self.last_error {
            fields.push((entity_ecf::text("last_error"), entity_ecf::text(le)));
        }
        if let Some(ls) = self.last_seen {
            fields.push((
                entity_ecf::text("last_seen"),
                entity_ecf::Value::Integer(ls.into()),
            ));
        }
        fields.push((entity_ecf::text("peer_id"), entity_ecf::text(&self.peer_id)));
        if let Some(ref r) = self.reason {
            fields.push((entity_ecf::text("reason"), entity_ecf::text(r)));
        }
        fields.push((entity_ecf::text("status"), entity_ecf::text(&self.status)));

        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
        Entity::new(TYPE_PEER_STATUS, data).expect("entity construction for system/peer/status")
    }

    /// Decode a `system/peer/status` `Entity`. Unknown fields are
    /// ignored (MUST-ignore-unknowns).
    pub fn from_entity(entity: &Entity) -> Result<Self, PeerStatusDecodeError> {
        if entity.entity_type != TYPE_PEER_STATUS {
            return Err(PeerStatusDecodeError::UnexpectedType(
                entity.entity_type.clone(),
            ));
        }
        let value: ciborium::Value = ciborium::from_reader(entity.data.as_slice())
            .map_err(|e| PeerStatusDecodeError::Cbor(e.to_string()))?;
        let map = match value {
            ciborium::Value::Map(m) => m,
            _ => return Err(PeerStatusDecodeError::NotAMap),
        };

        let peer_id =
            field_text(&map, "peer_id").ok_or(PeerStatusDecodeError::MissingField("peer_id"))?;
        let status =
            field_text(&map, "status").ok_or(PeerStatusDecodeError::MissingField("status"))?;

        Ok(Self {
            peer_id,
            status,
            connected_at: field_uint(&map, "connected_at"),
            last_seen: field_uint(&map, "last_seen"),
            connection: field_text(&map, "connection"),
            reason: field_text(&map, "reason"),
            last_error: field_text(&map, "last_error"),
            failing_since: field_uint(&map, "failing_since"),
        })
    }
}

fn field_lookup<'a>(
    map: &'a [(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Option<&'a ciborium::Value> {
    map.iter().find_map(|(k, v)| match k {
        ciborium::Value::Text(t) if t == key => Some(v),
        _ => None,
    })
}

fn field_text(map: &[(ciborium::Value, ciborium::Value)], key: &str) -> Option<String> {
    field_lookup(map, key).and_then(|v| match v {
        ciborium::Value::Text(s) => Some(s.clone()),
        _ => None,
    })
}

fn field_uint(map: &[(ciborium::Value, ciborium::Value)], key: &str) -> Option<u64> {
    field_lookup(map, key).and_then(|v| match v {
        ciborium::Value::Integer(i) => u64::try_from(*i).ok(),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_hash(seed: u8) -> Hash {
        let mut digest = [0u8; 32];
        digest[0] = seed;
        Hash::new(0x00, digest)
    }

    #[test]
    fn a12_status_relative_path_uses_remote_identity_hex() {
        let h = fixture_hash(0xab);
        assert_eq!(
            PeerStatusData::relative_path(&h),
            format!("system/peer/status/{}", h.to_hex())
        );
        assert_eq!(h.to_hex().len(), 66);
    }

    #[test]
    fn a12_status_bare_shape_round_trips() {
        let original = PeerStatusData::bare(
            "2KN3pAqMPYeVDnYXG7qk9geYmqTpmmcwyGL7EK5o8yuwLt",
            PEER_STATUS_CONNECTED,
        );
        let entity = original.to_entity();
        assert_eq!(entity.entity_type, "system/peer/status");
        let decoded = PeerStatusData::from_entity(&entity).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn a12_status_bare_write_omits_all_optionals() {
        // Ruling D: a bare {peer_id, status} write is conformant and a
        // peer that never sets §A2 fields emits byte-identical entities
        // to the pre-Amendment-12 shape.
        let entity = PeerStatusData::bare("p", PEER_STATUS_SUSPECT).to_entity();
        let value: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).unwrap();
        let map = match value {
            ciborium::Value::Map(m) => m,
            _ => panic!("expected map"),
        };
        assert_eq!(
            map.len(),
            2,
            "bare write must carry exactly peer_id + status"
        );
    }

    #[test]
    fn a12_status_full_shape_round_trips() {
        let original = PeerStatusData {
            peer_id: "2KN3pAqMPYeVDnYXG7qk9geYmqTpmmcwyGL7EK5o8yuwLt".into(),
            status: PEER_STATUS_SUSPECT.into(),
            connected_at: Some(1_700_000_000_000),
            last_seen: Some(1_700_000_100_000),
            connection: Some("system/connection/00ab".into()),
            reason: Some(PEER_STATUS_REASON_TRANSPORT_ERROR.into()),
            last_error: Some("write: broken pipe".into()),
            failing_since: Some(1_700_000_050_000),
        };
        let entity = original.to_entity();
        let decoded = PeerStatusData::from_entity(&entity).unwrap();
        assert_eq!(decoded, original);
    }

    /// Rulings 7/8: `failing_since` is the one durable retry field, and
    /// it must survive the wire as an integer under its spec name — a
    /// sibling reading this entity derives its whole backoff curve from
    /// it, so a rename or a re-type is a silent cross-impl pacing bug.
    #[test]
    fn a12_status_failing_since_encodes_under_its_spec_name() {
        let mut data = PeerStatusData::bare("p", PEER_STATUS_SUSPECT);
        data.failing_since = Some(1_700_000_000_000);
        let entity = data.to_entity();
        let value: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).unwrap();
        let map = match value {
            ciborium::Value::Map(m) => m,
            _ => panic!("expected map"),
        };
        let got = map.iter().find_map(|(k, v)| match (k, v) {
            (ciborium::Value::Text(t), ciborium::Value::Integer(i)) if t == "failing_since" => {
                Some(u64::try_from(*i).unwrap())
            }
            _ => None,
        });
        assert_eq!(got, Some(1_700_000_000_000));
    }

    /// Absent ⇒ not currently failing. A `connected` write clears the
    /// episode BY OMISSION, so `None` must encode as true CBOR absence:
    /// a null would decode back as "no episode" here but is a distinct
    /// wire shape, and the bare write must stay byte-identical to the
    /// pre-Amendment-12 one.
    #[test]
    fn a12_status_failing_since_absent_is_true_absence() {
        let entity = PeerStatusData::bare("p", PEER_STATUS_CONNECTED).to_entity();
        let value: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).unwrap();
        let map = match value {
            ciborium::Value::Map(m) => m,
            _ => panic!("expected map"),
        };
        assert!(
            !map.iter()
                .any(|(k, _)| matches!(k, ciborium::Value::Text(t) if t == "failing_since")),
            "a connected write must omit failing_since entirely, not null it"
        );
        assert_eq!(
            PeerStatusData::from_entity(&entity).unwrap().failing_since,
            None
        );
    }

    #[test]
    fn a12_status_decode_tolerates_unknown_fields() {
        // MUST-ignore-unknowns: a future writer adding fields must not
        // break this reader.
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("future_field"), entity_ecf::text("x")),
            (entity_ecf::text("peer_id"), entity_ecf::text("p")),
            (entity_ecf::text("status"), entity_ecf::text("connected")),
        ]));
        let entity = Entity::new(TYPE_PEER_STATUS, data).unwrap();
        let decoded = PeerStatusData::from_entity(&entity).unwrap();
        assert_eq!(decoded.status, PEER_STATUS_CONNECTED);
    }

    #[test]
    fn a12_status_decode_rejects_wrong_type() {
        let other = Entity::new("some/other/type", b"\xa0".to_vec()).unwrap();
        let err = PeerStatusData::from_entity(&other).unwrap_err();
        assert!(matches!(err, PeerStatusDecodeError::UnexpectedType(_)));
    }

    #[test]
    fn a12_status_enum_is_three_states() {
        // Ruling D pinned the 3-state enum; "reconnecting" is a
        // peer-summary value, not a status value. This test is the
        // tripwire against re-importing the arch's own D-class bug.
        for s in [
            PEER_STATUS_CONNECTED,
            PEER_STATUS_SUSPECT,
            PEER_STATUS_DISCONNECTED,
        ] {
            assert_ne!(*s, *"reconnecting");
        }
    }
}
