//! EXTENSION-NETWORK Amendment 12 §A3 — the liveness slice.
//!
//! The single primitive the whole reactive half composes on: write
//! `system/peer/status/{peer}` on connection state change. The write
//! goes through the notifying location index, so it fires any
//! `system/subscription` bound to the path — the "no poll" liveness
//! signal consumers block on. It needs none of `maintain-peer`, the
//! continuation graph, or the §8 outbox.
//!
//! Three writes make up the slice:
//! - `connected` on establish (§6.2, both ends of the handshake) —
//!   seams: `remote::get_or_connect` / `Peer::connect_to` (dialer),
//!   the AUTHENTICATE grant site in connection.rs (responder);
//! - `suspect` on transport error (§A1) — seams: the direct-dispatch
//!   send sites via [`demote_peer_on_transport_error`];
//! - `disconnected` on keepalive miss (§5.4, rung 2 — keepalive.rs).
//!
//! **Seam discipline (§A1, normative):** the demotion write happens at
//! the dispatch caller that both observes the send error and holds
//! `peer_id` — never buried inside a transport primitive that holds
//! only a socket handle. **Scope (ruling E, pinned normative):** the
//! demotion seams are the direct-dispatch send sites only; the RELAY
//! terminal-hop forward (relay_forwarder.rs) and the §10.2 fallback
//! path MUST NOT demote peer liveness.

use std::sync::Arc;

use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};

use crate::peer_status::{
    PeerStatusData, PEER_STATUS_DISCONNECTED, PEER_STATUS_REASON_KEEPALIVE_MISS,
    PEER_STATUS_REASON_TRANSPORT_ERROR, PEER_STATUS_SUSPECT,
};
use crate::remote::RemoteEndpoint;
use crate::PeerShared;

/// Write the §3.13 liveness entity for a remote peer to the local tree
/// at `/{local}/system/peer/status/{remote_hex}`.
///
/// Straight write (not read-modify-write): the status entity has no
/// field the caller must preserve. The §A1 no-clobber discipline — do
/// not demote a concurrently-established live re-entry — is the
/// CALLER's responsibility at the transport-error seam (pool
/// pointer-identity guard, see [`demote_peer_on_transport_error`]),
/// because only the caller knows whether the failed connection is
/// still the bound one.
///
/// Soft-fail: the liveness write is observability-only and must never
/// mask the transport/handshake outcome the caller is about to return.
/// Errors are logged and swallowed — same contract as the R6 session
/// writes at the same seams.
pub(crate) fn write_peer_status(
    content_store: &dyn ContentStore,
    location_index: &dyn LocationIndex,
    local_peer_id: &str,
    remote_identity_hash: &Hash,
    data: &PeerStatusData,
) {
    // §9.1 R6-f analog: no self-status. A peer never writes a liveness
    // entity keyed by its own peer_id; local dispatch has no connection
    // to observe.
    if data.peer_id == local_peer_id {
        return;
    }
    let path = format!(
        "/{}/{}",
        local_peer_id,
        PeerStatusData::relative_path(remote_identity_hash)
    );
    match content_store.put(data.to_entity()) {
        Ok(hash) => {
            location_index.set(&path, hash);
            tracing::debug!(
                path = %path,
                status = %data.status,
                reason = data.reason.as_deref().unwrap_or(""),
                "peer-status write"
            );
        }
        Err(e) => {
            tracing::warn!(
                path = %path,
                status = %data.status,
                error = %e,
                "peer-status write failed"
            );
        }
    }
}

/// Current wall-clock ms since epoch (WASM-safe).
pub(crate) fn now_ms() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// The Amendment 12 §A1 reactive demotion: a transport failure observed
/// on a connection believed active demotes peer liveness by writing
/// `system/peer/status = suspect` (reason `transport-error`), firing
/// the same subscription the keepalive path fires. It also evicts the
/// dead connection from the pool so the next dispatch redials.
///
/// No-clobber / idempotency (§A1 — behavioral, ruled per ask C; the
/// `Arc::ptr_eq` precedent at `remove_inbound`): the eviction and the
/// demotion fire only if `failed` is still the connection currently
/// bound for this peer — the pooled outbound conn, or the §6.11(b)
/// inbound-reentry conn for the no-published-profile path. If a
/// concurrent re-dial already replaced it with a live connection
/// (which wrote its own `connected`), or a concurrent identical
/// failure already evicted it, this is a no-op: never clobber the
/// current binding's liveness, and stay idempotent under concurrent
/// re-entry.
///
/// A single transport error writes `suspect`, not `disconnected` — one
/// failure is not proof of a dead peer (it may be this pooled socket
/// only); the §5.4 keepalive path escalates suspect → disconnected.
pub(crate) fn demote_peer_on_transport_error(
    shared: &PeerShared,
    peer_id: &str,
    failed: &Arc<dyn RemoteEndpoint>,
    cause: &str,
) {
    let was_pooled_binding = shared.remote.evict_outbound_if_bound(peer_id, failed);
    let was_reentry_binding = shared.remote.evict_inbound_if_bound(peer_id, failed);

    if !was_pooled_binding && !was_reentry_binding {
        // `failed` is no longer the bound path for this peer — a
        // concurrent re-establishment owns liveness now, or a concurrent
        // failure already demoted. Do not clobber.
        return;
    }

    let mut data = PeerStatusData::bare(failed.remote_peer_id(), PEER_STATUS_SUSPECT);
    data.reason = Some(PEER_STATUS_REASON_TRANSPORT_ERROR.to_string());
    data.last_error = Some(cause.to_string());
    data.last_seen = crate::keepalive::last_seen_snapshot(failed.as_ref());
    write_peer_status(
        shared.content_store.as_ref(),
        shared.location_index.as_ref(),
        shared.peer_id.as_str(),
        &failed.remote_identity_hash(),
        &data,
    );
    // §3.13 close/failure transition (ruling C): the demoted connection
    // was evicted above, so its system/connection record flips to
    // `closed`. No-op when establish never recorded one (reentry
    // bindings — the remote dialed).
    crate::connection_state::mark_connection_closed(
        shared.content_store.as_ref(),
        shared.location_index.as_ref(),
        shared.peer_id.as_str(),
        &failed.remote_identity_hash(),
    );
}

/// The §5.4 keepalive escalation terminal: the peer failed
/// `max_missed` pings and did not recover within the grace window —
/// write `system/peer/status = disconnected` (reason `keepalive-miss`)
/// and evict the dead connection. Same no-clobber discipline as the
/// transport-error demotion: fires only while `failed` is still the
/// bound connection (a concurrent re-dial owns liveness and MUST NOT
/// be clobbered); idempotent under concurrent re-entry.
///
/// Takes components rather than `&PeerShared`: the keepalive loop holds
/// the pool weakly (a loop must not keep a dropped peer alive) and the
/// stores directly.
pub(crate) fn demote_peer_on_keepalive_miss(
    remote: &crate::remote::RemoteState,
    content_store: &dyn ContentStore,
    location_index: &dyn LocationIndex,
    local_peer_id: &str,
    peer_id: &str,
    failed: &Arc<dyn RemoteEndpoint>,
) {
    let was_pooled_binding = remote.evict_outbound_if_bound(peer_id, failed);
    let was_reentry_binding = remote.evict_inbound_if_bound(peer_id, failed);
    if !was_pooled_binding && !was_reentry_binding {
        return;
    }

    let mut data = PeerStatusData::bare(failed.remote_peer_id(), PEER_STATUS_DISCONNECTED);
    data.reason = Some(PEER_STATUS_REASON_KEEPALIVE_MISS.to_string());
    data.last_seen = crate::keepalive::last_seen_snapshot(failed.as_ref());
    write_peer_status(
        content_store,
        location_index,
        local_peer_id,
        &failed.remote_identity_hash(),
        &data,
    );
    // §3.13 close/failure transition (ruling C) — same discipline as
    // the transport-error demotion above.
    crate::connection_state::mark_connection_closed(
        content_store,
        location_index,
        local_peer_id,
        &failed.remote_identity_hash(),
    );
}

/// Write `connected` for a freshly-established connection (§6.2 — the
/// baseline everything else demotes from). Called on BOTH ends of the
/// handshake: the dialer as the handshake completes, the responder as
/// it grants the connection capability.
///
/// `connection` is the §3.13 path reference to the sibling
/// `system/connection/{peer}` entity — `Some` on the dialer side (which
/// wrote that record), `None` on the responder side (which holds no
/// dialable address for the remote and records none; ruling C).
pub(crate) fn write_connected_status(
    content_store: &dyn ContentStore,
    location_index: &dyn LocationIndex,
    local_peer_id: &str,
    remote_peer_id: &str,
    remote_identity_hash: &Hash,
    connection: Option<String>,
) {
    let mut data = PeerStatusData::bare(remote_peer_id, crate::peer_status::PEER_STATUS_CONNECTED);
    data.connected_at = Some(now_ms());
    data.connection = connection;
    write_peer_status(
        content_store,
        location_index,
        local_peer_id,
        remote_identity_hash,
        &data,
    );
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use entity_crypto::Keypair;
    use entity_entity::Entity;
    use entity_hash::Hash;

    use super::*;
    use crate::peer_status::{
        PeerStatusData, PEER_STATUS_CONNECTED, PEER_STATUS_REASON_TRANSPORT_ERROR,
        PEER_STATUS_SUSPECT,
    };
    use crate::remote::{DispatchFuture, RemoteEndpoint};
    use crate::{Peer, PeerBuilder};

    /// Minimal `RemoteEndpoint` for exercising the §A1 no-clobber guard
    /// without a network (the Go `fakeEndpoint` analog). Its dispatch
    /// always fails at the "transport".
    struct FakeEndpoint {
        peer_id: String,
        identity_hash: Hash,
        capability: Entity,
        included: HashMap<Hash, Entity>,
    }

    impl FakeEndpoint {
        /// `identity_hash` is passed in (derived ONCE by the test) so the
        /// fixture stays self-consistent even if the process-global home
        /// hash format flips mid-suite (the SHA-384-window tests).
        fn for_remote(kp: &Keypair, identity_hash: Hash) -> Self {
            Self {
                peer_id: kp.peer_id().to_string(),
                identity_hash,
                capability: Entity::new("test/cap", b"\xa0".to_vec()).unwrap(),
                included: HashMap::new(),
            }
        }
    }

    impl RemoteEndpoint for FakeEndpoint {
        fn remote_peer_id(&self) -> &str {
            &self.peer_id
        }
        fn remote_identity_hash(&self) -> Hash {
            self.identity_hash
        }
        fn capability(&self) -> &Entity {
            &self.capability
        }
        fn auth_included(&self) -> &HashMap<Hash, Entity> {
            &self.included
        }
        fn next_request_id(&self) -> String {
            "req-fake".to_string()
        }
        fn transport_type(&self) -> &'static str {
            "fake"
        }
        fn dispatch_raw<'a>(&'a self, _request_id: String, _frame: Vec<u8>) -> DispatchFuture<'a> {
            Box::pin(async { Err(crate::PeerError::ConnectionError("fake endpoint".into())) })
        }
    }

    fn test_peer(seed: u8) -> Peer {
        PeerBuilder::new()
            .keypair(Keypair::from_seed([seed; 32]))
            .build()
            .unwrap()
    }

    fn status_of(shared: &PeerShared, remote_hash: &Hash) -> Option<PeerStatusData> {
        let path = format!(
            "/{}/{}",
            shared.peer_id.as_str(),
            PeerStatusData::relative_path(remote_hash)
        );
        let h = shared.location_index.get(&path)?;
        let e = shared.content_store.get(&h)?;
        PeerStatusData::from_entity(&e).ok()
    }

    fn seed_connected(shared: &PeerShared, remote_pid: &str, remote_hash: &Hash) {
        write_peer_status(
            shared.content_store.as_ref(),
            shared.location_index.as_ref(),
            shared.peer_id.as_str(),
            remote_hash,
            &PeerStatusData::bare(remote_pid, PEER_STATUS_CONNECTED),
        );
    }

    /// §A1 no-clobber MUST: a stale failed connection must NOT demote
    /// liveness when a different connection is currently bound for the
    /// peer (a concurrent re-establishment that already wrote its own
    /// connected).
    #[test]
    fn a12_demotion_no_clobber() {
        let peer = test_peer(0x51);
        let shared = peer.shared();
        let remote_kp = Keypair::from_seed([0x52; 32]);
        let remote_pid = remote_kp.peer_id().to_string();
        let remote_hash = remote_kp.peer_identity_hash();

        let live: Arc<dyn RemoteEndpoint> =
            Arc::new(FakeEndpoint::for_remote(&remote_kp, remote_hash));
        let stale: Arc<dyn RemoteEndpoint> =
            Arc::new(FakeEndpoint::for_remote(&remote_kp, remote_hash));

        // A live re-establishment is the current binding and wrote connected.
        shared.remote.insert_endpoint(&remote_pid, live.clone());
        seed_connected(&shared, &remote_pid, &remote_hash);

        // The stale conn fails and tries to demote. Guard must skip.
        demote_peer_on_transport_error(&shared, &remote_pid, &stale, "stale write failed");

        let d = status_of(&shared, &remote_hash).expect("status entity vanished");
        assert_eq!(
            d.status, PEER_STATUS_CONNECTED,
            "stale demotion clobbered live connected"
        );
        let bound = shared
            .remote
            .get(&remote_pid)
            .expect("live binding evicted");
        assert!(
            Arc::ptr_eq(&bound, &live),
            "stale demotion replaced the live binding"
        );
    }

    /// §A1 idempotency under concurrent re-entry: many threads observing
    /// the SAME failed connection produce exactly one demotion, ending at
    /// suspect with the failed conn evicted.
    #[test]
    fn a12_demotion_idempotent_under_concurrent_reentry() {
        let peer = test_peer(0x53);
        let shared = peer.shared();
        let remote_kp = Keypair::from_seed([0x54; 32]);
        let remote_pid = remote_kp.peer_id().to_string();
        let remote_hash = remote_kp.peer_identity_hash();

        let failed: Arc<dyn RemoteEndpoint> =
            Arc::new(FakeEndpoint::for_remote(&remote_kp, remote_hash));
        shared.remote.insert_endpoint(&remote_pid, failed.clone());
        seed_connected(&shared, &remote_pid, &remote_hash);

        let mut handles = Vec::new();
        for _ in 0..16 {
            let shared = shared.clone();
            let failed = failed.clone();
            let remote_pid = remote_pid.clone();
            handles.push(std::thread::spawn(move || {
                demote_peer_on_transport_error(
                    &shared,
                    &remote_pid,
                    &failed,
                    "concurrent transport error",
                );
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let d = status_of(&shared, &remote_hash).expect("status entity vanished");
        assert_eq!(d.status, PEER_STATUS_SUSPECT);
        assert_eq!(
            d.reason.as_deref(),
            Some(PEER_STATUS_REASON_TRANSPORT_ERROR)
        );
        assert!(
            shared.remote.get(&remote_pid).is_none(),
            "failed conn should be evicted from the pool"
        );
    }

    /// §6.11(b) reentry conns are a binding too: a failed inbound-reentry
    /// endpoint demotes (and unregisters) when it is still the registered
    /// one.
    #[test]
    fn a12_demotion_covers_reentry_binding() {
        let peer = test_peer(0x55);
        let shared = peer.shared();
        let remote_kp = Keypair::from_seed([0x56; 32]);
        let remote_pid = remote_kp.peer_id().to_string();
        let remote_hash = remote_kp.peer_identity_hash();

        let reentry: Arc<dyn RemoteEndpoint> =
            Arc::new(FakeEndpoint::for_remote(&remote_kp, remote_hash));
        shared.remote.register_inbound(&remote_pid, reentry.clone());
        seed_connected(&shared, &remote_pid, &remote_hash);

        demote_peer_on_transport_error(&shared, &remote_pid, &reentry, "reentry send failed");

        let d = status_of(&shared, &remote_hash).expect("status entity vanished");
        assert_eq!(d.status, PEER_STATUS_SUSPECT);
        assert!(
            shared.remote.get_inbound(&remote_pid).is_none(),
            "failed reentry endpoint should be unregistered"
        );
    }

    /// R6-f analog: a peer never writes a liveness entity keyed by its
    /// own peer_id.
    #[test]
    fn a12_write_skips_self_status() {
        let peer = test_peer(0x57);
        let shared = peer.shared();
        let self_hash = shared.identity_hash;
        write_peer_status(
            shared.content_store.as_ref(),
            shared.location_index.as_ref(),
            shared.peer_id.as_str(),
            &self_hash,
            &PeerStatusData::bare(shared.peer_id.as_str(), PEER_STATUS_CONNECTED),
        );
        assert!(
            status_of(&shared, &self_hash).is_none(),
            "self-status must not be written"
        );
    }
}
