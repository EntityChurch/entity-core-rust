//! `PeerLink` — the imperative connection-substrate seam the
//! `entity-network` handler drives (EXTENSION-NETWORK §3–§4, Amendment 12
//! rung 3).
//!
//! `entity-network` is an extension crate: it cannot import `entity-peer`
//! (that would invert the crate DAG). So `core/peer` injects this impl over
//! its outbound pool / dial / keepalive machinery at engine start — the same
//! inversion the RELAY forwarder uses (`relay_forwarder::PeerRelayForwarder`
//! behind `entity_relay`'s `PeerForwarder` seam). The handler owns the
//! REACTIVE half (the §4.1 continuation graph); this seam is the imperative
//! substrate it reuses (§A4: the handler double-builds no establish write or
//! keepalive loop — `connect_and_pool` already performs them).

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use entity_entity::Entity;
use entity_handler::{ExecuteOptions, HandlerError, HandlerResult};
use entity_hash::Hash;
use entity_network::{ConnectedPeer, PeerLink, ScheduledTask};

use crate::peer_status::{
    PeerStatusData, PEER_STATUS_DISCONNECTED, PEER_STATUS_REASON_LOCAL_RELEASE,
};
use crate::{connection, connection_state, liveness, remote, runtime, PeerShared};

/// `PeerLink` over a live `PeerShared`. Constructed once at `start_engines`
/// and handed to `NetworkHandler::bind`.
pub struct PeerNetworkLink {
    shared: Arc<PeerShared>,
}

impl PeerNetworkLink {
    pub fn new(shared: Arc<PeerShared>) -> Self {
        Self { shared }
    }

    fn local_pid(&self) -> &str {
        self.shared.peer_id.as_str()
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl PeerLink for PeerNetworkLink {
    async fn ensure_connected(
        &self,
        peer_id: &str,
        address: Option<&str>,
    ) -> Result<ConnectedPeer, String> {
        // Pool hit — reuse the live binding, no dial (§10 step 1).
        if let Some(endpoint) = self.shared.remote.get(peer_id) {
            return Ok(ConnectedPeer {
                peer_id: peer_id.to_string(),
                identity_hash: endpoint.remote_identity_hash(),
            });
        }
        // Not pooled — dial. An explicit maintain/reconnect address dials
        // directly (`connect_and_pool`, the shared connect_to body); absent
        // an address, resolve the peer's transport profiles from the tree
        // (`get_or_connect`).
        let endpoint = match address {
            Some(addr) => remote::connect_and_pool(&self.shared, addr)
                .await
                .map_err(|e| e.to_string())?,
            None => remote::get_or_connect(
                &self.shared.remote,
                peer_id,
                &self.shared.keypair,
                self.shared.content_store.as_ref(),
                self.shared.location_index.as_ref(),
                self.local_pid(),
                self.shared.connector.as_ref(),
                self.shared.config.home_hash_format,
                Some(self.shared.clone()),
            )
            .await
            .map_err(|e| e.to_string())?,
        };
        Ok(ConnectedPeer {
            peer_id: peer_id.to_string(),
            identity_hash: endpoint.remote_identity_hash(),
        })
    }

    fn evict(&self, peer_id: &str) {
        self.shared.remote.remove(peer_id);
    }

    fn is_connected(&self, peer_id: &str) -> bool {
        self.shared.remote.get(peer_id).is_some()
    }

    fn identity_hash_of(&self, peer_id: &str) -> Option<Hash> {
        self.shared
            .remote
            .get(peer_id)
            .map(|e| e.remote_identity_hash())
    }

    async fn self_execute(
        &self,
        uri: &str,
        operation: &str,
        params: Entity,
        opts: ExecuteOptions,
    ) -> Result<HandlerResult, HandlerError> {
        // Dispatch as the local peer identity — the same path
        // `Peer::execute_with_options` takes, so the handler sees
        // `author = local identity` and the deliver-token SB1/R1 chain-root
        // check (the lifecycle subscriptions are the peer's own) fires
        // identically. `opts.included` (deliver token + signature + granter
        // identity) is folded into the outbound envelope's `included` set at
        // dispatch (§6.13(b) seam).
        let local_identity = self.shared.identity_hash;
        let execute_fn = connection::make_execute_fn(
            self.shared.clone(),
            Some(local_identity),
            HashMap::new(),
            None,
            None,
        );
        execute_fn(uri.to_string(), operation.to_string(), params, opts).await
    }

    fn mint_deliver_token(&self, deliver_uri: &str) -> Result<(Entity, Entity, Entity), String> {
        // Self-owned deliver token: granter == grantee == the local peer
        // (the peer both subscribes and receives). No expiry — lifecycle
        // subscriptions must survive arbitrarily long disconnects;
        // release-peer is the deliberate teardown. `generate_deliver_token`
        // grants inbox `receive` at `deliver_uri` under the peer's identity;
        // passing the local identity hash as the grantee makes it self-owned.
        let params = remote::generate_deliver_token(
            &self.shared.keypair,
            self.shared.identity_hash,
            deliver_uri,
            "receive",
        )
        .map_err(|e| e.to_string())?;
        // Persist the token + signature so the subscription engine can
        // resolve them at delivery time (it reads from the tree, not the
        // subscribe envelope, on re-issue).
        let _ = self.shared.content_store.put(params.deliver_token.clone());
        let _ = self
            .shared
            .content_store
            .put(params.deliver_token_sig.clone());
        Ok((
            params.deliver_token,
            params.deliver_token_sig,
            params.local_identity,
        ))
    }

    fn write_released(&self, peer_id: &str, identity_hash: &Hash) {
        // §4.2 terminal write on shutdown: the relationship is deliberately
        // over — eviction alone would leave the last transition value
        // standing. Bare `{peer_id, status: disconnected}` (reason
        // `local-release`) matches the cohort shape.
        let mut data = PeerStatusData::bare(peer_id, PEER_STATUS_DISCONNECTED);
        data.reason = Some(PEER_STATUS_REASON_LOCAL_RELEASE.to_string());
        liveness::write_peer_status(
            self.shared.content_store.as_ref(),
            self.shared.location_index.as_ref(),
            self.local_pid(),
            identity_hash,
            &data,
        );
        connection_state::mark_connection_closed(
            self.shared.content_store.as_ref(),
            self.shared.location_index.as_ref(),
            self.local_pid(),
            identity_hash,
        );
    }

    fn mark_connection_closed(&self, identity_hash: &Hash) {
        connection_state::mark_connection_closed(
            self.shared.content_store.as_ref(),
            self.shared.location_index.as_ref(),
            self.local_pid(),
            identity_hash,
        );
    }

    fn schedule(&self, delay_ms: u64, task: ScheduledTask) {
        runtime::spawn(async move {
            runtime::sleep_ms(delay_ms).await;
            task.await;
        });
    }
}
