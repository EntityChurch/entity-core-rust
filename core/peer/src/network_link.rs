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
    PEER_STATUS_REASON_RETRY_EXHAUSTED,
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

    /// §6.7.2 dial-back probe. A bare `Connector::connect` to the observed
    /// source, dropped the instant it succeeds.
    ///
    /// Everything this does NOT do is the point. No `get_or_connect`: that
    /// pools the binding, runs the handshake, writes the §3.13 `connected`
    /// status and starts keepalive — turning a one-shot reachability question
    /// into a durable relationship with an ephemeral address, and writing that
    /// address into exactly the per-peer fields §6.7.1 MUST 2 forbids it to
    /// reach. No entry in `shared.remote` either, so a later real dispatch to
    /// that peer still resolves its profiles normally.
    ///
    /// The address arrives as bare `ip:port` (that is the shape
    /// `accept_source` carries), which `TcpConnector` accepts directly
    /// alongside the `tcp://` wire shape.
    async fn probe_address(&self, address: &str) -> bool {
        // Bound the wait: the interesting negative answer — a NAT'd requester
        // whose mapping we cannot dial — is usually a black hole rather than a
        // refusal, so without a deadline the honest `reachable: false` never
        // gets sent. 3s is well inside any caller's patience and long enough
        // that a real listener on a slow path still answers.
        #[cfg(not(target_arch = "wasm32"))]
        let attempt = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            self.shared.connector.connect(address),
        )
        .await;
        // On wasm32 there is no raw-socket connector to race a timer against —
        // the browser connector rejects an unsupported scheme immediately — so
        // the connect resolves on its own. Shaped as `Result<Result<_, _>, _>`
        // to keep one match arm below.
        #[cfg(target_arch = "wasm32")]
        let attempt: Result<_, ()> = Ok(self.shared.connector.connect(address).await);

        match attempt {
            Ok(Ok(conn)) => {
                // Proven. Close immediately — the connect IS the payload, which
                // is how §6.7.2's fixed-size requirement is met with an
                // amplification factor of exactly 1.
                drop(conn);
                tracing::debug!(address = %address, "§6.7.2: dial-back arrived");
                true
            }
            Ok(Err(e)) => {
                tracing::debug!(address = %address, error = %e, "§6.7.2: dial-back refused");
                false
            }
            Err(_) => {
                tracing::debug!(address = %address, "§6.7.2: dial-back timed out");
                false
            }
        }
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
            // **KNOWN NON-CONFORMANCE against §1.4 F65/E2 (0.8.2.19) on ONE of
            // this seam's call sites, held for a ruling — routed as
            // `ROUTING-2026-09-10-a` (docs/status/).**
            //
            // Three of the four `self_execute` callers in `extensions/network`
            // target a LOCAL uri (`system/subscription` subscribe/unsubscribe,
            // `system/continuation` advance), where the §1.4 outbound gate does
            // not run and the classification is inert. The fourth is §9.2's
            // best-effort close notification, `entity://{peer}/system/protocol/
            // connect:close` — a genuine outbound sub-dispatch at a foreign
            // peer, originated by the `system/network` handler while it serves
            // a caller-supplied `peer_id`. By 0.8.2.19's authority-provenance
            // test that spends the network handler's grant and is IN scope;
            // `PeerRoot` exempts it.
            //
            // **This is not the F67 credential bypass** (fixed at
            // `outbound_sub_dispatch_authorized`) — it is the same escape by
            // the other door: a ceiling classified out of the gate rather than
            // a credential jumping it. And it is why the rule cannot be read as
            // permitting a handler to re-root to peer authority at will: if a
            // seam may declare itself `PeerRoot`, F65 is evadable by every
            // handler and the rule is empty.
            //
            // **What blocks the flip.** `internal_scope()` below grants
            // `system/protocol/connect` only `hello` + `authenticate`, with
            // `peers` absent — so `Handler(..)` refuses the close notification
            // on Dimensions 2 AND 4, and nothing supplies a Dimension-4
            // relaxation: the `held_capability` we hold from that peer is
            // `default_connection_grants`, which does not cover
            // `connect:close`. Adding `close` to the scope is ours to do;
            // **what authorizes a peer's own §9.2 courtesy close toward the
            // peer it is disconnecting from is a cohort question**, and
            // widening a bootstrap grant to `peers: ["*"]` is the one direction
            // §6.2 names as specifically wrong. Routed rather than guessed.
            connection::DispatchCeiling::PeerRoot,
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
        //
        // **The self-grant is CONFORMANT here and this is not the §1.4 phase-1
        // gap** (`0.8.2.19`). That rule says the `grantee` is *the peer whose
        // engine will originate the delivery*; for a lifecycle subscription this
        // peer both subscribes and delivers, so the delivering engine IS the
        // local identity. Checked against the criterion rather than pattern-
        // matched on the shape — the gap is at `mint_delivery_grant` in
        // bindings/sdk, where the subscription is cross-peer and the engine is
        // somebody else's.
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

    fn write_retry_exhausted(&self, peer_id: &str, identity_hash: &Hash, failing_since: u64) {
        // §2.2 give-up (ruling 6). `last_error`/`last_seen` carry forward from
        // the episode's last demotion — the record an operator reads next to
        // "we stopped trying" should say what was failing, not just that we
        // gave up. `failing_since` is preserved, not cleared: it says how long
        // we tried before abandoning.
        let prev = liveness::read_peer_status(
            self.shared.content_store.as_ref(),
            self.shared.location_index.as_ref(),
            self.local_pid(),
            identity_hash,
        );
        let mut data = PeerStatusData::bare(peer_id, PEER_STATUS_DISCONNECTED);
        data.reason = Some(PEER_STATUS_REASON_RETRY_EXHAUSTED.to_string());
        data.last_error = prev.as_ref().and_then(|d| d.last_error.clone());
        data.last_seen = prev.as_ref().and_then(|d| d.last_seen);
        data.failing_since = Some(failing_since);
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
