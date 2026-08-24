//! The signaling carrier — offer/collect at a node, substrate-agnostic.
//!
//! `EXTENSION-SIGNALING.md` §7.3.1 draws the line this module sits on:
//! **substrates do not interoperate; the coordination layer does.** Carrier,
//! rendezvous key, and the bucket exchange are shared by every punch substrate
//! (`tcp`, `quic`, `webrtc`); only the transport underneath differs.
//!
//! This lived inside [`crate::punch_establisher`] until the browser leg needed
//! it. That module is gated `not(target_arch = "wasm32")` because its *wiring*
//! is TCP — correctly so — and the carrier had no reason to be separate while
//! TCP was the only substrate. The WebRTC substrate (`EXTENSION-SIGNALING.md`
//! §6.5) is the second one, and it reaches its node the same way: a live
//! connection to a signaling peer, `offer` and `collect` over EXECUTE. Nothing
//! here touches a socket, so it compiles for `wasm32` and a browser peer drives
//! its SDP/ICE exchange over the identical carrier.
//!
//! The move is a relocation, not a redesign: the TCP punch constructs the same
//! carrier through [`PeerCarrier::new`] and behaves exactly as before.

use std::sync::Arc;

use entity_crypto::IdentityKeypair;
use entity_entity::Entity;
use entity_signaling::data::{CollectRequest, CollectResult, OfferRequest};
use entity_signaling::punch::{Carrier, PunchError};
use entity_signaling::RendezvousKey;

use crate::remote;
use crate::transport::Connector;

/// [`Carrier`] over a live connection to a signaling node.
///
/// # The node is dialed by address, never resolved through the tree
///
/// `get_or_connect` resolves a peer through published transport profiles — and
/// that is exactly what a NAT'd peer cannot do for the *carrier*. Resolving the
/// rendezvous service the same way you resolve a peer is circular: the whole
/// reason the carrier exists is that peer resolution has already failed. So the
/// node's address is **operator configuration** (a CLI flag / a config field),
/// the same posture Go takes, and this dials it directly.
///
/// The connection is cached and reused across the several `offer` / `collect`
/// calls one exchange makes — reconnecting per verb would triple the carrier's
/// load for no benefit.
pub struct PeerCarrier {
    node_peer_id: String,
    node_addr: String,
    keypair: IdentityKeypair,
    connector: Arc<dyn Connector>,
    home_format: u8,
    conn: tokio::sync::Mutex<Option<Arc<remote::RemoteConnection>>>,
}

impl PeerCarrier {
    /// Wire a carrier to the operator-configured signaling node.
    ///
    /// `connector` is the platform's outbound transport — a `TcpConnector`
    /// natively, a `BrowserWebSocketConnector` in a browser. The carrier does
    /// not care which: it needs a live connection to the node, not a substrate.
    pub fn new(
        node_peer_id: impl Into<String>,
        node_addr: impl Into<String>,
        keypair: IdentityKeypair,
        connector: Arc<dyn Connector>,
        home_format: u8,
    ) -> Self {
        Self {
            node_peer_id: node_peer_id.into(),
            node_addr: node_addr.into(),
            keypair,
            connector,
            home_format,
            conn: tokio::sync::Mutex::new(None),
        }
    }

    async fn connection(&self) -> Result<Arc<remote::RemoteConnection>, PunchError> {
        let mut slot = self.conn.lock().await;
        if let Some(existing) = slot.as_ref() {
            return Ok(existing.clone());
        }
        let transport = self
            .connector
            .connect(&self.node_addr)
            .await
            .map_err(|e| PunchError::Carrier(format!("dial node {}: {}", self.node_addr, e)))?;
        let conn = remote::perform_connect(transport, &self.keypair, self.home_format)
            .await
            .map_err(|e| PunchError::Carrier(format!("handshake with node: {}", e)))?;
        let conn = Arc::new(conn);
        *slot = Some(conn.clone());
        Ok(conn)
    }

    async fn execute(&self, operation: &str, params: Entity) -> Result<(u32, Entity), PunchError> {
        let conn = self.connection().await?;
        let uri = format!("/{}/{}", self.node_peer_id, entity_signaling::PATTERN);
        // `resource: None` is load-bearing — see the module doc. A resource
        // target on a signaling verb is a 403 that reads as "not granted".
        let resp = remote::send_execute(
            conn.as_ref(),
            &self.keypair,
            &uri,
            operation,
            &params,
            None,
            None,
            None,
            &std::collections::HashMap::new(),
            None,
        )
        .await
        .map_err(|e| PunchError::Carrier(format!("{}: {}", operation, e)))?;
        Ok((resp.status, resp.result))
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl Carrier for PeerCarrier {
    async fn offer(&self, key: &RendezvousKey, blob: Vec<u8>) -> Result<(), PunchError> {
        let params = OfferRequest {
            rendezvous_key: *key,
            message: blob,
        }
        .to_entity()
        .map_err(PunchError::from)?;
        let (status, _) = self.execute(entity_signaling::OP_OFFER, params).await?;
        if status != 200 {
            return Err(PunchError::Carrier(format!("offer: status {}", status)));
        }
        Ok(())
    }

    async fn collect(&self, key: &RendezvousKey) -> Result<Vec<Vec<u8>>, PunchError> {
        let params = CollectRequest {
            rendezvous_key: *key,
        }
        .to_entity()
        .map_err(PunchError::from)?;
        let (status, result) = self.execute(entity_signaling::OP_COLLECT, params).await?;
        if status != 200 {
            return Err(PunchError::Carrier(format!("collect: status {}", status)));
        }
        Ok(CollectResult::from_params(&result.data)
            .map_err(PunchError::from)?
            .messages)
    }
}
