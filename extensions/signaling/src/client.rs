//! The **client** half — using a connection node from a peer
//! (`HANDOFF-2026-07-28-connection-node-staging-and-sequence` §8).
//!
//! This is the cheap half, and the reason Stage 1 is cheap at all: calling
//! `system/signaling:offer` on a gated node is an **ordinary EXECUTE**. All
//! three impls already have cross-peer execute and already conformance-test it,
//! so **no new handler is needed to *use* the service** — this module is a
//! typed wrapper over dispatch, not a new protocol surface.
//!
//! It does *not* extend to the unwrapped surface (a plain client per language,
//! §5.1) or to the punch (socket-level work in each language, not a dispatch
//! handler at all). Both are Stage 2.
//!
//! **The client owns the two convergence obligations the node does not:**
//! [`crate::key`] (which key) and [`crate::pool`] (which node). The node is
//! mode-blind and single; a peer that gets either wrong meets nobody and sees no
//! error. Together with the ordinary handshake this is the whole client surface.

use entity_handler::{
    Dispatcher, ExecuteOptions, HandlerError, STATUS_NOT_SUPPORTED, STATUS_OK, STATUS_RATE_LIMITED,
};

use crate::coordination::{self, Candidate, ConnectRequest, ConnectResponse, Nonce};
use crate::core::{Advertisement, RendezvousKey};
use crate::data::{advertisement_from_params, CollectRequest, CollectResult, OfferRequest};
use crate::{SignalingError, OP_ADVERTISE, OP_COLLECT, OP_OFFER, PATTERN};

/// What can go wrong calling a node.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("signaling dispatch failed: {0}")]
    Dispatch(String),
    #[error("node refused with status {status}")]
    Refused { status: u32 },
    /// The node is at capacity or throttling (429). **Retry-safe by
    /// construction** — every core refusal happens before any state change, and
    /// §1.1 pins each bucket rule to the choice that makes a retry safe.
    #[error("node is at capacity or rate-limiting; retry")]
    Backoff,
    /// The node does not serve this verb (501).
    ///
    /// **Not what a `reflect` call gets.** `reflect` is not a core operation at
    /// all (§1.4) — asking a wrapped node for it is an ordinary unknown
    /// operation (400), the same as any typo. There is no client method for it
    /// here: it belongs to the unwrapped listener, whose protocol is §5.1 and
    /// unwritten.
    #[error("node does not serve this operation on this surface")]
    Unsupported,
    #[error(transparent)]
    Codec(#[from] SignalingError),
}

/// A typed client for one node, over any [`Dispatcher`].
///
/// Taking a `&dyn Dispatcher` rather than a concrete peer keeps this usable from
/// an outer caller (`bindings/sdk::PeerContext`) and from handler-internal
/// dispatch alike, and makes it testable against a stub. Each dispatch is
/// cap-checked at the dispatcher, so the caller's grant must cover
/// `system/signaling:{op}` — this module adds no authority of its own.
pub struct SignalingClient<'a> {
    dispatcher: &'a dyn Dispatcher,
    node_uri: String,
}

impl<'a> SignalingClient<'a> {
    /// Target the node running at `node_peer_id`.
    ///
    /// The peer-id normally comes from the pool member the peer selected —
    /// [`crate::pool::select`] — not from a config constant, because both peers
    /// must land on the same one.
    pub fn new(dispatcher: &'a dyn Dispatcher, node_peer_id: &str) -> Self {
        Self {
            dispatcher,
            node_uri: format!("entity://{}/{}", node_peer_id, PATTERN),
        }
    }

    /// Deposit `message` at `key`.
    ///
    /// Safe to call again with the same bytes: §1.1 pin 2 dedups by content
    /// hash, so a retry after a timeout is idempotent rather than an
    /// accumulation. Peers MUST be prepared to re-offer, since the node's TTL is
    /// binding and a blob may have been reaped (§1.1 pin 3).
    pub async fn offer(&self, key: RendezvousKey, message: &[u8]) -> Result<(), ClientError> {
        let params = OfferRequest {
            rendezvous_key: key,
            message: message.to_vec(),
        }
        .to_entity()?;
        self.execute(OP_OFFER, params).await.map(|_| ())
    }

    /// Read what is at `key`. Removes nothing (§1.1 pin 1), so both peers may
    /// collect and re-collect the same bucket.
    ///
    /// An empty list means "nothing there **yet**" — not an error and not a
    /// reason to give up. A peer polling ahead of its counterpart is the normal
    /// case in a rendezvous.
    pub async fn collect(&self, key: &RendezvousKey) -> Result<Vec<Vec<u8>>, ClientError> {
        let params = CollectRequest {
            rendezvous_key: *key,
        }
        .to_entity()?;
        let result = self.execute(OP_COLLECT, params).await?;
        Ok(CollectResult::from_params(&result.data)?.messages)
    }

    /// Read the node's endpoint, limits, and `lobby` constant.
    ///
    /// Worth calling before deriving a `lobby` key: if the node overrides the
    /// constant and the peer derives from [`crate::LOBBY_DEFAULT`] anyway, it
    /// lands in a bucket nobody else on that pool uses.
    pub async fn advertise(&self) -> Result<Advertisement, ClientError> {
        let result = self.execute(OP_ADVERTISE, empty_params()?).await?;
        Ok(advertisement_from_params(&result.data)?)
    }

    // -----------------------------------------------------------------------
    // §4 step 2 — exchange candidate lists over the rendezvous carrier
    // -----------------------------------------------------------------------

    /// Deposit a coordination entity (§3) as an opaque blob.
    ///
    /// The blob is the canonical `{type, data, content_hash}` encoding, so the
    /// message type travels with it — the reader has nothing else to dispatch
    /// on, since a bucket is a mixed set.
    pub async fn offer_message(
        &self,
        key: RendezvousKey,
        entity: &entity_entity::Entity,
    ) -> Result<(), ClientError> {
        self.offer(key, &coordination::to_blob(entity)).await
    }

    /// Collect a bucket and classify every blob in it, unwrapping §6.3
    /// containers against the key it was collected from.
    ///
    /// Returns [`coordination::CollectedMessage::Unknown`] entries rather than dropping them:
    /// a shared `lobby` bucket may hold other pairs' traffic and message types
    /// this build has never seen, and a caller that wants to know how much it
    /// skipped should be able to count. A container that failed to verify lands
    /// in the same bucket of outcomes — deliberately indistinguishable *on the
    /// wire* (§6.4 skips silently), and deliberately **not** read as its bare
    /// inner entity.
    ///
    /// Each entry carries its `signer` when one was proven, which is the only
    /// place a counterpart's identity comes from before a connection exists.
    ///
    /// **Includes your own offers.** `collect` is non-destructive (§1.1 pin 1),
    /// so you always re-read what you wrote — which is why
    /// [`coordination::find_response`] and [`coordination::find_request`] both
    /// filter on peer-id.
    pub async fn collect_messages(
        &self,
        key: &RendezvousKey,
    ) -> Result<Vec<coordination::CollectedCoordination>, ClientError> {
        Ok(self
            .collect(key)
            .await?
            .iter()
            .map(|blob| coordination::classify_collected(blob, key))
            .collect())
    }

    /// §4 step 2, initiator half: offer a `connect-request` and return the
    /// nonce that identifies this exchange.
    ///
    /// Poll [`collect_messages`](Self::collect_messages) and pass the nonce to
    /// [`coordination::find_response`] to pick your answer out of the bucket.
    /// Re-offering the same request while polling is safe and expected — the
    /// node dedups it, and the TTL is binding so a long wait may need one.
    pub async fn initiate(
        &self,
        key: RendezvousKey,
        my_peer_id: &str,
        candidates: Vec<Candidate>,
    ) -> Result<Nonce, ClientError> {
        let nonce = Nonce::generate();
        let request = ConnectRequest {
            initiator: my_peer_id.to_string(),
            candidates,
            nonce: nonce.clone(),
        };
        self.offer_message(key, &request.to_entity()?).await?;
        Ok(nonce)
    }

    /// §4 step 2, responder half: answer a `connect-request` with our own
    /// candidates, echoing its nonce.
    pub async fn respond(
        &self,
        key: RendezvousKey,
        my_peer_id: &str,
        request: &ConnectRequest,
        candidates: Vec<Candidate>,
    ) -> Result<(), ClientError> {
        let response = ConnectResponse {
            responder: my_peer_id.to_string(),
            candidates,
            nonce: request.nonce.clone(),
        };
        self.offer_message(key, &response.to_entity()?).await
    }

    async fn execute(
        &self,
        operation: &str,
        params: entity_entity::Entity,
    ) -> Result<entity_entity::Entity, ClientError> {
        let result = self
            .dispatcher
            .execute(&self.node_uri, operation, params, ExecuteOptions::default())
            .await
            .map_err(|e: HandlerError| ClientError::Dispatch(e.to_string()))?;

        match result.status {
            STATUS_OK => Ok(result.result),
            STATUS_RATE_LIMITED => Err(ClientError::Backoff),
            STATUS_NOT_SUPPORTED => Err(ClientError::Unsupported),
            status => Err(ClientError::Refused { status }),
        }
    }
}

/// `advertise` takes no arguments, but an EXECUTE still carries a params
/// entity, and `Entity::new` rejects empty data — so this is an empty CBOR map,
/// the encoding of "no fields".
fn empty_params() -> Result<entity_entity::Entity, SignalingError> {
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![]));
    entity_entity::Entity::new("system/signaling/empty", data)
        .map_err(|e| SignalingError::Encode(e.to_string()))
}
