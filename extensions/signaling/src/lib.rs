//! `system/signaling` — the connection node: the standalone rendezvous service
//! two NAT'd peers need in order to meet, plus (on the unwrapped listener, §1.4)
//! the reflector they learn their own address from.
//!
//! Two peers both behind NAT cannot dial each other and have no public party
//! holding a socket to either of them. This is the minimum thing that fixes
//! that: a box that (a) tells a caller how it looks from the outside, and (b)
//! holds an opaque blob at an opaque key for a few seconds so the other peer can
//! pick it up. **It introduces; it never carries data, never decodes an entity
//! payload, and never learns who met whom beyond a hash** (§0).
//!
//! # The shape that matters
//!
//! ```text
//!                    ┌──────────────────────────┐
//!   cross-peer ─────►│  handler.rs  (wrapped)   │─┐
//!   execute          │  capability grant = the  │ │
//!                    │  admission control       │ │   ┌────────────────┐
//!                    └──────────────────────────┘ ├──►│    core.rs     │
//!                    ┌──────────────────────────┐ │   │  the 3 verbs,  │
//!   plain client ───►│  (unwrapped — Stage 2)   │─┘   │  no entity dep │
//!   request          │  rate limits = the whole │     └────────────────┘
//!                    │  admission story         │
//!                    │  + reflect (§1.4) ───────┼──►  owns the socket,
//!                    └──────────────────────────┘     so owns the observation
//! ```
//!
//! `reflect` hangs off the unwrapped listener rather than the core, and that is
//! the whole of ruling 2 (§1.4): it was never an operation on the mailbox.
//!
//! The verbs are the primitive; the entity wrapper is optional (§2). One
//! implementation of them, thin front ends over it — so "both surfaces behave
//! identically" is **structural, not a discipline someone has to maintain**
//! (§2.1). Adding the unwrapped surface later is purely additive; it cannot
//! redefine anything.
//!
//! This states what the handler abstraction is *for*: **the handler supplies the
//! entity wrapper and owns the lifecycle, while the service underneath needs no
//! awareness of the entity system and the entity system needs none of it.**
//!
//! # What ships here (Stage 1)
//!
//! [`core`] (the verbs) + [`handler`] (the wrapped surface). Both are unblocked
//! and neither owns a socket.
//!
//! **Stage 2 is not here and is blocked**, on two things that do not yet exist:
//! `PROPOSAL-SDK-HANDLER-OWNED-SERVICES` (DRAFT; §6 open item 1, the manifest
//! declaration's field shape, "needs a call before impl") for
//! the service-owning lifecycle, and `PROPOSAL-CONNECTION-NODE` §5.1 for the
//! public protocol three client languages must be written against. That is the
//! unwrapped surface and the punch.
//!
//! **Honest limit on Stage 1:** it does *not* produce a connection between two
//! NAT'd peers. It proves mechanism — the verb surface, the bucket semantics,
//! and the key derivation — not connectivity. The both-NAT'd case, the entire
//! motivating problem, needs Stage 2.
//!
//! Stage 1 has **no standalone deliverable beyond the rendezvous mechanism.**
//! It was previously credited with NAT-type detection via `reflect`; ruling
//! 2026-07-28 (§1.4) moved `reflect` to the unwrapped listener, so that value
//! moved to Stage 2 with it. Recorded here rather than quietly dropped — the
//! ruling was right and it made this stage smaller.
//!
//! # Isolation is the deliverable, not just the feature (§3)
//!
//! This crate is optional, imports no other extension, and required **zero edits
//! to `core/peer` or any other shared core crate** — it installs through the
//! public `PeerBuilder::handler()` seam, which already mints the interface
//! entity, the handler entity, the dispatch-index binding, and the §6.9 grant
//! for an externally-supplied handler. See `cmd/entity-signaling-node`.
//!
//! That is a **positive result for the dispatch half** of the §3.1 abstraction
//! test: an ordinary handler really does slot in without special-casing. The
//! finding narrows to **dispatch composes, lifecycle does not** — the
//! service-owning half is the half that fails, and it fails for the reason
//! `PROPOSAL-SDK-HANDLER-OWNED-SERVICES` was written.
//!
//! # Roles (§1.2 — departs from the RELAY precedent, deliberately)
//!
//! `EXTENSION-RELAY` §10.1 makes the service role mandatory for an
//! implementation. Here the **server role is OPTIONAL and the client role is the
//! conformance surface**: RELAY is a peer capability (any peer may relay for a
//! neighbor), while the connection node is deployed infrastructure — nobody will
//! run a Python rendezvous box. Rust implements the server; go/rust/py all
//! implement the client.
//!
//! The stated cost: a single-impl server means **underspecification stays
//! invisible** — one implementation cannot disagree with itself. Mitigated by
//! the §1.1 pins being made in advance, and by three independently-written
//! clients hitting this server from outside.
//!
//! Spec: `../entity-system-architecture/docs/proposals/PROPOSAL-CONNECTION-NODE.md`

pub mod coordination;
pub mod core;
pub mod data;
/// `EXTENSION-SIGNALING.md` §6.3 — the self-contained signed container every
/// coordination blob rides in. The §6.2/§6.3 contradiction, closed.
pub mod envelope;
pub mod handler;
pub mod key;
pub mod pool;
/// §7 punch choreography — substrate-agnostic, so it builds everywhere the
/// coordination layer does (§7.3.1).
pub mod punch;
/// `EXTENSION-SIGNALING.md` §6.5 — the WebRTC substrate's SDP/ICE
/// coordination (the browser leg). Rides the same carrier as §6.1.
pub mod webrtc;

#[cfg(not(target_arch = "wasm32"))]
pub mod client;

#[cfg(test)]
mod tests;

pub use coordination::{
    punch_delay, Candidate, CollectedMessage, ConnectRequest, ConnectResponse, Nonce, PunchSync,
    PUNCH_DELAY_FLOOR_MS,
};
pub use core::{
    Advertisement, CoreError, Limits, OfferOutcome, RendezvousKey, SignalingCore, LOBBY_DEFAULT,
    RENDEZVOUS_KEY_LEN,
};
pub use data::{CollectRequest, CollectResult, OfferRequest};
pub use envelope::{open, open_claimed, parse, seal, SignedBlob, TYPE_SIGNED_BLOB};
pub use handler::SignalingHandler;
pub use key::{lobby_key, pair_key, secret_key, tag_key};
pub use pool::{PoolMember, SKEW_FANOUT};

#[cfg(not(target_arch = "wasm32"))]
pub use client::{ClientError, SignalingClient};

use thiserror::Error;

// ---------------------------------------------------------------------------
// The verb surface (§1) — exactly three verbs, nothing more
// ---------------------------------------------------------------------------

/// The handler pattern, unqualified. Peer-qualified at construction.
pub const PATTERN: &str = "system/signaling";

/// Deposit an opaque blob at an opaque key.
pub const OP_OFFER: &str = "offer";
/// Read what is at a key, removing nothing.
pub const OP_COLLECT: &str = "collect";
/// Announce this node's endpoint and limits.
pub const OP_ADVERTISE: &str = "advertise";

/// Exactly three (§1). This list is the handler's declared operation set and is
/// what `bootstrap_handler` writes into the interface entity.
///
/// **`reflect` is not in it** (§1.4, ruling 2026-07-28) — and its absence has to
/// be visible *here*, because this list is what a peer reads off the interface
/// entity to learn what the node serves. Advertising a verb the wrapped surface
/// answers with an error would be a worse failure than not advertising it: the
/// peer would treat the refusal as a node fault rather than as "wrong surface".
pub const OPERATIONS: &[&str] = &[OP_OFFER, OP_COLLECT, OP_ADVERTISE];

// ---------------------------------------------------------------------------
// Capability surface — the wrapped surface's admission control (§2)
// ---------------------------------------------------------------------------

/// May deposit at a rendezvous key.
pub const CAP_SIGNALING_OFFER: &str = "system/capability/signaling-offer";
/// May read a rendezvous key.
pub const CAP_SIGNALING_COLLECT: &str = "system/capability/signaling-collect";
/// May publish the node's advertisement (typically operator-only).
pub const CAP_SIGNALING_ADVERTISE: &str = "system/capability/signaling-advertise";

/// The caps an operator running a node seeds for its own peers on install —
/// the private-device-mesh lens (§2.1), where a capability grant is the whole
/// point of choosing the wrapped surface.
///
/// **There is deliberately no equivalent for the unwrapped surface.** Its lack
/// of a capability gate is by design, not omission: on public infrastructure a
/// grant handshake buys nothing the rate limiter is not already providing, and
/// costs a round trip plus an entity encode/decode per request.
///
/// There is likewise no `signaling-reflect` cap: `reflect` lives on the
/// unwrapped listener (§1.4), and that surface has no capability gate at all
/// (§2.1). A cap for it would have nowhere to be checked.
pub const SIGNALING_SEED_CAPS: &[&str] = &[
    CAP_SIGNALING_OFFER,
    CAP_SIGNALING_COLLECT,
    CAP_SIGNALING_ADVERTISE,
];

/// The seed-policy grant that lets a peer *use* this node's wrapped surface —
/// [`SIGNALING_SEED_CAPS`] expressed in the shape `PeerBuilder::with_seed_policy`
/// actually consumes.
///
/// **Why this exists as a function.** The constants above name the caps
/// declaratively, the way every extension names its capability surface; nothing
/// enforces a name. What the dispatch layer checks is a `GrantEntry`, and until
/// this function there was no wired path from one to the other. The shipped
/// `entity-signaling-node` therefore granted a connecting peer **nothing** on
/// `system/signaling` — the §4.4 floor is `system/tree:get` + `system/capability:request`,
/// and `request` is pure attenuation, so a caller holding no signaling authority
/// could not mint any. Every foreign call got a 403 before reaching a verb.
/// **Found by the go and py clients independently**, on the first attempt to run
/// the §6 gate against a real node; the in-process live tests missed it because
/// they seed a wildcard, which authorizes everything and so proves nothing about
/// admission.
///
/// **Narrow on purpose.** Exactly [`OPERATIONS`] on exactly [`PATTERN`], with an
/// **empty** resource scope — a signaling EXECUTE carries no resource target
/// (`ExecuteOptions::default()`), so resources are never consulted, and the same
/// shape as the `system/capability:request` entry in `default_connection_grants`
/// is the honest one. A wildcard here would hand every caller every handler on
/// the node, which is what the test harness does and what an operator must not.
///
/// `peers: None` resolves to the local peer, which is this node — the target of
/// every inbound call to it.
pub fn signaling_seed_grants() -> Vec<entity_capability::GrantEntry> {
    vec![entity_capability::GrantEntry {
        handlers: entity_capability::PathScope::new(vec![PATTERN.into()]),
        resources: entity_capability::PathScope::new(vec![]),
        operations: entity_capability::IdScope::new(
            OPERATIONS.iter().map(|op| (*op).to_string()).collect(),
        ),
        peers: None,
        constraints: None,
        allowances: None,
    }]
}

// ---------------------------------------------------------------------------
// Error codes — signaling's own code domain (V7 §3.3)
// ---------------------------------------------------------------------------

/// Params failed to decode, or the rendezvous key was the wrong width — 400.
pub const CODE_INVALID_PARAMS: &str = "invalid_params";
/// Message exceeds `max_message_bytes` — 400.
pub const CODE_MESSAGE_TOO_LARGE: &str = "message_too_large";
/// The key already holds `max_messages_per_key` live messages — 429.
pub const CODE_BUCKET_FULL: &str = "bucket_full";
/// The node is at `max_keys` — 429.
pub const CODE_CAPACITY_EXHAUSTED: &str = "capacity_exhausted";
/// Unknown signaling operation — 400. This is what `reflect` gets on the
/// wrapped surface (§1.4): it is not served here, and "not served here" is an
/// unknown operation, not a distinct failure mode.
pub const CODE_UNKNOWN_OPERATION: &str = "unknown_operation";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Codec-level errors for the entity wrapper. The core's own refusals are
/// [`CoreError`] and are deliberately a separate type — the core does not know
/// entities exist, so it cannot produce or consume these.
#[derive(Debug, Error)]
pub enum SignalingError {
    #[error("signaling entity decode failed: {0}")]
    Decode(String),
    #[error("signaling entity encode failed: {0}")]
    Encode(String),
    /// A §6.5 negotiation was attempted against this peer's own id — which means
    /// §6.4's *skip your own messages* MUST was not applied upstream.
    ///
    /// Loud on purpose. A peer that negotiates with itself "succeeds" at every
    /// individual step, which is exactly the failure §6.4 calls miserable to
    /// diagnose. Matches `entity-core-go`'s `ErrSelfNegotiation`
    /// (`ext/signaling/webrtc.go`) so the two impls refuse the same input.
    #[error("negotiation against own peer_id (§6.4 skip-own was not applied)")]
    SelfNegotiation,
    /// §6.3 check (a) failed: the `public_key` does not derive the claimed
    /// peer-id, so the message does not belong to who it says it does.
    ///
    /// **Reserved for a claim comparison** — the §6.1 payloads that name their
    /// own `initiator`/`responder` (envelope step 3). A key that cannot be
    /// bound to its `signer` at all is [`Self::UnusableKey`], not this: the
    /// cohort taxonomy separates *"this is not who it says it is"* from
    /// *"this key cannot be used to answer the question."*
    #[error("public_key does not derive the claimed peer_id (§6.3)")]
    SignerMismatch,
    /// The signer's key cannot be used: an unallocated or sign-incapable
    /// `key_type`, a `public_key` whose length does not match it, or a `signer`
    /// that is not the **canonical** id for `(public_key, key_type)` — the
    /// last including a well-formed but non-canonical `hash_type`.
    ///
    /// **A well-formed unsupported `key_type` lands here and is skipped**, not
    /// rejected: ADR-0002 MUST-ignore. Hardcode-rejecting it is the exact Ed448
    /// defect a cross-impl vector caught in this crate — a fail-closed path
    /// that silently locked out an identity this codebase mints. The label is
    /// for diagnostics and conformance vectors only; on the wire every failure
    /// here is an undecodable blob (§6.4) and nothing more.
    #[error("signer key unusable — bad key_type, key length, or non-canonical signer (§6.3)")]
    UnusableKey,
    /// §6.3 check (b) failed: the signature does not verify over the entity's
    /// content hash.
    #[error("signature does not verify over the entity content hash (§6.3)")]
    BadSignature,
    /// A caller tried to take SDP out of an entity whose signature was never
    /// verified — the §6.5 channel-identity MUST, refused at the type level.
    #[error("refusing to release SDP from an unverified entity (§6.5)")]
    UnverifiedSdp,
}
