#![cfg(target_arch = "wasm32")]
//! Wire protocol shared between `wasm-worker-host` (worker side) and
//! `wasm-worker-proxy` (main-thread side).
//!
//! # Boundary rule (normative for contributors)
//!
//! This crate's enums (`Request`, `Response`, `Event`) are a **serializable
//! shadow of the SDK's L1 method signatures, nothing more**. Adding a variant
//! means a corresponding SDK method already exists (or is being added in
//! lock-step). Cross-cutting concerns — auth, retry, idempotency, batching,
//! caching semantics — belong in the SDK (so in-process consumers get them
//! too) or in the proxy/host pair (so they are transport-specific). They
//! **MUST NOT** be added in this crate. This crate exists to ferry typed
//! messages, not to define semantics.
//!
//! **Typed enums for discriminants are within bounds.** `WireErrorKind` and
//! `CasFailureKind` shadow `SdkError`'s and `CasError`'s discriminants — that
//! is mirroring the SDK signature faithfully, not adding cross-cutting
//! behavior. Stringly-typed `kind: String` was an earlier draft; reverted
//! after Phase 1 protocol review per egui-team push-back.
//!
//! See the worker-migration design notes for the boundary rule rationale
//! and the Phase 1 protocol review for the resolution of Q1-S3.
//!
//! # Versioning (R1)
//!
//! [`PROTOCOL_VERSION`] is bumped whenever the wire shape of any variant
//! changes. The worker posts `Response::Ready { protocol_version, sdk_version }`
//! on init; the proxy verifies match and fails fast on mismatch. The proxy
//! and host ship together.
//!
//! # Multi-peer addressing
//!
//! Every peer-scoped `Request` carries an explicit `peer_id: String` field
//! (per S1 — Option C: one worker hosts multiple peers via the existing
//! `EntitySDK` BTreeMap). Subscriptions are prefix-qualified so peer is
//! inferred from the prefix and no separate field is needed there.

use serde::{Deserialize, Serialize};

#[cfg(feature = "conversions")]
pub mod conversions;

/// Wire-protocol version. Bumped on any wire-shape change.
///
/// **v12:** the establisher-install report, so "I asked for WebRTC and the
/// worker installed it" stops being an inference. `WireCaps.webrtc_peers:
/// Vec<String>` names the Init-time peers that got a §6.5 establisher;
/// `CreatePeerOk.webrtc_active: bool` reports the same for a peer created
/// later. Both `#[serde(default)]`.
///
/// A **list**, not the worker-level bool that was proposed: v11 made the
/// enable decision per-peer, so a single flag cannot say "the primary has it,
/// this additional peer does not" — and answering a per-peer question with one
/// worker-wide value is the v6 Subscribe collapse restated. On `CreatePeerOk`
/// a bool *is* right, because that response is about exactly one peer.
///
/// This is a report, not a new failure mode: `webrtc_enabled` that cannot be
/// honoured still fails Init/CreatePeer loudly (v11). What was missing is the
/// affirmative signal in the **success** path — the same reason `opfs_active`
/// exists at v8, and the reason `entity-browser-rust` could not observe the
/// install at all.
///
/// **v11:** `InitParams.webrtc: Option<WireWebRtcConfig>` and per-peer
/// `webrtc_enabled: bool`. Provisions the §6.5 WebRTC establisher at the
/// §10.3 seam: signaling-node target, ICE servers, negotiation tunables.
/// Absent = unchanged v10 behaviour (no establisher installed). Enable is
/// per-peer and defaults to false — never inferred from config presence,
/// per the v6 lesson. v10 proxies fail fast via the `PROTOCOL_VERSION`
/// handshake.
///
/// Ruled with `entity-browser-rust`
/// (`docs/status/ROUTING-2026-08-03-provisioning-payload-for-codesign-to-browser-rust.md`
/// → their provisioning ruling): Init-time only, no
/// `Request::ProvisionWebRtc` — `live_establish` is installed at peer
/// **build**, and enabling WebRTC on an already-built peer would mean
/// mutating §10.3 policy while a dispatch could be consulting it. If a
/// "user toggles P2P on" flow ever lands, the path is destroy+recreate the
/// peer webrtc-enabled, not a mutate-in-place setter.
///
/// Note this bump is independent of `CONTROL_PROTOCOL_VERSION`, which went
/// 1 → 2 in the same change to carry `ice_servers` on `WebRtcOpen`. Two
/// planes, two versions: this one is app → worker, that one is worker →
/// broker.
///
/// **v10:** `Request::DisconnectPeer { peer_id, remote_peer_id }` (+ matching
/// `Response::DisconnectPeer`) evicts a pooled outbound connection inside the
/// worker so the next dial re-handshakes fresh — the way a peer adopts a
/// capability grant authored *after* it connected (the granter re-mints at
/// authenticate; a pooled reuse keeps the stale cap). Like
/// `SetInspectEnabled`, it is NOT in `REQUEST_VARIANT_NAMES` — it has no SDK
/// L1 counterpart (a worker-side connection control, not an SDK method).
/// Bumped even though the variant introduces no new argument *types*: the
/// proxy/host handshake compares versions for equality, so without a bump a
/// proxy that sends `DisconnectPeer` and a host that has never heard of it
/// both report `9` and the mismatch escapes the version check to fail at
/// decode instead.
///
/// **v9:** Inspect-hook plumbing per the upstream inspect-worker-arm design.
/// Adds `Event::Inspect { peer_id, fact }` carrying the marshalled
/// `InspectFact` (Dispatch / Wire / Binding variants) and
/// `Request::SetInspectEnabled { peer_id, enabled }` (+ matching
/// `Response::SetInspectEnabled`) so consumers can flip per-peer
/// marshalling on/off. Default off per §9 q1 — peers with no attached
/// sink pay zero marshal cost. Wire and binding facts carry frame
/// length + path metadata only; body retrieval is a deferred follow-on
/// (§9 q2). The new request is NOT in `REQUEST_VARIANT_NAMES` — it has
/// no SDK L1 counterpart (a worker-side toggle, not an SDK method).
///
/// **v8:** `Response::Ready` gains
/// `actual_capabilities: Option<WireCaps>` so the proxy gets an affirmative
/// "OPFS came up" signal rather than inferring it through retry gymnastics.
/// `WireCaps.opfs_active = true` iff `InitParams.opfs_root` was `Some` and
/// `build_async()` succeeded — note the host does NOT do silent
/// OPFS-to-memory fallback; OPFS init failure surfaces via
/// `Response::Init { result: Some(err) }` and `Ready` is never posted in
/// that path. The new field uses `#[serde(default)]` so v7 hosts that
/// don't emit it deserialize as `None`; the version handshake catches the
/// mismatch fail-fast anyway. Stage 3 UI on the consumer side reads this
/// to surface requested-vs-actual peer mode. See the upstream asks (Ask 1).
///
/// **v7:** `InitParams.enable_opfs: bool` replaced with
/// `InitParams.opfs_root: Option<String>` — clean break so multiple
/// OPFS-backed workers can coexist in one origin under distinct
/// subdirectories. `None` = no OPFS; `Some("")` = OPFS root (single-
/// instance legacy); `Some("peer-…")` = per-instance subdir.
/// `createSyncAccessHandle` is exclusive per file, so two stores rooted
/// at the same directory collide on `entities.log` — the new field exists
/// precisely to give each worker its own root. v6 proxies fail fast via
/// the version handshake. See the worker-migration design notes
/// (Appendix D) for the landed history.
///
/// **v6:** `Request::Subscribe` gains explicit `peer_id`.
/// The host previously hardcoded `default_peer_id` regardless of which
/// peer the subscription targeted, so any non-primary-peer window saw
/// the initial Snapshot (built from the shared store) but never any
/// Change events (registered on the wrong peer's L1 engine). v5→v6
/// `#[serde(default)]` lets old proxies be detected via empty peer_id;
/// the version handshake catches it cleanly anyway. See the
/// subscribe peer-scoping design notes.
///
/// **v5:** Wire-surface closeout — `Request::SetMetadata`
/// (Parity-C) and `Request::ConnectPeer` (Parity-D-narrow). SetMetadata
/// reuses `WirePeerMetadata` from v4. ConnectPeer adds `ConnectPeerOk
/// { remote_peer_id }` and wraps `Peer::connect_to(addr)`. After this,
/// the worker-mode wire surface fully mirrors what `PeerContext` exposes
/// in Direct mode. See the wire-surface closeout design notes.
///
/// **v4:** Worker-mode peer management parity. Adds
/// `Request::{CreatePeer, DeletePeer}` + `Response::{CreatePeer, DeletePeer}`
/// with the `CreatePeerOk { peer_id, keypair_seed, metadata }` shape —
/// generated seed round-trips to the consumer for localStorage
/// persistence. `WireQueryResults` gains `total` + `cursor`;
/// `WireQueryMatch` gains `entity_type`. All new fields use
/// `#[serde(default)]` for v3→v4 backcompat. See the Phase 3
/// worker-parity remainder design notes.
///
/// **v3:** `InitParams` gained `enable_opfs: bool`. When
/// `true`, the worker host builds its SDK with OPFS-backed durable
/// storage (`PeerBuilder::opfs().await`); default `false` preserves
/// the prior in-memory behavior. See the Phase 2 OPFS-wiring design notes.
///
/// **v2:** `Response::{Init, RegisterBackendPeer, Subscribe,
/// Unsubscribe}` changed from `result: Result<(), WireError>` to
/// `result: Option<WireError>`. Reason: ciborium's deserializer for
/// `()` from CBOR `null` is asymmetric — serde's encoder produces
/// `{ "Ok": null }`, the decoder rejects it. `Option<WireError>` round-trips
/// cleanly (None = success, Some = failure). Documented in the Phase 3
/// pilot status notes (§#1) with full hex evidence.
pub const PROTOCOL_VERSION: u32 = 12;

/// `Request` variants that mirror an L1 SDK method. Ordering must match
/// `entity_sdk::L1_WORKER_MIRRORED_SURFACE` — the [coverage check](crate)
/// fires a compile-time assertion if they diverge.
///
/// **What belongs in this list:** any `Request` variant that exists to
/// shadow a public `entity_sdk` L1 method (`Get`, `Put`, `Query`, etc.,
/// plus `Subscribe` / `Unsubscribe`).
///
/// **What does not belong:** wire-only primitives that have no SDK
/// counterpart (`Init`, `RegisterBackendPeer`). These exist solely on the
/// wire and are not part of the mirrored L1 surface; they are exempt from
/// the coverage check. See `CONTRIBUTING.md` boundary cases.
pub const REQUEST_VARIANT_NAMES: &[&str] = &[
    "Get",
    "Put",
    "PutCas",
    "List",
    "Remove",
    "Has",
    "Execute",
    "Query",
    "Count",
    "EntityCount",
    "PathCount",
    "InboxList",
    "InboxGet",
    "DiscoverHandlers",
    "DiscoverTypes",
    "Subscribe",
    "Unsubscribe",
];

// ---------------------------------------------------------------------------
// Drift-protection: compile-time coverage assertion
//
// This fires on `cargo check --target wasm32-unknown-unknown -p
// entity-wasm-worker-protocol`. If the SDK's declared worker-mirrored
// surface drifts from this crate's Request variant list, the build fails
// with the const-eval message — naming both lists and pointing to
// CONTRIBUTING.md.
//
// What this catches:
//   - Variant added to one list but not the other (most common drift).
//   - Lists same length but contents differ (typo, ordering drift).
//
// What this does NOT catch:
//   - SDK method added without anyone updating L1_WORKER_MIRRORED_SURFACE.
//     The CONTRIBUTING.md checklist is the cultural mechanism for that
//     gap. Reviewers checking SDK-modifying PRs should verify the four
//     sites were all updated.
// ---------------------------------------------------------------------------

// Used by the const _COVERAGE_CHECK_… assertion below. Rust's dead-code
// analysis doesn't trace through `const _` items, so allow the warning.
#[allow(dead_code)]
const fn str_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[allow(dead_code)]
const fn arrays_match(a: &[&str], b: &[&str]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if !str_eq(a[i], b[i]) {
            return false;
        }
        i += 1;
    }
    true
}

const _COVERAGE_CHECK_L1_SURFACE_MATCHES_PROTOCOL: () =
    assert!(
    arrays_match(entity_sdk::L1_WORKER_MIRRORED_SURFACE, REQUEST_VARIANT_NAMES),
    "wasm-worker-protocol Request variants do not match entity_sdk::L1_WORKER_MIRRORED_SURFACE. \
     See bindings/wasm-worker-protocol/CONTRIBUTING.md for the four-site checklist."
);

/// Correlation ID for matching a `Response` to its originating `Request`.
pub type RequestId = u64;

/// Subscription ID for routing `Event`s on the main thread back to the
/// originating subscriber's channel.
pub type SubId = u64;

// ---------------------------------------------------------------------------
// Wire types
//
// Phase 1 status: shapes finalized per protocol-review convergence (Q1, Q2,
// Q3, S1, S2). Payload bodies for not-yet-mirrored methods are still
// placeholders pending the broader L1 surface scaffolding (count,
// history_query, history_rollback, etc.) — added incrementally as their
// proxy_method! invocations land.
// ---------------------------------------------------------------------------

/// Content hash on the wire: `format varint || digest`, at whatever width
/// that leading format implies (33 bytes under ECFv1-SHA-256, 49 under
/// ECFv1-SHA-384 — worked instances, not a pin; SPECIFICATION-FORMAT
/// §8.4.5). Same layout as `entity_hash::Hash::to_bytes()`. Sent as a CBOR
/// byte string via `serde_bytes` to avoid array-of-int encoding bloat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireHash(#[serde(with = "serde_bytes")] pub Vec<u8>);

/// Q1 resolution (per protocol-review): keep `content_hash` on the wire. The
/// host has it for free (the SDK computes it on every dispatch return); the
/// consumer uses it directly in dedup / change-detection paths. Forcing
/// SHA-256 recomputation on every cache update is per-frame CPU work for a
/// 32-byte wire saving — not worth it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireEntity {
    pub entity_type: String,
    /// Raw CBOR-encoded body. Byte-string on the wire (serde_bytes), not an
    /// array of u8 ints — important for size on burst-traffic snapshots.
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
    /// Worker-computed content hash. Consumer trusts this for routine reads;
    /// hash verification (if a consumer wants it) is opt-in and recomputes.
    pub content_hash: WireHash,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WireExecuteOptions {
    pub resource_targets: Vec<String>,
    pub resource_exclude: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireHandlerResult {
    pub status: u32,
    pub result: WireEntity,
    /// Envelope `included` entities, if any. Keyed by content hash.
    pub included: Vec<(WireHash, WireEntity)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireQueryResults {
    pub matches: Vec<WireQueryMatch>,
    pub has_more: bool,
    /// Total number of matches in the underlying index (pre-pagination).
    /// `#[serde(default)]` for v3→v4 backcompat — older hosts ship 0.
    #[serde(default)]
    pub total: u64,
    /// Opaque pagination cursor; pass to a follow-up query to resume.
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireQueryMatch {
    pub path: String,
    pub content_hash: WireHash,
    pub entity: Option<WireEntity>,
    /// Entity type of the match (e.g. `"app/article"`). Mirrors
    /// `entity_sdk::QueryMatch.entity_type`. `#[serde(default)]` for
    /// v3→v4 backcompat — older hosts ship an empty string.
    #[serde(default)]
    pub entity_type: String,
}

// ---------------------------------------------------------------------------
// Error types — Q2/Q3 resolution: typed discriminants, not stringly-typed.
//
// Shadows SdkError's variant set without dragging in SdkError's internal
// payloads. New SdkError variant → parallel WireErrorKind variant + protocol
// version bump. Same discipline as the rest of the wire protocol.
// ---------------------------------------------------------------------------

/// Discriminant for `WireError`. Mirrors `entity_sdk::SdkError` variant kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireErrorKind {
    NotFound,
    CapabilityDenied,
    TreeError,
    HandlerError,
    Cas,
    InvalidParams,
    /// Forward-compat slot for SDK variants the protocol version doesn't yet
    /// model. Should be rare given the version handshake catches mismatches
    /// at boot, but useful for SDK-internal "unexpected" errors that the
    /// worker can't classify.
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireError {
    pub kind: WireErrorKind,
    /// Human-readable; not load-bearing for control flow. For logging /
    /// surfacing to the user.
    pub message: String,
    /// Optional kind-specific structured carry. CBOR `Value` so any
    /// serializable payload survives the wire. Most variants leave this
    /// `None`; `Cas` uses it (alternatively via `CasFailure`, see Q3).
    pub detail: Option<ciborium::Value>,
}

/// Discriminant for CAS failures. Q3 resolution: typed enum, not strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CasFailureKind {
    Mismatch,
    NotFound,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CasFailure {
    pub kind: CasFailureKind,
    /// Present on `Mismatch` with the actual current hash. Absent for `NotFound`.
    pub actual: Option<WireHash>,
}

// ---------------------------------------------------------------------------
// Init / handshake (S2)
//
// Worker boots, awaits `Request::Init`, applies params, posts
// `Response::Ready`. Subsequent Requests are accepted only after Ready.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedPeer {
    pub peer_id: String,
    /// 32-byte Ed25519 keypair seed. Stays main-thread-derived; passed to
    /// worker via init message per R10b ("pass-on-init").
    #[serde(with = "serde_bytes")]
    pub keypair_seed: Vec<u8>,
    pub label: Option<String>,
    /// v11. Install the §6.5 WebRTC establisher at this peer's §10.3 seam.
    ///
    /// **Explicit, per-peer, and defaults to false** — never inferred from
    /// "`InitParams.webrtc` is present" and never "the primary gets it."
    /// This is the v6 Subscribe lesson applied before it can bite: that bug
    /// was a host hardcoding `default_peer_id` regardless of which peer a
    /// request targeted, with every visible step still reporting success. A
    /// worker-wide config that silently installed an establisher on every
    /// peer is the same shape, and the thing it would silently confer is a
    /// dependency on a signaling node.
    ///
    /// Requires `InitParams.webrtc` to be `Some`; true with no config is a
    /// provisioning error the host reports rather than ignores.
    #[serde(default)]
    pub webrtc_enabled: bool,
}

/// v11. Worker-level provisioning for the §6.5 WebRTC establisher.
///
/// Carried on [`InitParams`]; which peers actually get an establisher is the
/// separate per-peer [`PersistedPeer::webrtc_enabled`] decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireWebRtcConfig {
    /// The signaling node's peer-id. Required — the carrier authenticates
    /// the node, so an address alone would be an unauthenticated rendezvous.
    pub node_peer_id: String,
    /// Its address, browser-reachable (`ws://` / `wss://`). A browser cannot
    /// open a raw TCP socket, so a node that binds TCP only is unreachable
    /// here no matter what this says — see the node's `--ws-listen`.
    pub node_addr: String,
    /// ICE servers for the browser's own ICE agent.
    ///
    /// **Empty is legal and means host-candidates-only** — a LAN-only
    /// deployment — rather than "use a default". A silent public-STUN
    /// default would enroll a third party on the operator's behalf,
    /// invisibly; keeping the emptiness on the wire makes it a stated
    /// deployment fact instead of an inferred one.
    ///
    /// This is the browser analogue of the native reflector/relay pool and
    /// **only** an analogue: a browser ICE agent speaks `stun:`/RFC 5389 and
    /// cannot be pointed at our entity `observe-address` node. Two browsers
    /// across real NATs need a real STUN server — operator infra, the
    /// browser leg's equivalent of native G4.
    #[serde(default)]
    pub ice_servers: Vec<WireIceServer>,
    /// §6.5 negotiation tunables. Absent = the impl's defaults.
    #[serde(default)]
    pub poll_interval_ms: Option<u64>,
    /// Ceiling for one negotiation. §10.3's deadline is the caller's, so
    /// this only ever *shortens* what `EstablishCtx` already allows.
    #[serde(default)]
    pub max_deadline_ms: Option<u64>,
}

/// v11. One ICE server for the browser's ICE agent.
///
/// Structurally parallel to `entity_peer::transport::WireIceServer`, which is
/// what actually reaches `RTCConfiguration` on the control plane. Kept
/// separate rather than shared because this crate is a deliberately decoupled
/// serializable shadow of the SDK surface; the host converts at the boundary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WireIceServer {
    /// `stun:` / `turn:` / `turns:` URLs for one logical server.
    pub urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandlerSpec {
    /// Handler URI pattern (e.g. "system/tree", "system/inbox"). The worker
    /// host's binary statically wires handler bodies; this list selects
    /// which compiled-in handlers to register.
    pub pattern: String,
}

/// Peer metadata on the wire. Mirrors `entity_sdk::PeerMetadata`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WirePeerMetadata {
    pub label: Option<String>,
    pub persisted: bool,
    pub listen_addresses: Vec<String>,
}

/// Success payload for `Request::CreatePeer`.
///
/// `keypair_seed` is the freshly-generated 32-byte Ed25519 secret —
/// returned so the consumer can persist it (e.g. localStorage) for
/// reload survival. The host does not retain it server-side; the
/// peer is reconstructed from the seed on the next `Init`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePeerOk {
    pub peer_id: String,
    #[serde(with = "serde_bytes")]
    pub keypair_seed: Vec<u8>,
    pub metadata: WirePeerMetadata,
    /// v12. Whether this peer got a §6.5 WebRTC establisher.
    ///
    /// A bool is the right shape *here* — unlike [`WireCaps::webrtc_peers`],
    /// this response is about exactly one peer, so there is no "which one?"
    /// left to be silent about.
    #[serde(default)]
    pub webrtc_active: bool,
}

/// Success payload for `Request::ConnectPeer`. Carries the remote peer's
/// identifier (derived from the entity-protocol handshake during
/// `Peer::connect_to`), which the consumer uses to construct
/// `entity://{remote_peer_id}/...` URIs for subsequent dispatches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectPeerOk {
    pub remote_peer_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitParams {
    pub primary_peer: PersistedPeer,
    pub additional_peers: Vec<PersistedPeer>,
    /// Handler set to register at boot. Per R7: handlers are baked into the
    /// worker-host binary; this list selects which of the compiled-in
    /// handlers to actually register for this consumer instance.
    pub handlers: Vec<HandlerSpec>,
    /// When `Some(root)`, the worker host backs its SDK with OPFS-backed
    /// durable storage rooted at the named OPFS subdirectory. Empty string
    /// uses the OPFS root directly (single-instance legacy). Multiple
    /// OPFS-backed workers in the same origin MUST use distinct roots —
    /// `createSyncAccessHandle` is exclusive per file. The host's build
    /// must enable `entity-sdk/wasm-persist`; otherwise it's a build-time
    /// configuration mismatch that the host detects at init.
    ///
    /// `#[serde(default)]` so v6 proxies (which don't know about this
    /// field) still deserialize; they'll be rejected by the
    /// PROTOCOL_VERSION handshake before any field is consulted.
    #[serde(default)]
    pub opfs_root: Option<String>,
    /// v11. Worker-level WebRTC provisioning.
    ///
    /// `None` = no establisher is installed on any peer, which is exactly
    /// v10 behaviour. Present-but-no-peer-enabled is also legal and inert:
    /// the config is the *capability*, `webrtc_enabled` is the *decision*.
    #[serde(default)]
    pub webrtc: Option<WireWebRtcConfig>,
}

/// Reports which optional kernel features actually wired up inside the
/// worker. Carried on `Response::Ready`. Reaching the Ready branch means
/// `build_async()` succeeded; the booleans then say which of the
/// optional capabilities the consumer requested came up.
///
/// **No silent fallback.** If the consumer asked for a capability and
/// the worker couldn't provide it, the host returns
/// `Response::Init { result: Some(err) }` and Ready is never posted.
/// `WireCaps` exists to give the consumer an affirmative "I have this"
/// signal in the success path so they don't have to infer it via retry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireCaps {
    /// `true` iff `InitParams.opfs_root` was `Some` and the SDK build
    /// completed (which implies OPFS handle acquisition succeeded —
    /// failure would have produced `Response::Init` with an error).
    pub opfs_active: bool,
    /// v12. The peer-ids that actually had a §6.5 WebRTC establisher
    /// installed at their §10.3 seam.
    ///
    /// **A list and not a bool, because the capability is per-peer.** A
    /// worker-level `webrtc_active: bool` cannot express "the primary has it,
    /// this additional peer does not" — and answering a per-peer question with
    /// one worker-wide flag is the exact collapse the v6 Subscribe bug was
    /// (a host answering "which peer?" with "the default one"). v11 made the
    /// enable decision per-peer; the report has to be per-peer or it cannot be
    /// checked against what was asked.
    ///
    /// The consumer knows which peers it flagged, so this is diffable: a peer
    /// in your `webrtc_enabled` set and absent here did not get one. Today
    /// that set difference is always empty — the host refuses Init outright
    /// rather than installing nothing — but "it cannot happen" is precisely
    /// the claim a report exists to stop having to take on faith.
    ///
    /// Init-time peers only. A peer created later reports via
    /// [`CreatePeerOk::webrtc_active`].
    #[serde(default)]
    pub webrtc_peers: Vec<String>,
}

// ---------------------------------------------------------------------------
// Request / Response / Event
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum Request {
    /// Worker initialization. Must be the first Request after spawn; worker
    /// rejects other Requests until Init completes and Ready has been posted.
    Init {
        request_id: RequestId,
        params: InitParams,
    },
    /// Register a peer the worker should treat as accessible at the given
    /// addresses (today's Tauri-backend-peer flow). Metadata-only — no local
    /// PeerContext is created; the SDK's connection pool reaches the peer
    /// via the listed addresses on demand. See `bindings/sdk/src/peer_manager.rs:188-206`.
    RegisterBackendPeer {
        request_id: RequestId,
        peer_id: String,
        label: Option<String>,
        listen_addresses: Vec<String>,
    },

    /// Create a new peer with a freshly-generated keypair. The worker
    /// host calls `Keypair::generate()` (browser `getrandom` works in
    /// the worker), constructs the peer via the SDK, and returns the
    /// seed inline so the consumer can persist it for reload survival.
    CreatePeer {
        request_id: RequestId,
        label: Option<String>,
        /// v11. Whether this newly-created peer gets the §6.5 establisher.
        ///
        /// On `CreatePeer` as well as `PersistedPeer` deliberately: a peer
        /// created after Init opts in at *its* creation and cannot inherit a
        /// capability nobody asked for. That is the whole reason the enable
        /// decision is per-peer rather than worker-wide.
        #[serde(default)]
        webrtc_enabled: bool,
    },

    /// Delete a peer by id. Returns false-equivalent (in `Response::DeletePeer.result`)
    /// if the id doesn't exist or is the primary peer (per SDK semantics).
    DeletePeer {
        request_id: RequestId,
        peer_id: String,
    },

    /// Update an existing peer's metadata (label, listen_addresses,
    /// persisted flag). Wraps `EntitySDK::set_metadata`. v5+.
    SetMetadata {
        request_id: RequestId,
        peer_id: String,
        metadata: WirePeerMetadata,
    },

    /// Open an outgoing connection from `peer_id` (local) to a remote
    /// peer at `address` (typically `ws://...` or `wss://...` in browser
    /// worker mode) and perform the entity-protocol handshake. Returns
    /// the remote peer's identifier on success. v5+.
    ///
    /// The connection is pooled inside the worker; subsequent
    /// `execute()` calls against `entity://{remote_peer_id}/...` URIs
    /// reuse it.
    ConnectPeer {
        request_id: RequestId,
        peer_id: String,
        address: String,
    },

    /// Evict a pooled outbound connection from `peer_id` (local) to
    /// `remote_peer_id`, closing the socket and dropping the pool entry.
    /// The next `ConnectPeer`/`execute` re-dials and re-handshakes fresh —
    /// which is how a peer adopts a capability grant authored *after* it
    /// connected (the granter re-mints at authenticate; a pooled reuse keeps
    /// the stale cap). No-op if no such connection is pooled. v6+.
    DisconnectPeer {
        request_id: RequestId,
        peer_id: String,
        remote_peer_id: String,
    },

    // -- Tree dispatched (S1: peer_id on every variant) --
    Get {
        request_id: RequestId,
        peer_id: String,
        path: String,
    },
    Put {
        request_id: RequestId,
        peer_id: String,
        path: String,
        entity: WireEntity,
    },
    PutCas {
        request_id: RequestId,
        peer_id: String,
        path: String,
        entity: WireEntity,
        expected: WireHash,
    },
    List {
        request_id: RequestId,
        peer_id: String,
        prefix: String,
    },
    Remove {
        request_id: RequestId,
        peer_id: String,
        path: String,
    },
    Has {
        request_id: RequestId,
        peer_id: String,
        path: String,
    },

    // -- Generic dispatch --
    Execute {
        request_id: RequestId,
        peer_id: String,
        handler: String,
        operation: String,
        params: WireEntity,
        opts: WireExecuteOptions,
    },

    // -- Query --
    Query {
        request_id: RequestId,
        peer_id: String,
        expression: WireEntity,
    },
    Count {
        request_id: RequestId,
        peer_id: String,
        expression: WireEntity,
    },

    // -- Metadata --
    EntityCount {
        request_id: RequestId,
        peer_id: String,
    },
    PathCount {
        request_id: RequestId,
        peer_id: String,
    },

    // -- Inbox --
    InboxList {
        request_id: RequestId,
        peer_id: String,
    },
    InboxGet {
        request_id: RequestId,
        peer_id: String,
        relative_path: String,
    },

    // -- Discovery --
    DiscoverHandlers {
        request_id: RequestId,
        peer_id: String,
    },
    DiscoverTypes {
        request_id: RequestId,
        peer_id: String,
    },

    // -- Inspect (v9+) --
    //
    // Flips whether the worker host marshals inspect facts for `peer_id`.
    // Default-off — peers with no attached sink pay zero marshal cost.
    // The consumer (via the SDK) sends this when it installs the first
    // inspect sink for a peer, and again with `enabled: false` when the
    // last sink detaches. Unknown peer ids return an error.
    SetInspectEnabled {
        request_id: RequestId,
        peer_id: String,
        enabled: bool,
    },

    // -- Subscriptions --
    //
    // `peer_id` (v6+): the local peer whose dispatch engine the callback
    // is registered against. Writes through *other* peers fire their own
    // engines independently; a subscription is bound to exactly one peer.
    // (#[serde(default)] for v5→v6 backcompat: empty string falls back to
    // SDK default_peer_id with a tracing warning at the host.)
    //
    // `prefix` semantics (Unix-style):
    //   - trailing slash → subtree match. `/peer/app/` fires for any write
    //     to a path starting with `/peer/app/`.
    //   - no trailing slash → exact-path match. `/peer/app/state` fires
    //     only for writes to that exact path.
    //   - already `/*`-terminated or the universal `*` → passed through.
    //
    // The host translates this into the SDK's pattern syntax; see
    // `wasm-worker-host::prefix_to_pattern`.
    Subscribe {
        request_id: RequestId,
        sub_id: SubId,
        #[serde(default)]
        peer_id: String,
        prefix: String,
    },
    Unsubscribe {
        request_id: RequestId,
        sub_id: SubId,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum Response {
    /// Posted by worker after `Request::Init` completes. Carries the
    /// protocol-version handshake (R1). Proxy verifies version match; on
    /// mismatch, fails fast.
    ///
    /// `actual_capabilities` (v8+) reports which optional kernel features
    /// actually wired up inside the worker. `None` means an older host
    /// (v7) is sending Ready without this field — the version handshake
    /// will reject before the field is consulted, so a real consumer
    /// only sees `Some` in practice.
    Ready {
        request_id: RequestId,
        protocol_version: u32,
        sdk_version: String,
        #[serde(default)]
        actual_capabilities: Option<WireCaps>,
    },
    /// Init outcome. `None` = success (worker fully initialized; `Ready`
    /// is the success-success signal). `Some(err)` = init failed.
    ///
    /// Was `Result<(), WireError>` in PROTOCOL_VERSION=1; changed to
    /// `Option<WireError>` to work around ciborium's unit-from-null
    /// asymmetry. See `PROTOCOL_VERSION` doc.
    Init {
        request_id: RequestId,
        result: Option<WireError>,
    },
    RegisterBackendPeer {
        request_id: RequestId,
        result: Option<WireError>,
    },

    CreatePeer {
        request_id: RequestId,
        result: Result<CreatePeerOk, WireError>,
    },

    DeletePeer {
        request_id: RequestId,
        /// `None` on success (peer removed). `Some(err)` on failure
        /// (peer didn't exist, or was the primary peer — per SDK).
        result: Option<WireError>,
    },

    SetMetadata {
        request_id: RequestId,
        /// `None` on success. `Some(err)` on unknown peer_id or
        /// other SDK rejection.
        result: Option<WireError>,
    },

    ConnectPeer {
        request_id: RequestId,
        result: Result<ConnectPeerOk, WireError>,
    },

    /// `None` on success (connection evicted, or none was pooled — both are
    /// success); `Some(err)` on unknown local peer_id or SDK rejection.
    DisconnectPeer {
        request_id: RequestId,
        result: Option<WireError>,
    },

    Get {
        request_id: RequestId,
        result: Result<Option<WireEntity>, WireError>,
    },
    Put {
        request_id: RequestId,
        result: Result<WireHash, WireError>,
    },
    PutCas {
        request_id: RequestId,
        /// Inner `Result` distinguishes CAS failure (typed via `CasFailure`)
        /// from generic error (everything else, via `WireError`).
        result: Result<Result<WireHash, CasFailure>, WireError>,
    },
    List {
        request_id: RequestId,
        result: Result<Vec<WireListingEntry>, WireError>,
    },
    Remove {
        request_id: RequestId,
        result: Result<bool, WireError>,
    },
    Has {
        request_id: RequestId,
        result: Result<bool, WireError>,
    },

    Execute {
        request_id: RequestId,
        result: Result<WireHandlerResult, WireError>,
    },

    Query {
        request_id: RequestId,
        result: Result<WireQueryResults, WireError>,
    },
    Count {
        request_id: RequestId,
        result: Result<u64, WireError>,
    },

    EntityCount {
        request_id: RequestId,
        result: Result<u64, WireError>,
    },
    PathCount {
        request_id: RequestId,
        result: Result<u64, WireError>,
    },

    InboxList {
        request_id: RequestId,
        result: Result<Vec<WireListingEntry>, WireError>,
    },
    InboxGet {
        request_id: RequestId,
        result: Result<Option<WireEntity>, WireError>,
    },

    DiscoverHandlers {
        request_id: RequestId,
        result: Result<Vec<WireHandlerInfo>, WireError>,
    },
    DiscoverTypes {
        request_id: RequestId,
        result: Result<Vec<WireTypeInfo>, WireError>,
    },

    Subscribe {
        request_id: RequestId,
        result: Option<WireError>,
    },
    Unsubscribe {
        request_id: RequestId,
        result: Option<WireError>,
    },

    /// `None` on success. `Some(err)` when the peer id is unknown.
    SetInspectEnabled {
        request_id: RequestId,
        result: Option<WireError>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireListingEntry {
    pub path: String,
    pub content_hash: WireHash,
}

// ---------------------------------------------------------------------------
// Discovery wire types — mirrors of entity_sdk::HandlerInfo / TypeInfo /
// FieldInfo. These are descriptive metadata the SDK already collects from
// the peer's tree (SDK-OPERATIONS §9.1, §9.2); the wire shape just carries
// them across.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireHandlerInfo {
    pub pattern: String,
    pub name: String,
    pub operations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireTypeInfo {
    pub type_path: String,
    pub fields: Vec<WireFieldInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireFieldInfo {
    pub name: String,
    pub type_ref: String,
    pub optional: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Event {
    /// Initial state delivered when a subscription is established. Per the
    /// cache invariants documented in `wasm-worker-proxy`, this MUST arrive
    /// over the same channel before any `Change` event for the same `sub_id`.
    Snapshot {
        sub_id: SubId,
        entries: Vec<(String, WireEntity)>,
    },
    /// Incremental change for an entity within a subscribed prefix.
    ///
    /// **Lossless on the wire** — every change generates one `Change` event.
    /// The proxy applies each one to the cache mirror losslessly; the
    /// per-subscription **notification channel** separately coalesces with
    /// newest-wins semantics (see Q4 / invariant #6 in `wasm-worker-proxy`
    /// crate docs).
    Change {
        sub_id: SubId,
        path: String,
        new_entity: Option<WireEntity>,
    },
    /// Worker → main signal that the proxy's subscription is gone (worker
    /// restart, transport drop). Proxy responds by invalidating cache and
    /// re-establishing subscriptions.
    SubscriptionLost { sub_id: SubId, reason: String },

    /// Worker → main marshalled substrate hook fact for `peer_id` (v9+).
    /// Routed by the proxy to inspect sinks registered on that peer.
    /// Default-off per peer; consumers flip it on via
    /// `Request::SetInspectEnabled` when the first sink attaches.
    ///
    /// Backpressure: shares the existing event channel; no per-Inspect
    /// flow control (§9 q4 — same regime as `Snapshot`/`Change`). Under
    /// sustained load consumers SHOULD detach the sink (which flips
    /// marshalling off) or filter inside `InspectSink::on_inspect`.
    Inspect { peer_id: String, fact: InspectFact },
}

// ---------------------------------------------------------------------------
// InspectFact — marshalled equivalent of the in-process substrate hook
// events. See the upstream inspect-worker-arm design notes (§4.2)
// for field provenance.
//
// The marshal site in wasm-worker-host is the absorption layer per §9 q5:
// substrate field churn lands here only, not in consumer code.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "fact")]
pub enum InspectFact {
    /// From substrate `DispatchEvent` (`PeerBuilder::with_dispatch_hook`).
    /// Fires twice per dispatch — once at handler entry, once at exit.
    /// On entry, `status` is 0 and `response_hash`-derived fields are
    /// absent. On exit, `status` carries the V7 §8.3 status code.
    Dispatch {
        request_id: String,
        handler_uri: String,
        operation: String,
        /// V7 §8.3 status. `0` on entry (no outcome yet), nonzero on exit.
        status: u32,
        /// Wall-clock elapsed entry→exit; only meaningful on exit.
        /// `None` in v9 — substrate doesn't track this without state.
        /// Marshal site may begin filling this in once the substrate
        /// exposes it. See §9 q5.
        elapsed_micros: Option<u64>,
        /// Cascade `chain_id` from `ExecutionContext`. `None` in v9 —
        /// not surfaced on `DispatchEvent` today.
        chain_id: Option<String>,
    },
    /// From substrate `WireEvent` (`PeerBuilder::with_wire_hook`). Fires
    /// at the post-handshake frame boundary in both directions. Frame
    /// body is NOT carried — only the length — to keep wire chatter
    /// bounded (§9 q2 / §4.3). Body fetch is a deferred follow-on.
    Wire {
        direction: WireDirection,
        /// Remote peer's identity (base58 peer id) when known. Empty
        /// `peer_address` on the substrate event becomes `None`.
        peer_remote: Option<String>,
        /// Frame kind. V7.9 only ships EXECUTE / EXECUTE_RESPONSE on
        /// the wire post-handshake; marshal derives a label from
        /// `direction` ("execute" Recv, "execute_response" Send) until
        /// substrate exposes a richer discriminant.
        frame_kind: String,
        /// Length of the framed envelope in bytes.
        bytes: u32,
        /// Envelope `request_id`. `None` when the substrate event
        /// carries the empty string (pre-auth handshake leftovers in
        /// v1.0 substrate scope; rare post-fix).
        request_id: Option<String>,
    },
    /// From substrate `TreeChangeEvent` (`PeerBuilder::with_binding_hook`).
    /// Fires synchronously on every tree write at the binding-observer
    /// position.
    Binding {
        kind: BindingKind,
        path: String,
        /// Entity type, when the marshal site has it for free. `None`
        /// in v9 — would require a content-store lookup, deliberately
        /// skipped (§4.3 wire chatter discipline).
        entity_type: Option<String>,
        /// 66-char `Hash::to_hex` (33-byte wire form). `None` on
        /// `Deleted` (no new hash).
        content_hash: Option<String>,
        /// `true` for `ChangeType::Created`, `false` for
        /// `Modified`/`Deleted`.
        is_new: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireDirection {
    /// Frame received from the remote peer (substrate `WireDirection::Recv`).
    Inbound,
    /// Frame being sent to the remote peer (substrate `WireDirection::Send`).
    Outbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BindingKind {
    /// Created or Modified (`ChangeType::Created`/`Modified`). Distinguish
    /// via `InspectFact::Binding::is_new`.
    Put,
    /// `ChangeType::Deleted`.
    Remove,
    /// Snapshot / cache invalidate (reserved). The substrate hook surface
    /// (v1.0) does not emit these; included for forward compatibility
    /// with cache-layer marshal sites.
    Snapshot,
    CacheInvalidate,
}

/// v11 wire-shape tests — the additivity claims in the `PROTOCOL_VERSION`
/// ladder, pinned.
///
/// # These do not run under `make test`, and saying so is the point
///
/// This crate is `#![cfg(target_arch = "wasm32")]`, so natively it compiles to
/// nothing and native `cargo test` has no tests here to skip — it has none to
/// find. They are `wasm_bindgen_test`s and need a wasm runner; being pure serde
/// over plain structs, they need no browser, so the node runner is enough.
/// `cargo clippy --target wasm32-unknown-unknown --all-targets` type-checks
/// them today, which is compile-verification and **not** evidence they pass.
///
/// What they are for: the ladder entry claims "absent = unchanged v10
/// behaviour," and that claim rests entirely on `#[serde(default)]` being right
/// on four fields. A same-side round-trip cannot prove the *shape* is what
/// `entity-browser-rust` expects — encoder and decoder agree even when both are
/// wrong — but it can prove the *additivity*, because that is a property of one
/// decoder meeting an older encoder, which is exactly what is simulated here by
/// hand-building v10 CBOR rather than round-tripping our own types.
#[cfg(all(test, target_arch = "wasm32"))]
mod v11_wire_shape {
    use super::*;
    use ciborium::Value;
    use wasm_bindgen_test::*;

    fn roundtrip<T: Serialize + for<'de> Deserialize<'de>>(v: &T) -> T {
        let mut buf = Vec::new();
        ciborium::into_writer(v, &mut buf).expect("encode");
        ciborium::from_reader(buf.as_slice()).expect("decode")
    }

    fn decode<T: for<'de> Deserialize<'de>>(v: &Value) -> T {
        let mut buf = Vec::new();
        ciborium::into_writer(v, &mut buf).expect("encode");
        ciborium::from_reader(buf.as_slice()).expect("decode")
    }

    fn txt(s: &str) -> Value {
        Value::Text(s.into())
    }

    #[wasm_bindgen_test]
    fn the_version_is_eleven() {
        assert_eq!(PROTOCOL_VERSION, 11);
    }

    /// The ladder entry claims "absent = unchanged v10 behaviour". That claim
    /// is only true if a payload from a v10 sender — which has never heard of
    /// `webrtc` or `webrtc_enabled` — still decodes. A missing `#[serde(default)]`
    /// would make it a hard decode error, and the ladder entry a lie.
    ///
    /// The handshake would reject a real v10 proxy before any field is read;
    /// this pins the *field-level* additivity underneath that, which is what
    /// makes the bump additive rather than a break.
    #[wasm_bindgen_test]
    fn a_v10_init_payload_still_decodes_and_means_no_webrtc() {
        let v10 = Value::Map(vec![
            (
                txt("primary_peer"),
                Value::Map(vec![
                    (txt("peer_id"), txt("peer-a")),
                    (txt("keypair_seed"), Value::Bytes(vec![7u8; 32])),
                    (txt("label"), Value::Null),
                ]),
            ),
            (txt("additional_peers"), Value::Array(vec![])),
            (txt("handlers"), Value::Array(vec![])),
            (txt("opfs_root"), Value::Null),
        ]);

        let params: InitParams = decode(&v10);
        assert!(
            params.webrtc.is_none(),
            "a v10 sender names no config, so no establisher is provisioned"
        );
        assert!(
            !params.primary_peer.webrtc_enabled,
            "and no peer opts in — the default is false, never inherited"
        );
    }

    /// Same additivity on the request plane: `CreatePeer` from a v10 sender
    /// must not fail to decode, and must not create a webrtc-enabled peer.
    #[wasm_bindgen_test]
    fn a_v10_create_peer_defaults_to_disabled() {
        let v10 = Value::Map(vec![
            (txt("op"), txt("CreatePeer")),
            (txt("request_id"), Value::Integer(1.into())),
            (txt("label"), txt("scratch")),
        ]);

        match decode::<Request>(&v10) {
            Request::CreatePeer {
                webrtc_enabled,
                label,
                ..
            } => {
                assert_eq!(label.as_deref(), Some("scratch"));
                assert!(!webrtc_enabled, "opt-in is never implied by omission");
            }
            other => panic!("expected CreatePeer, got {other:?}"),
        }
    }

    /// Config present with nothing enabled is legal and inert: the config is
    /// the capability, the per-peer flag is the decision. These are two axes
    /// and collapsing them is exactly the v6 Subscribe bug's shape.
    #[wasm_bindgen_test]
    fn config_present_does_not_enable_any_peer() {
        let params = InitParams {
            primary_peer: PersistedPeer {
                peer_id: "peer-a".into(),
                keypair_seed: vec![1u8; 32],
                label: None,
                webrtc_enabled: false,
            },
            additional_peers: vec![],
            handlers: vec![],
            opfs_root: None,
            webrtc: Some(WireWebRtcConfig {
                node_peer_id: "node-1".into(),
                node_addr: "ws://node.example:9000".into(),
                ice_servers: vec![],
                poll_interval_ms: None,
                max_deadline_ms: None,
            }),
        };

        let back = roundtrip(&params);
        assert!(back.webrtc.is_some());
        assert!(!back.primary_peer.webrtc_enabled);
    }

    /// Empty `ice_servers` is a value, not a gap. It must survive the wire as
    /// empty so the host provisions host-candidates-only rather than reaching
    /// for a public STUN default nobody named.
    #[wasm_bindgen_test]
    fn empty_ice_servers_survives_as_empty() {
        let cfg = WireWebRtcConfig {
            node_peer_id: "node-1".into(),
            node_addr: "wss://node.example".into(),
            ice_servers: vec![],
            poll_interval_ms: Some(250),
            max_deadline_ms: Some(15_000),
        };

        let back = roundtrip(&cfg);
        assert!(
            back.ice_servers.is_empty(),
            "empty means LAN-only, and nothing substitutes for it"
        );
        assert_eq!(back.poll_interval_ms, Some(250));
        assert_eq!(back.max_deadline_ms, Some(15_000));
    }

    /// An absent `ice_servers` decodes to the same empty vector — the two
    /// spellings agree, so a sender that omits the key cannot mean anything
    /// other than host-candidates-only.
    #[wasm_bindgen_test]
    fn absent_ice_servers_decodes_as_empty_not_as_a_default() {
        let cfg: WireWebRtcConfig = decode(&Value::Map(vec![
            (txt("node_peer_id"), txt("node-1")),
            (txt("node_addr"), txt("ws://node.example:9000")),
        ]));

        assert!(cfg.ice_servers.is_empty());
        assert_eq!(cfg.poll_interval_ms, None);
        assert_eq!(cfg.max_deadline_ms, None);
    }

    /// TURN credentials round-trip, and a STUN server carries neither.
    /// `username`/`credential` are `skip_serializing_if` so an absent one is a
    /// missing key rather than an explicit null — the same "optional fields
    /// SHOULD be absent" discipline the entity wire carries.
    #[wasm_bindgen_test]
    fn ice_server_credentials_are_absent_rather_than_null() {
        let servers = vec![
            WireIceServer {
                urls: vec!["stun:stun.example:3478".into()],
                username: None,
                credential: None,
            },
            WireIceServer {
                urls: vec!["turns:turn.example:5349".into()],
                username: Some("u".into()),
                credential: Some("p".into()),
            },
        ];

        let back = roundtrip(&servers);
        assert_eq!(back[0].urls, servers[0].urls);
        assert!(back[0].username.is_none() && back[0].credential.is_none());
        assert_eq!(back[1].username.as_deref(), Some("u"));
        assert_eq!(back[1].credential.as_deref(), Some("p"));

        // The STUN entry must not have written the keys at all.
        let mut buf = Vec::new();
        ciborium::into_writer(&servers[0], &mut buf).expect("encode");
        let decoded: Value = ciborium::from_reader(buf.as_slice()).expect("decode");
        let Value::Map(entries) = decoded else {
            panic!("expected a map")
        };
        let keys: Vec<_> = entries
            .iter()
            .filter_map(|(k, _)| k.as_text().map(str::to_owned))
            .collect();
        assert_eq!(
            keys,
            vec!["urls".to_string()],
            "absent optional fields are missing keys, not nulls"
        );
    }

    /// Per-peer enable is carried on every peer that can be named, including
    /// additional peers — a peer listed at Init opts in at its own listing.
    #[wasm_bindgen_test]
    fn each_peer_carries_its_own_enable() {
        let params = InitParams {
            primary_peer: PersistedPeer {
                peer_id: "peer-a".into(),
                keypair_seed: vec![1u8; 32],
                label: None,
                webrtc_enabled: false,
            },
            additional_peers: vec![PersistedPeer {
                peer_id: "peer-b".into(),
                keypair_seed: vec![2u8; 32],
                label: Some("b".into()),
                webrtc_enabled: true,
            }],
            handlers: vec![],
            opfs_root: None,
            webrtc: Some(WireWebRtcConfig {
                node_peer_id: "node-1".into(),
                node_addr: "ws://node.example:9000".into(),
                ice_servers: vec![],
                poll_interval_ms: None,
                max_deadline_ms: None,
            }),
        };

        let back = roundtrip(&params);
        assert!(!back.primary_peer.webrtc_enabled);
        assert!(back.additional_peers[0].webrtc_enabled);
    }
}

/// v12 capability-report tests. Same non-execution caveat as
/// [`v11_wire_shape`] — `wasm_bindgen_test`, no runner in this repo.
#[cfg(all(test, target_arch = "wasm32"))]
mod v12_capability_report {
    use super::*;
    use ciborium::Value;
    use wasm_bindgen_test::*;

    fn roundtrip<T: Serialize + for<'de> Deserialize<'de>>(v: &T) -> T {
        let mut buf = Vec::new();
        ciborium::into_writer(v, &mut buf).expect("encode");
        ciborium::from_reader(buf.as_slice()).expect("decode")
    }

    #[wasm_bindgen_test]
    fn the_version_is_twelve() {
        assert_eq!(PROTOCOL_VERSION, 12);
    }

    /// The report is per-peer, which is the whole reason it is a list. A
    /// worker-level bool could not distinguish these two peers, and answering
    /// "which peer?" with one worker-wide value is the v6 Subscribe collapse.
    #[wasm_bindgen_test]
    fn the_report_names_which_peers_got_one() {
        let caps = WireCaps {
            opfs_active: false,
            webrtc_peers: vec!["peer-a".into()],
        };

        let back = roundtrip(&caps);
        assert_eq!(back.webrtc_peers, vec!["peer-a".to_string()]);
        assert!(
            !back.webrtc_peers.contains(&"peer-b".to_string()),
            "a peer that got no establisher must be absent, not merely falsy"
        );
    }

    /// Nobody enabled it → an empty list, which is a complete answer, not a
    /// missing one. Distinguishable from "the worker never reported" only by
    /// `actual_capabilities` being `None`, which is the anomaly path.
    #[wasm_bindgen_test]
    fn nobody_enabled_reports_empty_rather_than_absent() {
        let caps = WireCaps {
            opfs_active: true,
            webrtc_peers: vec![],
        };
        let back = roundtrip(&caps);
        assert!(back.webrtc_peers.is_empty());
        assert!(back.opfs_active);
    }

    /// A v11 host's `WireCaps` (no `webrtc_peers`) still decodes — the field
    /// is additive, so the report degrades to "reported nothing" rather than
    /// to a decode error.
    #[wasm_bindgen_test]
    fn a_v11_wirecaps_still_decodes() {
        let v11 = Value::Map(vec![(Value::Text("opfs_active".into()), Value::Bool(true))]);
        let mut buf = Vec::new();
        ciborium::into_writer(&v11, &mut buf).expect("encode");
        let caps: WireCaps = ciborium::from_reader(buf.as_slice()).expect("decode");
        assert!(caps.opfs_active);
        assert!(caps.webrtc_peers.is_empty());
    }

    /// On `CreatePeerOk` a bool IS the right shape — one response, one peer,
    /// nothing left to be silent about.
    #[wasm_bindgen_test]
    fn create_peer_reports_its_single_peer_as_a_bool() {
        let ok = CreatePeerOk {
            peer_id: "peer-c".into(),
            keypair_seed: vec![3u8; 32],
            metadata: WirePeerMetadata::default(),
            webrtc_active: true,
        };
        assert!(roundtrip(&ok).webrtc_active);

        // And a v11 payload without the field decodes as false.
        let v11 = Value::Map(vec![
            (Value::Text("peer_id".into()), Value::Text("peer-c".into())),
            (
                Value::Text("keypair_seed".into()),
                Value::Bytes(vec![3u8; 32]),
            ),
            (
                Value::Text("metadata".into()),
                Value::Map(vec![
                    (Value::Text("label".into()), Value::Null),
                    (Value::Text("persisted".into()), Value::Bool(false)),
                    (Value::Text("listen_addresses".into()), Value::Array(vec![])),
                ]),
            ),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&v11, &mut buf).expect("encode");
        let ok: CreatePeerOk = ciborium::from_reader(buf.as_slice()).expect("decode");
        assert!(!ok.webrtc_active);
    }
}
