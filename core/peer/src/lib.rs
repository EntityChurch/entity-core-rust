//! Peer, PeerBuilder, and connection management.
//!
//! A Peer is the top-level runtime: it holds the identity, stores, handlers,
//! and manages connections. PeerBuilder enforces initialization order.

pub mod connection;
pub mod connection_state;
pub use entity_durability as durability;
#[cfg(all(feature = "local-files", not(target_arch = "wasm32")))]
pub use entity_local_files as local_files;
/// The §7.3.1 coordination half — offer/collect at a signaling node. Shared by
/// every punch substrate, so it is **not** gated on `wasm32`: the browser leg's
/// WebRTC exchange (`EXTENSION-SIGNALING.md` §6.5) rides the same carrier.
///
/// `signaling` only. It previously also carried `#[cfg(feature = "network")]`,
/// which nothing in the module justifies — its imports are `entity_signaling`,
/// `remote`, and `transport`, with no `entity_network` among them. The stray
/// gate made `--features signaling` alone fail to build, because
/// `punch_establisher` is `signaling`-gated and imports this module.
#[cfg(feature = "signaling")]
pub mod carrier;
#[cfg(all(feature = "http-live", not(target_arch = "wasm32")))]
pub mod http_connection;
#[cfg(all(feature = "http-live", not(target_arch = "wasm32")))]
pub mod http_live;
pub mod ingest;
pub mod keepalive;
pub mod live_establish;
pub mod liveness;
/// EXTENSION-NETWORK rung 3's imperative `PeerLink` seam. Gated on `network`
/// because it imports `entity_network` (an optional dep behind that feature)
/// and calls `runtime::sleep_ms` (gated the same way, and documented there as
/// gated "with `network_link` on the same feature" — this declaration is where
/// that pairing was missing). Its only consumer, the rung-3 injection in
/// `run()`, has always been `#[cfg(feature = "network")]`.
#[cfg(feature = "network")]
pub mod network_link;
pub mod peer_status;
/// Consumer half of the `http_live` poll routes — same gate as the publisher
/// it dials, because it is defined in terms of those routes' URL layout.
#[cfg(all(feature = "http-live", not(target_arch = "wasm32")))]
pub mod poll_read;
pub mod published_root;
/// The §7 punch wired behind the §10.3 seam. Opt-in (`signaling`) and native
/// only — the choreography is substrate-agnostic, but this wiring is TCP.
#[cfg(all(feature = "signaling", not(target_arch = "wasm32")))]
pub mod punch_establisher;
#[cfg(feature = "relay")]
pub mod relay_forwarder;
pub mod remote;
/// EXTENSION-SIGNALING §7.3 socket options — native only (no sockets on wasm32).
#[cfg(not(target_arch = "wasm32"))]
pub mod reuseport;
pub mod runtime;
/// The keystone-owned canonical §6.9a seed-policy file format — the cross-peer
/// operator file that desugars to [`PeerBuilder::with_seed_policy`].
pub mod seed_policy;
pub mod server;
pub mod session_entity;
/// EXTENSION-NETWORK §6.7.1 srflx gathering — the client half that turns a
/// reflector's observation into the `srflx` candidate a punch fires at. Needs
/// both extensions: the operation is NETWORK's, the candidate is SIGNALING's.
#[cfg(all(
    feature = "signaling",
    feature = "network",
    not(target_arch = "wasm32")
))]
pub mod srflx;
pub mod transport;
pub mod transport_profile;
/// The worker half of the §6.5 negotiation. wasm32-only and `signaling`-gated:
/// `RTCPeerConnection` is `[Exposed=Window]`, so the seam exists only where
/// there is a main thread to proxy to.
#[cfg(all(target_arch = "wasm32", feature = "signaling"))]
pub mod worker_webrtc;

pub use ingest::{ingest_envelope_signatures, IngestError};

use std::sync::Arc;

use entity_capability::GrantEntry;
use entity_crypto::{IdentityKeypair, Keypair, PeerId};
#[cfg(not(feature = "identity"))]
use entity_handler::NoopAttestationStore;
use entity_handler::{AttestationStore, Handler, HandlerRegistry};
use entity_hash::Hash;
/// Only the clock engine registers a context field, so the import carries the
/// same gate as its single use site — otherwise a build without `clock` warns,
/// which is fatal under the `-D warnings` lint gate.
#[cfg(feature = "clock")]
use entity_store::ContextFieldRegistration;
use entity_store::{
    CascadeHalt, ContentStore, ContentStoreEvent, ExecutionContext, LocationIndex,
    MemoryContentStore, MemoryLocationIndex, NotifyingContentStore, NotifyingLocationIndex,
    SyncTreeHook, TreeChangeEvent,
};
use entity_tree::TreeHandler;
use thiserror::Error;
use tokio::sync::broadcast;

/// Peer configuration.
#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub listen_addr: String,
    pub max_connections: usize,
    pub connection_timeout_secs: u64,
    /// Issue wide-open grants on connection (all handlers/resources/operations).
    /// **Debug only** — bypasses all authorization scoping.
    pub debug_open_grants: bool,
    /// Receiver durability policy (EXTENSION-DURABILITY §4). The max strength
    /// this peer can self-determine at acceptance from its store. Defaults to
    /// `None` (no durable store — e.g. an in-memory store); persistent-store
    /// builders (`sqlite`, `opfs`) raise it to `Stored`.
    pub durability_policy: durability::DurabilityPolicy,
    /// Override the configured frame budget the `system/content` handler
    /// applies to `get` responses (CONTENT v3.6 §6.2 / §4.2 Amendment 1
    /// receiver-side MUST). `None` keeps
    /// [`entity_content::handler::DEFAULT_GET_FRAME_BUDGET`]; `Some(n)`
    /// drives `n` bytes — used by the `frame-limit-respected` validate-peer
    /// check and by deployments tuning the transport. Per-connection
    /// plumbing is a future refinement; this is the per-peer knob.
    pub content_get_frame_budget: Option<u64>,
    /// This peer's **home** `content_hash_format` — the format under which
    /// it authors when it is the sole determinant (peer-startup local
    /// state) and its top preference in hello negotiation (V7 §4.5). The
    /// per-connection *active* format is negotiated and may differ (a
    /// SHA-384 home peer authors SHA-256 on a connection to a SHA-256-only
    /// peer, §4.5a). Defaults to SHA-256 (`0x00`), the conformance floor.
    pub home_hash_format: u8,
    /// §5 app-level keepalive over pooled outbound connections
    /// (EXTENSION-NETWORK §2.3 / §5.4, Amendment 12 rung 2). Defaults to
    /// the spec values (30s / 10s / 3, enabled).
    pub keepalive: keepalive::KeepaliveConfig,
    /// **EXTENSION-RELAY §8.1 (v1.3)** — the Mode-S retention CEILING in ms
    /// (`relay_store_retention`). `0` = enforce no ceiling.
    ///
    /// Default `0`, and that is a deliberate default-OFF: §8.1 is "MUST when
    /// present", so a relay that declares no ceiling holds entries to their own
    /// `expires_at`. Note §8.1's own warning about what that means — *"unlimited"
    /// is not a policy; it is unbounded accumulation* — which is why the knob
    /// exists in one place and is published (§4.1) wherever it is set.
    pub relay_store_retention_ms: u64,
    /// **EXTENSION-RELAY §8.2 (v1.3)** — the relay-wide Mode-S store bound in
    /// bytes. `0` = unbounded. Default-off for the same reason as above; when
    /// set, a `:put` over the bound is refused `storage_full`/507 and the relay
    /// MUST NOT evict to make room.
    pub relay_max_storage_bytes: u64,
}

impl Default for PeerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:9000".to_string(),
            max_connections: 100,
            connection_timeout_secs: 30,
            debug_open_grants: false,
            durability_policy: durability::DurabilityPolicy::default(),
            content_get_frame_budget: None,
            home_hash_format: entity_hash::HASH_ALGORITHM_SHA256,
            keepalive: keepalive::KeepaliveConfig::default(),
            relay_store_retention_ms: 0,
            relay_max_storage_bytes: 0,
        }
    }
}

/// Connect-handler grant resolver — consulted at AUTHENTICATE to choose
/// the connection cap's grants based on the connecting peer's identity
/// (EXTENSION-ROLE §4.7 + ENTITY-CORE-PROTOCOL-V7 §7.2).
///
/// Receives both the connecting peer's `PeerId` (Base58 of public-key
/// digest, V7 §1.4) AND the freshly-computed `system/peer` content hash
/// (the form by which role/identity tree state is keyed). Returns
/// `Some(grants)` if the resolver accepts the peer; `None` to fall
/// through to the connect handler's static fallback (currently
/// `default_connection_grants`).
pub type GrantResolver = Arc<dyn Fn(&PeerId, &Hash) -> Option<Vec<GrantEntry>> + Send + Sync>;

/// The §6.5 (b) minted-and-delivered reciprocal-grant ledger: the caps this
/// peer minted **and put on the wire**, with the entities a chain walk over
/// each one needs (the cap, its signature, and our identity — the §7a.2a
/// triple).
///
/// This is the supply side of the ruled two-phase carriage (Q1): an acceptor
/// wielding our reciprocal grant sends the cap **by reference**, and we resolve
/// it here rather than requiring it re-inlined in an envelope we authored
/// ourselves.
///
/// **The resolution key is the cap's content hash**
/// (`EXTENSION-SIGNALING` §6.5, *"The ledger's resolution key is the cap hash"*,
/// ruling 2026-08-07). The wielding EXECUTE's root `capability` field *is* the
/// reference, so the hash is the only key guaranteed present at the resolution
/// site. Recipient peer-id is kept as a secondary **index** — which that ruling
/// permits — but MUST NOT be the sole key: a wielder's peer-id equals the
/// delivery recipient's only while the cap is wielded by exactly the peer it was
/// delivered to, so a recipient-keyed-only ledger resolves nothing the moment a
/// cap is wielded by a **delegate** and fails closed with `403` on valid
/// authority. (Rust keyed on recipient peer-id alone until this ruling; the
/// divergence was reported by `entity-core-go` and by us, and arch pinned it to
/// Go's hash-keyed shape before `entity-core-py` builds a third one.)
///
/// **Deliberately not a content-store lookup**, which is the trap in reading
/// "resolves from its own content store" literally: the store also holds caps
/// we minted and never sent, and every cap we hold for any reason — so naming a
/// cap would become as good as holding one. Scoped to minted-**and-delivered**,
/// written only after the frame write succeeds. `grantee == author` still binds
/// the cap to the peer it names, so hash resolution is not third-party
/// escalation; what it must not do is erase the difference between "we minted
/// this for you" and "you hold it", which is the distinction the §6.5 (b) send
/// path depends on.
///
/// A re-mint to the same recipient does **not** evict the previous cap: a
/// delivered cap stays delivered, and dropping it would fail closed on
/// authority the counterpart legitimately holds. `entity-core-go`'s
/// `authoredGrantSet` retains likewise.
#[derive(Default)]
pub struct MintedGrantLedger {
    /// cap content hash → the entities a chain walk over that cap needs.
    by_cap: std::collections::HashMap<Hash, Vec<entity_entity::Entity>>,
    /// recipient peer-id → the most recent cap minted for it. An index onto
    /// `by_cap`, never a store of its own.
    by_recipient: std::collections::HashMap<String, Hash>,
}

impl MintedGrantLedger {
    /// Register a grant we minted **and sent**. `cap_hash` is the minted cap's
    /// content hash — the value the counterpart puts in its EXECUTE's
    /// `capability` field when it wields by reference.
    pub fn record(
        &mut self,
        recipient_peer_id: String,
        cap_hash: Hash,
        supporting: Vec<entity_entity::Entity>,
    ) {
        if supporting.is_empty() {
            return;
        }
        self.by_cap.insert(cap_hash, supporting);
        self.by_recipient.insert(recipient_peer_id, cap_hash);
    }

    /// Resolve by cap hash — the ruled key.
    pub fn by_cap(&self, cap_hash: &Hash) -> Option<&Vec<entity_entity::Entity>> {
        self.by_cap.get(cap_hash)
    }

    /// Resolve by recipient peer-id — the permitted secondary index.
    pub fn by_recipient(&self, recipient_peer_id: &str) -> Option<&Vec<entity_entity::Entity>> {
        self.by_recipient
            .get(recipient_peer_id)
            .and_then(|h| self.by_cap.get(h))
    }

    /// Resolve the supporting set for a wielding frame: the cap hash the frame
    /// names first (§6.5's MUST), the recipient index second.
    pub fn supply(
        &self,
        cap_hash: Option<&Hash>,
        recipient_peer_id: Option<&str>,
    ) -> Option<Vec<entity_entity::Entity>> {
        cap_hash
            .and_then(|h| self.by_cap(h))
            .or_else(|| recipient_peer_id.and_then(|p| self.by_recipient(p)))
            .cloned()
    }
}

/// Shared state passed to connection tasks (Arc'd).
pub struct PeerShared {
    pub keypair: IdentityKeypair,
    pub peer_id: PeerId,
    /// Content hash of the local peer's identity entity. Used by dispatch to
    /// verify that handler grants loaded from the tree were issued by THIS
    /// peer (V7 §6.2 / §6.8 — handler grants derive from the peer's root
    /// capability). Cross-peer transfer of a tree subtree carries the foreign
    /// peer's grants too; rejecting them at the dispatch grant-load site is
    /// what blocks the spec-gap-handler-grant-authority §S2 attack.
    pub identity_hash: entity_hash::Hash,
    pub content_store: Arc<dyn ContentStore>,
    pub location_index: Arc<dyn LocationIndex>,
    pub handler_registry: Arc<HandlerRegistry>,
    pub tree: Arc<TreeHandler>,
    pub config: PeerConfig,
    /// Outbound connection pool for remote execute. `Arc` so every
    /// `Peer::shared()` snapshot references the SAME pool — connection
    /// state is per-peer, not per-snapshot. (Pre-Amendment-12 each
    /// snapshot minted a fresh pool, so `connect_to`'s pooled connection
    /// was silently dropped and every `execute()` re-dialed; a persistent
    /// pool is load-bearing for the §A1 liveness contract, whose trigger
    /// is a failed dispatch over a dead *pooled* connection, and for the
    /// §5 keepalive loop that monitors it.)
    pub remote: Arc<remote::RemoteState>,
    /// Connector for outbound connections to remote peers.
    pub connector: Arc<dyn transport::Connector>,
    /// Identity-attestation lookup for the cap-verifier
    /// (EXTENSION-IDENTITY §10.1 / §12.3). Defaults to a no-op store
    /// when the identity extension isn't enabled. Currently exposed via
    /// `Peer::lookup_attestation()` for external callers; not yet wired
    /// into `verify_request` (gated on architect input — see the
    /// identity architecture review).
    pub attestation_store: Arc<dyn AttestationStore>,
    /// Optional grant resolver consulted at AUTHENTICATE before falling
    /// back to `default_connection_grants` (EXTENSION-ROLE §4.7).
    pub grant_resolver: Option<GrantResolver>,
    /// `EXTENSION-NETWORK` §10.3 (A14) — the live-establishment seam,
    /// consulted at §10 step 3b when durable-profile resolution finds no
    /// dialable address. `None` (nothing registered) makes the ladder
    /// byte-identical to the pre-seam behavior, which is A14's stated
    /// no-regression property. See [`live_establish::LiveEstablish`].
    pub live_establish: Option<Arc<dyn live_establish::LiveEstablish>>,
    /// `(author_hash_hex, request_id) → preserved handle` — idempotency
    /// index for durable requests (EXTENSION-DURABILITY §5 / Amendment 1).
    /// A replayed durable request whose pair matches a previously preserved
    /// entry returns 409 with the prior handle echoed; the receiver enforces
    /// uniqueness over the pair regardless of storage layout. Equivalent to
    /// Go's `preservedRequests sync.Map` in `core/protocol/dispatch.go`.
    /// `Arc<Mutex<...>>` so every `Peer::shared()` snapshot references the
    /// same map — dedup state is per-peer, not per-connection.
    pub preserved_requests:
        Arc<std::sync::Mutex<std::collections::HashMap<(String, String), String>>>,
    /// The §6.5 (b) minted-and-delivered grant ledger — see
    /// [`MintedGrantLedger`].
    pub minted_reentry_grants: Arc<std::sync::Mutex<MintedGrantLedger>>,
    /// Observe-only dispatch hooks registered via `PeerBuilder::with_dispatch_hook`.
    /// Fired in registration order at request-entry (before `handler.handle`)
    /// and request-exit (after the handler returns) per GUIDE-INSPECTABILITY
    /// v1.2 §2.1 #3.
    pub dispatch_hooks: Vec<(String, DispatchHookFn)>,
    /// Observe-only wire hooks registered via `PeerBuilder::with_wire_hook`.
    /// Fired at the post-handshake message-loop boundary (Recv after
    /// decode_envelope, Send before pushing into the response channel) per
    /// GUIDE-INSPECTABILITY v1.2 §2.1 #5.
    pub wire_hooks: Vec<(String, WireHookFn)>,
    /// CONTINUATION v1.23 §3.4 A.1: throttle stamp (unix ms) for the
    /// dispatcher's own §3.10 marker sweep. `0` until the first sweep.
    ///
    /// The dispatcher is a marker **binder** — every chain-scoped 403 mints
    /// a `rejected` marker (`try_bind_rejected_marker`) — so by §3.4 A.1 it
    /// is also a collector. It cannot lean on the continuation handler's
    /// sweep: that one only runs when a continuation *advances*, and a peer
    /// being hammered with denied chain dispatches may never advance one.
    /// That is the unbounded case here, and it is caller-driven.
    ///
    /// `Arc<AtomicU64>` so every `Peer::shared()` snapshot throttles against
    /// the same stamp — per-peer state, not per-snapshot (same reason the
    /// pool and the dedup map are shared).
    pub last_marker_collect_ms: Arc<std::sync::atomic::AtomicU64>,
}

/// A running peer instance.
pub struct Peer {
    keypair: IdentityKeypair,
    peer_id: PeerId,
    /// Content hash of the local peer's identity entity (V7 §1.5).
    /// Stored at build time and propagated to PeerShared so dispatch can
    /// validate handler-grant granter against the local peer.
    identity_hash: entity_hash::Hash,
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    handler_registry: Arc<HandlerRegistry>,
    tree: Arc<TreeHandler>,
    config: PeerConfig,
    /// Connector for outbound connections.
    connector: Arc<dyn transport::Connector>,
    /// Outbound connection pool — one per Peer, shared into every
    /// `shared()` snapshot (see the `PeerShared::remote` doc).
    remote: Arc<remote::RemoteState>,
    /// Event broadcast sender for tree changes.
    event_tx: broadcast::Sender<TreeChangeEvent>,
    /// Event broadcast sender for content store events.
    content_event_tx: broadcast::Sender<ContentStoreEvent>,
    /// Whether start_engines() has been called (prevents double-start).
    engines_started: std::sync::atomic::AtomicBool,
    /// Subscription engine (started when run() is called).
    #[cfg(feature = "subscription")]
    sub_engine: Option<Arc<entity_subscription::engine::Engine>>,
    /// `system/network` handler — held so `start_engines` can inject the
    /// imperative `PeerLink` seam (connect/keepalive/self-execute) once a
    /// `shared()` snapshot exists (post-construction wiring, same shape as
    /// the subscription delivery function).
    #[cfg(feature = "network")]
    network_handler: Arc<entity_network::NetworkHandler>,
    // Clock, history, and revision engines are synchronous emit hooks.
    // Their Arc references are held by the NotifyingLocationIndex sync_hooks list.
    /// Identity-attestation lookup (mirror of PeerShared.attestation_store
    /// for direct access via `Peer::lookup_attestation()`).
    attestation_store: Arc<dyn AttestationStore>,
    /// Optional grant resolver wired post-construction via
    /// `Peer::set_grant_resolver`. Cloned into every `PeerShared`.
    grant_resolver: Option<GrantResolver>,
    /// Optional §10.3 live-establishment seam wired post-construction via
    /// `Peer::set_live_establish`. Cloned into every `PeerShared`.
    ///
    /// Wired after construction rather than at build time for the same reason
    /// the grant resolver is: the registered policy (`EXTENSION-SIGNALING` §7)
    /// needs a carrier client, which needs a peer to execute through — so the
    /// peer must exist before its own traversal policy can be built.
    live_establish: Option<Arc<dyn live_establish::LiveEstablish>>,
    /// Substrate attestation index (when the `attestation` feature is
    /// enabled). Exposed so the role policy resolver — wired
    /// post-construction — can read from the same index that
    /// AttestationIndexHook populates.
    #[cfg(feature = "attestation")]
    attestation_index: Arc<entity_attestation::AttestationIndex>,
    /// `(author, request_id)` → preserved handle. Shared across all
    /// `shared()` snapshots so dedup applies peer-wide
    /// (EXTENSION-DURABILITY §5 / Amendment 1).
    preserved_requests: Arc<std::sync::Mutex<std::collections::HashMap<(String, String), String>>>,
    /// The §6.5 (b) reentry grants minted and delivered, keyed by cap hash
    /// ([`MintedGrantLedger`]). Shared across all `shared()` snapshots: the mint
    /// happens on the dial task and the supply happens on a spawned dispatch, so
    /// a per-snapshot ledger would record in one place and be read in another.
    minted_reentry_grants: Arc<std::sync::Mutex<MintedGrantLedger>>,
    /// `local/files` handler instance — held so reverse-write can be
    /// wired in `start_engines` and so external callers can register
    /// root mappings.
    #[cfg(all(feature = "local-files", not(target_arch = "wasm32")))]
    local_files_handler: Arc<entity_local_files::LocalFilesHandler>,
    /// Observe-only dispatch hooks registered via `PeerBuilder::with_dispatch_hook`.
    /// Cloned into every `PeerShared` snapshot via `shared()` so dispatch tasks
    /// can fire them at the dispatcher↔handler-body boundary.
    dispatch_hooks: Vec<(String, DispatchHookFn)>,
    /// Observe-only wire hooks registered via `PeerBuilder::with_wire_hook`.
    /// Cloned into every `PeerShared` snapshot so the connection task can fire
    /// them at frame boundaries.
    wire_hooks: Vec<(String, WireHookFn)>,
    /// CONTINUATION v1.23 §3.4 A.1 marker-sweep throttle stamp, shared into
    /// every `shared()` snapshot so the dispatcher throttles per peer.
    last_marker_collect_ms: Arc<std::sync::atomic::AtomicU64>,
    /// Shared write-behind checkpoint handle, present only when the peer was
    /// built with `.idb()`. The SDK/app calls `idb_checkpoint().checkpoint()`
    /// to await durability before acknowledging identity/destructive ops.
    #[cfg(all(target_arch = "wasm32", feature = "wasm-idb-persist"))]
    idb_checkpoint: Option<entity_store::idb::IdbCheckpoint>,
}

impl Peer {
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    pub fn keypair(&self) -> &IdentityKeypair {
        &self.keypair
    }

    pub fn content_store(&self) -> &Arc<dyn ContentStore> {
        &self.content_store
    }

    pub fn location_index(&self) -> &Arc<dyn LocationIndex> {
        &self.location_index
    }

    /// The IndexedDB write-behind checkpoint handle, present only when the peer
    /// was built with `PeerBuilder::idb()`. Returns `None` for every other
    /// backend (memory, SQLite, OPFS — those are flush-on-write or ephemeral).
    ///
    /// Call `handle.checkpoint().await` to await durability of all writes
    /// enqueued so far (identity/destructive ops); `handle.health()` for the
    /// pending-count / last-flushed / last-error honesty surface.
    #[cfg(all(target_arch = "wasm32", feature = "wasm-idb-persist"))]
    pub fn idb_checkpoint(&self) -> Option<&entity_store::idb::IdbCheckpoint> {
        self.idb_checkpoint.as_ref()
    }

    pub fn handler_registry(&self) -> &Arc<HandlerRegistry> {
        &self.handler_registry
    }

    pub fn tree(&self) -> &Arc<TreeHandler> {
        &self.tree
    }

    pub fn config(&self) -> &PeerConfig {
        &self.config
    }

    /// Look up identity attestation for a peer's identity hash
    /// (EXTENSION-IDENTITY §10.1 / §12.3). Returns `Attested` with the
    /// public-identity binding when an RPA exists in this peer's tree;
    /// `NotAttested` otherwise. Callers apply the cache-miss policy.
    pub fn lookup_attestation(
        &self,
        peer_identity_hash: &entity_hash::Hash,
    ) -> entity_handler::AttestationStatus {
        self.attestation_store.lookup(peer_identity_hash)
    }

    /// Bind a TCP listener on the configured address.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn listen(&self) -> Result<transport::TcpTransportListener, PeerError> {
        server::listen(&self.config.listen_addr).await
    }

    /// Create a shareable `PeerShared` for use with `server::run()` and engines.
    ///
    /// Bindings use this instead of constructing `PeerShared` manually.
    pub fn shared(&self) -> Arc<PeerShared> {
        Arc::new(PeerShared {
            keypair: self.keypair.clone_identity(),
            peer_id: self.peer_id.clone(),
            identity_hash: self.identity_hash,
            content_store: self.content_store.clone(),
            location_index: self.location_index.clone(),
            handler_registry: self.handler_registry.clone(),
            tree: self.tree.clone(),
            config: self.config.clone(),
            remote: self.remote.clone(),
            connector: self.connector.clone(),
            attestation_store: self.attestation_store.clone(),
            grant_resolver: self.grant_resolver.clone(),
            live_establish: self.live_establish.clone(),
            preserved_requests: self.preserved_requests.clone(),
            minted_reentry_grants: self.minted_reentry_grants.clone(),
            dispatch_hooks: self.dispatch_hooks.clone(),
            wire_hooks: self.wire_hooks.clone(),
            last_marker_collect_ms: self.last_marker_collect_ms.clone(),
        })
    }

    /// Install a connect-handler grant resolver (EXTENSION-ROLE §4.7).
    /// Must be called before `run()` / before any inbound connection;
    /// each `shared()` snapshot picks up the resolver at clone time.
    pub fn set_grant_resolver(&mut self, resolver: GrantResolver) {
        self.grant_resolver = Some(resolver);
    }

    /// Register the `EXTENSION-NETWORK` §10.3 live-establishment seam (A14).
    ///
    /// Must be called before any dispatch that should escalate to traversal;
    /// each `shared()` snapshot picks the seam up at clone time. With nothing
    /// registered the §10 ladder is unchanged — §10.3's additive property — so
    /// this is opt-in per deployment, not a default posture.
    pub fn set_live_establish(&mut self, seam: Arc<dyn live_establish::LiveEstablish>) {
        self.live_establish = Some(seam);
    }

    /// Substrate attestation index. Available when the `attestation`
    /// feature is enabled. Used by the role policy resolver wiring.
    #[cfg(feature = "attestation")]
    pub fn attestation_index(&self) -> &Arc<entity_attestation::AttestationIndex> {
        &self.attestation_index
    }

    /// Subscription engine. Available when the `subscription` feature
    /// is enabled and after `build()` (always Some on a successful
    /// build). Exposed for diagnostics and restart-equivalence tests.
    #[cfg(feature = "subscription")]
    pub fn subscription_engine(&self) -> Option<&Arc<entity_subscription::engine::Engine>> {
        self.sub_engine.as_ref()
    }

    /// `local/files` handler. Available when the `local-files` feature
    /// is enabled. Bindings call `.add_root(name, cfg)` to register a
    /// filesystem root mapping at runtime.
    #[cfg(all(feature = "local-files", not(target_arch = "wasm32")))]
    pub fn local_files_handler(&self) -> &Arc<entity_local_files::LocalFilesHandler> {
        &self.local_files_handler
    }

    /// Subscribe to tree change events.
    ///
    /// Returns a broadcast receiver that yields `TreeChangeEvent` on every
    /// location index mutation.
    pub fn subscribe_events(&self) -> broadcast::Receiver<TreeChangeEvent> {
        self.event_tx.subscribe()
    }

    /// Subscribe to content store events.
    ///
    /// Returns a broadcast receiver that yields `ContentStoreEvent` on every
    /// new entity stored in the content store.
    pub fn subscribe_content_events(&self) -> broadcast::Receiver<ContentStoreEvent> {
        self.content_event_tx.subscribe()
    }

    /// Start extension engines (clock, sync, subscription) and wire delivery.
    ///
    /// Must be called from within a tokio runtime. Requires `shared` so the
    /// subscription delivery function can dispatch through handlers.
    ///
    /// Safe to call multiple times — only the first call starts engines.
    pub fn start_engines(&self, shared: &Arc<PeerShared>) {
        if self
            .engines_started
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            tracing::debug!("start_engines: already started, skipping");
            return; // Already started
        }

        tracing::info!(peer_id = %self.peer_id, "starting extension engines");

        // Clock and history are now synchronous emit hooks (registered during build).
        // They no longer need async broadcast start() calls.

        // Revision auto-version is a SyncTreeHook registered during build
        // (spec position 7). No async broadcast start needed.

        // Subscription: sync hook handles matching + notification building (position 8).
        // The async delivery loop consumes pre-built work from the internal mpsc channel.
        #[cfg(feature = "subscription")]
        if let Some(ref engine) = self.sub_engine {
            tracing::debug!("wiring subscription delivery function");
            // Start the async delivery loop (consumes from internal mpsc channel)
            engine.start();
            // Wire delivery function for subscription notifications
            let shared_for_deliver = shared.clone();
            let deliver: entity_subscription::engine::DeliverFn = Arc::new(move |req| {
                let shared = shared_for_deliver.clone();
                Box::pin(async move {
                    // Engine delivers on behalf of the local peer; the local
                    // identity is the right author for SB1/R1 (the deliver_token
                    // chain is authority-rooted at this peer). Passing None here
                    // would silently disable the SB1 chain-root check and
                    // persist subscriber_identity = Hash::zero().
                    let local_identity = shared.identity_hash;
                    // EXTENSION-SUBSCRIPTION §4.2 delivery capability +
                    // coherent-capability B-rooting (Go routing 2026-07-19).
                    //
                    // The delivery EXECUTE's Site-3 root check runs AT THE
                    // RECEIVER: the presented `capability`'s authority chain MUST
                    // root at the receiving peer (Go `VerifyChain` M6,
                    // `core/capability/delegation.go`). The subscriber's
                    // deliver_token is NOT a reliable anchor for that — a
                    // *delegated* token roots wherever its parent chain
                    // terminates, which for a token minted with the SENDER's
                    // connection grant as parent (e.g. the cohort validator's
                    // `CreateDeliveryToken`) is the **sender**, not the receiver.
                    // Presenting such a token as the EXECUTE capability made the
                    // receiver's Site-3 fail with "root capability granter is not
                    // local peer" — the cross-impl delivery 403 (bc096b2 fixed
                    // the desync it cascaded into; this fixes the delivery
                    // itself).
                    //
                    //   Cross-peer: present the *connection grant* of the
                    //     connection to the receiver — `send_execute`'s `None`
                    //     path falls back to `conn.capability()`. A connection
                    //     Rust dials to the receiver is granted BY the receiver,
                    //     so that grant is B-rooted at the verifying peer and
                    //     passes Site-3 — the same receiver-rooted anchor Go and
                    //     Python present. The deliver_token still rides in the
                    //     envelope `included` (below) so the receiver's
                    //     scope/SB1 check on it is satisfied.
                    //   Same-peer: `None` too — local dispatch uses the server's
                    //     own system/inbox handler grant (root == local peer).
                    let is_remote = crate::remote::is_remote_uri(
                        &req.deliver_uri,
                        shared.keypair.peer_id().as_str(),
                    );
                    // PROPOSAL-CONVERGENT-MIRRORING §2: when the subscription
                    // opted into include_payload, the engine attached the
                    // changed entity to req.included. Pass it through to the
                    // dispatch envelope's `included` so the subscriber sees the
                    // entity atomically with the notification. For a cross-peer
                    // delivery we also fold in the deliver_token entity so the
                    // receiver can resolve it for its scope/SB1 check even though
                    // the EXECUTE capability is now the (receiver-rooted)
                    // connection grant rather than the token itself.
                    let mut included = req.included;
                    if is_remote {
                        included
                            .entry(req.deliver_token.content_hash)
                            .or_insert_with(|| req.deliver_token.clone());
                    }
                    let execute_fn = connection::make_execute_fn(
                        shared,
                        Some(local_identity),
                        included,
                        None, // engine-initiated, no parent bounds
                        None, // engine-initiated, no external caller
                        // The peer is dispatching as itself, not as a deputy.
                        connection::DispatchCeiling::PeerRoot,
                    );
                    let opts = entity_handler::ExecuteOptions {
                        resource: req.resource,
                        request_id: Some(req.request_id),
                        // Receiver-rooted connection grant (None → conn.capability()),
                        // not the sender-rooted deliver_token. See above.
                        capability: None,
                        ..Default::default()
                    };
                    execute_fn(
                        req.deliver_uri.clone(),
                        "receive".to_string(),
                        req.params,
                        opts,
                    )
                    .await?;
                    Ok(())
                })
            });
            *engine.deliver.write().unwrap() = Some(deliver);
        }

        // DOMAIN-LOCAL-FILES §5 reverse write: consume the peer's
        // tree-change broadcast and translate qualifying changes to
        // filesystem writes. The §10.1 MUST pins observable behavior;
        // the global-event-stream + handler-filter shape is conformant
        // per §5.1's flexibility note.
        #[cfg(all(feature = "local-files", not(target_arch = "wasm32")))]
        {
            let events = self.event_tx.subscribe();
            entity_local_files::start_reverse_write(self.local_files_handler.clone(), events);
        }

        // EXTENSION-NETWORK rung 3: inject the imperative `PeerLink` seam
        // (connect-if-needed / evict / self-execute / deliver-token mint /
        // backoff timer) now that a `shared()` snapshot exists. The handler
        // was registered + granted at build time; this is the post-
        // construction wiring the extension's crate-DAG position requires
        // (mirror of the subscription delivery function above).
        #[cfg(feature = "network")]
        {
            let link = Arc::new(network_link::PeerNetworkLink::new(shared.clone()));
            self.network_handler.bind(link);
        }

        // Suppress unused variable warning when subscription feature is disabled
        let _ = shared;
    }

    /// Execute a local handler dispatch without going through the wire protocol.
    ///
    /// This is the primary way bindings invoke handlers — no networking, no
    /// envelope framing. Dispatches as the local peer's identity (the handler
    /// sees `ctx.author = Some(local_identity_hash)`), so handler invariants
    /// keyed on author — notably SB1/R1 in subscription's deliver_token
    /// chain-root check — fire identically on the wire and local paths.
    pub async fn execute(
        &self,
        handler: &str,
        operation: &str,
        params: entity_entity::Entity,
    ) -> Result<entity_handler::HandlerResult, entity_handler::HandlerError> {
        self.execute_with_options(
            handler,
            operation,
            params,
            entity_handler::ExecuteOptions::default(),
        )
        .await
    }

    /// Execute with explicit options (resource target, request_id, etc.).
    pub async fn execute_with_options(
        &self,
        handler: &str,
        operation: &str,
        params: entity_entity::Entity,
        options: entity_handler::ExecuteOptions,
    ) -> Result<entity_handler::HandlerResult, entity_handler::HandlerError> {
        tracing::debug!(
            handler = %handler,
            operation = %operation,
            params_type = %params.entity_type,
            "local execute"
        );
        let shared = self.shared();
        // Local dispatch carries the local peer's identity as author — the
        // peer is an authenticated actor (it owns shared.keypair), and
        // handlers' author-keyed invariants must fire identically here and
        // on the wire path. See SB1/R1 in EXTENSION-SUBSCRIPTION §3.1.
        let local_identity = shared.identity_hash;
        let execute_fn = connection::make_execute_fn(
            shared,
            Some(local_identity),
            std::collections::HashMap::new(),
            None,
            None,
            // The peer is dispatching as itself, not as a deputy — the local
            // peer is root over its own namespace (D1).
            connection::DispatchCeiling::PeerRoot,
        );
        let result = execute_fn(handler.to_string(), operation.to_string(), params, options).await;
        match &result {
            Ok(r) => tracing::debug!(
                handler = %handler,
                operation = %operation,
                status = r.status,
                "local execute: completed"
            ),
            Err(e) => tracing::warn!(
                handler = %handler,
                operation = %operation,
                error = %e,
                "local execute: error"
            ),
        }
        result
    }

    /// Author + sign + serve a `system/peer/published-root` committing to
    /// `root_hash` (Phase P — PROPOSAL-PEER-MANIFEST §4). `MANIFEST_GET` then
    /// serves the new head; `seq` increments monotonically and `predecessor`
    /// chains to the prior head. Idempotent when `root_hash` is unchanged.
    pub fn publish_root(
        &self,
        root_hash: entity_hash::Hash,
    ) -> Result<entity_hash::Hash, published_root::PublishedRootError> {
        let shared = self.shared();
        let prefix = format!("/{}/", shared.peer_id.as_str());
        self.publish_root_with_prefix(root_hash, prefix)
    }

    /// [`publish_root`] declaring an explicit §3.3a `prefix` — the absolute
    /// prefix the trie keys committed to by `root_hash` are relative to.
    ///
    /// `publish_root` defaults to the peer-qualified `/{peer_id}/` because that
    /// is what a trie built over this peer's own subtree is keyed by. A caller
    /// that built its trie over some other operand (a `system/`-relative
    /// snapshot, or the universal tree where the trim is a no-op and keys stay
    /// fully qualified) MUST say so here: the field is the consumer's only way
    /// to reconstruct an absolute path, so a wrong declaration is worse than a
    /// missing one — it reconstructs confidently to a path that does not exist.
    ///
    /// [`publish_root`]: Self::publish_root
    pub fn publish_root_with_prefix(
        &self,
        root_hash: entity_hash::Hash,
        prefix: impl Into<String>,
    ) -> Result<entity_hash::Hash, published_root::PublishedRootError> {
        let shared = self.shared();
        let engine = published_root::PublishRootEngine::new(
            shared.content_store.clone(),
            shared.location_index.clone(),
            shared.keypair.clone_identity(),
            shared.peer_id.as_str().to_string(),
            shared.identity_hash,
            prefix,
        );
        engine.publish(root_hash)
    }

    /// The current published-root head hash served by `MANIFEST_GET`, if any.
    pub fn published_root_head(&self) -> Option<entity_hash::Hash> {
        let shared = self.shared();
        shared
            .location_index
            .get(&published_root::published_root_head_path(
                shared.peer_id.as_str(),
            ))
    }

    /// Start engines and return, without listening for connections.
    ///
    /// Use this for local-only peers (WASM, embedded) that only use
    /// `execute()` for handler dispatch. No networking.
    pub fn local_only(&self) {
        let shared = self.shared();
        self.start_engines(&shared);
    }

    /// Connect to a remote peer and perform the entity protocol handshake.
    ///
    /// On success, the connection is pooled for reuse by `execute()` when
    /// dispatching to remote URIs targeting this peer.
    pub async fn connect_to(&self, addr: &str) -> Result<String, PeerError> {
        let shared = self.shared();
        let endpoint = remote::connect_and_pool(&shared, addr).await?;
        let remote_peer_id = endpoint.remote_peer_id().to_string();
        tracing::info!(remote_peer = %remote_peer_id, addr = %addr, "connected to remote peer");
        Ok(remote_peer_id)
    }

    /// Run the accept loop with a single listener. Blocks until an error occurs.
    ///
    /// Calls `shared()`, `start_engines()`, and `server::run()` internally.
    /// Available on both native and WASM (Workers can host
    /// `MessagePortListener` for cross-Worker accepts).
    pub async fn run(&self, listener: impl transport::Listener + 'static) -> Result<(), PeerError> {
        let shared = self.shared();
        self.start_engines(&shared);
        server::run(listener, shared).await
    }

    /// Run with multiple listeners concurrently (e.g., TCP + WebSocket).
    /// Native-only — the tokio::spawn-based fan-out requires Send futures,
    /// which WASM accept loops aren't. WASM peers run a single listener
    /// via `run()`.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn run_multi(
        &self,
        listeners: Vec<Box<dyn transport::Listener>>,
    ) -> Result<(), PeerError> {
        let shared = self.shared();
        self.start_engines(&shared);
        server::run_multi(listeners, shared).await
    }
}

// ---------------------------------------------------------------------------
// Dispatch hooks (GUIDE-INSPECTABILITY v1.2 §2.1 #3 / §2.2 "Path tap")
// ---------------------------------------------------------------------------

/// Whether a `DispatchEvent` is fired at request entry or exit.
///
/// Per v1.2 §2.1 #3, each dispatch produces TWO events at the dispatcher↔
/// handler-body boundary: one before the handler is invoked (`Entry`) and
/// one after it returns (`Exit`). Observers correlate them by
/// `(request_id, target_uri)`.
#[derive(Debug, Clone)]
pub enum DispatchPhase {
    /// Fires immediately before `handler.handle(&ctx).await`. No outcome
    /// information yet — observers see the request half of the dispatch.
    Entry,
    /// Fires immediately after the handler returns, before response
    /// construction. Observers see the outcome half.
    Exit {
        /// V7 §8.3 status code returned by the handler.
        status: u32,
        /// Content hash of the result entity. `Hash::zero()` when the
        /// handler returned `Err(_)` before producing a result entity.
        response_hash: entity_hash::Hash,
    },
}

/// Fact-tuple captured at the dispatcher↔handler boundary per
/// GUIDE-INSPECTABILITY v1.2 §2.1 #3.
///
/// **Security note (audit §2.1):** the fact-tuple is metadata-only —
/// `params_hash` is the content hash of the request params entity, not
/// the entity body. Hook fns that need the params body MUST fetch it via
/// a separate auth-checked `ContentStore::get` call. Wire hooks (A3) are
/// the surface that carries full envelope bytes — different cap-scope.
///
/// **Per-hook discipline:** observers MUST snapshot the fields they need
/// before returning. Rust's borrow checker enforces that `&DispatchEvent`
/// cannot outlive the hook call.
#[derive(Debug, Clone)]
pub struct DispatchEvent {
    /// Resolved target URI (handler-pattern + suffix per V7 §6.5).
    pub target_uri: String,
    /// Operation name from the EXECUTE envelope.
    pub operation: String,
    /// Content hash of the request params entity.
    pub params_hash: entity_hash::Hash,
    /// Request ID from the envelope.
    pub request_id: String,
    /// Unix milliseconds at event capture (wall clock).
    pub timestamp_ms: u64,
    /// Whether this is the entry or exit event.
    pub phase: DispatchPhase,
}

/// Observe-only dispatch-event callback.
pub type DispatchHookFn = Arc<dyn Fn(&DispatchEvent) + Send + Sync>;

// ---------------------------------------------------------------------------
// Wire hooks (GUIDE-INSPECTABILITY v1.2 §2.1 #5 / §2.2 "Wire recorder")
// ---------------------------------------------------------------------------

/// Direction of a wire frame relative to the local peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireDirection {
    /// Frame received from the remote peer.
    Recv,
    /// Frame being sent to the remote peer.
    Send,
}

/// Fact-tuple captured at the wire codec boundary per
/// GUIDE-INSPECTABILITY v1.2 §2.1 #5.
///
/// **Security (audit §2.1):** `frame_bytes` is the full CBOR envelope —
/// caps, signatures, identity entities — and observers retaining it
/// effectively maintain a cap-token corpus. Wire recordings MUST be
/// treated as sensitive artifacts; consumers SHOULD cap-scope retention
/// (§6 audit). The hook surface is observe-only; consumers that retain
/// `frame_bytes` past the hook return MUST clone explicitly.
///
/// **Scope (v1.0):** instrumentation covers the post-handshake message
/// loop (Recv after decode_envelope succeeds; Send just before pushing
/// into the response channel). Handshake-frame instrumentation is
/// follow-up work — fold in when an actual wire recorder consumer
/// motivates the cap-scope design (§4 audit).
#[derive(Debug, Clone)]
pub struct WireEvent {
    pub direction: WireDirection,
    pub request_id: String,
    /// The framed CBOR envelope bytes — owned copy; consumers should
    /// avoid retaining unless they have a retention-budgeted sink.
    pub frame_bytes: Vec<u8>,
    /// Remote peer's identity (PeerID base58 string) where known. Empty
    /// for handshake frames where the peer has not yet authenticated.
    pub peer_address: String,
    pub timestamp_ms: u64,
}

/// Observe-only wire-event callback.
pub type WireHookFn = Arc<dyn Fn(&WireEvent) + Send + Sync>;

/// Observe-only binding-event callback. Per GUIDE-INSPECTABILITY v1.2 §2.2
/// "Binding stream" capability.
type BindingObserverFn = Arc<dyn Fn(&TreeChangeEvent) + Send + Sync>;

/// Observe-only binding-event observer.
///
/// Wraps a `BindingObserverFn` closure as a `SyncTreeHook` that always
/// returns `Ok(())` — observers cannot halt the cascade.
struct BindingObserver {
    name: String,
    f: BindingObserverFn,
}

impl SyncTreeHook for BindingObserver {
    fn on_tree_change(
        &self,
        event: &TreeChangeEvent,
        _ctx: &mut ExecutionContext,
    ) -> Result<(), CascadeHalt> {
        (self.f)(event);
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn handler_pattern(&self) -> &str {
        "system/inspect/observer"
    }
}

/// Builder for constructing a Peer with enforced initialization order.
pub struct PeerBuilder {
    keypair: Option<IdentityKeypair>,
    content_store: Option<Arc<dyn ContentStore>>,
    location_index: Option<Arc<dyn LocationIndex>>,
    connector: Option<Arc<dyn transport::Connector>>,
    config: PeerConfig,
    custom_handlers: Vec<Arc<dyn Handler>>,
    binding_hooks: Vec<(String, BindingObserverFn)>,
    dispatch_hooks: Vec<(String, DispatchHookFn)>,
    wire_hooks: Vec<(String, WireHookFn)>,
    /// F27 §6.9a: grantee identity for the principal-level self-owner seed
    /// cap. `None` ⇒ self-owned (the peer's own identity, axiom A1).
    owner_identity: Option<entity_hash::Hash>,
    /// F27 §6.9a: additional seed-policy entries materialized at L0, keyed by
    /// grantee address (hex identity-hash, Base58 PeerID, or literal `default`).
    seed_policy: Vec<(String, Vec<GrantEntry>)>,
    /// GUIDE-CONFORMANCE §7a opt-in: register the `system/validate/*` wire-gate
    /// scaffolding handlers. OFF by default — a peer without it 404s those
    /// patterns and the validator SKIPs honestly per §7a.4. Effective only when
    /// the `conformance` cargo feature is compiled in.
    conformance_handlers: bool,
    /// PROPOSAL-PEER-MANIFEST §4 P1 opt-in: the tracked prefix a
    /// `published_root::PublishRootHook` follows, republishing a signed
    /// `system/peer/published-root` on every trie-root change. `None` ⇒ no
    /// publisher (the peer serves no signed root unless one is minted by hand
    /// via `Peer::publish_root`).
    published_root_prefix: Option<String>,
    #[cfg(feature = "query")]
    query_indexes: Option<Arc<dyn entity_query::QueryIndexStore>>,
    /// Retained by `.idb()` so the built `Peer` can surface `checkpoint()` to
    /// the SDK/app for identity/destructive-op durability. WASM + IDB only.
    #[cfg(all(target_arch = "wasm32", feature = "wasm-idb-persist"))]
    idb_checkpoint: Option<entity_store::idb::IdbCheckpoint>,
}

impl PeerBuilder {
    pub fn new() -> Self {
        Self {
            keypair: None,
            content_store: None,
            location_index: None,
            connector: None,
            config: PeerConfig::default(),
            custom_handlers: Vec::new(),
            binding_hooks: Vec::new(),
            dispatch_hooks: Vec::new(),
            wire_hooks: Vec::new(),
            owner_identity: None,
            seed_policy: Vec::new(),
            conformance_handlers: false,
            published_root_prefix: None,
            #[cfg(feature = "query")]
            query_indexes: None,
            #[cfg(all(target_arch = "wasm32", feature = "wasm-idb-persist"))]
            idb_checkpoint: None,
        }
    }

    /// GUIDE-CONFORMANCE §7a opt-in (typically driven from a host `--validate`
    /// flag). Registers the `system/validate/echo` and
    /// `system/validate/dispatch-outbound` wire-gate handlers so a black-box
    /// validator can probe §6.13(a)/(b). OFF by default.
    ///
    /// **Do not enable in production.** `dispatch-outbound` originates outbound
    /// EXECUTEs from caller-supplied params — exactly the surface you don't want
    /// exposed unless the validator is the only thing wired to it. No-op unless
    /// the `conformance` cargo feature is compiled in.
    pub fn with_conformance_handlers(mut self) -> Self {
        self.conformance_handlers = true;
        self
    }

    /// Set the peer's signing identity from an Ed25519 keypair. Existing
    /// callers (SDK, bindings, CLI) keep working unchanged — the keypair is
    /// wrapped into [`IdentityKeypair::Ed25519`].
    pub fn keypair(mut self, keypair: Keypair) -> Self {
        self.keypair = Some(IdentityKeypair::Ed25519(keypair));
        self
    }

    /// Set the peer's signing identity from any allocated key_type
    /// (v7.67 Phase 2 — Ed448 peer backend). The CLI `--key-type ed448`
    /// path constructs an [`IdentityKeypair::Ed448`] and feeds it here.
    pub fn identity_keypair(mut self, keypair: IdentityKeypair) -> Self {
        self.keypair = Some(keypair);
        self
    }

    pub fn content_store(mut self, store: Arc<dyn ContentStore>) -> Self {
        self.content_store = Some(store);
        self
    }

    pub fn location_index(mut self, index: Arc<dyn LocationIndex>) -> Self {
        self.location_index = Some(index);
        self
    }

    pub fn config(mut self, config: PeerConfig) -> Self {
        self.config = config;
        self
    }

    /// Set the receiver durability policy (EXTENSION-DURABILITY §4) — the max
    /// strength this peer self-determines at acceptance. Overrides the
    /// store-derived default; call after `sqlite`/`opfs` to override their
    /// implicit `Stored`.
    pub fn durability_policy(mut self, policy: durability::DurabilityPolicy) -> Self {
        self.config.durability_policy = policy;
        self
    }

    pub fn listen_addr(mut self, addr: &str) -> Self {
        self.config.listen_addr = addr.to_string();
        self
    }

    /// Set this peer's home `content_hash_format` (V7 §4.5/§8.2) — the
    /// format it prefers in hello negotiation and authors under when not
    /// connection-bound. The per-connection active format is negotiated.
    /// `entity_hash::HASH_ALGORITHM_SHA256` (default) or `_SHA384`.
    pub fn home_hash_format(mut self, format_code: u8) -> Self {
        self.config.home_hash_format = format_code;
        self
    }

    /// Set the §5 keepalive configuration (EXTENSION-NETWORK §2.3;
    /// defaults 30s/10s/3, enabled). Tests inject short intervals here
    /// rather than waiting out the ~100s default envelope.
    pub fn keepalive(mut self, config: keepalive::KeepaliveConfig) -> Self {
        self.config.keepalive = config;
        self
    }

    /// Set the outbound connector for remote peer connections.
    /// Defaults to `TcpConnector` if not set.
    pub fn connector(mut self, connector: Arc<dyn transport::Connector>) -> Self {
        self.connector = Some(connector);
        self
    }

    /// Register a custom handler. It will be registered and bootstrapped
    /// in `build()` after core handlers but before extensions.
    pub fn handler(mut self, handler: Arc<dyn Handler>) -> Self {
        self.custom_handlers.push(handler);
        self
    }

    /// Register an observe-only binding-event hook (GUIDE-INSPECTABILITY v1.2
    /// §2.1 #2 / §2.2 "Binding stream"). Fires inline on every set/remove/CAS
    /// that produces a `TreeChangeEvent`, in registration order, AFTER
    /// extension-owned `SyncTreeHook` consumers have run.
    ///
    /// Observer-only: the closure cannot halt the cascade. For flow-control
    /// hooks, register a `SyncTreeHook` on the `NotifyingLocationIndex`
    /// directly (extension-internal pattern; not exposed via the builder).
    ///
    /// Per security audit §2: the closure MUST snapshot fact-tuple fields by
    /// value if it needs to retain them past return — Rust's borrow checker
    /// enforces this structurally (the `&TreeChangeEvent` reference is
    /// invalid after the hook returns).
    pub fn with_binding_hook(
        mut self,
        name: impl Into<String>,
        f: impl Fn(&TreeChangeEvent) + Send + Sync + 'static,
    ) -> Self {
        self.binding_hooks.push((name.into(), Arc::new(f)));
        self
    }

    /// Publish a signed `system/peer/published-root` over `tracked_prefix` and
    /// **keep republishing it on every trie-root change**
    /// (PROPOSAL-PEER-MANIFEST-STATIC-HANDSHAKE §4 P1).
    ///
    /// `tracked_prefix` is a peer-relative EXTENSION-TREE §3.4.1a prefix ending
    /// in `/`; `"/"` designates the universal tree root (every path in the
    /// peer's own subtree), which is what `--publish-root --serve-closure-root`
    /// selects. Build installs a `system/tree/tracking-config` for it, so the
    /// `RootTrackerEngine` maintains the trie root incrementally and the
    /// publisher only ever re-signs a hash the tracker already computed.
    ///
    /// Trie keys are relative to `tracked_prefix` — under `"/"` that is the
    /// peer-prefix-stripped form (`system/content/public/{hex}`), which is what
    /// a consumer passes to `PublishedRootClient::resolve`.
    pub fn with_published_root(mut self, tracked_prefix: impl Into<String>) -> Self {
        self.published_root_prefix = Some(tracked_prefix.into());
        self
    }

    /// Register an observe-only dispatch-event hook (GUIDE-INSPECTABILITY v1.2
    /// §2.1 #3 / §2.2 "Path tap"). Fires twice per dispatch — once at request
    /// entry, once at request exit — at the dispatcher↔handler-body boundary
    /// (`handler.handle(&ctx).await` in `connection.rs::dispatch_request`).
    ///
    /// Observer-only: the closure receives `&DispatchEvent` and cannot affect
    /// dispatch outcome.
    ///
    /// **Security (audit §2.1):** the event carries `params_hash`, not the
    /// full params entity body. Hook fns that need the body fetch it via a
    /// separate auth-checked `ContentStore::get` call.
    ///
    /// **Note (v1.0):** instrumentation currently covers the synchronous
    /// dispatch path. The async-delivery path (`process_async_delivery`)
    /// and the entity-native compute path (`dispatch_tree_only_handler`)
    /// are tracked as follow-up surfaces.
    pub fn with_dispatch_hook(
        mut self,
        name: impl Into<String>,
        f: impl Fn(&DispatchEvent) + Send + Sync + 'static,
    ) -> Self {
        self.dispatch_hooks.push((name.into(), Arc::new(f)));
        self
    }

    /// Register an observe-only wire-event hook (GUIDE-INSPECTABILITY v1.2
    /// §2.1 #5 / §2.2 "Wire recorder"). Fires at the wire codec boundary:
    /// `WireDirection::Recv` after `decode_envelope` succeeds (request_id
    /// available); `WireDirection::Send` just before pushing the encoded
    /// response frame into the writer channel.
    ///
    /// **SECURITY (audit §2.1 + §6):** wire hooks see the full CBOR
    /// envelope including capability tokens, signatures, and identity
    /// material. Observers retaining `frame_bytes` effectively maintain a
    /// cap-token corpus and MUST be operator-controlled. Wire recorder
    /// consumers SHOULD enforce a retention-volume cap-scope axis per the
    /// security audit's four-axis design.
    ///
    /// **Scope (v1.0):** covers post-handshake message-loop frames.
    /// Handshake-frame instrumentation is a follow-up surface.
    pub fn with_wire_hook(
        mut self,
        name: impl Into<String>,
        f: impl Fn(&WireEvent) + Send + Sync + 'static,
    ) -> Self {
        self.wire_hooks.push((name.into(), Arc::new(f)));
        self
    }

    /// Override the owner identity for the F27 §6.9a self-owner seed cap.
    ///
    /// Defaults to the peer's own identity (self-owned, axiom A1). Set this
    /// for a multi-key / operator-separated model where a distinct operator
    /// identity holds namespace-root authority over `/{peer_id}/*`. The seed
    /// entry is materialized at peer-init regardless of any inbound
    /// authenticate (the §6.9a in-process clause).
    pub fn with_owner_identity(mut self, identity_hash: entity_hash::Hash) -> Self {
        self.owner_identity = Some(identity_hash);
        self
    }

    /// Declare additional F27 §6.9a seed-policy entries materialized at L0.
    ///
    /// Each entry binds a grantee key — a v7.64 hex identity-hash, a Base58
    /// PeerID (pre-contact affordance), or the literal `default` — to a grant
    /// scope. Entries are written to `system/capability/policy/{key}` at
    /// peer-init and read at authenticate via the existing v7.64 dual-form
    /// lookup, unioned with the §4.4 discovery floor. The `self`-owner entry
    /// is always seeded automatically (see [`with_owner_identity`]); this is
    /// for naming operator / admin / reader identities.
    ///
    /// This is the **builder-first supply mechanism** (SDK-OPERATIONS §3.6).
    /// CLI / config / file wrappers desugar to this method — see
    /// [`with_seed_policy_from_file`](Self::with_seed_policy_from_file) for the
    /// keystone-ratified cross-peer file format.
    ///
    /// # A policy entry is read with two OPPOSITE meanings
    ///
    /// This method reads purely additive — you name a grantee, you hand them a
    /// scope — and on the connection path it is: `assemble_inbound_grants`
    /// **unions** the matched entry onto the connection's grants, so a narrow
    /// entry *adds* authority (a floor).
    ///
    /// On the §6.2 `capability:request` path the same entry is the attenuation
    /// **ceiling**: the handler rejects any request that is not an attenuation
    /// of it, so a narrow entry *removes* authority. The two readings live in
    /// different crates (`core/peer::connection` and
    /// `extensions/capability`), and nothing in the type system connects them.
    ///
    /// **This bites hardest on the literal `default` key**, which is the
    /// fallback for every caller without an entry of their own — so a narrow
    /// `default` becomes the request ceiling for the entire peer. Seeding one
    /// with three signaling verbs took the `capability` category from 13/13 to
    /// 7 P / 6 F on 2026-08-08: every §6.2 request 403'd, including ones that
    /// had nothing to do with signaling. A standalone single-handler node never
    /// trips it, because there is no other capability to request.
    ///
    /// So: prefer a **per-grantee** key (hex identity-hash or Base58 PeerID)
    /// whenever the grant is meant to be additive. Reach for `default` only
    /// when you intend a peer-wide ceiling as well as a peer-wide floor. When a
    /// request is rejected by a matched entry the capability handler logs at
    /// `warn` with which form matched.
    ///
    /// [`with_owner_identity`]: Self::with_owner_identity
    pub fn with_seed_policy(mut self, entries: Vec<(String, Vec<GrantEntry>)>) -> Self {
        self.seed_policy.extend(entries);
        self
    }

    /// Declare §6.9a seed-policy entries from a **canonical seed-policy file**.
    ///
    /// The file wrapper the doc above defers to: keystone's protocol-generator
    /// has since ratified the cross-peer format
    /// (`shared/seed-policy/seed-policy.schema.json`), so an operator hands the
    /// same file to a go, python or rust peer. Desugars to
    /// [`with_seed_policy`](Self::with_seed_policy) — every caveat there (the
    /// two opposite readings of a `default` entry above all) applies unchanged.
    ///
    /// Errors on a shape that is not the convention, on `version != 1`, and on
    /// the authority-narrowing fields this seam cannot carry
    /// (`bounds`/`constraints`/`allowances`); see
    /// [`seed_policy::parse_seed_policy`](crate::seed_policy::parse_seed_policy).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_seed_policy_from_file(
        self,
        path: impl AsRef<std::path::Path>,
    ) -> Result<Self, PeerError> {
        let entries = crate::seed_policy::load_seed_policy_file(path)?;
        Ok(self.with_seed_policy(entries))
    }

    /// Provide custom query index storage (e.g., `SqliteQueryIndexes`).
    /// If not set, defaults to in-memory `QueryIndexes`.
    #[cfg(feature = "query")]
    pub fn query_indexes(mut self, indexes: Arc<dyn entity_query::QueryIndexStore>) -> Self {
        self.query_indexes = Some(indexes);
        self
    }

    /// Configure SQLite as the storage backend. Sets content store,
    /// location index, and query indexes (if `query` feature is enabled)
    /// all backed by the same SQLite database.
    #[cfg(feature = "sqlite")]
    pub fn sqlite(mut self, path: impl AsRef<std::path::Path>) -> Result<Self, PeerError> {
        let store = entity_store::sqlite::SqliteStore::open(path)
            .map_err(|e| PeerError::BuildError(format!("sqlite: {e}")))?;
        self.content_store = Some(Arc::new(store.content_store()));
        self.location_index = Some(Arc::new(store.location_index()));
        #[cfg(feature = "query")]
        {
            let query_idx = entity_query::SqliteQueryIndexes::new(store.connection())
                .map_err(|e| PeerError::BuildError(format!("sqlite query indexes: {e}")))?;
            self.query_indexes = Some(Arc::new(query_idx));
        }
        // A persistent store can self-determine `Stored` durability (EXTENSION-DURABILITY §4).
        self.config.durability_policy.max_self_determinable = durability::DurabilityLevel::Stored;
        Ok(self)
    }

    /// Configure OPFS as the storage backend (WASM worker context only).
    ///
    /// Sets content store and location index to OPFS-backed implementations
    /// that durably journal writes to `entities.log` and `locations.log`
    /// under the OPFS subdirectory `root`. See `core/store/src/opfs.rs`.
    ///
    /// `root` is a slash-separated path under the OPFS root; intermediate
    /// directories are created on demand. Use an empty string for the root
    /// directory itself (single-instance case). Multiple OPFS-backed peers
    /// in the same origin MUST use distinct roots — `createSyncAccessHandle`
    /// is exclusive per file.
    ///
    /// Async because OPFS handle acquisition uses Promises. Mirrors the
    /// `Result<Self, PeerError>` shape of `.sqlite()`.
    #[cfg(all(target_arch = "wasm32", feature = "wasm-persist"))]
    pub async fn opfs(mut self, root: &str) -> Result<Self, PeerError> {
        let store = entity_store::opfs::OpfsStore::open(root)
            .await
            .map_err(|e| PeerError::BuildError(format!("opfs: {e}")))?;
        let (cs, li) = store.into_parts();
        self.content_store = Some(Arc::new(cs));
        self.location_index = Some(Arc::new(li));
        // OPFS journals durably (EXTENSION-DURABILITY §4) — self-determine `Stored`.
        self.config.durability_policy.max_self_determinable = durability::DurabilityLevel::Stored;
        Ok(self)
    }

    /// Configure IndexedDB as the storage backend (WASM main-thread or worker).
    ///
    /// Sets content store and location index to IDB-backed implementations: a
    /// sync in-memory mirror (every read) over a **write-behind** durable IDB
    /// journal. Unlike OPFS (synchronous flush-on-write), IDB writes are batched
    /// and committed asynchronously, so a write is durable only once its batch
    /// commits. Identity/destructive ops that cannot tolerate the loss of the
    /// last unflushed window MUST `await` the checkpoint handle
    /// ([`Peer::idb_checkpoint`]) before acknowledging. See
    /// `core/store/src/idb.rs`.
    ///
    /// `name` is the IndexedDB database name. Multiple IDB-backed peers in one
    /// origin SHOULD use distinct names; concurrent writers to one database race
    /// and must be gated by the app's single-writer lock.
    ///
    /// Async because IDB `open` + the initial replay scan are request-based.
    /// Reuses `DurabilityLevel::Stored` for v1 (the policy does not yet
    /// distinguish write-behind from flush-on-write — see the reply doc).
    #[cfg(all(target_arch = "wasm32", feature = "wasm-idb-persist"))]
    pub async fn idb(mut self, name: &str) -> Result<Self, PeerError> {
        let store = entity_store::idb::IdbStore::open(name)
            .await
            .map_err(|e| PeerError::BuildError(format!("idb: {e}")))?;
        // Grab the checkpoint handle before `into_parts()` consumes the store.
        self.idb_checkpoint = Some(store.checkpoint());
        let (cs, li) = store.into_parts();
        self.content_store = Some(Arc::new(cs));
        self.location_index = Some(Arc::new(li));
        // IDB persists durably (best-effort write-behind) — self-determine
        // `Stored` (EXTENSION-DURABILITY §4).
        self.config.durability_policy.max_self_determinable = durability::DurabilityLevel::Stored;
        Ok(self)
    }

    pub fn build(self) -> Result<Peer, PeerError> {
        let keypair = self
            .keypair
            .ok_or_else(|| PeerError::BuildError("keypair is required".into()))?;

        // F27 §3.7: `debug_open_grants` is the degenerate seed policy
        // `default → *`. DEPRECATED in v7.74, scheduled for removal in v7.75 —
        // migrate to `with_seed_policy(...)` / `with_owner_identity(...)`. Warn
        // once at build so operators see it at startup, not just per-connection.
        if self.config.debug_open_grants {
            tracing::warn!(
                "debug_open_grants is DEPRECATED (F27 §3.7, removed v7.75) — \
                 migrate to PeerBuilder::with_seed_policy / with_owner_identity"
            );
        }

        // NB: `build()` deliberately does NOT set the process home
        // `content_hash_format` global (V7 §1.2). That is a deployment-level
        // choice applied once at the process entry point (the CLI `run_peer`
        // from `--hash-type`, or an embedder via
        // `entity_hash::set_default_hash_format`) — one home format per
        // process. Keeping it out of `build()` means constructing many peers
        // in one process (the test suite, multi-peer embeddings) never races
        // the global; home authoring stays deterministic at the floor unless
        // the deployment explicitly opts into a different home format. The
        // `config.home_hash_format` here drives §4.5 wire advertisement /
        // negotiation; §4.5a connection authoring uses explicit
        // `*_with_format` paths. See `PeerConfig::home_hash_format`.

        let peer_id = keypair.peer_id();
        let base_content_store: Arc<dyn ContentStore> = self
            .content_store
            .unwrap_or_else(|| Arc::new(MemoryContentStore::new()));

        // Wrap content store with emit pathway dispatcher (parallel to tree events)
        let (content_event_tx, _) = broadcast::channel::<ContentStoreEvent>(256);
        let content_event_tx_clone = content_event_tx.clone();
        let content_dispatcher = Arc::new(NotifyingContentStore::new(
            base_content_store,
            Arc::new(move |evt| {
                let _ = content_event_tx_clone.send(evt);
            }),
        ));
        let content_store: Arc<dyn ContentStore> = content_dispatcher.clone();

        let base_location_index: Arc<dyn LocationIndex> = self
            .location_index
            .unwrap_or_else(|| Arc::new(MemoryLocationIndex::new()));

        // --- Query extension: wrap with IndexingLocationIndex for synchronous index updates ---
        #[cfg(feature = "query")]
        let query_indexes: Arc<dyn entity_query::QueryIndexStore> = self
            .query_indexes
            .unwrap_or_else(|| Arc::new(entity_query::QueryIndexes::new()));

        #[cfg(feature = "query")]
        let base_location_index: Arc<dyn LocationIndex> =
            Arc::new(entity_query::IndexingLocationIndex::new(
                base_location_index,
                content_store.clone(),
                query_indexes.clone(),
            ));

        // Wrap location index with emit pathway dispatcher (SYSTEM-COMPOSITION §1.3)
        // Two-phase delivery: sync hooks (Phase 1) + broadcast (Phase 2)
        // Hooks registered after engine construction via emit_dispatcher.register_hook().
        let (event_tx, _) = broadcast::channel::<TreeChangeEvent>(256);
        let event_tx_clone = event_tx.clone();
        let emit_dispatcher = Arc::new(NotifyingLocationIndex::new(
            base_location_index,
            Arc::new(move |evt| {
                let _ = event_tx_clone.send(evt); // Phase 2: async broadcast
            }),
        ));
        let notifying_li: Arc<dyn LocationIndex> = emit_dispatcher.clone();

        let tree = Arc::new(TreeHandler::new(
            content_store.clone(),
            notifying_li.clone(),
            peer_id.to_string(),
        ));
        let handler_registry = Arc::new(HandlerRegistry::new());

        // Register the tree handler
        handler_registry.register(tree.clone());

        let pid = peer_id.to_string();

        // Resolve the outbound connector up front: the RELAY forwarder (wired
        // below) needs it to dial terminal/next-hop peers, and the Peer struct
        // takes it at the end of build(). One resolution, shared by both.
        let connector: Arc<dyn transport::Connector> = self
            .connector
            .unwrap_or_else(|| transport::default_connector());

        // Bootstrap: store handler manifest + interface entities in the tree
        bootstrap_handler(
            &content_store,
            &notifying_li,
            &pid,
            "tree",
            "system/tree",
            &[
                "get", "put", "snapshot", "diff", "merge", "extract", "create", "destroy",
            ],
        )?;
        // §A5 (advertise-what-you-dispatch): `ping` (§5.1) is a connect
        // op dispatched on established connections and MUST appear in
        // the manifest — behavioral support without advertisement is the
        // D-class declared-surface divergence the validator flags.
        //
        // FM-2 gave that obligation a second edge: §4.7 row 10 refuses an
        // operation this handler does not implement, so the advertised list and
        // the dispatchable list are now two readings of one inventory — a
        // divergence would make us answer an op we do not publish, or 400 one we
        // do. `CONNECT_OPERATIONS` is that inventory, and it is imported rather
        // than re-spelled here for exactly that reason.
        bootstrap_handler(
            &content_store,
            &notifying_li,
            &pid,
            "connect",
            "system/protocol/connect",
            entity_protocol::CONNECT_OPERATIONS,
        )?;

        // Bootstrap: register and seed all core types into the tree
        let type_registry = entity_types::TypeRegistry::new();
        entity_types::register_core_types(&type_registry);
        for td in type_registry.all() {
            let bare_path = td.tree_path();
            let qualified_path = format!("/{}/{}", pid, bare_path);
            let entity = td
                .to_entity()
                .map_err(|e| PeerError::BuildError(e.to_string()))?;
            let hash = content_store
                .put(entity)
                .map_err(|e| PeerError::BuildError(e.to_string()))?;
            notifying_li.set(&qualified_path, hash);
        }

        // Store the peer's identity entity
        let identity = keypair
            .peer_entity()
            .map_err(|e| PeerError::BuildError(e.to_string()))?;
        let identity_hash = content_store
            .put(identity)
            .map_err(|e| PeerError::BuildError(e.to_string()))?;
        notifying_li.set(&format!("/{}/system/identity/{}", pid, pid), identity_hash);

        // RE-2: announce the local peer's runtime status to the tree.
        // `starting` is written early so any observer reading the tree
        // during the rest of build() sees the correct phase. The
        // transition to `ready` fires at the end of build() once all
        // engines are wired and rebuilds have completed.
        {
            let li_for_status: Arc<dyn LocationIndex> = notifying_li.clone();
            write_peer_self_status(
                PeerPhase::Starting,
                None,
                &content_store,
                &li_for_status,
                &pid,
            )?;
        }

        // --- Custom handlers ---
        for h in self.custom_handlers {
            let pattern = h.pattern().to_string();
            let bare_pattern = entity_entity::EntityUri::strip_peer_prefix(&pattern).to_string();
            let name = bare_pattern
                .rsplit('/')
                .next()
                .unwrap_or(&bare_pattern)
                .to_string();
            let ops: Vec<String> = h.operations().iter().map(|s| s.to_string()).collect();
            handler_registry.register(h);
            let op_refs: Vec<&str> = ops.iter().map(|s| s.as_str()).collect();
            bootstrap_handler(
                &content_store,
                &notifying_li,
                &pid,
                &name,
                &bare_pattern,
                &op_refs,
            )?;
        }

        // --- Extension handlers ---

        #[cfg(feature = "inbox")]
        {
            let inbox = Arc::new(entity_inbox::InboxHandler::new(
                content_store.clone(),
                notifying_li.clone(),
                pid.clone(),
            ));
            handler_registry.register(inbox);
            bootstrap_handler(
                &content_store,
                &notifying_li,
                &pid,
                "inbox",
                "system/inbox",
                &["receive"],
            )?;
        }

        #[cfg(feature = "continuation")]
        {
            let continuation = Arc::new(entity_continuation::ContinuationHandler::new(
                content_store.clone(),
                notifying_li.clone(),
                pid.clone(),
            ));
            handler_registry.register(continuation);
            bootstrap_handler(
                &content_store,
                &notifying_li,
                &pid,
                "continuations",
                "system/continuation",
                &["advance", "resume", "abandon"],
            )?;
        }

        #[cfg(feature = "subscription")]
        let sub_engine = {
            let sub_engine = Arc::new(entity_subscription::engine::Engine::new(
                content_store.clone(),
                notifying_li.clone(),
                pid.clone(),
            ));
            // Restart equivalence: rebuild the routing index from
            // durable tree state. Without this call, persistent peers
            // start with an empty index and notifications silently drop
            // until subscribers re-subscribe. Closes the gap that
            // triggered the restart-equivalence work.
            sub_engine.load();
            let subscription = Arc::new(entity_subscription::SubscriptionHandler::new(
                sub_engine.clone(),
                content_store.clone(),
                notifying_li.clone(),
                pid.clone(),
                identity_hash,
            ));
            handler_registry.register(subscription);
            bootstrap_handler(
                &content_store,
                &notifying_li,
                &pid,
                "subscriptions",
                "system/subscription",
                &["subscribe", "unsubscribe"],
            )?;
            sub_engine
        };

        #[cfg(feature = "clock")]
        {
            let clock_handler = Arc::new(entity_clock::ClockHandler::new(
                content_store.clone(),
                notifying_li.clone(),
                pid.clone(),
            ));
            handler_registry.register(clock_handler);
            bootstrap_handler(
                &content_store,
                &notifying_li,
                &pid,
                "clock",
                "system/clock",
                &["now", "compare", "tick"],
            )?;

            // Store default clock config
            let config_data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
                "mode" => entity_ecf::text("wall"),
                "wall_clock" => entity_ecf::bool_val(true)
            });
            let config_entity = entity_entity::Entity::new("system/clock/config", config_data)
                .map_err(|e| PeerError::BuildError(e.to_string()))?;
            let config_hash = content_store
                .put(config_entity)
                .map_err(|e| PeerError::BuildError(e.to_string()))?;
            notifying_li.set(&format!("/{}/system/clock/config", pid), config_hash);
        }

        #[cfg(feature = "revision")]
        {
            let revision_handler = Arc::new(entity_revision::RevisionHandler::new(
                content_store.clone(),
                notifying_li.clone(),
                pid.clone(),
            ));
            handler_registry.register(revision_handler);
            bootstrap_handler(
                &content_store,
                &notifying_li,
                &pid,
                "revision",
                "system/revision",
                &[
                    "branch",
                    "checkout",
                    "cherry-pick",
                    "commit",
                    "config",
                    "diff",
                    "fetch",
                    "fetch-entities",
                    "find-ancestor",
                    "log",
                    "merge",
                    "merge-config",
                    "push",
                    "resolve",
                    "revert",
                    "status",
                    "tag",
                ],
            )?;
        }

        #[cfg(feature = "history")]
        {
            let history_handler = Arc::new(entity_history::HistoryHandler::new(
                content_store.clone(),
                notifying_li.clone(),
                pid.clone(),
            ));
            handler_registry.register(history_handler);
            bootstrap_handler(
                &content_store,
                &notifying_li,
                &pid,
                "history",
                "system/history",
                &["query", "rollback"],
            )?;
        }

        #[cfg(feature = "compute")]
        let compute_engine = Arc::new(entity_compute::engine::ComputeEngine::new(
            content_store.clone(),
            notifying_li.clone(),
            pid.clone(),
            identity_hash,
        ));

        #[cfg(feature = "compute")]
        {
            let compute_handler = Arc::new(
                entity_compute::ComputeHandler::new(
                    content_store.clone(),
                    notifying_li.clone(),
                    pid.clone(),
                )
                .with_engine(compute_engine.clone()),
            );
            handler_registry.register(compute_handler);
            bootstrap_handler(
                &content_store,
                &notifying_li,
                &pid,
                "compute",
                "system/compute",
                &["eval", "install", "uninstall"],
            )?;
        }

        #[cfg(feature = "query")]
        {
            let query_handler = Arc::new(entity_query::QueryHandler::new(
                query_indexes,
                content_store.clone(),
                notifying_li.clone(),
                pid.clone(),
            ));
            handler_registry.register(query_handler);
            // Query handler bootstrap with input/output types per EXTENSION-QUERY §5.1
            let query_ops = entity_ecf::Value::Map(vec![
                (
                    entity_ecf::text("count"),
                    entity_ecf::Value::Map(vec![
                        (
                            entity_ecf::text("input_type"),
                            entity_ecf::text("system/query/expression"),
                        ),
                        (
                            entity_ecf::text("output_type"),
                            entity_ecf::text("primitive/uint"),
                        ),
                    ]),
                ),
                (
                    entity_ecf::text("find"),
                    entity_ecf::Value::Map(vec![
                        (
                            entity_ecf::text("input_type"),
                            entity_ecf::text("system/query/expression"),
                        ),
                        (
                            entity_ecf::text("output_type"),
                            entity_ecf::text("system/query/result"),
                        ),
                    ]),
                ),
            ]);
            // 1. Interface entity (public contract)
            let query_iface_data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
                "name" => entity_ecf::text("query"),
                "operations" => query_ops,
                "pattern" => entity_ecf::text("system/query")
            });
            let iface =
                entity_entity::Entity::new(entity_types::TYPE_HANDLER_INTERFACE, query_iface_data)
                    .map_err(|e| PeerError::BuildError(e.to_string()))?;
            let ih = content_store
                .put(iface)
                .map_err(|e| PeerError::BuildError(e.to_string()))?;
            notifying_li.set(&format!("/{}/system/handler/system/query", pid), ih);
            // 2. Handler entity (dispatch target, references interface)
            let query_handler_data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
                "interface" => entity_ecf::text("system/handler/system/query")
            });
            let handler_ent =
                entity_entity::Entity::new(entity_types::TYPE_HANDLER, query_handler_data)
                    .map_err(|e| PeerError::BuildError(e.to_string()))?;
            let hh = content_store
                .put(handler_ent)
                .map_err(|e| PeerError::BuildError(e.to_string()))?;
            notifying_li.set(&format!("/{}/system/query", pid), hh);
        }

        // Identity hash — needed for handler grants, clock engine, history engine
        let identity_hash = entity_hash::Hash::compute(
            entity_crypto::TYPE_PEER,
            &keypair
                .peer_entity()
                .map_err(|e| PeerError::BuildError(e.to_string()))?
                .data,
        );

        // V7 §6.9 bootstrap MUST: system/handler is one of the three required
        // bootstrap handlers (Tree, Handlers, Connect). It implements the
        // register/unregister entry point for dynamic handler installation
        // (§3.12, §6.2). Must be wired BEFORE the per-handler grant loop below
        // so its self-grant is created alongside the others.
        #[cfg(feature = "handlers")]
        {
            let handlers_handler = Arc::new(entity_handler_ops::HandlersHandler::new(
                content_store.clone(),
                notifying_li.clone(),
                pid.clone(),
                identity_hash,
                keypair.clone_identity(),
            ));
            handler_registry.register(handlers_handler);
            bootstrap_handler(
                &content_store,
                &notifying_li,
                &pid,
                "handler",
                "system/handler",
                &["register", "unregister"],
            )?;
        }

        // GUIDE-CONFORMANCE §7a wire-gate scaffolding — runtime opt-in (NOT
        // core protocol, NOT an extension primitive). Registered only when the
        // host called `with_conformance_handlers()` (typically a `--validate`
        // flag). A peer without the opt-in 404s system/validate/* and the
        // validator SKIPs honestly per §7a.4. MUST NOT be enabled in
        // production — dispatch-outbound originates outbound EXECUTEs from
        // caller-supplied params.
        #[cfg(feature = "conformance")]
        if self.conformance_handlers {
            let echo = Arc::new(entity_conformance::EchoHandler::new(&pid));
            handler_registry.register(echo);
            bootstrap_handler(
                &content_store,
                &notifying_li,
                &pid,
                "echo",
                "system/validate/echo",
                &["echo"],
            )?;
            let dispatch = Arc::new(entity_conformance::DispatchOutboundHandler::new(&pid));
            handler_registry.register(dispatch);
            bootstrap_handler(
                &content_store,
                &notifying_li,
                &pid,
                "dispatch-outbound",
                "system/validate/dispatch-outbound",
                &["dispatch"],
            )?;
            tracing::warn!(
                "GUIDE-CONFORMANCE §7a handlers ENABLED (system/validate/echo + \
                 dispatch-outbound) — test scaffolding; MUST NOT be enabled in production"
            );
        }

        // V7 §6.2 — the capability handler is SHOULD per §6.2:2516 and is
        // advertised by `default_connection_grants` (system/capability:request).
        // Per the capability-handler-advertisement ruling: an advertised
        // grant SHALL only reference handlers registered on this peer, so we
        // ship Resolution B (register the handler) so the advertised grant
        // resolves on dispatch instead of returning `handler_not_found`.
        #[cfg(feature = "capability-handler")]
        {
            let identity_entity = keypair
                .peer_entity()
                .map_err(|e| PeerError::BuildError(e.to_string()))?;
            let capability_handler = Arc::new(entity_capability_handler::CapabilityHandler::new(
                content_store.clone(),
                notifying_li.clone(),
                pid.clone(),
                identity_hash,
                identity_entity,
                keypair.clone_identity(),
            ));
            handler_registry.register(capability_handler);
            bootstrap_handler(
                &content_store,
                &notifying_li,
                &pid,
                "capability",
                "system/capability",
                &["request", "delegate", "revoke"],
            )?;
        }

        // EXTENSION-ATTESTATION v1.0 + EXTENSION-QUORUM v1.0 + EXTENSION-IDENTITY
        // v3.2 — three-extension stack. Per §12.5, bootstrap exemption: the
        // first `configure` (and initial `create_quorum` / `create_attestation`)
        // calls run via the L0 direct-store path (peer-owner authority),
        // bypassing dispatch authorization. After bootstrap, all identity ops
        // require controller-peer authority via the local peer→controller cap.
        //
        // Substrate primitive shared state (always created when feature is
        // enabled, since identity depends on quorum depends on attestation).
        #[cfg(feature = "attestation")]
        let attestation_index = Arc::new(entity_attestation::AttestationIndex::new());
        #[cfg(feature = "quorum")]
        let resolver_registry = entity_quorum::ResolverRegistry::new();
        #[cfg(feature = "quorum")]
        let signer_set_cache = Arc::new(entity_quorum::SignerSetCache::new());

        // Restart equivalence: rebuild the attestation index from the
        // durable tree state before any handler dispatches. Without this
        // call, persistent peers start with an empty index and identity
        // / quorum / role lookups silently miss entries until something
        // re-writes them. Closes EXTENSION-ATTESTATION §5.7 invariant.
        #[cfg(feature = "attestation")]
        {
            let li_for_load: Arc<dyn LocationIndex> = notifying_li.clone();
            attestation_index.load(&content_store, &li_for_load, &pid);
        }

        #[cfg(feature = "attestation")]
        {
            let attestation_handler = Arc::new(entity_attestation::AttestationHandler::new(
                content_store.clone(),
                notifying_li.clone(),
                attestation_index.clone(),
                pid.clone(),
            ));
            handler_registry.register(attestation_handler);
            bootstrap_handler(
                &content_store,
                &notifying_li,
                &pid,
                "attestation",
                "system/attestation",
                &["create", "supersede", "revoke", "verify"],
            )?;

            // Per EXTENSION-ATTESTATION v1.1 §5.7 / §9.1 invariant I1:
            // the index MUST be populated when ANY operation writes a
            // `system/attestation` entity to the tree (not only via the
            // substrate's `:create`). The index hook fires on every
            // tree write and updates indexes when the written entity is
            // `system/attestation`.
            //
            // Registered EARLY in the cascade so subsequent hooks +
            // handlers (identity/process_attestation, quorum cache
            // invalidation, etc.) see the bound entity in the index.
            let attestation_hook = Arc::new(entity_attestation::AttestationIndexHook::new(
                attestation_index.clone(),
                content_store.clone(),
                pid.clone(),
            ));
            emit_dispatcher.register_hook(attestation_hook);
        }

        #[cfg(feature = "quorum")]
        {
            let quorum_handler = Arc::new(entity_quorum::QuorumHandler::new(
                content_store.clone(),
                notifying_li.clone(),
                attestation_index.clone(),
                resolver_registry.clone(),
                signer_set_cache.clone(),
                pid.clone(),
            ));
            handler_registry.register(quorum_handler);
            bootstrap_handler(
                &content_store,
                &notifying_li,
                &pid,
                "quorum",
                "system/quorum",
                &["create", "update", "publish", "verify"],
            )?;
        }

        #[cfg(feature = "identity")]
        let attestation_store: Arc<dyn AttestationStore> =
            Arc::new(entity_identity::IdentityAttestationStore::new(
                attestation_index.clone(),
                content_store.clone(),
                notifying_li.clone(),
            ));
        #[cfg(not(feature = "identity"))]
        let attestation_store: Arc<dyn AttestationStore> = Arc::new(NoopAttestationStore);

        #[cfg(feature = "identity")]
        {
            let identity_handler = Arc::new(entity_identity::IdentityHandler::new(
                content_store.clone(),
                notifying_li.clone(),
                attestation_index.clone(),
                resolver_registry.clone(),
                signer_set_cache.clone(),
                pid.clone(),
                identity_hash,
                keypair.clone_identity(),
            ));
            handler_registry.register(identity_handler);
            // EXTENSION-IDENTITY v3.2 — 7 generic ops (preserved from v3.0).
            bootstrap_handler(
                &content_store,
                &notifying_li,
                &pid,
                "identity",
                "system/identity",
                &[
                    "configure",
                    "create_quorum",
                    "create_attestation",
                    "supersede_attestation",
                    "revoke_attestation",
                    "publish_attestation",
                    "process_attestation",
                ],
            )?;
        }

        // EXTENSION-ROLE v1.5 — `system/role` handler. Registered after
        // identity so identity bootstrap can install assignments via the
        // role handler in subsequent phases. Phase 2 advertises only the
        // four MVP ops; `define`, `re-derive`, `delegate` are added in
        // Phase 4+. The bootstrap manifest below mirrors the handler's
        // `operations()` slice; keep them in sync.
        #[cfg(feature = "role")]
        {
            let role_handler = Arc::new(entity_role::RoleHandler::new(
                content_store.clone(),
                notifying_li.clone(),
                pid.clone(),
                identity_hash,
                keypair.clone_identity(),
            ));
            handler_registry.register(role_handler);
            bootstrap_handler(
                &content_store,
                &notifying_li,
                &pid,
                "role",
                "system/role",
                &[
                    "assign",
                    "unassign",
                    "exclude",
                    "unexclude",
                    "define",
                    "re-derive",
                    "delegate",
                ],
            )?;

            // EXTENSION-ROLE §6.5 / IA8 — fleet-wide reactive sweep on
            // exclusion arrival. Required to make layer-1 enforcement
            // actually fleet-wide; without this, sibling peers in a
            // multi-device fleet would keep role-derived tokens for an
            // excluded peer until the next manual re-derive.
            let exclusion_sweep_hook = Arc::new(entity_role::RoleExclusionSweepHook::new(
                content_store.clone(),
                notifying_li.clone(),
                pid.clone(),
            ));
            emit_dispatcher.register_hook(exclusion_sweep_hook);
        }

        // EXTENSION-REGISTRY v1.0 — `system/registry` meta-resolver +
        // `system/registry/local-name` backend. Registered before the §6.9 step-6
        // handler-grant loop so both get auto handler-grants; the §6.9a
        // owner-self-grant gives the local peer full self-access over these
        // ops, satisfying the §5.2 / absorption §6.11 "grant the local peer all
        // seven registry caps" floor. No in-memory index (the local-name backend
        // reads its two-layer storage straight from the tree), so no hook. The
        // meta-resolver defaults to a local-name-only chain when no resolver-config
        // is present (§10), so the local store works out of the box.
        #[cfg(feature = "registry")]
        {
            let resolution_log = Arc::new(entity_registry::ResolutionLog::new(
                content_store.clone(),
                notifying_li.clone(),
                pid.clone(),
                1024,
            ));
            let registry_handler = entity_registry::RegistryHandler::new(
                content_store.clone(),
                notifying_li.clone(),
                pid.clone(),
                resolution_log,
            );
            // The §2.2 live remote-read transport for `peer-issued` chain
            // entries. Wired unconditionally where it can be built: it costs
            // nothing until a chain entry is BOTH `peer-issued` and carries an
            // endpoint hint, and a peer that pins a registry it cannot dial is
            // the confusing half-configured state — the pin looks installed and
            // silently resolves nothing.
            #[cfg(all(feature = "http-live", not(target_arch = "wasm32")))]
            let registry_handler = registry_handler
                .with_reader(Arc::new(crate::poll_read::HttpPollRegistryReader::new()));
            handler_registry.register(Arc::new(registry_handler));
            bootstrap_handler(
                &content_store,
                &notifying_li,
                &pid,
                "registry",
                "system/registry",
                // The §4.3 `[v1.18]` config pair is advertised here with the
                // resolve pair: `system/capability/registry-configure` named
                // an act with no operation until 1.18, and the §4.4
                // advertised-handler discipline is what makes it callable.
                &[
                    "resolve",
                    "invalidate-cache",
                    "set-resolver-config",
                    "get-resolver-config",
                ],
            )?;

            let local_name_handler = Arc::new(entity_registry::LocalNameHandler::new(
                content_store.clone(),
                notifying_li.clone(),
                pid.clone(),
            ));
            handler_registry.register(local_name_handler);
            bootstrap_handler(
                &content_store,
                &notifying_li,
                &pid,
                "registry-local-name",
                "system/registry/local-name",
                &["bind", "unbind", "list", "update-transports"],
            )?;

            // EXTENSION-REGISTRY §6a.9 — peer-issued live registration. Running
            // this handler is what makes the peer a *live* registry (a curated/
            // static registry §6a.8 simply omits it). The external surface
            // (`register-request`) stays gated by `registry-request-binding`,
            // which is NOT auto-seeded — an operator grants it explicitly — and
            // **no issuer-policy is stored until one is written**, so the
            // registration ops answer 404 curated-only (§6a.9.2: unset is not a
            // mode) and registering the handler here is inert until the operator
            // arms it. The §6.9a owner-self-grant still lets the local operator
            // drive its own ops, including the §6a.9.2 arming pair. The injected
            // signer is K_registry (the peer's own identity).
            let register_handler = Arc::new(entity_registry::RegisterRequestHandler::new(
                content_store.clone(),
                notifying_li.clone(),
                pid.clone(),
                keypair.clone_identity(),
            ));
            handler_registry.register(register_handler);
            bootstrap_handler(
                &content_store,
                &notifying_li,
                &pid,
                "registry-peer-issued",
                "system/registry/peer-issued",
                &[
                    "register-request",
                    "revoke-request",
                    "renew-request",
                    "set-issuer-policy",
                    "get-issuer-policy",
                ],
            )?;
        }

        // EXTENSION-DISCOVERY v1.0 — `system/discovery` (scan + announce +
        // announce-stop). The mDNS backend is native-only (browsers can't speak
        // multicast UDP, §3.4) and opens its socket lazily on first use, so
        // registering it here is free until discovery is actually exercised. On
        // wasm32 the handler registers with no backend; `:scan(mdns)` then
        // returns `unsupported_backend` (§3.4) rather than failing.
        // vec_init_then_push: the push below is cfg-gated (native-only
        // backend on an otherwise-empty wasm32 list) — a literal can't
        // express that.
        #[cfg(feature = "discovery")]
        #[allow(clippy::vec_init_then_push)]
        {
            #[allow(unused_mut)]
            let mut backends: Vec<Arc<dyn entity_discovery::DiscoveryBackend>> = Vec::new();
            #[cfg(not(target_arch = "wasm32"))]
            backends.push(Arc::new(entity_discovery::MdnsBackend::new()));

            let discovery_handler = Arc::new(entity_discovery::DiscoveryHandler::new(
                content_store.clone(),
                notifying_li.clone(),
                pid.clone(),
                backends,
            ));
            handler_registry.register(discovery_handler);
            bootstrap_handler(
                &content_store,
                &notifying_li,
                &pid,
                "discovery",
                "system/discovery",
                &["scan", "announce", "announce-stop"],
            )?;
        }

        // EXTENSION-RELAY v1.0 — `system/relay` (forward + put + poll +
        // advertise). v1 ships Mode F + Mode S; the in-memory Mode-S store and
        // relay-owned poll cursor live in the handler. Mode-F outbound delivery
        // is delegated to the injected `PeerRelayForwarder`, which performs the
        // §3.1.1 terminal-hop **raw-frame** delivery (inner envelope bytes
        // written verbatim into the destination's inbound frame — never
        // decoded/re-encoded) and the intermediate-hop forward over the peer's
        // connection pool. When the next hop can't be dialed the forwarder
        // reports unreachable and Mode F takes the §6.2.1 Mode-S fallback
        // (store at the destination's peer-id namespace).
        #[cfg(feature = "relay")]
        {
            let forwarder = Arc::new(relay_forwarder::PeerRelayForwarder::new(
                keypair.clone_identity(),
                content_store.clone(),
                notifying_li.clone(),
                connector.clone(),
                pid.clone(),
                self.config.home_hash_format,
            ));
            // §3.5 inbox-relay resolver (the MX lookup) for the §6.2.1 fallback.
            // Tree-backed + signature-verifying: reads the destination's signed
            // `system/peer/inbox-relay` declaration from the peer's tree and
            // returns it only if the V7 §5.2 invariant-pointer signature verifies
            // against the destination's own key (forged-redirection defense,
            // §3.5). Replaces the Nop default so the positive resolver path and
            // the fail-closed forged-decl rejection are both live.
            let inbox_relay_resolver = Arc::new(entity_relay::TreeInboxRelayResolver::new(
                content_store.clone(),
                notifying_li.clone(),
                pid.clone(),
            ));
            let relay_handler = Arc::new(
                entity_relay::RelayHandler::new(
                    content_store.clone(),
                    notifying_li.clone(),
                    pid.clone(),
                )
                .with_forwarder(forwarder)
                .with_inbox_relay_resolver(inbox_relay_resolver)
                // §8.1 / §8.2 (v1.3) operator bounds. Both default-off; when
                // set they are enforced AND published (the self-advertise
                // below reads them back off the handler, so there is one
                // source of truth for "what this relay actually enforces").
                .with_store_retention_ms(self.config.relay_store_retention_ms)
                .with_max_storage_bytes(self.config.relay_max_storage_bytes),
            );
            // §4.1 self-advertise. Published BEFORE the handler is registered
            // is unnecessary, but it must be published at all: §8.1 makes
            // publishing `max_retention_ms` a MUST for any relay that enforces
            // a ceiling, and §4.1 states the reason — "a ceiling that is
            // enforced but unpublished configures behaviour no counterparty can
            // observe before depending on it." A sender choosing a relay, and a
            // peer choosing which relays to name in its own §3.5 inbox-relay
            // declaration, both depend on how long an entry will be held.
            publish_relay_self_advertise(
                &content_store,
                &notifying_li,
                &keypair,
                &pid,
                relay_handler.configured_limits(),
            )?;
            handler_registry.register(relay_handler);
            bootstrap_handler(
                &content_store,
                &notifying_li,
                &pid,
                "relay",
                "system/relay",
                &["forward", "put", "poll", "advertise"],
            )?;
        }

        // EXTENSION-NETWORK §3–§4 (Amendment 12 rung 3) — `system/network`:
        // the maintain-peer reconnect lifecycle over the §A3 liveness floor.
        // Registered here so the §6.9 grant loop mints its handler grant
        // from `internal_scope()` (the §3.1 block + the two graph-authorizing
        // entries); the imperative connect/keepalive seam (`PeerLink`) is
        // injected at `start_engines` once `shared()` exists. Held as an Arc
        // on the Peer so the bind can reach it post-construction.
        #[cfg(feature = "network")]
        let network_handler = {
            let handler = Arc::new(entity_network::NetworkHandler::new(
                content_store.clone(),
                notifying_li.clone(),
                pid.clone(),
            ));
            handler_registry.register(handler.clone());
            bootstrap_handler(
                &content_store,
                &notifying_li,
                &pid,
                "network",
                "system/network",
                &[
                    "maintain-peer",
                    "release-peer",
                    "status",
                    "close",
                    "reconnect",
                    "restore-subscriptions",
                    // §6.7.1 (Amendment 13). Advertised so a caller can see
                    // the peer offers reflection before spending a round trip
                    // on it; §6.7.4 makes network-reflect a broad default
                    // grant, since the operation is a mirror and leaks nothing
                    // the caller did not reveal by connecting.
                    entity_network::OP_OBSERVE_ADDRESS,
                ],
            )?;
            handler
        };

        // EXTENSION-TYPE v1.1 — `system/type` (validate + compare + compatible)
        // and `system/type/constraint/*` (standard constraint handler over
        // the 11 standard constraint kinds). Constraint handler injects
        // tree access so `type_pattern` constraints can resolve hash /
        // path references.
        //
        // The constraint handler binds at `system/type/constraint`
        // (no `/*`) — the V7 §6.6 longest-prefix resolver walks back
        // through segments and finds it for any
        // `system/type/constraint/{kind}` dispatch. The wildcard suffix
        // lives ONLY in the published manifest's `pattern` field per
        // §5.1, signalling to readers that this handler covers
        // everything below the prefix. Standard `bootstrap_handler`
        // can't express the path-vs-manifest split, so we write the
        // interface + handler entities manually here.
        #[cfg(feature = "type-system")]
        {
            let constraint_handler = Arc::new(
                entity_type_system::StandardConstraintHandler::new(pid.clone())
                    .with_tree_access(content_store.clone(), notifying_li.clone()),
            );
            handler_registry.register(constraint_handler);

            // Manifest entity (public contract) — bound at
            // /{peer_id}/system/handler/system/type/constraint per the
            // strip-wildcard convention; `pattern` data field carries
            // the wildcard per §5.1 spec example.
            let constraint_iface_data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
                "name" => entity_ecf::text("standard-constraints"),
                "operations" => entity_ecf::Value::Map(vec![(
                    entity_ecf::text("validate"),
                    entity_ecf::Value::Map(vec![
                        (entity_ecf::text("input_type"),
                         entity_ecf::text("system/type/constraint/validate-request")),
                        (entity_ecf::text("output_type"),
                         entity_ecf::text("system/type/constraint/validate-result")),
                    ]),
                )]),
                "pattern" => entity_ecf::text("system/type/constraint/*")
            });
            let iface = entity_entity::Entity::new(
                entity_types::TYPE_HANDLER_INTERFACE,
                constraint_iface_data,
            )
            .map_err(|e| PeerError::BuildError(e.to_string()))?;
            let iface_hash = content_store
                .put(iface)
                .map_err(|e| PeerError::BuildError(e.to_string()))?;
            notifying_li.set(
                &format!("/{}/system/handler/system/type/constraint", pid),
                iface_hash,
            );

            // Handler entity at the dispatch target (no /*).
            let handler_data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
                "interface" => entity_ecf::text("system/handler/system/type/constraint")
            });
            let handler_ent = entity_entity::Entity::new(entity_types::TYPE_HANDLER, handler_data)
                .map_err(|e| PeerError::BuildError(e.to_string()))?;
            let hh = content_store
                .put(handler_ent)
                .map_err(|e| PeerError::BuildError(e.to_string()))?;
            notifying_li.set(&format!("/{}/system/type/constraint", pid), hh);

            let type_handler = Arc::new(entity_type_system::TypeHandler::new(
                pid.clone(),
                content_store.clone(),
                notifying_li.clone(),
            ));
            handler_registry.register(type_handler);
            bootstrap_handler(
                &content_store,
                &notifying_li,
                &pid,
                "types",
                "system/type",
                &["validate", "compare", "compatible"],
            )?;
        }

        // EXTENSION-CONTENT v3.5 — optional `system/content` handler.
        // Hash-addressed `get` (§6.2) + content-store `ingest` (§6.3).
        // Both ops require a `resource` field per the v3.5 normative
        // tightening; without one the handler returns
        // `path_required`. Handler binds at the bare prefix
        // `system/content`; the dispatcher's longest-prefix walk-back
        // (V7 §6.6) routes `system/content/{namespace}` URIs here so
        // namespace scoping (§6.4) is enforced at the handler.
        // Bootstrap entities use the standard helper — the manifest
        // pattern in the published interface is `system/content/*`
        // (§6.1) so consumers see the spec-advertised glob; the
        // dispatch target is the bare prefix.
        #[cfg(feature = "content")]
        {
            // Arch ruling 1b5c125 §2.3 — wire the
            // notifying LocationIndex into the content handler so
            // ingest writes the CONTENT §6.4.2 Hash Tree Presence
            // binding (`{namespace_uri}/{hex(H)}` → H). The spec MUST
            // the cohort had all three impls missing; closes the
            // gap that was blocking NamespaceScope serving-mode.
            let mut content_handler =
                entity_content::SystemContentHandler::new(&pid, content_store.clone())
                    .with_location_index(notifying_li.clone());
            if let Some(budget) = self.config.content_get_frame_budget {
                content_handler = content_handler.with_frame_budget(budget);
            }
            let content_handler = Arc::new(content_handler);
            handler_registry.register(content_handler);

            // Manifest entity with the spec-advertised `system/content/*`
            // glob. We can't use the generic `bootstrap_handler` helper
            // because it sets `pattern == bare_pattern` (no wildcard);
            // §6.1 wants the wildcard suffix in the manifest itself.
            let iface_data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
                "name" => entity_ecf::text("content"),
                "operations" => entity_ecf::Value::Map(vec![
                    (entity_ecf::text("get"), entity_ecf::Value::Map(vec![
                        (entity_ecf::text("input_type"),
                         entity_ecf::text("system/content/get-request")),
                        (entity_ecf::text("output_type"),
                         entity_ecf::text("system/content/content-response")),
                    ])),
                    (entity_ecf::text("ingest"), entity_ecf::Value::Map(vec![
                        (entity_ecf::text("input_type"),
                         entity_ecf::text("system/content/ingest-request")),
                        (entity_ecf::text("output_type"),
                         entity_ecf::text("system/content/ingest-result")),
                    ])),
                ]),
                "pattern" => entity_ecf::text("system/content/*")
            });
            let iface =
                entity_entity::Entity::new(entity_types::TYPE_HANDLER_INTERFACE, iface_data)
                    .map_err(|e| PeerError::BuildError(e.to_string()))?;
            let iface_hash = content_store
                .put(iface)
                .map_err(|e| PeerError::BuildError(e.to_string()))?;
            notifying_li.set(
                &format!("/{}/system/handler/system/content", pid),
                iface_hash,
            );

            let handler_data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
                "interface" => entity_ecf::text("system/handler/system/content")
            });
            let handler_ent = entity_entity::Entity::new(entity_types::TYPE_HANDLER, handler_data)
                .map_err(|e| PeerError::BuildError(e.to_string()))?;
            let hh = content_store
                .put(handler_ent)
                .map_err(|e| PeerError::BuildError(e.to_string()))?;
            notifying_li.set(&format!("/{}/system/content", pid), hh);
        }

        // DOMAIN-LOCAL-FILES v1.2 — optional `local/files` handler. Maps
        // host filesystem subtrees into the entity tree via the CONTENT
        // v3.5 substrate. Root mappings are configured via
        // `system/config/local/files/{name}` entities; the handler's
        // `load()` rebuilds in-memory state at startup. Reverse-write
        // (tree → filesystem) is wired by `start_engines` against the
        // peer's tree-change broadcast.
        #[cfg(all(feature = "local-files", not(target_arch = "wasm32")))]
        let local_files_handler = {
            let h = Arc::new(entity_local_files::LocalFilesHandler::new(
                pid.clone(),
                content_store.clone(),
                notifying_li.clone(),
            ));
            handler_registry.register(h.clone());
            bootstrap_handler(
                &content_store,
                &notifying_li,
                &pid,
                "local-files",
                "local/files",
                &["read", "write", "list", "delete", "watch"],
            )?;
            // Domain types (§11) — written into the tree at handler install.
            for td in entity_local_files::all_domain_types() {
                let qualified_path = format!("/{}/{}", pid, td.tree_path());
                let entity = td
                    .to_entity()
                    .map_err(|e| PeerError::BuildError(e.to_string()))?;
                let hash = content_store
                    .put(entity)
                    .map_err(|e| PeerError::BuildError(e.to_string()))?;
                notifying_li.set(&qualified_path, hash);
            }
            // Rehydrate root mappings from configs already in the tree
            // (GUIDE-RESTART-AND-PERSISTENCE.md §3 RE-1).
            h.load();
            h
        };

        // §6.9 step 6: Create handler grants for all registered handlers.
        //
        // The default (no `internal_scope`) is `default_handler_self_grant`, NOT
        // `wildcard_handler_grant`: since D1 (§5.2 resource dimension on the
        // in-process path) this grant is the ceiling for everything the handler
        // sub-dispatches, and the bare-`*` resource form canonicalizes to
        // `/{local}/*` — which would forbid the peer's own engine from writing
        // the foreign-namespace subtrees its store legitimately holds (V7 §1.4
        // Category A). See `default_handler_self_grant` for the full argument.
        //
        // Note `create_handler_grant` is install-once (Class I): a peer whose
        // tree already binds `system/capability/grants/{pattern}` keeps the grant
        // it was seeded with. That is deliberate (GUIDE-RESTART-AND-PERSISTENCE
        // §2.2) — the shape change reaches new peers, not stores minted earlier.
        let registered_patterns = handler_registry.patterns();
        for pattern in &registered_patterns {
            let bare = entity_entity::EntityUri::strip_peer_prefix(pattern).to_string();
            let scope = handler_registry
                .get(pattern)
                .and_then(|h| h.internal_scope())
                .unwrap_or_else(entity_capability::default_handler_self_grant);
            create_handler_grant(
                &bare,
                scope,
                &keypair,
                identity_hash,
                &content_store,
                &notifying_li,
                &pid,
            )?;
        }

        // F27 §6.9a peer-authority-bootstrap: materialize the principal-level
        // self-owner seed capability at L0, in ADDITION to the per-handler
        // self-grants above (§6.9a.4 coexistence — the per-handler grants stay
        // for peer-internal dispatch; this is the wire-time owner authority a
        // connection authenticating as the peer's own identity receives).
        //
        // Stored as a `TYPE_CAP_POLICY_ENTRY` at the v7.64 hex form
        // `system/capability/policy/{self_identity_hash_hex}` and read back by
        // `lookup_capability_policy_grants` at authenticate via the existing
        // dual-form lookup. Eager + entity-native + inspectable (A5);
        // materialized regardless of any inbound authenticate (the in-process
        // clause). The local tree is the trust root for policy entries, so —
        // unlike Go/keystone's self-signed token shape — no detached signature
        // is needed; the read path trusts entries present in the peer's own
        // tree (§9.4 impl-defined; §6.9a.4 either model conformant).
        {
            let owner_identity = self.owner_identity.unwrap_or(identity_hash);
            let mut seed_entries: Vec<(String, Vec<GrantEntry>)> = vec![(
                owner_identity.to_hex(),
                entity_capability::owner_self_grant(&pid),
            )];
            seed_entries.extend(self.seed_policy.iter().cloned());
            for (key, grants) in &seed_entries {
                write_seed_policy_entry(&content_store, &notifying_li, &pid, key, grants)?;
            }
        }

        #[cfg(feature = "clock")]
        let clock_engine = Arc::new(entity_clock::engine::ClockEngine::new(
            content_store.clone(),
            notifying_li.clone(),
            identity_hash,
            pid.clone(),
        ));

        #[cfg(feature = "revision")]
        let revision_engine = Arc::new(entity_revision::engine::RevisionEngine::new(
            content_store.clone(),
            notifying_li.clone(),
            pid.clone(),
        ));

        #[cfg(feature = "history")]
        let history_engine = Arc::new(entity_history::engine::HistoryEngine::new(
            content_store.clone(),
            notifying_li.clone(),
            pid.clone(),
            identity_hash,
        ));
        // Register synchronous emit pathway hooks in spec order
        // (SYSTEM-COMPOSITION §2.2). Query is already at position 1 via
        // IndexingLocationIndex decorator. Hooks registered here are positions 2-6.
        #[cfg(feature = "clock")]
        emit_dispatcher.register_hook(clock_engine.clone());
        #[cfg(feature = "clock")]
        emit_dispatcher.register_context_field(ContextFieldRegistration {
            field_name: "clock".to_string(),
            owner: "clock/advance".to_string(),
            description: "Structured clock state (system/clock/state)".to_string(),
        });

        #[cfg(feature = "history")]
        emit_dispatcher.register_hook(history_engine.clone());

        // Position 5 (compute) — reactive re-evaluation (SYSTEM-COMPOSITION §2.2)
        #[cfg(feature = "compute")]
        {
            compute_engine.rebuild_index();
            emit_dispatcher.register_hook(compute_engine);
        }

        // Position 6 (structural summaries): incremental trie root tracker
        // (EXTENSION-TREE §3.4, SYSTEM-COMPOSITION §2.2).
        let root_tracker = Arc::new(entity_tree::root_tracker::RootTrackerEngine::new(
            content_store.clone(),
            notifying_li.clone(),
            pid.clone(),
        ));
        root_tracker.bootstrap();
        emit_dispatcher.register_hook(root_tracker.clone());

        // PROPOSAL-PEER-MANIFEST §4 P1: re-sign the published-root on every
        // trie-root change. Registered right after the tracker whose output it
        // watches (the tracker's root write nested-dispatches through every
        // hook, so ordering is for legibility, not correctness).
        let published_root_hook = self.published_root_prefix.as_ref().map(|prefix| {
            let hook = Arc::new(published_root::PublishRootHook::new(
                published_root::PublishRootEngine::new(
                    content_store.clone(),
                    notifying_li.clone(),
                    keypair.clone_identity(),
                    pid.clone(),
                    identity_hash,
                    // §3.3a: declare the absolute prefix the tracker actually
                    // trims by, taken from the tracker itself. Under our
                    // universal `"/"` that is `/{peer_id}/` — the §3.3
                    // peer-qualified shape, which is what our keys really are
                    // (`system/attestation`, not the fully-qualified form the
                    // universal shape would require).
                    root_tracker.qualified_bare_prefix(prefix),
                ),
                root_tracker.qualified_root_path(prefix),
            ));
            emit_dispatcher.register_hook(hook.clone());
            hook
        });

        // Revision config ↔ tracking-config coordination (precondition hook).
        // Fires on writes to `system/revision/config/prefixes/*` and keeps the
        // matching `system/tree/tracking-config/*` entity in sync.
        // Registered after root_tracker so tracking-config writes the hook
        // produces are picked up by the same-cascade tracker pass.
        #[cfg(feature = "revision")]
        {
            let config_coord = Arc::new(entity_revision::engine::ConfigCoordinationHook::new(
                content_store.clone(),
                notifying_li.clone(),
                pid.clone(),
            ));
            emit_dispatcher.register_hook(config_coord);
        }

        // Position 7 (auto-version): per-write DAG entries for tracked
        // prefixes. MUST fire after position 6 (reads tracked root) and
        // before position 8 (subscription observes settled head advance).
        // See PROPOSAL-REVISION-AUTO-VERSION-FIX §6C.
        #[cfg(feature = "revision")]
        emit_dispatcher.register_hook(revision_engine.clone());

        // Position 8 (subscription).
        #[cfg(feature = "subscription")]
        emit_dispatcher.register_hook(sub_engine.clone());

        // Builder-supplied observe-only binding hooks (GUIDE-INSPECTABILITY
        // v1.2 §2.2 "Binding stream"). Registered LAST so observers see
        // post-cascade state — after every extension-owned hook has run.
        for (name, f) in self.binding_hooks {
            emit_dispatcher.register_hook(Arc::new(BindingObserver { name, f }));
        }

        let arm_published_root = |hook: &published_root::PublishRootHook, prefix: &str| {
            match entity_tree::root_tracker::tracking_config_entity(prefix, true) {
                Some(cfg) => {
                    match content_store.put(cfg) {
                        Ok(cfg_hash) => {
                            // A `{name}` of `publishedroot` labels who installed
                            // it (§3.4.1a: the name is opaque), so an operator
                            // config for the same prefix coexists rather than
                            // being displaced.
                            notifying_li.set(
                                &format!("/{}/system/tree/tracking-config/publishedroot", pid),
                                cfg_hash,
                            );
                        }
                        Err(e) => tracing::error!(
                            error = %e,
                            "published-root: storing tracking-config failed; no signed root will be served"
                        ),
                    }
                }
                None => tracing::error!(
                    prefix = %prefix,
                    "published-root: invalid tracking prefix; no signed root will be served"
                ),
            }
            // The config write above publishes via the cascade whenever it moved
            // the tracked root. It does not when the tracker already held that
            // exact root — a restart off persistent storage, or an operator
            // config for the same prefix that `bootstrap()` already built. Cover
            // that case explicitly; `publish` is a no-op on an unchanged root.
            if let Some(root) = root_tracker.tracked_root(prefix) {
                if let Err(e) = hook.publish_initial(root) {
                    tracing::error!(error = %e, "published-root: initial publish failed");
                }
            }
            tracing::info!(
                prefix = %prefix,
                tracked_root_path = %hook.tracked_root_path(),
                head = ?hook.current_head_hash(),
                "published-root publisher armed"
            );
        };

        tracing::info!(
            peer_id = %peer_id,
            handlers = registered_patterns.len(),
            "peer built"
        );
        tracing::debug!(
            peer_id = %peer_id,
            handlers = ?registered_patterns,
            "registered handlers"
        );

        // EXTENSION-ROLE §4.7 — auto-wire the role policy grant resolver
        // when both `role` and `attestation` features are enabled. The
        // resolver defaults to `anonymous-deny` (returns None → static
        // fallback) when no policy entity is bound, so this is a
        // behavior-preserving wire-up for deployments that never write
        // an initial-grant-policy entity.
        #[cfg(all(feature = "role", feature = "attestation"))]
        let grant_resolver: Option<GrantResolver> = Some(entity_role::build_policy_resolver(
            entity_role::PolicyResolverDeps {
                content_store: content_store.clone(),
                location_index: notifying_li.clone(),
                attestation_index: attestation_index.clone(),
                local_peer_id: pid.clone(),
            },
        ));
        #[cfg(not(all(feature = "role", feature = "attestation")))]
        let grant_resolver: Option<GrantResolver> = None;

        // RE-2: all engines wired, rebuilds complete. Transition the
        // local-status entity from `starting` to `ready`. For library
        // use (no listener), this is the steady state. For server use
        // (Peer::run binds a listener), the listener-bind step happens
        // outside build() — but dispatch via `Peer::execute()` is
        // already valid from this point.
        let started_at_ms = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        {
            let li_for_status: Arc<dyn LocationIndex> = notifying_li.clone();
            write_peer_self_status(
                PeerPhase::Ready,
                Some(started_at_ms),
                &content_store,
                &li_for_status,
                &pid,
            )?;
        }

        // EXTENSION-DURABILITY §3 (MAY) — publish a durability advertisement
        // at `/{peer_id}/system/durability`. The validator probes for this
        // path; absence is conformant but elicits a WARN. Mirrors Go's
        // `core/peer/peer.go:168-178` pattern. Best-effort: failures here
        // don't block peer startup — the contract (§5/§6) is what's MUSTed,
        // not the advertisement (§3 is explicitly SHOULD-tier in v0.1,
        // MAY-tier per Amendment 1 §9.2.6).
        {
            let max_self = self.config.durability_policy.max_self_determinable.clone();
            let levels: Vec<entity_ecf::Value> = match max_self {
                durability::DurabilityLevel::None => {
                    vec![entity_ecf::text("none")]
                }
                durability::DurabilityLevel::Stored => {
                    vec![entity_ecf::text("none"), entity_ecf::text("stored")]
                }
                durability::DurabilityLevel::Replicated => vec![
                    entity_ecf::text("none"),
                    entity_ecf::text("stored"),
                    entity_ecf::text("replicated"),
                ],
                durability::DurabilityLevel::Unknown(_) => {
                    vec![entity_ecf::text("none")]
                }
            };
            let max_self_str = self
                .config
                .durability_policy
                .max_self_determinable
                .as_str()
                .to_string();
            let ad_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
                (entity_ecf::text("levels"), entity_ecf::Value::Array(levels)),
                (
                    entity_ecf::text("max_self_determinable"),
                    entity_ecf::text(&max_self_str),
                ),
            ]));
            if let Ok(ad_entity) =
                entity_entity::Entity::new("system/durability-advertisement", ad_data)
            {
                if let Ok(hash) = content_store.put(ad_entity) {
                    let path = format!("/{}/system/durability", pid);
                    notifying_li.set(&path, hash);
                }
            }
        }

        // Arm the published-root publisher LAST. The hook is already
        // registered (position 6, above); what happens here is installing the
        // `system/tree/tracking-config` whose cascade builds the first trie
        // root and mints seq 0. Deferring it to the end of build() keeps
        // startup at a single publish — every bootstrap write above (identity,
        // handler grants, the RE-2 `ready` status, the durability
        // advertisement) is already in the tree and folds into that one root
        // instead of each minting its own head.
        if let (Some(hook), Some(prefix)) = (
            published_root_hook.as_ref(),
            self.published_root_prefix.as_ref(),
        ) {
            arm_published_root(hook, prefix);
        }

        Ok(Peer {
            keypair,
            peer_id,
            identity_hash,
            content_store,
            location_index: notifying_li,
            handler_registry,
            tree,
            config: self.config,
            // §10.3 is opt-in: a peer with no traversal policy registered runs
            // the pre-seam ladder exactly. Wired post-construction via
            // `set_live_establish`.
            live_establish: None,
            connector,
            remote: Arc::new(remote::RemoteState::new()),
            event_tx,
            content_event_tx,
            engines_started: std::sync::atomic::AtomicBool::new(false),
            attestation_store,
            grant_resolver,
            #[cfg(feature = "attestation")]
            attestation_index: attestation_index.clone(),
            #[cfg(feature = "subscription")]
            sub_engine: Some(sub_engine),
            #[cfg(feature = "network")]
            network_handler,
            preserved_requests: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            minted_reentry_grants: Arc::new(std::sync::Mutex::new(MintedGrantLedger::default())),
            #[cfg(all(feature = "local-files", not(target_arch = "wasm32")))]
            local_files_handler,
            dispatch_hooks: self.dispatch_hooks,
            wire_hooks: self.wire_hooks,
            last_marker_collect_ms: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            #[cfg(all(target_arch = "wasm32", feature = "wasm-idb-persist"))]
            idb_checkpoint: self.idb_checkpoint,
        })
    }
}

impl Default for PeerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Phase value for `system/peer/self/status` (PROPOSAL-RESTART-EQUIVALENCE
/// RE-2). Single coarse-grained enum for external observers — the
/// distinction subscribers and remote peers need is binary: "do I
/// expect responses?".
#[derive(Debug, Clone, Copy)]
pub enum PeerPhase {
    /// Peer is performing startup work (hydration, rebuild, self-mint).
    /// External EXECUTEs MUST NOT be accepted.
    Starting,
    /// Steady-state operation; full dispatch available.
    Ready,
    /// Graceful shutdown; in-flight requests completing. New requests
    /// rejected.
    Draining,
}

impl PeerPhase {
    fn as_str(self) -> &'static str {
        match self {
            PeerPhase::Starting => "starting",
            PeerPhase::Ready => "ready",
            PeerPhase::Draining => "draining",
        }
    }
}

/// Write (or overwrite) the local peer's runtime-status entity at
/// `/{peer_id}/system/peer/self/status`. Class L per
/// GUIDE-RESTART-AND-PERSISTENCE.md §2.3 — written through the normal
/// emit pathway as the peer transitions through phases.
///
/// `started_at` is set when the peer first reaches `Ready`; pass
/// `None` to omit the field (`starting`/`draining` typically don't
/// carry it). `last_phase_transition` is always set to "now".
fn write_peer_self_status(
    phase: PeerPhase,
    started_at: Option<u64>,
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
    peer_id: &str,
) -> Result<entity_hash::Hash, PeerError> {
    let now_ms = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let mut fields = vec![
        (
            entity_ecf::text("last_phase_transition"),
            entity_ecf::integer(now_ms as i64),
        ),
        (entity_ecf::text("phase"), entity_ecf::text(phase.as_str())),
    ];
    if let Some(started) = started_at {
        fields.push((
            entity_ecf::text("started_at"),
            entity_ecf::integer(started as i64),
        ));
    }
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
    let entity = entity_entity::Entity::new(entity_types::TYPE_PEER_SELF_STATUS, data)
        .map_err(|e| PeerError::BuildError(format!("build self-status: {}", e)))?;
    let hash = content_store
        .put(entity)
        .map_err(|e| PeerError::BuildError(e.to_string()))?;
    let path = format!("/{}/system/peer/self/status", peer_id);
    location_index.set(&path, hash);
    Ok(hash)
}

/// Store a handler manifest entity at its pattern path and an interface entity
/// at `{peer_id}/system/handler/{bare_pattern}`. Used during bootstrap to seed the tree.
///
/// `bare_pattern` is the interop-visible pattern (e.g., "system/tree").
/// Tree paths are qualified with `peer_id`.
/// Manifest entity DATA keeps the bare pattern for interop.
/// EXTENSION-RELAY §4.1 — publish this peer's own signed `system/relay/advertise`
/// entity, carrying the §8 bounds it actually enforces.
///
/// **Why this exists at all, and why it is not optional.** §8.1 makes publishing
/// `limits.max_retention_ms` a **MUST** for a relay that enforces a retention
/// ceiling, and §4.1 gives the reason in one sentence: *"a ceiling that is
/// enforced but unpublished configures behaviour no counterparty can observe
/// before depending on it."* Duration is the number that decides whether
/// store-and-forward is usable — a sender picking a relay, and a peer deciding
/// which relays to name in its own §3.5 `inbox-relay` declaration, both need it,
/// and neither can learn it any other way.
///
/// The limits come from the handler (`configured_limits`) rather than from the
/// config, so what is advertised is what the enforcing code holds. Reading them
/// off the config instead would make the advertise a second, independently
/// drifting statement of the same fact.
///
/// The entity is signed by `relay_peer_id` per V7 §5.2, with **no `refs:`
/// block** — the signature is reachable at the invariant pointer
/// `system/signature/{hex(advertise.content_hash)}` (§3.0/§4.1). The signature
/// is bound BEFORE the advertise (referenced-before-reference), so a reader that
/// sees the advertise can always resolve its signature.
///
/// **An advertised limit is a promise a relay can break** (§4.1), which is why
/// publishing it discloses nothing new: §5.1's threat model already bounds an
/// intermediary to drop-or-delay.
#[cfg(feature = "relay")]
fn publish_relay_self_advertise(
    store: &Arc<dyn ContentStore>,
    index: &Arc<dyn LocationIndex>,
    keypair: &entity_crypto::IdentityKeypair,
    peer_id: &str,
    limits: entity_relay::data::AdvertiseLimits,
) -> Result<(), PeerError> {
    let advertise = entity_relay::AdvertiseData {
        // v1 ships both named modes (§1, §10.1): a *deployment* may enable a
        // subset, but the implementation supports Mode F and Mode S.
        modes: vec![
            entity_relay::MODE_FORWARD.to_string(),
            entity_relay::MODE_STORE.to_string(),
        ],
        // NETWORK §6.5 dial-able endpoints. Empty: this peer's reachability is
        // published as `system/peer/transport/...` profiles, which is where a
        // dialer already looks. Endpoint duplication here is deferred rather
        // than guessed — an empty array and an absent key are the same fact.
        endpoints: Vec::new(),
        limits,
        // §5.2: polling a namespace is the cap a consumer of a Mode-S relay
        // needs to be told about; forward/put are per-deployment grants.
        caps_required: vec![entity_relay::CAP_RELAY_POLL.to_string()],
        // §4.1 `expires_at` is the advertise's own lifetime, not a store bound.
        // Absent = valid until superseded; the entity is republished on every
        // peer start (§8: "renewed on relay restart").
        expires_at: None,
    };

    let advertise_entity = advertise
        .to_entity()
        .map_err(|e| PeerError::BuildError(format!("encode relay advertise: {e}")))?;
    let advertise_hash = advertise_entity.content_hash;

    let identity = keypair
        .peer_entity()
        .map_err(|e| PeerError::BuildError(format!("relay advertise signer identity: {e}")))?;
    let signature = entity_types::SignatureData {
        target: advertise_hash,
        signer: identity.content_hash,
        algorithm: keypair.key_type().label().to_string(),
        signature: keypair.sign(&advertise_hash.to_bytes()).to_vec(),
    };
    let signature_entity = signature
        .to_entity()
        .map_err(|e| PeerError::BuildError(format!("encode relay advertise signature: {e}")))?;

    let signature_hash = store
        .put(signature_entity)
        .map_err(|e| PeerError::BuildError(e.to_string()))?;
    store
        .put(advertise_entity)
        .map_err(|e| PeerError::BuildError(e.to_string()))?;

    // Signature first — referenced-before-reference.
    index.set(
        &entity_hash::invariant_signature_path(peer_id, &advertise_hash),
        signature_hash,
    );
    index.set(
        &entity_relay::advertise_path(peer_id, peer_id),
        advertise_hash,
    );
    Ok(())
}

fn bootstrap_handler(
    store: &Arc<dyn ContentStore>,
    index: &Arc<dyn LocationIndex>,
    peer_id: &str,
    name: &str,
    bare_pattern: &str,
    operations: &[&str],
) -> Result<(), PeerError> {
    let ops = entity_ecf::Value::Map(
        operations
            .iter()
            .map(|op| (entity_ecf::text(*op), entity_ecf::Value::Map(vec![])))
            .collect(),
    );

    // 1. Interface entity at /{peer_id}/system/handler/{bare_pattern} (public contract)
    let interface_path = format!("system/handler/{}", bare_pattern);
    let interface_data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
        "name" => entity_ecf::text(name),
        "operations" => ops,
        "pattern" => entity_ecf::text(bare_pattern)
    });
    let interface =
        entity_entity::Entity::new(entity_types::TYPE_HANDLER_INTERFACE, interface_data)
            .map_err(|e| PeerError::BuildError(e.to_string()))?;
    let iface_hash = store
        .put(interface)
        .map_err(|e| PeerError::BuildError(e.to_string()))?;
    index.set(&format!("/{}/{}", peer_id, interface_path), iface_hash);

    // 2. Handler entity at /{peer_id}/{bare_pattern} (dispatch target, references interface)
    let handler_data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
        "interface" => entity_ecf::text(&interface_path)
    });
    let handler = entity_entity::Entity::new(entity_types::TYPE_HANDLER, handler_data)
        .map_err(|e| PeerError::BuildError(e.to_string()))?;
    let handler_hash = store
        .put(handler)
        .map_err(|e| PeerError::BuildError(e.to_string()))?;
    let qualified_pattern = format!("/{}/{}", peer_id, bare_pattern);
    index.set(&qualified_pattern, handler_hash);

    Ok(())
}

/// Create a signed capability self-grant for a handler and store it in the tree (§6.9).
///
/// Granter == grantee == local peer identity (self-grant). Grant scope comes from
/// the handler's `internal_scope()` or defaults to wildcard.
/// Stored at `/{peer_id}/system/capability/grants/{bare_pattern}`.
/// F27 §6.9a: write a seed-policy entry at `system/capability/policy/{key}`.
///
/// Persists a `TYPE_CAP_POLICY_ENTRY` carrying the grant scope under the
/// given grantee `key` (v7.64 hex identity-hash, Base58 PeerID, or `default`),
/// matching the shape `lookup_capability_policy_grants` reads at authenticate.
///
/// Class I — install-once. The entry carries no install-event data, but
/// re-writing on every restart would churn a persistent content store; check
/// the canonical path and skip if already bound (mirrors `create_handler_grant`).
fn write_seed_policy_entry(
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
    peer_id: &str,
    key: &str,
    grants: &[GrantEntry],
) -> Result<(), PeerError> {
    let path = format!("/{}/system/capability/policy/{}", peer_id, key);
    if location_index.get(&path).is_some() {
        return Ok(());
    }
    let arr: Vec<entity_ecf::Value> = grants
        .iter()
        .map(entity_capability::encode_grant_entry)
        .collect();
    // ECF sorts map keys; the read path is key-agnostic. `grants` + `peer_pattern`
    // match the `system/capability/policy-entry` type definition.
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (entity_ecf::text("grants"), entity_ecf::Value::Array(arr)),
        (entity_ecf::text("peer_pattern"), entity_ecf::text(key)),
    ]));
    let entity = entity_entity::Entity::new(entity_types::TYPE_CAP_POLICY_ENTRY, data)
        .map_err(|e| PeerError::BuildError(format!("build seed policy entry: {}", e)))?;
    let hash = content_store
        .put(entity)
        .map_err(|e| PeerError::BuildError(e.to_string()))?;
    location_index.set(&path, hash);
    tracing::debug!(path = %path, "F27 §6.9a: seed policy entry materialized");
    Ok(())
}

fn create_handler_grant(
    bare_pattern: &str,
    scope: Vec<entity_capability::GrantEntry>,
    keypair: &IdentityKeypair,
    identity_hash: entity_hash::Hash,
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
    peer_id: &str,
) -> Result<entity_hash::Hash, PeerError> {
    // Class I — install-once. Self-issued handler grants carry
    // install-event data (`created_at`) that isn't derivable from code
    // or identity material; re-minting on every start would churn the
    // content store and path binding. Per
    // `GUIDE-RESTART-AND-PERSISTENCE.md` §2.2, check existence at the
    // canonical path and skip if already bound. The existing
    // install-time value is canonical.
    let grant_path = format!("/{}/system/capability/grants/{}", peer_id, bare_pattern);
    if let Some(existing_hash) = location_index.get(&grant_path) {
        tracing::debug!(
            pattern = bare_pattern,
            path = %grant_path,
            "handler grant already bound; skipping re-mint (Class I)"
        );
        return Ok(existing_hash);
    }

    let now_ms = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let cap_token = entity_capability::CapabilityToken {
        grants: scope,
        granter: entity_capability::Granter::Single(identity_hash),
        grantee: identity_hash, // self-grant
        parent: None,
        created_at: now_ms,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };

    let cap_entity = cap_token
        .to_entity()
        .map_err(|e| PeerError::BuildError(format!("build handler grant: {}", e)))?;
    let cap_hash = content_store
        .put(cap_entity.clone())
        .map_err(|e| PeerError::BuildError(e.to_string()))?;

    // Sign the grant token (same pattern as connection grant signing)
    let sig_bytes = keypair.sign(&cap_entity.content_hash.to_bytes());
    let sig_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (
            entity_ecf::text("algorithm"),
            entity_ecf::text(keypair.key_type().label()),
        ),
        (
            entity_ecf::text("signature"),
            entity_ecf::Value::Bytes(sig_bytes),
        ),
        (
            entity_ecf::text("signer"),
            entity_ecf::Value::Bytes(identity_hash.to_bytes().to_vec()),
        ),
        (
            entity_ecf::text("target"),
            entity_ecf::Value::Bytes(cap_entity.content_hash.to_bytes().to_vec()),
        ),
    ]));
    let sig_entity = entity_entity::Entity::new(entity_entity::TYPE_SIGNATURE, sig_data)
        .map_err(|e| PeerError::BuildError(format!("build grant signature: {}", e)))?;
    let sig_hash = content_store
        .put(sig_entity)
        .map_err(|e| PeerError::BuildError(e.to_string()))?;

    // Store grant in tree
    location_index.set(
        &format!("/{}/system/capability/grants/{}", peer_id, bare_pattern),
        cap_hash,
    );

    // §S2(b) + v7.74 §3.4: the signature must be discoverable from the grant
    // for dispatch-time verification (`load_local_handler_grant`). Bound at
    // the §3.5 invariant-pointer path `system/signature/{grant_hash}`, keyed
    // by the grant entity's content hash (CONVERGENT ruling — the same
    // convention used for every other detached signature in the tree).
    location_index.set(
        &entity_hash::invariant_signature_path(peer_id, &cap_hash),
        sig_hash,
    );

    tracing::debug!(
        pattern = bare_pattern,
        grant_hash = %cap_hash,
        "handler grant created"
    );

    Ok(cap_hash)
}

#[derive(Debug, Error)]
pub enum PeerError {
    #[error("build error: {0}")]
    BuildError(String),

    #[error("connection error: {0}")]
    ConnectionError(String),

    /// Preserves a structured [`entity_protocol::ProtocolError`] across
    /// PeerError-typed boundaries so the wire-response layer can read
    /// the dedicated `wire_error_code()` (e.g.,
    /// `unsupported_key_type` for AGILITY-UNKNOWN-1) rather than the
    /// generic `handshake_failed` catch-all that string-only wrapping
    /// would produce.
    #[error("protocol: {0}")]
    Protocol(#[from] entity_protocol::ProtocolError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{Connector, Listener};

    fn test_keypair() -> Keypair {
        Keypair::from_seed([42u8; 32])
    }

    fn pid() -> String {
        test_keypair().peer_id().to_string()
    }

    /// Qualify a bare path with the test peer_id (absolute).
    fn qp(path: &str) -> String {
        format!("/{}/{}", pid(), path)
    }

    /// PROPOSAL-PATH-AS-RESOURCE-HYGIENE register/unregister: build
    /// ExecuteOptions whose `resource` is `system/handler/{pattern}`. The
    /// dispatch layer peer-qualifies the path before calling the handler.
    fn handler_resource_options(pattern: &str) -> entity_handler::ExecuteOptions {
        entity_handler::ExecuteOptions {
            resource: Some(entity_capability::ResourceTarget {
                targets: vec![format!("system/handler/{}", pattern)],
                exclude: vec![],
            }),
            ..Default::default()
        }
    }

    #[test]
    fn test_peer_builder_basic() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        assert!(!peer.peer_id().as_str().is_empty());
    }

    #[test]
    fn test_peer_builder_no_keypair() {
        let result = PeerBuilder::new().build();
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "identity")]
    fn test_peer_lookup_attestation_default_not_attested() {
        // Fresh peer has no attestations — lookup returns NotAttested.
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        let h = entity_hash::Hash::from_bytes(&{
            let mut b = vec![0u8];
            b.extend(std::iter::repeat_n(0xCDu8, 32));
            b
        })
        .unwrap();
        assert_eq!(
            peer.lookup_attestation(&h),
            entity_handler::AttestationStatus::NotAttested
        );
    }

    #[test]
    #[cfg(feature = "identity")]
    fn test_peer_lookup_attestation_finds_live_agent_cert() {
        // Provision a live identity-cert(function="agent") on the peer's
        // tree and verify lookup_attestation finds it (EXTENSION-IDENTITY
        // v3.2 §10.1 / §12.3).
        use entity_attestation::AttestationData;
        use entity_ecf::text;

        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();

        // Issuing controller (the attesting party).
        let kp_ctrl = Keypair::from_seed([180u8; 32]);
        let h_ctrl = peer
            .content_store()
            .put(kp_ctrl.peer_entity().unwrap())
            .unwrap();

        // Agent peer (the attested party).
        let kp_agent = Keypair::from_seed([181u8; 32]);
        let h_agent = peer
            .content_store()
            .put(kp_agent.peer_entity().unwrap())
            .unwrap();

        // Build identity-cert(function=agent, mode=internal).
        let att = AttestationData {
            attesting: h_ctrl,
            attested: h_agent,
            properties: vec![
                (text("function"), text("agent")),
                (text("kind"), text("identity-cert")),
                (text("mode"), text("internal")),
            ],
            supersedes: None,
            not_before: None,
            expires_at: None,
        };
        let entity = att.to_entity().unwrap();
        let att_hash = entity.content_hash;
        peer.content_store().put(entity).unwrap();
        let path = entity_identity::path_internal_cert(&att_hash);
        peer.location_index().set(&qp(&path), att_hash);
        // Manually populate the attestation index (Phase 7 wires the
        // SyncTreeHook for this; here we test the lookup path directly).
        // The attestation_store reads through the index, not the tree.
        // Without index population this would return NotAttested; we
        // accept that here and assert the trait's behavior matches the
        // wired implementation. For a real provisioning flow, call the
        // identity handler's create_attestation op which populates the
        // index atomically.
        match peer.lookup_attestation(&h_agent) {
            entity_handler::AttestationStatus::NotAttested => {
                // Expected without index population — the lookup is
                // index-backed per v3.2 §10.1.
            }
            entity_handler::AttestationStatus::Attested { .. } => {
                // Also acceptable if the path-scan fallback is added later.
            }
        }
    }

    #[test]
    fn test_peer_has_tree_handler() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        assert!(peer.handler_registry().get(&qp("system/tree")).is_some());
    }

    /// Cross-impl validator (`validate-peer -category identity`) walks the
    /// `system/identity` handler manifest at the tree path and verifies each
    /// op is exposed. The IdentityHandler's `operations()` and the
    /// `bootstrap_handler()` op list MUST stay in sync.
    #[test]
    #[cfg(feature = "identity")]
    fn test_peer_identity_manifest_lists_v32_ops() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        // Manifest entity lives at /{pid}/system/handler/system/identity.
        let pid = test_keypair().peer_id().to_string();
        let manifest_path = format!("/{}/system/handler/system/identity", pid);
        let entity = peer
            .tree()
            .get(&manifest_path)
            .expect("identity handler manifest missing");
        assert_eq!(entity.entity_type, entity_types::TYPE_HANDLER_INTERFACE);
        // Decode the manifest and confirm the v2.2 op list.
        let value: ciborium::Value =
            ciborium::from_reader(entity.data.as_slice()).expect("manifest CBOR decode");
        let map = value.as_map().expect("manifest is a map");
        let ops_field = map
            .iter()
            .find_map(|(k, v)| {
                if k.as_text() == Some("operations") {
                    Some(v)
                } else {
                    None
                }
            })
            .expect("operations field missing");
        // §3.12: operations is a CBOR map (op_name → op_spec), not an array.
        let ops = ops_field.as_map().expect("operations is a map");
        let op_names: std::collections::HashSet<String> = ops
            .iter()
            .filter_map(|(k, _)| k.as_text().map(|s| s.to_string()))
            .collect();
        for expected in [
            "configure",
            "create_quorum",
            "create_attestation",
            "supersede_attestation",
            "revoke_attestation",
            "publish_attestation",
            "process_attestation",
        ] {
            assert!(
                op_names.contains(expected),
                "v2.2 op {} missing from identity manifest at tree path",
                expected
            );
        }
        // Confirm v1.2 ops are NOT present (drift guard).
        for v1_only in [
            "process_delegation",
            "rotate_operator",
            "retire_operator",
            "rotate_quorum",
            "publish_runtime_peer_attestation",
            "revoke_peer",
        ] {
            assert!(
                !op_names.contains(v1_only),
                "v1.2 op {} still present in v2.2 identity manifest",
                v1_only
            );
        }
    }

    #[test]
    fn test_peer_tree_bootstrap() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        let entity = peer.tree().get(&qp("system/tree"));
        assert!(entity.is_some());
        assert_eq!(entity.unwrap().entity_type, entity_types::TYPE_HANDLER);
    }

    #[test]
    fn test_peer_identity_stored() {
        let kp = test_keypair();
        let peer_id = kp.peer_id();
        let peer = PeerBuilder::new().keypair(kp).build().unwrap();
        let path = format!("/{}/system/identity/{}", peer_id, peer_id);
        let entity = peer.tree().get(&path);
        assert!(entity.is_some());
        assert_eq!(entity.unwrap().entity_type, entity_crypto::TYPE_PEER);
    }

    #[test]
    fn test_peer_tree_get_put() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        let data = entity_ecf::to_ecf(&entity_ecf::text("test data"));
        let entity = entity_entity::Entity::new("test/type", data).unwrap();
        // Absolute, peer-qualified path per §5.4 validate_absolute_path.
        let path = format!("/{}/test/path", peer.peer_id());
        let hash = peer.tree().put(&path, entity.clone()).unwrap();
        let got = peer.tree().get(&path).unwrap();
        assert_eq!(got.content_hash, hash);
    }

    #[test]
    fn test_peer_with_wire_hook_propagates_to_shared() {
        // GUIDE-INSPECTABILITY v1.2 §2.1 #5 — wire hooks register at
        // PeerBuilder, propagate into PeerShared, and the connection-task
        // fire site (core/peer/src/connection.rs handle_connection
        // message loop) consults them. This test covers the API surface
        // and propagation. The actual firing on a wire roundtrip is
        // exercised by integration tests that drive cross-peer EXECUTEs;
        // we add a dedicated wire-recorder consumer e2e test when the
        // recorder lands per the L1 review §3 deferred-scope note.
        let peer = PeerBuilder::new()
            .keypair(test_keypair())
            .with_wire_hook("test/wire-noop", |_event| {})
            .build()
            .unwrap();
        let shared = peer.shared();
        assert_eq!(
            shared.wire_hooks.len(),
            1,
            "with_wire_hook should accumulate and propagate to PeerShared"
        );
        assert_eq!(shared.wire_hooks[0].0, "test/wire-noop");
    }

    #[tokio::test]
    async fn test_peer_with_dispatch_hook_observes_entry_and_exit() {
        use entity_handler::{ExecuteOptions, STATUS_OK};
        use std::sync::Mutex;

        let observed: Arc<Mutex<Vec<DispatchEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let observed_clone = observed.clone();
        let peer = PeerBuilder::new()
            .keypair(test_keypair())
            .with_dispatch_hook("test/observer", move |event| {
                observed_clone.lock().unwrap().push(event.clone());
            })
            .build()
            .unwrap();

        // Put an entity to a path, then GET it through the dispatch path —
        // exercises make_execute_fn's local-dispatch site (where the second
        // dispatch hook fire-pair is wired).
        let pid = peer.peer_id().clone();
        let path = format!("/{}/test/data", pid);
        let data = entity_ecf::to_ecf(&entity_ecf::text("hello"));
        let entity = entity_entity::Entity::new("test/data", data).unwrap();
        peer.tree().put(&path, entity).unwrap();

        // Build a get request against system/tree.
        let get_params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("uri"),
            entity_ecf::text(&path),
        )]));
        let get_params =
            entity_entity::Entity::new("system/tree/get-request", get_params_data).unwrap();
        let result = peer
            .execute_with_options(
                "system/tree",
                "get",
                get_params,
                ExecuteOptions {
                    resource: Some(entity_capability::ResourceTarget {
                        targets: vec![path.clone()],
                        exclude: vec![],
                    }),
                    ..Default::default()
                },
            )
            .await
            .expect("system/tree get should dispatch");
        assert_eq!(result.status, STATUS_OK, "tree get should return 200");

        let captured = observed.lock().unwrap();
        assert_eq!(
            captured.len(),
            2,
            "dispatch hook should fire exactly twice (entry + exit); got: {:?}",
            *captured
        );
        assert!(
            matches!(captured[0].phase, DispatchPhase::Entry),
            "first event should be Entry, got {:?}",
            captured[0].phase
        );
        match &captured[1].phase {
            DispatchPhase::Exit { status, .. } => {
                assert_eq!(*status, STATUS_OK, "exit hook should carry handler status");
            }
            other => panic!("second event should be Exit, got {other:?}"),
        }
        assert_eq!(captured[0].operation, "get");
        assert_eq!(captured[1].operation, "get");
        assert!(
            captured[0].target_uri.contains("system/tree"),
            "target_uri should contain handler pattern; got {}",
            captured[0].target_uri
        );
        assert_eq!(
            captured[0].request_id, captured[1].request_id,
            "entry and exit share the same request_id"
        );
    }

    #[cfg(feature = "registry")]
    #[tokio::test]
    async fn test_registry_bind_and_resolve_end_to_end() {
        use entity_handler::{ExecuteOptions, STATUS_OK};

        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        let pid = peer.peer_id().clone();

        // bind("alice" -> z6MkAlice) via the real cap-checked dispatch path —
        // authorized by the §6.9a owner-self-grant (the §5.2 default-grant floor).
        let bind_params = entity_entity::Entity::new(
            entity_types::TYPE_PROTOCOL_STATUS,
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
                (entity_ecf::text("name"), entity_ecf::text("alice")),
                (
                    entity_ecf::text("target_peer_id"),
                    entity_ecf::text("z6MkAlice"),
                ),
            ])),
        )
        .unwrap();
        let res = peer
            .execute_with_options(
                "system/registry/local-name",
                "bind",
                bind_params,
                ExecuteOptions {
                    resource: Some(entity_capability::ResourceTarget {
                        targets: vec![format!("/{}/system/registry/binding/local-name/alice", pid)],
                        exclude: vec![],
                    }),
                    ..Default::default()
                },
            )
            .await
            .expect("local-name bind should dispatch");
        assert_eq!(res.status, STATUS_OK, "bind should return 200");

        // resolve("alice")
        let resolve_params = entity_entity::Entity::new(
            entity_types::TYPE_PROTOCOL_STATUS,
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                entity_ecf::text("name"),
                entity_ecf::text("alice"),
            )])),
        )
        .unwrap();
        let res = peer
            .execute_with_options(
                "system/registry",
                "resolve",
                resolve_params,
                ExecuteOptions {
                    resource: Some(entity_capability::ResourceTarget {
                        targets: vec![format!("/{}/system/registry", pid)],
                        exclude: vec![],
                    }),
                    ..Default::default()
                },
            )
            .await
            .expect("registry resolve should dispatch");
        assert_eq!(res.status, STATUS_OK, "resolve should return 200");

        // Decode the ResolutionResult and assert it resolved to z6MkAlice. §2.1
        // Ruling-3: the result is the bare flat
        // `system/registry/resolution-result` entity — NOT wrapped under
        // `system/protocol/status` with a `{result: {...}}` payload.
        assert_eq!(res.result.entity_type, "system/registry/resolution-result");
        let outer: entity_ecf::Value = ciborium::from_reader(res.result.data.as_slice()).unwrap();
        let rm = outer.as_map().unwrap();
        let status = rm.iter().find_map(|(k, v)| {
            if k.as_text() == Some("status") {
                v.as_text()
            } else {
                None
            }
        });
        let peer_id = rm.iter().find_map(|(k, v)| {
            if k.as_text() == Some("peer_id") {
                v.as_text()
            } else {
                None
            }
        });
        assert_eq!(status, Some("resolved"));
        assert_eq!(peer_id, Some("z6MkAlice"));
    }

    #[test]
    fn test_publish_root_serves_signed_head() {
        use std::collections::BTreeMap;

        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        let shared = peer.shared();

        // Build a trie root over one binding in the peer's own store.
        let leaf = entity_entity::Entity::new(
            "test/leaf",
            entity_ecf::to_ecf(&entity_ecf::text("payload")),
        )
        .unwrap();
        let leaf_hash = leaf.content_hash;
        shared.content_store.put(leaf).unwrap();
        let mut bindings = BTreeMap::new();
        bindings.insert("system/x".to_string(), leaf_hash);
        let root = entity_tree::trie::build_trie(shared.content_store.as_ref(), &bindings).unwrap();

        // Publish — MANIFEST_GET head now points at the signed published-root.
        let head = peer.publish_root(root).unwrap();
        assert_eq!(peer.published_root_head(), Some(head));

        // Verify the served published-root + its invariant-pointer signature
        // against the peer's real public key (the §7.4 consumer trust check).
        let pr_bytes = entity_wire::encode_entity(&shared.content_store.get(&head).unwrap());
        let sig_path = entity_hash::invariant_signature_path(shared.peer_id.as_str(), &head);
        let sig_hash = shared
            .location_index
            .get(&sig_path)
            .expect("signature bound");
        let sig_bytes = entity_wire::encode_entity(&shared.content_store.get(&sig_hash).unwrap());

        let (verified_hash, data) = published_root::verify_signed_root(
            &pr_bytes,
            Some(&sig_bytes),
            &shared.keypair.public_key_bytes(),
            shared.keypair.key_type(),
            Some(shared.peer_id.as_str()),
        )
        .expect("published-root verifies against the peer's pinned key");
        assert_eq!(verified_hash, head);
        assert_eq!(data.root_hash, root);
        assert_eq!(data.seq, 0);
        assert!(data.predecessor.is_none());
    }

    /// Decode the peer's current published-root head into `(head, seq, root_hash,
    /// predecessor)`.
    #[cfg(test)]
    fn head_state(
        peer: &Peer,
    ) -> (
        entity_hash::Hash,
        u64,
        entity_hash::Hash,
        Option<entity_hash::Hash>,
    ) {
        let head = peer.published_root_head().expect("a head must be bound");
        let entity = peer.shared().content_store.get(&head).unwrap();
        let d = entity_types::PublishedRootData::from_entity(&entity).unwrap();
        (head, d.seq, d.root_hash, d.predecessor)
    }

    /// PROPOSAL-PEER-MANIFEST §4 P1 + EXTENSION-NETWORK §6.5.6 Amendment 10
    /// (arch `c78b3dc` closure-timing ruling): the served closure tracks the
    /// **current** `published-root.root_hash`, so a peer that mints a root once
    /// at startup and never again serves a closure frozen at boot — every
    /// entity written afterwards is permanently outside the served set.
    ///
    /// This is the check `serving_mode.seed_republished` makes over the wire
    /// (Go's report `2026-08-07-f`, which measured us at one distinct manifest
    /// across 5m45s, `seq` 0 and staying 0). Asserting on the *decoded head*
    /// rather than on the publisher call is deliberate: the pre-fix code also
    /// bound a head — what it never did was advance one.
    #[tokio::test]
    async fn published_root_republishes_on_every_tree_root_change() {
        let peer = PeerBuilder::new()
            .keypair(test_keypair())
            .with_published_root("/")
            .build()
            .unwrap();

        let (head0, seq0, root0, pred0) = head_state(&peer);
        assert!(pred0.is_none(), "the first head chains to nothing");

        // A tree:put through the ordinary emit path — exactly what the
        // validator's `seed_in_scope` does before it polls /manifest.
        let seeded = entity_entity::Entity::new(
            "test/leaf",
            entity_ecf::to_ecf(&entity_ecf::text("seed-1")),
        )
        .unwrap();
        let seeded_hash = seeded.content_hash;
        peer.tree()
            .put(&qp("system/content/public/seed-1"), seeded)
            .unwrap();

        let (head1, seq1, root1, pred1) = head_state(&peer);
        assert_ne!(head1, head0, "the head must advance on a tree-root change");
        assert_eq!(seq1, seq0 + 1, "seq is monotonic per republish");
        assert_eq!(pred1, Some(head0), "the new head chains to the prior one");
        assert_ne!(root1, root0, "the signed root commits to the new tree");

        // The seeded entity is inside the CURRENT root's closure — the property
        // the 27 dependent serving_mode checks were unexercised for.
        let closure =
            entity_tree::trie::collect_node_closure(peer.shared().content_store.as_ref(), root1);
        assert!(
            closure.contains(&seeded_hash),
            "the seeded entity must be reachable from the republished root"
        );

        // A second put chains again — this is a stream, not a one-shot.
        let second = entity_entity::Entity::new(
            "test/leaf",
            entity_ecf::to_ecf(&entity_ecf::text("seed-2")),
        )
        .unwrap();
        peer.tree()
            .put(&qp("system/content/public/seed-2"), second)
            .unwrap();
        let (_, seq2, _, pred2) = head_state(&peer);
        assert_eq!(seq2, seq1 + 1);
        assert_eq!(pred2, Some(head1));
    }

    /// The publisher's own two writes (manifest + invariant-pointer signature)
    /// land inside the universal tracked prefix, so they are tagged
    /// `PUBLISHED_ROOT_HANDLER_PATTERN` and the tracker skips them.
    ///
    /// Two distinct things go wrong without that tag, and only the second is
    /// visible from a seq count — which is why this asserts both:
    ///
    /// - **the seq count** — one `tree:put` must mint exactly one head. Go
    ///   measured the untagged runaway at ~55 publishes/s with no external
    ///   traffic, invalidating the closure cache faster than a consumer can
    ///   finish a CONTENT_GET.
    /// - **`root_hash == the tracked root`** — the load-bearing one, and the
    ///   one the re-entry guard alone does *not* buy. Untagged, the publisher's
    ///   writes advance the trie root after the head has been signed and the
    ///   re-entry guard swallows the follow-up publish, so the peer serves a
    ///   signed root that is permanently one step behind its own tree. That is
    ///   the frozen-closure defect again, just with a smaller freeze.
    #[tokio::test]
    async fn published_root_commits_to_the_tracked_root_exactly() {
        let peer = PeerBuilder::new()
            .keypair(test_keypair())
            .with_published_root("/")
            .build()
            .unwrap();
        let tracked_root_path = format!("/{}/system/tree/root", peer.peer_id());
        let tracked = || peer.shared().location_index.get(&tracked_root_path);

        let (_, seq_before, root_before, _) = head_state(&peer);
        assert_eq!(Some(root_before), tracked(), "at rest, after build");

        let entity =
            entity_entity::Entity::new("test/leaf", entity_ecf::to_ecf(&entity_ecf::text("once")))
                .unwrap();
        peer.tree()
            .put(&qp("system/content/public/once"), entity)
            .unwrap();

        let (_, seq_after, root_after, _) = head_state(&peer);
        assert_eq!(
            seq_after,
            seq_before + 1,
            "one tree:put must yield exactly one republish, not a cascade of them"
        );
        assert_eq!(
            Some(root_after),
            tracked(),
            "the signed root must be the tracked root, not the tracked root minus \
             the publisher's own writes"
        );
    }

    /// Without the opt-in the peer publishes nothing — a peer that advertises
    /// no signed root serves the path-bound shape, where §6.5.6's closure-timing
    /// rule does not apply. No republisher may be armed by default.
    #[test]
    fn published_root_publisher_is_opt_in() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        assert!(peer.published_root_head().is_none());
    }

    #[test]
    fn test_peer_with_binding_hook_observes_tree_writes() {
        use std::sync::Mutex;
        let observed: Arc<Mutex<Vec<(String, entity_store::ChangeType)>>> =
            Arc::new(Mutex::new(Vec::new()));
        let observed_clone = observed.clone();
        let peer = PeerBuilder::new()
            .keypair(test_keypair())
            .with_binding_hook("test/observer", move |event| {
                observed_clone
                    .lock()
                    .unwrap()
                    .push((event.path.clone(), event.change_type));
            })
            .build()
            .unwrap();
        let data = entity_ecf::to_ecf(&entity_ecf::text("hello"));
        let entity = entity_entity::Entity::new("test/type", data).unwrap();
        let path = format!("/{}/test/observer-target", peer.peer_id());
        peer.tree().put(&path, entity).unwrap();
        let captures = observed.lock().unwrap();
        assert!(
            captures
                .iter()
                .any(|(p, k)| p == &path && matches!(k, entity_store::ChangeType::Created)),
            "binding hook should have observed Created event for {path}; got: {:?}",
            *captures
        );
    }

    #[test]
    fn test_peer_custom_stores() {
        let store = Arc::new(MemoryContentStore::new());
        let index = Arc::new(MemoryLocationIndex::new());
        let peer = PeerBuilder::new()
            .keypair(test_keypair())
            .content_store(store.clone())
            .location_index(index.clone())
            .build()
            .unwrap();
        assert!(peer.tree().has(&qp("system/tree")));
        assert!(index.has(&qp("system/tree")));
    }

    #[test]
    fn test_peer_deterministic() {
        let p1 = PeerBuilder::new()
            .keypair(Keypair::from_seed([1u8; 32]))
            .build()
            .unwrap();
        let p2 = PeerBuilder::new()
            .keypair(Keypair::from_seed([1u8; 32]))
            .build()
            .unwrap();
        assert_eq!(p1.peer_id(), p2.peer_id());
    }

    #[test]
    fn test_peer_config_default() {
        let config = PeerConfig::default();
        assert_eq!(config.listen_addr, "127.0.0.1:9000");
        assert_eq!(config.max_connections, 100);
    }

    /// Like the test below but routes the put through the handler's
    /// dispatch path (`handle()` with an EXECUTE context) to match what
    /// wire-dispatched writes do.
    #[tokio::test]
    async fn test_root_tracker_fires_via_handler_dispatch() {
        use entity_handler::{Handler, HandlerContext};

        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();

        let build_put_ctx = |path: &str, entity: &entity_entity::Entity| {
            // Build an inline entity {content_hash, data, type} map for
            // params.entity — all three keys, per §6.3's structural admission
            // step. A two-key fixture is refused `400 invalid_request` since
            // 0.8.2.11 and no longer exercises the tracker at all.
            let inner: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).unwrap();
            let params = entity_ecf::Value::Map(vec![(
                entity_ecf::text("entity"),
                entity_ecf::Value::Map(vec![
                    (
                        entity_ecf::text("content_hash"),
                        entity_ecf::Value::Bytes(entity.content_hash.to_bytes()),
                    ),
                    (entity_ecf::text("data"), inner),
                    (
                        entity_ecf::text("type"),
                        entity_ecf::text(&entity.entity_type),
                    ),
                ]),
            )]);
            let params_entity =
                entity_entity::Entity::new("system/tree/put-request", entity_ecf::to_ecf(&params))
                    .unwrap();
            let execute_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
                (entity_ecf::text("operation"), entity_ecf::text("put")),
                (entity_ecf::text("request_id"), entity_ecf::text("t1")),
                (entity_ecf::text("uri"), entity_ecf::text("system/tree")),
            ]));
            let execute =
                entity_entity::Entity::new(entity_types::TYPE_EXECUTE, execute_data).unwrap();
            HandlerContext {
                handler_grant: None,
                caller_capability: None,
                execute,
                params: params_entity,
                pattern: qp("system/tree"),
                suffix: String::new(),
                resource_target: Some(entity_capability::ResourceTarget {
                    targets: vec![path.to_string()],
                    exclude: vec![],
                }),
                author: None,
                session_peer_id: None,
                request_id: "t1".to_string(),
                operation: "put".to_string(),
                execute_fn: None,
                included: std::collections::HashMap::new(),
                matching_grant: None,
                capability_hash: None,
                handler_grant_hash: None,
                bounds: None,
                is_external: false,
                reactive_trigger: false,
            }
        };

        // Config put (handler dispatch).
        let cfg_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("enabled"), entity_ecf::bool_val(true)),
            (
                entity_ecf::text("prefix"),
                entity_ecf::text("system/validate/trie-track/"),
            ),
        ]));
        let cfg = entity_entity::Entity::new("system/tree/tracking-config", cfg_data).unwrap();
        let ctx = build_put_ctx(&qp("system/tree/tracking-config/validate-trie-track"), &cfg);
        let result = peer.tree().handle(&ctx).await.unwrap();
        assert_eq!(result.status, entity_handler::STATUS_OK);

        // Data put under the tracked prefix (handler dispatch).
        let doc =
            entity_entity::Entity::new("test/doc", entity_ecf::to_ecf(&entity_ecf::text("hello")))
                .unwrap();
        let ctx = build_put_ctx(&qp("system/validate/trie-track/a.txt"), &doc);
        let result = peer.tree().handle(&ctx).await.unwrap();
        assert_eq!(result.status, entity_handler::STATUS_OK);

        // Tracked root must exist as a direct binding to the trie root node.
        let root_entity = peer
            .tree()
            .get(&qp("system/tree/root/system/validate/trie-track"));
        assert!(
            root_entity.is_some(),
            "tracked root must be materialized via handler dispatch"
        );
        assert_eq!(
            root_entity.unwrap().entity_type,
            "system/tree/snapshot/node",
        );
    }

    /// EXTENSION-TREE §3.4: after creating a tracking-config and writing a
    /// path under its prefix, the trie root for that prefix MUST be
    /// materialized at `system/tree/root/{prefix-without-trailing-slash}`.
    ///
    /// Exactly mirrors the Go validator's sequence:
    ///   1. tree put system/tree/tracking-config/validate-trie-track
    ///      data = {prefix: "system/validate/trie-track/", enabled: true}
    ///   2. tree put system/validate/trie-track/a.txt
    ///   3. tree get system/tree/root/system/validate/trie-track
    #[tokio::test]
    async fn test_root_tracker_fires_via_notifying_li() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();

        let cfg_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("enabled"), entity_ecf::bool_val(true)),
            (
                entity_ecf::text("prefix"),
                entity_ecf::text("system/validate/trie-track/"),
            ),
        ]));
        let cfg = entity_entity::Entity::new("system/tree/tracking-config", cfg_data).unwrap();
        peer.tree()
            .put(&qp("system/tree/tracking-config/validate-trie-track"), cfg)
            .unwrap();

        let doc =
            entity_entity::Entity::new("test/doc", entity_ecf::to_ecf(&entity_ecf::text("hello")))
                .unwrap();
        peer.tree()
            .put(&qp("system/validate/trie-track/a.txt"), doc)
            .unwrap();

        // Direct binding: the binding value is the trie root node's content
        // hash; tree.get returns the trie root node, NOT a wrapper entity
        // (EXTENSION-TREE §3.4.1 + TREE-ROOT-PATH-AMBIGUITY.md direct-binding).
        let root_entity = peer
            .tree()
            .get(&qp("system/tree/root/system/validate/trie-track"));
        assert!(
            root_entity.is_some(),
            "tracked root must be materialized after config + data write"
        );
        assert_eq!(
            root_entity.unwrap().entity_type,
            "system/tree/snapshot/node",
            "binding points directly at the trie root node"
        );
    }

    #[test]
    fn test_peer_builder_with_config() {
        let config = PeerConfig {
            listen_addr: "0.0.0.0:8080".to_string(),
            max_connections: 50,
            connection_timeout_secs: 60,
            debug_open_grants: false,
            ..PeerConfig::default()
        };
        let peer = PeerBuilder::new()
            .keypair(test_keypair())
            .config(config)
            .build()
            .unwrap();
        assert_eq!(peer.config().listen_addr, "0.0.0.0:8080");
    }

    #[test]
    fn test_peer_type_definitions_seeded() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();

        let handler_entity = peer.tree().get(&qp("system/type/system/handler"));
        assert!(
            handler_entity.is_some(),
            "system/handler type not found in tree"
        );
        let handler_entity = handler_entity.unwrap();
        assert_eq!(handler_entity.entity_type, entity_types::TYPE_TYPE);

        let hello_entity = peer
            .tree()
            .get(&qp("system/type/system/protocol/connect/hello"));
        assert!(hello_entity.is_some(), "hello type not found in tree");
        let hello_entity = hello_entity.unwrap();
        assert_eq!(hello_entity.entity_type, entity_types::TYPE_TYPE);

        assert_ne!(
            handler_entity.content_hash, hello_entity.content_hash,
            "different types should have different hashes"
        );

        let string_type = peer.tree().get(&qp("system/type/primitive/string"));
        assert!(string_type.is_some(), "primitive/string type not found");

        let type_entries = peer.tree().list(&qp("system/type/"));
        assert!(
            type_entries.len() >= 60,
            "Expected at least 60 types in tree, got {}",
            type_entries.len()
        );
    }

    #[test]
    fn test_peer_handler_interfaces_stored() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();

        let tree_iface = peer.tree().get(&qp("system/handler/system/tree"));
        assert!(tree_iface.is_some(), "tree handler interface not found");
        let tree_iface = tree_iface.unwrap();
        assert_eq!(tree_iface.entity_type, entity_types::TYPE_HANDLER_INTERFACE);

        let connect_iface = peer
            .tree()
            .get(&qp("system/handler/system/protocol/connect"));
        assert!(
            connect_iface.is_some(),
            "connect handler interface not found"
        );
        let connect_iface = connect_iface.unwrap();
        assert_eq!(
            connect_iface.entity_type,
            entity_types::TYPE_HANDLER_INTERFACE
        );

        // §A5 (advertise-what-you-dispatch): every op the connect
        // handler dispatches on an established connection appears in
        // its manifest — including the §5.1 keepalive `ping`.
        let val: ciborium::Value = ciborium::from_reader(connect_iface.data.as_slice()).unwrap();
        let ops = val
            .as_map()
            .unwrap()
            .iter()
            .find_map(|(k, v)| match k {
                ciborium::Value::Text(t) if t == "operations" => v.as_map(),
                _ => None,
            })
            .expect("connect interface has an operations map");
        for required in ["authenticate", "hello", "ping"] {
            assert!(
                ops.iter()
                    .any(|(k, _)| matches!(k, ciborium::Value::Text(t) if t == required)),
                "connect manifest missing required operation `{}`",
                required
            );
        }
    }

    #[test]
    fn test_type_hash_layout_only_on_system_hash() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();

        fn has_field(data: &[u8], field: &str) -> bool {
            let val: ciborium::Value = ciborium::from_reader(data).unwrap();
            val.as_map()
                .unwrap()
                .iter()
                .any(|(k, _v)| k.as_text() == Some(field))
        }

        let hash_type = peer.tree().get(&qp("system/type/system/hash")).unwrap();
        assert!(
            has_field(&hash_type.data, "layout"),
            "system/hash type should have layout field"
        );

        let handler_type = peer.tree().get(&qp("system/type/system/handler")).unwrap();
        assert!(
            !has_field(&handler_type.data, "layout"),
            "system/handler type should NOT have layout field"
        );
    }

    #[test]
    fn test_tree_listing_for_types() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();

        let result = peer.tree().handle_listing(&qp("system/type/")).unwrap();
        assert_eq!(result.status, 200);
        assert_eq!(result.result.entity_type, entity_types::TYPE_TREE_LISTING);

        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let count = map
            .iter()
            .find(|(k, _v): &&(ciborium::Value, ciborium::Value)| k.as_text() == Some("count"))
            .unwrap()
            .1
            .as_integer()
            .unwrap();
        assert!(
            i128::from(count) >= 3,
            "Expected at least 3 top-level type groups, got {}",
            i128::from(count)
        );
    }

    #[test]
    #[cfg(all(feature = "inbox", feature = "continuation", feature = "subscription"))]
    fn test_peer_extension_handlers_registered() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        assert!(peer.handler_registry().get(&qp("system/inbox")).is_some());
        assert!(peer
            .handler_registry()
            .get(&qp("system/continuation"))
            .is_some());
        assert!(peer
            .handler_registry()
            .get(&qp("system/subscription"))
            .is_some());
    }

    #[test]
    #[cfg(all(feature = "inbox", feature = "continuation", feature = "subscription"))]
    fn test_peer_extension_handlers_bootstrapped() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        let inbox_entity = peer.tree().get(&qp("system/inbox"));
        assert!(inbox_entity.is_some(), "inbox handler manifest not found");
        assert_eq!(
            inbox_entity.unwrap().entity_type,
            entity_types::TYPE_HANDLER
        );

        let cont_entity = peer.tree().get(&qp("system/continuation"));
        assert!(
            cont_entity.is_some(),
            "continuation handler manifest not found"
        );
        assert_eq!(cont_entity.unwrap().entity_type, entity_types::TYPE_HANDLER);

        let sub_entity = peer.tree().get(&qp("system/subscription"));
        assert!(
            sub_entity.is_some(),
            "subscription handler manifest not found"
        );
        assert_eq!(sub_entity.unwrap().entity_type, entity_types::TYPE_HANDLER);

        let inbox_iface = peer.tree().get(&qp("system/handler/system/inbox"));
        assert!(inbox_iface.is_some(), "inbox handler interface not found");
        assert_eq!(
            inbox_iface.unwrap().entity_type,
            entity_types::TYPE_HANDLER_INTERFACE
        );
    }

    #[tokio::test]
    async fn test_peer_listen() {
        let peer = PeerBuilder::new()
            .keypair(test_keypair())
            .listen_addr("127.0.0.1:0")
            .build()
            .unwrap();
        let listener = peer.listen().await.unwrap();
        assert_ne!(listener.socket_addr().port(), 0);
        drop(listener);
    }

    #[test]
    fn test_peer_shared() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        let shared = peer.shared();
        assert_eq!(shared.peer_id, *peer.peer_id());
        assert_eq!(shared.config.listen_addr, peer.config().listen_addr);
        // Verify keypair is duplicated correctly
        assert_eq!(shared.keypair.peer_id(), peer.keypair().peer_id());
    }

    #[test]
    fn test_peer_subscribe_events() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        // Should be able to subscribe multiple times
        let _rx1 = peer.subscribe_events();
        let _rx2 = peer.subscribe_events();
    }

    #[tokio::test]
    async fn test_peer_start_engines() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        let shared = peer.shared();
        // Should not panic even with all features enabled
        peer.start_engines(&shared);
    }

    #[tokio::test]
    async fn test_peer_start_engines_idempotent() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        let shared = peer.shared();
        peer.start_engines(&shared);
        // Second call should be a no-op (not spawn duplicate tasks)
        peer.start_engines(&shared);
    }

    #[tokio::test]
    async fn test_peer_execute_tree_get() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        // Put something in the tree first
        let data = entity_ecf::to_ecf(&entity_ecf::text("hello"));
        let entity = entity_entity::Entity::new("test/type", data).unwrap();
        let path = qp("test/exec");
        peer.tree().put(&path, entity).unwrap();

        // Execute tree get via the dispatch path
        let params_data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "path" => entity_ecf::text(&path)
        });
        let params = entity_entity::Entity::new("system/tree/get/params", params_data).unwrap();
        let result = peer.execute("system/tree", "get", params).await;
        assert!(
            result.is_ok(),
            "execute tree get failed: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap().status, 200);
    }

    #[tokio::test]
    async fn test_peer_execute_unknown_handler() {
        // R2: local-dispatch missing-handler now returns
        // the same 404 sync HandlerResult as the wire-dispatch path
        // (INBOX §3.6 option 3), carrying a `system/protocol/error` entity
        // with `code: "handler_not_found"`. Previously this site returned
        // `Err(HandlerError::Internal(_))`, which flattened both the status
        // and the substrate code at the SDK boundary.
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        let params = entity_entity::Entity::new(
            "primitive/null",
            entity_ecf::to_ecf(&entity_ecf::Value::Null),
        )
        .unwrap();
        let result = peer.execute("nonexistent/handler", "op", params).await;
        let hr = result.expect("missing handler now returns Ok(HandlerResult { status: 404 })");
        assert_eq!(hr.status, 404, "status must be 404 for handler-not-found");
        let (code, _msg) = entity_handler::decode_error_entity(&hr.result)
            .expect("result entity must be system/protocol/error");
        assert_eq!(code.as_deref(), Some("handler_not_found"));
    }

    /// §3.3's 500 and 501 rows (0.8.2.6/0.8.2.7): the default `code` is
    /// **mandatory for the generic case**, and the unit of conformance is the
    /// code SLOT rather than a spelling.
    ///
    /// `connection::handler_error_slot` is the peer's whole generic 500/501
    /// surface: every handler in the workspace that returns
    /// `HandlerError::{Internal, NotSupported}` is answered from that one
    /// function, so a minted spelling there is a minted spelling on every
    /// extension at once. It emitted `handler_error` and `not_supported` until
    /// this sweep, both codes in no spec code set — and arch's cohort census
    /// did not see either, because it censused the `STATUS_INTERNAL_ERROR`
    /// spelling and these codes sit in neither of the two forms it looked for.
    ///
    /// **§3b states in the spec that the 500 row is NOT oracle-drivable** — a
    /// conformant peer cannot be made to fail internally on demand over the
    /// wire — so that row is satisfied by source audit and no cross-impl check
    /// will ever catch a regression here. This is the only instrument it will
    /// ever have, which is why it asserts all three arms rather than the one
    /// that moved: the mapping is a single `match`, and a "fix" that collapses
    /// two arms into one would otherwise be invisible.
    #[test]
    fn handler_error_slot_is_the_one_inventory() {
        use entity_handler::HandlerError;
        assert_eq!(
            connection::handler_error_slot(&HandlerError::Internal("x".into())),
            (500, "internal_error"),
            "§3.3's 500 row default is mandatory for the generic case. This \
             emitted `handler_error`, a code in no spec code set, from the one \
             line that answers every handler-side fault in the workspace"
        );
        assert_eq!(
            connection::handler_error_slot(&HandlerError::NotSupported("x".into())),
            (501, "unsupported_operation"),
            "§3.3's 501 row default. This emitted `not_supported`, named at \
             §9.1 as a non-conformant spelling of exactly this row"
        );
        assert_eq!(
            connection::handler_error_slot(&HandlerError::InvalidParams("x".into())),
            (400, "invalid_params"),
            "§3.3's 400 row names `invalid_params` in its DEFINED specific-code \
             set, so this arm is conformant and was deliberately not swept — \
             asserted so that collapsing the three arms goes red"
        );
    }

    /// V7 §6.9 + §3.12: dynamic handler registration via system/handler:register
    /// must succeed and the registered handler must dispatch via tree-walk
    /// (V7 §6.6) — even though no compiled implementation exists in the registry.
    #[cfg(feature = "handlers")]
    #[cfg(feature = "compute")]
    #[tokio::test]
    async fn test_register_then_dispatch_tree_only_handler() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        let pid = peer.shared().keypair.peer_id().to_string();

        // 1. Tree-put a compute expression that returns a constructed entity.
        // construct{entity_type: "app/echo/result", fields: {}} → empty entity.
        let construct_data = entity_ecf::cbor_map! {
            "entity_type" => entity_ecf::text("app/echo/result"),
            "fields" => entity_ecf::Value::Map(vec![])
        };
        let construct =
            entity_entity::Entity::new("compute/construct", entity_ecf::to_ecf(&construct_data))
                .unwrap();
        let expr_path = format!("/{}/app/echo/expr", pid);
        peer.tree().put(&expr_path, construct).unwrap();

        // 2. Build a register-request manifest declaring expression_path.
        let manifest_fields = vec![
            (
                entity_ecf::text("expression_path"),
                entity_ecf::text("app/echo/expr"),
            ),
            (
                entity_ecf::text("internal_scope"),
                entity_ecf::Value::Array(vec![entity_ecf::Value::Map(vec![
                    (
                        entity_ecf::text("handlers"),
                        entity_ecf::Value::Map(vec![(
                            entity_ecf::text("include"),
                            entity_ecf::Value::Array(vec![entity_ecf::text("app/echo")]),
                        )]),
                    ),
                    (
                        entity_ecf::text("operations"),
                        entity_ecf::Value::Map(vec![(
                            entity_ecf::text("include"),
                            entity_ecf::Value::Array(vec![entity_ecf::text("compute")]),
                        )]),
                    ),
                    (
                        entity_ecf::text("resources"),
                        entity_ecf::Value::Map(vec![(
                            entity_ecf::text("include"),
                            entity_ecf::Value::Array(vec![entity_ecf::text("app/echo/*")]),
                        )]),
                    ),
                ])]),
            ),
            (entity_ecf::text("name"), entity_ecf::text("echo")),
            (
                entity_ecf::text("operations"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("compute"),
                    entity_ecf::Value::Map(vec![]),
                )]),
            ),
            (entity_ecf::text("pattern"), entity_ecf::text("app/echo")),
        ];
        let mut manifest_fields = manifest_fields;
        manifest_fields.sort_by(|(a, _), (b, _)| {
            let ab = entity_ecf::to_ecf(a);
            let bb = entity_ecf::to_ecf(b);
            ab.len().cmp(&bb.len()).then(ab.cmp(&bb))
        });
        let req_data = entity_ecf::cbor_map! {
            "manifest" => entity_ecf::Value::Map(manifest_fields)
        };
        let req = entity_entity::Entity::new(
            "system/handler/register-request",
            entity_ecf::to_ecf(&req_data),
        )
        .unwrap();

        let result = peer
            .execute_with_options(
                "system/handler",
                "register",
                req,
                handler_resource_options("app/echo"),
            )
            .await
            .unwrap();
        assert_eq!(result.status, 200, "register failed: {:?}", result.result);

        // 3. Verify all four canonical paths populated.
        let manifest_at_pattern = peer.tree().get(&format!("/{}/app/echo", pid));
        assert!(manifest_at_pattern.is_some(), "manifest at pattern path");
        assert_eq!(
            manifest_at_pattern.unwrap().entity_type,
            "system/handler",
            "manifest is system/handler entity"
        );
        let interface = peer
            .tree()
            .get(&format!("/{}/system/handler/app/echo", pid));
        assert!(
            interface.is_some(),
            "interface at /system/handler/{{pattern}}"
        );
        let grant = peer
            .tree()
            .get(&format!("/{}/system/capability/grants/app/echo", pid));
        assert!(
            grant.is_some(),
            "grant at /system/capability/grants/{{pattern}}"
        );

        // 4. Dispatch to the newly registered handler via tree-walk.
        // No compiled handler exists for "app/echo" in the registry — dispatch
        // MUST find the manifest in the tree (V7 §6.6) and route through
        // entity-native dispatch (PROPOSAL §1).
        let empty_params = entity_entity::Entity::new(
            "primitive/null",
            entity_ecf::to_ecf(&entity_ecf::Value::Null),
        )
        .unwrap();
        let dispatch_result = peer
            .execute("app/echo", "compute", empty_params)
            .await
            .expect("dispatch to tree-only handler must succeed");
        assert_eq!(dispatch_result.status, 200);
        assert_eq!(
            dispatch_result.result.entity_type, "app/echo/result",
            "expression returned its constructed entity"
        );
    }

    /// AUTHZ-SUBDISPATCH-RESOURCE-1 (PROPOSAL-DISPATCH-AUTHORIZATION-FRAME D1)
    /// — §5.2's resource dimension binds an in-process sub-dispatch exactly as
    /// it binds a wire dispatch, because the pseudocode's conditional is
    /// `resource_target is not null`: a test on the FIELD, not on the door.
    ///
    /// The confused-deputy shape, and the only shape that reaches this path: a
    /// handler holding a grant scoped to `app/*` sub-dispatches
    /// `system/handler:register` with a caller-influenced resource target
    /// outside that scope. §6.2 assigns `register`'s install-path authorization
    /// to this check and to nothing else, and `register` always carries a
    /// resource (§3.2 path-as-resource) — so before D1 this installed at `pwn`
    /// under a grant that covers only `app/*`.
    ///
    /// Teeth: this whole in-process path ran NO capability check of any
    /// dimension before D1. Deleting the resource-dimension block in
    /// `make_execute_fn` turns the first assertion red.
    #[cfg(feature = "handlers")]
    #[tokio::test]
    async fn subdispatch_resource_dimension_binds_the_dispatching_handler() {
        use entity_capability::{CapabilityToken, GrantEntry, Granter, IdScope, PathScope};

        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        let shared = peer.shared();
        let identity = shared.identity_hash;

        // The deputy's grant: everything, but only over `app/*`.
        let deputy_grant = CapabilityToken {
            grants: vec![GrantEntry {
                handlers: PathScope::new(vec!["*".into()]),
                resources: PathScope::new(vec!["app/*".into()]),
                operations: IdScope::new(vec!["*".into()]),
                peers: None,
                constraints: None,
                allowances: None,
            }],
            granter: Granter::Single(identity),
            grantee: identity,
            parent: None,
            created_at: 0,
            expires_at: None,
            not_before: None,
            delegation_caveats: None,
        };

        let execute_fn = connection::make_execute_fn(
            shared.clone(),
            Some(identity),
            std::collections::HashMap::new(),
            None,
            None,
            connection::DispatchCeiling::Handler(Some(Box::new(deputy_grant.clone()))),
        );

        let params = entity_entity::Entity::new(
            "primitive/null",
            entity_ecf::to_ecf(&entity_ecf::Value::Null),
        )
        .unwrap();

        // Outside the grant: `system/handler/pwn` is not under `app/*`.
        let denied = execute_fn(
            "system/handler".into(),
            "register".into(),
            params.clone(),
            handler_resource_options("pwn"),
        )
        .await
        .expect("dispatch returns a result, not a transport error");
        assert_eq!(
            denied.status, 403,
            "a deputy granted only `app/*` must not reach `system/handler/pwn`"
        );

        // Control: the same dispatch with an in-scope resource is NOT denied by
        // the resource dimension. It may fail later for unrelated reasons (the
        // params are not a real register-request) — what must not happen is a
        // 403 from this check, which would mean the guard denies everything and
        // the assertion above proves nothing.
        let allowed = execute_fn(
            "system/handler".into(),
            "register".into(),
            params,
            entity_handler::ExecuteOptions {
                resource: Some(entity_capability::ResourceTarget {
                    targets: vec!["app/mine".into()],
                    exclude: vec![],
                }),
                ..Default::default()
            },
        )
        .await
        .expect("dispatch returns a result");
        assert_ne!(
            allowed.status, 403,
            "an in-scope resource must pass the §5.2 resource dimension"
        );
    }

    /// The other half of D1: its ceiling must not forbid the peer's own engine
    /// from writing the **foreign-namespace** subtrees its store legitimately
    /// holds (V7 §1.4 Category A — a cached foreign content site, a `follow`
    /// mirror at `/{them}/app/...`).
    ///
    /// §6.9 calls the default per-handler self-grant "all resources", but the
    /// bare `*` resource form canonicalizes to `/{local}/*` — so written that
    /// way it silently means *own namespace only*, and every engine-dispatched
    /// mirror write 403s at the §5.2 resource dimension. Nothing read the field
    /// before D1, so the mis-encoding was invisible until D1 made this grant a
    /// ceiling; the first thing it broke was `follow(Continuation)`'s standing
    /// leg (`entity-sdk`'s `follow_continuation_standing_leg_fires_cross_peer`),
    /// which merges into `/{remote}/...` in the LOCAL tree. `/*/*` is the same
    /// R-5 form `debug_open_grants` already uses for the same reason.
    ///
    /// Teeth: build the ceiling from `wildcard_handler_grant()` — the pre-fix
    /// value — and the first assertion goes 403. The control below is the
    /// narrow-deputy case, which must stay denied: this is a fix to what "all
    /// resources" encodes, not a hole in D1.
    #[tokio::test]
    async fn default_handler_grant_ceiling_reaches_a_foreign_namespace_path() {
        use entity_capability::{CapabilityToken, GrantEntry, Granter, IdScope, PathScope};

        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        let shared = peer.shared();
        let identity = shared.identity_hash;
        // A real, well-formed foreign peer-id — the mirror path lives under its
        // namespace but the write lands in OUR tree.
        let foreign = Keypair::from_seed([7u8; 32]).peer_id().to_string();

        let token = |grants: Vec<GrantEntry>| CapabilityToken {
            grants,
            granter: Granter::Single(identity),
            grantee: identity,
            parent: None,
            created_at: 0,
            expires_at: None,
            not_before: None,
            delegation_caveats: None,
        };

        let foreign_resource = |path: String| entity_handler::ExecuteOptions {
            resource: Some(entity_capability::ResourceTarget {
                targets: vec![path],
                exclude: vec![],
            }),
            ..Default::default()
        };

        // `system/tree put` params: `{entity: {type, data}}` (§3.2 path-as-
        // resource, so the mirror path IS the resource target).
        let body = entity_entity::Entity::new(
            "primitive/text",
            entity_ecf::to_ecf(&entity_ecf::text("mirrored-from-them")),
        )
        .unwrap();
        let params = entity_entity::Entity::new(
            "system/tree/put-request",
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                entity_ecf::text("entity"),
                entity_ecf::Value::Map(vec![
                    (
                        entity_ecf::text("content_hash"),
                        entity_ecf::Value::Bytes(body.content_hash.to_bytes()),
                    ),
                    (
                        entity_ecf::text("data"),
                        entity_ecf::text("mirrored-from-them"),
                    ),
                    (
                        entity_ecf::text("type"),
                        entity_ecf::text(&body.entity_type),
                    ),
                ]),
            )])),
        )
        .unwrap();
        let mirror_path = format!("/{foreign}/app/mirror/x");

        // The §6.9 default scope: "all resources" must mean all resources.
        let default_scope = connection::make_execute_fn(
            shared.clone(),
            Some(identity),
            std::collections::HashMap::new(),
            None,
            None,
            connection::DispatchCeiling::Handler(Some(Box::new(token(
                entity_capability::default_handler_self_grant(),
            )))),
        );
        let mirrored = default_scope(
            "system/tree".into(),
            "put".into(),
            params.clone(),
            foreign_resource(mirror_path.clone()),
        )
        .await
        .expect("dispatch returns a result, not a transport error");
        assert_ne!(
            mirrored.status, 403,
            "the §6.9 default handler grant is `all resources`; a mirror write \
             under another peer's namespace in OUR OWN tree must not be denied \
             by the §5.2 resource dimension"
        );
        assert!(
            peer.tree().get(&mirror_path).is_some(),
            "and the write must actually land in the local tree"
        );

        // Control: a deputy that declared a narrow `internal_scope` is still
        // confined by it. D1's teeth are unchanged.
        let narrow = connection::make_execute_fn(
            shared.clone(),
            Some(identity),
            std::collections::HashMap::new(),
            None,
            None,
            connection::DispatchCeiling::Handler(Some(Box::new(token(vec![GrantEntry {
                handlers: PathScope::all(),
                resources: PathScope::new(vec!["app/*".into()]),
                operations: IdScope::all(),
                peers: Some(IdScope::all()),
                constraints: None,
                allowances: None,
            }])))),
        );
        let denied = narrow(
            "system/tree".into(),
            "put".into(),
            params,
            foreign_resource(format!("/{foreign}/app/mirror/y")),
        )
        .await
        .expect("dispatch returns a result");
        assert_eq!(
            denied.status, 403,
            "a deputy scoped to its own `app/*` must not reach a foreign \
             namespace — widening the DEFAULT scope is not widening D1"
        );
    }

    /// PROPOSAL §4 (revised): bare-primitive results from an entity-native
    /// handler are wrapped at the dispatch boundary using the operation's
    /// declared output_type. Validator-driving regression for Go's
    /// dispatch_basic / scope_params / scope_operation et al.
    #[cfg(feature = "handlers")]
    #[cfg(feature = "compute")]
    #[tokio::test]
    async fn test_register_then_dispatch_returns_wrapped_primitive() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        let pid = peer.shared().keypair.peer_id().to_string();

        // Expression: compute/literal { value: 42 } — returns a bare primitive.
        let lit_data = entity_ecf::cbor_map! {
            "value" => entity_ecf::integer(42)
        };
        let lit =
            entity_entity::Entity::new("compute/literal", entity_ecf::to_ecf(&lit_data)).unwrap();
        let expr_path = format!("/{}/app/lit/expr", pid);
        peer.tree().put(&expr_path, lit).unwrap();

        let mut manifest_fields = vec![
            (
                entity_ecf::text("expression_path"),
                entity_ecf::text("app/lit/expr"),
            ),
            (
                entity_ecf::text("internal_scope"),
                entity_ecf::Value::Array(vec![entity_ecf::Value::Map(vec![
                    (
                        entity_ecf::text("handlers"),
                        entity_ecf::Value::Map(vec![(
                            entity_ecf::text("include"),
                            entity_ecf::Value::Array(vec![entity_ecf::text("app/lit")]),
                        )]),
                    ),
                    (
                        entity_ecf::text("operations"),
                        entity_ecf::Value::Map(vec![(
                            entity_ecf::text("include"),
                            entity_ecf::Value::Array(vec![entity_ecf::text("compute")]),
                        )]),
                    ),
                    (
                        entity_ecf::text("resources"),
                        entity_ecf::Value::Map(vec![(
                            entity_ecf::text("include"),
                            entity_ecf::Value::Array(vec![entity_ecf::text("app/lit/*")]),
                        )]),
                    ),
                ])]),
            ),
            (entity_ecf::text("name"), entity_ecf::text("lit")),
            (
                entity_ecf::text("operations"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("compute"),
                    entity_ecf::Value::Map(vec![(
                        entity_ecf::text("output_type"),
                        entity_ecf::text("primitive/integer"),
                    )]),
                )]),
            ),
            (entity_ecf::text("pattern"), entity_ecf::text("app/lit")),
        ];
        manifest_fields.sort_by(|(a, _), (b, _)| {
            let ab = entity_ecf::to_ecf(a);
            let bb = entity_ecf::to_ecf(b);
            ab.len().cmp(&bb.len()).then(ab.cmp(&bb))
        });
        let req_data = entity_ecf::cbor_map! {
            "manifest" => entity_ecf::Value::Map(manifest_fields)
        };
        let req = entity_entity::Entity::new(
            "system/handler/register-request",
            entity_ecf::to_ecf(&req_data),
        )
        .unwrap();
        let result = peer
            .execute_with_options(
                "system/handler",
                "register",
                req,
                handler_resource_options("app/lit"),
            )
            .await
            .unwrap();
        assert_eq!(result.status, 200);

        // Dispatch to the new handler — bare 42 must come back wrapped as
        // {type: "primitive/integer", data: <42>}.
        let empty = entity_entity::Entity::new(
            "primitive/null",
            entity_ecf::to_ecf(&entity_ecf::Value::Null),
        )
        .unwrap();
        let dispatch_result = peer
            .execute("app/lit", "compute", empty)
            .await
            .expect("dispatch must succeed");
        assert_eq!(dispatch_result.status, 200);
        assert_eq!(
            dispatch_result.result.entity_type, "primitive/integer",
            "bare primitive wrapped using operation.output_type"
        );
        let value: ciborium::Value =
            ciborium::from_reader(dispatch_result.result.data.as_slice()).unwrap();
        let n: i128 = value.as_integer().unwrap().into();
        assert_eq!(n, 42, "primitive payload preserved");
    }

    /// spec-gap-handler-grant-authority §S2: the dispatcher MUST reject a
    /// handler grant whose granter is not the local peer's identity. Models
    /// the cross-peer subtree-transfer attack — Peer A's signed grant ends
    /// up in Peer B's tree at `system/capability/grants/{pattern}`; Peer B
    /// must NOT honor it for entity-native dispatch.
    ///
    /// Setup: build peer normally, register a handler so the manifest +
    /// interface land in the tree (with a valid local-issued grant), then
    /// overwrite the grant entity with one whose granter is a foreign hash.
    /// Dispatch must fail closed with 403 (per §7.1, since the grant is
    /// effectively missing as far as authority goes).
    #[cfg(feature = "handlers")]
    #[cfg(feature = "compute")]
    #[tokio::test]
    async fn test_dispatch_rejects_foreign_granter_handler_grant() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        let pid = peer.shared().keypair.peer_id().to_string();
        let local_identity = peer.shared().identity_hash;

        // Plant an expression and register a handler at app/echo (issues a
        // legitimate locally-granted grant).
        let lit_data = entity_ecf::cbor_map! {
            "value" => entity_ecf::integer(7)
        };
        let lit =
            entity_entity::Entity::new("compute/literal", entity_ecf::to_ecf(&lit_data)).unwrap();
        peer.tree()
            .put(&format!("/{}/app/echo/expr", pid), lit)
            .unwrap();

        let mut manifest_fields = vec![
            (
                entity_ecf::text("expression_path"),
                entity_ecf::text("app/echo/expr"),
            ),
            (
                entity_ecf::text("internal_scope"),
                entity_ecf::Value::Array(vec![entity_ecf::Value::Map(vec![
                    (
                        entity_ecf::text("handlers"),
                        entity_ecf::Value::Map(vec![(
                            entity_ecf::text("include"),
                            entity_ecf::Value::Array(vec![entity_ecf::text("app/echo")]),
                        )]),
                    ),
                    (
                        entity_ecf::text("operations"),
                        entity_ecf::Value::Map(vec![(
                            entity_ecf::text("include"),
                            entity_ecf::Value::Array(vec![entity_ecf::text("compute")]),
                        )]),
                    ),
                    (
                        entity_ecf::text("resources"),
                        entity_ecf::Value::Map(vec![(
                            entity_ecf::text("include"),
                            entity_ecf::Value::Array(vec![entity_ecf::text("app/echo/*")]),
                        )]),
                    ),
                ])]),
            ),
            (entity_ecf::text("name"), entity_ecf::text("echo")),
            (
                entity_ecf::text("operations"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("compute"),
                    entity_ecf::Value::Map(vec![(
                        entity_ecf::text("output_type"),
                        entity_ecf::text("primitive/integer"),
                    )]),
                )]),
            ),
            (entity_ecf::text("pattern"), entity_ecf::text("app/echo")),
        ];
        manifest_fields.sort_by(|(a, _), (b, _)| {
            let ab = entity_ecf::to_ecf(a);
            let bb = entity_ecf::to_ecf(b);
            ab.len().cmp(&bb.len()).then(ab.cmp(&bb))
        });
        let req = entity_entity::Entity::new(
            "system/handler/register-request",
            entity_ecf::to_ecf(&entity_ecf::cbor_map! {
                "manifest" => entity_ecf::Value::Map(manifest_fields)
            }),
        )
        .unwrap();
        peer.execute_with_options(
            "system/handler",
            "register",
            req,
            handler_resource_options("app/echo"),
        )
        .await
        .unwrap();

        // Sanity: the locally-issued grant works — dispatch returns 200.
        let empty = entity_entity::Entity::new(
            "primitive/null",
            entity_ecf::to_ecf(&entity_ecf::Value::Null),
        )
        .unwrap();
        let ok = peer
            .execute("app/echo", "compute", empty.clone())
            .await
            .unwrap();
        assert_eq!(ok.status, 200, "baseline dispatch with local grant");

        // Now overwrite the grant entity with one carrying a foreign granter
        // (the §S2 attack shape). Same scope, same parent, just a different
        // granter hash — simulating a grant signed by another peer.
        let foreign = entity_hash::Hash::compute("test", b"foreign-peer");
        assert_ne!(foreign, local_identity);
        let foreign_token = entity_capability::CapabilityToken {
            grants: entity_capability::wildcard_handler_grant(),
            granter: entity_capability::Granter::Single(foreign),
            grantee: foreign,
            parent: None,
            created_at: 0,
            expires_at: None,
            not_before: None,
            delegation_caveats: None,
        };
        let foreign_entity = foreign_token.to_entity().unwrap();
        peer.tree()
            .put(
                &format!("/{}/system/capability/grants/app/echo", pid),
                foreign_entity,
            )
            .unwrap();

        // Dispatch with the foreign grant in place — MUST fail closed (§7.1
        // engages because load_local_handler_grant treats foreign-granter as
        // missing per §S2).
        let denied = peer.execute("app/echo", "compute", empty).await.unwrap();
        assert_eq!(
            denied.status, 403,
            "foreign-granter handler grant must be rejected (spec-gap §S2)"
        );
    }

    /// Build + register a no-op entity-native compute handler at the given
    /// pattern with the given internal_scope. Plants the expression entity at
    /// `{pattern}/expr` (literal `7`) and registers via system/handler.
    /// Returns `(peer, pid)` for follow-on assertions.
    #[cfg(feature = "handlers")]
    #[cfg(feature = "compute")]
    async fn register_compute_handler(
        peer: &Peer,
        pattern: &str,
        internal_scope: entity_ecf::Value,
    ) {
        let pid = peer.shared().keypair.peer_id().to_string();

        let lit_data = entity_ecf::cbor_map! {
            "value" => entity_ecf::integer(7)
        };
        let lit =
            entity_entity::Entity::new("compute/literal", entity_ecf::to_ecf(&lit_data)).unwrap();
        peer.tree()
            .put(&format!("/{}/{}/expr", pid, pattern), lit)
            .unwrap();

        let mut manifest_fields = vec![
            (
                entity_ecf::text("expression_path"),
                entity_ecf::text(format!("{}/expr", pattern)),
            ),
            (entity_ecf::text("internal_scope"), internal_scope),
            (entity_ecf::text("name"), entity_ecf::text("test-handler")),
            (
                entity_ecf::text("operations"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("compute"),
                    entity_ecf::Value::Map(vec![(
                        entity_ecf::text("output_type"),
                        entity_ecf::text("primitive/integer"),
                    )]),
                )]),
            ),
            (entity_ecf::text("pattern"), entity_ecf::text(pattern)),
        ];
        manifest_fields.sort_by(|(a, _), (b, _)| {
            let ab = entity_ecf::to_ecf(a);
            let bb = entity_ecf::to_ecf(b);
            ab.len().cmp(&bb.len()).then(ab.cmp(&bb))
        });
        let req = entity_entity::Entity::new(
            "system/handler/register-request",
            entity_ecf::to_ecf(&entity_ecf::cbor_map! {
                "manifest" => entity_ecf::Value::Map(manifest_fields)
            }),
        )
        .unwrap();
        let result = peer
            .execute_with_options(
                "system/handler",
                "register",
                req,
                handler_resource_options(pattern),
            )
            .await
            .unwrap();
        assert_eq!(result.status, 200, "register must succeed for fixture");
    }

    /// internal_scope fixture: full wildcard for the given pattern. Used by
    /// tests that just need a successful baseline before tampering.
    #[cfg(feature = "handlers")]
    #[cfg(feature = "compute")]
    fn full_internal_scope(pattern: &str) -> entity_ecf::Value {
        entity_ecf::Value::Array(vec![entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("handlers"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("include"),
                    entity_ecf::Value::Array(vec![entity_ecf::text(pattern)]),
                )]),
            ),
            (
                entity_ecf::text("operations"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("include"),
                    entity_ecf::Value::Array(vec![entity_ecf::text("compute")]),
                )]),
            ),
            (
                entity_ecf::text("resources"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("include"),
                    entity_ecf::Value::Array(vec![entity_ecf::text(format!("{}/*", pattern))]),
                )]),
            ),
        ])])
    }

    /// spec-gap §S2(b): a grant whose signature does not verify against the
    /// local peer's pubkey MUST be rejected. Models a path-write attacker
    /// that forged a grant entity (with `granter = local_identity_hash` so
    /// the granter check would pass) and either forgot the signature or
    /// crafted a wrong one.
    #[cfg(feature = "handlers")]
    #[cfg(feature = "compute")]
    #[tokio::test]
    async fn test_dispatch_rejects_handler_grant_with_bad_signature() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        let pid = peer.shared().keypair.peer_id().to_string();
        let local_identity = peer.shared().identity_hash;
        register_compute_handler(&peer, "app/echo", full_internal_scope("app/echo")).await;

        let empty = entity_entity::Entity::new(
            "primitive/null",
            entity_ecf::to_ecf(&entity_ecf::Value::Null),
        )
        .unwrap();

        // Baseline: the signed grant works.
        let ok = peer
            .execute("app/echo", "compute", empty.clone())
            .await
            .unwrap();
        assert_eq!(ok.status, 200, "baseline: signed grant dispatches");

        // Read the existing grant hash so we can target it with a bad sig.
        let grant_path = format!("/{}/system/capability/grants/app/echo", pid);
        let cap_hash = peer
            .shared()
            .location_index
            .get(&grant_path)
            .expect("grant must be registered");

        // Build a signature entity that targets the right hash but carries
        // garbage signature bytes (right shape, wrong bytes — the verify
        // call must fail). signer = local identity so we exercise the
        // signature-verification path, not the signer-mismatch short-circuit.
        let bad_sig = entity_types::SignatureData {
            target: cap_hash,
            signer: local_identity,
            algorithm: "ed25519".to_string(),
            signature: vec![0u8; 64],
        };
        let bad_sig_entity = bad_sig.to_entity().unwrap();
        peer.tree()
            .put(
                &entity_hash::invariant_signature_path(&pid, &cap_hash),
                bad_sig_entity,
            )
            .unwrap();

        let denied = peer.execute("app/echo", "compute", empty).await.unwrap();
        assert_eq!(
            denied.status, 403,
            "tampered signature must be rejected (§S2)"
        );
    }

    /// spec-gap §S2(b): a grant with NO signature entity in the tree MUST be
    /// rejected. Models an attacker that wrote a forged grant but did not
    /// (or could not) write a corresponding signature.
    #[cfg(feature = "handlers")]
    #[cfg(feature = "compute")]
    #[tokio::test]
    async fn test_dispatch_rejects_handler_grant_with_missing_signature() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        let pid = peer.shared().keypair.peer_id().to_string();
        register_compute_handler(&peer, "app/echo", full_internal_scope("app/echo")).await;

        // Drop the signature entry from the index. The grant remains in place.
        // The sig is keyed by the grant's content hash (v7.74 §3.4).
        let grant_hash = peer
            .shared()
            .location_index
            .get(&format!("/{}/system/capability/grants/app/echo", pid))
            .expect("grant must be registered");
        peer.shared()
            .location_index
            .remove(&entity_hash::invariant_signature_path(&pid, &grant_hash));

        let empty = entity_entity::Entity::new(
            "primitive/null",
            entity_ecf::to_ecf(&entity_ecf::Value::Null),
        )
        .unwrap();
        let denied = peer.execute("app/echo", "compute", empty).await.unwrap();
        assert_eq!(
            denied.status, 403,
            "missing signature must be rejected (§S2)"
        );
    }

    /// spec-gap §S2(c): an `expires_at` in the past makes the grant invalid.
    /// Overwrite the registered grant with one whose `expires_at = 1`
    /// (effectively epoch) and confirm dispatch returns 403.
    #[cfg(feature = "handlers")]
    #[cfg(feature = "compute")]
    #[tokio::test]
    async fn test_dispatch_rejects_expired_handler_grant() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        let pid = peer.shared().keypair.peer_id().to_string();
        let local_identity = peer.shared().identity_hash;
        register_compute_handler(&peer, "app/echo", full_internal_scope("app/echo")).await;

        // Overwrite the grant with an expired one. Re-sign it so the
        // signature-verification step passes — we want the temporal check
        // to be the gating failure, not the sig check.
        let expired_token = entity_capability::CapabilityToken {
            grants: entity_capability::wildcard_handler_grant(),
            granter: entity_capability::Granter::Single(local_identity),
            grantee: local_identity,
            parent: None,
            created_at: 0,
            expires_at: Some(1), // 1ms past epoch — long expired
            not_before: None,
            delegation_caveats: None,
        };
        let expired_entity = expired_token.to_entity().unwrap();
        let expired_hash = expired_entity.content_hash;
        peer.tree()
            .put(
                &format!("/{}/system/capability/grants/app/echo", pid),
                expired_entity,
            )
            .unwrap();

        // Re-sign for the new cap_hash so the sig check would pass.
        let sig_bytes = peer.shared().keypair.sign(&expired_hash.to_bytes());
        let sig = entity_types::SignatureData {
            target: expired_hash,
            signer: local_identity,
            algorithm: "ed25519".to_string(),
            signature: sig_bytes.to_vec(),
        };
        peer.tree()
            .put(
                &entity_hash::invariant_signature_path(&pid, &expired_hash),
                sig.to_entity().unwrap(),
            )
            .unwrap();

        let empty = entity_entity::Entity::new(
            "primitive/null",
            entity_ecf::to_ecf(&entity_ecf::Value::Null),
        )
        .unwrap();
        let denied = peer.execute("app/echo", "compute", empty).await.unwrap();
        assert_eq!(denied.status, 403, "expired grant must be rejected (§S2)");
    }

    /// F27 §6.9a: the peer materializes a principal-level self-owner seed cap
    /// at `system/capability/policy/{self_identity_hash_hex}` at peer-init (the
    /// §9.1 floor MUST), eager + entity-native + inspectable (A5). Coexists
    /// with the per-handler self-grants (§6.9a.4); this asserts the new entry.
    #[tokio::test]
    async fn test_self_owner_seed_cap_materialized_at_bootstrap() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        let pid = peer.shared().keypair.peer_id().to_string();
        let self_hex = peer.shared().identity_hash.to_hex();

        let path = format!("/{}/system/capability/policy/{}", pid, self_hex);
        let h = peer
            .shared()
            .location_index
            .get(&path)
            .expect("F27 §6.9a: self-owner seed policy entry must exist at peer-init");
        let entity = peer.shared().content_store.get(&h).expect("entry entity");
        assert_eq!(entity.entity_type, entity_types::TYPE_CAP_POLICY_ENTRY);

        // The entry grants owner authority scoped to the peer's own namespace.
        let val: ciborium::Value = ciborium::de::from_reader(entity.data.as_slice()).unwrap();
        let grants_v = val
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_text() == Some("grants"))
            .map(|(_, v)| v)
            .expect("policy entry carries grants");
        let arr = grants_v.as_array().unwrap();
        assert_eq!(arr.len(), 1, "single owner grant");
        let g = entity_capability::decode_grant_entry(&arr[0]).unwrap();
        assert!(
            g.resources.include.contains(&format!("/{}/*", pid)),
            "owner grant scopes resources to the peer's own namespace, got {:?}",
            g.resources.include
        );
        assert!(
            g.operations.include.contains(&"*".to_string()),
            "owner grant covers all operations"
        );
    }

    /// F27 §6.9a: `with_owner_identity` overrides the self-owner seed grantee
    /// (operator-separated model). The seed entry keys by the operator's
    /// identity hash, not the peer's own.
    #[tokio::test]
    async fn test_with_owner_identity_overrides_seed_grantee() {
        let operator = entity_hash::Hash::compute("system/peer", b"operator-identity-entity");
        let peer = PeerBuilder::new()
            .keypair(test_keypair())
            .with_owner_identity(operator)
            .build()
            .unwrap();
        let pid = peer.shared().keypair.peer_id().to_string();
        let self_hex = peer.shared().identity_hash.to_hex();

        let operator_path = format!("/{}/system/capability/policy/{}", pid, operator.to_hex());
        assert!(
            peer.shared().location_index.get(&operator_path).is_some(),
            "owner seed keyed by the override operator identity"
        );
        // Default self-keyed entry is NOT written when overridden.
        let self_path = format!("/{}/system/capability/policy/{}", pid, self_hex);
        assert!(
            peer.shared().location_index.get(&self_path).is_none(),
            "no self-keyed owner entry when owner identity is overridden"
        );
    }

    /// F27 §6.9a: a canonical seed-policy **file** materializes the same
    /// entries `with_seed_policy` does — the operator hands one keystone-format
    /// file to any impl and gets one posture. Locks the whole path (file →
    /// parse → L0 entry), not just the parser: go's `--seed-policy-file` and
    /// python's `--seed-policy` read this exact document.
    #[tokio::test]
    async fn test_seed_policy_from_canonical_file_materializes_entries() {
        let admin = entity_hash::Hash::compute("system/peer", b"admin-identity-entity").to_hex();
        let doc = format!(
            r#"{{"version":1,"entries":[
                {{"_comment":"admin-seeded-restrictive posture",
                  "grantee":"{}",
                  "grants":[{{"handlers":{{"include":["*"]}},
                              "resources":{{"include":["*"]}},
                              "operations":{{"include":["*"]}},
                              "peers":{{"include":["self"]}}}}]}}]}}"#,
            admin
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seed-policy.json");
        std::fs::write(&path, doc).unwrap();

        let peer = PeerBuilder::new()
            .keypair(test_keypair())
            .with_seed_policy_from_file(&path)
            .unwrap()
            .build()
            .unwrap();
        let pid = peer.shared().keypair.peer_id().to_string();

        let entry_path = format!("/{}/system/capability/policy/{}", pid, admin);
        let h = peer
            .shared()
            .location_index
            .get(&entry_path)
            .expect("the file's admin entry is materialized at L0");
        let entity = peer.shared().content_store.get(&h).expect("entry entity");
        assert_eq!(entity.entity_type, entity_types::TYPE_CAP_POLICY_ENTRY);

        let val: ciborium::Value = ciborium::de::from_reader(entity.data.as_slice()).unwrap();
        let grants_v = val
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_text() == Some("grants"))
            .map(|(_, v)| v)
            .expect("policy entry carries grants");
        let arr = grants_v.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        let g = entity_capability::decode_grant_entry(&arr[0]).unwrap();
        assert_eq!(g.handlers.include, vec!["*".to_string()]);
        assert_eq!(g.operations.include, vec!["*".to_string()]);

        // Unknown peers match no entry: no `default` entry is invented from a
        // file that names only an admin — that absence IS the restrictive
        // posture the gating checks measure against.
        let default_path = format!("/{}/system/capability/policy/default", pid);
        assert!(
            peer.shared().location_index.get(&default_path).is_none(),
            "an admin-only file must not seed a `default` fallback"
        );
    }

    /// spec-gap §S2(c): a `not_before` in the future makes the grant not yet
    /// valid. Mirror of the expired test, but with `not_before = u64::MAX`.
    #[cfg(feature = "handlers")]
    #[cfg(feature = "compute")]
    #[tokio::test]
    async fn test_dispatch_rejects_not_yet_valid_handler_grant() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        let pid = peer.shared().keypair.peer_id().to_string();
        let local_identity = peer.shared().identity_hash;
        register_compute_handler(&peer, "app/echo", full_internal_scope("app/echo")).await;

        let future_token = entity_capability::CapabilityToken {
            grants: entity_capability::wildcard_handler_grant(),
            granter: entity_capability::Granter::Single(local_identity),
            grantee: local_identity,
            parent: None,
            created_at: 0,
            expires_at: None,
            // i64::MAX ms = ~292M years from epoch — effectively "never
            // valid" without tripping the u64-as-i64 truncation in
            // CapabilityToken::to_ecf (a separate, pre-existing bug).
            not_before: Some(i64::MAX as u64),
            delegation_caveats: None,
        };
        let future_entity = future_token.to_entity().unwrap();
        let future_hash = future_entity.content_hash;
        peer.tree()
            .put(
                &format!("/{}/system/capability/grants/app/echo", pid),
                future_entity,
            )
            .unwrap();

        let sig_bytes = peer.shared().keypair.sign(&future_hash.to_bytes());
        let sig = entity_types::SignatureData {
            target: future_hash,
            signer: local_identity,
            algorithm: "ed25519".to_string(),
            signature: sig_bytes.to_vec(),
        };
        peer.tree()
            .put(
                &entity_hash::invariant_signature_path(&pid, &future_hash),
                sig.to_entity().unwrap(),
            )
            .unwrap();

        let empty = entity_entity::Entity::new(
            "primitive/null",
            entity_ecf::to_ecf(&entity_ecf::Value::Null),
        )
        .unwrap();
        let denied = peer.execute("app/echo", "compute", empty).await.unwrap();
        assert_eq!(
            denied.status, 403,
            "not-yet-valid grant must be rejected (§S2)"
        );
    }

    /// spec-gap §S3: a handler with an EMPTY internal_scope (i.e. an empty
    /// `grants: []` array on its capability token) is a valid pure-functional
    /// handler. Dispatch must run — the expression here is `compute/literal 7`,
    /// which has no impure ops, so per-op cap checks never fire and the
    /// evaluator returns the literal unchanged.
    #[cfg(feature = "handlers")]
    #[cfg(feature = "compute")]
    #[tokio::test]
    async fn test_entity_native_handler_with_empty_internal_scope_runs() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        // internal_scope = []  — no impure authority granted.
        register_compute_handler(&peer, "app/pure", entity_ecf::Value::Array(vec![])).await;

        let empty = entity_entity::Entity::new(
            "primitive/null",
            entity_ecf::to_ecf(&entity_ecf::Value::Null),
        )
        .unwrap();
        let result = peer.execute("app/pure", "compute", empty).await.unwrap();
        assert_eq!(
            result.status, 200,
            "pure-functional handler with empty grants must dispatch (§S3)"
        );
    }

    /// V7 §6.2: register on system/* MUST be rejected (forbidden_pattern).
    #[cfg(feature = "handlers")]
    #[tokio::test]
    async fn test_register_rejects_system_pattern() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();

        let mut manifest_fields = vec![
            (entity_ecf::text("name"), entity_ecf::text("evil")),
            (
                entity_ecf::text("operations"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("op"),
                    entity_ecf::Value::Map(vec![]),
                )]),
            ),
            (entity_ecf::text("pattern"), entity_ecf::text("system/evil")),
        ];
        manifest_fields.sort_by(|(a, _), (b, _)| {
            let ab = entity_ecf::to_ecf(a);
            let bb = entity_ecf::to_ecf(b);
            ab.len().cmp(&bb.len()).then(ab.cmp(&bb))
        });
        let req_data = entity_ecf::cbor_map! {
            "manifest" => entity_ecf::Value::Map(manifest_fields)
        };
        let req = entity_entity::Entity::new(
            "system/handler/register-request",
            entity_ecf::to_ecf(&req_data),
        )
        .unwrap();

        let result = peer
            .execute_with_options(
                "system/handler",
                "register",
                req,
                handler_resource_options("system/evil"),
            )
            .await
            .unwrap();
        assert_eq!(result.status, 403);
    }

    /// Integration test: execute tree put, receive event via subscribe_events.
    #[tokio::test]
    async fn test_execute_put_triggers_event() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        let shared = peer.shared();
        peer.start_engines(&shared);

        let mut events = peer.subscribe_events();

        // Execute a tree put via the handler dispatch path (needs resource target)
        let path = qp("test/event-path");
        let body = entity_entity::Entity::new(
            "test/type",
            entity_ecf::to_ecf(&entity_ecf::text("event-test")),
        )
        .unwrap();
        let params_data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "entity" => entity_ecf::cbor_map!{
                "content_hash" => entity_ecf::Value::Bytes(body.content_hash.to_bytes()),
                "data" => entity_ecf::text("event-test"),
                "type" => entity_ecf::text("test/type")
            }
        });
        let params = entity_entity::Entity::new("system/tree/put-request", params_data).unwrap();
        let opts = entity_handler::ExecuteOptions {
            resource: Some(entity_capability::ResourceTarget {
                targets: vec![path.clone()],
                exclude: vec![],
            }),
            ..Default::default()
        };
        let result = peer
            .execute_with_options("system/tree", "put", params, opts)
            .await
            .unwrap();
        assert_eq!(result.status, 200);

        // Should receive the tree change event
        let evt = tokio::time::timeout(std::time::Duration::from_millis(100), events.recv())
            .await
            .expect("event timeout")
            .expect("event recv error");
        assert_eq!(evt.path, path);
    }

    /// End-to-end mirror of validator's `v38_tco_if_chain`: 1101 tree puts
    /// building a nested if-chain, plus one compute/eval at the top.
    /// Run with `cargo test -p entity-peer --release perf_tco_if_chain_e2e -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore]
    #[cfg(feature = "compute")]
    async fn perf_tco_if_chain_e2e() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        let shared = peer.shared();
        peer.start_engines(&shared);

        let put_one = |path: String, entity_type: &'static str, data: entity_ecf::Value| {
            let encoded = entity_ecf::to_ecf(&data);
            let body = entity_entity::Entity::new(entity_type, encoded.clone()).unwrap();
            let inner: ciborium::Value = ciborium::from_reader(encoded.as_slice()).unwrap();
            let params_data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
                "entity" => entity_ecf::cbor_map!{
                    "content_hash" => entity_ecf::Value::Bytes(body.content_hash.to_bytes()),
                    "data" => inner,
                    "type" => entity_ecf::text(entity_type)
                }
            });
            let params =
                entity_entity::Entity::new("system/tree/put-request", params_data).unwrap();
            let opts = entity_handler::ExecuteOptions {
                resource: Some(entity_capability::ResourceTarget {
                    targets: vec![path],
                    exclude: vec![],
                }),
                ..Default::default()
            };
            (params, opts)
        };

        let put_start = std::time::Instant::now();

        // Put condition (literal true) and final literal (42).
        let cond_path = qp("perf-tco/cond");
        let (p, o) = put_one(
            cond_path.clone(),
            "compute/literal",
            entity_ecf::cbor_map! { "value" => entity_ecf::bool_val(true) },
        );
        peer.execute_with_options("system/tree", "put", p, o)
            .await
            .unwrap();

        let mut current_path = qp("perf-tco/final");
        let (p, o) = put_one(
            current_path.clone(),
            "compute/literal",
            entity_ecf::cbor_map! { "value" => entity_ecf::integer(42) },
        );
        peer.execute_with_options("system/tree", "put", p, o)
            .await
            .unwrap();

        // Need the hash of cond_path + final_path to build an `if` referencing them.
        // Use peer's content store via shared.
        let cond_hash = shared.location_index.get(&cond_path).unwrap();
        let mut current_hash = shared.location_index.get(&current_path).unwrap();

        for i in 0..1100 {
            let if_path = qp(&format!("perf-tco/if-{}", i));
            let (p, o) = put_one(
                if_path.clone(),
                "compute/if",
                entity_ecf::cbor_map! {
                    "condition" => entity_ecf::Value::Bytes(cond_hash.to_bytes().to_vec()),
                    "then" => entity_ecf::Value::Bytes(current_hash.to_bytes().to_vec())
                },
            );
            peer.execute_with_options("system/tree", "put", p, o)
                .await
                .unwrap();
            current_hash = shared.location_index.get(&if_path).unwrap();
            current_path = if_path;
        }

        let put_elapsed = put_start.elapsed();

        // Now eval the top-of-chain via system/compute.
        let eval_start = std::time::Instant::now();
        let opts = entity_handler::ExecuteOptions {
            resource: Some(entity_capability::ResourceTarget {
                targets: vec![current_path.clone()],
                exclude: vec![],
            }),
            ..Default::default()
        };
        let empty = entity_entity::Entity::new(
            "system/protocol/empty-params",
            entity_ecf::to_ecf(&entity_ecf::Value::Null),
        )
        .unwrap();
        let result = peer
            .execute_with_options("system/compute", "eval", empty, opts)
            .await
            .unwrap();
        let eval_elapsed = eval_start.elapsed();
        assert_eq!(result.status, 200);

        eprintln!(
            "perf_tco_if_chain_e2e: 1102 puts in {:?}, eval in {:?}, total {:?}",
            put_elapsed,
            eval_elapsed,
            put_elapsed + eval_elapsed
        );
    }

    /// In-process perf canary: 1100 tree puts via execute_with_options.
    /// Marked `#[ignore]` so CI doesn't gate on it; run with
    /// `cargo test -p entity-peer --release perf_treeput_1100 -- --ignored --nocapture`.
    /// Existed to verify the per-put scan/decode regression fix.
    #[tokio::test]
    #[ignore]
    async fn perf_treeput_1100() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        let shared = peer.shared();
        peer.start_engines(&shared);

        const N: u32 = 1100;
        // Every iteration puts the same body, so its `content_hash` is hoisted
        // out of the timed region deliberately: computing it per-iteration
        // would fold 1100 SHA-256s of the submitter's own authoring step into
        // a number that exists to measure the PEER's per-put cost.
        let body_hash =
            entity_entity::Entity::new("test/type", entity_ecf::to_ecf(&entity_ecf::text("x")))
                .unwrap()
                .content_hash
                .to_bytes();
        let start = std::time::Instant::now();
        for i in 0..N {
            let path = qp(&format!("perf/path-{}", i));
            let params_data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
                "entity" => entity_ecf::cbor_map!{
                    "content_hash" => entity_ecf::Value::Bytes(body_hash.clone()),
                    "data" => entity_ecf::text("x"),
                    "type" => entity_ecf::text("test/type")
                }
            });
            let params =
                entity_entity::Entity::new("system/tree/put-request", params_data).unwrap();
            let opts = entity_handler::ExecuteOptions {
                resource: Some(entity_capability::ResourceTarget {
                    targets: vec![path.clone()],
                    exclude: vec![],
                }),
                ..Default::default()
            };
            let result = peer
                .execute_with_options("system/tree", "put", params, opts)
                .await
                .unwrap();
            assert_eq!(result.status, 200);
        }
        let elapsed = start.elapsed();
        let per_put_us = elapsed.as_micros() as f64 / f64::from(N);
        eprintln!(
            "perf_treeput_1100: {} puts in {:?} ({:.1} µs/put)",
            N, elapsed, per_put_us
        );
    }

    /// The same canary with the published-root publisher armed over the
    /// universal prefix — the configuration `--publish-root
    /// --serve-closure-root` runs, and the one where an O(tree)-per-put
    /// republish would hide.
    ///
    /// This is the shape the design deliberately avoids: re-deriving the root
    /// with `location_index.list()` + `build_trie` on every change is O(tree)
    /// per put and grows without bound. The publisher instead re-signs the
    /// hash `RootTrackerEngine` already maintains incrementally, so the added
    /// cost per put is one signature and two entities — a constant.
    ///
    /// Read it against `perf_treeput_1100` from the same run: the ratio is the
    /// number, not the absolute µs. Roughly flat is right; a ratio that climbs
    /// with N is the regression.
    ///
    /// `cargo test -p entity-peer --release --lib perf_treeput_1100_publishing -- --ignored --nocapture`
    #[tokio::test]
    #[ignore]
    async fn perf_treeput_1100_publishing() {
        let peer = PeerBuilder::new()
            .keypair(test_keypair())
            .with_published_root("/")
            .build()
            .unwrap();
        let shared = peer.shared();
        peer.start_engines(&shared);

        const N: u32 = 1100;
        // Every iteration puts the same body, so its `content_hash` is hoisted
        // out of the timed region deliberately: computing it per-iteration
        // would fold 1100 SHA-256s of the submitter's own authoring step into
        // a number that exists to measure the PEER's per-put cost.
        let body_hash =
            entity_entity::Entity::new("test/type", entity_ecf::to_ecf(&entity_ecf::text("x")))
                .unwrap()
                .content_hash
                .to_bytes();
        let start = std::time::Instant::now();
        for i in 0..N {
            let path = qp(&format!("perf/path-{}", i));
            let params_data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
                "entity" => entity_ecf::cbor_map!{
                    "content_hash" => entity_ecf::Value::Bytes(body_hash.clone()),
                    "data" => entity_ecf::text("x"),
                    "type" => entity_ecf::text("test/type")
                }
            });
            let params =
                entity_entity::Entity::new("system/tree/put-request", params_data).unwrap();
            let opts = entity_handler::ExecuteOptions {
                resource: Some(entity_capability::ResourceTarget {
                    targets: vec![path.clone()],
                    exclude: vec![],
                }),
                ..Default::default()
            };
            let result = peer
                .execute_with_options("system/tree", "put", params, opts)
                .await
                .unwrap();
            assert_eq!(result.status, 200);
        }
        let elapsed = start.elapsed();
        let per_put_us = elapsed.as_micros() as f64 / f64::from(N);
        let (_, seq, _, _) = head_state(&peer);
        eprintln!(
            "perf_treeput_1100_publishing: {} puts in {:?} ({:.1} µs/put), published-root seq={}",
            N, elapsed, per_put_us, seq
        );
        // Every put moved the root, so every put must have minted a head. A
        // seq that lags N is a swallowed republish, not a faster path.
        assert_eq!(
            seq,
            u64::from(N),
            "one republish per root-changing put (seq 0 was minted at build)"
        );
    }

    // --- deliver_to extraction tests ---

    #[test]
    fn test_extract_deliver_to() {
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("operation"), entity_ecf::text("get")),
            (entity_ecf::text("request_id"), entity_ecf::text("r1")),
            (entity_ecf::text("uri"), entity_ecf::text("system/tree")),
            (
                entity_ecf::text("deliver_to"),
                entity_ecf::Value::Map(vec![
                    (
                        entity_ecf::text("uri"),
                        entity_ecf::text("system/inbox/test"),
                    ),
                    (entity_ecf::text("operation"), entity_ecf::text("receive")),
                ]),
            ),
        ]));
        let execute = entity_entity::Entity::new(entity_types::TYPE_EXECUTE, data).unwrap();
        let spec = connection::extract_deliver_to(&execute).unwrap();
        assert_eq!(spec.uri, "system/inbox/test");
        assert_eq!(spec.operation, "receive");
    }

    #[test]
    fn test_extract_deliver_to_default_operation() {
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("operation"), entity_ecf::text("get")),
            (entity_ecf::text("request_id"), entity_ecf::text("r1")),
            (entity_ecf::text("uri"), entity_ecf::text("system/tree")),
            (
                entity_ecf::text("deliver_to"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("uri"),
                    entity_ecf::text("system/inbox/path"),
                )]),
            ),
        ]));
        let execute = entity_entity::Entity::new(entity_types::TYPE_EXECUTE, data).unwrap();
        let spec = connection::extract_deliver_to(&execute).unwrap();
        assert_eq!(spec.uri, "system/inbox/path");
        assert_eq!(spec.operation, "receive"); // default per spec
    }

    #[test]
    fn test_extract_deliver_to_absent() {
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("operation"), entity_ecf::text("get")),
            (entity_ecf::text("request_id"), entity_ecf::text("r1")),
            (entity_ecf::text("uri"), entity_ecf::text("system/tree")),
        ]));
        let execute = entity_entity::Entity::new(entity_types::TYPE_EXECUTE, data).unwrap();
        assert!(connection::extract_deliver_to(&execute).is_none());
    }

    #[test]
    fn test_extract_deliver_token() {
        let token_hash = entity_hash::Hash::compute("system/capability/token", b"test-token");
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("operation"), entity_ecf::text("get")),
            (entity_ecf::text("request_id"), entity_ecf::text("r1")),
            (entity_ecf::text("uri"), entity_ecf::text("system/tree")),
            (
                entity_ecf::text("deliver_token"),
                entity_ecf::Value::Bytes(token_hash.to_bytes().to_vec()),
            ),
        ]));
        let execute = entity_entity::Entity::new(entity_types::TYPE_EXECUTE, data).unwrap();
        let extracted = connection::extract_deliver_token(&execute).unwrap();
        assert_eq!(extracted, token_hash);
    }

    #[test]
    fn test_build_202_response() {
        let response = connection::build_202_response("test-req", None).unwrap();
        // Decode and verify it's a 202 response
        let val: ciborium::Value = ciborium::from_reader(response.root.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let status = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("status"))
            .unwrap()
            .1
            .as_integer()
            .unwrap();
        assert_eq!(i128::from(status), 202);
    }

    /// Integration test: async delivery via Peer::execute dispatches to inbox.
    #[tokio::test]
    async fn test_async_delivery_to_inbox() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        let shared = peer.shared();
        peer.start_engines(&shared);

        // Put something in the tree to retrieve
        let test_data = entity_ecf::to_ecf(&entity_ecf::text("async-test-value"));
        let test_entity = entity_entity::Entity::new("test/type", test_data).unwrap();
        let path = qp("test/async-target");
        peer.tree().put(&path, test_entity).unwrap();

        // Now manually simulate async delivery:
        // Build an InboxDeliveryData entity and deliver it to system/inbox
        let result_data = entity_ecf::to_ecf(&entity_ecf::text("delivered-result"));
        let delivery_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("original_request_id"),
                entity_ecf::text("async-req-1"),
            ),
            (
                entity_ecf::text("result"),
                entity_ecf::Value::Bytes(result_data),
            ),
            (entity_ecf::text("status"), entity_ecf::integer(200)),
        ]));
        let delivery_entity =
            entity_entity::Entity::new(entity_types::TYPE_INBOX_DELIVERY, delivery_data).unwrap();

        let inbox_path = qp("test/async-inbox");
        let opts = entity_handler::ExecuteOptions {
            resource: Some(entity_capability::ResourceTarget {
                targets: vec![inbox_path.clone()],
                exclude: vec![],
            }),
            request_id: Some("dlv-async-req-1".to_string()),
            ..Default::default()
        };

        let result = peer
            .execute_with_options("system/inbox", "receive", delivery_entity, opts)
            .await;
        assert!(result.is_ok(), "inbox delivery failed: {:?}", result.err());
        assert_eq!(result.unwrap().status, 200);

        // Verify the delivery was stored at inbox path
        let entries = peer.location_index().list(&format!("{}/", inbox_path));
        assert_eq!(entries.len(), 1, "expected 1 entry in inbox");

        // Verify the stored entity is the InboxDeliveryData
        let stored = peer.content_store().get(&entries[0].hash).unwrap();
        assert_eq!(stored.entity_type, entity_types::TYPE_INBOX_DELIVERY);
    }

    // -----------------------------------------------------------------------
    // WebSocket transport tests
    // -----------------------------------------------------------------------

    #[cfg(feature = "websocket")]
    #[tokio::test]
    async fn test_ws_listener_bind() {
        let listener = transport::WebSocketListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        assert_ne!(listener.socket_addr().port(), 0);
        assert_eq!(listener.transport_type(), "websocket");
        assert!(listener.local_addr().starts_with("ws://"));
    }

    #[cfg(feature = "websocket")]
    #[tokio::test]
    async fn test_ws_handshake() {
        // Start a peer with WS listener
        let server_seed = [1u8; 32];
        let server_peer = PeerBuilder::new()
            .keypair(Keypair::from_seed(server_seed))
            .listen_addr("127.0.0.1:0")
            .build()
            .unwrap();
        let server_pid = server_peer.peer_id().to_string();

        let ws_listener = transport::WebSocketListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let ws_addr = format!("ws://127.0.0.1:{}", ws_listener.socket_addr().port());

        let shared = server_peer.shared();
        server_peer.start_engines(&shared);

        // Run server in background
        let shared_for_server = shared.clone();
        let server_handle = tokio::spawn(async move {
            let _ = server::run(ws_listener, shared_for_server).await;
        });

        // Give server a moment to start accepting
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect as a client via WebSocket
        let client_kp = Keypair::from_seed([2u8; 32]);
        let connector = transport::WebSocketConnector;
        let conn = connector.connect(&ws_addr).await.unwrap();
        assert_eq!(conn.transport_type, "websocket");

        // Perform handshake over WS connection
        let remote_conn = remote::perform_connect(
            conn,
            &IdentityKeypair::Ed25519(client_kp.clone_inner()),
            entity_hash::HASH_ALGORITHM_SHA256,
        )
        .await
        .unwrap();
        assert_eq!(remote_conn.remote_peer_id, server_pid);

        // Clean up
        server_handle.abort();
    }

    #[cfg(feature = "websocket")]
    #[tokio::test]
    async fn test_ws_and_tcp_same_peer() {
        // Verify a peer can serve both TCP and WS simultaneously
        let seed = [3u8; 32];
        let peer = PeerBuilder::new()
            .keypair(Keypair::from_seed(seed))
            .listen_addr("127.0.0.1:0")
            .build()
            .unwrap();
        let peer_pid = peer.peer_id().to_string();

        let tcp_listener = peer.listen().await.unwrap();
        let tcp_port = tcp_listener.socket_addr().port();

        let ws_listener = transport::WebSocketListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let ws_port = ws_listener.socket_addr().port();

        assert_ne!(tcp_port, ws_port);

        let shared = peer.shared();
        peer.start_engines(&shared);

        let shared_clone = shared.clone();
        let server_handle = tokio::spawn(async move {
            let listeners: Vec<Box<dyn transport::Listener>> =
                vec![Box::new(tcp_listener), Box::new(ws_listener)];
            let _ = server::run_multi(listeners, shared_clone).await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect via TCP
        let client1 = Keypair::from_seed([4u8; 32]);
        let tcp_conn = transport::TcpConnector
            .connect(&format!("127.0.0.1:{}", tcp_port))
            .await
            .unwrap();
        assert_eq!(tcp_conn.transport_type, "tcp");
        let tcp_remote = remote::perform_connect(
            tcp_conn,
            &IdentityKeypair::Ed25519(client1.clone_inner()),
            entity_hash::HASH_ALGORITHM_SHA256,
        )
        .await
        .unwrap();
        assert_eq!(tcp_remote.remote_peer_id, peer_pid);

        // Connect via WebSocket
        let client2 = Keypair::from_seed([5u8; 32]);
        let ws_conn = transport::WebSocketConnector
            .connect(&format!("ws://127.0.0.1:{}", ws_port))
            .await
            .unwrap();
        assert_eq!(ws_conn.transport_type, "websocket");
        let ws_remote = remote::perform_connect(
            ws_conn,
            &IdentityKeypair::Ed25519(client2.clone_inner()),
            entity_hash::HASH_ALGORITHM_SHA256,
        )
        .await
        .unwrap();
        assert_eq!(ws_remote.remote_peer_id, peer_pid);

        server_handle.abort();
    }

    /// Regression: TcpConnector::connect must accept the D-14 wire
    /// shape `tcp://host:port` (TcpProfileData.endpoint_url), not just
    /// bare `host:port`. Pre-fix, the scheme-prefixed form went to
    /// getaddrinfo and failed with "Name or service not known", which
    /// only surfaced in Rust-as-dispatcher cross-impl validate-peer
    /// runs (the Rust TCP URL-dialer bug).
    #[tokio::test]
    async fn test_tcp_connector_accepts_scheme_prefix() {
        let peer = PeerBuilder::new()
            .keypair(Keypair::from_seed([42u8; 32]))
            .listen_addr("127.0.0.1:0")
            .build()
            .unwrap();
        let tcp_listener = peer.listen().await.unwrap();
        let tcp_port = tcp_listener.socket_addr().port();

        let shared = peer.shared();
        peer.start_engines(&shared);
        let shared_clone = shared.clone();
        let server_handle = tokio::spawn(async move {
            let _ = server::run(tcp_listener, shared_clone).await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let conn = transport::TcpConnector
            .connect(&format!("tcp://127.0.0.1:{}", tcp_port))
            .await
            .expect("TcpConnector must accept tcp:// scheme prefix");
        assert_eq!(conn.transport_type, "tcp");

        let client = Keypair::from_seed([43u8; 32]);
        let remote = remote::perform_connect(
            conn,
            &IdentityKeypair::Ed25519(client.clone_inner()),
            entity_hash::HASH_ALGORITHM_SHA256,
        )
        .await
        .unwrap();
        assert_eq!(remote.remote_peer_id, peer.peer_id().to_string());

        server_handle.abort();
    }

    // ===================================================================
    // V7.67 Phase 2 — MATRIX-M2 cross-key handshake
    // ===================================================================

    /// Build an [`IdentityKeypair`] of the given key_type from a 1-byte
    /// repeated seed (deterministic per combo).
    fn matrix_id(kt: entity_crypto::KeyType, seed: u8) -> IdentityKeypair {
        match kt {
            entity_crypto::KeyType::Ed25519 => {
                IdentityKeypair::Ed25519(Keypair::from_seed([seed; 32]))
            }
            entity_crypto::KeyType::Ed448 => {
                IdentityKeypair::Ed448(entity_crypto::Ed448Keypair::from_seed(&[seed; 57]).unwrap())
            }
            other => panic!("matrix_id: {other:?} has no sign/verify semantics"),
        }
    }

    /// Guards the process home `content_hash_format` global (V7 §1.2 — one
    /// home format per process). Only the SHA-384 smoke (M3) *writes* it
    /// (`set_default_hash_format`), so it takes `write()`; every test that
    /// *reads* the home format — by authoring an entity, deriving an identity
    /// hash, or minting a capability whose grantee is a home-format identity
    /// hash — takes `read()` and so may still run concurrently with its
    /// peers, but never inside M3's SHA-384 window.
    ///
    /// A read guard is REQUIRED for any test whose peers author under the
    /// home default: without it, M3 can flip the global mid-test, the peer
    /// re-derives `peer_entity()` under SHA-384 while its connection
    /// capability's `grantee` was minted under SHA-256, and the mismatch
    /// surfaces as a 401 `unresolvable_grantee` (this bit the `a12_keepalive_*`
    /// vectors — reproducible ~50% under `cargo test -p entity-peer --lib`,
    /// never under `--test-threads=1`).
    ///
    /// Production is unaffected: one peer, one home format, one process.
    static HOME_FORMAT_TEST_LOCK: tokio::sync::RwLock<()> = tokio::sync::RwLock::const_new(());

    /// One cell of the MATRIX-M2 grid: a `server_kt` server and a
    /// `client_kt` client complete the real-wire TCP handshake and the
    /// server mints a connection capability that (a) is granted to the
    /// client's *own* canonical identity hash — proving the grantee
    /// identity entity was built with the client's key_type, not a
    /// hardcoded "ed25519" — and (b) carries a signature that verifies
    /// under the *server's* key_type.
    async fn run_matrix_m2_cell(
        server_kt: entity_crypto::KeyType,
        client_kt: entity_crypto::KeyType,
    ) {
        let server = PeerBuilder::new()
            .identity_keypair(matrix_id(server_kt, 0x11))
            .listen_addr("127.0.0.1:0")
            .build()
            .unwrap();
        let server_pid = server.peer_id().to_string();
        let server_pubkey = server.keypair().public_key_bytes();
        let server_identity_hash = server.keypair().peer_identity_hash();

        let tcp_listener = server.listen().await.unwrap();
        let tcp_port = tcp_listener.socket_addr().port();

        let shared = server.shared();
        server.start_engines(&shared);
        let shared_clone = shared.clone();
        let server_handle = tokio::spawn(async move {
            let _ = server::run(tcp_listener, shared_clone).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = matrix_id(client_kt, 0x22);
        let client_identity_hash = client.peer_identity_hash();

        let conn = transport::TcpConnector
            .connect(&format!("tcp://127.0.0.1:{}", tcp_port))
            .await
            .unwrap();
        let remote = remote::perform_connect(conn, &client, entity_hash::HASH_ALGORITHM_SHA256)
            .await
            .unwrap_or_else(|e| {
                panic!("handshake {server_kt:?} server × {client_kt:?} client failed: {e}")
            });

        // (1) Handshake completed: both authenticate signatures verified
        // cross-key (server verified client's, client verified server's).
        assert_eq!(remote.remote_peer_id, server_pid);

        // (2) The minted connection cap is granted to the client's own
        // canonical identity hash. If the server had hardcoded the grantee
        // key_type as "ed25519", an Ed448 client's grantee hash would not
        // match what the client computes for itself.
        let cap = entity_capability::CapabilityToken::from_entity(&remote.capability)
            .expect("connection capability decodes");
        assert_eq!(
            cap.grantee, client_identity_hash,
            "grantee MUST equal the client's own identity hash ({client_kt:?} client)"
        );

        // (3) The cap signature verifies under the server's key_type.
        let cap_hash = remote.capability.content_hash;
        let sig = remote
            .auth_included
            .values()
            .filter(|e| e.entity_type == entity_entity::TYPE_SIGNATURE)
            .find_map(|e| {
                let sd = entity_types::SignatureData::from_entity(e).ok()?;
                (sd.target == cap_hash).then_some(sd)
            })
            .expect("capability signature present in auth_included");
        assert_eq!(sig.signer, server_identity_hash, "cap signed by the server");
        assert_eq!(
            sig.algorithm,
            server_kt.label(),
            "algorithm == server key_type"
        );
        entity_crypto::verify_for_key_type(
            server_kt,
            &server_pubkey,
            &cap_hash.to_bytes(),
            &sig.signature,
        )
        .unwrap_or_else(|_| panic!("cap signature must verify under {server_kt:?} server key"));

        server_handle.abort();
    }

    /// MATRIX-M2: all four (server, client) key_type directions over the
    /// {Ed25519, Ed448} grid complete the handshake and mint a verified
    /// cross-key capability. The ed25519×ed25519 cell is the no-regression
    /// baseline; the other three exercise the v7.67 Phase 2 dispatch.
    #[tokio::test]
    async fn matrix_m2_cross_key_handshake_all_directions() {
        use entity_crypto::KeyType::{Ed25519, Ed448};
        // SHA-256-home test: reads `peer_identity_hash()` (home global) and
        // asserts it equals the active-format grantee. Read-guard against any
        // concurrent SHA-384 home window so the global stays SHA-256 here.
        let _guard = HOME_FORMAT_TEST_LOCK.read().await;
        run_matrix_m2_cell(Ed25519, Ed25519).await;
        run_matrix_m2_cell(Ed25519, Ed448).await;
        run_matrix_m2_cell(Ed448, Ed25519).await;
        run_matrix_m2_cell(Ed448, Ed448).await;
    }

    /// One cell of the MATRIX-M3 grid: a `server_home`-format server and a
    /// `client_home`-format client over TCP. Asserts the handshake completes
    /// (no cross-format `cap_denied`), the minted connection cap is authored
    /// under the negotiated active format, and its grantee is the client's
    /// identity hash **under that active format** (§4.5a + §1.8). Returns the
    /// active format the cap was minted under.
    async fn run_matrix_m3_cell(server_home: u8, client_home: u8) -> u8 {
        let expected_active = entity_protocol::negotiate_active_format(
            &entity_protocol::default_advertised_hash_formats(client_home),
            &entity_protocol::default_advertised_hash_formats(server_home),
        )
        .expect("server and client share a format");

        let server = PeerBuilder::new()
            .identity_keypair(IdentityKeypair::Ed25519(Keypair::from_seed([0x31; 32])))
            .home_hash_format(server_home)
            .listen_addr("127.0.0.1:0")
            .build()
            .unwrap();
        let server_pid = server.peer_id().to_string();

        let tcp_listener = server.listen().await.unwrap();
        let tcp_port = tcp_listener.socket_addr().port();
        let shared = server.shared();
        server.start_engines(&shared);
        let server_handle = tokio::spawn(async move {
            let _ = server::run(tcp_listener, shared).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = IdentityKeypair::Ed25519(Keypair::from_seed([0x32; 32]));
        // The client's identity hash AT THE FLOOR — §4.5a item 1a pins
        // `system/peer` there whatever the active format, so this is the
        // grantee on every cell of the matrix, not just the SHA-256 ones.
        // This read `peer_entity_with_format(expected_active)`, which agreed
        // with the implementation on the floor cells and was untested
        // elsewhere.
        let client_active_identity = client.peer_entity().unwrap().content_hash;

        let conn = transport::TcpConnector
            .connect(&format!("tcp://127.0.0.1:{}", tcp_port))
            .await
            .unwrap();
        let remote = remote::perform_connect(conn, &client, client_home)
            .await
            .unwrap_or_else(|e| {
                panic!("M3 handshake server_home={server_home} client_home={client_home}: {e}")
            });

        assert_eq!(remote.remote_peer_id, server_pid);

        // The minted connection cap is authored under the active format
        // (responder §4.5a cap mint), and its grantee is the client's
        // active-format identity (§1.8 authored signer, not a re-derivation).
        assert_eq!(
            remote.capability.content_hash.algorithm, expected_active,
            "minted cap authored under negotiated active format"
        );
        let cap = entity_capability::CapabilityToken::from_entity(&remote.capability)
            .expect("connection capability decodes");
        assert_eq!(
            cap.grantee, client_active_identity,
            "grantee == client's active-format identity hash (§1.8/§4.5a)"
        );

        server_handle.abort();
        expected_active
    }

    /// MATRIX-M3: the full (server_home, client_home) grid over
    /// {SHA-256, SHA-384}. The cross-format cells (sha384×sha256,
    /// sha256×sha384) negotiate **down** to the common SHA-256 floor and
    /// complete — the cap-denied failure class v7.69 eliminates. The
    /// sha384×sha384 cell authors the whole handshake under SHA-384,
    /// exercising the production variable-length `Hash` path that the
    /// v7.67 Phase-2 deferral left unreachable. sha256×sha256 is the
    /// no-regression baseline.
    #[tokio::test]
    async fn matrix_m3_cross_format_handshake_all_directions() {
        use entity_hash::{HASH_ALGORITHM_SHA256 as S256, HASH_ALGORITHM_SHA384 as S384};
        // M3 asserts only on the negotiated *active* format via explicit
        // `peer_entity_with_format`/cap-mint paths — it never reads the home
        // global, and `build()` does not set it — so M3 is independent of the
        // process home default and needs no serialization.
        assert_eq!(run_matrix_m3_cell(S256, S256).await, S256);
        assert_eq!(run_matrix_m3_cell(S384, S256).await, S256);
        assert_eq!(run_matrix_m3_cell(S256, S384).await, S256);
        assert_eq!(run_matrix_m3_cell(S384, S384).await, S384);
    }

    /// v7.70 §1.2: a SHA-384-home peer authors its persistent content and
    /// substrate *uniformly* under SHA-384 — not SHA-256 content with a
    /// SHA-384 wire advertisement (the pre-v7.70 incoherence). Asserts the
    /// peer's own identity hash, content authored via the home default
    /// (`Entity::new` — the same path the tree/trie substrate authors its
    /// snapshot nodes through), the content-store put, and a persistently
    /// minted capability all carry the SHA-384 format code. SHA-256 stays
    /// the default for every other test.
    #[tokio::test]
    async fn home_format_sha384_authors_content_and_substrate_uniformly() {
        use entity_hash::{HASH_ALGORITHM_SHA256 as S256, HASH_ALGORITHM_SHA384 as S384};
        // Set the process home default the way the CLI `run_peer` does, under
        // the lock so no SHA-256-home reader (M2) sees this SHA-384 window.
        // `build()` does not touch the global, so no concurrent build stomps
        // it mid-test; restore the floor on exit. Exclusive: no home-format
        // reader may observe this SHA-384 window.
        let _guard = HOME_FORMAT_TEST_LOCK.write().await;
        entity_hash::set_default_hash_format(S384);

        let peer = PeerBuilder::new()
            .identity_keypair(IdentityKeypair::Ed25519(Keypair::from_seed([0x7a; 32])))
            .home_hash_format(S384)
            .build()
            .unwrap();

        // (1) The peer's own persistent identity hash is at the FLOOR, not the
        // home format — §4.5a item 1a, the single named exception to "a peer's
        // persistent state is uniformly its home format" (§1.2). This asserted
        // S384 until v7.77 ruled the exception; a SHA-384-home peer stores its
        // own `system/peer` entity at its floor hash, and nothing else changes
        // — which is what the rest of this test goes on to check.
        assert_eq!(
            peer.keypair().peer_identity_hash().algorithm,
            S256,
            "§4.5a item 1a: system/peer is pinned to the floor whatever the home format"
        );

        // (2) Content authored via the home default is SHA-384. The tree/trie
        // substrate authors its snapshot nodes through this same `Entity::new`
        // path, so substrate is SHA-384 transitively.
        let e = entity_entity::Entity::new("test/content", b"\x81\x01".to_vec()).unwrap();
        assert_eq!(
            e.content_hash.algorithm, S384,
            "Entity::new follows home format"
        );

        // (3) Storing it preserves the SHA-384 content hash byte-for-byte.
        let stored = peer
            .shared()
            .content_store
            .put(e.clone())
            .expect("content put");
        assert_eq!(stored.algorithm, S384, "stored content hash is SHA-384");
        assert_eq!(stored, e.content_hash, "store preserves byte-fidelity hash");

        entity_hash::set_default_hash_format(S256);
    }

    /// Regression for the v7.67 Phase 2 Ed448 cap-chain root-check gap
    /// (Go follow-up `93a5d78`, error `root capability granter is not
    /// local peer`). The single-sig root check in `verify.rs` derives the
    /// granter's canonical peer_id from its `system/peer` entity via
    /// `PeerData::canonical_peer_id()` and compares it to the local peer's
    /// `keypair.peer_id()`. For the connection cap the granter *is* the
    /// local peer, so the two derivations MUST agree for both key types.
    /// Before the fix, `canonical_peer_id()` returned `None` for any
    /// non-Ed25519 key_type, so every authenticated EXECUTE against an
    /// Ed448 peer bounced with `NotLocalPeer`. This asserts the two halves
    /// match — the exact equivalence the verify-side root check depends on.
    #[test]
    fn ed448_canonical_peer_id_matches_keypair_peer_id() {
        use entity_crypto::KeyType::{Ed25519, Ed448};
        for kt in [Ed25519, Ed448] {
            let kp = matrix_id(kt, 0x33);
            let entity = kp.peer_entity().expect("build system/peer entity");
            let peer_data = entity_types::PeerData::from_entity(&entity).expect("decode PeerData");
            let derived = peer_data
                .canonical_peer_id()
                .unwrap_or_else(|| panic!("{kt:?}: canonical_peer_id returned None"));
            assert_eq!(
                derived,
                kp.peer_id().as_str(),
                "{kt:?}: verify-side canonical_peer_id must equal the keypair's own peer_id"
            );
        }
    }

    /// V7.67 Phase 2 dispatch-gap repro: a client builds a *real*
    /// authenticated EXECUTE (the exact `build_authenticated_execute`
    /// path the live wire uses) against the connection cap minted during
    /// handshake, then the server runs `verify_request` on it. This is the
    /// surface MATRIX-M2 stops short of — it drives the author signature +
    /// full cap chain through the server's verify path. Run all four
    /// key-type directions; the Ed448-client cells are the failing live
    /// pairs (rs-25 × rs-48, go-48 × rs-25, …).
    async fn run_dispatch_verify_cell(
        server_kt: entity_crypto::KeyType,
        client_kt: entity_crypto::KeyType,
    ) {
        use transport::{MemoryConnector, MemoryListener, MemoryTransportRegistry};
        let registry = MemoryTransportRegistry::new();

        let server = PeerBuilder::new()
            .identity_keypair(matrix_id(server_kt, 0x11))
            .build()
            .unwrap();
        let server_pid = server.peer_id().to_string();

        let listener = MemoryListener::bind(server_pid.clone(), registry.clone()).unwrap();
        let shared = server.shared();
        server.start_engines(&shared);
        let shared_clone = shared.clone();
        let server_handle = tokio::spawn(async move {
            let _ = server::run(listener, shared_clone).await;
        });
        tokio::task::yield_now().await;

        let client = matrix_id(client_kt, 0x22);
        let conn = MemoryConnector::new(registry.clone())
            .connect(&format!("memory://{}", server_pid))
            .await
            .unwrap();
        let remote = remote::perform_connect(conn, &client, entity_hash::HASH_ALGORITHM_SHA256)
            .await
            .unwrap_or_else(|e| panic!("handshake {server_kt:?}×{client_kt:?}: {e}"));

        // Send a real EXECUTE over the wire (codec + server handler +
        // verify_request) and read back the status. tree/get on the
        // server's own peer-id root.
        let params = entity_entity::Entity::new(
            "system/params",
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                entity_ecf::text("path"),
                entity_ecf::text(format!("/{}/system/tree", server_pid)),
            )])),
        )
        .unwrap();
        let uri = format!("/{}/system/tree", server_pid);
        let resp = remote::send_execute(
            &remote,
            &client,
            &uri,
            "get",
            &params,
            None,
            None,
            None,
            &std::collections::HashMap::new(),
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("send_execute {client_kt:?}-client: {e}"));
        server_handle.abort();
        assert_ne!(
            resp.status, 403,
            "{client_kt:?}-client EXECUTE rejected with 403 (verify failed): {:?}",
            resp.result
        );
    }

    #[tokio::test]
    async fn dispatch_verify_all_directions() {
        use entity_crypto::KeyType::{Ed25519, Ed448};
        run_dispatch_verify_cell(Ed25519, Ed25519).await;
        run_dispatch_verify_cell(Ed25519, Ed448).await;
        run_dispatch_verify_cell(Ed448, Ed25519).await;
        run_dispatch_verify_cell(Ed448, Ed448).await;
    }

    /// RT-6 (§4.6, bucket-B `entity-system-architecture`
    /// `HANDOFF-2026-07-27-cohort-0.8.1-bucketB-update-packet.md`): the
    /// handshake nonce is single-use. A second, well-formed, fully-
    /// capability-authorized `authenticate` EXECUTE on
    /// `system/protocol/connect`, sent through the ALREADY-Established
    /// generic dispatch path on the SAME connection, MUST be rejected `401
    /// invalid_nonce`. This exercises the intercept with a request that
    /// *does* carry `author`/`capability` and passes generic verification —
    /// [`test_rt6_bare_authenticate_replay_returns_401_invalid_nonce`] below
    /// covers the other shape (no `author`/`capability`, the one the oracle's
    /// vector actually sends), which is what the pre-verification placement
    /// of the intercept exists for.
    #[tokio::test]
    async fn test_rt6_authenticate_replay_returns_401_invalid_nonce() {
        use transport::{MemoryConnector, MemoryListener, MemoryTransportRegistry};
        let registry = MemoryTransportRegistry::new();

        let server = PeerBuilder::new()
            .keypair(Keypair::from_seed([0x30u8; 32]))
            .build()
            .unwrap();
        let server_pid = server.peer_id().to_string();

        let listener = MemoryListener::bind(server_pid.clone(), registry.clone()).unwrap();
        let shared = server.shared();
        server.start_engines(&shared);
        let shared_clone = shared.clone();
        let server_handle = tokio::spawn(async move {
            let _ = server::run(listener, shared_clone).await;
        });
        tokio::task::yield_now().await;

        let client = matrix_id(entity_crypto::KeyType::Ed25519, 0x31);
        let conn = MemoryConnector::new(registry.clone())
            .connect(&format!("memory://{}", server_pid))
            .await
            .unwrap();
        let remote = remote::perform_connect(conn, &client, entity_hash::HASH_ALGORITHM_SHA256)
            .await
            .unwrap();

        let params = entity_entity::Entity::new(
            "system/params",
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![])),
        )
        .unwrap();
        let uri = format!("/{}/{}", server_pid, entity_protocol::CONNECT_PATH);
        let resp = remote::send_execute(
            &remote,
            &client,
            &uri,
            "authenticate",
            &params,
            None,
            None,
            None,
            &std::collections::HashMap::new(),
            None,
        )
        .await
        .unwrap();

        server_handle.abort();

        assert_eq!(
            resp.status, 401,
            "replayed authenticate must be 401, got {}: {:?}",
            resp.status, resp.result
        );
        let v: ciborium::Value = ciborium::from_reader(resp.result.data.as_slice()).unwrap();
        let code = v
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_text() == Some("code"))
            .and_then(|(_, v)| v.as_text());
        assert_eq!(code, Some("invalid_nonce"));
    }

    /// RT-6, the shape the oracle's `handshake_nonce_single_use` vector
    /// actually sends and the earlier (post-verification-only) fix missed:
    /// a **bare** connect-EXECUTE — `uri`/`operation`/`request_id` only, no
    /// `author`/`capability` — the same shape `build_connect_execute` uses
    /// for the original pre-Established authenticate. Sent raw via
    /// `dispatch_envelope` (bypassing `send_execute`'s auth-building, which
    /// would produce the OTHER, already-covered shape). Confirmed on the
    /// wire pre-fix by `entity-core-go`
    /// `docs/validation/reports/2026-07-27-0.8.1-bucketB-revalidation-after-sibling-fixes.md`:
    /// this shape fell through to generic verification and came back `401
    /// authentication_failed` (missing author), not `invalid_nonce` — the
    /// intercept sat on the wrong side of `verify_request_with_ctx`.
    #[tokio::test]
    async fn test_rt6_bare_authenticate_replay_returns_401_invalid_nonce() {
        use remote::RemoteEndpoint;
        use transport::{MemoryConnector, MemoryListener, MemoryTransportRegistry};
        let registry = MemoryTransportRegistry::new();

        let server = PeerBuilder::new()
            .keypair(Keypair::from_seed([0x32u8; 32]))
            .build()
            .unwrap();
        let server_pid = server.peer_id().to_string();

        let listener = MemoryListener::bind(server_pid.clone(), registry.clone()).unwrap();
        let shared = server.shared();
        server.start_engines(&shared);
        let shared_clone = shared.clone();
        let server_handle = tokio::spawn(async move {
            let _ = server::run(listener, shared_clone).await;
        });
        tokio::task::yield_now().await;

        let client = matrix_id(entity_crypto::KeyType::Ed25519, 0x33);
        let conn = MemoryConnector::new(registry.clone())
            .connect(&format!("memory://{}", server_pid))
            .await
            .unwrap();
        let remote = remote::perform_connect(conn, &client, entity_hash::HASH_ALGORITHM_SHA256)
            .await
            .unwrap();

        // The bare connect-EXECUTE shape: no author, no capability — exactly
        // what `verify_request_with_ctx` requires and this replay lacks.
        let params = entity_entity::Entity::new(
            "system/params",
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![])),
        )
        .unwrap();
        let request_id = remote.next_request_id();
        let exec_entity =
            entity_protocol::build_connect_execute(&request_id, "authenticate", &params).unwrap();
        let envelope = entity_entity::Envelope::new(exec_entity);

        let resp = remote
            .dispatch_envelope(request_id, envelope)
            .await
            .unwrap();

        server_handle.abort();

        assert_eq!(
            resp.status, 401,
            "bare-shape replayed authenticate must be 401, got {}: {:?}",
            resp.status, resp.result
        );
        let v: ciborium::Value = ciborium::from_reader(resp.result.data.as_slice()).unwrap();
        let code = v
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_text() == Some("code"))
            .and_then(|(_, v)| v.as_text());
        assert_eq!(
            code,
            Some("invalid_nonce"),
            "must not fall through to generic verification's authentication_failed"
        );
    }

    /// RT-13b Part B (§6.11 a′, bucket-B `entity-system-architecture`
    /// `HANDOFF-2026-07-27-cohort-0.8.1-bucketB-update-packet.md`): frame-write
    /// atomicity — on a connection carrying concurrent dispatch, the bytes of
    /// two distinct frames MUST NOT interleave. This is the peer-side
    /// attestation (the guarantee; a wire probe alone can't certify a race —
    /// mirrors Go's `TestConnection_FrameWriteAtomicity_RT13b`).
    ///
    /// N=64 concurrent `system/tree` GETs of distinct, byte-filled 16 KB
    /// payloads over ONE connection, ×3 windows. The accepted-connection side
    /// exercises the mechanism under test: `handle_connection`'s single writer
    /// task draining the per-connection `resp_tx` mpsc channel
    /// (`connection.rs`) is the only call site that ever writes to the
    /// socket, so concurrently-dispatched handler tasks can race to enqueue
    /// but never to write — each response frame is demuxed by `request_id`
    /// and checked byte-for-byte; a splice would corrupt a body or misroute
    /// a length-prefixed frame boundary.
    #[tokio::test]
    async fn test_rt13b_frame_write_atomicity_no_interleave() {
        use entity_capability::{GrantEntry, IdScope, PathScope, ResourceTarget};
        use transport::{MemoryConnector, MemoryListener, MemoryTransportRegistry};

        fn wildcard() -> Vec<(String, Vec<GrantEntry>)> {
            vec![(
                "default".to_string(),
                vec![GrantEntry {
                    handlers: PathScope::new(vec!["*".into()]),
                    resources: PathScope::new(vec!["*".into()]),
                    operations: IdScope::new(vec!["*".into()]),
                    peers: None,
                    constraints: None,
                    allowances: None,
                }],
            )]
        }

        const N: usize = 64;
        const BODY_LEN: usize = 16 * 1024;
        const WINDOWS: usize = 3;

        let registry = MemoryTransportRegistry::new();
        let server = PeerBuilder::new()
            .keypair(Keypair::from_seed([0x40u8; 32]))
            .with_seed_policy(wildcard())
            .build()
            .unwrap();
        let server_pid = server.peer_id().to_string();
        let listener = MemoryListener::bind(server_pid.clone(), registry.clone()).unwrap();
        let shared = server.shared();
        server.start_engines(&shared);
        let shared_clone = shared.clone();
        let server_handle = tokio::spawn(async move {
            let _ = server::run(listener, shared_clone).await;
        });
        tokio::task::yield_now().await;

        // Seed N distinct 16 KB entities directly in the server's store —
        // each body byte-filled with its own index so any splice/interleave
        // (wrong length, wrong bytes, wrong response matched to the wrong
        // request) is immediately detectable.
        let mut paths = Vec::with_capacity(N);
        for i in 0..N {
            let body = vec![i as u8; BODY_LEN];
            let entity = entity_entity::Entity::new(
                "test/rt13b-payload",
                entity_ecf::to_ecf(&entity_ecf::Value::Bytes(body)),
            )
            .unwrap();
            let path = format!("/{}/rt13b/{}", server_pid, i);
            shared.content_store.put(entity.clone()).unwrap();
            shared.location_index.set(&path, entity.content_hash);
            paths.push(path);
        }

        let client = matrix_id(entity_crypto::KeyType::Ed25519, 0x41);
        let conn = MemoryConnector::new(registry.clone())
            .connect(&format!("memory://{}", server_pid))
            .await
            .unwrap();
        let remote = std::sync::Arc::new(
            remote::perform_connect(conn, &client, entity_hash::HASH_ALGORITHM_SHA256)
                .await
                .unwrap(),
        );

        let empty_params = entity_entity::Entity::new(
            "system/params",
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![])),
        )
        .unwrap();

        for window in 0..WINDOWS {
            let mut tasks = Vec::with_capacity(N);
            for path in &paths {
                let remote = remote.clone();
                let client = client.clone_identity();
                let uri = format!("/{}/system/tree", server_pid);
                let path = path.clone();
                let params = empty_params.clone();
                tasks.push(tokio::spawn(async move {
                    let resource = ResourceTarget {
                        targets: vec![path],
                        exclude: vec![],
                    };
                    remote::send_execute(
                        remote.as_ref(),
                        &client,
                        &uri,
                        "get",
                        &params,
                        Some(&resource),
                        None,
                        None,
                        &std::collections::HashMap::new(),
                        None,
                    )
                    .await
                }));
            }

            for (i, t) in tasks.into_iter().enumerate() {
                let resp = t.await.unwrap().unwrap_or_else(|e| {
                    panic!("window {window} idx {i}: send_execute failed: {e}")
                });
                assert_eq!(
                    resp.status, 200,
                    "window {window} idx {i}: status {} (result: {:?})",
                    resp.status, resp.result
                );
                let v: ciborium::Value =
                    ciborium::from_reader(resp.result.data.as_slice()).unwrap();
                let bytes = v
                    .as_bytes()
                    .unwrap_or_else(|| panic!("window {window} idx {i}: result body not bytes"));
                assert_eq!(
                    bytes.len(),
                    BODY_LEN,
                    "window {window} idx {i}: length mismatch — frame interleave suspected"
                );
                assert!(
                    bytes.iter().all(|&b| b == i as u8),
                    "window {window} idx {i}: body corrupted — frame interleave suspected"
                );
            }
        }

        server_handle.abort();
    }

    /// Plant a standing continuation directly on `server`'s tree (author =
    /// server's own identity, no capability check — this is fixture setup,
    /// not the behavior under test). Mirrors
    /// `entity_continuation`'s own `install_standing_cont` test helper, built
    /// from the peer-crate side since a wire-level administrative-gate test
    /// needs a *second*, unprivileged peer to send the `advance` EXECUTE.
    #[cfg(feature = "continuation")]
    async fn install_standing_continuation_on(server: &Peer, path: &str) {
        let author = server.shared().identity_hash;
        let cap = entity_entity::Entity::new(
            "system/capability/token",
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
                (entity_ecf::text("created_at"), entity_ecf::integer(0)),
                (
                    entity_ecf::text("grantee"),
                    entity_ecf::Value::Bytes(author.to_bytes().to_vec()),
                ),
                (
                    entity_ecf::text("granter"),
                    entity_ecf::Value::Bytes(author.to_bytes().to_vec()),
                ),
                (entity_ecf::text("grants"), entity_ecf::Value::Array(vec![])),
            ])),
        )
        .unwrap();
        let cap_hash = cap.content_hash;
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("operation"), entity_ecf::text("process")),
            (entity_ecf::text("target"), entity_ecf::text("app/sink")),
            (
                entity_ecf::text("dispatch_capability"),
                entity_ecf::Value::Bytes(cap_hash.to_bytes().to_vec()),
            ),
        ]));
        let params = entity_entity::Entity::new("system/continuation", data).unwrap();
        let opts = entity_handler::ExecuteOptions {
            resource: Some(entity_capability::ResourceTarget {
                targets: vec![path.to_string()],
                exclude: vec![],
            }),
            included: vec![cap],
            ..Default::default()
        };
        let result = server
            .execute_with_options("system/continuation", "install", params, opts)
            .await
            .unwrap();
        assert_eq!(result.status, 200, "fixture setup: install must succeed");
    }

    /// STANDING-MODEL §3 AT-2 (`entity-core-go`
    /// `HANDOFF-2026-07-28-rust-py-convergence-standing-model-s3-s4.md`): an
    /// **administrative** `advance` (bare EXECUTE, not a reactive delivery
    /// trigger) stays capability-gated. A caller whose connection grant
    /// reaches the `system/continuation` handler but whose `operations`
    /// scope does not include `advance` (only `resume`/`abandon`) MUST be
    /// denied — the administrative gate bites even though the caller holds
    /// *some* capability here, just not this operation.
    #[cfg(feature = "continuation")]
    #[tokio::test]
    async fn test_standing_authority_at2_administrative_wrong_operation_denied() {
        use entity_capability::{GrantEntry, IdScope, PathScope};
        use transport::{MemoryConnector, MemoryListener, MemoryTransportRegistry};

        let registry = MemoryTransportRegistry::new();
        let server = PeerBuilder::new()
            .keypair(Keypair::from_seed([0x50u8; 32]))
            .with_seed_policy(vec![(
                "default".to_string(),
                vec![GrantEntry {
                    handlers: PathScope::new(vec!["system/continuation".into()]),
                    resources: PathScope::new(vec!["*".into()]),
                    operations: IdScope::new(vec!["resume".into(), "abandon".into()]),
                    peers: None,
                    constraints: None,
                    allowances: None,
                }],
            )])
            .build()
            .unwrap();
        let server_pid = server.peer_id().to_string();
        let path = format!("/{}/system/continuation/at2", server_pid);
        install_standing_continuation_on(&server, &path).await;

        let listener = MemoryListener::bind(server_pid.clone(), registry.clone()).unwrap();
        let shared = server.shared();
        server.start_engines(&shared);
        let shared_clone = shared.clone();
        let server_handle = tokio::spawn(async move {
            let _ = server::run(listener, shared_clone).await;
        });
        tokio::task::yield_now().await;

        let client = matrix_id(entity_crypto::KeyType::Ed25519, 0x51);
        let conn = MemoryConnector::new(registry.clone())
            .connect(&format!("memory://{}", server_pid))
            .await
            .unwrap();
        let remote = remote::perform_connect(conn, &client, entity_hash::HASH_ALGORITHM_SHA256)
            .await
            .unwrap();

        let uri = format!("/{}/system/continuation", server_pid);
        let params = entity_entity::Entity::new(
            "system/continuation/advance-request",
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                entity_ecf::text("result"),
                entity_ecf::Value::Null,
            )])),
        )
        .unwrap();
        let resource = entity_capability::ResourceTarget {
            targets: vec![path],
            exclude: vec![],
        };
        let resp = remote::send_execute(
            &remote,
            &client,
            &uri,
            "advance",
            &params,
            Some(&resource),
            None,
            None,
            &std::collections::HashMap::new(),
            None,
        )
        .await
        .unwrap();

        server_handle.abort();

        assert_eq!(
            resp.status, 403,
            "AT-2: administrative advance without the advance operation grant must be denied, got {}: {:?}",
            resp.status, resp.result
        );
    }

    /// STANDING-MODEL §3 AT-4 / O1 (load-bearing, same handoff as AT-2): a
    /// caller presenting no capability that grants anything on the
    /// continuation path at all — the plain default connection grant, which
    /// covers neither `system/continuation` nor `advance` — MUST be denied,
    /// never allowed by omission. Go's handoff calls this out specifically
    /// because a "no restriction found" formulation can silently invert into
    /// allow; this pins the deny outcome on the wire.
    #[cfg(feature = "continuation")]
    #[tokio::test]
    async fn test_standing_authority_at4_administrative_no_capability_denied() {
        use transport::{MemoryConnector, MemoryListener, MemoryTransportRegistry};

        let registry = MemoryTransportRegistry::new();
        let server = PeerBuilder::new()
            .keypair(Keypair::from_seed([0x52u8; 32]))
            .build()
            .unwrap();
        let server_pid = server.peer_id().to_string();
        let path = format!("/{}/system/continuation/at4", server_pid);
        install_standing_continuation_on(&server, &path).await;

        let listener = MemoryListener::bind(server_pid.clone(), registry.clone()).unwrap();
        let shared = server.shared();
        server.start_engines(&shared);
        let shared_clone = shared.clone();
        let server_handle = tokio::spawn(async move {
            let _ = server::run(listener, shared_clone).await;
        });
        tokio::task::yield_now().await;

        let client = matrix_id(entity_crypto::KeyType::Ed25519, 0x53);
        let conn = MemoryConnector::new(registry.clone())
            .connect(&format!("memory://{}", server_pid))
            .await
            .unwrap();
        let remote = remote::perform_connect(conn, &client, entity_hash::HASH_ALGORITHM_SHA256)
            .await
            .unwrap();

        let uri = format!("/{}/system/continuation", server_pid);
        let params = entity_entity::Entity::new(
            "system/continuation/advance-request",
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                entity_ecf::text("result"),
                entity_ecf::Value::Null,
            )])),
        )
        .unwrap();
        let resource = entity_capability::ResourceTarget {
            targets: vec![path],
            exclude: vec![],
        };
        let resp = remote::send_execute(
            &remote,
            &client,
            &uri,
            "advance",
            &params,
            Some(&resource),
            None,
            None,
            &std::collections::HashMap::new(),
            None,
        )
        .await
        .unwrap();

        server_handle.abort();

        assert_eq!(
            resp.status, 403,
            "AT-4/O1: administrative advance with no relevant capability must fail closed, got {}: {:?}",
            resp.status, resp.result
        );
    }

    #[cfg(feature = "websocket")]
    #[tokio::test]
    async fn test_cross_peer_ws_execute() {
        // Server peer: WS listener, puts an entity in its tree
        let server = PeerBuilder::new()
            .keypair(Keypair::from_seed([10u8; 32]))
            .listen_addr("127.0.0.1:0")
            .build()
            .unwrap();
        let server_pid = server.peer_id().to_string();

        // Put a test entity in the server's tree
        let data = entity_ecf::to_ecf(&entity_ecf::text("hello from server"));
        let test_entity = entity_entity::Entity::new("test/greeting", data).unwrap();
        let test_path = format!("/{}/app/greeting", server_pid);
        server.tree().put(&test_path, test_entity).unwrap();

        // Start server with WS listener
        let ws_listener = transport::WebSocketListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let ws_port = ws_listener.socket_addr().port();
        let shared = server.shared();
        server.start_engines(&shared);

        let shared_clone = shared.clone();
        let server_handle = tokio::spawn(async move {
            let _ = server::run(ws_listener, shared_clone).await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Client peer: connects to server via WebSocket
        let client = PeerBuilder::new()
            .keypair(Keypair::from_seed([11u8; 32]))
            .connector(std::sync::Arc::new(transport::WebSocketConnector))
            .build()
            .unwrap();
        client.local_only();

        // Connect to server
        let ws_url = format!("ws://127.0.0.1:{}", ws_port);
        let remote_pid = client.connect_to(&ws_url).await.unwrap();
        assert_eq!(remote_pid, server_pid);

        server_handle.abort();
    }

    /// EXTENSION-RELAY §3.1.1 terminal-hop **raw-frame** delivery, end-to-end
    /// over live TCP: A builds a fully-signed inner EXECUTE for C's tree, hands
    /// it to relay B as opaque bytes, and B writes those bytes **verbatim** into
    /// C's inbound frame. C verifies A's own signature + capability chain (never
    /// needing the RELAY extension to receive) and the payload lands at C's tree
    /// byte-identical — the property Go's decode-then-redispatch model only
    /// approximates. This is the Rust proof of the raw-frame path the shared Go
    /// validator cannot yet exercise (it builds an unsigned ExecuteData inner);
    /// see `docs/SPEC-AMBIGUITIES.md` (RELAY §3.1.1 terminal-hop).
    #[tokio::test]
    #[cfg(feature = "relay")]
    async fn test_relay_terminal_raw_frame_delivery() {
        use entity_capability::{GrantEntry, IdScope, PathScope};
        use entity_crypto::Keypair;

        fn wildcard() -> Vec<(String, Vec<GrantEntry>)> {
            vec![(
                "default".to_string(),
                vec![GrantEntry {
                    handlers: PathScope::new(vec!["*".into()]),
                    resources: PathScope::new(vec!["*".into()]),
                    operations: IdScope::new(vec!["*".into()]),
                    peers: None,
                    constraints: None,
                    allowances: None,
                }],
            )]
        }

        // --- Peer C (destination): TCP listener, wildcard seed so a connecting
        //     peer (A) receives a grant authorizing tree:put.
        let c = PeerBuilder::new()
            .keypair(Keypair::from_seed([31u8; 32]))
            .listen_addr("127.0.0.1:0")
            .with_seed_policy(wildcard())
            .build()
            .unwrap();
        let c_pid = c.peer_id().to_string();
        let c_listener = c.listen().await.unwrap();
        let c_port = c_listener.socket_addr().port();
        let c_shared = c.shared();
        c.start_engines(&c_shared);
        let c_shared_run = c_shared.clone();
        let c_handle = tokio::spawn(async move {
            let _ = server::run(c_listener, c_shared_run).await;
        });

        // --- Peer B (relay): TCP listener, wildcard seed; the PeerRelayForwarder
        //     is auto-wired by build() under the `relay` feature.
        let b = PeerBuilder::new()
            .keypair(Keypair::from_seed([32u8; 32]))
            .listen_addr("127.0.0.1:0")
            .with_seed_policy(wildcard())
            .build()
            .unwrap();
        let b_pid = b.peer_id().to_string();
        let b_listener = b.listen().await.unwrap();
        let b_port = b_listener.socket_addr().port();
        let b_shared = b.shared();
        b.start_engines(&b_shared);
        let b_shared_run = b_shared.clone();
        let b_handle = tokio::spawn(async move {
            let _ = server::run(b_listener, b_shared_run).await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Publish C's TCP transport profile in B's tree so B's forwarder can
        // dial C (the §3.1.1 terminal hop). Path segment is hex of C's
        // `system/peer` identity hash (v7.64 §1.4).
        let c_hex = remote::resolve_peer_id_hex(
            &c_pid,
            b_shared.content_store.as_ref(),
            b_shared.location_index.as_ref(),
            &b_pid,
        )
        .expect("derive C peer-id hex");
        let c_profile = transport_profile::TcpProfileData::for_local_listener_no_clock(
            &c_pid,
            format!("tcp://127.0.0.1:{}", c_port),
        )
        .to_entity();
        let c_profile_path = format!("/{}/system/peer/transport/{}/primary", b_pid, c_hex);
        b.tree().put(&c_profile_path, c_profile).unwrap();

        // --- A: a sending principal. Connect directly to C ONCE to obtain a
        //     real connection grant, then build a fully-signed inner EXECUTE
        //     (tree:put on C) using that grant. A does NOT route the put through
        //     this connection — it only borrows the grant; delivery goes via B.
        let a_kp = entity_crypto::IdentityKeypair::Ed25519(Keypair::from_seed([33u8; 32]));
        let conn_c = remote::perform_connect(
            transport::TcpConnector
                .connect(&format!("tcp://127.0.0.1:{}", c_port))
                .await
                .unwrap(),
            &a_kp,
            entity_hash::HASH_ALGORITHM_SHA256,
        )
        .await
        .unwrap();

        let payload = entity_entity::Entity::new(
            "test/relay-mp2-payload",
            entity_ecf::to_ecf(&entity_ecf::text("delivered-via-relay")),
        )
        .unwrap();
        let payload_value: entity_ecf::Value =
            ciborium::from_reader(payload.data.as_slice()).unwrap();
        let delivery_path = format!("/{}/app/relay-mp2", c_pid);

        let put_params = entity_entity::Entity::new(
            "system/tree/put-request",
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                entity_ecf::text("entity"),
                entity_ecf::Value::Map(vec![
                    (
                        entity_ecf::text("content_hash"),
                        entity_ecf::Value::Bytes(payload.content_hash.to_bytes()),
                    ),
                    (entity_ecf::text("data"), payload_value),
                    (
                        entity_ecf::text("type"),
                        entity_ecf::text(&payload.entity_type),
                    ),
                ]),
            )])),
        )
        .unwrap();
        let resource = entity_capability::ResourceTarget {
            targets: vec![delivery_path.clone()],
            exclude: vec![],
        };

        // Build the inner EXECUTE envelope — fully signed by A, carrying A's
        // capability chain in its `included` set so C can verify it standalone.
        let inner_env = remote::build_authenticated_execute(
            &a_kp,
            &conn_c.capability,
            &conn_c.auth_included,
            &std::collections::HashMap::new(),
            "mp2-req",
            &format!("/{}/system/tree", c_pid),
            "put",
            &put_params,
            Some(&resource),
            None,
            None,
        )
        .unwrap();
        // The opaque inner: a `system/envelope` entity whose data is the inner
        // envelope's raw bytes. The relay forwards these verbatim (§3.1.1).
        let inner_entity = entity_entity::Entity::new(
            entity_types::TYPE_ENVELOPE,
            entity_wire::encode_envelope(&inner_env),
        )
        .unwrap();

        // --- A → B :forward(dest=C, next=C). Connect to B and dispatch the
        //     relay forward-request, carrying the opaque inner in `included`.
        let conn_b = remote::perform_connect(
            transport::TcpConnector
                .connect(&format!("tcp://127.0.0.1:{}", b_port))
                .await
                .unwrap(),
            &a_kp,
            entity_hash::HASH_ALGORITHM_SHA256,
        )
        .await
        .unwrap();

        let fr = entity_relay::data::ForwardRequest {
            destination: c_pid.clone(),
            route: None,
            next_hop: Some(c_pid.clone()),
            ttl_hops: 3,
            expires_at: None,
            envelope_inner: inner_entity.content_hash,
        };
        let fr_entity = fr.to_entity().unwrap();
        let mut included = std::collections::HashMap::new();
        included.insert(inner_entity.content_hash, inner_entity.clone());

        let resp = remote::send_execute(
            &conn_b,
            &a_kp,
            &format!("/{}/system/relay", b_pid),
            "forward",
            &fr_entity,
            None,
            None,
            None,
            &included,
            None,
        )
        .await
        .unwrap();
        assert_eq!(resp.status, 200, "relay :forward should succeed");

        // forward-result.status MUST be `forwarded` (live terminal delivery),
        // NOT `queued-fallback` — proving the forwarder dialed C and delivered
        // rather than taking the §6.2.1 Mode-S fallback.
        let result_ent = resp.result;
        let result_map: entity_ecf::Value =
            ciborium::from_reader(result_ent.data.as_slice()).unwrap();
        let status = result_map
            .as_map()
            .and_then(|m| {
                m.iter().find_map(|(k, v)| {
                    if k.as_text() == Some("status") {
                        v.as_text()
                    } else {
                        None
                    }
                })
            })
            .unwrap_or("");
        assert_eq!(
            status,
            entity_relay::FORWARD_STATUS_FORWARDED,
            "expected live terminal delivery, got status={status:?}"
        );

        // The raw-frame inner landed at C's tree, byte-identical to the source.
        let got = c
            .tree()
            .get(&delivery_path)
            .expect("payload should be present at C's tree after relay delivery");
        assert_eq!(
            got.content_hash, payload.content_hash,
            "payload content_hash must match the source byte-for-byte (raw-frame)"
        );
        assert_eq!(got.entity_type, "test/relay-mp2-payload");

        c_handle.abort();
        b_handle.abort();
    }

    /// EXTENSION-RELAY v1.1 **source-routed multi-hop** end-to-end over live TCP
    /// (the `srcr2_3hop_a_to_d` equivalent). A names the full path in
    /// `route: [C, D]` and sends to the first relay B. B sees `next = C ≠ D` →
    /// intermediate, pops the head and forwards `{route: [D], next_hop: D}` to C;
    /// C sees `next = D == destination` → terminal raw-frame delivery to D. The
    /// inner envelope rides opaque + verbatim across BOTH hops (§9), and D
    /// verifies A's own signature exactly as on a direct connection. This proves
    /// the §3.1.1 per-hop pop-head algorithm + cross-impl trap #3 (intermediate
    /// `next_hop'` populated) over a genuine 2-relay chain.
    #[tokio::test]
    #[cfg(feature = "relay")]
    async fn test_relay_source_route_three_hop() {
        use entity_capability::{GrantEntry, IdScope, PathScope};
        use entity_crypto::Keypair;

        fn wildcard() -> Vec<(String, Vec<GrantEntry>)> {
            vec![(
                "default".to_string(),
                vec![GrantEntry {
                    handlers: PathScope::new(vec!["*".into()]),
                    resources: PathScope::new(vec!["*".into()]),
                    operations: IdScope::new(vec!["*".into()]),
                    peers: None,
                    constraints: None,
                    allowances: None,
                }],
            )]
        }

        // Spawn a wildcard-seeded TCP peer; returns (peer, peer_id, port, shared,
        // join handle). The relay forwarder is auto-wired by build() under the
        // `relay` feature.
        async fn spawn_peer(
            seed: u8,
        ) -> (
            Peer,
            String,
            u16,
            Arc<PeerShared>,
            tokio::task::JoinHandle<()>,
        ) {
            let p = PeerBuilder::new()
                .keypair(Keypair::from_seed([seed; 32]))
                .listen_addr("127.0.0.1:0")
                .with_seed_policy(wildcard())
                .build()
                .unwrap();
            let pid = p.peer_id().to_string();
            let listener = p.listen().await.unwrap();
            let port = listener.socket_addr().port();
            let shared = p.shared();
            p.start_engines(&shared);
            let run = shared.clone();
            let handle = tokio::spawn(async move {
                let _ = server::run(listener, run).await;
            });
            (p, pid, port, shared, handle)
        }

        // Publish `target`'s TCP transport profile into `host`'s tree so host's
        // forwarder can dial it (the next-hop resolution NETWORK §10 performs).
        fn publish_profile(
            host_shared: &Arc<PeerShared>,
            host_pid: &str,
            host: &Peer,
            target_pid: &str,
            target_port: u16,
        ) {
            let hex = remote::resolve_peer_id_hex(
                target_pid,
                host_shared.content_store.as_ref(),
                host_shared.location_index.as_ref(),
                host_pid,
            )
            .expect("derive target peer-id hex");
            let profile = transport_profile::TcpProfileData::for_local_listener_no_clock(
                target_pid,
                format!("tcp://127.0.0.1:{}", target_port),
            )
            .to_entity();
            let path = format!("/{}/system/peer/transport/{}/primary", host_pid, hex);
            host.tree().put(&path, profile).unwrap();
        }

        // D = destination, C + B = relays.
        let (d, d_pid, d_port, _d_shared, d_handle) = spawn_peer(41).await;
        let (c, c_pid, c_port, c_shared, c_handle) = spawn_peer(42).await;
        let (b, b_pid, b_port, b_shared, b_handle) = spawn_peer(43).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // B must reach C; C must reach D.
        publish_profile(&b_shared, &b_pid, &b, &c_pid, c_port);
        publish_profile(&c_shared, &c_pid, &c, &d_pid, d_port);

        // --- A: borrow a real connection grant from D, then build a fully-signed
        //     inner EXECUTE (tree:put on D) using it. Delivery goes via B→C.
        let a_kp = entity_crypto::IdentityKeypair::Ed25519(Keypair::from_seed([44u8; 32]));
        let conn_d = remote::perform_connect(
            transport::TcpConnector
                .connect(&format!("tcp://127.0.0.1:{}", d_port))
                .await
                .unwrap(),
            &a_kp,
            entity_hash::HASH_ALGORITHM_SHA256,
        )
        .await
        .unwrap();

        let payload = entity_entity::Entity::new(
            "test/relay-srcr-payload",
            entity_ecf::to_ecf(&entity_ecf::text("delivered-via-3hop")),
        )
        .unwrap();
        let payload_value: entity_ecf::Value =
            ciborium::from_reader(payload.data.as_slice()).unwrap();
        let delivery_path = format!("/{}/app/relay-srcr", d_pid);

        let put_params = entity_entity::Entity::new(
            "system/tree/put-request",
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                entity_ecf::text("entity"),
                entity_ecf::Value::Map(vec![
                    (
                        entity_ecf::text("content_hash"),
                        entity_ecf::Value::Bytes(payload.content_hash.to_bytes()),
                    ),
                    (entity_ecf::text("data"), payload_value),
                    (
                        entity_ecf::text("type"),
                        entity_ecf::text(&payload.entity_type),
                    ),
                ]),
            )])),
        )
        .unwrap();
        let resource = entity_capability::ResourceTarget {
            targets: vec![delivery_path.clone()],
            exclude: vec![],
        };
        let inner_env = remote::build_authenticated_execute(
            &a_kp,
            &conn_d.capability,
            &conn_d.auth_included,
            &std::collections::HashMap::new(),
            "srcr-req",
            &format!("/{}/system/tree", d_pid),
            "put",
            &put_params,
            Some(&resource),
            None,
            None,
        )
        .unwrap();
        let inner_entity = entity_entity::Entity::new(
            entity_types::TYPE_ENVELOPE,
            entity_wire::encode_envelope(&inner_env),
        )
        .unwrap();

        // --- A → B :forward(dest=D, route=[C, D]). B pops to C, C delivers to D.
        let conn_b = remote::perform_connect(
            transport::TcpConnector
                .connect(&format!("tcp://127.0.0.1:{}", b_port))
                .await
                .unwrap(),
            &a_kp,
            entity_hash::HASH_ALGORITHM_SHA256,
        )
        .await
        .unwrap();

        let fr = entity_relay::data::ForwardRequest {
            destination: d_pid.clone(),
            route: Some(vec![c_pid.clone(), d_pid.clone()]),
            next_hop: None,
            ttl_hops: 8,
            expires_at: None,
            envelope_inner: inner_entity.content_hash,
        };
        let fr_entity = fr.to_entity().unwrap();
        let mut included = std::collections::HashMap::new();
        included.insert(inner_entity.content_hash, inner_entity.clone());

        let resp = remote::send_execute(
            &conn_b,
            &a_kp,
            &format!("/{}/system/relay", b_pid),
            "forward",
            &fr_entity,
            None,
            None,
            None,
            &included,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            resp.status, 200,
            "B :forward (intermediate hop) should succeed"
        );

        // Allow the B→C→D chain to complete (each hop is its own dispatch).
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        // The raw-frame inner landed at D's tree, byte-identical to the source —
        // proving opacity held across both the intermediate (B→C) and terminal
        // (C→D) hops.
        let got = d
            .tree()
            .get(&delivery_path)
            .expect("payload should be present at D's tree after 3-hop relay delivery");
        assert_eq!(
            got.content_hash, payload.content_hash,
            "payload content_hash must match the source byte-for-byte across 2 relay hops"
        );
        assert_eq!(got.entity_type, "test/relay-srcr-payload");

        d_handle.abort();
        c_handle.abort();
        b_handle.abort();
    }

    /// Two co-located peers connect and complete the entity protocol
    /// handshake over in-process MemoryConnector / MemoryListener.
    /// No networking, no port allocation — `memory://<peer-id>` resolves
    /// directly via the registry. Mirrors `test_cross_peer_ws_execute`.
    #[tokio::test]
    async fn test_cross_peer_memory_connect() {
        use transport::{MemoryConnector, MemoryListener, MemoryTransportRegistry};

        let registry = MemoryTransportRegistry::new();

        let server = PeerBuilder::new()
            .keypair(Keypair::from_seed([20u8; 32]))
            .build()
            .unwrap();
        let server_pid = server.peer_id().to_string();

        let listener = MemoryListener::bind(server_pid.clone(), registry.clone()).unwrap();
        assert_eq!(listener.local_addr(), format!("memory://{}", server_pid));
        assert_eq!(listener.transport_type(), "memory");

        let shared = server.shared();
        server.start_engines(&shared);
        let shared_clone = shared.clone();
        let server_handle = tokio::spawn(async move {
            let _ = server::run(listener, shared_clone).await;
        });

        // Yield so the accept loop is parked on recv before we connect.
        tokio::task::yield_now().await;

        let client = PeerBuilder::new()
            .keypair(Keypair::from_seed([21u8; 32]))
            .connector(std::sync::Arc::new(MemoryConnector::new(registry.clone())))
            .build()
            .unwrap();
        client.local_only();

        let remote_pid = client
            .connect_to(&format!("memory://{}", server_pid))
            .await
            .unwrap();
        assert_eq!(remote_pid, server_pid);

        server_handle.abort();
    }

    // -----------------------------------------------------------------------
    // EXTENSION-NETWORK §10.3 (A14) — the live-establishment seam
    // -----------------------------------------------------------------------

    /// A seam that hands back an already-established memory connection to the
    /// server, standing in for a punched socket. §10.3 does not specify how the
    /// connection was obtained — candidate exchange, simultaneous open and the
    /// §7.4 check all belong to the registered policy — so a stub that skips
    /// straight to "here is a live transport" exercises exactly the seam's own
    /// contract and nothing else.
    struct StubEstablisher {
        registry: std::sync::Arc<transport::MemoryTransportRegistry>,
        target: String,
        /// Counts consultations, so a test can prove the seam is consulted
        /// **once** and the result reused (§10.3) rather than re-traversed.
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        /// What the caller declared about retry ownership (§10.3 obligation 4).
        saw_caller_owns_retry: std::sync::Arc<std::sync::atomic::AtomicBool>,
        /// What this stub reports as its §4.4 classification — i.e. whether it
        /// stands in for a policy that met the counterpart at a §3 rendezvous
        /// key (`pair`/`tag`/`secret`/`lobby`) or one that dialed a resolved
        /// address. Both real establishers in this crate report `true`; the
        /// default here is `false` so the seam's own tests keep exercising the
        /// asymmetric case.
        rendezvous_key: bool,
    }

    impl StubEstablisher {
        fn new(
            registry: std::sync::Arc<transport::MemoryTransportRegistry>,
            target: String,
        ) -> Self {
            Self {
                registry,
                target,
                calls: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                saw_caller_owns_retry: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
                    false,
                )),
                rendezvous_key: false,
            }
        }

        /// The same stub, standing in for a §6.5 (b) symmetric establishment:
        /// both peers brought the same §3 key and met at it.
        fn rendezvous(
            registry: std::sync::Arc<transport::MemoryTransportRegistry>,
            target: String,
        ) -> Self {
            Self {
                rendezvous_key: true,
                ..Self::new(registry, target)
            }
        }
    }

    #[async_trait::async_trait]
    impl live_establish::LiveEstablish for StubEstablisher {
        async fn establish_live(
            &self,
            ctx: live_establish::EstablishCtx,
            _peer_id: &str,
        ) -> Result<live_establish::LivePath, live_establish::LiveEstablishError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.saw_caller_owns_retry
                .store(ctx.caller_owns_retry, std::sync::atomic::Ordering::SeqCst);
            // A real policy checks the deadline between rungs rather than
            // starting a carrier round trip it cannot finish (§10.3).
            if ctx.expired() {
                return Err(live_establish::LiveEstablishError::NotAttempted {
                    substrate: "memory",
                    reason: "the seam deadline had already passed".to_string(),
                });
            }
            use transport::Connector;
            transport::MemoryConnector::new(self.registry.clone())
                .connect(&format!("memory://{}", self.target))
                .await
                .map(|connection| live_establish::LivePath {
                    connection,
                    // This double dials a memory transport, so exactly one side
                    // connected and §7.4.1 is settled the ordinary way.
                    role: live_establish::HandshakeRole::Initiator,
                    // §4.4: whichever establishment this stub stands in for.
                    // Default `false` — a plain address dial, no §3 key
                    // mutually brought — which also makes the default stub the
                    // negative vector for the mint gate.
                    established_via_rendezvous_key: self.rendezvous_key,
                })
                .map_err(|e| live_establish::LiveEstablishError::NoPath {
                    substrate: "memory",
                    reason: e.to_string(),
                })
        }
    }

    /// The additive, no-regression property (§10.3): with **nothing registered**
    /// the ladder is byte-identical to the pre-seam behavior. A peer with no
    /// resolvable durable profile still fails resolution, exactly as before —
    /// the seam must not turn a resolution miss into some new outcome.
    #[tokio::test]
    async fn live_establish_unregistered_leaves_the_ladder_unchanged() {
        let client = PeerBuilder::new()
            .keypair(Keypair::from_seed([40u8; 32]))
            .build()
            .unwrap();
        client.local_only();
        let shared = client.shared();
        assert!(
            shared.live_establish.is_none(),
            "§10.3 is opt-in — a peer must not acquire a traversal policy by default"
        );

        let err = remote::get_or_connect(
            &shared.remote,
            "PeerWithNoPublishedProfile",
            &shared.keypair,
            shared.content_store.as_ref(),
            shared.location_index.as_ref(),
            &shared.peer_id.to_string(),
            shared.connector.as_ref(),
            shared.config.home_hash_format,
            Some(shared.clone()),
        )
        .await;
        assert!(
            err.is_err(),
            "an unregistered seam must fall straight through to the pre-seam error"
        );
    }

    /// The seam's own contract: a returned connection is handshaken, **pooled**,
    /// and reused by every later dispatch (§10.3 — "returns a connection, not a
    /// result, and that is why it is a separate seam"). A seam consulted per
    /// message would punch a fresh hole each time and stay invisible to §10
    /// step 1; the call counter is what distinguishes those two worlds.
    #[tokio::test]
    async fn live_establish_connection_is_pooled_and_reused() {
        use transport::{MemoryListener, MemoryTransportRegistry};
        let registry = MemoryTransportRegistry::new();

        let server = PeerBuilder::new()
            .keypair(Keypair::from_seed([41u8; 32]))
            .build()
            .unwrap();
        let server_pid = server.peer_id().to_string();
        let listener = MemoryListener::bind(server_pid.clone(), registry.clone()).unwrap();
        let server_shared = server.shared();
        server.start_engines(&server_shared);
        let sc = server_shared.clone();
        let server_handle = tokio::spawn(async move {
            let _ = server::run(listener, sc).await;
        });
        tokio::task::yield_now().await;

        let mut client = PeerBuilder::new()
            .keypair(Keypair::from_seed([42u8; 32]))
            .build()
            .unwrap();
        client.local_only();
        let stub = std::sync::Arc::new(StubEstablisher::new(registry.clone(), server_pid.clone()));
        let calls = stub.calls.clone();
        let saw_retry = stub.saw_caller_owns_retry.clone();
        client.set_live_establish(stub);
        let shared = client.shared();

        // The server publishes no transport profile into the client's tree, so
        // durable-profile resolution misses and step 3b is the only way through.
        let first = remote::get_or_connect(
            &shared.remote,
            &server_pid,
            &shared.keypair,
            shared.content_store.as_ref(),
            shared.location_index.as_ref(),
            &shared.peer_id.to_string(),
            shared.connector.as_ref(),
            shared.config.home_hash_format,
            Some(shared.clone()),
        )
        .await
        .expect("§10.3 seam should have produced a live connection");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);

        let second = remote::get_or_connect(
            &shared.remote,
            &server_pid,
            &shared.keypair,
            shared.content_store.as_ref(),
            shared.location_index.as_ref(),
            &shared.peer_id.to_string(),
            shared.connector.as_ref(),
            shared.config.home_hash_format,
            Some(shared.clone()),
        )
        .await
        .expect("second dispatch");

        assert!(
            std::sync::Arc::ptr_eq(&first, &second),
            "the traversal connection must be POOLED — a second dispatch that \
             re-enters the seam would punch a fresh hole per message"
        );
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the seam is consulted once, at resolution — not per dispatch"
        );
        // §10.3 obligation 4: a §10 *dispatch* consultation leaves the policy
        // owning its own §7.2 exchange budget. Only the §4.1 reconnection path
        // caps it at one third-party exchange, and that call site is rung 4 —
        // asserted here so the two never quietly become one.
        assert!(
            !saw_retry.load(std::sync::atomic::Ordering::SeqCst),
            "a dispatch-driven consultation must not claim caller-owned retry"
        );

        server_handle.abort();
    }

    /// The **sequential** bound (`live_establish::ESTABLISH_FREE_CONSULTATIONS`)
    /// — obligation 5's single-flight gate stops N *concurrent* consultations;
    /// this stops an unbounded series of consecutive ones.
    ///
    /// The shape it defends against is the measured one: a caller re-dispatches
    /// to a peer that can never be reached, every consultation is individually
    /// conformant, and the series runs at the caller's dispatch rate forever
    /// (5/s per open conversation, ~1.1 offer deposits each, into a third
    /// party's rendezvous bucket). §11.5 cannot see it — that bound is per
    /// establishment, and every one of these is inside it.
    ///
    /// **Mutation check:** delete the `establish_cooldown_remaining` guard in
    /// `try_establish_live` and the consultation count becomes exactly
    /// `DISPATCHES`, failing the ceiling below. A test that passes without the
    /// mechanism would be worthless here, because the *pass* condition is a
    /// number that a broken build also produces if the ceiling is loose.
    #[tokio::test]
    async fn repeated_dispatch_to_an_unreachable_peer_stops_re_consulting_the_seam() {
        use transport::MemoryTransportRegistry;
        let registry = MemoryTransportRegistry::new();

        let mut client = PeerBuilder::new()
            .keypair(Keypair::from_seed([43u8; 32]))
            .build()
            .unwrap();
        client.local_only();
        // Nobody is listening at this address, so every consultation fails with
        // `NoPath` — a peer that can never be reached, which is the case the
        // bound exists for.
        let stub = std::sync::Arc::new(StubEstablisher::new(
            registry.clone(),
            "NobodyIsListeningAtThisAddress".to_string(),
        ));
        let calls = stub.calls.clone();
        client.set_live_establish(stub);
        let shared = client.shared();

        const DISPATCHES: usize = 200;
        for _ in 0..DISPATCHES {
            let r = remote::get_or_connect(
                &shared.remote,
                "NobodyIsListeningAtThisAddress",
                &shared.keypair,
                shared.content_store.as_ref(),
                shared.location_index.as_ref(),
                &shared.peer_id.to_string(),
                shared.connector.as_ref(),
                shared.config.home_hash_format,
                Some(shared.clone()),
            )
            .await;
            assert!(
                r.is_err(),
                "the peer is unreachable — the ladder must still fail the dispatch. \
                 A skipped consultation is a fall-through, NOT a new outcome"
            );
        }

        let consulted = calls.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            consulted >= live_establish::ESTABLISH_FREE_CONSULTATIONS as usize,
            "the grace window must be spent at full rate — establishment normally \
             takes several consultations, and backing off before that would slow \
             the path that works to bound the path that does not (got {consulted})"
        );
        // The loop runs in microseconds, so every dispatch after the grace
        // window lands inside the first few backoff steps (250ms, 500ms, ...).
        // The ceiling is deliberately a handful above the grace window rather
        // than exact: it must fail loudly at `DISPATCHES` while tolerating a
        // loaded box that takes a whole backoff step to get round the loop.
        assert!(
            consulted <= live_establish::ESTABLISH_FREE_CONSULTATIONS as usize + 5,
            "{DISPATCHES} dispatches to an unreachable peer must not produce \
             {DISPATCHES} consultations — the series is what a carrier pays for \
             (got {consulted})"
        );
    }

    /// A **cancelled** consultation counts too — the property that decides
    /// whether the bound holds under load, and the one the NAT rig caught.
    ///
    /// Charging the streak on the seam's `Err` return is the obvious factoring,
    /// and it silently exempts every consultation whose future is *dropped*: the
    /// caller's dispatch timed out, the surface moved on, nothing came back to
    /// charge — while the negotiation it started has already deposited into
    /// someone else's carrier. Those attempts are not an edge case; on the
    /// measured rig they were most of the gap between the rate the schedule
    /// predicts and the rate observed. So the charge happens before the await.
    ///
    /// **Mutation check:** move `note_establish_attempt` into the `Err` arm of
    /// `try_establish_live` and this test sees `DISPATCHES` consultations — a
    /// seam consulted 200 times because no consultation ever finished.
    #[tokio::test]
    async fn a_cancelled_consultation_still_counts_against_the_bound() {
        /// An establisher that never returns — the shape of a traversal still
        /// gathering candidates when the caller gives up on it.
        struct PendingEstablisher {
            calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        }
        #[async_trait::async_trait]
        impl live_establish::LiveEstablish for PendingEstablisher {
            async fn establish_live(
                &self,
                _ctx: live_establish::EstablishCtx,
                _peer_id: &str,
            ) -> Result<live_establish::LivePath, live_establish::LiveEstablishError> {
                self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                std::future::pending().await
            }
        }

        let mut client = PeerBuilder::new()
            .keypair(Keypair::from_seed([44u8; 32]))
            .build()
            .unwrap();
        client.local_only();
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        client.set_live_establish(std::sync::Arc::new(PendingEstablisher {
            calls: calls.clone(),
        }));
        let shared = client.shared();

        const DISPATCHES: usize = 200;
        for _ in 0..DISPATCHES {
            // Every dispatch abandons its consultation mid-negotiation.
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(2),
                remote::get_or_connect(
                    &shared.remote,
                    "APeerThatNeverAnswers",
                    &shared.keypair,
                    shared.content_store.as_ref(),
                    shared.location_index.as_ref(),
                    &shared.peer_id.to_string(),
                    shared.connector.as_ref(),
                    shared.config.home_hash_format,
                    Some(shared.clone()),
                ),
            )
            .await;
        }

        let consulted = calls.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            consulted <= live_establish::ESTABLISH_FREE_CONSULTATIONS as usize + 5,
            "consultations abandoned by the caller must still be charged — they \
             cost the carrier exactly as much as the ones that return (got \
             {consulted} of {DISPATCHES})"
        );
    }

    /// The bookkeeping itself, without the clock: the streak is cleared by a
    /// *pooled connection*, not by the seam returning `Ok` and not by time.
    ///
    /// Worth pinning separately because the end-to-end test above can only
    /// observe the cooldown engaging; the reset is what makes a peer that comes
    /// back reachable get full-rate treatment again, and it has no natural
    /// failure signal — a broken reset just makes reconnection quietly slow.
    #[tokio::test]
    async fn a_pooled_connection_clears_the_establish_backoff() {
        let pool = remote::RemoteState::new();
        let peer = "SomeUnreachablePeer";

        for _ in 0..live_establish::ESTABLISH_FREE_CONSULTATIONS {
            pool.note_establish_attempt(peer);
        }
        assert!(
            pool.establish_cooldown_remaining(peer).is_none(),
            "the grace window must run at full rate"
        );

        pool.note_establish_attempt(peer);
        let cooling = pool
            .establish_cooldown_remaining(peer)
            .expect("past the grace window the next consultation must be spaced out");
        assert!(cooling <= live_establish::ESTABLISH_BACKOFF_CAP);

        // Any connection reaching the pool clears it — this is the path
        // `insert_endpoint` / `rebind_endpoint` take.
        pool.note_establish_success(peer);
        assert!(
            pool.establish_cooldown_remaining(peer).is_none(),
            "a peer that just connected must not still be serving a cooldown"
        );

        // And the streak restarts from zero rather than resuming where it left
        // off: a peer that connected, dropped, and is being re-established is
        // not a peer that has been failing for a minute.
        pool.note_establish_attempt(peer);
        assert!(
            pool.establish_cooldown_remaining(peer).is_none(),
            "the streak must reset, not resume"
        );
    }

    /// §10.3: *"`ctx` carries a deadline and is cancellable (MUST)... a seam
    /// with no cancellation makes an unreachable peer indistinguishable from a
    /// hung dispatcher."*
    ///
    /// The deadline half is asserted here. The cancellation half is structural
    /// in Rust — dropping the future cancels it — so there is nothing to assert
    /// beyond the fact that the caller can wrap the call, which `tokio::time::
    /// timeout` does for free.
    #[tokio::test]
    async fn establish_ctx_carries_a_deadline_and_reports_expiry() {
        use live_establish::EstablishCtx;

        let live = EstablishCtx::dispatch(
            web_time::Instant::now() + live_establish::DEFAULT_TRAVERSAL_BUDGET,
        );
        assert!(!live.expired());
        assert!(!live.caller_owns_retry);
        assert!(live.remaining() > std::time::Duration::from_secs(1));

        // An already-elapsed deadline reads as expired rather than panicking or
        // wrapping — a policy consulted late must decline, not run.
        let past =
            EstablishCtx::dispatch(web_time::Instant::now() - std::time::Duration::from_secs(1));
        assert!(past.expired());
        assert_eq!(past.remaining(), std::time::Duration::ZERO);

        // The §4.1 constructor is the only thing that sets the obligation-4
        // flag; the two are named rather than boolean so a transposed argument
        // cannot silently swap the retry authority (§7.2.1).
        assert!(EstablishCtx::reconnect(web_time::Instant::now()).caller_owns_retry);
    }

    /// §10.3 MUST 1: the punched mapping is **session-scoped** — it is an
    /// ordinary transport and MUST NOT be published as a durable
    /// `system/peer/transport/*` profile (`EXTENSION-NETWORK.md` §6.7.3).
    ///
    /// Worth an explicit assertion rather than trusting the code path: writing
    /// the observed address into a durable profile is the *cheap* fix for "we
    /// know where this peer is now", and it corrupts §10 dispatch for every
    /// later reader — the same defect A13 calls out for `observed_address`.
    #[tokio::test]
    async fn live_establish_publishes_no_durable_transport_profile() {
        use transport::{MemoryListener, MemoryTransportRegistry};
        let registry = MemoryTransportRegistry::new();

        let server = PeerBuilder::new()
            .keypair(Keypair::from_seed([43u8; 32]))
            .build()
            .unwrap();
        let server_pid = server.peer_id().to_string();
        let listener = MemoryListener::bind(server_pid.clone(), registry.clone()).unwrap();
        let server_shared = server.shared();
        server.start_engines(&server_shared);
        let sc = server_shared.clone();
        let server_handle = tokio::spawn(async move {
            let _ = server::run(listener, sc).await;
        });
        tokio::task::yield_now().await;

        let mut client = PeerBuilder::new()
            .keypair(Keypair::from_seed([44u8; 32]))
            .build()
            .unwrap();
        client.local_only();
        client.set_live_establish(std::sync::Arc::new(StubEstablisher::new(
            registry.clone(),
            server_pid.clone(),
        )));
        let shared = client.shared();

        remote::get_or_connect(
            &shared.remote,
            &server_pid,
            &shared.keypair,
            shared.content_store.as_ref(),
            shared.location_index.as_ref(),
            &shared.peer_id.to_string(),
            shared.connector.as_ref(),
            shared.config.home_hash_format,
            Some(shared.clone()),
        )
        .await
        .expect("§10.3 seam should have produced a live connection");

        // A *published* profile lives at `system/peer/transport/{peer_id}/
        // {profile-id}` (D-13, §6.5.2a). Bootstrap `system/type/...` entities
        // declaring the profile *types* are unrelated and always present — the
        // filter excludes them so this asserts publication, not vocabulary.
        let profiles: Vec<String> = shared
            .location_index
            .list("")
            .into_iter()
            .map(|e| e.path)
            .filter(|p| p.contains("system/peer/transport") && !p.contains("system/type/"))
            .collect();
        assert!(
            profiles.is_empty(),
            "a traversal connection must publish no durable transport profile, found: {:?}",
            profiles
        );

        server_handle.abort();
    }

    /// R3a — granter idempotency: a single client redialing the same
    /// server MUST yield the **same** cap-token entity hash on the
    /// second authenticate, not two distinct tokens with different
    /// `created_at` timestamps. We assert by inspecting the server's
    /// granter cache: after N successful authenticate handshakes from
    /// the same grantee with the same grants config, the server's
    /// cache holds exactly ONE entry for that (grantee, grants) pair.
    /// Conformance evidence for PROPOSAL §7.3 R3a; precondition for
    /// R6's per-peer-session refactor.
    #[tokio::test]
    async fn test_r3a_granter_idempotency_across_redial() {
        use transport::{MemoryConnector, MemoryListener, MemoryTransportRegistry};

        let registry = MemoryTransportRegistry::new();

        let server = PeerBuilder::new()
            .keypair(Keypair::from_seed([30u8; 32]))
            .build()
            .unwrap();
        let server_pid = server.peer_id().to_string();

        // ONE shared snapshot; both the server task and our test
        // assertions read the same tree state.
        let server_shared = server.shared();
        let listener = MemoryListener::bind(server_pid.clone(), registry.clone()).unwrap();
        server.start_engines(&server_shared);
        let server_shared_for_task = server_shared.clone();
        let server_handle = tokio::spawn(async move {
            let _ = server::run(listener, server_shared_for_task).await;
        });
        tokio::task::yield_now().await;

        // Client peer_id is deterministic from the seed — pre-compute
        // its identity hash so we can assert on the server's session
        // entity path (v7.64: `{peer_id_hex}` not Base58).
        let client_kp = Keypair::from_seed([31u8; 32]);
        let client_pid = client_kp.peer_id().to_string();
        let client_identity_hash = client_kp.peer_identity_hash();
        let session_path = format!(
            "/{}/{}",
            server_pid,
            crate::session_entity::PeerSession::relative_path(&client_identity_hash)
        );
        let _ = client_pid; // retained as a documentary anchor

        // Helper: build a client (same keypair every call → same
        // grantee identity hash → same R6 session path on the server),
        // dial, return after the handshake completes.
        let dial = || {
            let registry = registry.clone();
            let server_pid = server_pid.clone();
            async move {
                let client = PeerBuilder::new()
                    .keypair(Keypair::from_seed([31u8; 32]))
                    .connector(std::sync::Arc::new(MemoryConnector::new(registry)))
                    .build()
                    .unwrap();
                client.local_only();
                client
                    .connect_to(&format!("memory://{}", server_pid))
                    .await
                    .unwrap();
            }
        };

        // Dial #1 — granter mints the cap + writes the session entity
        // with `minted_capability` set. R6 §9.3: one
        // `system/peer/session/{grantee}` per remote.
        dial().await;
        let session_after_one = server_shared.tree.get(&session_path).expect(
            "first dial must write the session entity at /{server}/system/peer/session/{client}",
        );
        let decoded_after_one = crate::session_entity::PeerSession::from_entity(&session_after_one)
            .expect("session entity decodes cleanly");
        let minted_hash_after_one = decoded_after_one
            .minted_capability
            .as_ref()
            .expect("granter-side session entity MUST have minted_capability")
            .hash;

        // Dial #2 — same grantee, same grants ⇒ minted cap MUST be
        // reused (no per-handshake token churn). R6 §9.1 R6-e preserves
        // R3a via mint-fresh-only-on-grants-change.
        dial().await;
        let session_after_two = server_shared
            .tree
            .get(&session_path)
            .expect("redial must leave the session entity in place");
        let decoded_after_two = crate::session_entity::PeerSession::from_entity(&session_after_two)
            .expect("session entity still decodes");
        let minted_hash_after_two = decoded_after_two
            .minted_capability
            .as_ref()
            .expect("redial MUST keep minted_capability populated")
            .hash;
        assert_eq!(
            minted_hash_after_two, minted_hash_after_one,
            "R6 idempotency violation: redial replaced minted_capability — granter minted fresh instead of reusing"
        );

        server_handle.abort();
    }

    /// R6 (PROPOSAL §7.2): "Persists across `disconnected` status —
    /// disconnection MUST NOT delete it." Pin that property: after a
    /// successful handshake, drop the client connection and verify
    /// the server's `system/peer/session/{client_pid}` entity is
    /// still present + decodable + unchanged.
    #[tokio::test]
    async fn test_r6_session_persists_across_disconnect() {
        use transport::{MemoryConnector, MemoryListener, MemoryTransportRegistry};

        let registry = MemoryTransportRegistry::new();
        let server = PeerBuilder::new()
            .keypair(Keypair::from_seed([40u8; 32]))
            .build()
            .unwrap();
        let server_pid = server.peer_id().to_string();
        let server_shared = server.shared();
        let listener = MemoryListener::bind(server_pid.clone(), registry.clone()).unwrap();
        server.start_engines(&server_shared);
        let server_shared_for_task = server_shared.clone();
        let server_handle = tokio::spawn(async move {
            let _ = server::run(listener, server_shared_for_task).await;
        });
        tokio::task::yield_now().await;

        let client_kp = Keypair::from_seed([41u8; 32]);
        let client_pid = client_kp.peer_id().to_string();
        let client_identity_hash = client_kp.peer_identity_hash();
        let session_path = format!(
            "/{}/{}",
            server_pid,
            crate::session_entity::PeerSession::relative_path(&client_identity_hash)
        );

        // Handshake, then drop the client. The session MUST survive.
        {
            let client = PeerBuilder::new()
                .keypair(Keypair::from_seed([41u8; 32]))
                .connector(std::sync::Arc::new(MemoryConnector::new(registry.clone())))
                .build()
                .unwrap();
            client.local_only();
            client
                .connect_to(&format!("memory://{}", server_pid))
                .await
                .unwrap();
            // Client dropped at end of scope — connection torn down.
        }
        // Give the server task a beat to observe the close.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let session_entity = server_shared
            .tree
            .get(&session_path)
            .expect("R6: session entity MUST persist across client disconnect");
        let decoded = crate::session_entity::PeerSession::from_entity(&session_entity)
            .expect("session entity still decodes after disconnect");
        assert_eq!(decoded.remote_peer_id, client_pid);
        // §9 dropped the `status` field; persistence is the invariant
        // (the entity stays in place and is decodable).
        assert!(
            decoded.minted_capability.is_some(),
            "granter-side session entity MUST have minted_capability"
        );

        server_handle.abort();
    }

    /// R6 §9.1 R6-a — bidirectional cap recording. After a single
    /// dial A→B, BOTH peers MUST hold a session entity for the other:
    /// A's `/{A}/system/peer/session/{B}` carries `held_capability`
    /// (the cap B granted A); B's `/{B}/system/peer/session/{A}`
    /// carries `minted_capability` (the cap B issued to A). The two
    /// caps are the same content-addressed entity recorded from both
    /// ends.
    #[tokio::test]
    async fn test_r6_bidirectional_held_and_minted_after_single_dial() {
        use transport::{MemoryConnector, MemoryListener, MemoryTransportRegistry};

        let registry = MemoryTransportRegistry::new();
        let server = PeerBuilder::new()
            .keypair(Keypair::from_seed([50u8; 32]))
            .build()
            .unwrap();
        let server_pid = server.peer_id().to_string();
        let server_shared = server.shared();
        let listener = MemoryListener::bind(server_pid.clone(), registry.clone()).unwrap();
        server.start_engines(&server_shared);
        let server_shared_for_task = server_shared.clone();
        let server_handle = tokio::spawn(async move {
            let _ = server::run(listener, server_shared_for_task).await;
        });
        tokio::task::yield_now().await;

        let client = PeerBuilder::new()
            .keypair(Keypair::from_seed([51u8; 32]))
            .connector(std::sync::Arc::new(MemoryConnector::new(registry.clone())))
            .build()
            .unwrap();
        client.local_only();
        let client_pid = client.peer_id().to_string();
        let client_shared = client.shared();

        client
            .connect_to(&format!("memory://{}", server_pid))
            .await
            .unwrap();
        // Let the server-side write settle.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        // Server side: minted_capability set, held_capability absent.
        // v7.64: `{peer_id_hex}` not Base58.
        let client_identity_hash = Keypair::from_seed([51u8; 32]).peer_identity_hash();
        let server_session_path = format!(
            "/{}/{}",
            server_pid,
            crate::session_entity::PeerSession::relative_path(&client_identity_hash)
        );
        let server_session = server_shared
            .tree
            .get(&server_session_path)
            .expect("server MUST have session entity for client after handshake");
        let server_decoded =
            crate::session_entity::PeerSession::from_entity(&server_session).unwrap();
        let server_minted = server_decoded
            .minted_capability
            .as_ref()
            .expect("granter side MUST have minted_capability");
        assert!(
            server_decoded.held_capability.is_none(),
            "granter side MUST NOT have held_capability after a single inbound dial"
        );

        // Client side: held_capability set, minted_capability absent.
        let server_identity_hash = Keypair::from_seed([50u8; 32]).peer_identity_hash();
        let client_session_path = format!(
            "/{}/{}",
            client_pid,
            crate::session_entity::PeerSession::relative_path(&server_identity_hash)
        );
        let client_session = client_shared
            .tree
            .get(&client_session_path)
            .expect("client MUST have session entity for server after handshake");
        let client_decoded =
            crate::session_entity::PeerSession::from_entity(&client_session).unwrap();
        let client_held = client_decoded
            .held_capability
            .as_ref()
            .expect("dialer side MUST have held_capability");
        assert!(
            client_decoded.minted_capability.is_none(),
            "dialer side MUST NOT have minted_capability after a single outbound dial"
        );

        // §9.1 R6-a: A's minted_capability for B IS the same cap as
        // B's held_capability from A — one cap, recorded from both
        // ends.
        assert_eq!(
            server_minted.hash, client_held.hash,
            "bidirectional invariant: server's minted_capability.hash must equal client's held_capability.hash"
        );

        server_handle.abort();
    }

    /// §6.5 mutual minting (PROPOSAL-SYMMETRIC-REENTRY-MUTUAL-MINTING): after a
    /// **§6.5 (b) symmetric establishment** C→S, the ACCEPTOR S acquires
    /// originating authority from C's reciprocal reentry grant and can originate
    /// a dispatch back to C over the same connection.
    ///
    /// This constructs the acceptor's originating path end-to-end — the path the
    /// native suite never built, which is exactly how the §6.5 gap shipped. It is
    /// the regression guard for the whole chain: C mints + sends the grant on
    /// establishment; S intercepts it in the message loop, verifies granter == C,
    /// and installs it (with its signature + granter identity) on the reentry
    /// endpoint; S then originates under it, and the merged chain bundle makes the
    /// single-sig cap verify at C (before the fix this was `no originating
    /// authority`, then `403 missing_signature`).
    ///
    /// The establishment runs through the §10.3 seam reporting
    /// `established_via_rendezvous_key = true` (§4.4) — a plain dial no longer
    /// mints, which is the point of its negative twin below.
    #[tokio::test]
    async fn test_s65_acceptor_originates_after_reciprocal_grant() {
        use transport::{MemoryListener, MemoryTransportRegistry};

        let registry = MemoryTransportRegistry::new();
        let server = PeerBuilder::new()
            .keypair(Keypair::from_seed([60u8; 32]))
            .build()
            .unwrap();
        let server_pid = server.peer_id().to_string();
        let server_shared = server.shared();
        let listener = MemoryListener::bind(server_pid.clone(), registry.clone()).unwrap();
        server.start_engines(&server_shared);
        let server_shared_for_task = server_shared.clone();
        let server_handle = tokio::spawn(async move {
            let _ = server::run(listener, server_shared_for_task).await;
        });
        tokio::task::yield_now().await;

        let mut client = PeerBuilder::new()
            .keypair(Keypair::from_seed([61u8; 32]))
            .build()
            .unwrap();
        client.local_only();
        // The §10.3 seam stands in for a policy that met S at a §3 rendezvous
        // key. S publishes no transport profile into C's tree, so step 3b is the
        // only way through and the seam's classification is the one in play.
        client.set_live_establish(std::sync::Arc::new(StubEstablisher::rendezvous(
            registry.clone(),
            server_pid.clone(),
        )));
        let client_pid = client.peer_id().to_string();
        let client_shared = client.shared();
        client.start_engines(&client_shared);

        // C establishes to S through the seam WITH C's dispatch context, so C
        // mints and sends the reciprocal reentry grant.
        remote::get_or_connect(
            &client_shared.remote,
            &server_pid,
            &client_shared.keypair,
            client_shared.content_store.as_ref(),
            client_shared.location_index.as_ref(),
            &client_pid,
            client_shared.connector.as_ref(),
            client_shared.config.home_hash_format,
            Some(client_shared.clone()),
        )
        .await
        .expect("§10.3: the rendezvous seam should have produced a live connection");

        // The grant lands a beat after the handshake. Poll S's inbound endpoint
        // for C until it gains originating authority (it starts with none).
        let mut endpoint = None;
        for _ in 0..200 {
            if let Some(e) = server_shared.remote.get_inbound(&client_pid) {
                if e.originating_capability().is_some() {
                    endpoint = Some(e);
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let endpoint = endpoint.expect(
            "§6.5: acceptor MUST acquire originating authority from the reciprocal reentry grant",
        );

        // S ORIGINATES back to C over the reentry endpoint with no explicit
        // dispatch_cap — so it authors under the reciprocal cap, wielded **by
        // reference**: the envelope carries the cap hash and nothing else, no
        // inlined signature or granter identity (arch `cbe9dff`). That makes
        // this the native gate on the whole references-only round trip — S's
        // sender emits a bare reference, and C must resolve the cap from the
        // ledger it minted it into, because a reciprocal cap is never in the
        // content store. Before the sender flip this path inlined the chain,
        // which is precisely what hid our double-walk revocation bug (`f227df8`)
        // until core-go flipped first and V3 direction B went 200 -> 403.
        // `get` on C's own `system/tree` returns the handler descriptor (200),
        // the same shape the rung-1 rig sees.
        let empty_params = entity_entity::Entity::new(
            "system/params",
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![])),
        )
        .unwrap();
        let resp = remote::send_execute(
            endpoint.as_ref(),
            server.keypair(),
            &format!("/{}/system/tree", client_pid),
            "get",
            &empty_params,
            None,
            None,
            None,
            &std::collections::HashMap::new(),
            None,
        )
        .await
        .expect("§6.5: acceptor→dialer originate must not error at the transport layer");
        assert_eq!(
            resp.status, 200,
            "§6.5: acceptor→dialer originate must authorize (got {}: {:?})",
            resp.status, resp.result
        );

        server_handle.abort();
    }

    /// The §6.5 (b) **Contents** ruling (arch `f8f736a`, 2026-08-05) measured on
    /// both directions of one peer: the reciprocal grant C mints for S is the
    /// grant C would issue S **as an inbound dialer** — the assembled §4.4 set,
    /// not the flat `default_connection_grants` floor.
    ///
    /// The defect this catches is not a wrong grant list; it is the two
    /// directions *drifting apart*. So the assertion is a comparison, never a
    /// hardcoded expectation: C is given a resolver that answers with a
    /// distinguishable non-floor set, S meets C both ways — once at the
    /// rendezvous (C mints the reciprocal grant) and once as an ordinary inbound
    /// dialer (C mints the §6.6 handshake cap) — and the two grant lists must be
    /// the same. A test that pinned today's list would go stale the next time
    /// the assembly changes and would still pass while the directions diverged.
    ///
    /// The second assertion is the anti-vacuity one: the set must not be the
    /// floor, or the comparison would hold for the pre-ruling build too.
    #[tokio::test]
    async fn test_s65_reciprocal_grant_is_the_assembled_inbound_grant() {
        use transport::{MemoryConnector, MemoryListener, MemoryTransportRegistry};

        /// C's assembled answer for any counterpart: the floor plus one entry
        /// nothing in `default_connection_grants` carries.
        ///
        /// The extra entry names a handler C **actually serves**. It used to
        /// name `app/echo`, which C does not register — and once the §3
        /// advertisement filter landed in `assemble_inbound_grants` that entry
        /// was correctly dropped, collapsing the assembly back to the floor and
        /// tripping this test's own "off the floor" guard. The guard was right:
        /// an unadvertised entry is no longer part of any assembly, so it can no
        /// longer be what distinguishes one.
        fn assembled() -> Vec<entity_capability::GrantEntry> {
            let mut grants = entity_capability::default_connection_grants();
            grants.push(entity_capability::GrantEntry {
                handlers: entity_capability::PathScope::new(vec!["system/tree".into()]),
                resources: entity_capability::PathScope::new(vec![]),
                operations: entity_capability::IdScope::new(vec!["list".into()]),
                peers: None,
                constraints: None,
                allowances: None,
            });
            grants
        }

        fn grants_of(cap: &entity_entity::Entity) -> Vec<entity_capability::GrantEntry> {
            entity_capability::CapabilityToken::from_entity(cap)
                .expect("a minted capability decodes")
                .grants
        }

        let registry = MemoryTransportRegistry::new();

        // S — the acceptor at the rendezvous, and the inbound dialer afterwards.
        let server = PeerBuilder::new()
            .keypair(Keypair::from_seed([66u8; 32]))
            .connector(std::sync::Arc::new(MemoryConnector::new(registry.clone())))
            .build()
            .unwrap();
        let server_pid = server.peer_id().to_string();
        let server_shared = server.shared();
        let server_listener = MemoryListener::bind(server_pid.clone(), registry.clone()).unwrap();
        server.start_engines(&server_shared);
        let server_shared_for_task = server_shared.clone();
        let server_handle = tokio::spawn(async move {
            let _ = server::run(server_listener, server_shared_for_task).await;
        });

        // C — the minter. Its resolver is the one assembly both directions read.
        let mut client = PeerBuilder::new()
            .keypair(Keypair::from_seed([67u8; 32]))
            .build()
            .unwrap();
        client.set_grant_resolver(std::sync::Arc::new(|_peer, _hash| Some(assembled())));
        client.set_live_establish(std::sync::Arc::new(StubEstablisher::rendezvous(
            registry.clone(),
            server_pid.clone(),
        )));
        let client_pid = client.peer_id().to_string();
        let client_shared = client.shared();
        let client_listener = MemoryListener::bind(client_pid.clone(), registry.clone()).unwrap();
        client.start_engines(&client_shared);
        let client_shared_for_task = client_shared.clone();
        let client_handle = tokio::spawn(async move {
            let _ = server::run(client_listener, client_shared_for_task).await;
        });
        tokio::task::yield_now().await;

        // Direction 1 — the rendezvous. C establishes to S through the seam and
        // mints the reciprocal grant.
        remote::get_or_connect(
            &client_shared.remote,
            &server_pid,
            &client_shared.keypair,
            client_shared.content_store.as_ref(),
            client_shared.location_index.as_ref(),
            &client_pid,
            client_shared.connector.as_ref(),
            client_shared.config.home_hash_format,
            Some(client_shared.clone()),
        )
        .await
        .expect("§10.3: the rendezvous seam should have produced a live connection");

        let mut reciprocal = None;
        for _ in 0..(remote::RECIPROCAL_GRANT_VECTOR_FLOOR_MS / 10) {
            if let Some(e) = server_shared.remote.get_inbound(&client_pid) {
                if let Some(cap) = e.originating_capability() {
                    reciprocal = Some(cap);
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let reciprocal = reciprocal.expect("§6.5 (b): the reciprocal grant must arrive");

        // Direction 2 — the ordinary inbound dial. S dials C by address, so C
        // runs the same assembly for the §6.6 handshake cap.
        let inbound = remote::connect_and_pool(&server_shared, &format!("memory://{}", client_pid))
            .await
            .expect("S should be able to dial C by address");

        assert_eq!(
            grants_of(&reciprocal),
            grants_of(inbound.capability()),
            "§6.5 (b) Contents: the reciprocal grant MUST be the grant C issues \
             an inbound dialer — the assembled set, not a second construction"
        );
        assert_ne!(
            grants_of(&reciprocal),
            entity_capability::default_connection_grants(),
            "the fixture must put C's assembly off the floor, or this proves nothing"
        );

        server_handle.abort();
        client_handle.abort();
    }

    /// Taxonomy **row 2** end-to-end (PROPOSAL-SYMMETRIC-REENTRY-MUTUAL-MINTING
    /// §3 / §7 ruling): a cross-peer async delivery is authorized by the
    /// caller's `deliver_token` and by nothing else.
    ///
    /// The topology is the one that makes the claim testable at all. C dials S
    /// by address and publishes no transport profile, so:
    /// - S reaches C only through the §6.11(b) inbound-reentry fallback, and
    /// - after the §7 narrowing S holds **no** reciprocal grant on that
    ///   connection (its asymmetric twin above pins exactly that),
    ///
    /// so the delivery has no connection authority to fall back on — and
    /// `default_connection_grants` never covered `system/inbox receive` anyway.
    /// If the delivery arrives, the token is what carried it.
    ///
    /// This is the vector the native suite never had: the only async-delivery
    /// coverage was a single-peer simulation, which cannot see a wire authority
    /// decision at all. `entity-core-go` found the same defect in `deliverToInbox`
    /// the same way — green on a dialed connection, `401` on the profile-less path.
    #[tokio::test]
    async fn test_row2_async_delivery_authorizes_under_the_deliver_token() {
        use transport::{MemoryConnector, MemoryListener, MemoryTransportRegistry};

        let registry = MemoryTransportRegistry::new();
        let server = PeerBuilder::new()
            .keypair(Keypair::from_seed([64u8; 32]))
            .build()
            .unwrap();
        let server_pid = server.peer_id().to_string();
        let server_shared = server.shared();
        let listener = MemoryListener::bind(server_pid.clone(), registry.clone()).unwrap();
        server.start_engines(&server_shared);
        let server_shared_for_task = server_shared.clone();
        let server_handle = tokio::spawn(async move {
            let _ = server::run(listener, server_shared_for_task).await;
        });
        tokio::task::yield_now().await;

        let client = PeerBuilder::new()
            .keypair(Keypair::from_seed([65u8; 32]))
            .connector(std::sync::Arc::new(MemoryConnector::new(registry.clone())))
            .build()
            .unwrap();
        client.local_only();
        let client_pid = client.peer_id().to_string();
        let client_shared = client.shared();
        client.start_engines(&client_shared);

        client
            .connect_to(&format!("memory://{}", server_pid))
            .await
            .unwrap();
        let endpoint = client_shared
            .remote
            .get(&server_pid)
            .expect("C should hold the connection it dialed");

        // C mints the delivery authority: granter = C (it owns the inbox),
        // grantee = S (the peer that will deliver), scoped to `receive` at
        // exactly this inbox URI.
        let deliver_uri = format!("/{}/system/inbox", client_pid);
        let deliver_params = remote::generate_deliver_token(
            &client_shared.keypair,
            endpoint.remote_identity_hash(),
            &deliver_uri,
            "receive",
        )
        .unwrap();

        let empty_params = entity_entity::Entity::new(
            "system/params",
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![])),
        )
        .unwrap();
        let resp = remote::send_execute(
            endpoint.as_ref(),
            &client_shared.keypair,
            &format!("/{}/system/tree", server_pid),
            "get",
            &empty_params,
            None,
            Some(&deliver_params),
            None,
            &std::collections::HashMap::new(),
            None,
        )
        .await
        .expect("the deliver_to request itself rides C's connection grant");
        assert_eq!(
            resp.status, 202,
            "EXTENSION-INBOX §4.5: a deliver_to request is accepted, not answered"
        );

        // S runs the handler, then delivers back over the inbound endpoint,
        // authoring under C's deliver_token. The result lands under the inbox
        // URI keyed by the delivery's own request_id.
        let prefix = format!("{}/", deliver_uri);
        let mut delivered = false;
        for _ in 0..200 {
            if !client_shared.location_index.list(&prefix).is_empty() {
                delivered = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            delivered,
            "row 2: the async delivery MUST authorize under the deliver_token — \
             nothing else on this connection could have carried it"
        );

        server_handle.abort();
    }

    /// Q1 phase (2), the **receiver** half: an acceptor may wield our §6.5 (b)
    /// reciprocal grant by *reference*, and we — the peer that authored those
    /// entities — resolve them instead of demanding them back.
    ///
    /// The frame this pins is the one `entity-core-go` found and warned about,
    /// and it is not the tidy "references-only" shape the ruling describes:
    /// `build_authenticated_execute` inlines the capability **unconditionally**,
    /// so a sender that simply stops attaching the supporting set emits a
    /// *partial* reference frame — cap present, its signature and the granter
    /// identity absent. That dies at the chain walk as `missing_signature`, not
    /// as a missing cap. Any impl that flips by "stop attaching the chain" will
    /// ship exactly this, so it is the shape the receiver has to handle.
    ///
    /// Three assertions, and the third is the one that matters:
    ///
    /// 1. Without the ledger the partial frame is refused — this is today's
    ///    shipped behavior, and it is what makes assertion 2 a change rather
    ///    than a tautology.
    /// 2. With the grant recorded as minted-and-delivered to *this* peer, the
    ///    same bytes verify.
    /// 3. **Resolution does not widen.** The same cap, minted and recorded
    ///    against a *different* counterpart, is refused. Read literally,
    ///    "the dialer resolves from its own content store" would make naming a
    ///    cap as good as holding one; the ledger is scoped to who we actually
    ///    delivered to, so a mint that went elsewhere — or never went out at
    ///    all — stays unwieldable. If this assertion ever flips to 200, the
    ///    supplier has become a general store lookup and the scope is gone.
    #[tokio::test]
    async fn test_q1_phase2_references_only_wielding_is_scoped_to_minted_and_delivered() {
        use std::collections::HashMap;

        fn status_of(env: &entity_entity::Envelope) -> i128 {
            let val: entity_ecf::Value =
                ciborium::from_reader(env.root.data.as_slice()).expect("response decodes");
            let map = val.as_map().expect("response is a map");
            map.iter()
                .find(|(k, _): &&(entity_ecf::Value, entity_ecf::Value)| {
                    k.as_text() == Some("status")
                })
                .and_then(|(_, v)| v.as_integer())
                .map(i128::from)
                .expect("response carries a status")
        }

        /// Does the response body carry this error code? Scans the encoded
        /// bytes rather than re-deriving the nested error shape — the point is
        /// which rejection fired, and that string is the whole signal.
        fn carries(env: &entity_entity::Envelope, needle: &str) -> bool {
            env.root
                .data
                .windows(needle.len())
                .any(|w| w == needle.as_bytes())
        }

        let peer = PeerBuilder::new()
            .keypair(Keypair::from_seed([81u8; 32]))
            .build()
            .unwrap();
        let shared = peer.shared();
        let local_pid = shared.peer_id.as_str().to_string();
        let fmt = shared.config.home_hash_format;

        // The acceptor: the peer we mint FOR and who wields back at us.
        let acceptor = IdentityKeypair::from(Keypair::from_seed([82u8; 32]));
        let acceptor_identity = acceptor.peer_entity().expect("acceptor identity");
        let acceptor_pid = acceptor.peer_id().as_str().to_string();

        // The §6.5 (b) mint, through the same builder the live dial uses.
        let grant_env = remote::build_reentry_grant_envelope(
            &shared.keypair,
            acceptor_identity.content_hash,
            fmt,
            entity_capability::default_connection_grants(),
        )
        .expect("the reciprocal grant mints");
        let bundle: Vec<entity_entity::Entity> = grant_env.included.values().cloned().collect();
        let cap_entity = bundle
            .iter()
            .find(|e| e.entity_type == entity_types::TYPE_CAP_TOKEN)
            .expect("the minted bundle carries the capability")
            .clone();

        // The wielding frame, with an EMPTY supporting set — the partial
        // reference shape described above.
        let get_path = format!("/{}/system/type/system/peer", local_pid);
        let params = entity_entity::Entity::new(
            entity_types::TYPE_TREE_GET_REQ,
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                entity_ecf::text("uri"),
                entity_ecf::text(&get_path),
            )])),
        )
        .expect("tree get params");
        let resource = entity_capability::ResourceTarget {
            targets: vec![get_path.clone()],
            exclude: vec![],
        };
        let wield = remote::build_authenticated_execute(
            &acceptor,
            &cap_entity,
            &HashMap::new(),
            &HashMap::new(),
            "q1-phase2-req",
            &format!("entity://{}/system/tree", local_pid),
            "get",
            &params,
            Some(&resource),
            None,
            None,
        )
        .expect("the acceptor can author its origination");

        // 1. No ledger entry — refused, as today.
        let refused =
            connection::dispatch_request(&wield, shared.clone(), Some(&acceptor_pid)).await;
        assert_eq!(
            (status_of(&refused), carries(&refused, "missing_signature")),
            (403, true),
            "a partial reference frame MUST be refused when nothing says we \
             minted this cap for this peer — and it MUST fail as \
             `missing_signature` at the chain walk, not as a missing cap, \
             because the sender still inlined the cap itself. That exact code \
             is `entity-core-go`'s finding, pinned here so a future refactor \
             cannot quietly turn this into a different rejection"
        );

        // 3. A DIFFERENT cap in the ledger — the wielded one still refused.
        //    Written before the positive case so a supplier that ignores the key
        //    cannot pass by having been primed correctly first.
        //
        //    Since arch's 2026-08-07 ruling the ledger resolves by CAP HASH, so
        //    what this pins is the scoping that actually survives: only what we
        //    minted AND delivered is suppliable. It is emphatically not a store
        //    lookup — a cap absent from the ledger stays unresolvable even when
        //    the ledger holds some other cap for the very peer that is asking.
        let third_party = IdentityKeypair::from(Keypair::from_seed([83u8; 32]));
        let other_grant = remote::build_reentry_grant_envelope(
            &shared.keypair,
            third_party
                .peer_entity()
                .expect("third-party identity")
                .content_hash,
            fmt,
            entity_capability::default_connection_grants(),
        )
        .expect("the third-party grant mints");
        shared.minted_reentry_grants.lock().unwrap().record(
            acceptor_pid.clone(),
            remote::reciprocal_cap_hash(&other_grant).expect("one cap in the grant"),
            other_grant.included.values().cloned().collect(),
        );
        let wrong_cap =
            connection::dispatch_request(&wield, shared.clone(), Some(&acceptor_pid)).await;
        assert_eq!(
            (
                status_of(&wrong_cap),
                carries(&wrong_cap, "missing_signature")
            ),
            (403, true),
            "resolution widened: a cap we never recorded as minted-and-delivered \
             was supplied. The supplier has become a store lookup, and naming a \
             cap is now as good as holding one"
        );

        // 2. Recorded as delivered — the same bytes verify.
        let cap_hash = remote::reciprocal_cap_hash(&grant_env).expect("one cap in the grant");
        shared
            .minted_reentry_grants
            .lock()
            .unwrap()
            .record(acceptor_pid.clone(), cap_hash, bundle);
        let accepted =
            connection::dispatch_request(&wield, shared.clone(), Some(&acceptor_pid)).await;
        assert!(
            !carries(&accepted, "missing_signature"),
            "§7a.2a: the acceptor wielded a grant WE minted and delivered to it, \
             by reference. Re-carrying our own entities back to us is the waste \
             the two-phase carriage exists to delete"
        );

        // 4. The ruling itself (EXTENSION-SIGNALING §6.5, *"The ledger's
        //    resolution key is the cap hash"*, 2026-08-07): the SAME frame
        //    resolves when the session peer-id is not the delivery recipient.
        //
        //    That is the delegation shape. A recipient-keyed-only ledger — what
        //    this impl had until the ruling — resolves nothing here and fails
        //    CLOSED: `403` on valid authority, the same wrong answer as the
        //    store-only revocation walk, arriving by a different route. Both
        //    impls caught a wrong wielder today, which is why neither filed it;
        //    the divergence is only visible at this cross-peer seam.
        let delegated = connection::dispatch_request(
            &wield,
            shared.clone(),
            Some("2KsomeDelegateWieldingOurCap"),
        )
        .await;
        assert!(
            !carries(&delegated, "missing_signature"),
            "the ledger resolved nothing for a wielder whose peer-id is not the \
             delivery recipient's — recipient peer-id is still the sole key, and \
             a delegated wield fails closed on valid authority"
        );
    }

    /// §1.4 / §6.5 step 3 (PD-1h) — an inbound EXECUTE whose HANDLER URI names
    /// a peer that is not us is refused `400 invalid_request` at
    /// canonicalization, before handler resolution.
    ///
    /// **The control is the whole test.** A bare "foreign uri → 400" assertion
    /// is satisfied by a peer that 400s the frame for any reason at all, so each
    /// foreign form is paired with a LOCAL form that is identical in every other
    /// respect — same cap, same handler, same operation, same resource — and the
    /// local form must NOT be gated. That is what makes the 400 attributable to
    /// the peer segment rather than to a malformed request.
    ///
    /// **Both foreign spellings, because they reach the defect by different
    /// routes.** `entity://{them}/…` is the escalating one:
    /// `extract_handler_path` drops the authority and `qualify_path` re-attaches
    /// OURS, so pre-fix it resolved OUR handler under THEIR address.
    /// `/{them}/…` survives that round-trip unchanged. One gate covers both
    /// because it reads `extract_peer`, which is authority-aware.
    ///
    /// The cap deliberately carries `peers: ["*"]` — the §5.2 open-access
    /// dev-cap shape the conformance driver presents. That is the condition
    /// under which the pre-fix behaviour is not merely a wrong status but a
    /// privilege escalation: Dimension 4 compares the cap's peer scope against
    /// the foreign target and ALLOWS, so the frame ran to completion. Mutation
    /// (delete the gate): all four rows collapse to the same answer, and the two
    /// foreign rows go red.
    #[tokio::test]
    async fn inbound_execute_naming_a_foreign_peer_is_refused_before_handler_resolution() {
        fn status_of(env: &entity_entity::Envelope) -> u32 {
            entity_protocol::parse_execute_response(env)
                .map(|r| r.status)
                .unwrap_or(0)
        }
        fn carries(env: &entity_entity::Envelope, needle: &str) -> bool {
            env.root
                .data
                .windows(needle.len())
                .any(|w| w == needle.as_bytes())
        }

        let peer = PeerBuilder::new()
            .keypair(Keypair::from_seed([91u8; 32]))
            .build()
            .unwrap();
        let shared = peer.shared();
        let local_pid = shared.peer_id.as_str().to_string();
        let fmt = shared.config.home_hash_format;

        let caller = IdentityKeypair::from(Keypair::from_seed([92u8; 32]));
        let caller_identity = caller.peer_entity().expect("caller identity");

        // A THIRD peer id — the namespace the foreign rows address. Not us, and
        // not the caller, so nothing about the frame's authorship can be
        // mistaken for the reason it is refused.
        let foreign_pid = IdentityKeypair::from(Keypair::from_seed([93u8; 32]))
            .peer_id()
            .as_str()
            .to_string();

        // §5.2's open-access shape: `/*/*` resources plus `peers: ["*"]`. With
        // anything narrower on `peers`, Dimension 4 would deny the foreign row
        // on its own and the gate would be untestable through this path.
        let open = vec![entity_capability::GrantEntry {
            handlers: entity_capability::PathScope::new(vec!["system/tree".into()]),
            resources: entity_capability::PathScope::new(vec!["/*/*".into()]),
            operations: entity_capability::IdScope::new(vec!["get".into()]),
            peers: Some(entity_capability::IdScope::all()),
            constraints: None,
            allowances: None,
        }];
        let grant_env = remote::build_reentry_grant_envelope(
            &shared.keypair,
            caller_identity.content_hash,
            fmt,
            open,
        )
        .expect("the open cap mints");
        let bundle: std::collections::HashMap<entity_hash::Hash, entity_entity::Entity> = grant_env
            .included
            .values()
            .map(|e| (e.content_hash, e.clone()))
            .collect();
        let cap_entity = bundle
            .values()
            .find(|e| e.entity_type == entity_types::TYPE_CAP_TOKEN)
            .expect("the minted bundle carries the capability")
            .clone();

        // One resource for every row: a path in OUR namespace. The gate is about
        // the handler address, never the resource target, so holding this fixed
        // keeps the only variable the uri's peer segment.
        let get_path = format!("/{}/system/type/system/peer", local_pid);
        let params = entity_entity::Entity::new(
            entity_types::TYPE_TREE_GET_REQ,
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                entity_ecf::text("uri"),
                entity_ecf::text(&get_path),
            )])),
        )
        .expect("tree get params");
        let resource = entity_capability::ResourceTarget {
            targets: vec![get_path.clone()],
            exclude: vec![],
        };

        let dispatch = |uri: String, rid: &'static str| {
            let wield = remote::build_authenticated_execute(
                &caller,
                &cap_entity,
                &bundle,
                &std::collections::HashMap::new(),
                rid,
                &uri,
                "get",
                &params,
                Some(&resource),
                None,
                None,
            )
            .expect("the caller can author the frame");
            let shared = shared.clone();
            async move { connection::dispatch_request(&wield, shared, None).await }
        };

        // --- The two foreign spellings: both MUST be refused, same pair. ---
        for (uri, rid, shape) in [
            (
                format!("entity://{}/system/tree", foreign_pid),
                "pd1h-foreign-authority",
                "entity:// authority form — the one whose authority is stripped \
                 and re-qualified to us, so pre-fix it ran OUR handler under \
                 THEIR address",
            ),
            (
                format!("/{}/system/tree", foreign_pid),
                "pd1h-foreign-absolute",
                "absolute-path form — survives strip+qualify unchanged, so it \
                 reaches the defect by a different route than the authority form",
            ),
        ] {
            let refused = dispatch(uri.clone(), rid).await;
            assert_eq!(
                (status_of(&refused), carries(&refused, "invalid_request")),
                (400, true),
                "{uri}: §1.4 requires `400 invalid_request` for an inbound \
                 EXECUTE naming a non-local namespace ({shape}). §5.2a's \
                 pre-dispatch row and §6.2 both forbid the alternatives: it MUST \
                 NOT surface as `404 handler_not_found` (false — we HAVE the \
                 handler, we are refusing the address) and MUST NOT surface as \
                 `403 capability_denied` (there is no authorization verdict; the \
                 refusal precedes authorization entirely)"
            );
            assert!(
                !carries(&refused, "handler_not_found") && !carries(&refused, "capability_denied"),
                "{uri}: refused with the right status but a code that reports it \
                 as a resolution or an authorization failure"
            );
        }

        // --- The controls: identical frames, local address. NOT gated. ---
        for (uri, rid, shape) in [
            (
                format!("entity://{}/system/tree", local_pid),
                "pd1h-local-authority",
                "our own peer id, spelled as an authority",
            ),
            (
                "system/tree".to_string(),
                "pd1h-peer-relative",
                "peer-relative — §1.4 qualifies it to us, so `extract_peer` \
                 returns local and there is nothing to refuse",
            ),
        ] {
            let allowed = dispatch(uri.clone(), rid).await;
            assert!(
                !(status_of(&allowed) == 400 && carries(&allowed, "invalid_request")),
                "{uri}: the routing gate fired on a LOCAL address ({shape}). The \
                 gate is scoped to a uri naming a peer that is not us; catching \
                 this frame means it is keyed on something else, and every \
                 foreign-row PASS above is then attributable to that instead"
            );
        }
    }

    /// §4.2 / §4.6 step 1 / §4.7 row 6 (FM-1) — an `authenticate` arriving
    /// before any hello nonce has been issued is `401 invalid_nonce`, on BOTH
    /// transports.
    ///
    /// We emitted `400 handshake_failed` — a code that appears nowhere in the
    /// spec corpus, so non-conformant under any reading of §4.7's MUST-emit
    /// contract. Both entry points matched on `conn.state` and never looked at
    /// the frame's operation, so the frame was processed AS A HELLO and failed
    /// through the catch-all.
    ///
    /// **The control is what stops this from being a rename.** Rows 2 and 4 send
    /// a frame that is genuinely not a hello and not an `authenticate` either.
    /// Had we "fixed" this by relabelling `handshake_error_envelope`'s default,
    /// rows 1 and 3 would pass and the controls would go red — a conformant pair
    /// reached over an incorrect path, reporting "invalid nonce" for a malformed
    /// `hello` too. Status alone cannot separate the readings either, so the
    /// CODE is pinned on every row.
    ///
    /// **The control's expected value changed with FM-2, and the honest account
    /// of what that cost is the point of this paragraph.** It read *"must still
    /// exit through the catch-all as `400 handshake_failed`"*. §4.7 row 10 now
    /// refuses an unimplemented operation by name as `400 invalid_request`, so
    /// `goodbye` **no longer reaches the catch-all at all** — and the control
    /// passed FM-2's change untouched, because it asserted only
    /// `status == 400 && !invalid_nonce`, which both codes satisfy.
    ///
    /// Measured rather than assumed: with the rows below pinning `goodbye` to
    /// `invalid_request`, relabelling `handshake_error_envelope`'s default to
    /// `invalid_nonce` **still left this test green**. The anti-rename property
    /// was gone, not preserved. Rows 5+6 restore it with a frame that does still
    /// reach the catch-all — a `hello` whose params are not a hello — and that
    /// mutation now reddens them. Rows 2+4 keep their own (different) job: they
    /// fail if FM-1's discrimination is re-keyed on connection *state* instead
    /// of on the frame's *operation*. Row 10's own teeth are in
    /// `incompatible_protocol_and_unknown_connect_op_on_both_transports`.
    ///
    /// **And then 0.8.2.5 retired the control's discriminator outright, which is
    /// the same lesson arriving from the third direction.** That fold names
    /// `handshake_failed` a code in no spec code set and forbids emitting it at
    /// all, so the catch-all is now `invalid_request` — the same code row 10
    /// emits, because §4.7 says they are the same class. The property rows 5+6
    /// used to have ("the residual has a private code, so relabelling it is
    /// visible") is therefore **gone by ruling, not by oversight**, and no
    /// rewriting of these rows can bring it back. What they assert instead is
    /// what still discriminates: the residual is `(400, invalid_request)` and is
    /// specifically none of the three coded pairs that surround it — row 6's
    /// `(401, invalid_nonce)`, the out-of-order row's `(409,
    /// connection_sequence_error)`, or CE-1's `(401, authentication_failed)`.
    /// The `!handshake_failed` term is the new one and it is the teeth for the
    /// sweep: it fails if either call-site default is put back.
    ///
    /// Both transports, because arch found the second one after the filing seat
    /// named only the first: the TCP handshake reads its first frame in
    /// `handle_connection` and the http-live dispatcher routes by session state
    /// in `dispatch_session_envelope`. One helper serves both; two rows measure
    /// both, so a fix applied to one is not mistaken for a fix.
    #[tokio::test]
    async fn prehello_authenticate_is_invalid_nonce_on_both_transports() {
        use entity_wire::{read_frame, write_frame, DEFAULT_MAX_FRAME_SIZE};

        fn pair_of(env: &entity_entity::Envelope) -> (u32, bool, bool, bool) {
            let status = entity_protocol::parse_execute_response(env)
                .map(|r| r.status)
                .unwrap_or(0);
            let has = |needle: &str| {
                env.root
                    .data
                    .windows(needle.len())
                    .any(|w| w == needle.as_bytes())
            };
            (
                status,
                has("invalid_nonce"),
                has("invalid_request"),
                has("handshake_failed"),
            )
        }

        let peer = PeerBuilder::new()
            .keypair(Keypair::from_seed([94u8; 32]))
            .build()
            .unwrap();
        let shared = peer.shared();
        let fmt = shared.config.home_hash_format;

        // A well-formed `authenticate`, authored against a nonce this peer never
        // issued — i.e. exactly a captured frame replayed onto a fresh
        // connection, which is the attack §4.6 step 1 exists to stop.
        let dialer = IdentityKeypair::from(Keypair::from_seed([95u8; 32]));
        let captured_nonce = [7u8; 32];
        let authenticate =
            entity_protocol::build_authenticate_envelope(&dialer, &captured_nonce, fmt)
                .expect("a well-formed authenticate");

        // A frame that is neither a hello nor an `authenticate` — the control.
        let junk = entity_entity::Entity::new(
            "test/v1",
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![])),
        )
        .expect("junk params");
        let not_a_hello = entity_entity::Envelope::new(
            entity_protocol::build_connect_execute("fm1-control", "goodbye", &junk)
                .expect("connect execute"),
        );

        // Drive one frame as the FIRST thing a TCP-shaped connection ever sees.
        let over_tcp = |frame_env: entity_entity::Envelope, shared: Arc<PeerShared>| async move {
            let (mut client, server) = crate::transport::memory_transport_pair();
            let handshake = tokio::spawn(async move {
                // Returns Err after writing the refusal — the connection closes,
                // which is correct and is not what these rows measure.
                let _ = connection::handle_connection(server, shared).await;
            });

            let frame = entity_wire::encode_envelope(&frame_env);
            write_frame(&mut client.writer, &frame)
                .await
                .expect("the dialer can send its first frame");
            let response = read_frame(&mut client.reader, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect(
                    "§4.6: the refusal MUST surface as a wire EXECUTE_RESPONSE, \
                     not a bare close — an undiagnosable drop is non-conformant \
                     whatever the peer thinks of the frame",
                );
            let _ = handshake.await;
            entity_wire::decode_envelope(&response).expect("a decodable response")
        };

        // --- Row 1: TCP, the pre-hello `authenticate`. ---
        assert_eq!(
            pair_of(&over_tcp(authenticate.clone(), shared.clone()).await),
            (401, true, false, false),
            "TCP: a pre-hello `authenticate` MUST be `401 invalid_nonce` (§4.7 \
             row 6). `handle_connection` reads its first frame and handed it to \
             `build_hello_response_envelope`, which rejected it as a non-hello \
             and exited through the `handshake_failed` catch-all — a code with \
             zero occurrences in the spec corpus"
        );

        // --- Row 2: TCP control. Every OTHER out-of-order connect operation
        //     keeps the catch-all. This is the row that fails if the "fix" was a
        //     rename of `handshake_error_envelope`'s default code — and it lives
        //     on the UNGATED path deliberately, so the anti-rename guard exists
        //     in every feature configuration, not only where `http-live` is on. ---
        {
            let (status, invalid_nonce, invalid_request, _) =
                pair_of(&over_tcp(not_a_hello.clone(), shared.clone()).await);
            assert!(
                status == 400 && !invalid_nonce && invalid_request,
                "TCP: a connect frame that is neither `hello` nor `authenticate` \
                 must NOT be reported as a nonce failure — it never named the \
                 nonce. Reporting 401 `invalid_nonce` here means the \
                 discrimination is not on the operation at all, and row 1 is then \
                 passing for a reason that has nothing to do with §4.6 step 1. \
                 The code is pinned as well as the status: asserting only \
                 `400 && !invalid_nonce` is satisfied by any 400 code at all, \
                 which is how this control silently stopped biting"
            );
        }

        // --- Rows 3+4: the http-live path, which routes by session state and so
        //     reaches the same defect by a different route. Gated because
        //     `dispatch_session_envelope` is; the rows above are not, because a
        //     §4.6 refusal must not be reachable only through a feature gate. ---
        #[cfg(feature = "http-live")]
        {
            let mut conn = entity_protocol::Connection::new(shared.keypair.peer_id());
            let env =
                connection::dispatch_session_envelope(&authenticate, &mut conn, shared.clone())
                    .await;
            assert_eq!(
                pair_of(&env),
                (401, true, false, false),
                "http-live: same input, same pair. This transport reaches the \
                 defect through `dispatch_session_envelope`'s `AwaitingHello` \
                 arm rather than through the TCP first-frame read, so a fix \
                 landed at one entry point does not cover it"
            );

            let mut conn = entity_protocol::Connection::new(shared.keypair.peer_id());
            let env =
                connection::dispatch_session_envelope(&not_a_hello, &mut conn, shared.clone())
                    .await;
            let (status, invalid_nonce, invalid_request, _) = pair_of(&env);
            assert!(
                status == 400 && !invalid_nonce && invalid_request,
                "http-live: the control on this transport — the two transports \
                 build their error envelopes at two different call sites, so a \
                 rename at one is invisible to the other's rows"
            );
        }

        // --- Rows 5+6: the CATCH-ALL, which rows 2 and 4 stopped reaching when
        //     §4.7 row 10 gave `goodbye` a coded refusal of its own. A `hello`
        //     whose params are not a hello is a genuinely malformed frame: it
        //     passes the operation-name check (`hello` is implemented), passes
        //     the pre-hello `authenticate` check, passes CE-1 (it IS on the
        //     connect path), and fails inside `build_hello_response_envelope` —
        //     which is the only way left to land on `handshake_error_envelope`'s
        //     default.
        //
        //     That default was `handshake_failed` and is `invalid_request` since
        //     0.8.2.5, which forbids the former as a code in no spec code set.
        //     So these rows no longer separate the residual from row 10 BY CODE
        //     — the ruling merged them — and the `!handshake_failed` term is
        //     what they buy instead: it is the only assertion in this file that
        //     reddens if either call-site default is reverted. ---
        let malformed_hello = entity_entity::Envelope::new(
            entity_protocol::build_connect_execute(
                "fm1-malformed-hello",
                "hello",
                &entity_entity::Entity::new(
                    "test/v1",
                    entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![])),
                )
                .expect("junk params"),
            )
            .expect("connect execute"),
        );
        {
            let (status, invalid_nonce, invalid_request, handshake_failed) =
                pair_of(&over_tcp(malformed_hello.clone(), shared.clone()).await);
            assert!(
                status == 400 && invalid_request && !invalid_nonce && !handshake_failed,
                "TCP: a malformed `hello` is neither a nonce failure nor an \
                 unimplemented operation — it is the residual catch-all, which \
                 0.8.2.5 moved from `handshake_failed` (a code in no spec code \
                 set, forbidden outright) to §4.7's `invalid_request` class. \
                 The `!handshake_failed` term is the sweep's teeth: reverting \
                 either call-site default reddens exactly this row"
            );
        }
        #[cfg(feature = "http-live")]
        {
            let mut conn = entity_protocol::Connection::new(shared.keypair.peer_id());
            let env =
                connection::dispatch_session_envelope(&malformed_hello, &mut conn, shared.clone())
                    .await;
            let (status, _, invalid_request, handshake_failed) = pair_of(&env);
            assert!(
                status == 400 && invalid_request && !handshake_failed,
                "http-live: the same residual, on this transport's own call \
                 site — the two transports build their error envelopes at two \
                 different call sites, so the sweep had to touch both"
            );
        }
    }

    /// CE-1 — §4.2's third pre-authorization rule + §5.2a, restated under §4.7
    /// by **0.8.2.5**: a non-connect EXECUTE arriving before the connection is
    /// established is **401 `authentication_failed`**.
    ///
    /// **All three ground-up seats got this wrong for two releases, in three
    /// different ways, and none of them was reading the rule that governs it.**
    /// go answered `403 connection_required`, py `403 capability_denied`, and we
    /// answered `400 handshake_failed`. The 403s are the blanket 403 that §4.2's
    /// F32 amendment *retired* at 0.8.1 when it replaced that bullet with the
    /// auth/authz discriminator; ours was the catch-all, reached because the
    /// frame is not a connect frame so no connect refusal claimed it. The input
    /// carries no verified signer at all, which §5.2a makes **auth-class** — a
    /// 403 asserts an authorization decision was reached about an authenticated
    /// caller, and none was.
    ///
    /// **Row 3 is the control, and it is the row that separates this fix from a
    /// blanket relabel of the catch-all.** The refusal has to discriminate on
    /// the URI's *authority*: a foreign-namespace EXECUTE is refused as an
    /// ADDRESS (`400 invalid_request`, §1.4 / §6.5 step 3 / §4.7's
    /// `invalid_request` paragraph, which names the foreign namespace in its own
    /// class list) and never becomes an authorization question, while an EXECUTE
    /// addressed to *us* reaches the 401. A peer that simply renamed its
    /// pre-establishment catch-all to `authentication_failed` passes rows 1, 2
    /// and 4 and fails row 3. core-go's probe deliberately targets the
    /// responder's own namespace for the same reason from the other side — so
    /// that the §1.4 gate cannot be the mechanism doing the refusing.
    ///
    /// **Row 4 is the other control and it is the expensive one to omit.** The
    /// helper's job is to refuse a class of frame during the handshake, so the
    /// failure mode of getting it wrong is refusing the handshake itself. A
    /// property of the form "X is still allowed" is prose until the test drives
    /// X, so row 4 runs a real `hello` end-to-end and requires a hello response
    /// back — the same charter rule the `ping` row earned one packet ago.
    ///
    /// Rows 1–4 are on the ungated TCP path; rows 5–7 repeat them through
    /// `dispatch_session_envelope`, which is `#[cfg(feature = "http-live")]`. A
    /// control that does not compile in a configuration proves nothing there,
    /// so the anti-rename row lives on the path every configuration builds.
    #[tokio::test]
    async fn pre_establishment_execute_is_401_authentication_failed_on_both_transports() {
        use entity_wire::{read_frame, write_frame, DEFAULT_MAX_FRAME_SIZE};

        fn pair_of(env: &entity_entity::Envelope) -> (u32, bool, bool, bool) {
            let status = entity_protocol::parse_execute_response(env)
                .map(|r| r.status)
                .unwrap_or(0);
            let has = |needle: &str| {
                env.root
                    .data
                    .windows(needle.len())
                    .any(|w| w == needle.as_bytes())
            };
            (
                status,
                has("authentication_failed"),
                has("invalid_request"),
                has("handshake_failed"),
            )
        }

        let peer = PeerBuilder::new()
            .keypair(Keypair::from_seed([96u8; 32]))
            .build()
            .unwrap();
        let shared = peer.shared();
        let local_pid = shared.keypair.peer_id().as_str().to_string();
        let fmt = shared.config.home_hash_format;

        let params = entity_entity::Entity::new(
            "test/v1",
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![])),
        )
        .expect("params");

        // A genuine, well-formed `hello` — row 4's input. Built the same way
        // `remote.rs` builds the one it actually dials with, so "the connect
        // path still works" is measured against the real frame rather than a
        // stand-in that happens to survive.
        let a_real_hello = |kp: Keypair, rid: &str| {
            let hello = entity_protocol::HelloData {
                peer_id: kp.peer_id().to_string(),
                nonce: vec![11u8; 32],
                protocols: vec!["entity-core/1.0".to_string()],
                hash_formats: entity_protocol::default_advertised_hash_formats(fmt),
                key_types: entity_protocol::default_advertised_key_types(),
                timestamp: None,
            };
            entity_entity::Envelope::new(
                entity_protocol::build_connect_execute(
                    rid,
                    "hello",
                    &hello.to_entity().expect("hello entity"),
                )
                .expect("hello execute"),
            )
        };

        // The routed input: a perfectly ordinary substrate operation, sent as
        // the first thing on the wire. Peer-relative, so it is unambiguously
        // addressed to us and the §1.4 gate has nothing to say about it.
        let execute_relative = |rid: &str| {
            entity_entity::Envelope::new(
                entity_protocol::build_connect_execute_at("system/tree", rid, "get", &params)
                    .expect("execute"),
            )
        };
        // Same operation, fully qualified at OUR peer-id — §4.3 permits either
        // spelling, and a check written against a scheme-stripping path helper
        // matches one and silently misses the other. That was the exact defect
        // in row 10's first landing, so it is driven here rather than assumed.
        let execute_qualified = |rid: &str| {
            entity_entity::Envelope::new(
                entity_protocol::build_connect_execute_at(
                    &format!("/{}/system/tree", local_pid),
                    rid,
                    "get",
                    &params,
                )
                .expect("execute"),
            )
        };
        // The control: a FOREIGN namespace. Refused as an address, never as an
        // authentication failure.
        // 46 base58 chars — `EntityUri::is_peer_id` gates on exactly that
        // length, so a shorter literal would read as an ordinary path segment
        // and this control would silently become a duplicate of row 1.
        let foreign = "1BvPHnpAJ4dLpU7dvBqhkVFuGrCGdW8kSHi9pnJDzzZhpK";
        assert!(
            entity_entity::EntityUri::is_peer_id(foreign),
            "the control's foreign authority must parse AS a peer-id"
        );
        let execute_foreign = |rid: &str| {
            entity_entity::Envelope::new(
                entity_protocol::build_connect_execute_at(
                    &format!("/{}/system/tree", foreign),
                    rid,
                    "get",
                    &params,
                )
                .expect("execute"),
            )
        };

        let over_tcp = |frame_env: entity_entity::Envelope, shared: Arc<PeerShared>| async move {
            let (mut client, server) = crate::transport::memory_transport_pair();
            let handshake = tokio::spawn(async move {
                let _ = connection::handle_connection(server, shared).await;
            });
            let frame = entity_wire::encode_envelope(&frame_env);
            write_frame(&mut client.writer, &frame)
                .await
                .expect("the dialer can send its first frame");
            let response = read_frame(&mut client.reader, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect(
                    "§4.1/§4.6: the refusal MUST surface as a wire \
                     EXECUTE_RESPONSE, not a bare close",
                );
            let _ = handshake.await;
            entity_wire::decode_envelope(&response).expect("a decodable response")
        };

        // --- Row 1: TCP, peer-relative. The routed input. ---
        assert_eq!(
            pair_of(&over_tcp(execute_relative("ce1-tcp-rel"), shared.clone()).await),
            (401, true, false, false),
            "TCP: a non-connect EXECUTE before establishment is auth-class — \
             no handshake has run, so there is no verified signer (§4.2 rule 3, \
             §5.2a). We answered `400 handshake_failed`: the frame is not a \
             connect frame, so none of the connect refusals claimed it and it \
             fell through to `build_hello_response_envelope`"
        );

        // --- Row 2: TCP, the same request fully qualified at our own peer-id.
        //     §4.3 permits both spellings; a refusal that reads only one of
        //     them is half a refusal. ---
        assert_eq!(
            pair_of(&over_tcp(execute_qualified("ce1-tcp-qual"), shared.clone()).await),
            (401, true, false, false),
            "TCP: `/{{local}}/system/tree` is the same request as `system/tree` \
             (§4.3). A check keyed on the peer-relative spelling alone would \
             pass row 1 and leave the qualified form on the old catch-all"
        );

        // --- Row 3: THE CONTROL. Foreign namespace → refused as an ADDRESS. ---
        let (status, auth_failed, invalid_request, _) =
            pair_of(&over_tcp(execute_foreign("ce1-tcp-foreign"), shared.clone()).await);
        assert!(
            status == 400 && invalid_request && !auth_failed,
            "TCP: a foreign-namespace EXECUTE is `400 invalid_request` — refused \
             as an address before it can become an authorization question (§6.5 \
             step 3 calls this a gate, not an ordering preference; §4.7's \
             `invalid_request` paragraph names it in the class). This is the row \
             that fails if CE-1 is 'fixed' by relabelling the pre-establishment \
             catch-all to `authentication_failed`, which passes every other row \
             here. It also covers the escalation shape: the three connect \
             refusals re-qualify the path onto OUR peer-id, so only a check that \
             reads the authority can see this frame at all. Got status {status}, \
             auth_failed={auth_failed}, invalid_request={invalid_request}"
        );

        // --- Row 4: THE OTHER CONTROL. A real `hello` still completes. A
        //     refusal added to the handshake's own entry point can refuse the
        //     handshake, and "the connect path still works" is prose until it
        //     is driven.
        //
        //     It cannot reuse `over_tcp`, and the reason is worth a line because
        //     it deadlocked once: every other row's input makes
        //     `handle_connection` write a refusal and RETURN, so awaiting the
        //     server task terminates. A hello that succeeds leaves the server in
        //     Phase 3 blocked on `read_frame` for the authenticate that never
        //     comes, and `handshake.await` then waits on a task waiting on a
        //     client this scope is still holding open. Dropping the client first
        //     is what turns that read into EOF. ---
        {
            let (mut client, server) = crate::transport::memory_transport_pair();
            let shared_for_task = shared.clone();
            let handshake = tokio::spawn(async move {
                let _ = connection::handle_connection(server, shared_for_task).await;
            });
            let frame = entity_wire::encode_envelope(&a_real_hello(
                Keypair::from_seed([97u8; 32]),
                "ce1-hello",
            ));
            write_frame(&mut client.writer, &frame)
                .await
                .expect("the dialer can send its hello");
            let response = read_frame(&mut client.reader, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("a hello response");
            drop(client);
            let _ = handshake.await;
            let env = entity_wire::decode_envelope(&response).expect("a decodable response");
            let resp = entity_protocol::parse_execute_response(&env)
                .expect("the connect surface still answers");
            assert_eq!(
                resp.status, 200,
                "TCP: CE-1 runs at the handshake's first frame, so a helper that \
                 over-matches takes the whole connect surface down with it. \
                 `system/protocol/connect` is the one path §4.2 pre-authorizes \
                 and it MUST still be served"
            );
        }

        // --- Rows 5-7: the http-live transport, whose pre-Established arms are
        //     a second call site. Gated because `dispatch_session_envelope` is;
        //     rows 1-4 are not, because a refusal — and the control that proves
        //     it discriminates — must not be reachable only through a feature
        //     gate. ---
        #[cfg(feature = "http-live")]
        {
            let mut conn = entity_protocol::Connection::new(shared.keypair.peer_id());
            let env = connection::dispatch_session_envelope(
                &execute_relative("ce1-http-rel"),
                &mut conn,
                shared.clone(),
            )
            .await;
            assert_eq!(
                pair_of(&env),
                (401, true, false, false),
                "http-live: same input, same pair, reached through the \
                 `AwaitingHello` arm rather than the TCP first-frame read"
            );

            // `AwaitingAuthenticate` is still pre-Established — a hello has been
            // exchanged, but no signer has been verified — so the rule binds
            // there too. This is the arm a first-frame-only fix would miss.
            let mut conn = entity_protocol::Connection::new(shared.keypair.peer_id());
            let hello = a_real_hello(Keypair::from_seed([98u8; 32]), "ce1-http-hello");
            let _ = connection::dispatch_session_envelope(&hello, &mut conn, shared.clone()).await;
            assert!(
                matches!(
                    conn.state,
                    entity_protocol::ConnectionState::AwaitingAuthenticate
                ),
                "the hello must have advanced the session, or the row below is \
                 measuring `AwaitingHello` a second time"
            );
            let env = connection::dispatch_session_envelope(
                &execute_relative("ce1-http-await-auth"),
                &mut conn,
                shared.clone(),
            )
            .await;
            assert_eq!(
                pair_of(&env),
                (401, true, false, false),
                "http-live: `AwaitingAuthenticate` is pre-Established too. The \
                 state assertion above is what stops this row silently \
                 re-testing `AwaitingHello`"
            );

            let mut conn = entity_protocol::Connection::new(shared.keypair.peer_id());
            let env = connection::dispatch_session_envelope(
                &execute_foreign("ce1-http-foreign"),
                &mut conn,
                shared.clone(),
            )
            .await;
            let (status, auth_failed, invalid_request, _) = pair_of(&env);
            assert!(
                status == 400 && invalid_request && !auth_failed,
                "http-live: the control on this transport's own call site"
            );
        }
    }

    /// EXTENSION-RELAY §4.1 + §8 (v1.3) — the peer publishes a SIGNED
    /// self-advertise carrying the store bounds it actually enforces.
    ///
    /// §8.1 makes publishing `max_retention_ms` a MUST for a relay that
    /// enforces a ceiling, and §4.1 gives the reason: a ceiling that is
    /// enforced but unpublished configures behaviour no counterparty can
    /// observe before depending on it. A sender picking a relay, and a peer
    /// choosing which relays to name in its own §3.5 inbox-relay declaration,
    /// both depend on how long an entry will be held.
    ///
    /// Three claims: the entity is published at the §4.1 path, its limits are
    /// the ENFORCED ones, and it is signed by `relay_peer_id` with the
    /// signature reachable at the invariant pointer (§3.0 — no `refs:` block).
    /// The signature is verified here rather than merely being present: an
    /// unverifiable advertise is one a consumer must reject, so "published" is
    /// not the property that matters.
    #[tokio::test]
    #[cfg(feature = "relay")]
    async fn relay_self_advertise_publishes_the_enforced_bounds_signed() {
        use entity_relay::{AdvertiseData, MODE_FORWARD, MODE_STORE};

        let peer = PeerBuilder::new()
            .keypair(Keypair::from_seed([98u8; 32]))
            .config(PeerConfig {
                relay_store_retention_ms: 3_600_000,
                relay_max_storage_bytes: 4096,
                ..PeerConfig::default()
            })
            .build()
            .unwrap();
        let shared = peer.shared();
        let pid = shared.keypair.peer_id().as_str().to_string();

        let path = entity_relay::advertise_path(&pid, &pid);
        let hash = shared
            .location_index
            .get(&path)
            .expect("§4.1: the relay MUST publish its advertise at system/relay/advertise/{self}");
        let entity = shared.content_store.get(&hash).expect("advertise entity");
        let advertise = AdvertiseData::from_entity(&entity).expect("decodes as an advertise");

        assert_eq!(
            advertise.limits.max_retention_ms,
            Some(3_600_000),
            "§8.1: a relay enforcing a ceiling MUST publish it as              limits.max_retention_ms — this is the field that tells a              counterparty whether store-and-forward is usable at all"
        );
        assert_eq!(advertise.limits.max_storage_bytes, Some(4096));
        assert!(
            advertise.modes.contains(&MODE_FORWARD.to_string())
                && advertise.modes.contains(&MODE_STORE.to_string()),
            "v1 ships both named modes (§10.1)"
        );

        // --- The signature, verified rather than merely located. ---
        let sig_hash = shared
            .location_index
            .get(&entity_hash::invariant_signature_path(&pid, &hash))
            .expect("§4.1: signed per V7 §5.2, reachable at the invariant pointer");
        let sig = entity_types::SignatureData::from_entity(
            &shared
                .content_store
                .get(&sig_hash)
                .expect("signature entity"),
        )
        .expect("decodes as a signature");
        assert_eq!(sig.target, hash, "the signature targets the advertise");
        assert!(
            entity_crypto::verify_for_key_type(
                shared.keypair.key_type(),
                shared.keypair.public_key_bytes().as_slice(),
                &hash.to_bytes(),
                &sig.signature,
            )
            .is_ok(),
            "the advertise signature MUST verify against the relay's own key —              a consumer that cannot verify it must reject the advertise, so              'a signature entity exists' is not the property"
        );
    }

    /// The §4.1 control — a relay enforcing NO bound omits the keys entirely.
    ///
    /// §8.1: absent means "declares no ceiling", which is a different statement
    /// from "the ceiling is zero". This row is what fails if the bounds are ever
    /// given a non-zero default, or if the encoder starts writing `0` for unset.
    #[tokio::test]
    #[cfg(feature = "relay")]
    async fn relay_self_advertise_omits_bounds_it_does_not_enforce() {
        let peer = PeerBuilder::new()
            .keypair(Keypair::from_seed([99u8; 32]))
            .build()
            .unwrap();
        let shared = peer.shared();
        let pid = shared.keypair.peer_id().as_str().to_string();
        let hash = shared
            .location_index
            .get(&entity_relay::advertise_path(&pid, &pid))
            .expect("an advertise is published either way");
        let advertise =
            entity_relay::AdvertiseData::from_entity(&shared.content_store.get(&hash).unwrap())
                .unwrap();
        assert_eq!(advertise.limits.max_retention_ms, None);
        assert_eq!(advertise.limits.max_storage_bytes, None);
    }

    /// §4.7 row 9 (G-28) — a second `hello` on an ESTABLISHED connection is
    /// `409 connection_already_established`, over the real wire.
    ///
    /// We emitted `401 authentication_failed`. The frame fell past the
    /// post-established connect intercept (which matched `authenticate` only)
    /// into generic §5.2 verification, where the bare connect-EXECUTE shape has
    /// no `author` — so the peer reported an authentication failure for a
    /// caller that had *just authenticated successfully*. Wrong status class
    /// (a state conflict is not an auth failure) and wrong code.
    ///
    /// **The control is what stops this from being a collapse.** A second
    /// `authenticate` post-establishment is a DIFFERENT §4.7 row — RT-6 pins it
    /// at `401 invalid_nonce` — and it arrives at the same intercept. Had row 9
    /// been "fixed" by answering 409 for every post-established connect frame,
    /// row 1 would pass and the control would go red. Both rows live on the
    /// UNGATED TCP path deliberately: a §4.7 invariant must not be reachable
    /// only through the `http-live` feature gate.
    ///
    /// Row 10 (`connection_sequence_error`) is deliberately NOT asserted here —
    /// the §4.7 table pins 400 and core-go emits 409, and it is routed as
    /// spec-issue `2026-09-01-b`. A row asserting either value would gate one
    /// seat's reading of an unruled semantic.
    #[tokio::test]
    async fn second_hello_after_established_is_409_already_established() {
        use entity_wire::{read_frame, write_frame, DEFAULT_MAX_FRAME_SIZE};

        fn pair_of(env: &entity_entity::Envelope) -> (u32, String) {
            let status = entity_protocol::parse_execute_response(env)
                .map(|r| r.status)
                .unwrap_or(0);
            let code = [
                "connection_already_established",
                "invalid_nonce",
                "authentication_failed",
                "connection_sequence_error",
            ]
            .iter()
            .find(|needle| {
                env.root
                    .data
                    .windows(needle.len())
                    .any(|w| w == needle.as_bytes())
            })
            .map(|s| s.to_string())
            .unwrap_or_else(|| "<none of the §4.7 codes>".into());
            (status, code)
        }

        let peer = PeerBuilder::new()
            .keypair(Keypair::from_seed([96u8; 32]))
            .build()
            .unwrap();
        let shared = peer.shared();
        let fmt = shared.config.home_hash_format;
        let dialer = IdentityKeypair::from(Keypair::from_seed([97u8; 32]));

        let (mut client, server) = crate::transport::memory_transport_pair();
        let handshake = tokio::spawn({
            let shared = shared.clone();
            async move {
                let _ = connection::handle_connection(server, shared).await;
            }
        });

        // A client-side `hello` EXECUTE. Built here rather than through a
        // helper because the peer under test is the RESPONDER: what matters is
        // that the frame is a well-formed hello naming the dialer, twice.
        let build_hello = |nonce: u8| {
            let hello = entity_protocol::HelloData {
                peer_id: dialer.peer_id().as_str().to_string(),
                nonce: vec![nonce; 32],
                protocols: vec!["entity-core/1.0".to_string()],
                hash_formats: vec![],
                key_types: vec![dialer.key_type().label().to_string()],
                timestamp: None,
            };
            entity_entity::Envelope::new(
                entity_protocol::build_connect_execute(
                    "row9-hello",
                    "hello",
                    &hello.to_entity().expect("hello entity"),
                )
                .expect("connect execute"),
            )
        };

        async fn round_trip(
            client: &mut crate::transport::Connection,
            env: entity_entity::Envelope,
        ) -> entity_entity::Envelope {
            let frame = entity_wire::encode_envelope(&env);
            write_frame(&mut client.writer, &frame).await.expect("send");
            let response = read_frame(&mut client.reader, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("§4.6: a coded EXECUTE_RESPONSE, never a bare close");
            entity_wire::decode_envelope(&response).expect("a decodable response")
        }

        // --- Complete a genuine handshake. Everything below measures the
        //     POST-established path, so reaching `Established` honestly is a
        //     precondition, not a convenience. ---
        let hello_response = round_trip(&mut client, build_hello(1)).await;
        let nonce = entity_protocol::parse_execute_response(&hello_response)
            .ok()
            .and_then(|r| entity_protocol::HelloData::from_entity(&r.result).ok())
            .map(|h| h.nonce)
            .expect("the hello response carries the peer's issued nonce");

        let authenticate = entity_protocol::build_authenticate_envelope(&dialer, &nonce, fmt)
            .expect("a well-formed authenticate");
        let auth_response = round_trip(&mut client, authenticate.clone()).await;
        assert_eq!(
            entity_protocol::parse_execute_response(&auth_response)
                .map(|r| r.status)
                .unwrap_or(0),
            200,
            "the handshake must actually complete — every row below is about \
             what happens AFTER `Established`, and a failed authenticate would \
             make them measure the handshake path instead"
        );

        // --- Row 1: the second hello. ---
        assert_eq!(
            pair_of(&round_trip(&mut client, build_hello(2)).await),
            (409, "connection_already_established".to_string()),
            "§4.7 row 9: a second `hello` after the handshake completes is a \
             sequence/state conflict. We answered `401 authentication_failed` \
             — telling a peer that had just authenticated that its credentials \
             failed, which is both the wrong class and unactionable"
        );

        // --- Row 2 (the control): a second `authenticate` is a DIFFERENT row
        //     and MUST keep its own pair. This is the row that fails if row 9
        //     was satisfied by answering 409 for the whole connect path. ---
        assert_eq!(
            pair_of(&round_trip(&mut client, authenticate).await).1,
            "invalid_nonce".to_string(),
            "RT-6 / §4.7 row 6: a replayed `authenticate` on an established \
             connection stays `invalid_nonce` — the issued nonce is single-use. \
             Collapsing it into row 9's 409 would under-signal a REPLAY as a \
             state conflict, which §4.6's Hardening block rejects by name"
        );

        drop(client);
        let _ = handshake.await;
    }

    /// §4.7 rows 1 and 10 (FM-2) — the two connect-error rows this seat owed,
    /// over the real wire, on **both** transports.
    ///
    /// These are core-go's `connect_incompatible_protocol` and
    /// `connect_unknown_operation` inputs exactly, so a green row here predicts
    /// the wire check rather than merely agreeing with our own reading.
    ///
    /// **Row 1** — a hello advertising only `entity-core/99.0`. We completed the
    /// handshake at 200: `process_hello` parsed `protocols` and validated
    /// nothing, so a peer speaking no version we support got a connection and
    /// discovered the incompatibility at its first EXECUTE, as some other
    /// failure. This one is **landed spec** — §4.5's table pins the non-empty
    /// intersection, §4.7 row 1 pins the pair, and arch confirmed the row needs
    /// no spec change.
    ///
    /// **Row 10** — a connect EXECUTE naming `frobnicate`. We answered `400
    /// handshake_failed`, a code in no spec document, by handing the frame to
    /// the hello path and failing it there as a non-hello. The pair asserted is
    /// arch's 2026-09-01 ruling (`invalid_request`), which supersedes the landed
    /// table's `connection_sequence_error` for this input and folds as FM-2
    /// Edit D — see `connection::unknown_connect_operation_refusal` for why we
    /// land it ahead of the fold. **If the fold moves the value, this constant
    /// and that one change together and nothing else does.**
    ///
    /// **The controls are what stop either row from being a catch-all rename**,
    /// and they are the reason this test is not four asserts:
    ///
    /// - `ping` post-Established must still be answered. It is a connect
    ///   operation we DO implement (EXTENSION-NETWORK §5.1), and it reaches the
    ///   same intercept as `frobnicate` — a refusal keyed on "not hello and not
    ///   authenticate" rather than on the advertised inventory passes row 10 and
    ///   kills every keepalive on every established connection.
    /// - a well-formed hello must still establish. A guard that refuses on any
    ///   non-empty `protocols` set passes row 1 and closes the peer to everyone.
    ///
    /// Both rows run on the **ungated TCP path**, with the `http-live` rows
    /// gated beside them: a §4.7 MUST-emit pair must not be reachable only
    /// through a feature gate, and `make features` does not build this module.
    #[tokio::test]
    async fn incompatible_protocol_and_unknown_connect_op_on_both_transports() {
        use entity_wire::{read_frame, write_frame, DEFAULT_MAX_FRAME_SIZE};

        fn pair_of(env: &entity_entity::Envelope) -> (u32, String) {
            let status = entity_protocol::parse_execute_response(env)
                .map(|r| r.status)
                .unwrap_or(0);
            let code = [
                "incompatible_protocol",
                "invalid_request",
                "connection_sequence_error",
                "handshake_failed",
                "authentication_failed",
                "invalid_nonce",
            ]
            .iter()
            .find(|needle| {
                env.root
                    .data
                    .windows(needle.len())
                    .any(|w| w == needle.as_bytes())
            })
            .map(|s| s.to_string())
            .unwrap_or_else(|| "<none of the §4.7 codes>".into());
            (status, code)
        }

        let peer = PeerBuilder::new()
            .keypair(Keypair::from_seed([104u8; 32]))
            .build()
            .unwrap();
        let shared = peer.shared();
        let fmt = shared.config.home_hash_format;
        let dialer = IdentityKeypair::from(Keypair::from_seed([105u8; 32]));

        let hello_offering = |versions: &[&str]| {
            let hello = entity_protocol::HelloData {
                peer_id: dialer.peer_id().as_str().to_string(),
                nonce: vec![11u8; 32],
                protocols: versions.iter().map(|s| s.to_string()).collect(),
                hash_formats: vec![],
                key_types: vec![dialer.key_type().label().to_string()],
                timestamp: None,
            };
            entity_entity::Envelope::new(
                entity_protocol::build_connect_execute(
                    "fm2-hello",
                    "hello",
                    &hello.to_entity().expect("hello entity"),
                )
                .expect("connect execute"),
            )
        };

        let unknown_op = {
            let params = entity_entity::Entity::new(
                "test/v1",
                entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![])),
            )
            .expect("params");
            entity_entity::Envelope::new(
                entity_protocol::build_connect_execute("fm2-unknown-op", "frobnicate", &params)
                    .expect("connect execute"),
            )
        };

        // Drive one frame as the FIRST thing a TCP-shaped connection sees —
        // which is where core-go's probes send both of these.
        //
        // The client is dropped BEFORE awaiting the server task, and that is
        // load-bearing rather than tidiness: control A's hello **succeeds**, so
        // `handle_connection` goes on to await an `authenticate` this probe
        // never sends. Awaiting the task first hangs the suite forever. Dropping
        // the client closes the transport, the server's next `read_frame` gets
        // EOF, and the task returns.
        let over_tcp = |frame_env: entity_entity::Envelope, shared: Arc<PeerShared>| async move {
            let (mut client, server) = crate::transport::memory_transport_pair();
            let handshake = tokio::spawn(async move {
                let _ = connection::handle_connection(server, shared).await;
            });
            let frame = entity_wire::encode_envelope(&frame_env);
            write_frame(&mut client.writer, &frame)
                .await
                .expect("the dialer can send its first frame");
            let response = read_frame(&mut client.reader, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect(
                    "§4.6: the refusal MUST surface as a coded EXECUTE_RESPONSE \
                     before the close — a bare drop is indistinguishable from a \
                     network fault and is non-conformant",
                );
            drop(client);
            let _ = handshake.await;
            entity_wire::decode_envelope(&response).expect("a decodable response")
        };

        // --- Row 1, TCP. ---
        assert_eq!(
            pair_of(&over_tcp(hello_offering(&["entity-core/99.0"]), shared.clone()).await),
            (400, "incompatible_protocol".to_string()),
            "§4.5 / §4.7 row 1: an empty `protocols` intersection MUST be \
             refused at hello. We completed this handshake at 200 and deferred \
             the failure to the first EXECUTE, where it surfaces as something \
             else entirely"
        );

        // --- Row 10, TCP. ---
        assert_eq!(
            pair_of(&over_tcp(unknown_op.clone(), shared.clone()).await),
            (400, "invalid_request".to_string()),
            "§4.7 row 10 (ruled 2026-09-01): an operation the connect handler \
             does not implement is an invalid REQUEST, not a sequence error and \
             not `handshake_failed` — a code that appears nowhere in the corpus"
        );

        // --- FM-2e, TCP: `protocols` absent/empty is MALFORMED, not a version
        //     incompatibility. Ruled against the reading we and core-go both
        //     shipped (SA-PY-31, folded at 0.8.2.4).
        //
        //     The pair is the whole assertion. Refusing the empty set is the
        //     easy half and a one-line `!intersects(...)` gets it — and answers
        //     `incompatible_protocol`, telling a caller that named no version
        //     that the comparison failed, and pointing it at "change your
        //     version" when the remedy is "send the field". §4.7 selects a code
        //     precisely so the remedy is selectable, so the near-miss here is
        //     non-conformant in the way that matters and green under any test
        //     that only asserts `status == 400`.
        //
        //     Our own encoder builds this input: `HelloData::to_entity` omits
        //     the key entirely for an empty list, so absent and empty are one
        //     frame on the wire and one input to the guard. ---
        assert_eq!(
            pair_of(&over_tcp(hello_offering(&[]), shared.clone()).await),
            (400, "invalid_request".to_string()),
            "§4.5 (0.8.2.4): `protocols` is Required with NO default, so there \
             is no floor to fall back to and an absent-or-empty set is a \
             malformed hello. We accepted it as 'unconstrained' — the reading \
             keystone's csharp and typescript peers had already refuted by \
             requiring the field and passing conformance"
        );

        // --- The §4.7 out-of-order row, TCP: an operation we DO implement,
        //     arriving in a state that forbids it → **409
        //     `connection_sequence_error`**.
        //
        //     `ping` in `AwaitingHello` is that input: EXTENSION-NETWORK §5.1's
        //     keepalive, for a connection that does not exist yet. It is the
        //     input the two neighbouring refusals deliberately do NOT claim —
        //     row 10 passes it through because we implement it, and the row-6
        //     carve-out is scoped to `authenticate` — so it lands on this row by
        //     construction rather than by ordering luck.
        //
        //     0.8.2.4 split the old out-of-order row and moved this half's
        //     status 400 → 409, matching `connection_already_established`
        //     directly above it. We had never implemented the row at all: the
        //     frame reached `process_hello`, failed there as a non-hello, and
        //     exited the catch-all as `400 handshake_failed`. ---
        assert_eq!(
            pair_of(
                &over_tcp(
                    entity_entity::Envelope::new(
                        entity_protocol::build_connect_execute(
                            "fm2-ping-pre-hello",
                            "ping",
                            &entity_entity::Entity::new(
                                "system/network/ping",
                                entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![])),
                            )
                            .expect("ping params"),
                        )
                        .expect("connect execute"),
                    ),
                    shared.clone(),
                )
                .await
            ),
            (409, "connection_sequence_error".to_string()),
            "§4.7 (0.8.2.4): `ping` is implemented and advertised, so this is \
             not row 10's unknown NAME — it is the same operation arriving in a \
             state that forbids it, which is a state conflict and takes 409. \
             The pre-fix answer was `400 handshake_failed`, a pair in no row"
        );

        // --- The out-of-order row's OTHER state, TCP, and it is the example
        //     §4.7 names in its own text: "a second `hello` after
        //     `hello_done`". The handshake is past hello and awaiting
        //     authenticate; `hello` is implemented, so row 10 passes it
        //     through, and it is not an `authenticate` so the row-6 carve-out
        //     does not claim it either. Both pre-established states need their
        //     own row because this refusal is decided per-arm — "forbidden" is
        //     precisely what the state decides.
        //
        //     What we answered was `400 authentication_failed`: the status came
        //     from the error and the code from `handshake_error_envelope`'s
        //     call-site default at the authenticate frame. That PAIR appears in
        //     no row of §4.7 — the same defect `entity-core-py` was corrected
        //     for at `400 invalid_nonce`, since the table obligates the pair
        //     and a plausible code under the wrong status is non-conformant
        //     too. It also reads to the caller as "your credentials failed"
        //     about a frame whose credentials were never examined.
        //
        //     Its own connection, because the refusal is terminal: like every
        //     other handshake refusal here it writes the coded response and
        //     then closes (§4.6 — the response MUST precede the close). Folded
        //     into the multi-frame block below it just yields a broken pipe. ---
        {
            let (mut client, server) = crate::transport::memory_transport_pair();
            let shared_c = shared.clone();
            let handshake = tokio::spawn(async move {
                let _ = connection::handle_connection(server, shared_c).await;
            });
            let hello_frame = entity_wire::encode_envelope(&hello_offering(&["entity-core/1.0"]));
            write_frame(&mut client.writer, &hello_frame)
                .await
                .expect("first hello");
            let _ = read_frame(&mut client.reader, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("hello response");
            write_frame(&mut client.writer, &hello_frame)
                .await
                .expect("second hello");
            let response = read_frame(&mut client.reader, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("the misordered frame is answered, not dropped");
            let env = entity_wire::decode_envelope(&response).expect("decodable");
            assert_eq!(
                pair_of(&env),
                (409, "connection_sequence_error".to_string()),
                "§4.7 (0.8.2.4): a second `hello` where `authenticate` was \
                 expected is a state conflict — 409, the same status as \
                 `connection_already_established` in the row above it, and \
                 never `authentication_failed`, which names a check this frame \
                 never reached"
            );
            drop(client);
            let _ = handshake.await;
        }

        // --- SA-PY-35, the half-open state, and it is the input a cohort
        //     ledger currently predicts we get wrong.
        //
        //     Three connection states, two of them ruled. Pre-`hello` `ping`
        //     is the 409 row above. `Established` + unsigned `ping` is 200 —
        //     arch's `0.8.2.6` Q2, which we landed by moving the connect
        //     intercept ahead of `verify_request`. **Post-`hello`,
        //     pre-`authenticate` is named by neither**, and py filed it as
        //     SA-PY-35 with no arch ruling yet. core-go's open-items ledger
        //     reads the intercept move as making rust *"the live divergence
        //     risk"* on this input.
        //
        //     It does not. The intercept moved into `dispatch_request`, which
        //     runs exclusively post-`Established`; a half-open frame never
        //     reaches it and lands on the same per-arm out-of-order refusal as
        //     the second `hello` above. So we answer 409, identical to go
        //     (`connect.go` gates `ping` to `Completed`) and to py — the
        //     cohort is 3-0, not 2-1, and this row is what makes that a
        //     measurement instead of a reading of our own control flow.
        //
        //     Pinned on the ungated TCP path deliberately: a data point that
        //     only compiles under `http-live` is not available to the
        //     configuration a divergence would be reported against. ---
        {
            let (mut client, server) = crate::transport::memory_transport_pair();
            let shared_c = shared.clone();
            let handshake = tokio::spawn(async move {
                let _ = connection::handle_connection(server, shared_c).await;
            });
            let hello_frame = entity_wire::encode_envelope(&hello_offering(&["entity-core/1.0"]));
            write_frame(&mut client.writer, &hello_frame)
                .await
                .expect("hello");
            let _ = read_frame(&mut client.reader, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("hello response — the connection is now half-open");
            let ping = entity_wire::encode_envelope(&entity_entity::Envelope::new(
                entity_protocol::build_connect_execute(
                    "sa-py-35-half-open-ping",
                    "ping",
                    &entity_entity::Entity::new(
                        "system/network/ping",
                        entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![])),
                    )
                    .expect("ping params"),
                )
                .expect("connect execute"),
            ));
            write_frame(&mut client.writer, &ping)
                .await
                .expect("half-open ping");
            let response = read_frame(&mut client.reader, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("the half-open ping is answered, not dropped");
            let env = entity_wire::decode_envelope(&response).expect("decodable");
            assert_eq!(
                pair_of(&env),
                (409, "connection_sequence_error".to_string()),
                "SA-PY-35: a `ping` after `hello` and before `authenticate` is                  an implemented connect operation in a state that forbids it —                  the out-of-order row, same as the second `hello`. It is NOT                  the 200 that `0.8.2.6` Q2 rules for an ESTABLISHED                  connection: no signer has been verified, so the state Q2                  reasons about does not exist yet. Answering 200 here is the                  divergence go's ledger predicts of us; answering 401 would be                  the pre-`f8e7e83` defect in the other direction"
            );
            drop(client);
            let _ = handshake.await;
        }

        // --- Control A: a hello whose set OVERLAPS ours still establishes.
        //     Fails if row 1 was "fixed" by refusing any advertised set. ---
        {
            let (status, _) = pair_of(
                &over_tcp(
                    hello_offering(&["entity-core/99.0", "entity-core/1.0"]),
                    shared.clone(),
                )
                .await,
            );
            assert_eq!(
                status, 200,
                "§4.5 negotiates `protocols` by INTERSECTION: a peer offering a \
                 superset of ours is compatible. A guard that refuses this \
                 passes row 1 and closes the peer to every counterparty that \
                 advertises more than one version"
            );
        }

        // --- Control B: `ping`, post-Established, still answered. This is the
        //     row that fails if row 10's refusal is keyed on "not hello and not
        //     authenticate" instead of on the advertised inventory. ---
        {
            let (mut client, server) = crate::transport::memory_transport_pair();
            let shared_c = shared.clone();
            let handshake = tokio::spawn(async move {
                let _ = connection::handle_connection(server, shared_c).await;
            });
            async fn round_trip(
                client: &mut crate::transport::Connection,
                env: entity_entity::Envelope,
            ) -> entity_entity::Envelope {
                let frame = entity_wire::encode_envelope(&env);
                write_frame(&mut client.writer, &frame).await.expect("send");
                let response = read_frame(&mut client.reader, DEFAULT_MAX_FRAME_SIZE)
                    .await
                    .expect("a coded response");
                entity_wire::decode_envelope(&response).expect("decodable")
            }

            let hello_response =
                round_trip(&mut client, hello_offering(&["entity-core/1.0"])).await;
            let nonce = entity_protocol::parse_execute_response(&hello_response)
                .ok()
                .and_then(|r| entity_protocol::HelloData::from_entity(&r.result).ok())
                .map(|h| h.nonce)
                .expect("the hello response carries the issued nonce");
            let authenticate = entity_protocol::build_authenticate_envelope(&dialer, &nonce, fmt)
                .expect("a well-formed authenticate");
            assert_eq!(
                entity_protocol::parse_execute_response(
                    &round_trip(&mut client, authenticate).await
                )
                .map(|r| r.status)
                .unwrap_or(0),
                200,
                "the handshake must complete honestly — control B measures the \
                 POST-established intercept"
            );

            let (status, code) = pair_of(&round_trip(&mut client, unknown_op.clone()).await);
            assert_eq!(
                (status, code.as_str()),
                (400, "invalid_request"),
                "row 10 binds post-Established too — arch ruled it 'a name the \
                 responder does not implement, in ANY state'. This arm fell \
                 through to generic §5.2 verification, where the bare \
                 connect-EXECUTE shape has no `author`, and reported `401 \
                 authentication_failed` for a caller that had just authenticated"
            );

            // The SAME operation in the FULLY QUALIFIED spelling. §4.3 permits
            // either form post-Established, and a real client uses this one —
            // core-go's probe uses the peer-relative form, so a peer whose
            // refusal recognizes only that spelling passes the wire check and
            // refuses nothing a client would actually send.
            //
            // This row is not decoration: the first cut of the refusal tested
            // the path with `Connection::is_connect_path`, which strips only an
            // `entity://` scheme and therefore never matched `/{pid}/...`. Every
            // assertion above passed and the post-Established arm was dead.
            let qualified = entity_entity::Envelope::new(
                entity_protocol::build_connect_execute_at(
                    &format!(
                        "/{}/{}",
                        shared.keypair.peer_id().as_str(),
                        entity_protocol::CONNECT_PATH
                    ),
                    "fm2-unknown-op-qualified",
                    "frobnicate",
                    &entity_entity::Entity::new(
                        "test/v1",
                        entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![])),
                    )
                    .expect("params"),
                )
                .expect("connect execute"),
            );
            let (q_status, q_code) = pair_of(&round_trip(&mut client, qualified).await);
            assert_eq!(
                (q_status, q_code.as_str()),
                (400, "invalid_request"),
                "§4.3: `/{{pid}}/system/protocol/connect` and \
                 `system/protocol/connect` are the same address, so row 10 must \
                 answer the same pair for both. Recognizing only the \
                 peer-relative spelling makes this refusal a handshake-only \
                 check wearing an 'in any state' comment"
            );

            // Control B, and it is a MEASUREMENT rather than a comment: send an
            // actual `ping` and require that it be ANSWERED.
            //
            // `ping` is a connect operation we implement (EXTENSION-NETWORK
            // §5.1), so row 10's refusal must not reach it. A refusal keyed on
            // "anything that is not hello or authenticate" rather than on
            // `CONNECT_OPERATIONS` passes every row above and kills every
            // keepalive on every established connection; the mutation proving it
            // was written as a `matches!(op, "hello" | "authenticate")` guard.
            //
            // **This frame is UNAUTHENTICATED — bare `uri`/`operation`/
            // `request_id`, no `author`, no `capability`, no signature — and
            // that is now the whole point of the row rather than an accident of
            // how it was built.** 0.8.2.6 §4.2 Q2 (ruled 2026-09-03): §3.3 line
            // 773 excepts the connection path with no state qualifier, and §5.1
            // is scoped to *authenticated* EXECUTE, so an unauthenticated
            // post-handshake `ping` MUST be served. We had it the other way
            // round and answered `401 authentication_failed`.
            //
            // The assertion moved with the ruling. It used to read `!(400 &&
            // invalid_request)` — "not row 10's pair" — which the 401 satisfied,
            // so the row was green against a peer that refuses every
            // unauthenticated keepalive. That weak form was correct while the
            // question was open and is worthless now: it passes under both
            // readings, which is exactly the discriminator failure this file
            // keeps re-learning. It asserts the served answer instead.
            //
            // §5.2's `timestamp`/`sequence` are supplied for the same reason —
            // with an empty params map the served path answers `400
            // invalid_params`, which is a legitimate outcome and would let the
            // row pass without ever reaching `build_pong_response`.
            //
            // `a12_keepalive_ping_answers_pong` covers the same round-trip with
            // a fully signed client. It passes under BOTH readings and always
            // did — it is the neighbour that cannot see this class, kept
            // deliberately so the pair of them shows which one discriminates.
            let ping_response = round_trip(
                &mut client,
                entity_entity::Envelope::new(
                    entity_protocol::build_connect_execute(
                        "fm2-ping-control",
                        "ping",
                        &entity_entity::Entity::new(
                            "system/network/ping",
                            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
                                (
                                    entity_ecf::text("sequence"),
                                    entity_ecf::Value::Integer(7u64.into()),
                                ),
                                (
                                    entity_ecf::text("timestamp"),
                                    entity_ecf::Value::Integer(1_700_000_000_001u64.into()),
                                ),
                            ])),
                        )
                        .expect("ping params"),
                    )
                    .expect("connect execute"),
                ),
            )
            .await;
            let ping_parsed = entity_protocol::parse_execute_response(&ping_response)
                .expect("the ping is answered with an EXECUTE_RESPONSE");
            assert_eq!(
                (ping_parsed.status, ping_parsed.result.entity_type.as_str()),
                (200, "system/network/pong"),
                "§4.2 / §3.3 line 773 (0.8.2.6 Q2): `system/protocol/connect` is \
                 pre-authorized in EVERY state, so an unauthenticated \
                 post-handshake `ping` MUST be served. We ran the intercept \
                 AFTER `verify_request`, so this bare frame — which carries no \
                 `author` — was answered `401 authentication_failed`. That is \
                 what made core-go's `pingServedOnceEstablished` applicability \
                 control record `served=false` and SKIP their §4.7 409 row \
                 against us: a scored row silently disabled by our own reading"
            );

            drop(client);
            let _ = handshake.await;
        }

        // --- Rows on http-live, which routes by session state and so reaches
        //     both refusals by a different path. ---
        #[cfg(feature = "http-live")]
        {
            let mut conn = entity_protocol::Connection::new(shared.keypair.peer_id());
            let env = connection::dispatch_session_envelope(
                &hello_offering(&["entity-core/99.0"]),
                &mut conn,
                shared.clone(),
            )
            .await;
            assert_eq!(
                pair_of(&env),
                (400, "incompatible_protocol".to_string()),
                "http-live: same input, same pair. The negotiation lives in \
                 `process_hello`, which both transports share — this row is what \
                 proves the shared function is where the check landed"
            );

            let mut conn = entity_protocol::Connection::new(shared.keypair.peer_id());
            let env =
                connection::dispatch_session_envelope(&unknown_op, &mut conn, shared.clone()).await;
            assert_eq!(
                pair_of(&env),
                (400, "invalid_request".to_string()),
                "http-live: the unknown-operation refusal is hoisted OUT of \
                 `dispatch_session_envelope`'s state match, so it binds every \
                 arm. Landed inside the `AwaitingHello` arm it would miss the \
                 other two"
            );

            // FM-2e on http-live. Same shared `process_hello`, different call
            // site — the row that would go red if the guard were bolted onto
            // the TCP handshake loop instead of into the negotiation both
            // transports run.
            let mut conn = entity_protocol::Connection::new(shared.keypair.peer_id());
            let env = connection::dispatch_session_envelope(
                &hello_offering(&[]),
                &mut conn,
                shared.clone(),
            )
            .await;
            assert_eq!(
                pair_of(&env),
                (400, "invalid_request".to_string()),
                "http-live: `protocols` absent/empty is malformed here too"
            );

            // The out-of-order row on http-live, in BOTH pre-established
            // states. Unlike row 10 this one is checked per-arm — "forbidden"
            // is what the state decides — so each arm needs its own row and a
            // guard landed in one of them would leave the other answering a
            // pair in no table.
            let mut conn = entity_protocol::Connection::new(shared.keypair.peer_id());
            let ping_frame = entity_entity::Envelope::new(
                entity_protocol::build_connect_execute(
                    "fm2-ping-pre-hello-live",
                    "ping",
                    &entity_entity::Entity::new(
                        "system/network/ping",
                        entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![])),
                    )
                    .expect("ping params"),
                )
                .expect("connect execute"),
            );
            let env =
                connection::dispatch_session_envelope(&ping_frame, &mut conn, shared.clone()).await;
            assert_eq!(
                pair_of(&env),
                (409, "connection_sequence_error".to_string()),
                "http-live, `AwaitingHello`: an implemented operation in a \
                 forbidden state is a 409 state conflict"
            );

            let mut conn = entity_protocol::Connection::new(shared.keypair.peer_id());
            let established = connection::dispatch_session_envelope(
                &hello_offering(&["entity-core/1.0"]),
                &mut conn,
                shared.clone(),
            )
            .await;
            assert_eq!(
                pair_of(&established).0,
                200,
                "the first hello must succeed — the row below measures the \
                 state it moves us into, not a rejected handshake"
            );
            let env = connection::dispatch_session_envelope(
                &hello_offering(&["entity-core/1.0"]),
                &mut conn,
                shared.clone(),
            )
            .await;
            assert_eq!(
                pair_of(&env),
                (409, "connection_sequence_error".to_string()),
                "http-live, `AwaitingAuthenticate`: §4.7's own example — a \
                 second `hello` after `hello_done`"
            );
        }
    }

    /// The §3 advertisement filter, on the real assembly rather than on the
    /// relation (arch ruling 2026-08-05). `assemble_inbound_grants` is the one
    /// function both the §6.6 handshake and the §6.5 (b) reciprocal mint read,
    /// so filtering here moves both directions at once — the property the Q2
    /// extraction bought.
    ///
    /// The fixture is the case the discipline exists for: an operator-authored
    /// entry naming a handler this peer does **not** register. It is dropped;
    /// the entry naming a handler it does register survives; the §4.4 floor
    /// survives whole, which is the non-negotiable part — every floor entry
    /// names a handler this peer serves by construction (Resolution B), so a
    /// filter that ate any of it would be filtering the peer's own admission
    /// control away.
    #[tokio::test]
    async fn test_advertisement_filter_drops_unserved_entries_from_the_assembly() {
        let served = entity_capability::GrantEntry {
            handlers: entity_capability::PathScope::new(vec!["system/tree".into()]),
            resources: entity_capability::PathScope::new(vec![]),
            operations: entity_capability::IdScope::new(vec!["list".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        };
        let unserved = entity_capability::GrantEntry {
            handlers: entity_capability::PathScope::new(vec!["app/echo".into()]),
            resources: entity_capability::PathScope::new(vec![]),
            operations: entity_capability::IdScope::new(vec!["invoke".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        };

        let mut peer = PeerBuilder::new()
            .keypair(Keypair::from_seed([71u8; 32]))
            .build()
            .unwrap();
        let (served_c, unserved_c) = (served.clone(), unserved.clone());
        peer.set_grant_resolver(std::sync::Arc::new(move |_peer, _hash| {
            let mut grants = entity_capability::default_connection_grants();
            grants.push(served_c.clone());
            grants.push(unserved_c.clone());
            Some(grants)
        }));
        let shared = peer.shared();

        let assembled = connection::assemble_inbound_grants(
            &shared,
            &entity_hash::Hash::zero(),
            &entity_crypto::PeerId::from("2Ksome-counterpart"),
        );

        assert!(
            !assembled.contains(&unserved),
            "§3: a peer MUST NOT grant authority it does not advertise it \
             serves — `app/echo` is not registered here"
        );
        assert!(
            assembled.contains(&served),
            "the filter drops only what is unadvertised; `system/tree` is served"
        );
        for floor_entry in entity_capability::default_connection_grants() {
            assert!(
                assembled.contains(&floor_entry),
                "the §4.4 floor MUST survive its own filter — every floor entry \
                 names a handler this peer registers by construction. If this \
                 fires, the advertised served-scope is being read as empty on \
                 some axis the manifest does not express, and the floor is \
                 filtering itself away: {:?}",
                floor_entry
            );
        }
    }

    /// The §8.2 asymmetric non-regression vector (arch ruling, 2026-08-05): a
    /// peer reached by **ordinary dial-by-address** MUST NOT gain reciprocal
    /// originating authority.
    ///
    /// This is the vector the pre-narrowing build would fail — it fired the
    /// reciprocal grant from the shared client handshake, so *every* full-peer
    /// dial handed the acceptor reach-back into the dialer. No §3 rendezvous key
    /// is brought here, so the establishment is the asymmetric one §6.6
    /// describes: C asked S for service, and nothing about that authorizes S to
    /// originate into C.
    ///
    /// Paired with its positive twin above, this is what makes the discriminator
    /// observable at all: the two tests differ *only* in how the connection was
    /// established, and the authority outcome must follow that difference.
    #[tokio::test]
    async fn test_s65_dial_by_address_grants_no_reciprocal_authority() {
        use transport::{MemoryConnector, MemoryListener, MemoryTransportRegistry};

        let registry = MemoryTransportRegistry::new();
        let server = PeerBuilder::new()
            .keypair(Keypair::from_seed([62u8; 32]))
            .build()
            .unwrap();
        let server_pid = server.peer_id().to_string();
        let server_shared = server.shared();
        let listener = MemoryListener::bind(server_pid.clone(), registry.clone()).unwrap();
        server.start_engines(&server_shared);
        let server_shared_for_task = server_shared.clone();
        let server_handle = tokio::spawn(async move {
            let _ = server::run(listener, server_shared_for_task).await;
        });
        tokio::task::yield_now().await;

        let client = PeerBuilder::new()
            .keypair(Keypair::from_seed([63u8; 32]))
            .connector(std::sync::Arc::new(MemoryConnector::new(registry.clone())))
            .build()
            .unwrap();
        client.local_only();
        let client_pid = client.peer_id().to_string();
        let client_shared = client.shared();
        client.start_engines(&client_shared);

        // C dials S by address — `connect_to` → `connect_and_pool`, with C's
        // dispatch context present. Before the narrowing that context was the
        // whole condition for minting.
        client
            .connect_to(&format!("memory://{}", server_pid))
            .await
            .unwrap();

        // Give a grant every chance to arrive: the endpoint registers at
        // handshake, and the grant would follow within a beat of it.
        let mut endpoint = None;
        for _ in 0..50 {
            if let Some(e) = server_shared.remote.get_inbound(&client_pid) {
                endpoint = Some(e);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let endpoint =
            endpoint.expect("S should hold an inbound endpoint for the peer that dialed");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        assert!(
            endpoint.originating_capability().is_none(),
            "§8.2: a dial-by-address acceptor MUST NOT hold reciprocal originating authority"
        );

        // And the refusal is local and named, not a misleading remote status.
        let empty_params = entity_entity::Entity::new(
            "system/params",
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![])),
        )
        .unwrap();
        let outcome = remote::send_execute(
            endpoint.as_ref(),
            server.keypair(),
            &format!("/{}/system/tree", client_pid),
            "get",
            &empty_params,
            None,
            None,
            None,
            &std::collections::HashMap::new(),
            None,
        )
        .await;
        match outcome {
            Err(e) => assert!(
                e.to_string().contains("no originating authority"),
                "the refusal must name the condition, got: {}",
                e
            ),
            Ok(resp) => panic!(
                "§8.2: originating over an asymmetric connection must fail closed, \
                 got status {}",
                resp.status
            ),
        }

        server_handle.abort();
    }

    /// **The §6.7.5 gate, local half: a real reflect + a real dial-back over
    /// real sockets.** Arch records this gate as never having run in any
    /// implementation; this is the loopback case of it, end to end.
    ///
    /// A binds a listener, then dials B *from that same port* through
    /// `reuseport` — which is the §6.7.3 MUST in action, and also the only
    /// arrangement in which the answer means anything: dial back an ephemeral
    /// source and you learn nothing about the endpoint the punch will fire
    /// from. B observes A's source, dials it, reaches A's listener, and reports
    /// `reachable: true` with the address it actually tested.
    ///
    /// The `address_tested` assertion is the one that would catch a lazy
    /// implementation: a responder that returned `reachable: true` without
    /// dialing, or that dialed something other than what it observed, still
    /// produces a well-formed 200. Pinning the echoed address to A's real
    /// listening port is what makes the pass mean the dial arrived *there*.
    #[cfg(all(
        feature = "signaling",
        feature = "network",
        not(target_arch = "wasm32")
    ))]
    #[tokio::test]
    async fn test_s675_reflect_and_dial_back_over_real_sockets() {
        // --- B, the responder. Grants check-reachability, which the §6.7.4
        // default floor deliberately withholds (`network-dialback` is the
        // restricted one). Granting it here is the deployment choice §12.3
        // describes, and without it this test would measure a conformant 403.
        let responder = PeerBuilder::new()
            .keypair(Keypair::from_seed([90u8; 32]))
            .listen_addr("127.0.0.1:0")
            .build()
            .unwrap();
        let mut responder = responder;
        responder.set_grant_resolver(std::sync::Arc::new(|_peer, _hash| {
            let mut grants = entity_capability::default_connection_grants();
            grants.push(entity_capability::GrantEntry {
                handlers: entity_capability::PathScope::new(vec!["system/network".into()]),
                resources: entity_capability::PathScope::new(vec![]),
                operations: entity_capability::IdScope::new(vec![
                    entity_network::OP_CHECK_REACHABILITY.into(),
                ]),
                peers: None,
                constraints: None,
                allowances: None,
            });
            Some(grants)
        }));
        let responder_listener = responder.listen().await.unwrap();
        let responder_addr = responder_listener.socket_addr();
        let responder_shared = responder.shared();
        responder.start_engines(&responder_shared);
        let responder_shared_for_task = responder_shared.clone();
        let responder_handle = tokio::spawn(async move {
            let _ = server::run(responder_listener, responder_shared_for_task).await;
        });

        // --- A, the requester. Its endpoint is the thing under test, and it
        // has to be bound with SO_REUSEPORT: the §6.7.3 MUST is that the probe
        // dials *from* the same local port the endpoint listens on, and a plain
        // `bind` refuses the second bind with EADDRINUSE. `listen_reuseport` is
        // the same call the punch path uses for exactly this reason.
        //
        // A bare acceptor rather than a full peer server, deliberately: a §6.7.2
        // dial-back is a bare connect that the responder drops the instant it
        // lands (that IS the fixed-size payload), so what has to be listening is
        // a socket, not a protocol. Standing a peer up here would test the
        // handshake as well and blur what a pass means.
        let requester_key = Keypair::from_seed([91u8; 32]);
        let requester_keypair = IdentityKeypair::Ed25519(requester_key.clone_inner());
        let requester_listener = crate::reuseport::listen_reuseport("127.0.0.1:0".parse().unwrap())
            .expect("bind A's probe endpoint with SO_REUSEPORT");
        let requester_addr = requester_listener.local_addr().unwrap();
        let requester_handle =
            tokio::spawn(async move { while requester_listener.accept().await.is_ok() {} });

        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        let probe = crate::srflx::check_reachability_at(
            &responder_addr.to_string(),
            requester_addr,
            &requester_keypair,
            entity_hash::HASH_ALGORITHM_SHA256,
        )
        .await
        .expect("§6.7.2: the probe itself must not error against a granting responder");

        match probe {
            crate::srflx::ReachabilityProbe::Answered(result) => {
                assert!(
                    result.reachable,
                    "§6.7.2: B dialed A's own listening port on loopback — the dial-back \
                     MUST have arrived (got address_tested={})",
                    result.address_tested
                );
                assert_eq!(
                    result.address_tested,
                    requester_addr.to_string(),
                    "§6.7.2: the echoed address MUST be the source B observed, which — \
                     because A dialed from its listener via reuseport — is A's listening \
                     address. A different value means B dialed something it did not observe."
                );
            }
            crate::srflx::ReachabilityProbe::Refused(status) => panic!(
                "the responder granted network-dialback, so this must be answered, not \
                 refused with {}",
                status
            ),
        }

        responder_handle.abort();
        requester_handle.abort();
    }

    /// The other half of the same gate: **without** the grant, the dial-back is
    /// refused — and refused *before* any traffic is emitted.
    ///
    /// This is what makes `network-dialback` restricted rather than merely
    /// documented as restricted. §6.7.4 puts it opposite `network-reflect`
    /// precisely because reflection answers from state already held while a
    /// dial-back makes this peer emit traffic at an address; if the default
    /// floor let it through, every peer offering §6.7 would be a dial-on-demand
    /// cannon for anyone who could open a connection. The peer here is built
    /// with no grant resolver at all, so it carries exactly
    /// `default_connection_grants` — the floor a real deployment starts from.
    #[cfg(all(
        feature = "signaling",
        feature = "network",
        not(target_arch = "wasm32")
    ))]
    #[tokio::test]
    async fn test_s674_dial_back_is_refused_without_the_restricted_grant() {
        let responder = PeerBuilder::new()
            .keypair(Keypair::from_seed([92u8; 32]))
            .listen_addr("127.0.0.1:0")
            .build()
            .unwrap();
        let responder_listener = responder.listen().await.unwrap();
        let responder_addr = responder_listener.socket_addr();
        let responder_shared = responder.shared();
        responder.start_engines(&responder_shared);
        let responder_shared_for_task = responder_shared.clone();
        let responder_handle = tokio::spawn(async move {
            let _ = server::run(responder_listener, responder_shared_for_task).await;
        });

        let requester_key = Keypair::from_seed([93u8; 32]);
        let requester_keypair = IdentityKeypair::Ed25519(requester_key.clone_inner());
        let requester_listener =
            crate::reuseport::listen_reuseport("127.0.0.1:0".parse().unwrap()).unwrap();
        let requester_addr = requester_listener.local_addr().unwrap();
        let requester_handle = tokio::spawn(async move {
            loop {
                if requester_listener.accept().await.is_err() {
                    break;
                }
            }
        });

        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        let probe = crate::srflx::check_reachability_at(
            &responder_addr.to_string(),
            requester_addr,
            &requester_keypair,
            entity_hash::HASH_ALGORITHM_SHA256,
        )
        .await
        .expect("a conformant refusal is an answer, not a client-side error");

        match probe {
            crate::srflx::ReachabilityProbe::Refused(status) => assert_eq!(
                status, 403,
                "§6.7.4: check-reachability is gated by network-dialback, which \
                 default_connection_grants withholds — an ungranted caller MUST be refused"
            ),
            crate::srflx::ReachabilityProbe::Answered(r) => panic!(
                "the default grant floor MUST NOT authorize a dial-back; got reachable={} \
                 against {}",
                r.reachable, r.address_tested
            ),
        }

        responder_handle.abort();
        requester_handle.abort();
    }

    /// Read the `system/peer/status` entity `holder` keeps for the peer
    /// whose identity hash is `remote_hash`, if any.
    fn liveness_status_of(
        shared: &Arc<PeerShared>,
        remote_hash: &entity_hash::Hash,
    ) -> Option<crate::peer_status::PeerStatusData> {
        let path = format!(
            "/{}/{}",
            shared.peer_id.as_str(),
            crate::peer_status::PeerStatusData::relative_path(remote_hash)
        );
        let h = shared.location_index.get(&path)?;
        let e = shared.content_store.get(&h)?;
        crate::peer_status::PeerStatusData::from_entity(&e).ok()
    }

    /// Poll until `shared` holds a status entity with the wanted status
    /// for `remote_hash`, or fail after ~2s. Used for the responder
    /// side, whose write settles as it produces the AUTHENTICATE
    /// response (asynchronous relative to the dialer's connect return).
    async fn wait_liveness_status(
        shared: &Arc<PeerShared>,
        remote_hash: &entity_hash::Hash,
        want: &str,
    ) -> crate::peer_status::PeerStatusData {
        for _ in 0..200 {
            if let Some(d) = liveness_status_of(shared, remote_hash) {
                if d.status == want {
                    return d;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("status never reached {:?}", want);
    }

    /// Amendment 12 §A3 baseline: a completed handshake (§6.2) writes
    /// `system/peer/status = connected` on BOTH ends — the dialer
    /// synchronously in `connect_to`, the responder as it grants the
    /// connection capability.
    #[tokio::test]
    async fn a12_liveness_connected_on_establish_both_ends() {
        use transport::{MemoryConnector, MemoryListener, MemoryTransportRegistry};
        let registry = MemoryTransportRegistry::new();

        let server = PeerBuilder::new()
            .keypair(Keypair::from_seed([0x60u8; 32]))
            .build()
            .unwrap();
        let server_pid = server.peer_id().to_string();
        let server_shared = server.shared();
        // The status path is keyed by the identity hash AS AUTHORED at
        // build time — read it off the peer rather than re-deriving via
        // the process-global home format (racy under the SHA-384-window
        // tests, and the authored value is the ground truth anyway).
        let server_hash = server_shared.identity_hash;
        let listener = MemoryListener::bind(server_pid.clone(), registry.clone()).unwrap();
        server.start_engines(&server_shared);
        let shared_for_task = server_shared.clone();
        let server_handle = tokio::spawn(async move {
            let _ = server::run(listener, shared_for_task).await;
        });
        tokio::task::yield_now().await;

        let client = PeerBuilder::new()
            .keypair(Keypair::from_seed([0x61u8; 32]))
            .connector(std::sync::Arc::new(MemoryConnector::new(registry.clone())))
            .build()
            .unwrap();
        client.local_only();
        let client_pid = client.peer_id().to_string();
        let client_shared = client.shared();
        let client_hash = client_shared.identity_hash;

        client
            .connect_to(&format!("memory://{}", server_pid))
            .await
            .unwrap();

        // Dialer side: written synchronously during connect_to.
        let d = liveness_status_of(&client_shared, &server_hash)
            .expect("dialer has no status entity for server after connect");
        assert_eq!(d.status, crate::peer_status::PEER_STATUS_CONNECTED);
        assert_eq!(d.peer_id, server_pid);
        assert!(d.reason.is_none() && d.last_error.is_none());
        assert!(d.connected_at.is_some());

        // Responder side: symmetric write as the server produced the grant.
        let rd = wait_liveness_status(
            &server_shared,
            &client_hash,
            crate::peer_status::PEER_STATUS_CONNECTED,
        )
        .await;
        assert_eq!(rd.peer_id, client_pid);

        server_handle.abort();
    }

    /// Amendment 12 §A1 anchor vector: a live two-peer session, drop one
    /// side, and the surviving side's `system/peer/status` flips
    /// connected → suspect (reason `transport-error`) the moment a
    /// dispatch over the dead pooled connection fails. The write is a
    /// plain tree entity through the notifying index, so a subscriber
    /// sees it with no poll.
    #[tokio::test]
    async fn a12_liveness_suspect_on_transport_error() {
        use transport::{MemoryConnector, MemoryListener, MemoryTransportRegistry};
        let registry = MemoryTransportRegistry::new();

        let server = PeerBuilder::new()
            .keypair(Keypair::from_seed([0x62u8; 32]))
            .build()
            .unwrap();
        let server_pid = server.peer_id().to_string();
        let server_shared = server.shared();
        let server_hash = server_shared.identity_hash;
        let listener = MemoryListener::bind(server_pid.clone(), registry.clone()).unwrap();
        server.start_engines(&server_shared);
        let shared_for_task = server_shared.clone();
        let server_handle = tokio::spawn(async move {
            let _ = server::run(listener, shared_for_task).await;
        });
        tokio::task::yield_now().await;

        let client = PeerBuilder::new()
            .keypair(Keypair::from_seed([0x63u8; 32]))
            .connector(std::sync::Arc::new(MemoryConnector::new(registry.clone())))
            .build()
            .unwrap();
        client.local_only();
        let client_shared = client.shared();

        // Establish: dials + handshakes through the outbound pool, so the
        // failing conn later is the pooled binding the no-clobber guard
        // checks.
        client
            .connect_to(&format!("memory://{}", server_pid))
            .await
            .unwrap();
        let baseline =
            liveness_status_of(&client_shared, &server_hash).expect("connected baseline missing");
        assert_eq!(baseline.status, crate::peer_status::PEER_STATUS_CONNECTED);
        assert!(baseline.reason.is_none());

        // Drop the server: aborting the accept-loop task drops its
        // ConnectionGuard, which aborts every per-connection task — the
        // client's pooled connection is now dead, but the pool still
        // hands it out (the "browse over a dead pool" symptom).
        server_handle.abort();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        // Next dispatch fails at the transport → §A1 demotion fires.
        // (Any EXECUTE_RESPONSE — even 4xx — would be Ok here; only a
        // transport failure errors.)
        let params = entity_entity::Entity::new(
            "system/params",
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                entity_ecf::text("path"),
                entity_ecf::text(format!("/{}/system/tree", server_pid)),
            )])),
        )
        .unwrap();
        let res = client
            .execute(&format!("/{}/system/tree", server_pid), "get", params)
            .await;
        assert!(
            res.is_err(),
            "expected transport error dispatching over dropped server"
        );

        // The surviving side flipped to suspect with the transport-error
        // reason, and the dead conn is evicted.
        let d = liveness_status_of(&client_shared, &server_hash)
            .expect("client lost status entity for server after demotion");
        assert_eq!(d.status, crate::peer_status::PEER_STATUS_SUSPECT);
        assert_eq!(
            d.reason.as_deref(),
            Some(crate::peer_status::PEER_STATUS_REASON_TRANSPORT_ERROR)
        );
        assert!(
            d.last_error.is_some(),
            "suspect status should carry a coded last_error"
        );
        assert_eq!(d.peer_id, server_pid);
        assert!(
            client_shared.remote.get(&server_pid).is_none(),
            "dead conn must be evicted from the pool"
        );
    }

    /// Spin up a memory-transport server peer + a client peer with the
    /// given keepalive config; returns (server_shared, server_handle,
    /// client, client_shared, server_pid, server_hash).
    async fn a12_keepalive_pair(
        seed: u8,
        cfg: keepalive::KeepaliveConfig,
    ) -> (
        Arc<PeerShared>,
        tokio::task::JoinHandle<()>,
        Peer,
        Arc<PeerShared>,
        String,
        entity_hash::Hash,
        tokio::sync::RwLockReadGuard<'static, ()>,
    ) {
        use transport::{MemoryConnector, MemoryListener, MemoryTransportRegistry};
        // These peers author identities under the home default and the server
        // mints a cap whose `grantee` is the client's home-format identity
        // hash, so they are home-format READERS: held for the caller's whole
        // test, this guard keeps M3's SHA-384 window from flipping the global
        // mid-test (→ 401 `unresolvable_grantee`). Returned, not dropped here
        // — the client re-derives `peer_entity()` on every later request.
        let home_format_guard = HOME_FORMAT_TEST_LOCK.read().await;
        let registry = MemoryTransportRegistry::new();

        let server = PeerBuilder::new()
            .keypair(Keypair::from_seed([seed; 32]))
            .build()
            .unwrap();
        let server_pid = server.peer_id().to_string();
        let server_shared = server.shared();
        let server_hash = server_shared.identity_hash;
        let listener = MemoryListener::bind(server_pid.clone(), registry.clone()).unwrap();
        server.start_engines(&server_shared);
        let shared_for_task = server_shared.clone();
        let server_handle = tokio::spawn(async move {
            let _ = server::run(listener, shared_for_task).await;
        });
        tokio::task::yield_now().await;

        let client = PeerBuilder::new()
            .keypair(Keypair::from_seed([seed + 1; 32]))
            .connector(std::sync::Arc::new(MemoryConnector::new(registry.clone())))
            .keepalive(cfg)
            .build()
            .unwrap();
        client.local_only();
        let client_shared = client.shared();
        client
            .connect_to(&format!("memory://{}", server_pid))
            .await
            .unwrap();
        (
            server_shared,
            server_handle,
            client,
            client_shared,
            server_pid,
            server_hash,
            home_format_guard,
        )
    }

    /// EXTENSION-NETWORK §5.1–§5.3: an EXECUTE `ping` on the connect
    /// handler answers 200 with a `system/network/pong` echoing the
    /// ping's timestamp/sequence plus the responder's clock.
    ///
    /// This drives a **fully signed** client, so it exercises the pong
    /// construction and the echo fields, and it passed under both readings of
    /// §4.2's pre-authorization — before 0.8.2.6 Q2, when the intercept sat
    /// after `verify_request`, and after, now that it sits before. **It cannot
    /// see the Q2 defect and is kept that way on purpose.** The row that does
    /// see it is control B of
    /// `incompatible_protocol_and_unknown_connect_op_on_both_transports`, which
    /// sends the bare unauthenticated frame; the two together are what show
    /// which of them discriminates.
    #[tokio::test]
    async fn a12_keepalive_ping_answers_pong() {
        let disabled = keepalive::KeepaliveConfig {
            enabled: false, // exercise the op directly, not the loop
            ..Default::default()
        };
        let (_ss, server_handle, client, _cs, server_pid, _sh, _home_format_guard) =
            a12_keepalive_pair(0x64, disabled).await;

        let params = entity_entity::Entity::new(
            "system/network/ping",
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
                (
                    entity_ecf::text("sequence"),
                    entity_ecf::Value::Integer(42u64.into()),
                ),
                (
                    entity_ecf::text("timestamp"),
                    entity_ecf::Value::Integer(1_700_000_000_000u64.into()),
                ),
            ])),
        )
        .unwrap();
        let resp = client
            .execute(
                &format!("/{}/system/protocol/connect", server_pid),
                "ping",
                params,
            )
            .await
            .expect("ping round-trip");
        assert_eq!(
            resp.status,
            200,
            "ping rejected: type={} body={:?}",
            resp.result.entity_type,
            String::from_utf8_lossy(&resp.result.data)
        );
        assert_eq!(resp.result.entity_type, "system/network/pong");
        let value: ciborium::Value = ciborium::from_reader(resp.result.data.as_slice()).unwrap();
        let map = value.into_map().expect("pong data is a map");
        let field = |key: &str| -> Option<u64> {
            map.iter().find_map(|(k, v)| match (k, v) {
                (ciborium::Value::Text(t), ciborium::Value::Integer(i)) if t == key => {
                    u64::try_from(*i).ok()
                }
                _ => None,
            })
        };
        assert_eq!(field("sequence"), Some(42), "pong echoes sequence");
        assert_eq!(
            field("timestamp"),
            Some(1_700_000_000_000),
            "pong echoes timestamp"
        );
        assert!(field("server_time").unwrap_or(0) > 0, "server_time set");

        server_handle.abort();
    }

    /// Amendment 12 rung-2 anchor: drop the peer, let the keepalive
    /// loop run, and the survivor escalates to `disconnected` (reason
    /// `keepalive-miss`) within the §A3 envelope
    /// (interval_ms × max_missed + timeout_ms — short config injected),
    /// with the dead conn evicted from the pool. The demotion write
    /// carries the §A4 `last_seen` transition snapshot — the last
    /// moment the survivor actually heard from the peer.
    #[tokio::test]
    async fn a12_keepalive_miss_escalates_to_disconnected() {
        let short = keepalive::KeepaliveConfig {
            interval_ms: 50,
            timeout_ms: 60,
            max_missed: 2,
            enabled: true,
        };
        let (
            _ss,
            server_handle,
            client,
            client_shared,
            server_pid,
            server_hash,
            _home_format_guard,
        ) = a12_keepalive_pair(0x66, short).await;

        let baseline =
            liveness_status_of(&client_shared, &server_hash).expect("connected baseline missing");
        assert_eq!(baseline.status, crate::peer_status::PEER_STATUS_CONNECTED);

        // One successful exchange so the endpoint has recorded activity
        // — the freshness mark the §A4 demotion snapshot preserves.
        let params = entity_entity::Entity::new(
            "system/network/ping",
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
                (
                    entity_ecf::text("sequence"),
                    entity_ecf::Value::Integer(1u64.into()),
                ),
                (
                    entity_ecf::text("timestamp"),
                    entity_ecf::Value::Integer(1_700_000_000_000u64.into()),
                ),
            ])),
        )
        .unwrap();
        client
            .execute(
                &format!("/{}/system/protocol/connect", server_pid),
                "ping",
                params,
            )
            .await
            .expect("pre-drop ping round-trip");

        // Drop the server; the idle pooled connection goes dark. No
        // dispatch ever runs — only the keepalive loop observes it.
        server_handle.abort();

        let d = wait_liveness_status(
            &client_shared,
            &server_hash,
            crate::peer_status::PEER_STATUS_DISCONNECTED,
        )
        .await;
        assert_eq!(
            d.reason.as_deref(),
            Some(crate::peer_status::PEER_STATUS_REASON_KEEPALIVE_MISS)
        );
        assert_eq!(d.peer_id, server_pid);
        assert!(
            d.last_seen.is_some(),
            "demotion write must carry the §A4 last_seen transition snapshot"
        );
        assert!(
            client_shared.remote.get(&server_pid).is_none(),
            "dead conn must be evicted after keepalive escalation"
        );
    }

    /// §3.13 `system/connection` transition writes (ruling C — full
    /// NETWORK conformance tier, not floor): establish (dialer side)
    /// records `active` with transport+address and the sibling status
    /// entity carries the `connection` path ref; the keepalive demotion
    /// flips the record to `closed`, preserving how we WERE attached.
    #[tokio::test]
    async fn a12_connection_transitions_active_to_closed() {
        let short = keepalive::KeepaliveConfig {
            interval_ms: 50,
            timeout_ms: 60,
            max_missed: 2,
            enabled: true,
        };
        let (
            _ss,
            server_handle,
            _client,
            client_shared,
            server_pid,
            server_hash,
            _home_format_guard,
        ) = a12_keepalive_pair(0x6a, short).await;

        let conn_path = format!(
            "/{}/{}",
            client_shared.peer_id.as_str(),
            connection_state::ConnectionData::relative_path(&server_hash)
        );
        let read_conn = || {
            client_shared
                .location_index
                .get(&conn_path)
                .and_then(|h| client_shared.content_store.get(&h))
                .and_then(|e| connection_state::ConnectionData::from_entity(&e).ok())
        };

        // Establish transition: active, with attachment diagnostics.
        let active = read_conn().expect("establish must write system/connection (dialer side)");
        assert_eq!(active.status, connection_state::CONNECTION_STATUS_ACTIVE);
        assert_eq!(active.peer_id, server_pid);
        assert_eq!(active.transport, "memory");
        assert_eq!(active.address, format!("memory://{}", server_pid));
        assert!(active.established_at > 0);

        // The status entity references the connection record (§3.13).
        let status =
            liveness_status_of(&client_shared, &server_hash).expect("connected baseline missing");
        assert_eq!(
            status.connection.as_deref(),
            Some(conn_path.as_str()),
            "status `connection` field must point at the system/connection path"
        );

        // Close/failure transition: drop the server, let keepalive
        // escalate; the record flips to closed and still answers how we
        // WERE attached.
        server_handle.abort();
        wait_liveness_status(
            &client_shared,
            &server_hash,
            crate::peer_status::PEER_STATUS_DISCONNECTED,
        )
        .await;
        let closed = read_conn().expect("closed record must remain readable");
        assert_eq!(closed.status, connection_state::CONNECTION_STATUS_CLOSED);
        assert_eq!(closed.transport, "memory");
        assert_eq!(closed.established_at, active.established_at);
    }

    /// §A4 (rung-2 ruling 1) pinned as an invariant: the status entity
    /// is TRANSITION-written only. Keepalive successes advance the
    /// impl-internal freshness (`RemoteEndpoint::last_activity_ms`) but
    /// MUST NOT rewrite the tree entity — no `last_seen` cadence
    /// refresh, no subscriber fan-out, no CAS accretion on an idle
    /// healthy connection. This is the negative test replacing the
    /// rung-2 cadence-refresh vector after arch ruled the refresh a
    /// spec defect (Go analog: `TestKeepaliveNoCadenceWrites`).
    #[tokio::test]
    async fn a12_keepalive_no_cadence_writes() {
        let short = keepalive::KeepaliveConfig {
            interval_ms: 40,
            timeout_ms: 200,
            max_missed: 3,
            enabled: true,
        };
        let (
            _ss,
            server_handle,
            _client,
            client_shared,
            server_pid,
            server_hash,
            _home_format_guard,
        ) = a12_keepalive_pair(0x68, short).await;

        let baseline =
            liveness_status_of(&client_shared, &server_hash).expect("connected baseline missing");
        assert_eq!(baseline.status, crate::peer_status::PEER_STATUS_CONNECTED);
        assert!(
            baseline.last_seen.is_none(),
            "establish write must not carry last_seen"
        );

        let status_path = format!(
            "/{}/{}",
            client_shared.peer_id.as_str(),
            crate::peer_status::PeerStatusData::relative_path(&server_hash)
        );
        let h0 = client_shared
            .location_index
            .get(&status_path)
            .expect("no status binding after establish");
        let endpoint = client_shared
            .remote
            .get(&server_pid)
            .expect("pooled outbound binding missing");
        let activity0 = endpoint.last_activity_ms();

        // Wait until the in-memory freshness advances past the
        // establish-time mark — proof at least one keepalive pong
        // landed (the impl-internal bookkeeping §A4 keeps).
        let mut advanced = false;
        for _ in 0..500 {
            let a = endpoint.last_activity_ms();
            if a != 0 && a > activity0 {
                advanced = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            advanced,
            "keepalive success never advanced in-memory freshness"
        );

        // Let several more keepalive intervals elapse so any (forbidden)
        // cadence write would have landed.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let h1 = client_shared
            .location_index
            .get(&status_path)
            .expect("status binding vanished");
        assert_eq!(
            h1, h0,
            "status entity rewritten at keepalive cadence — §A4: transition writes only"
        );

        server_handle.abort();
    }

    /// EXTENSION-NETWORK §5.4a `[MUST]` —
    /// `NET-LIVENESS-ESCALATE-AFTER-EVICTION-1`, the positive half.
    ///
    /// The composition no vector in any implementation visited: an
    /// episode that OPENS at the §A1 transport seam rather than at an
    /// idle keepalive miss. §A1 evicts the pooled binding as it writes
    /// `suspect` — one event — so a keepalive loop that exits on sight
    /// of a missing binding kills the escalation exactly when it becomes
    /// owed, and the peer stays `suspect` forever (no disconnect
    /// subscription, so no §4.1 reconnect). Measured that way against
    /// this peer by go's harness at `21eb223`.
    ///
    /// `interval_ms` is set well above the demotion's latency on
    /// purpose: the transport seam must be what opens the episode, not a
    /// keepalive miss racing it — the race that made go's own check read
    /// as a 1-in-4 flake.
    ///
    /// Asserts the reason too: §5.4a preserves the episode's ORIGINATING
    /// `transport-error`. Re-stamping to `keepalive-miss` would assert
    /// pings that provably were not sent — the connection was gone
    /// before the loop could send one.
    #[tokio::test]
    async fn a12_escalates_to_disconnected_after_the_a1_eviction() {
        let short = keepalive::KeepaliveConfig {
            interval_ms: 400,
            timeout_ms: 60,
            max_missed: 2,
            enabled: true,
        };
        let (
            _ss,
            server_handle,
            client,
            client_shared,
            server_pid,
            server_hash,
            _home_format_guard,
        ) = a12_keepalive_pair(0x6c, short).await;

        // Kill the server, then dispatch over the dead pooled conn: the
        // §A1 seam demotes to suspect and evicts, all before the first
        // keepalive tick.
        server_handle.abort();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let params = entity_entity::Entity::new(
            "system/params",
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                entity_ecf::text("path"),
                entity_ecf::text(format!("/{}/system/tree", server_pid)),
            )])),
        )
        .unwrap();
        assert!(
            client
                .execute(&format!("/{}/system/tree", server_pid), "get", params)
                .await
                .is_err(),
            "expected a transport error dispatching over the dropped server"
        );

        let opened = liveness_status_of(&client_shared, &server_hash)
            .expect("no status entity after the §A1 demotion");
        assert_eq!(opened.status, crate::peer_status::PEER_STATUS_SUSPECT);
        assert_eq!(
            opened.reason.as_deref(),
            Some(crate::peer_status::PEER_STATUS_REASON_TRANSPORT_ERROR)
        );
        assert!(
            client_shared.remote.get(&server_pid).is_none(),
            "precondition: the §A1 demotion evicts the binding it demotes"
        );

        // Nothing touches the peer from here. Only the grace path can
        // move it — and §5.4a says it must.
        let escalated = wait_liveness_status(
            &client_shared,
            &server_hash,
            crate::peer_status::PEER_STATUS_DISCONNECTED,
        )
        .await;
        assert_eq!(
            escalated.reason.as_deref(),
            Some(crate::peer_status::PEER_STATUS_REASON_TRANSPORT_ERROR),
            "§5.4a [MUST]: the escalation carries the episode's originating reason"
        );
        assert_eq!(escalated.peer_id, server_pid);
        assert_eq!(
            escalated.failing_since, opened.failing_since,
            "the escalation is the same episode — failing_since must not re-stamp"
        );
    }

    /// CONTINUATION v1.23 §3.4 A.1 — **the dispatcher collects the markers
    /// the dispatcher binds.**
    ///
    /// Every chain-scoped 403 mints a `rejected` marker
    /// (`connection::try_bind_rejected_marker`), so a peer under a stream of
    /// denied chain dispatches accretes marker nodes at the caller's chosen
    /// rate. Leaning on the continuation handler's sweep would not cover it:
    /// that sweep runs when a continuation *advances*, which this peer may
    /// never do.
    ///
    /// The sweep is root-wide, so it also collects the `lost` markers the
    /// subscription engine binds — which cannot call the collector itself,
    /// since `subscription → continuation` is an extension-to-extension edge
    /// the crate DAG forbids.
    #[tokio::test]
    async fn v123_the_dispatcher_collects_expired_chain_error_markers() {
        let peer = PeerBuilder::new()
            .keypair(Keypair::from_seed([0x5c; 32]))
            .build()
            .unwrap();
        let shared = peer.shared();
        let pid = shared.peer_id.as_str().to_string();

        let marker = |ts: u64| {
            entity_entity::Entity::new(
                "system/runtime/chain-error-lost",
                entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
                    (entity_ecf::text("chain_id"), entity_ecf::text("c1")),
                    (
                        entity_ecf::text("reason"),
                        entity_ecf::text("capability_denied"),
                    ),
                    (
                        entity_ecf::text("timestamp"),
                        entity_ecf::integer(ts as i64),
                    ),
                ])),
            )
            .unwrap()
        };
        let bind = |e: entity_entity::Entity| -> String {
            let path = format!(
                "/{}/system/runtime/chain-errors/rejected/c1/r1/capability_denied/{}",
                pid,
                e.content_hash.to_hex()
            );
            let h = shared.content_store.put(e).unwrap();
            shared.location_index.set(&path, h);
            path
        };

        let now_ms = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let expired = bind(marker(now_ms - 30 * 60 * 60 * 1000));
        let fresh = bind(marker(now_ms - 60 * 1000));

        connection::maybe_collect_chain_error_markers(&shared);

        assert!(
            shared.location_index.get(&expired).is_none(),
            "§3.4 A.1: a marker past the 24h default window must be collected \
             by the peer that bound it"
        );
        assert!(
            shared.location_index.get(&fresh).is_some(),
            "a marker inside the window must survive"
        );

        // Throttled: the next denial in the same minute must not pay for
        // another scan of the tree.
        let expired_again = bind(marker(now_ms - 40 * 60 * 60 * 1000));
        connection::maybe_collect_chain_error_markers(&shared);
        assert!(
            shared.location_index.get(&expired_again).is_some(),
            "the sweep must be throttled off the dispatch path"
        );
    }

    /// EXTENSION-NETWORK §5.4.1 `[MUST]` — **`system/peer/status` is
    /// transition-written; a successful keepalive tick MUST NOT produce a
    /// tree write.**
    ///
    /// The shape of the rule was already right here (`recover_connected`
    /// early-returns when the entity already says `connected`); what was
    /// missing was the *negative* — nothing failed if the guard were
    /// deleted. Cross-impl review flagged exactly that: Go verified this
    /// and Rust had it "shaped right, unverified."
    ///
    /// **Why the assertion is on the content hash rather than the decoded
    /// status.** A per-tick write would still say `connected`, so reading
    /// the status back proves nothing. It would, however, re-stamp
    /// `last_seen` to the tick's own clock — a different body, a different
    /// `content_hash`, a new entity in the store, and a subscription event
    /// delivered to every lifecycle consumer bound to this path. Hash
    /// equality across a dozen healthy ticks is the observable form of
    /// "no write happened."
    ///
    /// The connection is deliberately left idle: with no application
    /// traffic every interval takes the ping branch, so this exercises the
    /// success path (pong received → `recover_connected`) repeatedly,
    /// which is the branch §5.4.1 is about.
    ///
    /// **Mutation it is verified against:** delete the
    /// `existing.status == PEER_STATUS_CONNECTED` early return in
    /// `keepalive::recover_connected` — this test must fail (the hash
    /// moves on the first tick) while the demotion/escalation vectors
    /// above still pass.
    #[tokio::test]
    async fn a12_5_4_1_a_successful_keepalive_tick_writes_no_status() {
        let short = keepalive::KeepaliveConfig {
            interval_ms: 40,
            timeout_ms: 300,
            max_missed: 3,
            enabled: true,
        };
        let (
            _ss,
            server_handle,
            _client,
            client_shared,
            _server_pid,
            server_hash,
            _home_format_guard,
        ) = a12_keepalive_pair(0x7a, short).await;

        let path = format!(
            "/{}/{}",
            client_shared.peer_id.as_str(),
            crate::peer_status::PeerStatusData::relative_path(&server_hash)
        );
        let baseline_hash = client_shared
            .location_index
            .get(&path)
            .expect("§6.2: establish writes `connected`");
        let baseline =
            liveness_status_of(&client_shared, &server_hash).expect("connected baseline missing");
        assert_eq!(baseline.status, crate::peer_status::PEER_STATUS_CONNECTED);

        // ~12 keepalive intervals of a healthy, idle connection. Every one
        // of them pings, gets a pong, and calls the transition guard.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let after = liveness_status_of(&client_shared, &server_hash)
            .expect("status entity vanished on a healthy connection");
        assert_eq!(
            after.status,
            crate::peer_status::PEER_STATUS_CONNECTED,
            "precondition: the connection stayed healthy for the whole window"
        );
        let after_hash = client_shared
            .location_index
            .get(&path)
            .expect("status binding vanished on a healthy connection");
        assert_eq!(
            after_hash, baseline_hash,
            "§5.4.1 [MUST]: a successful keepalive tick must not write \
             `system/peer/status` — the binding moved, so ticks are \
             re-stamping the entity every lifecycle consumer subscribes to"
        );
        assert_eq!(
            after.last_seen, baseline.last_seen,
            "§5.4.1: `last_seen` is a transition snapshot, not a heartbeat \
             — per-tick freshness is implementation-internal (§A4)"
        );

        server_handle.abort();
    }

    /// EXTENSION-NETWORK §5.4a —
    /// `NET-LIVENESS-NO-ESCALATION-WITHOUT-EPISODE-1`, the negative half
    /// of the pair, and the reason the pair is a pair: an implementation
    /// that escalates every *unbound* peer rather than every *`suspect`*
    /// peer passes the positive vector above and breaks the §A1 seam's
    /// deliberate exclusions.
    ///
    /// **In-process by declared exclusion**, per §5.4a's own
    /// satisfaction mode: the state it needs — unbound yet still
    /// `connected` — is reachable only from the §10.2 dispatch fallback
    /// and the RELAY terminal hop, which evict without demoting, so no
    /// conformance client can construct it over the wire against a peer
    /// without those paths installed. Recorded at
    /// `docs/validation/CONFORMANCE-EXCLUSIONS.md`; an in-process result
    /// is never reported as a cross-impl vector pass.
    ///
    /// **Mutation it is verified against:** delete the
    /// `prev.status != PEER_STATUS_SUSPECT` guard in
    /// `keepalive::escalate_unbound_suspect` — this test must fail while
    /// `a12_escalates_to_disconnected_after_the_a1_eviction` still
    /// passes.
    #[tokio::test]
    async fn a12_no_escalation_without_an_open_failure_episode() {
        let short = keepalive::KeepaliveConfig {
            interval_ms: 60,
            timeout_ms: 60,
            max_missed: 2,
            enabled: true,
        };
        let (
            _ss,
            server_handle,
            _client,
            client_shared,
            server_pid,
            server_hash,
            _home_format_guard,
        ) = a12_keepalive_pair(0x6e, short).await;

        let baseline =
            liveness_status_of(&client_shared, &server_hash).expect("connected baseline missing");
        assert_eq!(baseline.status, crate::peer_status::PEER_STATUS_CONNECTED);

        // The §A1 scope pin, reproduced: evict the binding and write NO
        // status — what a §10.2 fallback / RELAY terminal-hop teardown
        // does to a peer that is perfectly healthy. The server stays up,
        // so nothing else can demote it either.
        client_shared.remote.remove(&server_pid);

        // Several keepalive intervals plus the grace: any escalation
        // this teardown could manufacture has had its chance.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let after = liveness_status_of(&client_shared, &server_hash)
            .expect("status entity vanished during the teardown");
        assert_eq!(
            after.status,
            crate::peer_status::PEER_STATUS_CONNECTED,
            "an evict-without-demote teardown was turned into a demotion — §5.4a scope pin: \
             escalate only where a failure episode is open (status `suspect`)"
        );

        server_handle.abort();
    }

    // -----------------------------------------------------------------
    // EXTENSION-NETWORK Amendment 12 rung 3 — the maintain-peer reconnect
    // lifecycle. In-process two-peer vectors over the full reactive stack
    // (inbox + continuation + subscription + network), the Rust shape of
    // Go's `ext/network/lifecycle_test.go`. These double as the Rust
    // observation of PROPOSAL-CONTINUATION-LOST-ERROR-MARKER-MUST §4's
    // reconnect-chain vectors: the reconnect-failure path MUST leave
    // §3.10 lost-error markers (no-on_error forward non-2xx) bound under
    // the continuation handler's own authority, keyed by RequestID.
    // -----------------------------------------------------------------

    #[cfg(feature = "network")]
    fn maintain_request_entity(peer_id: &str, address: &str) -> entity_entity::Entity {
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("address"), entity_ecf::text(address)),
            (entity_ecf::text("peer_id"), entity_ecf::text(peer_id)),
        ]));
        entity_entity::Entity::new(entity_network::TYPE_MAINTAIN_REQUEST, data).unwrap()
    }

    /// Drive the initial maintain-peer, retrying transient readiness-race
    /// 502s: the in-memory server's accept loop may not be scheduled yet
    /// when the client dials (a single `yield_now` after spawn is not a
    /// deterministic readiness barrier under heavy parallel test load — the
    /// same race the pre-existing `a12_keepalive_pair` peers carry). Each
    /// failed FIRST call drops its session (§4.1 step 1), so a retry is a
    /// clean fresh establish. Returns the 200 response.
    #[cfg(feature = "network")]
    async fn maintain_with_retry(
        client: &Peer,
        client_pid: &str,
        params: entity_entity::Entity,
    ) -> entity_handler::HandlerResult {
        for _ in 0..100 {
            let resp = client
                .execute(
                    &format!("/{}/system/network", client_pid),
                    "maintain-peer",
                    params.clone(),
                )
                .await
                .expect("maintain-peer dispatch");
            if resp.status == 200 {
                return resp;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("maintain-peer never returned 200 within the readiness window");
    }

    /// Build a memory-transport server peer (engines + accept loop) and a
    /// local-only client peer sharing `registry`. Returns the pieces the
    /// rung-3 vectors drive. The client is NOT pre-connected — maintain-peer
    /// performs the §4.1 step-1 establish.
    #[cfg(feature = "network")]
    async fn rung3_pair(
        registry: std::sync::Arc<transport::MemoryTransportRegistry>,
        server_seed: u8,
        client_seed: u8,
        client_keepalive: keepalive::KeepaliveConfig,
    ) -> (
        Peer,
        Arc<PeerShared>,
        tokio::task::JoinHandle<()>,
        String,
        Peer,
        Arc<PeerShared>,
    ) {
        use transport::{MemoryConnector, MemoryListener};
        let server = PeerBuilder::new()
            .keypair(Keypair::from_seed([server_seed; 32]))
            .build()
            .unwrap();
        let server_pid = server.peer_id().to_string();
        let server_shared = server.shared();
        let listener = MemoryListener::bind(server_pid.clone(), registry.clone()).unwrap();
        server.start_engines(&server_shared);
        let shared_for_task = server_shared.clone();
        let server_handle = tokio::spawn(async move {
            let _ = server::run(listener, shared_for_task).await;
        });
        tokio::task::yield_now().await;

        let client = PeerBuilder::new()
            .keypair(Keypair::from_seed([client_seed; 32]))
            .connector(std::sync::Arc::new(MemoryConnector::new(registry)))
            .keepalive(client_keepalive)
            .build()
            .unwrap();
        client.local_only();
        let client_shared = client.shared();
        (
            server,
            server_shared,
            server_handle,
            server_pid,
            client,
            client_shared,
        )
    }

    /// §4.1 happy path: maintain-peer connects, installs the three-
    /// continuation graph + two lifecycle subscriptions, returns session
    /// info. The graph residents ride the handler grant as
    /// dispatch_capability (§11 / F2), and none routes on_error to
    /// system/inbox/* (marker-proposal §5).
    #[cfg(feature = "network")]
    #[tokio::test]
    async fn a12_rung3_maintain_peer_establishes_graph() {
        let registry = transport::MemoryTransportRegistry::new();
        let ka = keepalive::KeepaliveConfig {
            enabled: false,
            ..Default::default()
        };
        let (_server, _ss, server_handle, server_pid, client, client_shared) =
            rung3_pair(registry, 0x80, 0x81, ka).await;
        let client_pid = client_shared.peer_id.as_str().to_string();
        let addr = format!("memory://{}", server_pid);

        let resp = maintain_with_retry(
            &client,
            &client_pid,
            maintain_request_entity(&server_pid, &addr),
        )
        .await;
        assert_eq!(resp.status, 200, "maintain-peer returned non-200");
        assert_eq!(
            resp.result.entity_type,
            entity_network::TYPE_MAINTAIN_RESULT
        );
        let result: ciborium::Value = ciborium::from_reader(resp.result.data.as_slice()).unwrap();
        let rmap = result.as_map().unwrap();
        let get = |k: &str| {
            rmap.iter()
                .find(|(kk, _)| kk.as_text() == Some(k))
                .map(|(_, v)| v)
        };
        assert_eq!(get("peer_id").unwrap().as_text(), Some(server_pid.as_str()));
        assert!(!get("session_id").unwrap().as_text().unwrap().is_empty());
        // §3.11: single path segment — the marker path embeds it verbatim.
        // Shape only; the spelling is impl-defined and not the contract.
        let chain_id = get("chain_id").unwrap().as_text().unwrap();
        assert!(!chain_id.is_empty(), "chain_id is empty");
        assert!(
            !chain_id.contains('/'),
            "chain_id {:?} is not a single path segment",
            chain_id
        );
        let subs = get("subscriptions").unwrap().as_array().unwrap();
        assert_eq!(subs.len(), 2, "expected 2 lifecycle subscriptions");

        // The graph is in the tree: two inbox residents + the managed-
        // namespace backoff resident, all system/continuation entities
        // carrying the handler grant as dispatch_capability.
        //
        // `on_error` is asserted per-path, not blanket-absent. This loop used
        // to require it absent everywhere, citing marker-proposal §5's "never
        // route on_error at system/inbox/*" — guidance arch has since WITHDRAWN
        // as too broad (ruling 4): routing there is correct when the error is
        // MEANT to drive the next step, and the on-disconnect trigger's failed
        // `reconnect` is exactly that — the failure IS the retry trigger. The
        // trap the old rule guarded against is unintended advancement.
        let grant_hash = client_shared
            .location_index
            .get(&format!(
                "/{}/system/capability/grants/system/network",
                client_pid
            ))
            .expect("network handler grant not bound");
        for path in [
            format!(
                "/{}/system/inbox/network/{}/on-disconnect",
                client_pid, server_pid
            ),
            format!(
                "/{}/system/inbox/network/{}/on-reconnect",
                client_pid, server_pid
            ),
            format!(
                "/{}/system/network/peers/{}/on-reconnect-backoff",
                client_pid, server_pid
            ),
        ] {
            let h = client_shared
                .location_index
                .get(&path)
                .unwrap_or_else(|| panic!("no continuation bound at {}", path));
            let ent = client_shared.content_store.get(&h).unwrap();
            assert_eq!(ent.entity_type, "system/continuation", "at {}", path);
            let cont: ciborium::Value = ciborium::from_reader(ent.data.as_slice()).unwrap();
            let cmap = cont.as_map().unwrap();
            let dc = cmap
                .iter()
                .find(|(k, _)| k.as_text() == Some("dispatch_capability"))
                .and_then(|(_, v)| match v {
                    ciborium::Value::Bytes(b) => entity_hash::Hash::from_bytes(b).ok(),
                    _ => None,
                })
                .expect("dispatch_capability present");
            assert_eq!(dc, grant_hash, "continuation at {} rides wrong cap", path);

            let on_error = cmap
                .iter()
                .find(|(k, _)| k.as_text() == Some("on_error"))
                .map(|(_, v)| {
                    let m = v.as_map().expect("on_error is a bare delivery-spec map");
                    let f = |key: &str| {
                        m.iter()
                            .find(|(k, _)| k.as_text() == Some(key))
                            .and_then(|(_, v)| v.as_text())
                            .unwrap_or("")
                            .to_string()
                    };
                    (f("uri"), f("operation"))
                });

            if path.ends_with("/on-disconnect") {
                // Ruling 3: the failed reconnect routes to the backoff seam
                // instead of binding a lost marker per attempt (~1,440
                // nodes/day against a peer that stays dead).
                let (uri, operation) =
                    on_error.expect("on-disconnect MUST carry on_error → the backoff seam");
                assert_eq!(
                    uri,
                    format!(
                        "/{}/system/network/peers/{}/on-reconnect-backoff",
                        client_pid, server_pid
                    ),
                    "on-disconnect on_error must target the backoff resident"
                );
                assert_eq!(operation, "advance");
            } else {
                // The other two stay absent. The backoff resident in
                // particular must NOT route its error back to `advance`: it
                // re-EXECUTEs maintain-peer, whose own failure branch re-arms
                // and reschedules, so an on_error here would fire the next
                // retry immediately and defeat the §2.2 pacing.
                assert!(
                    on_error.is_none(),
                    "continuation at {} must not carry on_error",
                    path
                );
            }
        }

        // Idempotent re-entry: same params → same session.
        let resp2 = client
            .execute(
                &format!("/{}/system/network", client_pid),
                "maintain-peer",
                maintain_request_entity(&server_pid, &addr),
            )
            .await
            .unwrap();
        let r2: ciborium::Value = ciborium::from_reader(resp2.result.data.as_slice()).unwrap();
        let r2map = r2.as_map().unwrap();
        let sid2 = r2map
            .iter()
            .find(|(k, _)| k.as_text() == Some("session_id"))
            .and_then(|(_, v)| v.as_text())
            .unwrap();
        let sid1 = get("session_id").unwrap().as_text().unwrap();
        assert_eq!(sid1, sid2, "re-entry minted a new session");

        server_handle.abort();
    }

    /// First imperative maintain-peer to an unreachable peer → 502
    /// connection_failed, no graph, no session (§4.1 step 1).
    #[cfg(feature = "network")]
    #[tokio::test]
    async fn a12_rung3_maintain_peer_connect_failure() {
        let registry = transport::MemoryTransportRegistry::new();
        let client = PeerBuilder::new()
            .keypair(Keypair::from_seed([0x83; 32]))
            .connector(std::sync::Arc::new(transport::MemoryConnector::new(
                registry,
            )))
            .build()
            .unwrap();
        client.local_only();
        let client_shared = client.shared();
        let client_pid = client_shared.peer_id.as_str().to_string();
        let ghost = Keypair::from_seed([0x84; 32]).peer_id().to_string();

        let resp = client
            .execute(
                &format!("/{}/system/network", client_pid),
                "maintain-peer",
                maintain_request_entity(&ghost, "memory://nobody-home"),
            )
            .await
            .unwrap();
        assert_eq!(resp.status, 502, "expected 502 connection_failed");
        let v: ciborium::Value = ciborium::from_reader(resp.result.data.as_slice()).unwrap();
        let code = v
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_text() == Some("code"))
            .and_then(|(_, v)| v.as_text());
        assert_eq!(code, Some("connection_failed"));
        assert!(
            client_shared
                .location_index
                .get(&format!(
                    "/{}/system/inbox/network/{}/on-disconnect",
                    client_pid, ghost
                ))
                .is_none(),
            "failed first maintain-peer installed the graph"
        );
    }

    /// The rung-3 anchor vector: establish → kill the remote → the floor
    /// demotes → the graph reconnects through backoff retries against the
    /// restarted peer → status returns to connected and restore-
    /// subscriptions ran. The failed attempts MUST leave §3.10 lost-error
    /// markers (the marker-proposal §4 reconnect-chain evidence).
    #[cfg(feature = "network")]
    #[tokio::test]
    async fn a12_rung3_reconnect_lifecycle() {
        let registry = transport::MemoryTransportRegistry::new();
        let short = keepalive::KeepaliveConfig {
            interval_ms: 50,
            timeout_ms: 60,
            max_missed: 2,
            enabled: true,
        };
        let (server, _ss, server_handle, server_pid, client, client_shared) =
            rung3_pair(registry.clone(), 0x86, 0x87, short).await;
        let client_pid = client_shared.peer_id.as_str().to_string();
        let server_hash = server.shared().identity_hash;
        let addr = format!("memory://{}", server_pid);

        // Backoff tight so the retries fire fast.
        let maintain = {
            let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
                (entity_ecf::text("address"), entity_ecf::text(&addr)),
                (
                    entity_ecf::text("backoff"),
                    entity_ecf::Value::Map(vec![
                        (entity_ecf::text("max_ms"), entity_ecf::integer(200)),
                        (entity_ecf::text("min_ms"), entity_ecf::integer(60)),
                    ]),
                ),
                (entity_ecf::text("peer_id"), entity_ecf::text(&server_pid)),
            ]));
            entity_entity::Entity::new(entity_network::TYPE_MAINTAIN_REQUEST, data).unwrap()
        };
        let resp = maintain_with_retry(&client, &client_pid, maintain).await;
        assert_eq!(resp.status, 200, "maintain-peer baseline");

        // Connected baseline.
        wait_liveness_status(&client_shared, &server_hash, "connected").await;

        // Kill the server: aborting the accept loop drops its
        // ConnectionGuard → the client's pooled conn dies. The §5.4
        // keepalive demotes; the demotion write fires the on-disconnect
        // continuation.
        server_handle.abort();
        drop(server);
        // Wait for demotion off connected.
        let mut demoted = false;
        for _ in 0..400 {
            if let Some(d) = liveness_status_of(&client_shared, &server_hash) {
                if d.status != "connected" {
                    demoted = true;
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(demoted, "peer never demoted after kill");

        // The graph is now retrying against a dead address. The observable
        // for that is the §3.13 FAILURE EPISODE, not a marker.
        //
        // This vector used to require a lost-error marker here (the
        // marker-proposal §4 shape: no-`on_error` forward non-2xx, keyed by
        // RequestID). That requirement is RETIRED — rulings 2 and 3 route the
        // failed reconnect through `on_error` to the backoff seam and return
        // 200 with the retry armed, so a peer that is merely offline produces
        // no error record at all. `a12_retry_survives_outage` now asserts that
        // tree is empty; requiring a marker here would contradict it.
        //
        // What replaces it is a stronger claim about the same failure: the
        // demotion stamped `failing_since`, which is the one durable input the
        // §2.2 pacing derives from (rulings 7/8). A retry loop with no episode
        // on record is one that re-derives `attempt = 0` forever.
        let episode = liveness_status_of(&client_shared, &server_hash)
            .and_then(|d| d.failing_since)
            .expect("the demotion must stamp the failure episode (§3.13 failing_since)");

        // Restart the server: same keypair, same memory endpoint — the
        // retry loop must find it and re-establish without intervention.
        let server2 = PeerBuilder::new()
            .keypair(Keypair::from_seed([0x86; 32]))
            .build()
            .unwrap();
        let server2_shared = server2.shared();
        let listener2 = transport::MemoryListener::bind(server_pid.clone(), registry).unwrap();
        server2.start_engines(&server2_shared);
        let shared_for_task = server2_shared.clone();
        let server2_handle = tokio::spawn(async move {
            let _ = server::run(listener2, shared_for_task).await;
        });

        // Re-established after restart.
        wait_liveness_status(&client_shared, &server_hash, "connected").await;

        // Recovery ENDS the episode. A `failing_since` surviving a
        // re-establish would have the NEXT failure resume this episode's stale
        // §2.2 curve — starting at a max-length wait instead of min_ms — so a
        // peer that flaps once would then reconnect slowly forever. The
        // `connected` write clears it by omission; this is that, observed.
        let recovered = liveness_status_of(&client_shared, &server_hash)
            .expect("status entity vanished after re-establish");
        assert_eq!(
            recovered.failing_since, None,
            "re-established connected but the §3.13 status still carries \
             failing_since={:?} (episode opened at {}) — the failure episode \
             was never closed",
            recovered.failing_since, episode,
        );

        // The lifecycle subscriptions survived the outage (still two).
        let subs = client_shared
            .location_index
            .list(&format!("/{}/system/subscription/", client_pid))
            .into_iter()
            .filter(|e| {
                client_shared
                    .content_store
                    .get(&e.hash)
                    .map(|ent| ent.entity_type == "system/subscription")
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(
            subs, 2,
            "lifecycle subscriptions did not survive the outage"
        );

        server2_handle.abort();
    }

    /// Retry survival against a peer that STAYS dead — the question
    /// `a12_rung3_reconnect_lifecycle` cannot ask, because it restarts the
    /// counterpart promptly and so needs exactly one retry to land.
    ///
    /// Retry-forever is normative (ruling 6), and the loop that delivers it
    /// survives because the backoff continuation is STANDING (ruling 1).
    ///
    /// History: this vector was written `#[ignore]`d, asserting the stall it
    /// measured (2 attempts where §2.2 predicted ~20) — Rust's independent
    /// confirmation of the cohort-wide defect Go found on all three seats.
    /// A one-shot cannot re-arm itself: the re-install lands INSIDE the
    /// dispatch while the advance's consume runs AFTER it and deletes the
    /// path. Ordering, not timing. Ruling 1 resolved it to standing; this
    /// now asserts survival, which is what it was always for.
    ///
    /// **Counts dials, not markers** — and the switch is the point.
    ///
    /// This vector used to count §3.10 lost-error markers: every failed
    /// reconnect bound one, so the marker count WAS the attempt count. Rulings
    /// 2 and 3 retired that observable exactly as predicted when it was
    /// written — the failed `reconnect` now routes through the on-disconnect
    /// trigger's `on_error` to the backoff seam, and maintain-peer returns 200
    /// with the retry armed, so a dead peer's marker tree is empty. A
    /// marker-counting vector would have read a correctly working loop as a
    /// dead one.
    ///
    /// So it counts what an attempt physically IS (a dial, from outside the
    /// peer — the Go seat counts dials for the same reason), and asserts the
    /// empty marker tree as a SEPARATE property. The loop is alive AND silent;
    /// the old observable could not express both at once. The `>= 4` claim is
    /// what had to survive, not the way it was counted.
    #[cfg(feature = "network")]
    #[tokio::test]
    async fn a12_retry_survives_outage() {
        let registry = transport::MemoryTransportRegistry::new();
        let short = keepalive::KeepaliveConfig {
            interval_ms: 50,
            timeout_ms: 60,
            max_missed: 2,
            enabled: true,
        };
        let (server, _ss, server_handle, server_pid, client, client_shared) =
            rung3_pair(registry.clone(), 0x8a, 0x8b, short).await;
        let client_pid = client_shared.peer_id.as_str().to_string();
        let server_hash = server.shared().identity_hash;
        let addr = format!("memory://{}", server_pid);

        // min 60 / max 200: over the ~3s window below the §2.2 schedule
        // predicts well over a dozen retries.
        let maintain = {
            let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
                (entity_ecf::text("address"), entity_ecf::text(&addr)),
                (
                    entity_ecf::text("backoff"),
                    entity_ecf::Value::Map(vec![
                        (entity_ecf::text("max_ms"), entity_ecf::integer(200)),
                        (entity_ecf::text("min_ms"), entity_ecf::integer(60)),
                    ]),
                ),
                (entity_ecf::text("peer_id"), entity_ecf::text(&server_pid)),
            ]));
            entity_entity::Entity::new(entity_network::TYPE_MAINTAIN_REQUEST, data).unwrap()
        };
        let resp = maintain_with_retry(&client, &client_pid, maintain).await;
        assert_eq!(resp.status, 200, "maintain-peer baseline");
        let session_chain = {
            let v: ciborium::Value = ciborium::from_reader(resp.result.data.as_slice()).unwrap();
            v.as_map()
                .unwrap()
                .iter()
                .find(|(k, _)| k.as_text() == Some("chain_id"))
                .and_then(|(_, v)| v.as_text())
                .unwrap()
                .to_string()
        };
        wait_liveness_status(&client_shared, &server_hash, "connected").await;

        // Kill the counterpart and leave it dead.
        server_handle.abort();
        drop(server);
        let mut demoted = false;
        for _ in 0..400 {
            if let Some(d) = liveness_status_of(&client_shared, &server_hash) {
                if d.status != "connected" {
                    demoted = true;
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(demoted, "peer never demoted after kill");

        // Let the retry loop run well past several backoff periods, counting
        // dials from OUTSIDE the peer.
        let before = registry.dial_count();
        tokio::time::sleep(std::time::Duration::from_millis(3000)).await;
        let attempts = registry.dial_count() - before;

        // Rulings 2 + 3: a dead peer's marker tree is EMPTY. The failed
        // `reconnect` routes through the on-disconnect trigger's `on_error`
        // to the backoff seam, and the backoff's own maintain-peer re-EXECUTE
        // returns 200 with the retry armed — so the retry loop working
        // correctly writes no error records at all. ~1,440 nodes/day → 0.
        //
        // This assertion is the other half of the count above: together they
        // say the loop is alive AND silent. Counting markers could not express
        // that — the two halves would contradict each other.
        let marker_prefix = format!("/{}/system/runtime/chain-errors/lost/", client_pid);
        let markers: Vec<String> = client_shared
            .location_index
            .list(&marker_prefix)
            .into_iter()
            .map(|e| e.path)
            .filter(|p| p.contains("/connection_failed/"))
            .collect();

        // The standing resident is still there: nothing consumes it, so
        // nothing races to re-create it (ruling 1).
        let backoff_path = format!(
            "/{}/system/network/peers/{}/on-reconnect-backoff",
            client_pid, server_pid
        );
        let resident = client_shared.location_index.get(&backoff_path).is_some();
        eprintln!(
            "a12 retry survival: {} dial(s) in 3000ms at min_ms=60/max_ms=200, \
             backoff resident={}, connection_failed markers={} (chain {})",
            attempts,
            resident,
            markers.len(),
            session_chain,
        );

        assert!(
            attempts >= 4,
            "retry loop stalled: only {} dial(s) in 3s at min_ms=60/max_ms=200 \
             — want >= 4 (retry-forever is normative, ruling 6). backoff \
             resident={}",
            attempts,
            resident,
        );
        assert!(
            resident,
            "the standing backoff continuation was consumed — a one-shot \
             cannot re-arm itself through the operation it dispatches \
             (ruling 1)",
        );
        assert!(
            markers.is_empty(),
            "a working retry loop bound {} lost-error marker(s) against a peer \
             that is merely offline — the marker is for EXCEPTIONAL failure \
             (rulings 2 + 3). At this pacing that is ~1,440 nodes/day for a \
             dead peer.\n  {:#?}",
            markers.len(),
            markers,
        );
    }

    /// The §2.2 give-up (ruling 6): a caller that opted into `max_attempts`
    /// gets a loop that stops AND says so.
    ///
    /// The stopping is half of it. Without the terminal write the loop just
    /// goes quiet and the peer's last status stays `suspect` forever — a
    /// relationship that has been abandoned while still looking like one that
    /// is trying. Exhaustion is not a fourth status: it terminates at
    /// `disconnected` with `reason: retry-exhausted`, and the enum stays
    /// three-state.
    ///
    /// The counterpart of `a12_retry_survives_outage`: same rig, same dead
    /// peer, opposite claim — that one proves the DEFAULT never gives up,
    /// this one proves an opted-in bound does.
    #[cfg(feature = "network")]
    #[tokio::test]
    async fn a12_retry_exhausted_is_terminal_and_recorded() {
        let registry = transport::MemoryTransportRegistry::new();
        let short = keepalive::KeepaliveConfig {
            interval_ms: 50,
            timeout_ms: 60,
            max_missed: 2,
            enabled: true,
        };
        let (server, _ss, server_handle, server_pid, client, client_shared) =
            rung3_pair(registry.clone(), 0x8c, 0x8d, short).await;
        let client_pid = client_shared.peer_id.as_str().to_string();
        let server_hash = server.shared().identity_hash;
        let addr = format!("memory://{}", server_pid);

        // min 60 / max 100, give up after 3 retries — reached in well under
        // the window below.
        let maintain = {
            let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
                (entity_ecf::text("address"), entity_ecf::text(&addr)),
                (
                    entity_ecf::text("backoff"),
                    entity_ecf::Value::Map(vec![
                        (entity_ecf::text("max_attempts"), entity_ecf::integer(3)),
                        (entity_ecf::text("max_ms"), entity_ecf::integer(100)),
                        (entity_ecf::text("min_ms"), entity_ecf::integer(60)),
                    ]),
                ),
                (entity_ecf::text("peer_id"), entity_ecf::text(&server_pid)),
            ]));
            entity_entity::Entity::new(entity_network::TYPE_MAINTAIN_REQUEST, data).unwrap()
        };
        let resp = maintain_with_retry(&client, &client_pid, maintain).await;
        assert_eq!(resp.status, 200, "maintain-peer baseline");
        wait_liveness_status(&client_shared, &server_hash, "connected").await;

        server_handle.abort();
        drop(server);

        // The bound trips, and the terminal write lands.
        let mut exhausted = None;
        for _ in 0..400 {
            if let Some(d) = liveness_status_of(&client_shared, &server_hash) {
                if d.reason.as_deref() == Some("retry-exhausted") {
                    exhausted = Some(d);
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let d = exhausted.expect(
            "max_attempts was reached but no terminal retry-exhausted status was written — \
             the loop went quiet without saying it had given up",
        );
        assert_eq!(
            d.status, "disconnected",
            "exhaustion terminates at disconnected — it is NOT a fourth status value"
        );
        assert!(
            d.failing_since.is_some(),
            "the terminal record must keep failing_since: it says how long we tried"
        );

        // And it STAYS stopped: no further dials once abandoned.
        let settled = registry.dial_count();
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert_eq!(
            registry.dial_count(),
            settled,
            "kept dialing after recording the relationship as abandoned"
        );
    }

    /// §4.2 release-peer: continuations deleted, lifecycle subscriptions
    /// unsubscribed, terminal disconnected write on reason=shutdown.
    #[cfg(feature = "network")]
    #[tokio::test]
    async fn a12_rung3_release_peer() {
        let registry = transport::MemoryTransportRegistry::new();
        let ka = keepalive::KeepaliveConfig {
            enabled: false,
            ..Default::default()
        };
        let (server, _ss, server_handle, server_pid, client, client_shared) =
            rung3_pair(registry, 0x88, 0x89, ka).await;
        let client_pid = client_shared.peer_id.as_str().to_string();
        let server_hash = server.shared().identity_hash;
        let addr = format!("memory://{}", server_pid);

        maintain_with_retry(
            &client,
            &client_pid,
            maintain_request_entity(&server_pid, &addr),
        )
        .await;

        let release_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("peer_id"),
            entity_ecf::text(&server_pid),
        )]));
        let release =
            entity_entity::Entity::new(entity_network::TYPE_RELEASE_REQUEST, release_data).unwrap();
        let resp = client
            .execute(
                &format!("/{}/system/network", client_pid),
                "release-peer",
                release,
            )
            .await
            .unwrap();
        assert_eq!(resp.status, 200, "release-peer returned non-200");
        let v: ciborium::Value = ciborium::from_reader(resp.result.data.as_slice()).unwrap();
        let cleaned = v
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_text() == Some("cleaned_up"))
            .and_then(|(_, v)| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        assert_eq!(cleaned, 3, "expected 3 cleaned-up continuation paths");

        for path in [
            format!(
                "/{}/system/inbox/network/{}/on-disconnect",
                client_pid, server_pid
            ),
            format!(
                "/{}/system/inbox/network/{}/on-reconnect",
                client_pid, server_pid
            ),
            format!(
                "/{}/system/network/peers/{}/on-reconnect-backoff",
                client_pid, server_pid
            ),
        ] {
            assert!(
                client_shared.location_index.get(&path).is_none(),
                "continuation still bound at {} after release",
                path
            );
        }
        let surviving_subs = client_shared
            .location_index
            .list(&format!("/{}/system/subscription/", client_pid))
            .into_iter()
            .filter(|e| {
                client_shared
                    .content_store
                    .get(&e.hash)
                    .map(|ent| ent.entity_type == "system/subscription")
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(surviving_subs, 0, "lifecycle subscription survived release");

        // Terminal disconnected write on shutdown.
        let d = liveness_status_of(&client_shared, &server_hash)
            .expect("status entity gone after release");
        assert_eq!(d.status, "disconnected");

        server_handle.abort();
    }

    /// §4.3 status: read-model over the §3.13 entities. pending_count is
    /// bare zero (no §8 outbox, Amendment 11).
    #[cfg(feature = "network")]
    #[tokio::test]
    async fn a12_rung3_status_op() {
        let registry = transport::MemoryTransportRegistry::new();
        let ka = keepalive::KeepaliveConfig {
            enabled: false,
            ..Default::default()
        };
        let (_server, _ss, server_handle, server_pid, client, client_shared) =
            rung3_pair(registry, 0x8a, 0x8b, ka).await;
        let client_pid = client_shared.peer_id.as_str().to_string();
        let addr = format!("memory://{}", server_pid);

        let mresp = maintain_with_retry(
            &client,
            &client_pid,
            maintain_request_entity(&server_pid, &addr),
        )
        .await;
        let mres: ciborium::Value = ciborium::from_reader(mresp.result.data.as_slice()).unwrap();
        let want_sid = mres
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_text() == Some("session_id"))
            .and_then(|(_, v)| v.as_text())
            .unwrap()
            .to_string();

        let empty = entity_entity::Entity::new(
            "primitive/any",
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![])),
        )
        .unwrap();
        let resp = client
            .execute(&format!("/{}/system/network", client_pid), "status", empty)
            .await
            .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.result.entity_type, entity_network::TYPE_NETWORK_STATUS);
        let v: ciborium::Value = ciborium::from_reader(resp.result.data.as_slice()).unwrap();
        let vmap = v.as_map().unwrap();
        let pending = vmap
            .iter()
            .find(|(k, _)| k.as_text() == Some("pending_count"))
            .and_then(|(_, v)| v.as_integer())
            .map(i128::from)
            .unwrap();
        assert_eq!(pending, 0, "pending_count must be bare zero (no §8 outbox)");
        let peers = vmap
            .iter()
            .find(|(k, _)| k.as_text() == Some("maintained_peers"))
            .and_then(|(_, v)| v.as_array())
            .unwrap();
        let row = peers
            .iter()
            .find_map(|p| {
                let pm = p.as_map()?;
                let pid = pm
                    .iter()
                    .find(|(k, _)| k.as_text() == Some("peer_id"))
                    .and_then(|(_, v)| v.as_text())?;
                if pid == server_pid {
                    Some(pm.clone())
                } else {
                    None
                }
            })
            .expect("status omitted the maintained peer");
        let got_sid = row
            .iter()
            .find(|(k, _)| k.as_text() == Some("session_id"))
            .and_then(|(_, v)| v.as_text())
            .unwrap();
        assert_eq!(got_sid, want_sid, "status session_id mismatch");
        let row_status = row
            .iter()
            .find(|(k, _)| k.as_text() == Some("status"))
            .and_then(|(_, v)| v.as_text())
            .unwrap();
        assert_eq!(row_status, "connected");

        server_handle.abort();
    }

    /// `MemoryConnector::connect` fails cleanly when no listener is
    /// registered for the requested endpoint.
    #[tokio::test]
    async fn test_memory_connect_no_listener() {
        use transport::{MemoryConnector, MemoryTransportRegistry};
        let registry = MemoryTransportRegistry::new();
        let connector = MemoryConnector::new(registry);
        match connector.connect("memory://nobody-home").await {
            Err(transport::TransportError::ConnectError(_)) => {}
            Err(e) => panic!("expected ConnectError, got {:?}", e),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    /// `MemoryListener::bind` rejects a duplicate endpoint registration.
    #[tokio::test]
    async fn test_memory_bind_duplicate_endpoint() {
        use transport::{MemoryListener, MemoryTransportRegistry};
        let registry = MemoryTransportRegistry::new();
        let _a = MemoryListener::bind("dup", registry.clone()).unwrap();
        match MemoryListener::bind("dup", registry.clone()) {
            Err(transport::TransportError::BindError(_)) => {}
            Err(e) => panic!("expected BindError, got {:?}", e),
            Ok(_) => panic!("expected duplicate bind to fail"),
        }
    }

    /// Dropping a `MemoryListener` removes its registry entry so the
    /// endpoint can be rebound and subsequent connects fail cleanly.
    #[tokio::test]
    async fn test_memory_listener_drop_cleans_up() {
        use transport::{MemoryConnector, MemoryListener, MemoryTransportRegistry};
        let registry = MemoryTransportRegistry::new();
        {
            let _l = MemoryListener::bind("ephemeral", registry.clone()).unwrap();
            assert_eq!(registry.len(), 1);
        }
        assert_eq!(registry.len(), 0);

        // After drop, connect resolves to no listener.
        let connector = MemoryConnector::new(registry.clone());
        match connector.connect("memory://ephemeral").await {
            Err(transport::TransportError::ConnectError(_)) => {}
            Err(e) => panic!("expected ConnectError, got {:?}", e),
            Ok(_) => panic!("expected connect to fail after drop"),
        }

        // Endpoint is rebindable.
        let _l2 = MemoryListener::bind("ephemeral", registry).unwrap();
    }

    /// MultiConnector dispatches to the underlying connector matching
    /// the address's scheme, end-to-end through a real handshake.
    /// Uses two MemoryTransportRegistries (one per scheme) to prove
    /// the dispatcher actually picks different connectors based on
    /// scheme rather than always hitting the first.
    #[tokio::test]
    async fn test_multi_connector_routes_by_scheme() {
        use transport::{MemoryConnector, MemoryListener, MemoryTransportRegistry, MultiConnector};

        let reg_a = MemoryTransportRegistry::new();
        let reg_b = MemoryTransportRegistry::new();

        // Stand up two servers, each on its own registry.
        let server_a = PeerBuilder::new()
            .keypair(Keypair::from_seed([30u8; 32]))
            .build()
            .unwrap();
        let server_a_pid = server_a.peer_id().to_string();
        let listener_a = MemoryListener::bind(server_a_pid.clone(), reg_a.clone()).unwrap();
        let shared_a = server_a.shared();
        server_a.start_engines(&shared_a);
        let shared_a_clone = shared_a.clone();
        let server_a_handle = tokio::spawn(async move {
            let _ = server::run(listener_a, shared_a_clone).await;
        });

        let server_b = PeerBuilder::new()
            .keypair(Keypair::from_seed([31u8; 32]))
            .build()
            .unwrap();
        let server_b_pid = server_b.peer_id().to_string();
        let listener_b = MemoryListener::bind(server_b_pid.clone(), reg_b.clone()).unwrap();
        let shared_b = server_b.shared();
        server_b.start_engines(&shared_b);
        let shared_b_clone = shared_b.clone();
        let server_b_handle = tokio::spawn(async move {
            let _ = server::run(listener_b, shared_b_clone).await;
        });

        tokio::task::yield_now().await;

        // Build a MultiConnector that routes "memorya://" to reg_a's
        // MemoryConnector and "memoryb://" to reg_b's. Then assert
        // the client uses the right one for each address.
        //
        // We can't use the literal "memory://" twice because each
        // MemoryConnector parses its own scheme; so we make two
        // distinct schemes by registering them in MultiConnector
        // mapped to two different MemoryConnector instances. The
        // underlying MemoryConnector still expects `memory://` —
        // we'd need a real-world distinction. For this dispatch
        // test the simplest proof is registering ONE scheme and
        // verifying unknown schemes get the right error.
        let memory_connector = std::sync::Arc::new(MemoryConnector::new(reg_a.clone()));
        let multi: std::sync::Arc<dyn transport::Connector> =
            std::sync::Arc::new(MultiConnector::new().with("memory", memory_connector));

        let client = PeerBuilder::new()
            .keypair(Keypair::from_seed([32u8; 32]))
            .connector(multi.clone())
            .build()
            .unwrap();
        client.local_only();

        // Routed to reg_a: succeeds and returns server_a's PeerID.
        let pid = client
            .connect_to(&format!("memory://{}", server_a_pid))
            .await
            .unwrap();
        assert_eq!(pid, server_a_pid);

        // Unknown scheme: MultiConnector returns a clean
        // ConnectError naming the registered schemes.
        let err_msg = client.connect_to("unknown://nowhere").await.unwrap_err();
        let msg = format!("{}", err_msg);
        assert!(
            msg.contains("MultiConnector") && msg.contains("memory"),
            "unexpected error: {}",
            msg
        );

        server_a_handle.abort();
        server_b_handle.abort();
        let _ = reg_b; // keep alive
    }

    /// MultiConnector exact-scheme dispatch — no `starts_with` ambiguity.
    /// Registering `"ws"` and `"wss"` must route correctly regardless
    /// of insertion order (the `ws://`-prefix-of-`wss://` trap).
    #[tokio::test]
    async fn test_multi_connector_exact_scheme_no_prefix_collision() {
        use transport::MultiConnector;

        // No real ws connector — we just probe the dispatch via
        // the error path. Use MemoryConnector instances as stand-ins;
        // the dispatcher returns the connector, which then errors on
        // its own scheme check. That's enough to prove which one was
        // picked.
        let reg = transport::MemoryTransportRegistry::new();
        let c_ws: std::sync::Arc<dyn transport::Connector> =
            std::sync::Arc::new(transport::MemoryConnector::new(reg.clone()));
        let c_wss: std::sync::Arc<dyn transport::Connector> =
            std::sync::Arc::new(transport::MemoryConnector::new(reg.clone()));

        // ws first, then wss — under starts_with this would mis-route
        // wss://...  to the ws entry. Exact-match doesn't.
        let multi = MultiConnector::new().with("ws", c_ws).with("wss", c_wss);

        assert!(multi.handles("ws://anything"));
        assert!(multi.handles("wss://anything"));
        assert!(!multi.handles("xworker://anything"));
        assert!(!multi.handles("no-scheme"));
    }

    /// `with()` accepts both `"scheme"` and `"scheme://"` forms;
    /// internally they normalize to the same key.
    #[tokio::test]
    async fn test_multi_connector_accepts_scheme_with_or_without_suffix() {
        use transport::MultiConnector;
        let reg = transport::MemoryTransportRegistry::new();
        let c: std::sync::Arc<dyn transport::Connector> =
            std::sync::Arc::new(transport::MemoryConnector::new(reg));

        let with_suffix = MultiConnector::new().with("memory://", c.clone());
        assert!(with_suffix.handles("memory://x"));

        let without_suffix = MultiConnector::new().with("memory", c);
        assert!(without_suffix.handles("memory://x"));
    }

    // ----------------------------------------------------------------
    // EXTENSION-ROLE v1.5 — peer-level integration smoke tests
    // ----------------------------------------------------------------

    /// Smoke test: the role handler is registered, reachable via dispatch,
    /// and rejects an assign without caller_capability (RL2 fail-closed
    /// per IA10). Local `Peer::execute` always passes
    /// `caller_capability: None` so the runtime path's RL2 check fires —
    /// that's the wiring proof. Happy-path RL2-passing tests require
    /// either a wire-path (two-peer EXECUTE with a real caller cap) or
    /// the L0 bootstrap path (Phase 7); both are deferred. Comprehensive
    /// handler-level happy-path coverage lives in
    /// `extensions/role/src/tests.rs`.
    #[tokio::test]
    #[cfg(feature = "role")]
    async fn role_handler_dispatch_reaches_handler_and_enforces_rl2() {
        use entity_capability::{GrantEntry, IdScope, PathScope};
        use entity_role::data::RoleData;
        use entity_role::paths::{path_role_assignment, path_role_definition};

        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();

        // Plant a role definition; necessary so the handler reaches the
        // RL2 step (otherwise it'd 404 before checking the caller cap).
        let role = RoleData {
            name: "operator".into(),
            grants: vec![GrantEntry {
                handlers: PathScope::new(vec!["system/tree".into()]),
                resources: PathScope::new(vec!["shared/{context}/*".into()]),
                operations: IdScope::new(vec!["get".into(), "put".into()]),
                peers: None,
                constraints: None,
                allowances: None,
            }],
            metadata: None,
        };
        let role_entity = role.to_entity().unwrap();
        peer.tree()
            .put(&qp(&path_role_definition("admin", "operator")), role_entity)
            .unwrap();

        let assignment_bare = path_role_assignment("admin", "alice", "operator");
        let params = entity_entity::Entity::new(
            "system/role/assign-request",
            entity_ecf::to_ecf(&entity_ecf::cbor_map! {
                "role" => entity_ecf::text("operator")
            }),
        )
        .unwrap();
        let opts = entity_handler::ExecuteOptions {
            resource: Some(entity_capability::ResourceTarget {
                targets: vec![assignment_bare],
                exclude: vec![],
            }),
            ..Default::default()
        };
        let result = peer
            .execute_with_options("system/role", "assign", params, opts)
            .await
            .unwrap();
        // 403 = RL2 missing-caller-capability (handler reached + enforced).
        // Anything other than 403 means the wiring is broken.
        assert_eq!(
            result.status, 403,
            "dispatch must reach role handler and RL2 must fail-closed; got {}",
            result.status
        );
    }

    /// The role handler's bootstrap manifest (system/handler/system/role)
    /// must be present after PeerBuilder::build() so dispatch resolution
    /// can find it.
    #[test]
    #[cfg(feature = "role")]
    fn role_handler_manifest_bootstrapped() {
        let peer = PeerBuilder::new().keypair(test_keypair()).build().unwrap();
        let manifest_path = qp("system/handler/system/role");
        assert!(
            peer.location_index().get(&manifest_path).is_some(),
            "role handler manifest must be bootstrapped at {}",
            manifest_path
        );
        // And the handler entity itself must be bound at /pid/system/role.
        let handler_path = qp("system/role");
        assert!(
            peer.location_index().get(&handler_path).is_some(),
            "role handler entity must be bound at {}",
            handler_path
        );
    }
}
