//! Phase P resolution-substrate baseline — `system/peer/published-root`
//! publisher + http-poll outbound verification/walk.
//!
//! Spec: `PROPOSAL-PEER-MANIFEST-STATIC-HANDSHAKE.md` §1 (threat model), §2
//! (trust model), §4 (`published-root`, NORMATIVE-LOCKED).
//!
//! **Publisher** ([`PublishRootEngine`]) — on tree-root change, authors + signs
//! a `published-root` entity (monotonic `seq`, `predecessor` chain), carries the
//! signature at the invariant-pointer path, and binds the current head at
//! `/{peer}/system/peer/published-root` so `MANIFEST_GET` serves the latest.
//! [`PublishRootHook`] is the "on tree-root change" half: a `SyncTreeHook`
//! watching the `RootTrackerEngine`'s `system/tree/root/{P}` binding, so the
//! republish is O(1) per tree change rather than an O(tree) rebuild per put.
//!
//! **Consumer** ([`PublishedRootClient`]) — fetches a peer's signed root,
//! verifies the signature against a **pinned** publisher key (the §2 trust
//! model: the signature defends against an untrusted intermediary), enforces
//! `seq` monotonicity (rollback rejection, §1.4), and resolves a path by
//! walking the HAMT **from the signed `root_hash`** — never trusting a
//! host-served `path → hash` binding (§1.1). Content is hash-verified on
//! receive (§1.2). The walk + verification are transport-agnostic over a
//! [`ContentFetcher`]; [`HttpPollFetcher`] is the live reqwest-backed impl.

use std::sync::Arc;
use std::sync::Mutex;

use entity_crypto::{verify_for_key_type, IdentityKeypair, KeyType};
use entity_entity::Entity;
use entity_hash::{default_hash_format, invariant_signature_path, Hash};
use entity_store::{
    CascadeHalt, ContentStore, ExecutionContext, LocationIndex, StoreError, SyncTreeHook,
    TreeChangeEvent,
};
use entity_tree::root_tracker::PUBLISHED_ROOT_HANDLER_PATTERN;
use entity_tree::trie::trie_get;
use entity_types::{PublishedRootData, SignatureData, TYPE_PUBLISHED_ROOT};

/// Well-known head-pointer path holding the current published-root hash.
pub fn published_root_head_path(peer_id: &str) -> String {
    format!("/{}/system/peer/published-root", peer_id)
}

fn now_ms() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, thiserror::Error)]
pub enum PublishedRootError {
    #[error("store error: {0}")]
    Store(String),
    #[error("encode error: {0}")]
    Encode(String),
    #[error("decode error: {0}")]
    Decode(String),
    #[error("published-root signature missing")]
    SignatureMissing,
    #[error("published-root signature invalid")]
    SignatureInvalid,
    #[error("peer_id mismatch: expected {expected}, got {got}")]
    PeerIdMismatch { expected: String, got: String },
    #[error("seq rollback: cached {cached}, received {received}")]
    SeqRollback { cached: u64, received: u64 },
    #[error("content hash mismatch (host served bytes that do not match the requested hash)")]
    ContentHashMismatch,
    #[error("path does not hash-chain from the signed root")]
    PathNotInSignedTree,
    #[error("fetch error: {0}")]
    Fetch(String),
}

impl From<StoreError> for PublishedRootError {
    fn from(e: StoreError) -> Self {
        PublishedRootError::Store(e.to_string())
    }
}

// ===========================================================================
// Publisher — task P1/P2 publisher half
// ===========================================================================

/// Authors + signs `system/peer/published-root` entities and serves them via
/// the head pointer (read by `MANIFEST_GET`).
pub struct PublishRootEngine {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    keypair: IdentityKeypair,
    peer_id: String,
    identity_hash: Hash,
    /// EXTENSION-TREE §3.3's `absolute_prefix` — the operand this publisher's
    /// trie keys are relative to, declared on every published root (§3.3a).
    /// Derived from the tracker via `qualified_bare_prefix` rather than from
    /// the operator's bare flag, so the declaration cannot drift from the trim
    /// that actually produced the keys.
    prefix: String,
}

impl PublishRootEngine {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        keypair: IdentityKeypair,
        peer_id: String,
        identity_hash: Hash,
        prefix: impl Into<String>,
    ) -> Self {
        Self {
            content_store,
            location_index,
            keypair,
            peer_id,
            identity_hash,
            prefix: prefix.into(),
        }
    }

    /// The §3.3a prefix this publisher declares.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    fn head_path(&self) -> String {
        published_root_head_path(&self.peer_id)
    }

    /// The cascade context every publisher write carries. The
    /// `handler_pattern` tag is what lets `RootTrackerEngine` skip these
    /// writes: both of them land inside a `system/`-or-universal tracked
    /// prefix, so untagged they would advance the trie root and re-fire the
    /// publisher (see [`entity_tree::root_tracker::is_feedback_loop_handler`]).
    ///
    /// A fresh context rather than the ambient cascade's: a republish is the
    /// publisher's own act, not a continuation of whatever write moved the
    /// root. Mirrors Go's `publisherCtx` (`ext/publishedroot/publisher.go`).
    fn write_context(&self) -> ExecutionContext {
        ExecutionContext {
            author: Some(self.identity_hash),
            handler_pattern: Some(PUBLISHED_ROOT_HANDLER_PATTERN.to_string()),
            operation: Some("publish".to_string()),
            ..Default::default()
        }
    }

    /// The current head published-root hash (what `MANIFEST_GET` serves).
    pub fn current_head_hash(&self) -> Option<Hash> {
        self.location_index.get(&self.head_path())
    }

    /// The current head published-root, decoded.
    pub fn current_head(&self) -> Option<(Hash, PublishedRootData)> {
        let h = self.current_head_hash()?;
        let e = self.content_store.get(&h)?;
        PublishedRootData::from_entity(&e).ok().map(|d| (h, d))
    }

    /// Author + sign a new published-root committing to `root_hash`. `seq`
    /// increments from the prior head (recovered on startup from the tree);
    /// `predecessor` chains to it. Re-publishing an unchanged `root_hash` is a
    /// no-op (returns the existing head) so idempotent tree writes don't churn
    /// the chain. Returns the new (or unchanged) head hash.
    pub fn publish(&self, root_hash: Hash) -> Result<Hash, PublishedRootError> {
        let prev = self.current_head();
        if let Some((prev_hash, prev_data)) = &prev {
            if prev_data.root_hash == root_hash {
                return Ok(*prev_hash);
            }
        }
        let (seq, predecessor) = match &prev {
            Some((prev_hash, prev_data)) => (prev_data.seq + 1, Some(*prev_hash)),
            None => (0, None),
        };
        let pr = PublishedRootData {
            peer_id: self.peer_id.clone(),
            root_hash,
            prefix: self.prefix.clone(),
            seq,
            published_at: now_ms(),
            predecessor,
        };
        let entity = pr
            .to_entity()
            .map_err(|e| PublishedRootError::Encode(e.to_string()))?;
        let hash = entity.content_hash;
        self.content_store.put(entity)?;

        // Sign the published-root's content hash; carry the signature at the
        // invariant-pointer path (§4 — NOT a refs: block).
        let sig = SignatureData {
            target: hash,
            signer: self.identity_hash,
            algorithm: self.keypair.key_type().label().to_string(),
            signature: self.keypair.sign(&hash.to_bytes()),
        };
        let sig_entity = sig
            .to_entity()
            .map_err(|e| PublishedRootError::Encode(e.to_string()))?;
        let sig_hash = sig_entity.content_hash;
        self.content_store.put(sig_entity)?;
        let _ = self.location_index.set_with_context(
            &invariant_signature_path(&self.peer_id, &hash),
            sig_hash,
            self.write_context(),
        );

        // ⛔ **THE ORDER IS LOAD-BEARING — signature first, head last (NETWORK
        // §1.1: the PUBLISHER-SIDE window of the published-root verify race).**
        // `MANIFEST_GET` reads this binding, and a consumer that gets head *N*
        // back immediately fetches *N*'s signature. Bind the head before its
        // signature and there is a window in which the peer is serving a head
        // whose signature **does not yet exist**: the consumer's second fetch
        // 404s, and an unsigned-looking root is the one thing it must refuse.
        // The two writes are separate `set` calls with no transaction between
        // them, so ordering is the entire defence.
        //
        // The consumer-side window of the same race is closed at
        // `http_live::scope::ClosureScope::refresh` (the retained-anchor ring);
        // core-py measured that BOTH windows redden `published_root.v5_outbound_dial`
        // and neither alone leaves it green, so neither fix is the other's spare.
        // Pinned by `publish_binds_the_signature_before_the_head`, which fails if
        // these two blocks are ever swapped.
        let _ = self
            .location_index
            .set_with_context(&self.head_path(), hash, self.write_context());
        Ok(hash)
    }
}

// ===========================================================================
// Publisher hook — "on tree-root change" (PROPOSAL-PEER-MANIFEST §4 P1)
// ===========================================================================

/// Republishes `system/peer/published-root` whenever the tracked trie root for
/// one prefix advances.
///
/// The hook watches exactly one path — the `RootTrackerEngine`'s output binding
/// for its prefix (`system/tree/root` for the universal prefix, else
/// `system/tree/root/{P}`) — and re-signs the hash bound there. That is the
/// whole cost: the tracker already maintains the root **incrementally**
/// (`trie_put`/`trie_remove` along one path), so a republish is one signature
/// and two entities per tree change, not a `location_index.list()` +
/// `build_trie` over the served subtree per put (the O(tree)-per-put shape
/// `perf_treeput_1100` exists to catch).
///
/// Recursion is broken at the tracker, not here: the publisher's own two writes
/// are tagged [`PUBLISHED_ROOT_HANDLER_PATTERN`] and the tracker skips them, so
/// they never move the root that would re-fire this hook. `publishing` is the
/// belt-and-braces second guard (matching Go's re-entry sentinel) in case a
/// future consumer relays a root write back around.
pub struct PublishRootHook {
    engine: PublishRootEngine,
    /// Absolute path of the tracked-root binding this publisher follows.
    tracked_root_path: String,
    publishing: Mutex<bool>,
}

impl PublishRootHook {
    pub fn new(engine: PublishRootEngine, tracked_root_path: impl Into<String>) -> Self {
        Self {
            engine,
            tracked_root_path: tracked_root_path.into(),
            publishing: Mutex::new(false),
        }
    }

    /// The tracked-root path this hook watches.
    pub fn tracked_root_path(&self) -> &str {
        &self.tracked_root_path
    }

    /// Publish `root_hash` under the re-entry guard. Returns `None` when a
    /// publish is already in flight on this hook (the in-flight one subsumes
    /// this call) — never an error the caller must distinguish.
    fn guarded_publish(&self, root_hash: Hash) -> Option<Result<Hash, PublishedRootError>> {
        {
            let mut in_flight = self.publishing.lock().unwrap();
            if *in_flight {
                return None;
            }
            *in_flight = true;
        }
        let result = self.engine.publish(root_hash);
        *self.publishing.lock().unwrap() = false;
        Some(result)
    }

    /// Publish the tracked root as it stands now. Used at startup, when the
    /// tracker already holds a root (a restart off persistent storage, or a
    /// bootstrap rebuild that ran before this hook was registered) and so no
    /// change event is coming. A no-op when `root_hash` already matches the
    /// current head.
    pub fn publish_initial(&self, root_hash: Hash) -> Result<Hash, PublishedRootError> {
        match self.guarded_publish(root_hash) {
            Some(r) => r,
            // A publish is in flight; it covers this root.
            None => self
                .engine
                .current_head_hash()
                .ok_or(PublishedRootError::SignatureMissing),
        }
    }

    /// The current head hash, if anything has been published.
    pub fn current_head_hash(&self) -> Option<Hash> {
        self.engine.current_head_hash()
    }
}

impl SyncTreeHook for PublishRootHook {
    fn on_tree_change(
        &self,
        event: &TreeChangeEvent,
        _ctx: &mut ExecutionContext,
    ) -> Result<(), CascadeHalt> {
        if event.path != self.tracked_root_path {
            return Ok(());
        }
        // A delete at the tracked-root path means the prefix was disabled or
        // removed (EXTENSION-TREE §3.4.1a hot-reload), not a new root. Leave
        // the last published head standing rather than signing a zero root.
        let root_hash = match event.new_hash {
            Some(h) => h,
            None => return Ok(()),
        };
        match self.guarded_publish(root_hash) {
            Some(Ok(head)) => tracing::debug!(
                root = %root_hash,
                head = %head,
                "[published-root] republished on tracked-root change"
            ),
            Some(Err(e)) => tracing::error!(
                root = %root_hash,
                error = %e,
                "[published-root] republish failed"
            ),
            None => tracing::debug!(
                root = %root_hash,
                "[published-root] publish already in flight; skipping re-entry"
            ),
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "peer/published-root-publisher"
    }

    fn handler_pattern(&self) -> &str {
        PUBLISHED_ROOT_HANDLER_PATTERN
    }
}

// ===========================================================================
// Pure verification (no I/O) — shared by sync + async consumers
// ===========================================================================

/// Decode + hash-verify a content body fetched by hash. Mechanism A (§1.2):
/// the consumer trusts the bytes only if they **re-hash** to the requested
/// hash. The body is parsed form-agnostically — both the 3-key authored form
/// and the 2-key `CONTENT_GET` form (`{data, type}`) are accepted — and the
/// hash is **recomputed** from `(type, data)` under the requested hash's own
/// format code. Any `content_hash` the host put on the wire is never read: a
/// host serving `{type, data:<evil>, content_hash:<expected>}` is rejected
/// because the recompute over `<evil>` will not equal `expected`.
pub fn verify_content(bytes: &[u8], expected: &Hash) -> Result<Entity, PublishedRootError> {
    let (entity_type, data) = entity_wire::decode_entity_parts(bytes)
        .map_err(|e| PublishedRootError::Decode(e.to_string()))?;
    // Recompute under the EXPECTED hash's format (§1.8 validate-on-receipt) —
    // never trust a wire-supplied content_hash. `new_with_format` rejects an
    // unsupported format code, which surfaces as a decode error.
    let entity = Entity::new_with_format(&entity_type, data, expected.algorithm)
        .map_err(|e| PublishedRootError::Decode(e.to_string()))?;
    if &entity.content_hash != expected {
        return Err(PublishedRootError::ContentHashMismatch);
    }
    Ok(entity)
}

/// Verify a fetched published-root against a **pinned** publisher key.
///
/// `manifest_bytes` is the published-root entity ECF; `signature_bytes` is its
/// `system/signature` entity ECF (carried per the §4 invariant pointer).
/// Verifies: (a) the published-root entity re-hashes consistently; (b) the
/// signature targets it and validates against `pinned_pubkey`; (c) the
/// `peer_id` matches `expected_peer_id` when given. Returns
/// `(published_root_hash, data)`. Does NOT enforce `seq` monotonicity — that is
/// stateful and lives in the client.
pub fn verify_signed_root(
    manifest_bytes: &[u8],
    signature_bytes: Option<&[u8]>,
    pinned_pubkey: &[u8],
    pinned_key_type: KeyType,
    expected_peer_id: Option<&str>,
) -> Result<(Hash, PublishedRootData), PublishedRootError> {
    // The manifest is served as a full wire entity (§6.5.3.1 MANIFEST_GET), so
    // it carries its own `content_hash` (with the publisher's format code). We
    // read that format but NEVER trust the digest: recompute under it and
    // require equality (§1.2 host-bytes-distrust). A host that swaps `data` —
    // e.g. to repoint the inner `root_hash` at an attacker-chosen tree while
    // keeping the outer hash that the publisher signed — fails the recompute,
    // and it cannot forge the publisher signature over the genuine hash.
    let entity = entity_wire::decode_entity(manifest_bytes)
        .map_err(|e| PublishedRootError::Decode(e.to_string()))?;
    if entity.entity_type != TYPE_PUBLISHED_ROOT {
        return Err(PublishedRootError::Decode(format!(
            "expected {}, got {}",
            TYPE_PUBLISHED_ROOT, entity.entity_type
        )));
    }
    Hash::validate(&entity.entity_type, &entity.data, &entity.content_hash)
        .map_err(|_| PublishedRootError::ContentHashMismatch)?;
    let root_hash = entity.content_hash;
    let data = PublishedRootData::from_entity(&entity)
        .map_err(|e| PublishedRootError::Decode(e.to_string()))?;

    if let Some(expected) = expected_peer_id {
        if data.peer_id != expected {
            return Err(PublishedRootError::PeerIdMismatch {
                expected: expected.to_string(),
                got: data.peer_id.clone(),
            });
        }
    }

    let sig_bytes = signature_bytes.ok_or(PublishedRootError::SignatureMissing)?;
    // The signature entity may be served in either the 3-key authored form or
    // the 2-key `CONTENT_GET` form, so decode it form-agnostically. Its own
    // `content_hash` is not security-relevant — trust comes from the Ed25519
    // verify against the pinned key below, not from the entity's self-hash —
    // so we reconstruct it under the floor format purely to parse the data.
    let (sig_type, sig_data) = entity_wire::decode_entity_parts(sig_bytes)
        .map_err(|e| PublishedRootError::Decode(e.to_string()))?;
    let sig_entity = Entity::new_with_format(&sig_type, sig_data, default_hash_format())
        .map_err(|e| PublishedRootError::Decode(e.to_string()))?;
    let sig = SignatureData::from_entity(&sig_entity)
        .map_err(|e| PublishedRootError::Decode(e.to_string()))?;
    if sig.target != root_hash {
        return Err(PublishedRootError::SignatureInvalid);
    }
    verify_for_key_type(
        pinned_key_type,
        pinned_pubkey,
        &root_hash.to_bytes(),
        &sig.signature,
    )
    .map_err(|_| PublishedRootError::SignatureInvalid)?;

    Ok((root_hash, data))
}

// ===========================================================================
// Consumer — sync transport-agnostic client (task P5 verification core)
// ===========================================================================

/// Transport-agnostic fetch surface for the outbound connector. Errors are
/// transport-level (connection / HTTP status) and carried as strings.
pub trait ContentFetcher: Send + Sync {
    /// `MANIFEST_GET` → the published-root entity ECF bytes.
    fn manifest(&self) -> Result<Vec<u8>, String>;
    /// `CONTENT_GET {hash}` → entity ECF bytes (verified by the caller).
    fn content(&self, hash: &Hash) -> Result<Vec<u8>, String>;
    /// The published-root's `system/signature` entity ECF, if served. May be
    /// fetched host-trusted (a forged signature simply fails verification).
    fn signature_for(&self, target: &Hash) -> Result<Option<Vec<u8>>, String>;
}

/// A hash-verifying [`ContentStore`] view over a [`ContentFetcher`], so the
/// shared sync [`trie_get`] walk fetches + verifies each HAMT node by hash.
///
/// **It records a hash mismatch, because `ContentStore::get` cannot report
/// one.** The trait returns `Option<Entity>`, so a body that does not hash to
/// its own address leaves by the same door as a body that was never there — and
/// [`trie_get`] then reads that as *no such branch*, so the walk ends
/// `Ok(None)`. A consumer therefore learns "that key is not in the signed tree"
/// about an origin that just served bytes matching no hash the root committed
/// to: an absence, reported for a forgery.
///
/// Found downstream (entity-browser-rust, 2026-08-19) by flipping one byte in
/// each blob a resolve fetches. The **leaf** was always safe — [`resolve`]
/// hashes it directly and returns [`PublishedRootError::ContentHashMismatch`] —
/// and every **interior** node was not.
///
/// The mismatch is latched here and consulted by [`PublishedRootClient::resolve`]
/// before it believes a `None`. A flag rather than an error channel because the
/// store is `&self` behind a trait we do not own — and an **atomic** rather than
/// a `Cell` because `ContentStore` is `Send + Sync`, so interior mutability here
/// has to be too, even though the walk is single-threaded per resolve and the
/// store is built fresh for each one.
///
/// [`resolve`]: PublishedRootClient::resolve
struct VerifyingFetchStore<'a> {
    fetcher: &'a dyn ContentFetcher,
    /// Set once any fetched node's bytes failed to hash to its own address.
    mismatch: std::sync::atomic::AtomicBool,
}

impl ContentStore for VerifyingFetchStore<'_> {
    fn put(&self, _entity: Entity) -> Result<Hash, StoreError> {
        Err(StoreError::Internal("read-only fetch store".into()))
    }
    fn get(&self, hash: &Hash) -> Option<Entity> {
        let bytes = self.fetcher.content(hash).ok()?;
        match verify_content(&bytes, hash) {
            Ok(entity) => Some(entity),
            Err(_) => {
                self.mismatch
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                None
            }
        }
    }
    fn has(&self, hash: &Hash) -> bool {
        self.get(hash).is_some()
    }
    fn remove(&self, _hash: &Hash) -> bool {
        false
    }
    fn len(&self) -> usize {
        0
    }
}

/// Pins a publisher key + dials it over a [`ContentFetcher`]; verifies the
/// signed root, enforces `seq` monotonicity, and resolves paths by walking from
/// the signed root.
pub struct PublishedRootClient<F: ContentFetcher> {
    fetcher: F,
    pinned_pubkey: Vec<u8>,
    pinned_key_type: KeyType,
    expected_peer_id: Option<String>,
    cached_seq: Mutex<Option<u64>>,
}

impl<F: ContentFetcher> PublishedRootClient<F> {
    pub fn new(
        fetcher: F,
        pinned_pubkey: Vec<u8>,
        pinned_key_type: KeyType,
        expected_peer_id: Option<String>,
    ) -> Self {
        Self {
            fetcher,
            pinned_pubkey,
            pinned_key_type,
            expected_peer_id,
            cached_seq: Mutex::new(None),
        }
    }

    /// Fetch + verify the publisher's current signed root, enforcing `seq`
    /// monotonicity against the highest `seq` seen this session.
    pub fn fetch_root(&self) -> Result<PublishedRootData, PublishedRootError> {
        let manifest = self.fetcher.manifest().map_err(PublishedRootError::Fetch)?;
        // Decode once to learn the root hash so we can fetch the signature.
        let probe = entity_wire::decode_entity(&manifest)
            .map_err(|e| PublishedRootError::Decode(e.to_string()))?;
        let sig = self
            .fetcher
            .signature_for(&probe.content_hash)
            .map_err(PublishedRootError::Fetch)?;
        let (_, data) = verify_signed_root(
            &manifest,
            sig.as_deref(),
            &self.pinned_pubkey,
            self.pinned_key_type,
            self.expected_peer_id.as_deref(),
        )?;

        let mut cached = self.cached_seq.lock().unwrap();
        if let Some(prev) = *cached {
            if data.seq < prev {
                return Err(PublishedRootError::SeqRollback {
                    cached: prev,
                    received: data.seq,
                });
            }
        }
        *cached = Some(data.seq);
        Ok(data)
    }

    /// Resolve `relative_key` by walking the HAMT from the verified signed root.
    /// Returns the hash-verified leaf entity, or `None` if the key is not in the
    /// signed tree (host-fabricated bindings cannot appear here — §1.1).
    ///
    /// **`None` means absent, never "the origin served something that did not
    /// verify."** A node whose body fails its hash check cannot say so through
    /// `ContentStore::get` (see [`VerifyingFetchStore`]), so the walk would end
    /// indistinguishable from a genuine miss; the mismatch is latched and
    /// checked here, and a forgery leaves as
    /// [`PublishedRootError::ContentHashMismatch`].
    pub fn resolve(&self, relative_key: &str) -> Result<Option<Entity>, PublishedRootError> {
        let root = self.fetch_root()?;
        let store = VerifyingFetchStore {
            fetcher: &self.fetcher,
            mismatch: std::sync::atomic::AtomicBool::new(false),
        };
        let leaf = match trie_get(&store, root.root_hash, relative_key) {
            Some(h) => h,
            // Checked BEFORE reporting an absence, not after: the walk stops at
            // the unverifiable node, so "not found" is exactly what a tampered
            // interior node produces.
            None if store.mismatch.load(std::sync::atomic::Ordering::Relaxed) => {
                return Err(PublishedRootError::ContentHashMismatch)
            }
            None => return Ok(None),
        };
        let bytes = self
            .fetcher
            .content(&leaf)
            .map_err(PublishedRootError::Fetch)?;
        Ok(Some(verify_content(&bytes, &leaf)?))
    }
}

// ===========================================================================
// Live HTTP-poll fetcher — speaks the http_live publisher URL layout
// ===========================================================================

/// `{base}/manifest`.
pub fn manifest_url(base: &str) -> String {
    format!("{}/manifest", base.trim_end_matches('/'))
}

/// `{base}/content/{hex66}` (flat content layout — what http_live serves).
pub fn content_url(base: &str, hash: &Hash) -> String {
    format!("{}/content/{}", base.trim_end_matches('/'), hash.to_hex())
}

/// `{base}/{peer}/system/signature/{hex66}{suffix}` — the invariant-pointer
/// tree path the publisher binds the signature at. Host-trusted fetch; the
/// signature is verified against the pinned key, so host tampering is caught.
pub fn signature_url(base: &str, peer_id: &str, target: &Hash, tree_leaf_suffix: &str) -> String {
    format!(
        "{}/{}/system/signature/{}{}",
        base.trim_end_matches('/'),
        peer_id,
        target.to_hex(),
        tree_leaf_suffix
    )
}

/// Live reqwest-backed [`ContentFetcher`] for dialing an http-poll publisher.
///
/// Uses `reqwest::blocking` so it drives the sync [`PublishedRootClient`] walk
/// directly. **Caveat:** a blocking client MUST NOT be called from within an
/// async runtime — wrap usage in `tokio::task::spawn_blocking` when dialing
/// from an async context. Wiring this into the live transport-dispatch loop is
/// Phase P P7 (cohort convergence); the verification + walk logic it drives is
/// covered by the in-memory tests below.
#[cfg(all(feature = "http-live", not(target_arch = "wasm32")))]
pub struct HttpPollFetcher {
    client: reqwest::blocking::Client,
    base: String,
    peer_id: String,
    tree_leaf_suffix: String,
}

#[cfg(all(feature = "http-live", not(target_arch = "wasm32")))]
impl HttpPollFetcher {
    /// `base` is the poll route root (e.g. `http://host:port` or
    /// `http://host:port/poll`); `peer_id` is the publisher's Base58 id;
    /// `tree_leaf_suffix` is the publisher's leaf suffix (default `.bin`).
    pub fn new(
        base: impl Into<String>,
        peer_id: impl Into<String>,
        tree_leaf_suffix: impl Into<String>,
    ) -> Self {
        Self {
            client: reqwest::blocking::Client::new(),
            base: base.into(),
            peer_id: peer_id.into(),
            tree_leaf_suffix: tree_leaf_suffix.into(),
        }
    }

    fn get(&self, url: &str) -> Result<Option<Vec<u8>>, String> {
        let resp = self.client.get(url).send().map_err(|e| e.to_string())?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(format!("http status {}", resp.status()));
        }
        let bytes = resp.bytes().map_err(|e| e.to_string())?;
        Ok(Some(bytes.to_vec()))
    }
}

#[cfg(all(feature = "http-live", not(target_arch = "wasm32")))]
impl ContentFetcher for HttpPollFetcher {
    fn manifest(&self) -> Result<Vec<u8>, String> {
        self.get(&manifest_url(&self.base))?
            .ok_or_else(|| "manifest not found".to_string())
    }
    fn content(&self, hash: &Hash) -> Result<Vec<u8>, String> {
        self.get(&content_url(&self.base, hash))?
            .ok_or_else(|| "content not found".to_string())
    }
    fn signature_for(&self, target: &Hash) -> Result<Option<Vec<u8>>, String> {
        self.get(&signature_url(
            &self.base,
            &self.peer_id,
            target,
            &self.tree_leaf_suffix,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashMap};

    use entity_crypto::Keypair;
    use entity_store::{MemoryContentStore, MemoryLocationIndex};
    use entity_tree::trie::build_trie;

    fn kp() -> IdentityKeypair {
        IdentityKeypair::Ed25519(Keypair::from_seed([7u8; 32]))
    }

    fn dummy_identity_hash() -> Hash {
        Hash::compute("system/peer", b"identity")
    }

    fn leaf_entity(tag: &str) -> Entity {
        Entity::new("test/leaf", entity_ecf::to_ecf(&entity_ecf::text(tag))).unwrap()
    }

    /// Fetcher serving directly off the publisher's content store + location
    /// index — mirrors the real http_live publisher (manifest = the head
    /// published-root; content by hash; signature via invariant pointer).
    struct StoreFetcher {
        store: Arc<dyn ContentStore>,
        li: Arc<dyn LocationIndex>,
        peer_id: String,
        manifest_hash: Mutex<Hash>,
        forced_sig: Mutex<Option<Option<Vec<u8>>>>,
        content_override: Mutex<HashMap<Hash, Vec<u8>>>,
    }

    impl StoreFetcher {
        fn new(
            store: Arc<dyn ContentStore>,
            li: Arc<dyn LocationIndex>,
            peer_id: String,
            manifest_hash: Hash,
        ) -> Self {
            Self {
                store,
                li,
                peer_id,
                manifest_hash: Mutex::new(manifest_hash),
                forced_sig: Mutex::new(None),
                content_override: Mutex::new(HashMap::new()),
            }
        }
        fn serve(&self, h: &Hash) -> Result<Vec<u8>, String> {
            if let Some(b) = self.content_override.lock().unwrap().get(h) {
                return Ok(b.clone());
            }
            self.store
                .get(h)
                .map(|e| entity_wire::encode_entity(&e))
                .ok_or_else(|| "not found".to_string())
        }
    }

    impl ContentFetcher for StoreFetcher {
        fn manifest(&self) -> Result<Vec<u8>, String> {
            let h = *self.manifest_hash.lock().unwrap();
            self.serve(&h)
        }
        fn content(&self, hash: &Hash) -> Result<Vec<u8>, String> {
            self.serve(hash)
        }
        fn signature_for(&self, target: &Hash) -> Result<Option<Vec<u8>>, String> {
            if let Some(forced) = &*self.forced_sig.lock().unwrap() {
                return Ok(forced.clone());
            }
            let path = invariant_signature_path(&self.peer_id, target);
            match self.li.get(&path) {
                Some(sig_hash) => self.serve(&sig_hash).map(Some),
                None => Ok(None),
            }
        }
    }

    fn build_published(
        bindings: BTreeMap<String, Hash>,
    ) -> (
        Arc<dyn ContentStore>,
        Arc<dyn LocationIndex>,
        IdentityKeypair,
        String,
        Hash,
    ) {
        let store: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let root_hash = build_trie(store.as_ref(), &bindings).unwrap();
        let keypair = kp();
        let peer_id = keypair.peer_id().as_str().to_string();
        let engine = PublishRootEngine::new(
            store.clone(),
            li.clone(),
            keypair.clone_identity(),
            peer_id.clone(),
            dummy_identity_hash(),
            format!("/{}/", peer_id),
        );
        let head = engine.publish(root_hash).unwrap();
        (store, li, keypair, peer_id, head)
    }

    // ----- Publisher -----

    /// ⛔ **The PUBLISHER-SIDE window of the published-root verify race
    /// (NETWORK §1.1): the signature MUST be bound before the head.**
    ///
    /// A consumer's verify cycle is two fetches — `MANIFEST_GET` returns head
    /// *N*, then it fetches *N*'s signature and verifies before walking
    /// anything. `publish` performs two independent `set`s with no transaction
    /// between them, so **ordering is the entire defence**: bind the head first
    /// and there is a window in which this peer serves a head whose signature
    /// does not yet exist, and the consumer's second fetch 404s. It cannot tell
    /// that from a publisher serving an unsigned root — the one thing the
    /// signature exists to rule out — so it fails the cycle rather than
    /// retrying.
    ///
    /// core-py measured both windows of this race against
    /// `published_root.v5_outbound_dial`, and **neither fix alone leaves it
    /// green**; the consumer-side half is `ClosureScope::refresh`'s retained-
    /// anchor ring. core-go carries both, which is what made this a grep at our
    /// seat rather than a report.
    ///
    /// **Observed at the moment of the write, not after it.** Asserting that
    /// both bindings exist once `publish` returns is true under either order and
    /// measures nothing; the decorator samples whether the signature already
    /// resolves *as the head is being set*, which is exactly the consumer's
    /// vantage point.
    ///
    /// **Mutation RUN:** swap the two blocks in `publish` (head bound before the
    /// signature) → this row reddens with `signature_bound_when_head_was_set =
    /// false`, and every other row in this module stays green — they all run
    /// after both writes and cannot see the order.
    #[test]
    fn publish_binds_the_signature_before_the_head() {
        /// Samples the signature binding at the instant the head path is set.
        struct WatchHeadWrite {
            inner: Arc<MemoryLocationIndex>,
            head_path: String,
            sig_path_prefix: String,
            /// `Some(true)` once the head was set with its signature already
            /// bound; `Some(false)` if it was set without one.
            observed: Mutex<Option<bool>>,
        }
        impl WatchHeadWrite {
            fn sample(&self, path: &str) {
                if path != self.head_path {
                    return;
                }
                let sig_bound = self
                    .inner
                    .list(&self.sig_path_prefix)
                    .iter()
                    .any(|e| e.path.starts_with(&self.sig_path_prefix));
                *self.observed.lock().unwrap() = Some(sig_bound);
            }
        }
        impl LocationIndex for WatchHeadWrite {
            fn set(&self, path: &str, hash: Hash) {
                self.sample(path);
                self.inner.set(path, hash)
            }
            fn set_with_context(
                &self,
                path: &str,
                hash: Hash,
                ctx: entity_store::EmitContext,
            ) -> entity_store::CascadeResult {
                // `publish` writes through this one, not through `set`.
                self.sample(path);
                self.inner.set_with_context(path, hash, ctx)
            }
            fn get(&self, path: &str) -> Option<Hash> {
                self.inner.get(path)
            }
            fn has(&self, path: &str) -> bool {
                self.inner.has(path)
            }
            fn remove(&self, path: &str) -> Option<Hash> {
                self.inner.remove(path)
            }
            fn list(&self, prefix: &str) -> Vec<entity_store::LocationEntry> {
                self.inner.list(prefix)
            }
            fn len_prefix(&self, prefix: &str) -> usize {
                self.inner.len_prefix(prefix)
            }
            // Forward the CAS trio: the defaults are a non-atomic get+set, and a
            // decorator that declines to mention a method silently supplies
            // them in front of a correct backend. Not load-bearing for `publish`
            // — which writes through `set_with_context` — and forwarded anyway,
            // because "this wrapper happens not to need it" is how that defect
            // reached production once already.
            fn compare_and_swap(
                &self,
                path: &str,
                expected: Hash,
                new_hash: Hash,
            ) -> Result<(), entity_store::CasError> {
                self.inner.compare_and_swap(path, expected, new_hash)
            }
            fn compare_and_remove(
                &self,
                path: &str,
                expected: Hash,
            ) -> Result<Hash, entity_store::CasError> {
                self.inner.compare_and_remove(path, expected)
            }
            fn compare_and_create(
                &self,
                path: &str,
                new_hash: Hash,
            ) -> Result<(), entity_store::CasError> {
                self.inner.compare_and_create(path, new_hash)
            }
        }

        let store: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let keypair = kp();
        let peer_id = keypair.peer_id().as_str().to_string();
        let watcher = Arc::new(WatchHeadWrite {
            inner: Arc::new(MemoryLocationIndex::new()),
            head_path: published_root_head_path(&peer_id),
            sig_path_prefix: format!("/{}/system/signature/", peer_id),
            observed: Mutex::new(None),
        });
        let li: Arc<dyn LocationIndex> = watcher.clone();

        let mut bindings = BTreeMap::new();
        bindings.insert("a".to_string(), store.put(leaf_entity("a")).unwrap());
        let root_hash = build_trie(store.as_ref(), &bindings).unwrap();

        let engine = PublishRootEngine::new(
            store.clone(),
            li.clone(),
            keypair.clone_identity(),
            peer_id.clone(),
            dummy_identity_hash(),
            format!("/{}/", peer_id),
        );
        let head = engine.publish(root_hash).unwrap();

        let observed = *watcher.observed.lock().unwrap();
        assert_eq!(
            observed,
            Some(true),
            "signature_bound_when_head_was_set — the head was bound while no \
             signature resolved, which serves a head a consumer cannot verify"
        );
        // And the ordinary post-condition, which is true under BOTH orders and
        // is here only so a reader does not mistake it for the assertion above.
        assert!(li.get(&invariant_signature_path(&peer_id, &head)).is_some());
    }

    #[test]
    fn url_construction_matches_http_live_routes() {
        let h = Hash::compute("t", b"x");
        let hex = h.to_hex();
        assert_eq!(
            manifest_url("http://host:9/poll"),
            "http://host:9/poll/manifest"
        );
        assert_eq!(
            manifest_url("http://host:9/poll/"),
            "http://host:9/poll/manifest"
        );
        assert_eq!(
            content_url("http://host:9", &h),
            format!("http://host:9/content/{}", hex)
        );
        assert_eq!(
            signature_url("http://host:9", "z6Mk", &h, ".bin"),
            format!("http://host:9/z6Mk/system/signature/{}.bin", hex)
        );
    }

    /// EXTENSION-NETWORK §6.5.3 hex-strictness: the content-hash hex on the
    /// `http-poll` routes is the **full wire form, format-code byte included**
    /// — never the digest-only form — and **its length is the one the leading
    /// format byte implies and is NEVER hardcoded** (`SPECIFICATION-FORMAT`
    /// §8.4.5): 66 chars beginning `00` under ECFv1-SHA-256, 98 beginning `01`
    /// under ECFv1-SHA-384.
    ///
    /// This asserts the PROPERTY, not a round-trip. `content_url(..) ==
    /// format!("…/{}", h.to_hex())` is a tautology — it compares the builder
    /// against the very function the builder calls, so it stays green under a
    /// digest-only builder too, which is how core-go's `BuildContentURL` shipped
    /// `EffectiveDigest()` past its own test. What separates the two is the
    /// leading byte and the byte-implied width, checked at two formats: a
    /// hardcoded 66 passes the SHA-256 row and fails the SHA-384 one, and that
    /// is the 2026-08-10 cohort defect that `400`'d a valid SHA-384 hash.
    #[test]
    fn content_url_hex_is_the_full_wire_form_at_every_format_width() {
        for (code, digest_len) in [
            (entity_hash::HASH_ALGORITHM_SHA256, 32usize),
            (entity_hash::HASH_ALGORITHM_SHA384, 48usize),
        ] {
            let h = Hash::compute_format("t", b"x", code).expect("allocated format");
            let url = content_url("http://host:9", &h);
            let hex = url
                .strip_prefix("http://host:9/content/")
                .expect("flat content route");

            // The format-code byte leads — `[0:2]` is the algorithm partition
            // the sharded CDN layouts key on. A digest-only hex silently slices
            // the first DIGEST byte instead and that property dies.
            assert_eq!(
                &hex[0..2],
                &format!("{:02x}", code),
                "the content-URL hex must begin with the content_hash_format byte"
            );
            // Length is byte-implied, not a constant.
            assert_eq!(
                hex.len(),
                2 + digest_len * 2,
                "format {:#04x} implies {} hex chars",
                code,
                2 + digest_len * 2
            );
            // And it round-trips through the strict parser the serve side uses.
            assert_eq!(Hash::from_bytes(&hex_to_bytes(hex)).unwrap(), h);
        }
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn publisher_increments_seq_and_chains() {
        let store: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let keypair = kp();
        let peer_id = keypair.peer_id().as_str().to_string();
        let engine = PublishRootEngine::new(
            store.clone(),
            li.clone(),
            keypair.clone_identity(),
            peer_id.clone(),
            dummy_identity_hash(),
            format!("/{}/", peer_id),
        );
        let root_a = Hash::compute("test", b"root-a");
        let root_b = Hash::compute("test", b"root-b");

        let h0 = engine.publish(root_a).unwrap();
        let (_, d0) = engine.current_head().unwrap();
        assert_eq!(d0.seq, 0);
        assert!(d0.predecessor.is_none());
        assert_eq!(d0.root_hash, root_a);

        let h1 = engine.publish(root_b).unwrap();
        let (_, d1) = engine.current_head().unwrap();
        assert_eq!(d1.seq, 1);
        assert_eq!(d1.predecessor, Some(h0));
        assert_eq!(d1.root_hash, root_b);

        // Re-publishing the same root is a no-op (no churn).
        let h1_again = engine.publish(root_b).unwrap();
        assert_eq!(h1_again, h1);
        assert_eq!(engine.current_head().unwrap().1.seq, 1);
    }

    // ----- Consumer: verify + walk -----

    fn client_for(
        store: Arc<dyn ContentStore>,
        li: Arc<dyn LocationIndex>,
        keypair: &IdentityKeypair,
        peer_id: &str,
        head: Hash,
    ) -> PublishedRootClient<StoreFetcher> {
        let fetcher = StoreFetcher::new(store, li, peer_id.to_string(), head);
        PublishedRootClient::new(
            fetcher,
            keypair.public_key_bytes(),
            keypair.key_type(),
            Some(peer_id.to_string()),
        )
    }

    #[test]
    fn consumer_verifies_and_resolves_from_signed_root() {
        let leaf = leaf_entity("alpha");
        let mut bindings = BTreeMap::new();
        bindings.insert("system/a".to_string(), leaf.content_hash);
        let (store, li, keypair, peer_id, head) = build_published(bindings);
        store.put(leaf.clone()).unwrap();

        let client = client_for(store, li, &keypair, &peer_id, head);
        let root = client.fetch_root().unwrap();
        assert_eq!(root.seq, 0);

        let got = client.resolve("system/a").unwrap().unwrap();
        assert_eq!(got.content_hash, leaf.content_hash);
        // Absent key → None (not an error).
        assert!(client.resolve("system/absent").unwrap().is_none());
    }

    #[test]
    fn consumer_rejects_forged_root_signature() {
        let (store, li, keypair, peer_id, head) = build_published(BTreeMap::new());
        let client = client_for(store, li.clone(), &keypair, &peer_id, head);
        // Force a garbage signature entity (valid shape, wrong bytes).
        let bad_sig = SignatureData {
            target: head,
            signer: dummy_identity_hash(),
            algorithm: "ed25519".into(),
            signature: vec![0u8; 64],
        };
        *client.fetcher.forced_sig.lock().unwrap() = Some(Some(entity_wire::encode_entity(
            &bad_sig.to_entity().unwrap(),
        )));
        match client.fetch_root() {
            Err(PublishedRootError::SignatureInvalid) => {}
            other => panic!("expected SignatureInvalid, got {:?}", other),
        }
    }

    #[test]
    fn consumer_rejects_missing_signature() {
        let (store, li, keypair, peer_id, head) = build_published(BTreeMap::new());
        let client = client_for(store, li, &keypair, &peer_id, head);
        *client.fetcher.forced_sig.lock().unwrap() = Some(None);
        match client.fetch_root() {
            Err(PublishedRootError::SignatureMissing) => {}
            other => panic!("expected SignatureMissing, got {:?}", other),
        }
    }

    #[test]
    fn consumer_rejects_seq_rollback() {
        // Publish seq 0 then seq 1 in the same store.
        let store: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let keypair = kp();
        let peer_id = keypair.peer_id().as_str().to_string();
        let engine = PublishRootEngine::new(
            store.clone(),
            li.clone(),
            keypair.clone_identity(),
            peer_id.clone(),
            dummy_identity_hash(),
            format!("/{}/", peer_id),
        );
        let h0 = engine.publish(Hash::compute("t", b"r0")).unwrap();
        let h1 = engine.publish(Hash::compute("t", b"r1")).unwrap();

        let client = client_for(store, li, &keypair, &peer_id, h1);
        // Fetch the newer (seq 1) first → caches seq 1.
        assert_eq!(client.fetch_root().unwrap().seq, 1);
        // Now serve the older (seq 0) → rollback rejected.
        *client.fetcher.manifest_hash.lock().unwrap() = h0;
        match client.fetch_root() {
            Err(PublishedRootError::SeqRollback {
                cached: 1,
                received: 0,
            }) => {}
            other => panic!("expected SeqRollback, got {:?}", other),
        }
    }

    #[test]
    fn consumer_rejects_host_fabricated_binding() {
        // The signed trie binds "system/a" → real leaf. A hostile host cannot
        // make resolve() return a different entity for "system/a" (the walk is
        // from the signed root) and cannot inject a binding for an unsigned key.
        let real = leaf_entity("real");
        let mut bindings = BTreeMap::new();
        bindings.insert("system/a".to_string(), real.content_hash);
        let (store, li, keypair, peer_id, head) = build_published(bindings);
        store.put(real.clone()).unwrap();

        let client = client_for(store, li, &keypair, &peer_id, head);
        // resolve returns the real leaf, never anything the host fabricates.
        assert_eq!(
            client.resolve("system/a").unwrap().unwrap().content_hash,
            real.content_hash
        );
        // A key the host might "claim" but the signed trie never bound → None.
        assert!(client.resolve("system/evil").unwrap().is_none());
    }

    #[test]
    fn consumer_rejects_tampered_content() {
        let leaf = leaf_entity("honest");
        let mut bindings = BTreeMap::new();
        bindings.insert("system/a".to_string(), leaf.content_hash);
        let (store, li, keypair, peer_id, head) = build_published(bindings);
        store.put(leaf.clone()).unwrap();

        let client = client_for(store, li, &keypair, &peer_id, head);
        // Host serves a valid-but-DIFFERENT entity for the leaf hash → it
        // decodes fine but re-hashes to a different hash → rejected (§1.2).
        let impostor = leaf_entity("impostor");
        client
            .fetcher
            .content_override
            .lock()
            .unwrap()
            .insert(leaf.content_hash, entity_wire::encode_entity(&impostor));
        match client.resolve("system/a") {
            Err(PublishedRootError::ContentHashMismatch) => {}
            other => panic!("expected ContentHashMismatch, got {:?}", other),
        }
    }

    /// **A tampered INTERIOR node is a forgery, not an absence.**
    ///
    /// `consumer_rejects_tampered_content` above covers the leaf, which
    /// `resolve` hashes itself. Everything the *walk* fetches went through
    /// `ContentStore::get`, whose `Option` return has no way to say "this did
    /// not verify" — so a HAMT node serving bytes that hash to nothing left by
    /// the same door as a node that was never published, `trie_get` read it as
    /// *no such branch*, and `resolve` answered `Ok(None)`.
    ///
    /// That answer is *"the publisher never bound that key"* — said about an
    /// origin that just served a forgery. Every consumer of a signed root got
    /// it; reported from entity-browser-rust 2026-08-19, found by flipping one
    /// byte in each blob a resolve fetches.
    ///
    /// The control matters as much as the attack: a key the trie genuinely does
    /// not carry must still be `Ok(None)` afterwards, or the fix has traded a
    /// silent forgery for a loud absence.
    #[test]
    fn a_tampered_interior_node_is_a_mismatch_not_an_absence() {
        // Enough keys that the root is a real interior node with children, so
        // the walk has to fetch and verify it before it can find anything.
        let leaves: Vec<Entity> = (0..8).map(|i| leaf_entity(&format!("leaf-{i}"))).collect();
        let mut bindings = BTreeMap::new();
        for (i, l) in leaves.iter().enumerate() {
            bindings.insert(format!("system/k{i}"), l.content_hash);
        }
        let (store, li, keypair, peer_id, head) = build_published(bindings);
        for l in &leaves {
            store.put(l.clone()).unwrap();
        }

        let client = client_for(store, li, &keypair, &peer_id, head);
        // Precondition: it all resolves honestly first, or the assertions below
        // could pass against a fixture that never worked.
        assert_eq!(
            client.resolve("system/k3").unwrap().unwrap().content_hash,
            leaves[3].content_hash
        );
        assert!(
            client.resolve("system/nope").unwrap().is_none(),
            "control: a real absence"
        );

        // The attack: serve a valid, well-formed entity for the TRIE ROOT's
        // hash. It decodes, it re-hashes to something else, and the walk cannot
        // proceed past it.
        let trie_root = client.fetch_root().unwrap().root_hash;
        let impostor = leaf_entity("impostor");
        client
            .fetcher
            .content_override
            .lock()
            .unwrap()
            .insert(trie_root, entity_wire::encode_entity(&impostor));

        match client.resolve("system/k3") {
            Err(PublishedRootError::ContentHashMismatch) => {}
            other => panic!(
                "a tampered interior node must be a mismatch, not an absence — got {other:?}"
            ),
        }
        // And the same for a key that is genuinely absent: with the tree
        // unwalkable we cannot know it is absent, so it must NOT come back as
        // one. This is the half that makes the answer honest rather than merely
        // different.
        match client.resolve("system/nope") {
            Err(PublishedRootError::ContentHashMismatch) => {}
            other => panic!("an unwalkable tree cannot report an absence — got {other:?}"),
        }

        // Control, restored: with the tamper removed, absence is absence again.
        client.fetcher.content_override.lock().unwrap().clear();
        assert!(client.resolve("system/nope").unwrap().is_none());
        assert_eq!(
            client.resolve("system/k3").unwrap().unwrap().content_hash,
            leaves[3].content_hash
        );
    }

    // ----- verify_content: §1.2 host-bytes-distrust (Gap A + Gap B) -----

    #[test]
    fn verify_content_accepts_2key_content_get_form() {
        // The live CONTENT_GET route serves the bare 2-key `{data, type}` form
        // (`ecf_for_hash`), with NO `content_hash` on the wire. verify_content
        // must decode it and recompute the hash itself.
        let leaf = leaf_entity("alpha");
        let body = entity_ecf::ecf_for_hash(&leaf.entity_type, &leaf.data);
        let got = verify_content(&body, &leaf.content_hash).unwrap();
        assert_eq!(got.content_hash, leaf.content_hash);
        assert_eq!(got.data, leaf.data);
    }

    #[test]
    fn verify_content_rejects_hash_lying_host() {
        // The Gap B attack: a host serves the 3-key form with HONEST-looking
        // `content_hash:<expected>` but `data:<evil>`. The old code trusted the
        // wire `content_hash` and let this pass. verify_content now recomputes
        // from (type, data) and must reject — the evil bytes do not re-hash to
        // the requested hash.
        let honest = leaf_entity("honest");
        let evil = leaf_entity("evil");
        let lying = Entity {
            entity_type: evil.entity_type.clone(),
            data: evil.data.clone(),
            content_hash: honest.content_hash, // the lie
        };
        let body = entity_wire::encode_entity(&lying);
        match verify_content(&body, &honest.content_hash) {
            Err(PublishedRootError::ContentHashMismatch) => {}
            other => panic!("expected ContentHashMismatch, got {:?}", other),
        }
    }

    /// EXTENSION-TREE §3.3a + §6.2, in-tree: **the declared prefix must
    /// reconstruct every published key to a path the peer actually holds.**
    ///
    /// This is Go's `v9_prefix_key_form` / `v10_prefix_reconstruction` asked
    /// from our own side, and it is a *different question* from the rebuild
    /// check. `v8` mirrors the trie, rebuilds it, and compares roots — which
    /// proves the routing algorithm and can never fail on key **form**, because
    /// the rebuild takes its keys from the trie. An implementation keying by
    /// absolute path rebuilds to its own root perfectly. Go demonstrated
    /// exactly that by making its peer declare `"/"` while still keying
    /// `system/`-relative: v8 PASSed, v9 and v10 FAILed.
    ///
    /// So this walks the other way: take each published `relative_key`,
    /// reconstruct `absolute_prefix + relative_key` through the prefix WE
    /// declared, and require the LocationIndex to bind that path to the same
    /// hash the trie holds. A declaration that does not describe the keys
    /// produces a path the peer does not have — confidently, which is what
    /// makes a wrong prefix worse than a missing one.
    #[test]
    fn the_declared_prefix_reconstructs_every_key_to_a_held_path() {
        let store: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let keypair = kp();
        let peer_id = keypair.peer_id().as_str().to_string();

        // Bindings across two subtrees, because the distinction between our
        // peer-qualified prefix and Go's `system/` one is invisible if
        // everything lives under `system/` — `local/files` is precisely the
        // key their prefix excludes and ours covers.
        let mut bindings = BTreeMap::new();
        for key in ["system/attestation/a", "local/files/doc", "data/notes"] {
            let e = leaf_entity(key);
            let h = e.content_hash;
            store.put(e).unwrap();
            li.set(&format!("/{}/{}", peer_id, key), h);
            bindings.insert(key.to_string(), h);
        }
        let root_hash = build_trie(store.as_ref(), &bindings).unwrap();

        let declared = format!("/{}/", peer_id);
        let engine = PublishRootEngine::new(
            store.clone(),
            li.clone(),
            keypair.clone_identity(),
            peer_id.clone(),
            dummy_identity_hash(),
            declared.clone(),
        );
        let head = engine.publish(root_hash).unwrap();

        let published = PublishedRootData::from_entity(&store.get(&head).unwrap()).unwrap();
        assert_eq!(
            published.prefix, declared,
            "the published root MUST carry the prefix its keys are relative to"
        );
        assert!(
            published.prefix.ends_with('/'),
            "§3.3a: a prefix MUST end with `/`"
        );

        // §3.3's resolution: `/`-leading is already absolute; `/` alone is the
        // universal tree and resolves to the empty operand (a no-op trim).
        let absolute_prefix = if published.prefix == "/" {
            String::new()
        } else if published.prefix.starts_with('/') {
            published.prefix.clone()
        } else {
            format!("/{}/{}", peer_id, published.prefix)
        };

        let served = entity_tree::trie::collect_all_bindings(store.as_ref(), root_hash, "");
        assert_eq!(served.len(), 3, "all three bindings should be published");
        for (relative_key, value_hash) in &served {
            let reconstructed = format!("{}{}", absolute_prefix, relative_key);
            assert_eq!(
                li.get(&reconstructed),
                Some(*value_hash),
                "reconstructing {:?} through the declared prefix {:?} gave {:?}, \
                 which this peer does not bind to that hash — the declaration \
                 does not describe the keys",
                relative_key,
                published.prefix,
                reconstructed
            );
        }
    }
}
