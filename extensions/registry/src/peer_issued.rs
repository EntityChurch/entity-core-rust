//! Peer-issued backend (PROPOSAL-PEER-ISSUED-REGISTRY-BACKEND).
//!
//! The twin of [`crate::local_name`], with a different **trust source**: a
//! pinned *remote* registry key instead of *local* authority. The backend is
//! **pure trust logic over transport-agnostic reads** — it reads a registry
//! peer's bindings with the ordinary `tree:get` / `content:get` machinery and
//! **does not know or care** whether that peer is reached over http-poll (a
//! static coral-reef) or a live socket (NETWORK §6.5 decides the wire).
//!
//! For the v1 demo the reads resolve against the **local store** — the
//! offline / precede path (proposal §2.2): the registry's bindings are cached
//! locally (shipped or pre-fetched), stored under the *registry's* namespace
//! `/{registry}/system/registry/binding/…`. The live remote-read seam (fetch
//! the registry peer's tree on a cache miss) is a `core/peer`/SDK concern that
//! populates this store; it is not part of the extension (see
//! `docs/archive/SPEC-PROBLEMS-PEER-ISSUED-REGISTRY.md`).
//!
//! The only registry-specific substance is step 3 of [`resolve_one`]:
//! signature-verify the binding against the **pinned** registry key
//! (`pinned_key_of(registry)` — materialized per spec-problems doc **P1**:
//! the signer's identity entity must derive to the configured registry peer-id).

use std::sync::Arc;

use entity_ecf::Value;
use entity_entity::Entity;
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};
use entity_types::SignatureData;

use crate::data::{
    normalize_name, BindingData, ResolutionResult, RevocationData, STATUS_RESOLVED,
    TRUST_PEER_ISSUED_PREFIX,
};
use crate::log::now_ms;
use crate::resolver::resolve_peer_pubkey;
use crate::{
    binding_body_path, by_name_pointer_path, revocation_by_target_path, revocation_prefix,
    signature_pointer_path, ResolverChainEntry,
};

/// Backend resolve (proposal §2.1) — invoked by the meta-resolver for
/// `peer-issued` chain entries. `entry.backend_id` is the registry's Base58
/// peer-id (the pinned trust root + the namespace its bindings live under).
///
/// Returns:
/// - `Some(resolved)` on a verified, unrevoked, unexpired binding;
/// - `Some(not_found)` when the by-name pointer is absent (proposal §2.1 step 1;
///   spec-problems **P2** — backend-level not_found, distinct from chain-exhausted);
/// - `None` on any verify / revocation / expiry failure → the chain advances,
///   **never** silently downgrading to a pin (fail-closed, proposal §5).
pub fn resolve_one(
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
    entry: &ResolverChainEntry,
    name: &str,
) -> Option<ResolutionResult> {
    let registry = entry.backend_id.as_str();
    if registry.is_empty() {
        return None;
    }
    // NFC-only normalization (proposal §2.1 `nfc_normalize`); case-folding is a
    // local-name-config knob on the *local* store, not a peer-issued concern.
    let norm = normalize_name(name, "none");

    // 1. by-name index → binding hash (transport-agnostic read; local store for
    //    the precede path).
    let binding_hash = match location_index.get(&by_name_pointer_path(registry, &norm)) {
        Some(h) => h,
        None => {
            return Some(ResolutionResult::not_found(neg_ttl_from_hints(
                &entry.hints,
            )))
        }
    };

    // 2. binding hash → binding body (content is self-verifying by hash).
    let body = content_store.get(&binding_hash)?;
    let binding = BindingData::from_entity(&body).ok()?;

    // 3. VERIFY — the only registry-specific logic. Signature at the
    //    invariant-pointer, signed by the *pinned* registry key.
    if !verify_signed_by_registry(content_store, location_index, registry, &binding_hash) {
        return None;
    }

    // Revocation (proposal §2.3): a registry-signed revocation targeting the
    // binding excludes it and advances the chain.
    if is_revoked(content_store, location_index, registry, &binding_hash) {
        return None;
    }

    // TTL (proposal §2.1): `issued_at + ttl > now`, or ttl null (no expiry).
    if let Some(ttl) = binding.ttl {
        if binding.issued_at.saturating_add(ttl) <= now_ms() {
            return None;
        }
    }

    // 4. surface.
    Some(ResolutionResult {
        status: STATUS_RESOLVED.into(),
        binding: Some(binding_hash),
        peer_id: Some(binding.target_peer_id),
        transports: binding.transports,
        attestations: Vec::new(),
        trust_anchor: Some(format!("{}{}", TRUST_PEER_ISSUED_PREFIX, registry)),
        ttl: binding.ttl,
        neg_ttl: None,
        backend_id: Some(registry.to_string()),
    })
}

/// Verify a `system/signature` at the invariant-pointer `/{registry}/system/
/// signature/{hex(target)}` proves `target` was signed by the **pinned**
/// registry key. The pin (spec-problems **P1**): the signer's identity entity,
/// resolved from `sig.signer`, must derive to the peer-id `registry`. Ed25519
/// only (spec-problems **P5**).
fn verify_signed_by_registry(
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
    registry: &str,
    target: &Hash,
) -> bool {
    let sig_hash = match location_index.get(&signature_pointer_path(registry, target)) {
        Some(h) => h,
        None => return false,
    };
    let sig = match content_store
        .get(&sig_hash)
        .and_then(|e| SignatureData::from_entity(&e).ok())
    {
        Some(s) => s,
        None => return false,
    };
    if &sig.target != target {
        return false;
    }
    let pubkey = match resolve_peer_pubkey(&sig.signer, content_store) {
        Some(pk) => pk,
        None => return false,
    };
    // The pin: the signer's key must derive to the configured registry peer-id.
    if entity_crypto::PeerId::from_public_key(&pubkey).as_str() != registry {
        return false;
    }
    entity_crypto::Keypair::verify(&pubkey, &target.to_bytes(), &sig.signature).is_ok()
}

/// True if a registry-signed `system/registry/revocation` in the registry's
/// subtree targets `binding_hash` (proposal §2.3). Unlike local-name (where the
/// local store is itself the trust source, §6.3 carve-out), a peer-issued
/// revocation MUST verify against the registry key — otherwise anyone serving
/// the registry's tree could censor a binding.
fn is_revoked(
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
    registry: &str,
    binding_hash: &Hash,
) -> bool {
    location_index
        .list(&revocation_prefix(registry))
        .into_iter()
        .any(|entry| {
            let targets = content_store
                .get(&entry.hash)
                .and_then(|e| RevocationData::from_entity(&e).ok())
                .map(|rev| &rev.revokes == binding_hash)
                .unwrap_or(false);
            targets
                && verify_signed_by_registry(content_store, location_index, registry, &entry.hash)
        })
}

/// Read `neg_ttl` (uint ms) from the chain entry's free-form `hints` map
/// (spec-problems **P3** — no first-class config field yet).
fn neg_ttl_from_hints(hints: &Option<Value>) -> Option<u64> {
    let map = hints.as_ref()?.as_map()?;
    map.iter().find_map(|(k, v)| {
        if k.as_text() == Some("neg_ttl") {
            v.as_integer().and_then(|i| u64::try_from(i).ok())
        } else {
            None
        }
    })
}

// ===========================================================================
// The live remote-read seam (proposal §2.2)
// ===========================================================================

/// Transport for reading a *remote* registry peer's tree.
///
/// **The split this trait draws.** The extension owns which paths matter —
/// that is the trust logic in [`resolve_one`], and it is the whole substance of
/// the peer-issued backend. The host owns how bytes arrive: http-poll against a
/// static coral-reef, a live socket, anything NETWORK §6.5 permits. That is why
/// this is a trait here rather than an http client here: the module has said
/// since v1 that "the live remote-read seam … is a `core/peer`/SDK concern",
/// and this is that seam, not a second registry.
///
/// **Every read is host-trusted except `read_content`.** The registry host
/// asserts its own bindings, so `read_path` and `list_children` return what it
/// claims. That is sound *only* because step 3 of [`resolve_one`] then verifies
/// the binding's signature against the pinned registry key — the pin is the
/// trust, not the transport. `read_content` is the one read a hostile host
/// cannot influence, and implementations MUST re-hash the body and drop a
/// mismatch.
#[async_trait::async_trait]
pub trait RegistryTreeReader: Send + Sync {
    /// The hash bound at `absolute_path` on the registry peer, if any.
    async fn read_path(&self, endpoint: &str, absolute_path: &str) -> Option<Hash>;

    /// The entity for `hash`, **verified by re-hashing**.
    async fn read_content(&self, endpoint: &str, hash: &Hash) -> Option<Entity>;
}

/// Read the registry endpoint out of a chain entry's `hints` map.
///
/// §4's `ResolverChainEntry` carries a free-form `hints` map and this is where
/// the cohort puts the endpoint — Python's `RegistryReader` reads it from
/// there, and Go's validator writes it there. Go itself takes the endpoint from
/// a CLI flag and so never read the field, which is exactly how its harness
/// shipped a bare `(kind, id)` entry that disarmed a correctly-pinned Python
/// peer: the entry looked complete to the only impl that did not need it. Read
/// the hint.
pub fn endpoint_from_hints(hints: &Option<Value>) -> Option<String> {
    let map = hints.as_ref()?.as_map()?;
    map.iter().find_map(|(k, v)| {
        if k.as_text() == Some("endpoint") {
            v.as_text().map(|s| s.to_string())
        } else {
            None
        }
    })
}

/// Populate the local store with everything [`resolve_one`] will read for
/// `name`, by fetching it from the pinned registry.
///
/// **Lazy, and that is a conformance requirement, not an optimization.** The
/// §2.2 precede path says a locally-cached binding resolves *identically to
/// live-fetch, without touching the wire* — so this returns immediately when
/// the by-name pointer is already bound locally. A warm cache that re-fetched
/// anyway would still resolve correctly and would still be wrong.
///
/// Conversely a *cold* miss MUST reach the wire even when the answer is
/// "absent": a name the registry does not carry has to produce the backend's
/// negative result after a real probe, not a local shrug. Both directions are
/// observable from the registry's side, which is how the cohort's vectors tell
/// "rejected for the right reason" from "never looked" — over the wire four of
/// the six collapse to the same status.
///
/// Returns `true` if anything was fetched. Failures are silent by design: this
/// warms a cache, and every reason a fetch can fail (404, unreachable host,
/// undecodable body) lands at the same place — [`resolve_one`] runs against
/// whatever is present and fails closed on its own terms. Manufacturing an
/// error here would turn "the registry is down" into a different answer than
/// "the registry says no", which §2.1 does not distinguish either.
pub async fn warm_cache(
    reader: &dyn RegistryTreeReader,
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
    entry: &ResolverChainEntry,
    name: &str,
) -> bool {
    let registry = entry.backend_id.as_str();
    if registry.is_empty() {
        return false;
    }
    let Some(endpoint) = endpoint_from_hints(&entry.hints) else {
        return false;
    };
    let norm = normalize_name(name, "none");
    let by_name = by_name_pointer_path(registry, &norm);

    // The precede path: already cached ⇒ do not touch the wire (§2.2).
    if location_index.get(&by_name).is_some() {
        return false;
    }

    // 1. by-name → binding hash. A 404 here is the whole answer for a name the
    //    registry does not carry; nothing is cached and `resolve_one` reports
    //    the backend-level not_found.
    let Some(binding_hash) = reader.read_path(&endpoint, &by_name).await else {
        return true;
    };

    // 2. the binding body. Cached under the registry's namespace, because that
    //    is where `resolve_one` looks — this store is a view of the REGISTRY's
    //    subtree, not of ours.
    if !cache_entity(reader, content_store, &endpoint, &binding_hash).await {
        return true;
    }
    location_index.set(&binding_body_path(registry, &binding_hash), binding_hash);
    location_index.set(&by_name, binding_hash);

    // 3. the authenticating signature at the §5.2 invariant pointer, plus the
    //    signer's identity entity — `verify_signed_by_registry` resolves the
    //    signer's public key from it to apply the pin, so a cached signature
    //    without a cached identity verifies nothing.
    cache_signature_for(
        reader,
        content_store,
        location_index,
        &endpoint,
        registry,
        &binding_hash,
    )
    .await;

    // 4. the §6a.6 by-target revocation index. Fetched by DIRECT lookup, not by
    //    listing the revocation subtree: the index exists precisely so a
    //    resolver does not walk every revocation a registry ever issued. Cached
    //    under the own-hash-keyed path because that is what the local
    //    `is_revoked` scan reads.
    if let Some(rev_hash) = reader
        .read_path(
            &endpoint,
            &revocation_by_target_path(registry, &binding_hash),
        )
        .await
    {
        if cache_entity(reader, content_store, &endpoint, &rev_hash).await {
            location_index.set(
                &format!("{}{}", revocation_prefix(registry), rev_hash.to_hex()),
                rev_hash,
            );
            // A revocation is only honored if it too verifies against the
            // pinned key, so it needs its own signature cached.
            cache_signature_for(
                reader,
                content_store,
                location_index,
                &endpoint,
                registry,
                &rev_hash,
            )
            .await;
        }
    }

    true
}

/// Fetch `hash` and put it in the local content store. Content is
/// self-verifying, so the reader's re-hash is the only check needed.
async fn cache_entity(
    reader: &dyn RegistryTreeReader,
    content_store: &Arc<dyn ContentStore>,
    endpoint: &str,
    hash: &Hash,
) -> bool {
    if content_store.has(hash) {
        return true;
    }
    match reader.read_content(endpoint, hash).await {
        Some(entity) => content_store.put(entity).is_ok(),
        None => false,
    }
}

/// Cache the signature bound at `target`'s invariant pointer, and the signer's
/// identity entity behind it.
async fn cache_signature_for(
    reader: &dyn RegistryTreeReader,
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
    endpoint: &str,
    registry: &str,
    target: &Hash,
) {
    let sig_path = signature_pointer_path(registry, target);
    let Some(sig_hash) = reader.read_path(endpoint, &sig_path).await else {
        return;
    };
    if !cache_entity(reader, content_store, endpoint, &sig_hash).await {
        return;
    }
    location_index.set(&sig_path, sig_hash);

    // The signer's identity entity — `resolve_peer_pubkey` needs it to derive
    // the public key the pin is checked against.
    if let Some(signer) = content_store
        .get(&sig_hash)
        .and_then(|e| SignatureData::from_entity(&e).ok())
        .map(|s| s.signer)
    {
        cache_entity(reader, content_store, endpoint, &signer).await;
    }
}
