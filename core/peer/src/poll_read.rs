//! Consumer-side reader for the Amendment 5 `http-poll` routes.
//!
//! The publisher half of these routes lives in [`crate::http_live`]; this is
//! the half that dials one. [`crate::published_root`] already reads two of them
//! ([`ContentFetcher`]: `manifest` + `content` + the signature leaf) because a
//! signed-root walk needs exactly those. This module adds the two a *path*
//! consumer needs — the `.bin` leaf pointer and the `.list` listing — and packs
//! all four behind one struct.
//!
//! **Host-trusted by construction, and that is the whole design constraint.**
//! A published-root walk verifies every node against a pinned signature, so the
//! host cannot lie. These routes have no such anchor: `.bin` and `.list` answer
//! from the host's own LocationIndex, so a malicious host can bind any path to
//! any hash it likes. What it *cannot* do is forge the bytes behind a hash —
//! [`read_content`] re-hashes every body and drops a mismatch. So a caller gets
//! "these bytes really are H" for free, and must supply its own reason to trust
//! the *binding* that produced H. The peer-issued registry backend's reason is
//! the pinned registry key: it signature-verifies the binding after the fetch,
//! which is why fetching host-trusted is sound there (proposal §2.1 step 3).
//!
//! **Async client, deliberately.** `published_root`'s [`HttpPollFetcher`] is
//! `reqwest::blocking`, because the trie walk it drives is a sync recursion and
//! threading async through it would have meant rewriting the walk. Nothing here
//! is walked — each read is one request — and every caller is an async handler,
//! so this uses the async client directly rather than paying for a
//! `spawn_blocking` hop per read.
//!
//! [`ContentFetcher`]: crate::published_root::ContentFetcher
//! [`HttpPollFetcher`]: crate::published_root::HttpPollFetcher
//! [`read_content`]: PollReader::read_content

use entity_entity::Entity;
use entity_hash::Hash;

use crate::http_live::{DEFAULT_TREE_LEAF_SUFFIX, DEFAULT_TREE_LISTING_SUFFIX};

/// `{base}/{absolute_path}{suffix}` — the Amendment 5 leaf-pointer URL.
///
/// `absolute_path` is universal-tree absolute (`/{peer}/system/...`), so it
/// already carries its own leading slash.
pub fn leaf_url(base: &str, absolute_path: &str, leaf_suffix: &str) -> String {
    format!(
        "{}{}{}",
        base.trim_end_matches('/'),
        absolute_path,
        leaf_suffix
    )
}

/// `{base}/{absolute_prefix}{suffix}` — the Amendment 5 listing URL.
pub fn listing_url(base: &str, absolute_prefix: &str, listing_suffix: &str) -> String {
    format!(
        "{}{}{}",
        base.trim_end_matches('/'),
        absolute_prefix.trim_end_matches('/'),
        listing_suffix
    )
}

/// Decode a `.bin` response body — the 2-key bare pointer
/// `ECF({type:"system/hash", data:<bstr33>})` — into the bound hash.
///
/// Deliberately not `entity_wire::decode_entity`: the pointer is 2-key by
/// design (§6.5.3.1 — a path-addressed pointer has no useful self-hash, and a
/// 3-key body would carry two hashes), so a full wire decode rejects it.
pub fn decode_leaf_pointer(body: &[u8]) -> Option<Hash> {
    let value: ciborium::Value = ciborium::de::from_reader(body).ok()?;
    let map = value.as_map()?;
    let mut ty = None;
    let mut data = None;
    for (k, v) in map {
        match k.as_text() {
            Some("type") => ty = v.as_text(),
            Some("data") => data = v.as_bytes(),
            _ => {}
        }
    }
    if ty? != entity_types::TYPE_HASH {
        return None;
    }
    Hash::from_bytes(data?).ok()
}

/// Decode a `.list` response body into the immediate child names.
///
/// Names only. The listing also carries each child's bound hash, but a consumer
/// that trusts those has skipped the second hop the two-hop split exists to
/// force — take the name, then read the leaf.
pub fn decode_listing_children(body: &[u8]) -> Option<Vec<String>> {
    let entity = entity_wire::decode_entity(body).ok()?;
    if entity.entity_type != entity_types::TYPE_TREE_LISTING {
        return None;
    }
    let value: ciborium::Value = ciborium::de::from_reader(entity.data.as_slice()).ok()?;
    let map = value.as_map()?;
    for (k, v) in map {
        if k.as_text() == Some("entries") {
            return Some(
                v.as_map()?
                    .iter()
                    .filter_map(|(name, _)| name.as_text().map(|s| s.to_string()))
                    .collect(),
            );
        }
    }
    Some(Vec::new())
}

/// A reader for one remote peer's http-poll surface.
///
/// `base` is the poll route root (`http://host:port`, or with a path prefix if
/// the publisher mounted one). Every method answers `None` on 404, on a
/// transport error, and on a body that does not decode — the caller cannot act
/// differently on those and collapsing them keeps a miss from reading as an
/// outage.
pub struct PollReader {
    client: reqwest::Client,
    base: String,
    leaf_suffix: String,
    listing_suffix: String,
}

impl PollReader {
    /// A reader against `base`, using the publisher's default suffixes.
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            base: base.into(),
            leaf_suffix: DEFAULT_TREE_LEAF_SUFFIX.to_string(),
            listing_suffix: DEFAULT_TREE_LISTING_SUFFIX.to_string(),
        }
    }

    /// Override the publisher's leaf / listing suffixes (§6.5.3.1 lets an
    /// operator pick them; they MUST differ from each other).
    pub fn with_suffixes(
        mut self,
        leaf_suffix: impl Into<String>,
        listing_suffix: impl Into<String>,
    ) -> Self {
        self.leaf_suffix = leaf_suffix.into();
        self.listing_suffix = listing_suffix.into();
        self
    }

    async fn get(&self, url: &str) -> Option<Vec<u8>> {
        let resp = self.client.get(url).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        Some(resp.bytes().await.ok()?.to_vec())
    }

    /// `TREE_GET(absolute_path)` → the bound hash. Host-trusted (see the module
    /// doc): this is the binding the host asserts, not one you can verify.
    pub async fn read_path(&self, absolute_path: &str) -> Option<Hash> {
        let url = leaf_url(&self.base, absolute_path, &self.leaf_suffix);
        decode_leaf_pointer(&self.get(&url).await?)
    }

    /// `CONTENT_GET(hash)` → the entity, **re-hashed and dropped on mismatch**.
    /// The one read here that a hostile host cannot influence.
    pub async fn read_content(&self, hash: &Hash) -> Option<Entity> {
        let url = crate::published_root::content_url(&self.base, hash);
        let bytes = self.get(&url).await?;
        crate::published_root::verify_content(&bytes, hash).ok()
    }

    /// List the immediate children of `absolute_prefix`. Empty vec for an
    /// in-scope prefix with no children; also empty for a 404, which the
    /// caller cannot distinguish and does not need to.
    pub async fn list_children(&self, absolute_prefix: &str) -> Vec<String> {
        let url = listing_url(&self.base, absolute_prefix, &self.listing_suffix);
        match self.get(&url).await {
            Some(body) => decode_listing_children(&body).unwrap_or_default(),
            None => Vec::new(),
        }
    }
}

// ===========================================================================
// The peer-issued registry's remote-read seam, over http-poll
// ===========================================================================

/// [`PollReader`] as the registry extension's [`RegistryTreeReader`].
///
/// The adapter is thin on purpose: the extension decides *which* paths a
/// peer-issued resolve needs and *why* each one is trustworthy; this only says
/// how the bytes arrive. One reader serves every pinned registry — the endpoint
/// travels per call from the chain entry's `hints`, so a peer can pin several
/// registries at different origins without a client each.
///
/// Endpoint→client caching is deliberately absent: `reqwest::Client` already
/// pools connections internally and is cheap to clone, so a map here would add
/// a lock on the resolve path to save nothing.
///
/// [`RegistryTreeReader`]: entity_registry::peer_issued::RegistryTreeReader
#[cfg(all(
    feature = "http-live",
    feature = "registry",
    not(target_arch = "wasm32")
))]
pub struct HttpPollRegistryReader {
    client: reqwest::Client,
    leaf_suffix: String,
    listing_suffix: String,
}

#[cfg(all(
    feature = "http-live",
    feature = "registry",
    not(target_arch = "wasm32")
))]
impl Default for HttpPollRegistryReader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(
    feature = "http-live",
    feature = "registry",
    not(target_arch = "wasm32")
))]
impl HttpPollRegistryReader {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            leaf_suffix: DEFAULT_TREE_LEAF_SUFFIX.to_string(),
            listing_suffix: DEFAULT_TREE_LISTING_SUFFIX.to_string(),
        }
    }

    fn reader_for(&self, endpoint: &str) -> PollReader {
        PollReader {
            client: self.client.clone(),
            base: endpoint.to_string(),
            leaf_suffix: self.leaf_suffix.clone(),
            listing_suffix: self.listing_suffix.clone(),
        }
    }
}

#[cfg(all(
    feature = "http-live",
    feature = "registry",
    not(target_arch = "wasm32")
))]
#[async_trait::async_trait]
impl entity_registry::peer_issued::RegistryTreeReader for HttpPollRegistryReader {
    async fn read_path(&self, endpoint: &str, absolute_path: &str) -> Option<Hash> {
        self.reader_for(endpoint).read_path(absolute_path).await
    }

    async fn read_content(&self, endpoint: &str, hash: &Hash) -> Option<Entity> {
        self.reader_for(endpoint).read_content(hash).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_pointer_round_trips_through_the_publisher_encoder() {
        let h = Hash::compute("test/blob", b"payload");
        let body = entity_ecf::ecf_for_hash_value(
            "system/hash",
            &entity_ecf::Value::Bytes(h.to_bytes().to_vec()),
        );
        assert_eq!(decode_leaf_pointer(&body), Some(h));
    }

    /// A same-side round-trip passes with the wrong shape too, so pin the two
    /// ways the publisher's body could be misread: a 3-key wire entity is NOT
    /// what `.bin` serves, and a pointer of some other type is not a hash.
    #[test]
    fn leaf_pointer_rejects_a_wire_entity_and_a_foreign_type() {
        let entity = Entity::new("test/blob", b"payload".to_vec()).expect("entity");
        assert_eq!(
            decode_leaf_pointer(&entity_wire::encode_entity(&entity)),
            None,
            "a 3-key wire entity is not a leaf pointer — accepting one would \
             read the entity's own self-hash as the bound hash"
        );

        let h = Hash::compute("test/blob", b"payload");
        let wrong_type = entity_ecf::ecf_for_hash_value(
            "system/not-a-hash",
            &entity_ecf::Value::Bytes(h.to_bytes().to_vec()),
        );
        assert_eq!(decode_leaf_pointer(&wrong_type), None);
    }

    #[test]
    fn url_builders_do_not_double_the_separator() {
        assert_eq!(
            leaf_url("http://h:1/", "/pid/system/x", ".bin"),
            "http://h:1/pid/system/x.bin"
        );
        assert_eq!(
            listing_url("http://h:1", "/pid/system/x/", ".list"),
            "http://h:1/pid/system/x.list"
        );
    }
}
