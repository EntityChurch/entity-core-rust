//! Entity, Envelope, and URI types.
//!
//! An Entity is the fundamental unit of data: `{type, data}` with a content hash.
//! An Envelope wraps an entity with included entities (signatures, identities, capabilities).

// Same rationale as entity-hash's crate-level allow: `EntityError`
// embeds `HashMismatch { expected: Hash, actual: Hash }` (two 64-byte
// inline-buffer `Copy` values, ≥132 bytes), over clippy's 128-byte
// `result_large_err` threshold. Cold error path; boxing would churn
// every constructor for no runtime win.
#![allow(clippy::result_large_err)]

use std::collections::BTreeMap;

use entity_hash::Hash;
use thiserror::Error;

/// System type for signature entities.
pub const TYPE_SIGNATURE: &str = "system/signature";

/// `system/peer` — the identity entity. Declared here (rather than only in
/// `entity-crypto` / `entity-types`, which sit above this crate) because
/// [`Entity::new_with_format`] enforces V7 §4.5a item 1a's floor pin on it and
/// needs the name at this layer.
pub const TYPE_PEER: &str = "system/peer";

/// `system/deletion-marker` — ENTITY-NATIVE-TYPE-SYSTEM v4.2.0 §4.9.
/// Zero-field canonical entity. Its `data` is the CBOR empty map (`0xa0`).
pub const TYPE_DELETION_MARKER: &str = "system/deletion-marker";

/// The canonical hash of `system/deletion-marker`, hex-encoded:
/// `ecf-sha256:689ae4679f69f006e4bf7cb7c7a9155d0de5fb9fe31e81692dca5769eda9e0a6`.
/// Implementations MUST verify their local computation matches this value
/// (NATIVE-TYPE-SYSTEM §4.9) — any deviation signals an ECF-encoding bug.
pub const CANONICAL_DELETION_MARKER_HASH_HEX: &str =
    "689ae4679f69f006e4bf7cb7c7a9155d0de5fb9fe31e81692dca5769eda9e0a6";

/// Build the canonical `system/deletion-marker` entity.
/// `data` is the CBOR empty map (`0xa0`).
pub fn canonical_deletion_marker_entity() -> Entity {
    // CBOR empty map = 0xa0 (one byte).
    Entity::new(TYPE_DELETION_MARKER, vec![0xa0u8])
        .expect("canonical deletion marker must construct")
}

/// Return the canonical `system/deletion-marker` content hash. Memoized
/// per-process via OnceLock. The hash MUST equal
/// `CANONICAL_DELETION_MARKER_HASH_HEX` — verified by debug_assert.
pub fn canonical_deletion_marker_hash() -> Hash {
    static CACHED: std::sync::OnceLock<Hash> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| canonical_deletion_marker_entity().content_hash)
}

/// URI scheme for entity references.
pub const URI_SCHEME: &str = "entity://";

/// The unmatchable canonical value (§5.4, 0.8.2.20). See
/// `entity_capability::NEVER_MATCH`, which re-exports this constant — the
/// definition lives here because `core/entity` sits above `core/capability` in
/// the crate DAG and both `qualify_path` and `canonicalize` must return the
/// *same* string for the matcher rule to hold across them.
///
/// A single-segment absolute path whose first segment cannot be a `peer_id`
/// ([`EntityUri::is_peer_id`] requires >= 46 Base58 characters and `-` is
/// outside the Base58 alphabet), so it is unreachable as a canonical path by
/// construction rather than by prohibition. Star-free, plain ASCII, greppable.
pub const NEVER_MATCH: &str = "/never-match";

/// An entity: the fundamental unit of content-addressed data.
///
/// Contains a type string, raw CBOR data bytes, and its content hash.
/// The data bytes are preserved exactly as received — never decoded and re-encoded.
#[derive(Debug, Clone)]
pub struct Entity {
    /// Entity type string (e.g., "system/handler").
    pub entity_type: String,
    /// Raw CBOR-encoded data bytes (preserved for hash fidelity).
    pub data: Vec<u8>,
    /// Content hash: SHA-256 over ECF-encoded `{data, type}`.
    pub content_hash: Hash,
}

impl Entity {
    /// Create a new entity, computing its content hash under the process
    /// **home** `content_hash_format` ([`entity_hash::default_hash_format`]).
    ///
    /// This is the home-authoring default, correct for non-connection-bound
    /// authoring (peer-startup local state, stored content, substrate,
    /// handler results). It is the SHA-256 floor unless the peer set a
    /// different home format at build (V7 §1.2 / v7.70). Connection-bound
    /// authoring that must honor a negotiated active format (V7 §4.5a) uses
    /// [`Entity::new_with_format`] with the connection's active format.
    ///
    /// Validates that type and data are non-empty.
    pub fn new(entity_type: &str, data: Vec<u8>) -> Result<Self, EntityError> {
        Self::new_with_format(entity_type, data, entity_hash::default_hash_format())
    }

    /// Create a new entity, computing its content hash under an explicit
    /// `content_hash_format` code (V7 §4.5a — author under the connection's
    /// negotiated active format). An unsupported format code is rejected.
    ///
    /// **`system/peer` at a non-floor format is refused outright** — see the
    /// guard below.
    pub fn new_with_format(
        entity_type: &str,
        data: Vec<u8>,
        format_code: u8,
    ) -> Result<Self, EntityError> {
        if entity_type.is_empty() {
            return Err(EntityError::InvalidType(
                "entity type cannot be empty".into(),
            ));
        }
        if data.is_empty() {
            return Err(EntityError::MissingField("data".into()));
        }
        // V7 §4.5a **item 1a** (v7.77): the `system/peer` identity entity is
        // authored at the ECFv1-SHA-256 floor **unconditionally** — on every
        // connection, whatever the active format, and whatever the peer's home
        // format. It is the single exception to §1.2's "persistent state is
        // uniformly the home format", and item 4 names the failure it prevents
        // by name: an implementation that *derives* an identity hash for a path
        // segment and *authors* one for an equality check is using **one**
        // function, and two functions is the defect.
        //
        // **Refused at the constructor rather than fixed at each call site,
        // because the failure is silent by construction.** A non-floor identity
        // entity is well-formed; it just carries a second content_hash for the
        // one identity item 1a exists to collapse — on the exact surface where
        // §5.2's `grantee`/`granter`/`signer` equalities are evaluated. Both
        // sides of every downstream comparison are then wrong the same way, so
        // nothing fails and no cross-impl check can see it: go's own item-1a
        // vector is a `[self]` check by construction, and it can only ever
        // measure the seat that runs it.
        //
        // Authors go through `entity_crypto::peer_entity_from_components*`,
        // which takes no format parameter for this reason.
        if entity_type == TYPE_PEER && format_code != entity_hash::HASH_ALGORITHM_SHA256 {
            return Err(EntityError::InvalidType(format!(
                "{} is pinned to the ECFv1-SHA-256 floor (V7 §4.5a item 1a); \
                 refusing to author it under content_hash_format {:#04x}",
                TYPE_PEER, format_code
            )));
        }
        let content_hash = Hash::compute_format(entity_type, &data, format_code)
            .map_err(|e| EntityError::InvalidType(e.to_string()))?;
        Ok(Self {
            entity_type: entity_type.to_string(),
            data,
            content_hash,
        })
    }

    /// Validate that the content hash matches the entity's type and data,
    /// recomputing under the entity's own `content_hash_format` (V7 §1.8).
    pub fn validate(&self) -> Result<(), EntityError> {
        Hash::validate(&self.entity_type, &self.data, &self.content_hash).map_err(|e| match e {
            entity_hash::HashError::HashMismatch { expected, actual } => {
                EntityError::HashMismatch { expected, actual }
            }
            other => EntityError::InvalidType(other.to_string()),
        })
    }
}

impl PartialEq for Entity {
    fn eq(&self, other: &Self) -> bool {
        self.content_hash == other.content_hash
    }
}

impl Eq for Entity {}

/// An envelope wraps a root entity with included entities.
///
/// Auth metadata (signatures, identities, capabilities) are separate entities
/// in the `included` map, found by scanning for matching types.
#[derive(Debug, Clone)]
pub struct Envelope {
    /// The primary entity in this envelope.
    pub root: Entity,
    /// Additional entities keyed by content hash (signatures, identities, etc.).
    pub included: BTreeMap<Hash, Entity>,
}

impl Envelope {
    /// Create an envelope with just a root entity.
    pub fn new(root: Entity) -> Self {
        Self {
            root,
            included: BTreeMap::new(),
        }
    }

    /// Create an envelope with a root entity and included entities.
    pub fn with_included(root: Entity, included: BTreeMap<Hash, Entity>) -> Self {
        Self { root, included }
    }

    /// Add an entity to the included map, keyed by its content hash.
    ///
    /// ⛔ **The key is RECOMPUTED from `{type, data}`, not read off the entity's
    /// `content_hash` field `[MUST]` (§3.1, 0.8.2.23).** §3.1's keying is now
    /// normative in **both** directions — *"a sender MUST key each entry by the
    /// content hash of the entity it holds"* — and this is the one site in this
    /// tree that keys the map, so it is the one site that has to hold it.
    ///
    /// The field and the content can disagree, and exactly one path produces
    /// that: `decode_entity` takes `content_hash` from the wire **verbatim**,
    /// because §5.4 byte fidelity forbids a decode+re-encode. Our own decoder
    /// refuses a mis-keyed `included` entry, but a mis-stamped **root** is
    /// admitted there and validated later — so any path that receives an
    /// envelope and forwards one of its entities onward (a relay, a mirror, a
    /// `follow` leg) could re-emit it under the stamped lie. Keying by the field
    /// would have made *us* the sender that violates §3.1.
    ///
    /// **Recomputed under the hash's OWN declared format**, not the process
    /// default: on a SHA-384 connection the default would re-address every
    /// entity in the map. An unallocated format cannot be recomputed at all, so
    /// that case keys by the stamped hash unchanged — the receiver refuses it
    /// with `unsupported_content_hash_format` (§4.7), which is the right defect
    /// and a better one than anything this function could invent.
    ///
    /// Note what this deliberately does **not** do: it does not repair the
    /// entity's own `content_hash`. The map becomes content-addressed, which is
    /// the property §3.1 protects; the entity stays self-inconsistent, and the
    /// receiver's §1.8 item-1 validation answers `hash_mismatch` **about the
    /// entity** rather than about the map. Self-consistency and correct
    /// addressing are different properties and each keeps its own error.
    pub fn include(&mut self, entity: Entity) {
        let key = Hash::compute_format(
            &entity.entity_type,
            &entity.data,
            entity.content_hash.format_code(),
        )
        .unwrap_or(entity.content_hash);
        self.included.insert(key, entity);
    }

    /// Find an included entity by its content hash.
    pub fn find_included(&self, hash: &Hash) -> Option<&Entity> {
        self.included.get(hash)
    }

    /// Find a signature entity targeting the given hash.
    ///
    /// Scans included entities for `system/signature` type where the data
    /// contains a `target` field matching the given hash. Returns the first match.
    pub fn find_signature_for(&self, target: &Hash) -> Option<&Entity> {
        find_signature_for_target(self.included.values(), target)
    }

    /// Validate the root entity and all included entities.
    pub fn validate_all(&self) -> Result<(), EntityError> {
        self.root.validate()?;
        for entity in self.included.values() {
            entity.validate()?;
        }
        Ok(())
    }
}

/// Find a signature entity targeting the given hash in an entity collection.
///
/// Scans for `system/signature` entities whose data contains a `target` field
/// matching the given hash. Returns the first match.
///
/// Generic over the input iterator so both `BTreeMap`-backed (Envelope) and
/// `HashMap`-backed (HandlerContext) callers can pass `.values()` directly.
pub fn find_signature_for_target<'a, I>(entities: I, target: &Hash) -> Option<&'a Entity>
where
    I: IntoIterator<Item = &'a Entity>,
{
    for entity in entities {
        if entity.entity_type == TYPE_SIGNATURE {
            if let Some((sig_target, _)) = decode_sig_target_signer(&entity.data) {
                if sig_target == *target {
                    return Some(entity);
                }
            }
        }
    }
    None
}

/// Find a signature entity matching both target hash AND signer identity hash
/// (PROPOSAL-MULTISIG-CORE-PRIMITIVE §4.0 / new helper).
///
/// `find_signature_for_target` returns the *first* signature for a target.
/// Multi-sig verification needs to locate signatures by *both* fields since
/// multiple constituents sign the same target. Used by M4 (per-link sig
/// verification multi-sig branch), M6 (root-trust check), and M7
/// (`check_creator_authority` strict-with-signature).
///
/// Generic over the input iterator so both BTreeMap- and HashMap-backed
/// callers can pass `.values()` directly.
pub fn find_signature_by_signer<'a, I>(
    entities: I,
    target: &Hash,
    signer: &Hash,
) -> Option<&'a Entity>
where
    I: IntoIterator<Item = &'a Entity>,
{
    for entity in entities {
        if entity.entity_type == TYPE_SIGNATURE {
            if let Some((t, s)) = decode_sig_target_signer(&entity.data) {
                if t == *target && s == *signer {
                    return Some(entity);
                }
            }
        }
    }
    None
}

/// Decode just the (target, signer) hashes from a `system/signature` entity's
/// CBOR data. Returns None on any decode failure (defensive — fail-closed
/// callers get a no-match).
fn decode_sig_target_signer(data: &[u8]) -> Option<(Hash, Hash)> {
    let value: ciborium::Value = ciborium::from_reader(data).ok()?;
    let entries = value.as_map()?;
    let mut target = None;
    let mut signer = None;
    for (k, v) in entries {
        match k.as_text() {
            Some("target") => {
                target = v.as_bytes().and_then(|b| Hash::from_bytes(b).ok());
            }
            Some("signer") => {
                signer = v.as_bytes().and_then(|b| Hash::from_bytes(b).ok());
            }
            _ => {}
        }
    }
    Some((target?, signer?))
}

/// A parsed entity URI: `entity://<peer_id>/<path>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityUri {
    /// Peer identifier (PeerID or empty for local).
    pub peer_id: String,
    /// Path (e.g., "system/tree"). No leading slash.
    pub path: String,
}

impl EntityUri {
    /// Parse an entity URI string.
    ///
    /// Format: `entity://<peer_id>/<path>` or `entity://<peer_id>`.
    pub fn parse(s: &str) -> Result<Self, EntityError> {
        let rest = s
            .strip_prefix(URI_SCHEME)
            .ok_or_else(|| EntityError::InvalidUri(format!("expected '{}' prefix", URI_SCHEME)))?;
        match rest.find('/') {
            Some(idx) => Ok(Self {
                peer_id: rest[..idx].to_string(),
                path: rest[idx + 1..].to_string(),
            }),
            None => Ok(Self {
                peer_id: rest.to_string(),
                path: String::new(),
            }),
        }
    }

    /// Normalize a path or URI to just the path portion.
    ///
    /// Strips `entity://` prefix and peer_id if present.
    pub fn normalize_path(uri: &str) -> &str {
        match uri.strip_prefix(URI_SCHEME) {
            Some(rest) => match rest.find('/') {
                Some(idx) => &rest[idx + 1..],
                None => "",
            },
            None => uri,
        }
    }

    /// Extract the handler path from a URI or path.
    ///
    /// For fully-qualified URIs, strips scheme + peer_id.
    /// For bare paths, returns as-is.
    pub fn extract_handler_path(uri: &str) -> &str {
        Self::normalize_path(uri)
    }

    /// Check if a string segment looks like a Base58 PeerID (46 chars).
    pub fn is_peer_id(segment: &str) -> bool {
        const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        segment.len() == 46 && segment.bytes().all(|b| BASE58.contains(&b))
    }

    /// Extract the peer a URI addresses (V7 §5.2 `extract_peer`).
    ///
    /// ```text
    /// extract_peer(uri, local_peer_id):
    ///   first = first_segment(uri)
    ///   if is_peer_id(first): return first
    ///   return local_peer_id
    /// ```
    ///
    /// This is the `target_peer` fed to the `peers` dimension of
    /// [`check_permission`]. It is deliberately **not** `local_peer_id`: a
    /// dispatch whose URI names a foreign peer must be tested against that
    /// peer, or a grant scoped `peers: {include: [local]}` (or absent, which
    /// defaults to the same) authorizes a *foreign* namespace. Passing `local`
    /// here is a privilege escalation, not a conservative default.
    ///
    /// Short-form and non-peer-prefixed absolute paths (`system/tree`,
    /// `/system/tree`) belong to the local peer.
    ///
    /// [`check_permission`]: ../entity_capability/fn.check_permission.html
    pub fn extract_peer(uri: &str, local_peer_id: &str) -> String {
        // `entity://{authority}/rest` — the authority IS the first segment.
        // Note this cannot go through `normalize_path`, which *strips* the
        // authority; routing it through there would read every `entity://`
        // URI as local, which is the escalation this function exists to stop.
        let rest = match uri.strip_prefix(URI_SCHEME) {
            Some(rest) => rest,
            None => uri.strip_prefix('/').unwrap_or(uri),
        };
        let first = match rest.find('/') {
            Some(slash) => &rest[..slash],
            None => rest,
        };
        if Self::is_peer_id(first) {
            first.to_string()
        } else {
            local_peer_id.to_string()
        }
    }

    /// Qualify a path to absolute form. Idempotent.
    ///
    /// - `entity://peer/path` → `/peer/path`
    /// - `/peer/path` (already absolute) → as-is
    /// - `system/tree` (peer-relative) → `/{local_peer_id}/system/tree`
    /// - `*` (bare wildcard) → `/{local_peer_id}/*`
    ///
    /// **Total** (§5.4, 0.8.2.20). The three reserved shapes — `./…`, `../…`
    /// and the ambiguous bare `*/…` — yield [`NEVER_MATCH`], which
    /// [`Self::validate_absolute_path`] then refuses, so the dispatch sites'
    /// existing post-qualify check answers the caller `400 invalid_path`
    /// (§6.5 admission, `CORE-TREE-PATH-FLEX-1`).
    ///
    /// ⛔ These three shapes were `assert!`s, and `validate_path_input` — the
    /// pre-qualify guard both dispatch sites run — rejects `./` and `../` but
    /// **not** `*/`. So an inbound EXECUTE carrying
    /// `resource: {targets: ["*/anything"]}` reached this function and
    /// **panicked**, killing the connection task, from any authenticated peer
    /// and *before* `check_permission` ran. A path helper that panics on
    /// caller-controlled input is a defect whichever answer is correct; the
    /// answer here is the one §5.4 already gives its sibling `canonicalize`.
    pub fn qualify_path(path: &str, local_peer_id: &str) -> String {
        // Strip entity:// scheme → produce absolute path
        if let Some(rest) = path.strip_prefix(URI_SCHEME) {
            return Self::clean_path(&format!("/{}", rest));
        }
        // Reserved directory-relative paths (§1.4).
        if path.starts_with("./") || path.starts_with("../") {
            return NEVER_MATCH.to_string();
        }
        // Ambiguous bare */rest — must use /*/rest.
        if path.starts_with("*/") {
            return NEVER_MATCH.to_string();
        }
        // Already absolute → pass through
        if path.starts_with('/') {
            return Self::clean_path(path);
        }
        // Bare wildcard → local peer all paths
        if path == "*" {
            return format!("/{}/*", local_peer_id);
        }
        // Defense-in-depth: legacy qualified path without leading /
        if let Some(slash) = path.find('/') {
            if Self::is_peer_id(&path[..slash]) {
                return format!("/{}", path);
            }
        } else if Self::is_peer_id(path) {
            return format!("/{}", path);
        }
        // Bare path → absolute with local peer
        format!("/{}/{}", local_peer_id, path)
    }

    /// Strip peer_id prefix from a qualified path.
    /// Returns the bare path portion.
    ///
    /// Handles both absolute (`/peer_id/rest` → `rest`) and legacy
    /// (`peer_id/rest` → `rest`) formats.
    pub fn strip_peer_prefix(path: &str) -> &str {
        // Strip leading / for absolute paths
        let p = path.strip_prefix('/').unwrap_or(path);
        if let Some(slash) = p.find('/') {
            if Self::is_peer_id(&p[..slash]) {
                return &p[slash + 1..];
            }
        }
        // Bare peer_id only (no path after)
        if Self::is_peer_id(p) {
            return "";
        }
        path
    }

    /// Check if a path is absolute (starts with `/`).
    pub fn is_absolute(path: &str) -> bool {
        path.starts_with('/')
    }

    /// Validate that a path is well-formed for dispatch (R12).
    ///
    /// Called **before** `qualify_path` at the protocol boundary.
    /// Returns `Err` with a description on failure.
    ///
    /// Rejects:
    /// - `./` and `../` prefixes (reserved for directory-relative)
    /// - Empty segments (`//`) in the path portion (not in `entity://` scheme)
    pub fn validate_path_input(path: &str) -> Result<(), String> {
        if path.starts_with("./") || path == "." {
            return Err("reserved: directory-relative path ./".into());
        }
        if path.starts_with("../") || path == ".." {
            return Err("reserved: directory-relative path ../".into());
        }
        // Check for empty segments — skip entity:// scheme
        let check_part = path.strip_prefix(URI_SCHEME).unwrap_or(path);
        if check_part.contains("//") {
            return Err("invalid: path contains empty segment (//)".into());
        }
        Ok(())
    }

    /// Validate that an absolute path has a valid structure (R12, R2).
    ///
    /// Called **after** `qualify_path` at the protocol boundary on tree paths
    /// (dispatch paths and resource targets). NOT called on patterns.
    ///
    /// Checks:
    /// - Starts with `/`
    /// - No empty segments (`//`)
    /// - First segment after `/` is a valid peer_id (Base58, >= 46 chars)
    ///
    /// **Strict — rejects `content` / `manifest` reserved words too** per
    /// `PROPOSAL-TRANSPORT-FAMILY-CHUNK-C-AMENDMENTS §2.10`
    /// (D9). This rejection is load-bearing for the §6.4 collision-safety
    /// argument: a tree path's first segment is always a peer-ID, period.
    /// Reserved-word recognition for the `{X}`-slot URL form is a
    /// **separate URL-layer concern**; see [`Self::is_reserved_path_word`]
    /// for that helper. The two surfaces are deliberately distinct — the
    /// http-poll URL parser MAY accept reserved words; the entity tree
    /// path validator MUST NOT.
    pub fn validate_absolute_path(path: &str) -> Result<(), String> {
        if !path.starts_with('/') {
            return Err(format!("path is not absolute (no leading /): {}", path));
        }
        if path.contains("//") {
            return Err(format!("path contains empty segment (//): {}", path));
        }
        let after_slash = &path[1..]; // skip leading /
        let first_segment = match after_slash.find('/') {
            Some(idx) => &after_slash[..idx],
            None => after_slash,
        };
        if !Self::is_peer_id(first_segment) {
            return Err(format!(
                "first segment is not a valid peer_id: '{}' (expected Base58, 46 chars)",
                first_segment
            ));
        }
        Ok(())
    }

    /// True if `segment` is one of the `{X}`-slot reserved words (`content`
    /// or `manifest`).
    ///
    /// **URL-layer helper only** (`EXTENSION-NETWORK` §6.4 / D-12). This
    /// is NOT used by [`Self::validate_absolute_path`] — entity tree paths
    /// are strict-peer-ID per D9. Reserved-word redirects are an
    /// `http-poll` URL convention; the parser walking such URLs may use
    /// this helper to recognize the reserved-segment positions and
    /// redirect to content-store / manifest operations accordingly.
    /// Live `http` EXECUTEs the handler directly with no indirection.
    pub fn is_reserved_path_word(segment: &str) -> bool {
        matches!(segment, "content" | "manifest")
    }

    /// Clean a path: collapse consecutive `//` → `/`, preserve leading `/`,
    /// preserve trailing `/`. Handles `entity://` scheme transparently.
    ///
    /// Trailing slashes are data for tree prefix operations (they distinguish
    /// "subtree prefix" from "exact binding path" and are required by
    /// `tree.snapshot`, `tree.extract`, `tree.merge`). Callers that want a
    /// canonical binding path should strip trailing slashes themselves.
    ///
    /// **Total.** Cleans whatever it is given and never panics (§5.4,
    /// 0.8.2.21: *"path validation is a property of the BOUNDARY, not of the
    /// channel… a boundary MUST NOT assert on a malformed path"*).
    ///
    /// ⛔ **This function used to `assert!` on a leading `./` or `../`, under a
    /// `#[should_panic]` test that made the crash read as intentional.** It is
    /// the same shape as `qualify_path`'s `*/` assert, which was wire-reachable
    /// and shipped; this one was not reachable through `qualify_path` (the
    /// reserved prefixes are answered with `NEVER_MATCH` before this is called)
    /// but it is a `pub` path helper on the store side of the tree, and *"not
    /// reachable today"* is the sentence that was true about the other one
    /// until a params channel appeared. The **disposition** for a reserved
    /// prefix lives at the boundary that has a caller to answer —
    /// [`Self::validate_path_input`] (`400 invalid_path`) and
    /// `entity_capability::canonicalize` ([`NEVER_MATCH`]) — not here.
    ///
    /// Cleaning is not canonicalization: this collapses `//` and preserves
    /// leading/trailing `/`. It does not resolve `.` or `..` segments and never
    /// did — [`is_safe_path_segment`] is the defense for an interpolated value.
    pub fn clean_path(input: &str) -> String {
        // Handle entity:// scheme — clean only the path portion
        if let Some(rest) = input.strip_prefix(URI_SCHEME) {
            return format!("{}{}", URI_SCHEME, Self::clean_path(rest));
        }
        if input.is_empty() {
            return String::new();
        }
        // Collapse consecutive slashes, preserve leading and trailing /
        let mut result = String::with_capacity(input.len());
        let mut prev_slash = false;
        for ch in input.chars() {
            if ch == '/' {
                if !prev_slash {
                    result.push('/');
                }
                prev_slash = true;
            } else {
                result.push(ch);
                prev_slash = false;
            }
        }
        result
    }
}

/// Reports whether `s` can be interpolated verbatim as ONE segment of a tree
/// path: non-empty, slash-free, neither reserved dot token, and free of
/// control characters (V7 §1.4).
///
/// [`EntityUri::clean_path`] only rejects a LEADING `./` or `../`, which a
/// value interpolated into the MIDDLE of a path never is — so it is not a
/// defense for this. `"sink/{X}/.."` is inside the sink by string prefix
/// while naming somewhere else entirely.
pub fn is_safe_path_segment(s: &str) -> bool {
    if s.is_empty() || s == "." || s == ".." {
        return false;
    }
    if s.contains('/') {
        return false;
    }
    // Slashes are handled above; printable ASCII and high-bit Unicode bytes
    // are fine (Unicode segments are accepted per §1.4).
    !s.bytes().any(|b| b < 0x20 || b == 0x7F)
}

/// Sentinel for a non-path-safe `{reason}` coordinate — EXTENSION-
/// CONTINUATION §3.10.5, landed (not ours to choose).
pub const SENTINEL_UNSPECIFIED_ERROR: &str = "unspecified_error";
/// Sentinel for a non-path-safe `{chain_id}` coordinate (arch round-2
/// ruling 3; converged with Go's `types.ChainIDUnspecified`).
pub const SENTINEL_UNSPECIFIED_CHAIN_ID: &str = "unspecified_chain_id";
/// Sentinel for a non-path-safe `{step_index}` coordinate (arch round-2
/// ruling 3; converged with Go's `types.StepIndexUnspecified`).
pub const SENTINEL_UNSPECIFIED_STEP_INDEX: &str = "unspecified_step_index";

/// Returns `s` when it is safe as one path segment, else the caller's fixed
/// `sentinel`.
///
/// For any value that arrives from the wire — `request_id`, `bounds.chain_id`,
/// a remote handler's `result.data.code` — this is the boundary between "a
/// caller names its own coordinate" and "a caller chooses where our entity
/// lands". Callers MUST run every untrusted value through this BEFORE
/// concatenating it into a path, and MUST preserve the original in the
/// record's body — collapsing is only lossless because the body recovers it
/// (§3.10.6's pinned schema).
///
/// The §3.10.3 `rejected` marker is the sharp case: it is bound precisely
/// BECAUSE the sender's cap check failed, so an unauthorized caller reaches
/// the binding site by construction and no capability is required to choose
/// where that entity lands.
///
/// **Collapse, not hash** (arch round-2 ruling 1, amending round-1 ruling 13;
/// the shape §3.10.5 already lands for `{reason}`). This function first hashed
/// unsafe values to keep distinct values on distinct coordinates. That was
/// wrong three ways:
///
/// - **Distinctness was already carried elsewhere.** §3.10.1's terminal
///   `{marker_hash}` segment puts every occurrence at its own path regardless
///   of what the intermediate segments do, so collapsing loses no occurrence.
/// - **Hashing is a ONE-WAY loss wherever the body does not carry the
///   original** — exactly `chain_id`, the one coordinate a remote fully
///   controls. An operator reading the marker that exists to observe a hostile
///   failure could not answer what the attacker sent.
/// - **It re-opened the vector the sanitizing closed, one layer up:** each
///   distinct hostile value hashed to a distinct node, so an attacker could
///   mint unbounded path nodes, bounded only by GC. A sentinel bounds it to
///   one quarantine node — pinned by
///   `sanitize_path_segment_does_not_let_an_attacker_mint_nodes`.
///
/// One sentinel per coordinate rather than one shared, so a quarantined marker
/// still says WHICH coordinate was hostile without putting the value on the
/// path.
///
/// Safe values pass through byte-identical, so this changes no conformant
/// coordinate and cannot de-converge a seat. Matches Go's
/// `store.SanitizePathSegment(s, sentinel)` (`core/store/store.go`).
pub fn sanitize_path_segment<'a>(s: &'a str, sentinel: &'a str) -> &'a str {
    if is_safe_path_segment(s) {
        return s;
    }
    sentinel
}

impl std::fmt::Display for EntityUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.path.is_empty() {
            write!(f, "{}{}", URI_SCHEME, self.peer_id)
        } else {
            write!(f, "{}{}/{}", URI_SCHEME, self.peer_id, self.path)
        }
    }
}

#[derive(Debug, Error)]
pub enum EntityError {
    #[error("invalid entity type: {0}")]
    InvalidType(String),

    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: Hash, actual: Hash },

    #[error("missing required field: {0}")]
    MissingField(String),

    #[error("invalid URI: {0}")]
    InvalidUri(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_data(s: &str) -> Vec<u8> {
        entity_ecf::to_ecf(&entity_ecf::text(s))
    }

    // --- Entity tests ---

    #[test]
    fn test_entity_new() {
        let e = Entity::new("test/type", make_data("hello")).unwrap();
        assert_eq!(e.entity_type, "test/type");
        assert!(!e.content_hash.is_zero());
    }

    #[test]
    fn test_entity_new_empty_type() {
        assert!(matches!(
            Entity::new("", make_data("hello")),
            Err(EntityError::InvalidType(_))
        ));
    }

    #[test]
    fn test_entity_new_empty_data() {
        assert!(matches!(
            Entity::new("test/type", vec![]),
            Err(EntityError::MissingField(_))
        ));
    }

    #[test]
    fn test_entity_validate_ok() {
        let e = Entity::new("test/type", make_data("hello")).unwrap();
        assert!(e.validate().is_ok());
    }

    #[test]
    fn test_entity_validate_tampered() {
        let mut e = Entity::new("test/type", make_data("hello")).unwrap();
        e.data = make_data("tampered");
        assert!(matches!(
            e.validate(),
            Err(EntityError::HashMismatch { .. })
        ));
    }

    #[test]
    fn test_entity_equality_by_hash() {
        let e1 = Entity::new("test/type", make_data("hello")).unwrap();
        let e2 = Entity::new("test/type", make_data("hello")).unwrap();
        assert_eq!(e1, e2);
    }

    #[test]
    fn test_entity_different_data_not_equal() {
        let e1 = Entity::new("test/type", make_data("aaa")).unwrap();
        let e2 = Entity::new("test/type", make_data("bbb")).unwrap();
        assert_ne!(e1, e2);
    }

    // --- Envelope tests ---

    #[test]
    fn test_envelope_new() {
        let root = Entity::new("test/root", make_data("root")).unwrap();
        let env = Envelope::new(root.clone());
        assert_eq!(env.root, root);
        assert!(env.included.is_empty());
    }

    #[test]
    fn test_envelope_include() {
        let root = Entity::new("test/root", make_data("root")).unwrap();
        let extra = Entity::new("test/extra", make_data("extra")).unwrap();
        let extra_hash = extra.content_hash;
        let mut env = Envelope::new(root);
        env.include(extra);
        assert!(env.find_included(&extra_hash).is_some());
    }

    #[test]
    fn test_envelope_with_included() {
        let root = Entity::new("test/root", make_data("root")).unwrap();
        let extra = Entity::new("test/extra", make_data("extra")).unwrap();
        let extra_hash = extra.content_hash;
        let mut map = BTreeMap::new();
        map.insert(extra.content_hash, extra);
        let env = Envelope::with_included(root, map);
        assert!(env.find_included(&extra_hash).is_some());
    }

    #[test]
    fn canonical_deletion_marker_hash_matches_spec() {
        // ENTITY-NATIVE-TYPE-SYSTEM §4.9 (v4.2.0) — implementations MUST
        // verify the canonical deletion-marker hash matches the value
        // pinned in the spec. Any deviation signals an ECF-encoding bug.
        let h = canonical_deletion_marker_hash();
        let hex_digest: String = h.digest().iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            hex_digest, CANONICAL_DELETION_MARKER_HASH_HEX,
            "canonical deletion-marker hash MUST match the spec value"
        );
        // The data MUST be CBOR empty map (0xa0) — not 0x40 (empty bstr), not 0xf6 (null).
        let e = canonical_deletion_marker_entity();
        assert_eq!(e.data, vec![0xa0u8]);
        assert_eq!(e.entity_type, "system/deletion-marker");
    }

    #[test]
    fn test_envelope_validate_all() {
        let root = Entity::new("test/root", make_data("root")).unwrap();
        let extra = Entity::new("test/extra", make_data("extra")).unwrap();
        let mut env = Envelope::new(root);
        env.include(extra);
        assert!(env.validate_all().is_ok());
    }

    #[test]
    fn test_envelope_validate_all_tampered() {
        let root = Entity::new("test/root", make_data("root")).unwrap();
        let mut extra = Entity::new("test/extra", make_data("extra")).unwrap();
        extra.data = make_data("tampered");
        let mut env = Envelope::new(root);
        env.include(extra);
        assert!(env.validate_all().is_err());
    }

    /// ⛔ **§3.1's SENDER MUST (0.8.2.23): the `included` key is the content
    /// hash of the entity under it, and `include` recomputes rather than
    /// trusting the stamped field.**
    ///
    /// §3.1 stated the map's shape in the indicative for seven revisions and
    /// obliged nothing; 0.8.2.23 makes it normative in **both** directions. The
    /// receiver half this tree has enforced since `0fc01ad` (three sites). This
    /// is the sender half, and it is one function because `include` is the only
    /// site that keys the map.
    ///
    /// **The fixture carries a value the codec cannot emit**, which is the only
    /// way to tell the two implementations apart: `Entity::new` computes the
    /// hash, so for any honestly-built entity `key = entity.content_hash` and
    /// `key = recompute(entity)` are the **same address** and no assertion can
    /// separate them. A mis-stamped entity — content changed under a stamp that
    /// was correct for the old content, which is exactly what `decode_entity`
    /// admits from the wire — is the discriminator.
    ///
    /// Row 2 is the property, not the mechanism: whatever key was chosen, the
    /// map must be **content-addressed**, i.e. every key equals the hash of its
    /// value's content. That is the sentence a receiver checks, so it is the
    /// sentence asserted.
    ///
    /// Row 3 is the control, and it is the one that fails if "recompute" is
    /// implemented as "recompute under the process default": an honest entity
    /// must still land under its own hash, unmoved.
    ///
    /// **Mutation-verified:** restoring `self.included.insert(entity.content_hash,
    /// entity)` reddens rows 1 and 2 and leaves row 3 green. Row 2 was confirmed
    /// **separately, with row 1 neutered** — row 1 is an `assert!` and
    /// short-circuits, so a single run is evidence about row 1 only. Two runs,
    /// because "the test went red" and "this row went red" are different claims.
    #[test]
    fn include_keys_by_recomputed_content_not_by_the_stamped_field() {
        let root = Entity::new("test/root", make_data("root")).unwrap();

        // Self-inconsistent by construction: the stamp is correct for "before",
        // the content is "after". `Entity::new` cannot produce this; only the
        // wire decoder can, and it does — `content_hash` is taken verbatim there
        // because §5.4 byte fidelity forbids a decode+re-encode.
        let mut mis_stamped = Entity::new("test/extra", make_data("before")).unwrap();
        let stamped = mis_stamped.content_hash;
        mis_stamped.data = make_data("after");
        let true_hash =
            Hash::compute_format("test/extra", &mis_stamped.data, stamped.format_code()).unwrap();
        assert_ne!(stamped, true_hash, "fixture precondition: the stamp lies");

        let honest = Entity::new("test/honest", make_data("honest")).unwrap();
        let honest_hash = honest.content_hash;

        let mut env = Envelope::new(root);
        env.include(mis_stamped);
        env.include(honest);

        assert!(
            env.included.contains_key(&true_hash) && !env.included.contains_key(&stamped),
            "row 1: the entry is filed under the hash of its CONTENT, not under \
             the hash it claims — a sender that keys by the field emits a map \
             every conformant receiver refuses"
        );
        for (key, entity) in env.included.iter() {
            let recomputed =
                Hash::compute_format(&entity.entity_type, &entity.data, key.format_code()).unwrap();
            assert_eq!(
                *key, recomputed,
                "row 2: the map is content-addressed — every key is the hash of \
                 its value, which is the property §3.1 obliges and the one a \
                 receiver checks"
            );
        }
        assert!(
            env.included.contains_key(&honest_hash),
            "row 3 CONTROL: an honestly-built entity is UNMOVED — it lands under \
             its own hash. This fails if the recomputation uses the process \
             default format instead of the hash's own, which would silently \
             re-address every entity on a non-floor connection."
        );
    }

    #[test]
    fn test_envelope_find_signature_for() {
        let root = Entity::new("test/root", make_data("root")).unwrap();
        let target_hash = root.content_hash;

        // Build a signature entity whose data has a "target" field = target_hash bytes
        let sig_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("target"),
                entity_ecf::Value::Bytes(target_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("signer"),
                entity_ecf::Value::Bytes(Hash::zero().to_bytes().to_vec()),
            ),
        ]));
        let sig_entity = Entity::new(TYPE_SIGNATURE, sig_data).unwrap();
        let mut env = Envelope::new(root);
        env.include(sig_entity);

        let found = env.find_signature_for(&target_hash);
        assert!(found.is_some());
        assert_eq!(found.unwrap().entity_type, TYPE_SIGNATURE);
    }

    #[test]
    fn test_envelope_find_signature_for_no_match() {
        let root = Entity::new("test/root", make_data("root")).unwrap();
        let env = Envelope::new(root);
        assert!(env.find_signature_for(&Hash::zero()).is_none());
    }

    // --- URI tests ---

    #[test]
    fn test_uri_parse_full() {
        let uri = EntityUri::parse("entity://abc123/system/tree").unwrap();
        assert_eq!(uri.peer_id, "abc123");
        assert_eq!(uri.path, "system/tree");
    }

    #[test]
    fn test_uri_parse_no_path() {
        let uri = EntityUri::parse("entity://abc123").unwrap();
        assert_eq!(uri.peer_id, "abc123");
        assert_eq!(uri.path, "");
    }

    #[test]
    fn test_uri_parse_invalid_scheme() {
        assert!(EntityUri::parse("http://abc123/path").is_err());
    }

    #[test]
    fn test_uri_display_roundtrip() {
        let uri = EntityUri::parse("entity://abc123/system/tree").unwrap();
        assert_eq!(uri.to_string(), "entity://abc123/system/tree");
    }

    #[test]
    fn test_uri_display_no_path() {
        let uri = EntityUri::parse("entity://abc123").unwrap();
        assert_eq!(uri.to_string(), "entity://abc123");
    }

    #[test]
    fn test_normalize_path_full_uri() {
        assert_eq!(
            EntityUri::normalize_path("entity://abc123/system/tree"),
            "system/tree"
        );
    }

    #[test]
    fn test_normalize_path_bare() {
        assert_eq!(EntityUri::normalize_path("system/tree"), "system/tree");
    }

    #[test]
    fn test_extract_handler_path() {
        assert_eq!(
            EntityUri::extract_handler_path("entity://alice/system/tree"),
            "system/tree"
        );
        assert_eq!(
            EntityUri::extract_handler_path("system/tree"),
            "system/tree"
        );
    }

    // --- is_peer_id tests ---

    #[test]
    fn test_is_peer_id_valid() {
        // A real Base58 46-char peer ID
        let peer_id = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        assert!(EntityUri::is_peer_id(peer_id.as_str()));
    }

    #[test]
    fn test_is_peer_id_invalid() {
        assert!(!EntityUri::is_peer_id("system"));
        assert!(!EntityUri::is_peer_id("short"));
        assert!(!EntityUri::is_peer_id("")); // too short
                                             // 46 chars with invalid Base58 char (0, O, I, l)
        assert!(!EntityUri::is_peer_id(
            "0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));
    }

    // --- qualify_path tests ---

    #[test]
    fn test_qualify_path_bare() {
        let pid = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        let result = EntityUri::qualify_path("system/tree", pid.as_str());
        assert_eq!(result, format!("/{}/system/tree", pid));
    }

    #[test]
    fn test_qualify_path_already_absolute() {
        let pid = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        let absolute = format!("/{}/system/tree", pid);
        let result = EntityUri::qualify_path(&absolute, pid.as_str());
        assert_eq!(result, absolute, "idempotent");
    }

    #[test]
    fn test_qualify_path_legacy_qualified() {
        // Legacy format without leading / — defense-in-depth upgrades it
        let pid = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        let legacy = format!("{}/system/tree", pid);
        let result = EntityUri::qualify_path(&legacy, pid.as_str());
        assert_eq!(result, format!("/{}/system/tree", pid));
    }

    #[test]
    fn test_qualify_path_entity_uri() {
        let pid = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        let uri = format!("entity://{}/system/tree", pid);
        let result = EntityUri::qualify_path(&uri, "other_peer_id_that_is_46chars_long12345678901");
        assert_eq!(result, format!("/{}/system/tree", pid));
    }

    #[test]
    fn test_qualify_path_bare_peer_id_only() {
        let pid = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        let result = EntityUri::qualify_path(pid.as_str(), pid.as_str());
        assert_eq!(result, format!("/{}", pid), "bare peer_id becomes absolute");
    }

    /// §5.2 `extract_peer` — the `target_peer` the `peers` dimension tests.
    ///
    /// The `entity://` case is the one with teeth: routing this through
    /// `normalize_path`/`extract_handler_path` (which *strip* the authority)
    /// reads every foreign `entity://` URI as local, which is precisely the
    /// privilege escalation the peers dimension exists to stop. That mistake
    /// turns the `entity_scheme_authority_is_the_target_peer` case red while
    /// leaving the absolute-path case green — so both forms are asserted here.
    #[test]
    fn extract_peer_reads_the_uri_authority_not_the_local_peer() {
        let local = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        let foreign = entity_crypto::Keypair::from_seed([7u8; 32]).peer_id();
        assert_ne!(local.as_str(), foreign.as_str());

        // entity:// form — authority is the first segment after the scheme.
        assert_eq!(
            EntityUri::extract_peer(&format!("entity://{}/system/tree", foreign), local.as_str()),
            foreign.to_string(),
            "entity:// authority is the target peer"
        );
        // absolute-path form.
        assert_eq!(
            EntityUri::extract_peer(&format!("/{}/system/tree", foreign), local.as_str()),
            foreign.to_string(),
            "leading peer segment is the target peer"
        );
        // Bare peer-id with no trailing path.
        assert_eq!(
            EntityUri::extract_peer(&format!("/{}", foreign), local.as_str()),
            foreign.to_string(),
            "a bare peer-id is still a target peer"
        );

        // Short forms and non-peer-prefixed absolutes belong to the local peer.
        for local_form in ["system/tree", "/system/tree", ""] {
            assert_eq!(
                EntityUri::extract_peer(local_form, local.as_str()),
                local.to_string(),
                "{local_form:?} has no authority, so it is local"
            );
        }
        assert_eq!(
            EntityUri::extract_peer(&format!("entity://{}/system/tree", local), local.as_str()),
            local.to_string(),
            "self-addressed entity:// is local"
        );
    }

    #[test]
    fn test_qualify_path_bare_wildcard() {
        let pid = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        let result = EntityUri::qualify_path("*", pid.as_str());
        assert_eq!(result, format!("/{}/*", pid));
    }

    #[test]
    fn test_qualify_path_absolute_peer_wildcard() {
        let pid = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        let result = EntityUri::qualify_path("/*/system/tree", pid.as_str());
        assert_eq!(
            result, "/*/system/tree",
            "absolute peer wildcard passes through"
        );
    }

    /// `qualify_path` is TOTAL (§5.4, 0.8.2.20): the three reserved shapes
    /// yield `NEVER_MATCH`, and `validate_absolute_path` then refuses it, so the
    /// dispatch sites' existing post-qualify check answers the caller
    /// `400 invalid_path`.
    ///
    /// ⛔ **These three rows asserted `#[should_panic]`, and the `*/` one was
    /// reachable from the wire.** `validate_path_input` — the pre-qualify guard
    /// both dispatch sites in `connection.rs` run — rejects `./` and `../` and
    /// does **not** reject `*/`, so an inbound EXECUTE carrying
    /// `resource: {targets: ["*/anything"]}` reached `qualify_path` and
    /// panicked, from any authenticated peer and *before* `check_permission`.
    /// The `should_panic` attribute is what made that read as intentional.
    #[test]
    fn qualify_path_is_total_over_the_three_reserved_shapes() {
        let pid = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        for reserved in ["*/system/tree", "./relative", "../parent"] {
            let got = EntityUri::qualify_path(reserved, pid.as_str());
            assert_eq!(
                got, NEVER_MATCH,
                "{reserved} must canonicalize to NEVER_MATCH"
            );
            // The sentinel's own contract: it is refused by the post-qualify
            // validator, which is where the diagnostic the matcher cannot raise
            // is delivered to the caller.
            assert!(
                EntityUri::validate_absolute_path(&got).is_err(),
                "NEVER_MATCH must fail validate_absolute_path"
            );
        }
    }

    /// CONTROL for the row above: an ordinary peer-relative path is still
    /// qualified and still validates. Without this, replacing the whole function
    /// body with `NEVER_MATCH` would pass.
    #[test]
    fn qualify_path_still_qualifies_an_ordinary_relative_path() {
        let pid = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        let got = EntityUri::qualify_path("system/tree", pid.as_str());
        assert_eq!(got, format!("/{}/system/tree", pid.as_str()));
        assert!(EntityUri::validate_absolute_path(&got).is_ok());
    }

    // --- strip_peer_prefix tests ---

    #[test]
    fn test_strip_peer_prefix_absolute() {
        let pid = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        let absolute = format!("/{}/system/tree", pid);
        assert_eq!(EntityUri::strip_peer_prefix(&absolute), "system/tree");
    }

    #[test]
    fn test_strip_peer_prefix_legacy_qualified() {
        let pid = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        let legacy = format!("{}/system/tree", pid);
        assert_eq!(EntityUri::strip_peer_prefix(&legacy), "system/tree");
    }

    #[test]
    fn test_strip_peer_prefix_bare() {
        assert_eq!(EntityUri::strip_peer_prefix("system/tree"), "system/tree");
    }

    // --- clean_path tests ---

    #[test]
    fn test_clean_path_collapse_double_slash() {
        assert_eq!(
            EntityUri::clean_path("/peer//system/tree"),
            "/peer/system/tree"
        );
    }

    #[test]
    fn test_clean_path_preserve_leading_slash() {
        assert_eq!(
            EntityUri::clean_path("/peer/system/tree"),
            "/peer/system/tree"
        );
    }

    #[test]
    fn test_clean_path_preserves_trailing_slash() {
        // Trailing slash is data for tree prefix operations.
        assert_eq!(EntityUri::clean_path("/peer/path/"), "/peer/path/");
    }

    #[test]
    fn test_clean_path_root_only() {
        assert_eq!(EntityUri::clean_path("/"), "/");
    }

    #[test]
    fn test_clean_path_entity_scheme() {
        assert_eq!(
            EntityUri::clean_path("entity://peer//path"),
            "entity://peer/path"
        );
    }

    #[test]
    fn test_clean_path_bare_path() {
        assert_eq!(EntityUri::clean_path("system/tree"), "system/tree");
    }

    /// ⛔ **This row asserted `#[should_panic(expected = "reserved")]`, and the
    /// attribute is what kept anybody from re-asking whether a caller could
    /// reach it** — the identical construction that hid the wire-reachable
    /// `qualify_path` panic one revision ago. §5.4 (0.8.2.21) states the rule
    /// as a property of the boundary: a path helper MUST NOT assert on a
    /// malformed path. The refusal moved to the boundaries that have a caller
    /// to answer; `clean_path` is total.
    ///
    /// Both reserved prefixes and the `entity://`-wrapped forms, because
    /// `clean_path` recurses through the scheme arm and the recursion is where
    /// the old assert was actually reachable: `clean_path("entity://./x")`
    /// panicked while `qualify_path("entity://./x")` did not.
    #[test]
    fn clean_path_is_total_on_the_reserved_prefixes() {
        for input in ["./relative", "../escape", ".", "..", "./"] {
            let cleaned = EntityUri::clean_path(input);
            assert_eq!(
                cleaned, input,
                "cleaning collapses slashes only; it does not resolve dot tokens"
            );
        }
        assert_eq!(
            EntityUri::clean_path("entity://./x"),
            "entity://./x",
            "the scheme arm recurses — it is where the assert was reachable"
        );
        // The disposition lives at the boundaries, and it is unchanged.
        assert!(EntityUri::validate_path_input("./relative").is_err());
        assert_eq!(EntityUri::qualify_path("./relative", "peer"), NEVER_MATCH);
        assert_eq!(EntityUri::qualify_path("../escape", "peer"), NEVER_MATCH);
    }

    #[test]
    fn test_clean_path_dot_segments_ok() {
        // Segments starting with . are fine — only ./ and ../ at start are reserved
        assert_eq!(
            EntityUri::clean_path("/peer/.hidden/config"),
            "/peer/.hidden/config"
        );
    }

    // --- is_absolute tests ---

    #[test]
    fn test_is_absolute() {
        assert!(EntityUri::is_absolute("/peer/system/tree"));
        assert!(EntityUri::is_absolute("/"));
        assert!(!EntityUri::is_absolute("system/tree"));
        assert!(!EntityUri::is_absolute(""));
    }

    // --- validate_path_input tests ---

    #[test]
    fn test_validate_path_input_ok() {
        assert!(EntityUri::validate_path_input("system/tree").is_ok());
        assert!(EntityUri::validate_path_input("/peer/system/tree").is_ok());
        assert!(EntityUri::validate_path_input("entity://peer/path").is_ok());
        assert!(EntityUri::validate_path_input(".hidden/config").is_ok()); // dot segment, not ./
    }

    #[test]
    fn test_validate_path_input_rejects_dot_slash() {
        assert!(EntityUri::validate_path_input("./relative").is_err());
        assert!(EntityUri::validate_path_input(".").is_err());
    }

    #[test]
    fn test_validate_path_input_rejects_dotdot_slash() {
        assert!(EntityUri::validate_path_input("../parent").is_err());
        assert!(EntityUri::validate_path_input("..").is_err());
    }

    #[test]
    fn test_validate_path_input_rejects_empty_segment() {
        assert!(EntityUri::validate_path_input("system//tree").is_err());
        assert!(EntityUri::validate_path_input("//peer/path").is_err());
    }

    // --- validate_absolute_path tests ---

    #[test]
    fn test_validate_absolute_path_ok() {
        let pid = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        let path = format!("/{}/system/tree", pid);
        assert!(EntityUri::validate_absolute_path(&path).is_ok());
    }

    #[test]
    fn test_validate_absolute_path_bare_peer() {
        let pid = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        let path = format!("/{}", pid);
        assert!(EntityUri::validate_absolute_path(&path).is_ok());
    }

    #[test]
    fn test_validate_absolute_path_not_absolute() {
        assert!(EntityUri::validate_absolute_path("system/tree").is_err());
    }

    #[test]
    fn test_validate_absolute_path_empty_segment() {
        let pid = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        let path = format!("/{}//system/tree", pid);
        assert!(EntityUri::validate_absolute_path(&path).is_err());
    }

    #[test]
    fn test_validate_absolute_path_invalid_peer_id() {
        assert!(EntityUri::validate_absolute_path("/notapeerid/system/tree").is_err());
    }

    #[test]
    fn test_validate_absolute_path_short_segment() {
        assert!(EntityUri::validate_absolute_path("/abc/system/tree").is_err());
    }

    // --- D9 (PROPOSAL-TRANSPORT-FAMILY-CHUNK-C-AMENDMENTS §2.10):
    //     validate_absolute_path stays STRICT — reserved-word recognition
    //     is a SEPARATE URL-layer helper. The strict rejection is
    //     load-bearing for the §6.4 collision-safety argument.

    #[test]
    fn test_validate_absolute_path_rejects_reserved_words() {
        // `content` and `manifest` are URL-layer reserved words for the
        // http-poll `{X}` slot, NOT valid entity-tree-path first segments.
        // The entity tree path validator MUST reject them.
        assert!(EntityUri::validate_absolute_path("/content").is_err());
        assert!(EntityUri::validate_absolute_path("/content/00aa").is_err());
        assert!(EntityUri::validate_absolute_path("/manifest").is_err());
        assert!(EntityUri::validate_absolute_path("/manifest/current").is_err());
    }

    #[test]
    fn test_validate_absolute_path_rejects_arbitrary_short_word() {
        assert!(EntityUri::validate_absolute_path("/system/tree").is_err());
        assert!(EntityUri::validate_absolute_path("/peers/foo").is_err());
    }

    #[test]
    fn test_is_reserved_path_word_helper_intact() {
        // The URL-layer helper is independent of validate_absolute_path;
        // recognizes the {X}-slot reserved words for http-poll URL
        // parsing. Decoupled per D9.
        assert!(EntityUri::is_reserved_path_word("content"));
        assert!(EntityUri::is_reserved_path_word("manifest"));
        assert!(!EntityUri::is_reserved_path_word("Content"));
        assert!(!EntityUri::is_reserved_path_word("manifests"));
        assert!(!EntityUri::is_reserved_path_word(""));
    }

    /// A safe value MUST pass through byte-identical — this is the property
    /// that makes sanitization unable to de-converge a seat or move any
    /// conformant coordinate.
    #[test]
    fn sanitize_path_segment_passes_safe_values_through() {
        for seg in [
            "chain-abc123",
            "req-1",
            "capability_denied",
            "network-maintain-e79c8bca6eec8a43",
            "internal",
            "a.b",
            "...",
            "..a",
            "sub-1",
            "0",
            "é-unicode-is-fine",
        ] {
            assert_eq!(
                sanitize_path_segment(seg, SENTINEL_UNSPECIFIED_CHAIN_ID),
                seg,
                "a safe value MUST pass through unchanged"
            );
        }
    }

    /// The hostile cases. `..` is the one Go's probe found live in our tree:
    /// it is not the LEADING `../` form `clean_path` rejects — it lands in
    /// the MIDDLE of the path, where a normalizer resolves it and walks the
    /// marker back OUT of the chain-errors subtree.
    #[test]
    fn sanitize_path_segment_contains_unsafe_values() {
        for seg in [
            "..",
            ".",
            "",
            "../../../../authority/keys",
            "a/b",
            "/",
            "with\0null",
            "with\nnewline",
            "with\x7fdel",
        ] {
            let got = sanitize_path_segment(seg, SENTINEL_UNSPECIFIED_CHAIN_ID);
            assert!(
                is_safe_path_segment(got),
                "sanitize_path_segment({:?}) = {:?}, still not a safe segment",
                seg,
                got
            );
            assert_eq!(
                got, SENTINEL_UNSPECIFIED_CHAIN_ID,
                "sanitize_path_segment({:?}) = {:?}, want the caller's sentinel",
                seg, got
            );
            // The property that actually matters: assert on the CLEANED
            // path, not the literal one. `sink/{X}/..` is inside the sink by
            // string prefix while naming somewhere else.
            let joined = format!("/peer1/system/runtime/chain-errors/rejected/{}", got);
            assert!(
                EntityUri::clean_path(&joined).starts_with("/peer1/system/runtime/chain-errors/"),
                "{:?} escaped the sink under cleaning",
                got
            );
        }
    }

    /// The invariant that decided arch round-2 ruling 1, and the reason the
    /// previous hashing rule was reversed: hostile input MUST NOT be able to
    /// mint path nodes.
    ///
    /// Hashing put every distinct hostile value on its own node, which
    /// re-opened the tree-pollution vector the injection fix had just closed —
    /// one layer up, bounded only by GC. Neither implementing seat found that
    /// argument; it is pinned here as an invariant rather than left as a
    /// comment, because it is the whole reason this function collapses.
    ///
    /// History: this test replaces `..._keeps_distinct_values_distinct`, which
    /// asserted the opposite. Distinctness was never at risk from collapsing —
    /// §3.10.1's terminal `{marker_hash}` segment already gives every
    /// occurrence its own path (distinct bodies → distinct hashes), so the
    /// property that test protected was being carried elsewhere all along.
    #[test]
    fn sanitize_path_segment_does_not_let_an_attacker_mint_nodes() {
        let nodes: std::collections::BTreeSet<&str> = (0..1000)
            .map(|i| {
                let hostile = format!("../../../../authority/keys/{i}");
                // The sanitizer is a pure function of (value, sentinel), so a
                // borrowed result would not outlive `hostile`. Collapse means
                // the result is the sentinel itself — a 'static constant —
                // which is exactly what this asserts.
                let got = sanitize_path_segment(&hostile, SENTINEL_UNSPECIFIED_CHAIN_ID);
                assert_eq!(got, SENTINEL_UNSPECIFIED_CHAIN_ID);
                SENTINEL_UNSPECIFIED_CHAIN_ID
            })
            .collect();
        assert_eq!(
            nodes.len(),
            1,
            "1000 distinct hostile values must collapse to exactly 1 quarantine node"
        );
    }

    /// One sentinel per coordinate: a quarantined marker still says WHICH
    /// coordinate was hostile, without putting the hostile value on the path.
    #[test]
    fn sanitize_path_segment_uses_the_callers_sentinel_per_coordinate() {
        assert_eq!(
            sanitize_path_segment("..", SENTINEL_UNSPECIFIED_CHAIN_ID),
            "unspecified_chain_id"
        );
        assert_eq!(
            sanitize_path_segment("..", SENTINEL_UNSPECIFIED_STEP_INDEX),
            "unspecified_step_index"
        );
        assert_eq!(
            sanitize_path_segment("..", SENTINEL_UNSPECIFIED_ERROR),
            "unspecified_error"
        );
        // Every sentinel must itself be a safe segment, or the quarantine
        // node is the next injection.
        for s in [
            SENTINEL_UNSPECIFIED_ERROR,
            SENTINEL_UNSPECIFIED_CHAIN_ID,
            SENTINEL_UNSPECIFIED_STEP_INDEX,
        ] {
            assert!(is_safe_path_segment(s), "sentinel {s:?} is not path-safe");
        }
    }

    /// **V7 §4.5a item 1a — `system/peer` is pinned to the ECFv1-SHA-256 floor,
    /// and the constructor refuses anything else.**
    ///
    /// The rule exists because a non-floor identity entity is *well-formed*: it
    /// simply carries a second `content_hash` for the one identity item 1a
    /// exists to collapse. §5.2's `grantee` / `granter` / `signer` equalities
    /// then compare two values that are wrong the same way, so nothing fails.
    /// That is why this is enforced at construction rather than checked at the
    /// comparison sites — there is no observable downstream to assert on.
    ///
    /// **Note what this test can and cannot stand in for.** It is a self-check
    /// by nature; so is go's cross-impl vector for the same rule, which its own
    /// harness labels `[self]` and which therefore only ever measures the seat
    /// running it. No wire probe can catch this class, at any seat. That is the
    /// argument for the constructor guard, not an argument that the guard is
    /// untested — the guard IS the enforcement point.
    #[test]
    fn system_peer_is_refused_at_any_format_but_the_floor() {
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("key_type"), entity_ecf::text("ed25519")),
            (
                entity_ecf::text("public_key"),
                entity_ecf::Value::Bytes(vec![7u8; 32]),
            ),
        ]));

        // The floor authors, unconditionally.
        let floor =
            Entity::new_with_format(TYPE_PEER, data.clone(), entity_hash::HASH_ALGORITHM_SHA256)
                .expect("the floor is the one legal format for an identity entity");
        assert_eq!(
            floor.content_hash.algorithm,
            entity_hash::HASH_ALGORITHM_SHA256
        );

        // Every other allocated format is refused — enumerated rather than
        // spot-checked at 0x01, so allocating a third format does not silently
        // open a hole this row would have caught at the second.
        for fmt in 0x01u8..=0x03 {
            let err = Entity::new_with_format(TYPE_PEER, data.clone(), fmt).unwrap_err();
            assert!(
                format!("{err}").contains("floor"),
                "format {fmt:#04x} must be refused by the item-1a guard, got: {err}"
            );
        }

        // **The control, and it is what says this is a type-scoped pin and not
        // a ban on non-floor authoring.** An ordinary content entity at
        // SHA-384 is legal (§1.2 home format, §4.5a item 2), so a guard written
        // as "refuse 0x01" rather than "refuse 0x01 FOR system/peer" reddens
        // here and nowhere else.
        Entity::new_with_format("app/thing", data, entity_hash::HASH_ALGORITHM_SHA384)
            .expect("a CONTENT entity may be authored at any supported format");
    }
}
