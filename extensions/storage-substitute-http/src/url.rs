//! Endpoint decoding + URL construction.
//!
//! Per STORAGE-SUBSTITUTE-HTTP proposal §3-RES.2 (two-prefix URL space +
//! pure-hash content layout). The endpoint config is the data shape
//! carried inside a `system/substitute/endpoint` entity (Ruling 1)
//! referenced by each substitute-source entry's
//! `data.endpoint` field.

use ciborium::Value;
use thiserror::Error;

use entity_entity::Entity;
use entity_hash::Hash;
use entity_storage_substitute_sources::TYPE_SUBSTITUTE_ENDPOINT;

/// Pure-hash content-layout enum (CDN proposal §3-RES.2).
///
/// All four variants describe how a content hash maps to a URL path
/// under [`EndpointConfig::content_url_prefix`]. Peer-namespacing is
/// orthogonal — it's a property of the `content_url_prefix` string
/// itself, not of this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentLayout {
    /// `{content_url_prefix}/{hash}`.
    Flat,
    /// `{content_url_prefix}/{hash[0:2]}/{hash}` — one shard level; hash
    /// flat inside (Round-6 item #2).
    Sharded2Flat,
    /// `{content_url_prefix}/{hash[0:2]}/{hash[2:4]}/{hash}` — two shard
    /// levels.
    Sharded2_4,
}

impl ContentLayout {
    /// Wire string for the enum (matches the values stored in entry
    /// endpoint payloads).
    pub fn as_str(self) -> &'static str {
        match self {
            ContentLayout::Flat => "flat",
            ContentLayout::Sharded2Flat => "sharded-2-flat",
            ContentLayout::Sharded2_4 => "sharded-2-4",
        }
    }

    /// Parse a layout string from an endpoint payload. Accepts
    /// `"sharded-2-2"` as an alias for `"sharded-2-4"` per the CDN
    /// proposal's §3-RES.2 note ("kept for naming clarity").
    pub fn parse(s: &str) -> Option<ContentLayout> {
        match s {
            "flat" => Some(ContentLayout::Flat),
            "sharded-2-flat" => Some(ContentLayout::Sharded2Flat),
            "sharded-2-4" | "sharded-2-2" => Some(ContentLayout::Sharded2_4),
            _ => None,
        }
    }
}

/// Decoded `http`-convention endpoint payload (the data of a
/// `system/substitute/endpoint` entity per Ruling 1, with the field
/// vocabulary defined by STORAGE-SUBSTITUTE-HTTP §3-RES.2).
#[derive(Debug, Clone)]
pub struct EndpointConfig {
    /// Tree-URL prefix (used by the manifest / path-resolution path).
    /// Optional on the bare-hash path; the v1 handler reads it but does
    /// not exercise it.
    pub tree_url_prefix: Option<String>,
    /// Content-URL prefix; required for bare-hash fetch.
    pub content_url_prefix: String,
    /// How the requested hash maps onto a path segment under
    /// `content_url_prefix`.
    pub content_layout: ContentLayout,
    /// Tree-leaf URL disambiguator (Round-6 item #1). Required to be
    /// present on the endpoint; default `".bin"`. v1 bare-hash fetch
    /// does not use this; manifest path (v1.1) will.
    pub tree_leaf_suffix: String,
}

/// Errors decoding an endpoint payload.
#[derive(Debug, Error)]
pub enum EndpointDecodeError {
    /// Endpoint payload missing entirely (entry had no `endpoint` field).
    #[error("substitute entry is missing endpoint payload")]
    MissingEndpoint,
    /// Endpoint payload was not a CBOR map.
    #[error("endpoint payload is not a CBOR map")]
    NotAMap,
    /// A required endpoint field was absent.
    #[error("endpoint missing required field {0}")]
    MissingField(&'static str),
    /// A required endpoint field had the wrong CBOR shape.
    #[error("endpoint field {field} has wrong shape: {detail}")]
    BadFieldShape {
        /// The field name.
        field: &'static str,
        /// Diagnostic detail.
        detail: String,
    },
    /// `content_layout` enum value not recognized.
    #[error("unknown content_layout enum value: {0}")]
    UnknownContentLayout(String),
}

impl EndpointConfig {
    /// Decode an endpoint config from the CBOR `data` map of a
    /// `system/substitute/endpoint` entity (post-Ruling-1).
    ///
    /// Shared between [`Self::decode_entity`] and the legacy inline-map
    /// fallback in [`Self::decode_endpoint_field`].
    ///
    /// **`content_url_prefix` is REQUIRED and there is NO derivation
    /// default** — §2.2, *pinned ruling*, whose last sentence is
    /// "an impl that treats it as optional-with-derivation is
    /// non-conformant." An absent `content_url_prefix` is
    /// `MissingField`, whether or not a `tree_url_prefix` is present to
    /// derive from.
    ///
    /// **This replaces D-14** (§6.4, the workbench-go review), which asked
    /// for `content_url_prefix = {tree_url_prefix}/content` when absent —
    /// the single-peer default S1/S2/S3/S6. We implemented D-14 and the
    /// ruling later superseded it; the ruling's argument is deployment
    /// scenario **S4** (tree per-peer, content dedup'd to a shared bucket),
    /// where deriving sends the fetch to an origin the publisher never
    /// committed to. That either 404s or — worse — exists and serves some
    /// other peer's bytes. A proposal carries rationale; the spec carries
    /// the rule.
    ///
    /// The refusal is deliberately ahead of every check that *interprets*
    /// the prefix, including the §7 https floor: a derived prefix that then
    /// fails the scheme check reports the wrong defect and hides this one.
    fn decode_data_map(map: &[(Value, Value)]) -> Result<EndpointConfig, EndpointDecodeError> {
        let content_layout_str = field_text(map, "content_layout")
            .ok_or(EndpointDecodeError::MissingField("content_layout"))?;
        let content_layout = ContentLayout::parse(&content_layout_str).ok_or(
            EndpointDecodeError::UnknownContentLayout(content_layout_str),
        )?;
        let tree_url_prefix = field_text(map, "tree_url_prefix");
        let tree_leaf_suffix = field_text(map, "tree_leaf_suffix").unwrap_or_else(default_suffix);

        // Absent AND empty are the same fact — "the publisher stated no
        // content commitment". go's `TransportEndpoint.ContentURLPrefix`
        // carries no `omitempty`, so an endpoint that simply does not set it
        // arrives here as `Some("")`, not `None`; refusing only `None` leaves
        // the empty string to fall through to the scheme check and answer
        // 403 https_required, which reports the wrong defect and hides this
        // one. core-go guards the same way (`contentPrefix == ""` → 400,
        // ahead of its https gate).
        let content_url_prefix = field_text(map, "content_url_prefix")
            .filter(|s| !s.is_empty())
            .ok_or(EndpointDecodeError::MissingField("content_url_prefix"))?;

        Ok(EndpointConfig {
            tree_url_prefix,
            content_url_prefix,
            content_layout,
            tree_leaf_suffix,
        })
    }

    /// Decode a full `system/substitute/endpoint` entity (Ruling 1).
    pub fn decode_entity(entity: &Entity) -> Result<EndpointConfig, EndpointDecodeError> {
        if entity.entity_type != TYPE_SUBSTITUTE_ENDPOINT {
            return Err(EndpointDecodeError::BadFieldShape {
                field: "<entity_type>",
                detail: format!(
                    "expected {}, got {}",
                    TYPE_SUBSTITUTE_ENDPOINT, entity.entity_type
                ),
            });
        }
        let value: Value = ciborium::from_reader(entity.data.as_slice()).map_err(|e| {
            EndpointDecodeError::BadFieldShape {
                field: "<data>",
                detail: format!("cbor decode: {}", e),
            }
        })?;
        let map = match value {
            Value::Map(m) => m,
            _ => return Err(EndpointDecodeError::NotAMap),
        };
        Self::decode_data_map(&map)
    }

    /// Decode the endpoint config from a substitute-source entry's
    /// `data.endpoint` field value.
    ///
    /// Rust v1.0 accepts two shapes (Ruling 1 pinned the type name; the
    /// source-side encoding shape is cross-impl-flexible until
    /// validate-peer category authoring converges):
    ///
    /// - `Value::Bytes(bytes)` where `bytes = encode_entity(endpoint)` —
    ///   the byte-fidelity-preserving shape (preferred).
    /// - `Value::Map(...)` — the endpoint's data map inline (legacy v0
    ///   compatibility; deprecated shape).
    pub fn decode_endpoint_field(
        endpoint: Option<&Value>,
    ) -> Result<EndpointConfig, EndpointDecodeError> {
        let value = endpoint.ok_or(EndpointDecodeError::MissingEndpoint)?;
        match value {
            Value::Bytes(bytes) => {
                let entity = entity_wire::decode_entity(bytes.as_slice()).map_err(|e| {
                    EndpointDecodeError::BadFieldShape {
                        field: "endpoint",
                        detail: format!("decode_entity: {}", e),
                    }
                })?;
                Self::decode_entity(&entity)
            }
            Value::Map(map) => Self::decode_data_map(map),
            _ => Err(EndpointDecodeError::BadFieldShape {
                field: "endpoint",
                detail: "expected CBOR bytes (wire-encoded endpoint entity) or map (legacy inline shape)".to_string(),
            }),
        }
    }
}

/// Errors building a content URL from a config + hash.
#[derive(Debug, Error)]
pub enum UrlBuildError {
    /// CDN proposal defense-in-depth (§3-RES.3): convention SHOULD
    /// reject non-`https` URLs at consumption time, even if the cap
    /// would permit them. v1 enforces this on every fetched URL.
    #[error("non-https scheme on content URL prefix is not allowed: {0}")]
    NonHttpsScheme(String),
}

/// Build the content URL for a hash under the given endpoint.
///
/// Pure function: no I/O, no allocation other than the URL string.
/// Used by the handler module + cross-impl URL-construction TVs
/// (TV-CDN-CORE-1..3).
pub fn build_content_url(config: &EndpointConfig, hash: &Hash) -> Result<String, UrlBuildError> {
    if !config.content_url_prefix.starts_with("https://") {
        return Err(UrlBuildError::NonHttpsScheme(
            config.content_url_prefix.clone(),
        ));
    }
    let hex = hash_hex(hash);
    let url = match config.content_layout {
        ContentLayout::Flat => format!("{}/{}", trim(&config.content_url_prefix), hex),
        ContentLayout::Sharded2Flat => {
            format!("{}/{}/{}", trim(&config.content_url_prefix), &hex[..2], hex)
        }
        ContentLayout::Sharded2_4 => {
            format!(
                "{}/{}/{}/{}",
                trim(&config.content_url_prefix),
                &hex[..2],
                &hex[2..4],
                hex
            )
        }
    };
    Ok(url)
}

fn trim(s: &str) -> &str {
    s.trim_end_matches('/')
}

fn hash_hex(hash: &Hash) -> String {
    let bytes = hash.to_bytes();
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in &bytes {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

fn field_text(map: &[(Value, Value)], key: &str) -> Option<String> {
    map.iter().find_map(|(k, v)| match (k, v) {
        (Value::Text(t), Value::Text(s)) if t == key => Some(s.clone()),
        _ => None,
    })
}

fn default_suffix() -> String {
    ".bin".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_hash() -> Hash {
        // Build a 33-byte hash with predictable hex
        // (0x00 algorithm byte + 32-byte digest).
        let mut digest = [0u8; 32];
        for (i, slot) in digest.iter_mut().enumerate() {
            *slot = i as u8;
        }
        Hash::new(0, digest)
    }

    #[test]
    fn flat_layout_url() {
        let cfg = EndpointConfig {
            tree_url_prefix: None,
            content_url_prefix: "https://cdn.example.com/content".to_string(),
            content_layout: ContentLayout::Flat,
            tree_leaf_suffix: ".bin".to_string(),
        };
        let url = build_content_url(&cfg, &fake_hash()).unwrap();
        // The wire hex begins with "00" (the algorithm byte).
        assert!(url.starts_with("https://cdn.example.com/content/00"));
        assert_eq!(url.len(), "https://cdn.example.com/content/".len() + 66);
    }

    #[test]
    fn sharded_2_flat_url() {
        let cfg = EndpointConfig {
            tree_url_prefix: None,
            content_url_prefix: "https://cdn.example.com/content".to_string(),
            content_layout: ContentLayout::Sharded2Flat,
            tree_leaf_suffix: ".bin".to_string(),
        };
        let url = build_content_url(&cfg, &fake_hash()).unwrap();
        // hex[0..2] is "00" (algorithm byte) per the fake hash.
        assert!(url.starts_with("https://cdn.example.com/content/00/00"));
    }

    #[test]
    fn sharded_2_4_url() {
        let cfg = EndpointConfig {
            tree_url_prefix: None,
            content_url_prefix: "https://cdn.example.com/content".to_string(),
            content_layout: ContentLayout::Sharded2_4,
            tree_leaf_suffix: ".bin".to_string(),
        };
        let url = build_content_url(&cfg, &fake_hash()).unwrap();
        // hex[0..2]="00", hex[2..4]="00" (first two digest bytes are 0,1
        // → hex "0001", so hex[2..4] is "01"). Wait — algorithm byte is
        // 0x00 → hex[0..2]="00"; first digest byte 0x00 → hex[2..4]="00";
        // second digest byte 0x01 is at hex[4..6]="01".
        assert!(url.starts_with("https://cdn.example.com/content/00/00/00"));
    }

    /// EXTENSION-NETWORK §6.5.3 hex-strictness at the substitute-CDN builder.
    ///
    /// Exercised at TWO formats, because a hardcoded 66 passes the SHA-256 row
    /// and fails the SHA-384 one — the flat-layout test above pins 66 as a
    /// literal, so on its own it cannot tell a byte-implied width from a
    /// constant. `[0:2]` of the hex is the **format-code byte = the algorithm
    /// partition** the sharded layouts key on; under a digest-only hex the shard
    /// silently slices the first DIGEST byte instead and that property dies,
    /// which is what this asserts rather than a `to_hex` round-trip.
    #[test]
    fn content_url_hex_width_follows_the_format_byte_at_every_layout() {
        for (code, digest_len) in [
            (entity_hash::HASH_ALGORITHM_SHA256, 32usize),
            (entity_hash::HASH_ALGORITHM_SHA384, 48usize),
        ] {
            let h = Hash::new(code, vec![0xABu8; digest_len]);
            let lead = format!("{:02x}", code);
            let base = "https://cdn.example.com/content";

            for (layout, expected_prefix) in [
                (ContentLayout::Flat, format!("{base}/{lead}")),
                (ContentLayout::Sharded2Flat, format!("{base}/{lead}/{lead}")),
                // `sharded-2-4` is `{prefix}/{hex[0:2]}/{hex[2:4]}/{hex}` —
                // the first segment is the FORMAT-CODE byte (the algorithm
                // partition), the second the first digest byte.
                (
                    ContentLayout::Sharded2_4,
                    format!("{base}/{lead}/ab/{lead}"),
                ),
            ] {
                let cfg = EndpointConfig {
                    tree_url_prefix: None,
                    content_url_prefix: base.to_string(),
                    content_layout: layout,
                    tree_leaf_suffix: ".bin".to_string(),
                };
                let url = build_content_url(&cfg, &h).unwrap();
                assert!(
                    url.starts_with(&expected_prefix),
                    "format {:#04x}: expected {} to start with {}",
                    code,
                    url,
                    expected_prefix
                );
                let hex = url.rsplit('/').next().unwrap();
                assert_eq!(
                    hex.len(),
                    2 + digest_len * 2,
                    "format {:#04x} implies {} hex chars, never a constant",
                    code,
                    2 + digest_len * 2
                );
            }
        }
    }

    #[test]
    fn sharded_2_2_aliases_sharded_2_4() {
        assert_eq!(
            ContentLayout::parse("sharded-2-2"),
            Some(ContentLayout::Sharded2_4)
        );
    }

    #[test]
    fn non_https_rejected() {
        let cfg = EndpointConfig {
            tree_url_prefix: None,
            content_url_prefix: "http://cdn.example.com/content".to_string(),
            content_layout: ContentLayout::Flat,
            tree_leaf_suffix: ".bin".to_string(),
        };
        match build_content_url(&cfg, &fake_hash()) {
            Err(UrlBuildError::NonHttpsScheme(_)) => {}
            other => panic!("expected NonHttpsScheme, got {:?}", other),
        }
    }

    #[test]
    fn endpoint_decode_round_trip() {
        let cbor = Value::Map(vec![
            (
                Value::Text("tree_url_prefix".to_string()),
                Value::Text("https://cdn.example.com/peer".to_string()),
            ),
            (
                Value::Text("content_url_prefix".to_string()),
                Value::Text("https://cdn.example.com/content".to_string()),
            ),
            (
                Value::Text("content_layout".to_string()),
                Value::Text("sharded-2-flat".to_string()),
            ),
            (
                Value::Text("tree_leaf_suffix".to_string()),
                Value::Text(".ent".to_string()),
            ),
        ]);
        let cfg = EndpointConfig::decode_endpoint_field(Some(&cbor)).unwrap();
        assert_eq!(
            cfg.tree_url_prefix.as_deref(),
            Some("https://cdn.example.com/peer")
        );
        assert_eq!(cfg.content_url_prefix, "https://cdn.example.com/content");
        assert_eq!(cfg.content_layout, ContentLayout::Sharded2Flat);
        assert_eq!(cfg.tree_leaf_suffix, ".ent");
    }

    #[test]
    fn endpoint_decode_bstr_wrapped_entity() {
        // The preferred shape (Ruling 1): source.data.endpoint is a CBOR
        // bstr containing encode_entity(endpoint_entity) bytes.
        let data_map = Value::Map(vec![
            (
                Value::Text("content_url_prefix".to_string()),
                Value::Text("https://cdn.example.com/content".to_string()),
            ),
            (
                Value::Text("content_layout".to_string()),
                Value::Text("flat".to_string()),
            ),
            (
                Value::Text("tree_leaf_suffix".to_string()),
                Value::Text(".ent".to_string()),
            ),
        ]);
        let mut data_bytes = Vec::new();
        ciborium::into_writer(&data_map, &mut data_bytes).unwrap();
        let endpoint_entity = Entity::new(TYPE_SUBSTITUTE_ENDPOINT, data_bytes).unwrap();
        let endpoint_bytes = entity_wire::encode_entity(&endpoint_entity);
        let endpoint_field = Value::Bytes(endpoint_bytes);

        let cfg = EndpointConfig::decode_endpoint_field(Some(&endpoint_field)).unwrap();
        assert_eq!(cfg.content_url_prefix, "https://cdn.example.com/content");
        assert_eq!(cfg.content_layout, ContentLayout::Flat);
        assert_eq!(cfg.tree_leaf_suffix, ".ent");
    }

    #[test]
    fn a_tree_prefix_alone_does_not_derive_a_content_prefix() {
        // §2.2 pinned ruling: `content_url_prefix` is REQUIRED and there is
        // NO derivation default — "an impl that treats it as
        // optional-with-derivation is non-conformant." This test replaces
        // two that asserted D-14's derivation (`{tree}/content`, with
        // trailing-slash trimming); D-14 was superseded, and the derivation
        // is the S4 defect the ruling exists to remove.
        //
        // **The rewritten expectation is not the evidence.** A test edited in
        // the same commit as the behaviour witnesses nothing; the independent
        // witness is core-go's `substitute` category check
        // `content_url_prefix_required_no_derivation`, which scored this seat
        // FAIL (403/"https_required", want 400) before the fix and PASS after.
        //
        // Both rows matter: the plain prefix is the one D-14 derived from,
        // and the trailing-slash form is the one whose trimming used to be a
        // separate test — under derivation each produced a URL, so a row that
        // only asserted "some prefix came back" could not tell the readings
        // apart.
        // The third row is the one the wire actually sends and the one the
        // first pass at this fix missed: go's `TransportEndpoint` has no
        // `omitempty` on `content_url_prefix`, so "unset" reaches us as
        // `Some("")`. Refusing only the absent key left the empty string
        // falling through to the §7 scheme gate — 403 https_required, the
        // wrong defect, and the cross-impl check stayed red through a fix
        // that looked complete in-tree. Absent and empty are one fact.
        for (label, prefix_entry) in [
            ("absent", None),
            ("empty", Some(String::new())),
            ("empty-with-slash-tree", Some(String::new())),
        ] {
            let tree = if label == "empty-with-slash-tree" {
                "https://shared.example.com/peers/peerA/"
            } else {
                "https://my-domain.example"
            };
            let mut fields = vec![
                (
                    Value::Text("tree_url_prefix".to_string()),
                    Value::Text(tree.to_string()),
                ),
                (
                    Value::Text("content_layout".to_string()),
                    Value::Text("flat".to_string()),
                ),
            ];
            if let Some(p) = prefix_entry {
                fields.push((
                    Value::Text("content_url_prefix".to_string()),
                    Value::Text(p),
                ));
            }
            let cbor = Value::Map(fields);
            match EndpointConfig::decode_endpoint_field(Some(&cbor)) {
                Err(EndpointDecodeError::MissingField("content_url_prefix")) => {}
                other => panic!("{label}: must be MissingField(content_url_prefix), got {other:?}"),
            }
        }
    }

    #[test]
    fn endpoint_decode_explicit_content_prefix_wins_over_derivation() {
        // Multi-peer-shared-domain dedup (S4): explicit content_url_prefix
        // is preserved verbatim even when tree_url_prefix is also present.
        let cbor = Value::Map(vec![
            (
                Value::Text("tree_url_prefix".to_string()),
                Value::Text("https://shared.example.com/peers/peerA".to_string()),
            ),
            (
                Value::Text("content_url_prefix".to_string()),
                Value::Text("https://shared.example.com/content".to_string()),
            ),
            (
                Value::Text("content_layout".to_string()),
                Value::Text("flat".to_string()),
            ),
        ]);
        let cfg = EndpointConfig::decode_endpoint_field(Some(&cbor)).unwrap();
        assert_eq!(cfg.content_url_prefix, "https://shared.example.com/content");
    }

    #[test]
    fn endpoint_decode_both_prefixes_absent_errors() {
        // Nothing to derive from → MissingField.
        let cbor = Value::Map(vec![(
            Value::Text("content_layout".to_string()),
            Value::Text("flat".to_string()),
        )]);
        match EndpointConfig::decode_endpoint_field(Some(&cbor)) {
            Err(EndpointDecodeError::MissingField("content_url_prefix")) => {}
            other => panic!("expected MissingField(content_url_prefix), got {:?}", other),
        }
    }

    #[test]
    fn endpoint_decode_default_suffix() {
        let cbor = Value::Map(vec![
            (
                Value::Text("content_url_prefix".to_string()),
                Value::Text("https://cdn.example.com/content".to_string()),
            ),
            (
                Value::Text("content_layout".to_string()),
                Value::Text("flat".to_string()),
            ),
        ]);
        let cfg = EndpointConfig::decode_endpoint_field(Some(&cbor)).unwrap();
        assert_eq!(cfg.tree_leaf_suffix, ".bin");
    }
}
