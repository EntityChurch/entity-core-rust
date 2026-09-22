//! Length-prefixed framing and envelope codec.
//!
//! Wire format per Entity Core Protocol v7.9 §1.6, §3.1:
//! - Frame: 4-byte big-endian length prefix + CBOR payload
//! - Envelope: `{root: Entity, included: Map<Hash, Entity>}`
//! - Only two message types: EXECUTE and EXECUTE_RESPONSE

use std::collections::BTreeMap;

use entity_entity::{Entity, Envelope};
use entity_hash::Hash;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Default maximum frame size: 16 MiB (spec recommendation).
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Framing (§1.6)
// ---------------------------------------------------------------------------

/// Write a length-prefixed frame.
#[tracing::instrument(level = "debug", skip_all, fields(bytes = payload.len()))]
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> Result<(), WireError> {
    let len = payload.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Read a length-prefixed frame.
///
/// Returns the payload bytes. Enforces `max_frame_size` to bound memory allocation.
///
/// # A clean EOF and a truncated frame are different facts (§4.11, 0.8.2.25)
///
/// `read_exact` reports both as [`std::io::ErrorKind::UnexpectedEof`], and the
/// caller cannot tell them apart afterwards — the phase is only knowable here.
/// §4.11 gives them **opposite dispositions**: EOF at a frame boundary is an
/// ordinary disconnect and owes nothing, while a frame that started and did not
/// finish is a pre-admission refusal owing a coded `400 invalid_request`. So the
/// prefix is read a byte at a time up to the first one rather than with
/// `read_exact`: reading **zero** bytes is the boundary, reading one to three is
/// a truncated prefix. Everything past that point is
/// [`WireError::TruncatedFrame`].
#[tracing::instrument(level = "debug", skip_all, fields(bytes = tracing::field::Empty))]
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_frame_size: u32,
) -> Result<Vec<u8>, WireError> {
    let mut len_buf = [0u8; 4];
    let mut got = 0usize;
    while got < 4 {
        // `read` rather than `read_exact`: a 0 return is EOF, and at got == 0
        // that is the clean frame boundary the caller must NOT answer.
        let n = reader.read(&mut len_buf[got..]).await?;
        if n == 0 {
            if got == 0 {
                return Err(WireError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "clean EOF at frame boundary",
                )));
            }
            return Err(WireError::TruncatedFrame {
                phase: "length prefix",
                read: got,
                expected: 4,
            });
        }
        got += n;
    }
    let len = u32::from_be_bytes(len_buf);
    if len > max_frame_size {
        return Err(WireError::FrameTooLarge {
            size: len,
            max: max_frame_size,
        });
    }
    let mut payload = vec![0u8; len as usize];
    let mut filled = 0usize;
    while filled < payload.len() {
        let n = reader.read(&mut payload[filled..]).await?;
        if n == 0 {
            return Err(WireError::TruncatedFrame {
                phase: "payload",
                read: filled,
                expected: payload.len(),
            });
        }
        filled += n;
    }
    tracing::Span::current().record("bytes", len);
    Ok(payload)
}

// ---------------------------------------------------------------------------
// Entity codec
// ---------------------------------------------------------------------------

/// Encode an entity to CBOR bytes: `{type, data, content_hash}`.
///
/// The `data` field is embedded as raw CBOR bytes (not re-encoded)
/// to preserve byte fidelity for hash verification.
pub fn encode_entity(entity: &Entity) -> Vec<u8> {
    // Build manually to embed data as raw CBOR bytes (no re-encoding).
    let mut output = Vec::new();

    // Map with 3 items
    output.push(0xA3);

    // ECF key ordering: by encoded key byte length, then lexicographic.
    // "data" (5 encoded bytes) < "type" (5 bytes) lex < "content_hash" (13 bytes)

    // "data" key + raw value
    entity_ecf::encode_cbor_text(&mut output, "data");
    output.extend_from_slice(&entity.data);

    // "type" key + value
    entity_ecf::encode_cbor_text(&mut output, "type");
    entity_ecf::encode_cbor_text(&mut output, &entity.entity_type);

    // "content_hash" key + value (33-byte bstr)
    entity_ecf::encode_cbor_text(&mut output, "content_hash");
    entity_ecf::encode_cbor_bstr(&mut output, &entity.content_hash.to_bytes());

    output
}

/// Decode an entity from CBOR bytes.
///
/// **Byte fidelity (TODO-WIRE-CODEC-FLOAT-FIX, ENTITY-CBOR-ENCODING §4.2).**
/// The `data` field is captured as its **raw on-wire CBOR bytes**, not
/// decoded into a `ciborium::Value` and re-encoded. Any decode+re-encode
/// cycle would route through whichever encoder ciborium ships and risk
/// differing from the sender's canonical (ECF) output on edge cases —
/// notably non-minimal float encodings, multi-sig cap entities, and
/// anywhere an integer/float distinction or map-key ordering matters.
/// The mirrored extraction in `decode_envelope` preserves the same
/// fidelity for the wrapping envelope's root / included entries.
pub fn decode_entity(data: &[u8]) -> Result<Entity, WireError> {
    let (major, count, head_size) = parse_cbor_head(data, 0)?;
    if major != 5 {
        return Err(WireError::CborDecode(format!(
            "expected CBOR map for entity, got major={major}"
        )));
    }

    let mut entity_type: Option<String> = None;
    let mut entity_data: Option<Vec<u8>> = None;
    let mut content_hash: Option<Hash> = None;

    let mut cursor = head_size;
    for _ in 0..count {
        let (key, after_key) = decode_cbor_text(data, cursor)?;
        let value_start = after_key;
        let value_end = cbor_item_end(data, value_start)?;
        match key {
            "type" => {
                let (s, _) = decode_cbor_text(data, value_start)?;
                entity_type = Some(s.to_string());
            }
            "data" => {
                // Raw byte slice — no decode+re-encode round-trip.
                entity_data = Some(data[value_start..value_end].to_vec());
            }
            "content_hash" => {
                let (bytes, _) = decode_cbor_bytes(data, value_start)?;
                content_hash = Some(
                    Hash::from_bytes(bytes).map_err(|e| WireError::CborDecode(e.to_string()))?,
                );
            }
            _ => {} // unknown keys are tolerated
        }
        cursor = value_end;
    }

    let entity_type =
        entity_type.ok_or_else(|| WireError::CborDecode("missing 'type' field".into()))?;
    let data = entity_data.ok_or_else(|| WireError::CborDecode("missing 'data' field".into()))?;
    let content_hash =
        content_hash.ok_or_else(|| WireError::CborDecode("missing 'content_hash' field".into()))?;

    Ok(Entity {
        entity_type,
        data,
        content_hash,
    })
}

/// Decode an entity's `(type, data)` parts **without** requiring (or trusting)
/// a `content_hash` field. Unlike [`decode_entity`], this tolerates both the
/// 3-key authored form `{data, type, content_hash}` and the 2-key
/// hash-addressed form `{data, type}` that `CONTENT_GET` serves
/// (`ecf_for_hash`). Any `content_hash` present on the wire is ignored.
///
/// This is the parse half of host-bytes-distrust (V7 §1.2): a content consumer
/// that fetched bytes by hash MUST recompute `Hash::compute_format(type, data,
/// expected_format)` and compare against the requested hash — never read a
/// host-supplied `content_hash`. The recompute (which needs the expected hash's
/// format code) is the caller's responsibility; this returns the raw material.
/// `data` is captured as its on-wire CBOR slice for byte fidelity.
pub fn decode_entity_parts(data: &[u8]) -> Result<(String, Vec<u8>), WireError> {
    let (major, count, head_size) = parse_cbor_head(data, 0)?;
    if major != 5 {
        return Err(WireError::CborDecode(format!(
            "expected CBOR map for entity, got major={major}"
        )));
    }

    let mut entity_type: Option<String> = None;
    let mut entity_data: Option<Vec<u8>> = None;

    let mut cursor = head_size;
    for _ in 0..count {
        let (key, after_key) = decode_cbor_text(data, cursor)?;
        let value_start = after_key;
        let value_end = cbor_item_end(data, value_start)?;
        match key {
            "type" => {
                let (s, _) = decode_cbor_text(data, value_start)?;
                entity_type = Some(s.to_string());
            }
            "data" => {
                entity_data = Some(data[value_start..value_end].to_vec());
            }
            _ => {} // content_hash and unknown keys are tolerated and ignored
        }
        cursor = value_end;
    }

    let entity_type =
        entity_type.ok_or_else(|| WireError::CborDecode("missing 'type' field".into()))?;
    let entity_data =
        entity_data.ok_or_else(|| WireError::CborDecode("missing 'data' field".into()))?;
    Ok((entity_type, entity_data))
}

// ---------------------------------------------------------------------------
// Envelope codec (§3.1)
// ---------------------------------------------------------------------------

/// Encode an envelope to CBOR bytes.
pub fn encode_envelope(envelope: &Envelope) -> Vec<u8> {
    let mut output = Vec::new();

    if envelope.included.is_empty() {
        // Map with 1 item (root only, omit empty included)
        output.push(0xA1);
    } else {
        // Map with 2 items
        output.push(0xA2);

        // ECF key ordering: "root" (5 encoded bytes) before "included" (9 encoded bytes)
    }

    // "root" key + entity value
    entity_ecf::encode_cbor_text(&mut output, "root");
    let root_bytes = encode_entity(&envelope.root);
    output.extend_from_slice(&root_bytes);

    if !envelope.included.is_empty() {
        // "included" key + map value
        entity_ecf::encode_cbor_text(&mut output, "included");
        entity_ecf::encode_head(&mut output, 5 << 5, envelope.included.len() as u64);

        for (hash, entity) in &envelope.included {
            // Key: hash as CBOR bstr (33 bytes)
            entity_ecf::encode_cbor_bstr(&mut output, &hash.to_bytes());
            // Value: encoded entity
            let entity_bytes = encode_entity(entity);
            output.extend_from_slice(&entity_bytes);
        }
    }

    output
}

/// Decode an envelope from CBOR bytes.
///
/// Uses byte-slice extraction throughout — root and each included entity
/// are passed to `decode_entity` as their on-wire slice, preserving the
/// sender's `data`-field encoding. See `decode_entity` for the rationale.
pub fn decode_envelope(data: &[u8]) -> Result<Envelope, WireError> {
    let (major, count, head_size) = parse_cbor_head(data, 0)?;
    if major != 5 {
        return Err(WireError::CborDecode(format!(
            "expected CBOR map for envelope, got major={major}"
        )));
    }

    let mut root: Option<Entity> = None;
    let mut included: BTreeMap<Hash, Entity> = BTreeMap::new();

    let mut cursor = head_size;
    for _ in 0..count {
        let (key, after_key) = decode_cbor_text(data, cursor)?;
        let value_start = after_key;
        let value_end = cbor_item_end(data, value_start)?;
        match key {
            "root" => {
                root = Some(decode_entity(&data[value_start..value_end])?);
            }
            "included" => {
                let (inc_major, inc_count, inc_head) = parse_cbor_head(data, value_start)?;
                if inc_major != 5 {
                    return Err(WireError::CborDecode(format!(
                        "envelope.included must be a CBOR map, got major={inc_major}"
                    )));
                }
                let mut inc_cursor = value_start + inc_head;
                for _ in 0..inc_count {
                    let (hash_bytes, after_hash) = decode_cbor_bytes(data, inc_cursor)?;
                    let hash = Hash::from_bytes(hash_bytes)
                        .map_err(|e| WireError::CborDecode(e.to_string()))?;
                    let entity_start = after_hash;
                    let entity_end = cbor_item_end(data, entity_start)?;
                    let entity = decode_entity(&data[entity_start..entity_end])?;
                    // ⛔ **The key IS the hash of the value — an `included` map
                    // is content-addressed, and every downstream consumer uses
                    // the KEY as the address.**
                    //
                    // `decode_entity` takes `content_hash` from the wire
                    // verbatim (it must — §5.4 byte fidelity forbids a
                    // decode+re-encode), so at this point neither the key nor
                    // the field has been checked against the bytes. The
                    // security pass that recomputes the field is
                    // `verify_request` step 2b; what belongs *here* is the
                    // cheaper structural half it cannot express as a property
                    // of the type: a mis-keyed entry is a malformed envelope,
                    // and admitting one lets an attacker file their own
                    // `system/peer` entity under a victim's identity hash and
                    // sign a delegation as the victim
                    // (`core/protocol/tests/included_key_binding.rs` drives it
                    // end to end).
                    //
                    // Refused rather than silently re-keyed: re-keying turns a
                    // forged lookup into a `MissingEntity` further downstream,
                    // which is fail-closed but reports the wrong defect — and
                    // this boundary has a caller to answer, which is where the
                    // house rule puts a diagnostic.
                    //
                    // ⚠ Equality is over the WHOLE `Hash`, format byte
                    // included, so this also refuses an entity addressed under
                    // one `content_hash_format` while carrying another. That is
                    // the intended reading of §5.5's per-chain format freeze;
                    // if a cross-format addressing case is ever legitimate it
                    // must be spelled as its own field, not as a key that does
                    // not match its value.
                    if hash != entity.content_hash {
                        // Typed, not stringly — the caller has to tell this
                        // apart from un-parseable bytes to answer it. See
                        // `WireError::IncludedKeyMismatch`.
                        return Err(WireError::IncludedKeyMismatch {
                            key: hash.to_string(),
                            actual: entity.content_hash.to_string(),
                        });
                    }
                    included.insert(hash, entity);
                    inc_cursor = entity_end;
                }
            }
            _ => {} // unknown keys tolerated
        }
        cursor = value_end;
    }

    let root = root.ok_or_else(|| WireError::CborDecode("missing 'root' field".into()))?;
    Ok(Envelope::with_included(root, included))
}

/// Decode **only** an envelope's `root` entity, ignoring `included` entirely.
///
/// For one caller and one purpose: answering a [`WireError::IncludedKeyMismatch`]
/// with a coded response instead of a silent drop. §5.2a's decode-boundary
/// corollary says such a peer answers `400 hash_mismatch`, and an answer needs
/// the `request_id`, which lives in the root — the part of a mis-keyed envelope
/// that is *not* in question.
///
/// ⚠ **Not an alternative decode path, and deliberately not `pub`-adjacent to
/// one.** The root it returns has been through no security pass: `content_hash`
/// is verbatim from the wire (§5.4 byte fidelity) and nothing here validates it.
/// The only field any caller may read from it is `request_id`, to address a
/// refusal. Using it to *dispatch* would re-open the hole
/// [`decode_envelope`] closes, one function over.
pub fn decode_envelope_root(data: &[u8]) -> Result<Entity, WireError> {
    let (major, count, head_size) = parse_cbor_head(data, 0)?;
    if major != 5 {
        return Err(WireError::CborDecode(format!(
            "expected CBOR map for envelope, got major={major}"
        )));
    }
    let mut cursor = head_size;
    for _ in 0..count {
        let (key, value_start) = decode_cbor_text(data, cursor)?;
        let value_end = cbor_item_end(data, value_start)?;
        if key == "root" {
            return decode_entity(&data[value_start..value_end]);
        }
        cursor = value_end;
    }
    Err(WireError::CborDecode("missing 'root' field".into()))
}

/// Extract the raw on-wire CBOR byte slice of `key`'s value from a top-level
/// CBOR map, without decoding the value.
///
/// Preserves byte fidelity for nested entities / opaque payloads carried as
/// map fields — e.g. GUIDE-CONFORMANCE §7a.2a in-band cap-passing, where the
/// reentry capability / granter / signature ride as entity-CBOR inside a
/// `primitive/any` params map and MUST round-trip without a decode+re-encode
/// cycle. Returns `None` if `data` is not a definite-length CBOR map, has a
/// non-text key, or does not contain `key`.
pub fn cbor_map_field_raw<'a>(data: &'a [u8], key: &str) -> Option<&'a [u8]> {
    let (major, count, head_size) = parse_cbor_head(data, 0).ok()?;
    if major != 5 {
        return None;
    }
    let mut cursor = head_size;
    for _ in 0..count {
        let (k, after_key) = decode_cbor_text(data, cursor).ok()?;
        let value_start = after_key;
        let value_end = cbor_item_end(data, value_start).ok()?;
        if k == key {
            return Some(&data[value_start..value_end]);
        }
        cursor = value_end;
    }
    None
}

/// Split a definite-length CBOR **array** into the raw on-wire byte slice of
/// each element, without decoding any of them.
///
/// The array counterpart of [`cbor_map_field_raw`], and it exists for the same
/// reason: GUIDE-CONFORMANCE §7a.1's reentry carriers went **plural** at
/// `0.8.2.19` (`reentry_granters` / `reentry_cap_signatures` are arrays, the
/// single-granter case being an array of one), and each element is a nested
/// entity whose `data` must survive without a decode+re-encode cycle.
///
/// Returns `None` if `data` is not a definite-length CBOR array, or if any
/// element is malformed. An **empty** array yields `Some(vec![])` — absent and
/// empty are the same fact for an optional array, and the caller decides.
pub fn cbor_array_elements_raw(data: &[u8]) -> Option<Vec<&[u8]>> {
    let (major, count, head_size) = parse_cbor_head(data, 0).ok()?;
    if major != 4 {
        return None;
    }
    let mut out = Vec::with_capacity(count as usize);
    let mut cursor = head_size;
    for _ in 0..count {
        let end = cbor_item_end(data, cursor).ok()?;
        out.push(&data[cursor..end]);
        cursor = end;
    }
    Some(out)
}

/// Rebuild a definite-length CBOR **map** with one text-keyed field set to
/// `value` **verbatim**, copying every other entry's key and value as their
/// on-wire byte slices. Output is in ECF key order (encoded-key length, then
/// lexicographic), so a map assembled this way is byte-identical to `to_ecf`
/// over the same logical value — except that no value is ever re-encoded.
///
/// ⛔ **This is the write half of `cbor_map_field_raw`, and it exists because
/// `entity_ecf::Value` cannot hold raw bytes.** An entity's `data` is a CBOR
/// *item*, so inlining an entity inside another entity's data (`{content_hash,
/// data, type}`) through a `Value` tree means a decode+re-encode cycle on
/// `data` — which §5.4 forbids and which silently re-addresses any entity
/// whose bytes our own encoder would not have produced. go gets this for free
/// because its `Entity.Data` is `cbor.RawMessage`; in this tree the splice has
/// to be explicit, and this is the function that makes it one line.
///
/// Errors if `map_bytes` is not a definite-length CBOR map with text keys.
/// Setting a key that is absent inserts it; setting one that is present
/// replaces its value.
pub fn cbor_map_set_raw(map_bytes: &[u8], key: &str, value: &[u8]) -> Result<Vec<u8>, WireError> {
    let (major, count, head_size) = parse_cbor_head(map_bytes, 0)?;
    if major != 5 {
        return Err(WireError::CborDecode(format!(
            "cbor_map_set_raw: expected CBOR map, got major={major}"
        )));
    }

    // (encoded key bytes, value bytes) — keys stay encoded so the ECF sort
    // below is over exactly the bytes that will be emitted.
    let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(count as usize + 1);
    let mut cursor = head_size;
    for _ in 0..count {
        let (k, after_key) = decode_cbor_text(map_bytes, cursor)?;
        let value_end = cbor_item_end(map_bytes, after_key)?;
        if k != key {
            entries.push((
                map_bytes[cursor..after_key].to_vec(),
                map_bytes[after_key..value_end].to_vec(),
            ));
        }
        cursor = value_end;
    }

    let mut encoded_key = Vec::new();
    entity_ecf::encode_cbor_text(&mut encoded_key, key);
    entries.push((encoded_key, value.to_vec()));

    entries.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));

    let mut out = Vec::new();
    entity_ecf::encode_head(&mut out, 5 << 5, entries.len() as u64);
    for (k, v) in entries {
        out.extend_from_slice(&k);
        out.extend_from_slice(&v);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// CBOR byte-range walker (ENTITY-CBOR-ENCODING §4.2 — definite-length only)
// ---------------------------------------------------------------------------
//
// Minimal CBOR parser whose job is to locate item boundaries without
// decoding values. Lets us preserve raw byte ranges for `data` fields
// (and entity-shaped values inside envelopes) end-to-end. ECF mandates
// definite-length encodings throughout, so indefinite-length / reserved
// argument bytes are spec violations and surface as decode errors.

/// Parse a CBOR head at `offset`. Returns `(major_type, argument_value, head_size)`.
/// Errors on indefinite-length or reserved argument bytes (ECF requires definite).
fn parse_cbor_head(data: &[u8], offset: usize) -> Result<(u8, u64, usize), WireError> {
    if offset >= data.len() {
        return Err(WireError::CborDecode(
            "unexpected EOF parsing CBOR head".into(),
        ));
    }
    let first = data[offset];
    let major = first >> 5;
    let ai = first & 0x1F;
    let (value, head_size) = match ai {
        n @ 0..=23 => (n as u64, 1usize),
        24 => {
            if offset + 2 > data.len() {
                return Err(WireError::CborDecode("EOF reading CBOR u8 argument".into()));
            }
            (data[offset + 1] as u64, 2)
        }
        25 => {
            if offset + 3 > data.len() {
                return Err(WireError::CborDecode(
                    "EOF reading CBOR u16 argument".into(),
                ));
            }
            let mut b = [0u8; 2];
            b.copy_from_slice(&data[offset + 1..offset + 3]);
            (u16::from_be_bytes(b) as u64, 3)
        }
        26 => {
            if offset + 5 > data.len() {
                return Err(WireError::CborDecode(
                    "EOF reading CBOR u32 argument".into(),
                ));
            }
            let mut b = [0u8; 4];
            b.copy_from_slice(&data[offset + 1..offset + 5]);
            (u32::from_be_bytes(b) as u64, 5)
        }
        27 => {
            if offset + 9 > data.len() {
                return Err(WireError::CborDecode(
                    "EOF reading CBOR u64 argument".into(),
                ));
            }
            let mut b = [0u8; 8];
            b.copy_from_slice(&data[offset + 1..offset + 9]);
            (u64::from_be_bytes(b), 9)
        }
        _ => {
            return Err(WireError::CborDecode(format!(
                "CBOR additional-info {ai} (indefinite-length / reserved); ECF requires \
                 definite-length encoding per ENTITY-CBOR-ENCODING §4.2"
            )));
        }
    };
    Ok((major, value, head_size))
}

/// Return the end offset (exclusive) of the CBOR item starting at `offset`.
fn cbor_item_end(data: &[u8], offset: usize) -> Result<usize, WireError> {
    let (major, value, head_size) = parse_cbor_head(data, offset)?;
    let after_head = offset + head_size;
    match major {
        0 | 1 => Ok(after_head), // uint / negative integer — head only
        2 | 3 => {
            // bytes / text — head + N bytes payload
            let end = after_head
                .checked_add(value as usize)
                .ok_or_else(|| WireError::CborDecode("CBOR string/bytes length overflow".into()))?;
            if end > data.len() {
                return Err(WireError::CborDecode(
                    "CBOR string/bytes runs past end".into(),
                ));
            }
            Ok(end)
        }
        4 => {
            // array — head + N child items
            let mut cursor = after_head;
            for _ in 0..value {
                cursor = cbor_item_end(data, cursor)?;
            }
            Ok(cursor)
        }
        5 => {
            // map — head + 2N child items
            let mut cursor = after_head;
            for _ in 0..value {
                cursor = cbor_item_end(data, cursor)?; // key
                cursor = cbor_item_end(data, cursor)?; // value
            }
            Ok(cursor)
        }
        6 => {
            // ⛔ **The tag-policy refusal, and it lives HERE rather than at N
            // call sites** (`ENTITY-CBOR-ENCODING` §6.3; §4.11 arm (5a),
            // 0.8.2.26). §6.3: *"Implementations MUST reject any received
            // protocol frame containing a CBOR tag on a data field … Detection
            // is at decode time … covers any CBOR major-type-6 item appearing
            // anywhere within an entity's `data` field at any nesting depth …
            // MUST NOT silently strip tags, MUST NOT preserve them through
            // forwarding, and MUST NOT attempt to interpret them."*
            //
            // This arm used to `cbor_item_end(data, after_head)` — walk past
            // the tag head and carry on — which is *"preserve"*, one of the two
            // dispositions that sentence forbids. Before the §5.4 byte-fidelity
            // fix (`23513a0`) the other one applied instead: `to_ecf`'s
            // `Value::Tag(_, inner)` arm dropped the tag on the forward path,
            // which is *"silently strip"*. **The tree has been on one side or
            // the other of that MUST NOT the whole time, and the §5.4 fix moved
            // us from the first to the second without touching this file.**
            //
            // ⭐ **Why this function and not a scan in `decode_entity`.** Every
            // inbound decode in the peer — TCP, http-live, http-connection,
            // relay-forwarder — reaches `decode_envelope` / `decode_entity`,
            // and both resolve each field's extent through *this* function,
            // recursing to the bottom of `data` already. So the check is
            // structural, total over every nesting depth §6.3 names, and costs
            // **no additional traversal**: the walk was happening regardless,
            // and only the disposition of one arm changes. A scan bolted onto
            // `decode_entity` would be a second walk, would have to be repeated
            // at each ingress, and is the shape §1.8 calls out as the one that
            // cannot be reviewed at a single site.
            //
            // ⚠ **Detection is wider than §6.3's "data-field position", and
            // that is §6.3's own instruction, not a liberty:** *"The envelope
            // and entity-wrapper CBOR shapes are fixed maps and contain no
            // positions where a tag could legally be placed; any tag
            // encountered in those structures is a structurally invalid frame
            // rejected by ordinary decoder validation."* There is no position
            // in a protocol frame where a tag is legal, so a total refusal is
            // the rule, not a superset of it.
            Err(WireError::CborTag { offset })
        }
        7 => {
            // float / simple — head_size already includes the float payload
            // (ai 25 → +2 bytes, ai 26 → +4, ai 27 → +8, ai 0..=23 → 0).
            Ok(after_head)
        }
        _ => Err(WireError::CborDecode(format!(
            "unknown CBOR major type {major}"
        ))),
    }
}

/// Decode a CBOR text item at `offset`. Returns `(borrowed_str, end_offset)`.
fn decode_cbor_text(data: &[u8], offset: usize) -> Result<(&str, usize), WireError> {
    let (major, len, head_size) = parse_cbor_head(data, offset)?;
    if major != 3 {
        return Err(WireError::CborDecode(format!(
            "expected CBOR text, got major={major}"
        )));
    }
    let start = offset + head_size;
    let end = start
        .checked_add(len as usize)
        .ok_or_else(|| WireError::CborDecode("CBOR text length overflow".into()))?;
    if end > data.len() {
        return Err(WireError::CborDecode("CBOR text runs past end".into()));
    }
    let s = std::str::from_utf8(&data[start..end])
        .map_err(|e| WireError::CborDecode(format!("CBOR text invalid utf-8: {e}")))?;
    Ok((s, end))
}

/// Decode a CBOR byte-string item at `offset`. Returns `(borrowed_slice, end_offset)`.
fn decode_cbor_bytes(data: &[u8], offset: usize) -> Result<(&[u8], usize), WireError> {
    let (major, len, head_size) = parse_cbor_head(data, offset)?;
    if major != 2 {
        return Err(WireError::CborDecode(format!(
            "expected CBOR bytes, got major={major}"
        )));
    }
    let start = offset + head_size;
    let end = start
        .checked_add(len as usize)
        .ok_or_else(|| WireError::CborDecode("CBOR bytes length overflow".into()))?;
    if end > data.len() {
        return Err(WireError::CborDecode("CBOR bytes runs past end".into()));
    }
    Ok((&data[start..end], end))
}

#[derive(Debug, Error)]
pub enum WireError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("frame too large: {size} bytes (max {max})")]
    FrameTooLarge { size: u32, max: u32 },

    #[error("CBOR decode error: {0}")]
    CborDecode(String),

    /// An `included` entry filed under a hash that is not its own — §1.8's
    /// resolution-integrity refusal, taken at the decode boundary (0.8.2.23).
    ///
    /// ⛔ **Typed, and separate from [`WireError::CborDecode`], because the
    /// two get different answers.** Un-parseable bytes have no `request_id` to
    /// reply to and the frame is dropped; a mis-keyed envelope is *structurally
    /// fine* — the root decodes, the request_id is right there — so §4.1's
    /// *"every EXECUTE receives a response"* binds, and §5.2a names the answer:
    /// a peer refusing at the decode boundary answers **`400 hash_mismatch`**.
    /// Folding this into the generic decode error is what made our refusal
    /// silent: fail-closed, and indistinguishable from a lost frame.
    #[error("envelope.included entry is filed under a hash that is not its own: key {key} vs entity {actual}")]
    IncludedKeyMismatch { key: String, actual: String },

    /// A CBOR **major-type-6 (tag)** item inside a protocol frame — the
    /// tag-policy refusal, `400 non_canonical_ecf`
    /// (`ENTITY-CBOR-ENCODING` §6.3; `ENTITY-CORE-PROTOCOL` §4.11 arm (5a),
    /// 0.8.2.26).
    ///
    /// ⛔ **Typed, and separate from [`WireError::CborDecode`], because
    /// `0.8.2.26` `DR-3` partitions the input those two used to share.** The
    /// framing arm is *bytes that do not decode at all* → `400
    /// invalid_request`. These bytes **do** decode — a tag is well-formed CBOR
    /// — and are refused by policy, so the code is §6.3's and the caller's
    /// remedy is *re-encode without the tag*, not *your frame is broken*.
    /// §4.11's own rule is that a code merely in the right family is still the
    /// wrong code, because the code selects the remedy.
    ///
    /// Both are **pre-admission refusals** and both owe a coded frame; the
    /// stream is synchronized either way here, so the close stays the peer's
    /// choice (this is never the `(a2)` truncated shape).
    #[error("CBOR tag (major type 6) at byte {offset}: tags are not part of ECF (ENTITY-CBOR-ENCODING §6.3)")]
    CborTag { offset: usize },

    /// EOF arrived **part-way through a frame** — after at least one byte of
    /// the length prefix, or with fewer than `expected` payload bytes read.
    ///
    /// ⛔ **Typed, and separate from [`WireError::Io`], because §4.11 gives the
    /// two opposite dispositions** (0.8.2.25). A clean EOF *at a frame
    /// boundary* is an ordinary disconnect and nothing is owed. A frame that
    /// started and did not finish is the **framing population** of the
    /// pre-admission refusal class: the caller owes a coded `400
    /// invalid_request` before it closes. `read_exact` reports both as
    /// `UnexpectedEof`, so the distinction cannot be recovered by the caller
    /// and has to be made here, where the phase is known.
    ///
    /// The stream is **desynchronized** when this fires (the frame the prefix
    /// promised never arrived), which is why its disposition is *answer, then
    /// close* rather than the `continue` that [`WireError::CborDecode`] gets.
    #[error("truncated frame: EOF after {read} of {expected} bytes ({phase})")]
    TruncatedFrame {
        phase: &'static str,
        read: usize,
        expected: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entity(type_str: &str, data_str: &str) -> Entity {
        let data = entity_ecf::to_ecf(&entity_ecf::text(data_str));
        Entity::new(type_str, data).unwrap()
    }

    // --- cbor_map_set_raw (§5.4 byte fidelity) ---

    /// The value goes in **verbatim**, including byte sequences no ECF encoder
    /// emits. This is the property the whole function exists for: an entity's
    /// `data` is a CBOR item, and carrying it through `ciborium::Value`
    /// normalizes non-minimal integer and length encodings, folds
    /// indefinite-length items to definite, sorts map keys and drops tags.
    ///
    /// The fixture is a non-minimal uint (`0x18 0x01` for `1`) because the
    /// alternative — a value our own codec authors — makes the broken and the
    /// fixed implementation byte-identical and the assertion a tautology.
    #[test]
    fn map_set_raw_splices_bytes_our_own_encoder_cannot_emit() {
        let noncanonical = [0xa1u8, 0x61, 0x76, 0x18, 0x01]; // {"v": 1}, 1 written long
        let base = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("type"),
            entity_ecf::text("test/x"),
        )]));

        let out = cbor_map_set_raw(&base, "data", &noncanonical).unwrap();
        assert_eq!(
            cbor_map_field_raw(&out, "data"),
            Some(&noncanonical[..]),
            "the spliced value is the caller's bytes, not a re-encoding of them"
        );
        assert_eq!(
            cbor_map_field_raw(&out, "type"),
            cbor_map_field_raw(&base, "type"),
            "untouched fields keep their own byte slices too"
        );

        // Control: a round trip through `Value` would have changed it, which is
        // what makes the assertion above worth making.
        let v: ciborium::Value = ciborium::from_reader(&noncanonical[..]).unwrap();
        let mut reencoded = Vec::new();
        ciborium::into_writer(&v, &mut reencoded).unwrap();
        assert_ne!(
            reencoded,
            noncanonical.to_vec(),
            "fixture must be a value the codec cannot author, or this test is a tautology"
        );
    }

    // --- tag policy (ENTITY-CBOR-ENCODING §6.3; §4.11 arm (5a), 0.8.2.26) ---

    /// Every one of §6.3's positions, refused with the **typed** error the
    /// caller needs in order to answer `400 non_canonical_ecf` rather than
    /// `400 invalid_request`.
    ///
    /// The four fixtures are the cohort's own `tag_reject` corpus shapes
    /// (`cmd/wire-conformance`'s F30 set), re-pointed at the production decoder
    /// instead of at `is_canonical_ecf` — which is the whole finding: that
    /// validator carries a complete major-6 arm and has **zero callers on any
    /// protocol boundary**, so the corpus scored a function the peer never ran.
    ///
    /// ⚠ **The last row is the one that fails a shallow implementation.** A
    /// check at the top of `data` — the natural reading of *"a data-field
    /// position"*, and the cheap one given that `decode_entity` holds `data` as
    /// a single opaque slice — passes rows 1–3 and misses row 4. §6.3 says
    /// *"any nesting depth"* and means it.
    #[test]
    fn a_cbor_tag_is_refused_at_every_position_in_a_frame() {
        // {"a": 0("x")}  — tag at the top of a data field.
        let shallow = [0xa1u8, 0x61, b'a', 0xc0, 0x61, b'x'];
        // 0({})  — tag wrapping the whole item (the `d9d9f7` self-describe shape).
        let wrapper = [0xc0u8, 0xa0];
        // ["x", 0("y")]  — tag as a later array element.
        let in_array = [0x82u8, 0x61, b'x', 0xc0, 0x61, b'y'];
        // {"a": [{"b": 0("x")}]}  — depth 4.
        let deep = [0xa1u8, 0x61, b'a', 0x81, 0xa1, 0x61, b'b', 0xc0, 0x61, b'x'];

        for (label, bytes) in [
            ("shallow", &shallow[..]),
            ("wrapper", &wrapper[..]),
            ("in_array", &in_array[..]),
            ("deep", &deep[..]),
        ] {
            let err = cbor_item_end(bytes, 0).expect_err(label);
            assert!(
                matches!(err, WireError::CborTag { .. }),
                "{label}: a tag MUST surface as the TYPED CborTag — folded into \
                 `CborDecode` it becomes the framing arm's `invalid_request`, \
                 which is the pre-fix answer and the wrong remedy: got {err:?}"
            );
        }
    }

    /// The control, and it is the half that makes the rows above mean anything:
    /// **an untagged twin of each fixture still decodes.** A refusal that fires
    /// on every input is not a tag check, and this is the assertion that fails
    /// if the `6 =>` arm is ever widened to a neighbouring major type.
    #[test]
    fn the_untagged_twins_still_decode() {
        for (label, bytes) in [
            ("shallow", &[0xa1u8, 0x61, b'a', 0x61, b'x'][..]),
            ("wrapper", &[0xa0u8][..]),
            ("in_array", &[0x82u8, 0x61, b'x', 0x61, b'y'][..]),
            (
                "deep",
                &[0xa1u8, 0x61, b'a', 0x81, 0xa1, 0x61, b'b', 0x61, b'x'][..],
            ),
        ] {
            assert_eq!(
                cbor_item_end(bytes, 0).expect(label),
                bytes.len(),
                "{label}: the twin differs from its fixture in the tag head and \
                 nothing else, so it must decode whole"
            );
        }
    }

    /// The finding, recorded as a row rather than as prose: **a tagged entity
    /// used to decode**, so the peer admitted a frame `ENTITY-CBOR-ENCODING`
    /// §6.3 obliges it to refuse, and answered on the frame's merits.
    ///
    /// This is the test whose pre-fix state is the measurement. Restoring
    /// `6 => cbor_item_end(data, after_head)` turns the `expect_err` into a
    /// successful decode and reddens exactly this row plus the two above —
    /// **and nothing else in the 133-suite set**, which is the other half of
    /// the finding: no in-tree row anywhere drove a tag through the production
    /// decoder.
    #[test]
    fn a_tagged_entity_does_not_decode_and_the_untagged_one_does() {
        let mk = |inner: &[u8]| {
            let base = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                entity_ecf::text("a"),
                entity_ecf::text("placeholder"),
            )]));
            let data = cbor_map_set_raw(&base, "a", inner).unwrap();
            encode_entity(&Entity::new("test/v1", data).unwrap())
        };

        assert!(
            matches!(
                decode_entity(&mk(&[0xc0, 0x61, b'x'])),
                Err(WireError::CborTag { .. })
            ),
            "§6.3: a tag inside `data` is a decode-time rejection condition"
        );
        assert!(
            decode_entity(&mk(&[0x61, b'x'])).is_ok(),
            "control: the same entity without the tag head is ordinary ECF"
        );
    }

    /// Output is in ECF key order regardless of where the set key sorts, so a
    /// map assembled this way is byte-identical to `to_ecf` over the same
    /// logical value. Checked against `to_ecf` itself on an all-canonical map.
    #[test]
    fn map_set_raw_emits_ecf_key_order() {
        let base = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("source_prefix"), entity_ecf::text("a/")),
            (
                entity_ecf::text("strategy"),
                entity_ecf::text("source-wins"),
            ),
            (entity_ecf::text("target_prefix"), entity_ecf::text("b/")),
        ]));
        let env = entity_ecf::to_ecf(&entity_ecf::text("envelope-stand-in"));
        let out = cbor_map_set_raw(&base, "source_envelope", &env).unwrap();

        let expected = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("source_envelope"),
                entity_ecf::text("envelope-stand-in"),
            ),
            (entity_ecf::text("source_prefix"), entity_ecf::text("a/")),
            (
                entity_ecf::text("strategy"),
                entity_ecf::text("source-wins"),
            ),
            (entity_ecf::text("target_prefix"), entity_ecf::text("b/")),
        ]));
        assert_eq!(out, expected);
    }

    /// Setting a key that is already present replaces it rather than emitting
    /// a duplicate — a duplicate key is not a CBOR map.
    #[test]
    fn map_set_raw_replaces_an_existing_key() {
        let base = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("a"), entity_ecf::text("old")),
            (entity_ecf::text("b"), entity_ecf::text("keep")),
        ]));
        let new_val = entity_ecf::to_ecf(&entity_ecf::text("new"));
        let out = cbor_map_set_raw(&base, "a", &new_val).unwrap();
        let decoded: ciborium::Value = ciborium::from_reader(out.as_slice()).unwrap();
        let map = decoded.as_map().unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(cbor_map_field_raw(&out, "a"), Some(&new_val[..]));
    }

    #[test]
    fn map_set_raw_refuses_a_non_map() {
        let arr = entity_ecf::to_ecf(&entity_ecf::Value::Array(vec![entity_ecf::text("x")]));
        assert!(cbor_map_set_raw(&arr, "k", b"\x01").is_err());
    }

    // --- Framing tests ---

    #[tokio::test]
    async fn test_frame_roundtrip() {
        let payload = b"hello world";
        let mut buf = Vec::new();
        write_frame(&mut buf, payload).await.unwrap();
        assert_eq!(buf.len(), 4 + payload.len());
        // First 4 bytes are big-endian length
        assert_eq!(&buf[..4], &(payload.len() as u32).to_be_bytes());

        let mut cursor = std::io::Cursor::new(buf);
        let read_back = read_frame(&mut cursor, DEFAULT_MAX_FRAME_SIZE)
            .await
            .unwrap();
        assert_eq!(read_back, payload);
    }

    #[tokio::test]
    async fn test_frame_empty_payload() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"").await.unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let read_back = read_frame(&mut cursor, DEFAULT_MAX_FRAME_SIZE)
            .await
            .unwrap();
        assert!(read_back.is_empty());
    }

    #[tokio::test]
    async fn test_frame_too_large() {
        let mut buf = Vec::new();
        let big_payload = vec![0u8; 1000];
        write_frame(&mut buf, &big_payload).await.unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let result = read_frame(&mut cursor, 100).await;
        assert!(matches!(result, Err(WireError::FrameTooLarge { .. })));
    }

    #[tokio::test]
    async fn test_multiple_frames() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"first").await.unwrap();
        write_frame(&mut buf, b"second").await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let f1 = read_frame(&mut cursor, DEFAULT_MAX_FRAME_SIZE)
            .await
            .unwrap();
        let f2 = read_frame(&mut cursor, DEFAULT_MAX_FRAME_SIZE)
            .await
            .unwrap();
        assert_eq!(f1, b"first");
        assert_eq!(f2, b"second");
    }

    // --- Entity codec tests ---

    #[test]
    fn test_entity_encode_decode() {
        let entity = make_entity("test/type", "hello");
        let encoded = encode_entity(&entity);
        let decoded = decode_entity(&encoded).unwrap();
        assert_eq!(decoded.entity_type, entity.entity_type);
        assert_eq!(decoded.content_hash, entity.content_hash);
    }

    #[test]
    fn test_entity_hash_preserved() {
        let entity = make_entity("test/type", "hello");
        let encoded = encode_entity(&entity);
        let decoded = decode_entity(&encoded).unwrap();
        // The decoded entity should validate (hash matches)
        assert!(decoded.validate().is_ok());
    }

    #[test]
    fn test_entity_encode_deterministic() {
        let entity = make_entity("test/type", "hello");
        let e1 = encode_entity(&entity);
        let e2 = encode_entity(&entity);
        assert_eq!(e1, e2);
    }

    // --- Byte-fidelity regression tests (TODO-WIRE-CODEC-FLOAT-FIX) ---
    //
    // These lock in that `decode_entity` / `decode_envelope` preserve the
    // sender's `data`-field bytes exactly — no ciborium round-trip on the
    // hashed payload. The earlier impl decoded `data` to a `ciborium::Value`
    // and re-encoded it, which differs from the ECF canonical form on
    // floats and on any future encoder divergence between Rust and other
    // impls. Cross-impl symptom: hashes computed by Go/Python over their
    // canonical encoding didn't validate after Rust's decode+re-encode.

    #[test]
    fn test_decode_entity_preserves_float_data_bytes() {
        // ECF Rule 4 / 4a (ENTITY-CBOR-ENCODING): shortest float encoding
        // preserving value; ±0.0, ±Inf, NaN canonicalized to float16.
        for v in [
            0.0_f64,
            -0.0,
            1.0,
            1.5,
            65504.0, // f16 max-normal
            1.1,     // not representable in f16/f32 — falls through to f64
            0.333333,
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
        ] {
            let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                entity_ecf::text("v"),
                entity_ecf::Value::Float(v),
            )]));
            let entity = Entity::new("test/float", data).unwrap();
            let encoded = encode_entity(&entity);
            let decoded = decode_entity(&encoded).unwrap();
            assert_eq!(
                decoded.data, entity.data,
                "data bytes must round-trip exactly for float {v}"
            );
            assert!(
                decoded.validate().is_ok(),
                "content_hash must still validate after wire decode for float {v}"
            );
        }
    }

    #[test]
    fn test_decode_envelope_preserves_root_data_bytes() {
        // Same property on the envelope path — root entity's data bytes
        // must arrive untouched through decode_envelope.
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("v"),
            entity_ecf::Value::Float(1.5),
        )]));
        let root = Entity::new("test/float", data).unwrap();
        let envelope = Envelope::new(root.clone());
        let encoded = encode_envelope(&envelope);
        let decoded = decode_envelope(&encoded).unwrap();
        assert_eq!(decoded.root.data, root.data);
        assert!(decoded.root.validate().is_ok());
    }

    #[test]
    fn test_decode_envelope_preserves_included_data_bytes() {
        // Same property for included entries (load-bearing for the
        // cross-peer mirror recipe: include_payload + deref_included).
        let root = make_entity("test/root", "r");
        let payload_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("created_at"),
                entity_ecf::integer(1_700_000_000),
            ),
            (entity_ecf::text("ratio"), entity_ecf::Value::Float(1.5)),
        ]));
        let payload = Entity::new("test/cap", payload_data).unwrap();
        let payload_hash = payload.content_hash;
        let mut envelope = Envelope::new(root);
        envelope.include(payload.clone());
        let encoded = encode_envelope(&envelope);
        let decoded = decode_envelope(&encoded).unwrap();
        let decoded_payload = decoded
            .included
            .get(&payload_hash)
            .expect("included payload missing after decode");
        assert_eq!(decoded_payload.data, payload.data);
        assert!(decoded_payload.validate().is_ok());
    }

    // --- Envelope codec tests ---

    #[test]
    fn test_envelope_roundtrip_root_only() {
        let root = make_entity("test/root", "root data");
        let envelope = Envelope::new(root.clone());
        let encoded = encode_envelope(&envelope);
        let decoded = decode_envelope(&encoded).unwrap();
        assert_eq!(decoded.root.entity_type, "test/root");
        assert_eq!(decoded.root.content_hash, root.content_hash);
        assert!(decoded.included.is_empty());
    }

    #[test]
    fn test_envelope_roundtrip_with_included() {
        let root = make_entity("test/root", "root");
        let extra = make_entity("test/extra", "extra");
        let extra_hash = extra.content_hash;
        let mut envelope = Envelope::new(root);
        envelope.include(extra);
        let encoded = encode_envelope(&envelope);
        let decoded = decode_envelope(&encoded).unwrap();
        assert!(decoded.included.contains_key(&extra_hash));
        assert_eq!(decoded.included[&extra_hash].entity_type, "test/extra");
    }

    #[test]
    fn test_execute_response_result_is_inline_entity() {
        // Verify the result field in EXECUTE_RESPONSE data contains an inline
        // entity map, not just a content hash byte string.
        //
        // Build the response data the same way protocol::build_execute_response does:
        // result = inline entity, not hash reference.
        let result_entity = make_entity("system/protocol/connect/hello", "hello");
        let result_encoded = encode_entity(&result_entity);

        // Build response data with inline entity in result field
        let mut data = Vec::new();
        data.push(0xA3); // map(3)
                         // "result" (7 encoded bytes) < "status" (7) lex, then "request_id" (11)
                         // text(6) "result"
        data.extend_from_slice(&[0x66, b'r', b'e', b's', b'u', b'l', b't']);
        data.extend_from_slice(&result_encoded);
        // text(6) "status"
        data.extend_from_slice(&[0x66, b's', b't', b'a', b't', b'u', b's']);
        data.push(0x18);
        data.push(200); // uint 200
                        // text(10) "request_id"
        data.extend_from_slice(&[
            0x6A, b'r', b'e', b'q', b'u', b'e', b's', b't', b'_', b'i', b'd',
        ]);
        data.extend_from_slice(&[0x65, b'r', b'e', b'q', b'-', b'1']); // text(5) "req-1"

        let resp_entity = Entity::new("system/protocol/execute_response", data).unwrap();
        let mut envelope = Envelope::new(resp_entity);
        envelope.include(result_entity);

        let encoded = encode_envelope(&envelope);

        // Decode and check the result field is an inline entity map
        let v: ciborium::Value = ciborium::from_reader(encoded.as_slice()).unwrap();
        let top_map = v.as_map().expect("envelope must be a map");

        for (k, val) in top_map {
            if k.as_text() == Some("root") {
                let root_map = val.as_map().expect("root must be entity map");
                for (rk, rv) in root_map {
                    if rk.as_text() == Some("data") {
                        let resp_map = rv.as_map().expect("response data must be a map");
                        for (dk, dv) in resp_map {
                            if dk.as_text() == Some("result") {
                                assert!(
                                    dv.as_map().is_some(),
                                    "result must be an inline entity map, got: {:?}",
                                    dv
                                );
                                assert!(
                                    dv.as_bytes().is_none(),
                                    "result must NOT be a byte string (hash reference)"
                                );
                                let ent_map = dv.as_map().unwrap();
                                let keys: Vec<_> =
                                    ent_map.iter().filter_map(|(k, _)| k.as_text()).collect();
                                assert!(keys.contains(&"type"));
                                assert!(keys.contains(&"data"));
                                assert!(keys.contains(&"content_hash"));
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_envelope_validate_after_decode() {
        let root = make_entity("test/root", "root");
        let extra = make_entity("test/extra", "extra");
        let mut envelope = Envelope::new(root);
        envelope.include(extra);
        let encoded = encode_envelope(&envelope);
        let decoded = decode_envelope(&encoded).unwrap();
        assert!(decoded.validate_all().is_ok());
    }

    // --- Full wire roundtrip ---

    #[tokio::test]
    async fn test_full_wire_roundtrip() {
        let root = make_entity("system/protocol/execute", "request");
        let sig = make_entity("system/signature", "sig");
        let mut envelope = Envelope::new(root.clone());
        envelope.include(sig);

        let payload = encode_envelope(&envelope);
        let mut buf = Vec::new();
        write_frame(&mut buf, &payload).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let read_payload = read_frame(&mut cursor, DEFAULT_MAX_FRAME_SIZE)
            .await
            .unwrap();
        let decoded = decode_envelope(&read_payload).unwrap();

        assert_eq!(decoded.root.content_hash, root.content_hash);
        assert_eq!(decoded.included.len(), 1);
        assert!(decoded.validate_all().is_ok());
    }
}
