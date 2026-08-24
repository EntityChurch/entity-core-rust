//! Tier 1: Content hash compute/validate/format.
//!
//! **No width is pinned here** (SPECIFICATION-FORMAT §8.4.5). A content
//! hash is the self-describing pair `(content_hash_format, digest)` and
//! its length follows its leading format varint — 33 bytes / 66 hex
//! chars under ECFv1-SHA-256 (`0x00`), 49 / 98 under ECFv1-SHA-384
//! (`0x01`), as worked instances and not as the requirement.
//!
//! The three `hash_ptr` entry points below take no companion length, so
//! they read the width off the leading byte via [`wire_len_at`] rather
//! than assuming 33. That is what keeps the C ABI unchanged while the
//! surface stops being SHA-256-only: the caller already holds a
//! self-describing buffer, so the length parameter it never had was
//! never needed.

use crate::error::set_last_error;
use crate::types::{EntityCoreBuffer, EntityCoreError};

/// Total wire length of the hash beginning at `ptr`, read from its own
/// leading `content_hash_format` byte. `None` when the code is
/// unallocated (the caller surfaces `400
/// unsupported_content_hash_format`, V7 §4.7) or when it carries a
/// varint continuation bit — every allocated and reserved format in V7
/// §8.2 is a single-byte code, so a continuation byte means the buffer
/// is not a hash and reading further would be a wild read.
///
/// # Safety
/// `ptr` must point to at least one readable byte.
unsafe fn wire_len_at(ptr: *const u8) -> Option<usize> {
    let format_code = unsafe { *ptr };
    if format_code & 0x80 != 0 {
        return None;
    }
    entity_hash::digest_len_for_format(format_code).map(|digest| 1 + digest)
}

/// Compute the content hash of an entity (type + data).
///
/// Returns 33 bytes (algorithm byte + 32-byte SHA-256 digest).
///
/// # Safety
/// `type_ptr`/`type_len` and `data_ptr`/`data_len` must be valid.
#[no_mangle]
pub unsafe extern "C" fn entity_hash_compute(
    type_ptr: *const u8,
    type_len: usize,
    data_ptr: *const u8,
    data_len: usize,
) -> EntityCoreBuffer {
    ffi_fn!({
        let entity_type =
            match unsafe { std::str::from_utf8(std::slice::from_raw_parts(type_ptr, type_len)) } {
                Ok(s) => s,
                Err(e) => {
                    set_last_error(&format!("invalid UTF-8 type: {}", e));
                    return EntityCoreBuffer::null();
                }
            };
        let data = unsafe { std::slice::from_raw_parts(data_ptr, data_len) };
        let hash = entity_hash::Hash::compute(entity_type, data);
        EntityCoreBuffer::from_vec(hash.to_bytes().to_vec())
    })
}

/// Validate that a hash matches the given type + data.
///
/// # Safety
/// All pointer/length pairs must be valid. `hash_ptr` must point to a
/// complete wire hash — one format byte plus the digest that byte
/// implies (33 bytes under `0x00`, 49 under `0x01`).
#[no_mangle]
pub unsafe extern "C" fn entity_hash_validate(
    type_ptr: *const u8,
    type_len: usize,
    data_ptr: *const u8,
    data_len: usize,
    hash_ptr: *const u8,
) -> EntityCoreError {
    ffi_fn!(
        {
            let entity_type = match unsafe {
                std::str::from_utf8(std::slice::from_raw_parts(type_ptr, type_len))
            } {
                Ok(s) => s,
                Err(e) => {
                    set_last_error(&format!("invalid UTF-8 type: {}", e));
                    return EntityCoreError::InvalidArgument;
                }
            };
            let data = unsafe { std::slice::from_raw_parts(data_ptr, data_len) };
            let wire_len = match unsafe { wire_len_at(hash_ptr) } {
                Some(n) => n,
                None => {
                    set_last_error("unsupported content_hash_format in hash buffer");
                    return EntityCoreError::InvalidArgument;
                }
            };
            let hash_bytes = unsafe { std::slice::from_raw_parts(hash_ptr, wire_len) };
            let claimed = match entity_hash::Hash::from_bytes(hash_bytes) {
                Ok(h) => h,
                Err(e) => {
                    set_last_error(&format!("invalid hash: {}", e));
                    return EntityCoreError::InvalidArgument;
                }
            };
            match entity_hash::Hash::validate(entity_type, data, &claimed) {
                Ok(()) => EntityCoreError::Ok,
                Err(e) => {
                    set_last_error(&format!("hash mismatch: {}", e));
                    EntityCoreError::InvalidArgument
                }
            }
        },
        EntityCoreError::InternalError
    )
}

/// Format a wire hash as a hex string. Length follows the hash's own
/// format byte.
///
/// # Safety
/// `hash_ptr` must point to a complete wire hash (format byte + the
/// digest that byte implies).
#[no_mangle]
pub unsafe extern "C" fn entity_hash_to_hex(hash_ptr: *const u8) -> EntityCoreBuffer {
    ffi_fn!({
        let wire_len = match unsafe { wire_len_at(hash_ptr) } {
            Some(n) => n,
            None => {
                set_last_error("unsupported content_hash_format in hash buffer");
                return EntityCoreBuffer::null();
            }
        };
        let hash_bytes = unsafe { std::slice::from_raw_parts(hash_ptr, wire_len) };
        let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
        EntityCoreBuffer::from_vec(hex.into_bytes())
    })
}

/// Parse a hex string back into wire-hash bytes.
///
/// # Safety
/// `hex_ptr`/`hex_len` must point to a valid hex string.
#[no_mangle]
pub unsafe extern "C" fn entity_hash_from_hex(
    hex_ptr: *const u8,
    hex_len: usize,
) -> EntityCoreBuffer {
    ffi_fn!({
        let hex = match unsafe { std::str::from_utf8(std::slice::from_raw_parts(hex_ptr, hex_len)) }
        {
            Ok(s) => s,
            Err(e) => {
                set_last_error(&format!("invalid UTF-8: {}", e));
                return EntityCoreBuffer::null();
            }
        };
        if hex.is_empty() || hex.len() % 2 != 0 {
            set_last_error("hex string must have an even, non-zero length");
            return EntityCoreBuffer::null();
        }
        let mut bytes = vec![0u8; hex.len() / 2];
        for (i, byte) in bytes.iter_mut().enumerate() {
            match u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16) {
                Ok(b) => *byte = b,
                Err(e) => {
                    set_last_error(&format!("invalid hex: {}", e));
                    return EntityCoreBuffer::null();
                }
            }
        }
        // Reject anything that is not a well-formed hash rather than
        // handing back a buffer of the wrong width. This is the check the
        // old fixed-66 was reaching for, and it is stronger: it also
        // rejects a 98-char string claiming `00`, a 66-char one claiming
        // `01`, and the digest-only form that drops the format code.
        if let Err(e) = entity_hash::Hash::from_bytes(&bytes) {
            set_last_error(&format!("not a wire hash: {}", e));
            return EntityCoreBuffer::null();
        }
        EntityCoreBuffer::from_vec(bytes)
    })
}

/// Format a wire hash as the display string ("ecfv1-sha256:...").
///
/// # Safety
/// `hash_ptr` must point to a complete wire hash (format byte + the
/// digest that byte implies).
#[no_mangle]
pub unsafe extern "C" fn entity_hash_to_display(hash_ptr: *const u8) -> EntityCoreBuffer {
    ffi_fn!({
        let wire_len = match unsafe { wire_len_at(hash_ptr) } {
            Some(n) => n,
            None => {
                set_last_error("unsupported content_hash_format in hash buffer");
                return EntityCoreBuffer::null();
            }
        };
        let hash_bytes = unsafe { std::slice::from_raw_parts(hash_ptr, wire_len) };
        match entity_hash::Hash::from_bytes(hash_bytes) {
            Ok(h) => EntityCoreBuffer::from_vec(h.to_string().into_bytes()),
            Err(e) => {
                set_last_error(&format!("invalid hash: {}", e));
                EntityCoreBuffer::null()
            }
        }
    })
}
