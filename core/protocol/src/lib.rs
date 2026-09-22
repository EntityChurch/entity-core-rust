//! EXECUTE dispatch, connection handshake, authentication.
//!
//! Per spec §3.2, §4, §5.2, §6.5:
//! - Connection: 3 EXECUTE + 3 EXECUTE_RESPONSE via system/protocol/connect
//! - Auth: every non-connect EXECUTE requires author + capability + signature
//! - Dispatch: verify → resolve handler → check permission → dispatch

mod connect;
mod response;
mod verify;

use thiserror::Error;

// Re-export public API
pub use connect::{
    build_authenticate_envelope, build_connect_execute, build_connect_execute_at,
    default_advertised_hash_formats, default_advertised_key_types, default_advertised_protocols,
    negotiate_active_format, protocols_compatible, AuthenticateData, Connection, ConnectionState,
    HelloData, CONNECT_OPERATIONS, CONNECT_PATH,
};
pub use response::{
    build_error_response, build_error_response_with_marker, build_execute_response,
    build_execute_response_full, build_execute_response_with_included, extract_rejected_marker,
    extract_response_request_id, parse_execute_response, ParsedResponse,
};
pub use verify::{
    capability_path_for_scan, check_creator_authority, collect_authority_chain,
    collect_chain_bundle, decode_execute_fields, is_operator_class_for, is_revoked,
    verify_capability_chain, verify_request, verify_request_with_ctx, ChainWalkError,
    CreatorAuthorityResult, ExecuteFields, VerifiedRequest, VerifyContext, MAX_CHAIN_DEPTH,
};

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("content hash mismatch")]
    HashMismatch,

    #[error("missing signature")]
    MissingSignature,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("signer does not match expected identity")]
    SignerMismatch,

    #[error("grantee does not match author")]
    GranteeMismatch,

    /// V7 §4.10(b) (v7.75, RATIFIED): a presented capability chain
    /// exceeds `MAX_CHAIN_DEPTH` (recommended default 64). Per Keystone's
    /// cross-impl reshape this is a **client-correctable structural excess, not
    /// an authorization denial** — it maps to **400 `chain_depth_exceeded`**
    /// and MUST NOT use 403 (the pre-v7.75 mapping, which conflated "too deep"
    /// with "unauthorized"). Distinct from the `max_delegation_depth` caveat
    /// (an authorization caveat → AttenuationViolation/403): this is the
    /// structural chain-walk bound, not a delegation-policy violation.
    #[error("capability chain too deep (max {MAX_CHAIN_DEPTH})")]
    ChainTooDeep,

    #[error("root capability granter is not local peer")]
    NotLocalPeer,

    #[error("missing capability")]
    MissingCapability,

    #[error("capability token not in included")]
    MissingCapabilityEntity,

    #[error("capability expired")]
    CapabilityExpired,

    #[error("capability not yet valid")]
    CapabilityNotYetValid,

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// A capability-chain authenticity dependency is absent from
    /// `envelope.included`: either an intermediate chain link is
    /// unreachable (`"capability in chain"`) or a link's granter identity
    /// entity is missing (`"granter identity"`). Both are EXECUTE-path
    /// chain-verification failures — the presented capability cannot be
    /// authenticated. Per V7 §3.3 status-normalization these belong to the
    /// **403 `capability_denied`** family (matching Go's
    /// `ErrCapabilityDenied` for "granter identity not found" /
    /// chain-unreachable, and consistent with the sibling
    /// `MissingCapabilityEntity` variant which already maps to 403). NOT a
    /// generic 400 — an unverifiable cap is an
    /// authority failure, not a malformed request. The tree-write
    /// creator-authority path keeps its own 404 `chain_unreachable` surface
    /// via `check_creator_authority`, which returns `ChainWalkError`
    /// directly and never constructs this variant.
    #[error("missing required entity: {0}")]
    MissingEntity(&'static str),

    #[error("capability chain attenuation violation: child grants not subset of parent")]
    AttenuationViolation,

    #[error("invalid: {0}")]
    Invalid(String),

    /// PROPOSAL-MULTISIG-CORE-PRIMITIVE follow-up #4 (§3.3, §10.1):
    /// M3 structural violations on `system/capability/token` entities MUST
    /// surface as `403 capability_denied`, regardless of detection layer.
    /// This is distinct from generic `Invalid` (→400) so the wire-response
    /// boundary classifies it as auth-failure.
    #[error("capability invalid: {0}")]
    CapabilityInvalid(String),

    /// PROPOSAL-ROLE-V2.0-PRODUCTION-READINESS PR-3 / V7 v7.39 §3.6 + §5.5:
    /// a capability in the chain has a `grantee` that does not resolve to a
    /// present `system/peer` entity. Per V7 §3.3 maps to status **401**
    /// (cap-validity-at-the-auth-layer rejection; consistent with
    /// `capability_revoked`). Bearer-cap rejection: zero-hash and any other
    /// unresolvable hash MUST be rejected.
    #[error("unresolvable grantee: capability grantee does not resolve to an identity entity")]
    UnresolvableGrantee,

    /// V7.62 §5.1 + closeout F2: a capability presented for verification is
    /// revoked (path-binding mismatch, unreachable chain, or an explicit
    /// marker at `system/capability/revocations/{root_hash_hex}`). Surfaced
    /// only when the impl advertises `supports_revocation = true` and runs
    /// the §5.2 Step 4 `is_revoked` check. Maps to **403** to match Go's
    /// `revoked_cap_denied_on_use` matrix vector and the same family as
    /// `CapabilityExpired` (cap-rejected-at-permission-tier — distinct
    /// from `UnresolvableGrantee`/401 which is a missing-identity case).
    #[error("capability revoked")]
    CapabilityRevoked,

    /// V7 §1.2 v7.66 normative: format-code dispatch on `content_hash`.
    /// An impl receiving a `content_hash` whose leading `content_hash_format`
    /// byte it does not support SHALL return this error rather than
    /// silently failing or treating the hash as a content miss. Maps to
    /// **400** (validation/format error). Wire surface name:
    /// `unsupported_content_hash_format` per V7 §4.7 v7.66 addition.
    /// Today only `0x00` (ECFv1-SHA-256) is in production use; this
    /// surface exists to gate future format-code transitions.
    #[error("unsupported content_hash_format: {0:#04x}")]
    UnsupportedContentHashFormat(u8),

    /// V7 §4.5 / §4.7 normative: the `hash_formats` negotiation produced an
    /// empty intersection — the initiator advertised no `content_hash_format`
    /// the responder supports. The `content_hash_format` is a **single
    /// active value** for the connection (§4.5a); without a common value the
    /// connection cannot be established. Maps to **400** with wire code
    /// `incompatible_hash_format` per the §4.7 error-code table.
    #[error("no common hash formats in hello negotiation")]
    IncompatibleHashFormat,

    /// V7 §4.5 / §4.7 row 1: the `protocols` negotiation produced an empty
    /// intersection — the initiator advertised no protocol version this
    /// responder speaks. §4.5's negotiation table pins `protocols` as
    /// **"Intersection, must be non-empty"**, and §4.4 requires the responder
    /// to say so explicitly rather than let the initiator infer it from
    /// silence. Maps to **400** with wire code `incompatible_protocol`.
    ///
    /// Unlike `hash_formats` and `key_types` this field has **no default**, and
    /// 0.8.2.4 resolved what that means: only a NON-EMPTY initiator set
    /// disjoint from ours earns this code, and an absent-or-empty list is
    /// [`Self::InvalidRequest`] instead — not, as we and `entity-core-go` both
    /// first shipped, unconstrained. The distinction is a MUST because the two
    /// remedies differ; see `connect::protocols_compatible` for the ruling.
    #[error("no common protocol version in hello negotiation")]
    IncompatibleProtocol,

    /// V7 §4.5 / §4.7 — the generic malformed-request code, **400
    /// `invalid_request`** (declared at core level by 0.8.2.4): "a well-formed
    /// frame whose *content* the responder cannot act on as a request."
    ///
    /// On the connect path this carries FM-2e: a hello with `protocols`
    /// **absent or empty**. `protocols` is the one negotiated field that is
    /// Required with **no default** (§4.5's table leaves that column `—`), so
    /// there is no floor to fall back to and a peer that named no version has
    /// made no version claim to compare. It is distinct from
    /// [`Self::IncompatibleProtocol`] by MUST: that code tells the caller *"we
    /// compared and share nothing"*, and the remedies differ — send the field
    /// versus change the version — which is the whole reason §4.7 selects a
    /// code at all.
    ///
    /// The message is `&'static str` rather than `String` because every
    /// construction here is a fixed spec sentence, not a formatted value.
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),

    /// V7 §4.7 normative: an inbound peer_id (handshake hello, authenticate,
    /// or cap-chain peer reference) presents a `key_type` byte not in
    /// this impl's supported set. Maps to **400** with wire code
    /// `unsupported_key_type` per the AGILITY-UNKNOWN-1 conformance
    /// vector (v7.66 §4.4 surface 6 / §7.1). Returned as a structured
    /// EXECUTE_RESPONSE (NOT a transport-level drop) so the peer can
    /// surface a clean error rather than seeing an EOF.
    #[error("unsupported key_type: {0:#04x}")]
    UnsupportedKeyType(u8),

    /// V7 §5.5 v7.66 normative: cap-chain format-code freeze (Reading A).
    /// A cap chain's links MUST share the same `content_hash_format` for
    /// the entities' own `content_hash`es. A chain that crosses
    /// format-code boundaries without a continuous signer-set re-signing
    /// event is rejected. Maps to **403** (capability_denied family —
    /// chain validity rejection, same status as M3 / `CapabilityInvalid`).
    #[error("cap chain crosses content_hash_format boundary: {0:#04x} != {1:#04x}")]
    CapabilityFormatCodeMismatch(u8, u8),

    /// V7 §5.2 step-1/step-2 authentication-class DENY (v7.71 §3.3 401 row).
    /// The EXECUTE-level identity checks — content-hash validation, author
    /// presence/resolution, EXECUTE-signature presence/signer-match/validity
    /// — are the *wire-side authentication* half of `verify_request`. v7.71
    /// §3.3 maps these to **401 `authentication_failed`**, distinct from the
    /// §5.2 step-3+ *authorization* (capability) failures which surface as
    /// 403. The same underlying conditions (missing/invalid signature, signer
    /// mismatch) occurring during step-3+ capability-chain verification keep
    /// their existing 403 mapping via the dedicated chain variants — the
    /// status is a function of WHICH §5.2 step failed, so the discrimination
    /// lives at the call site, not in the variant. Cohort oracle:
    /// `security.go` `sendAndExpectAuthDeny` (status 401).
    #[error("authentication failed: {0}")]
    AuthenticationFailed(&'static str),

    /// V7 §4.6 step 1 / §4.7 row 6: the `authenticate` did not echo the nonce
    /// this responder issued in its `hello` response (or none had been issued).
    /// **401 `invalid_nonce`** — the connection handshake is the authentication
    /// boundary (§4.6), so a nonce failure is authentication-class, never the
    /// 400 a malformed frame would earn and never a 409 state conflict (the
    /// Hardening block pins that explicitly for a replayed authenticate).
    ///
    /// Distinct from [`Self::AuthenticationFailed`] because §4.7 is a MUST-emit
    /// `(code, status)` contract: collapsing the two is non-conformant even
    /// though both are 401.
    #[error("invalid nonce: {0}")]
    InvalidNonce(&'static str),

    /// V7 §4.6 step 3 / §4.7 row 8: `authenticate.peer_id` is not the peer-id
    /// derived from `authenticate.public_key`, or it disagrees with the
    /// `hello.peer_id` for the same connection. **401 `identity_mismatch`**.
    ///
    /// Step 2 proves possession of *some* private key; step 3 is what binds
    /// that proof to the identity the caller claims. Grants resolve by
    /// `remote_peer_id`, so an unbound proof lets a caller act under another
    /// peer's identity — which is why this is its own code and not folded into
    /// `authentication_failed`.
    #[error("identity mismatch: {0}")]
    IdentityMismatch(&'static str),

    #[error("connection error: {0}")]
    ConnectionError(String),
}

impl ProtocolError {
    /// Returns true if this error represents an authorization failure
    /// (→401 or →403), as opposed to a format/validation error (→400).
    pub fn is_auth_error(&self) -> bool {
        self.wire_status_code() != STATUS_BAD_REQUEST
    }

    /// Maps this error to the wire `code` string per V7 §4.7 normative
    /// error-code registry. Stable across cohort impls — the
    /// AGILITY-UNKNOWN-1 / FORMAT-CODE-INTERPRETATION-1 / CAP-FREEZE-1 vectors
    /// assert on these exact strings. Errors without a dedicated registry
    /// entry surface as the call-site default ("verification_failed",
    /// "invalid_request", etc.); only dedicated-registry variants
    /// override here. **Not `handshake_failed`** — 0.8.2.5 names that code
    /// non-conformant outright, as a code appearing in no spec code set.
    pub fn wire_error_code(&self) -> Option<&'static str> {
        match self {
            Self::UnsupportedKeyType(_) => Some("unsupported_key_type"),
            Self::UnsupportedContentHashFormat(_) => Some("unsupported_content_hash_format"),
            Self::IncompatibleHashFormat => Some("incompatible_hash_format"),
            Self::IncompatibleProtocol => Some("incompatible_protocol"),
            Self::InvalidRequest(_) => Some("invalid_request"),
            Self::CapabilityRevoked => Some("capability_revoked"),
            // v7.71 §3.3 line 900: capability expiry (§5.6 / §5.2 validity)
            // surfaces as the default `capability_denied` — there is NO
            // separate `capability_expired` string. (Class B-Rust-2.)
            Self::CapabilityExpired => Some("capability_denied"),
            Self::CapabilityNotYetValid => Some("capability_not_yet_valid"),
            Self::AuthenticationFailed(_) => Some("authentication_failed"),
            // §4.7 rows 6 + 8 — the two connect-handshake failures that are 401
            // but are NOT `authentication_failed`. The table forbids collapsing
            // them (see the variants' docs).
            Self::InvalidNonce(_) => Some("invalid_nonce"),
            Self::IdentityMismatch(_) => Some("identity_mismatch"),
            Self::CapabilityFormatCodeMismatch(_, _) => Some("capability_denied"),
            Self::MissingEntity(_) => Some("capability_denied"),
            Self::UnresolvableGrantee => Some("unresolvable_grantee"),
            // V7 §4.10(b) v7.75: structural chain-depth excess. 400, not 403.
            Self::ChainTooDeep => Some("chain_depth_exceeded"),
            Self::InvalidSignature => Some("invalid_signature"),
            Self::MissingSignature => Some("missing_signature"),
            Self::HashMismatch => Some("hash_mismatch"),
            _ => None,
        }
    }

    /// Maps this error to the wire status code per V7 §3.3.
    ///
    /// - `401` authentication-class: `unresolvable_grantee` (PR-3 / V7 v7.39)
    ///   and `authentication_failed` (§5.2 step-1/step-2 EXECUTE identity, per
    ///   v7.71 §3.3 401 row).
    /// - `403` for the authorization (capability) failure family (chain
    ///   signature/attenuation, expiration, M3 capability-invalid, etc.).
    /// - `400` for format/validation errors (the catch-all), including
    ///   `ChainTooDeep` (§4.10(b) v7.75: a too-deep chain is a structural
    ///   excess, not an authorization denial).
    pub fn wire_status_code(&self) -> u32 {
        match self {
            // 401 authentication-class (§5.2 step-1/step-2 + PR-3 grantee), plus
            // the §4.6 proof-of-possession failures: "All proof-of-possession
            // failures above (nonce mismatch, absent/invalid signature, identity
            // mismatch) are authentication failures and MUST be reported with
            // status 401." That sentence names three failures; all three land
            // here, and only the `code` distinguishes them (§4.7).
            Self::UnresolvableGrantee
            | Self::AuthenticationFailed(_)
            | Self::InvalidNonce(_)
            | Self::IdentityMismatch(_) => STATUS_AUTH_FAILED,
            Self::CapabilityRevoked
            | Self::MissingSignature
            | Self::InvalidSignature
            | Self::SignerMismatch
            | Self::GranteeMismatch
            | Self::NotLocalPeer
            | Self::MissingCapability
            | Self::MissingCapabilityEntity
            | Self::MissingEntity(_)
            | Self::CapabilityExpired
            | Self::CapabilityNotYetValid
            | Self::AttenuationViolation
            | Self::PermissionDenied(_)
            | Self::CapabilityInvalid(_)
            | Self::CapabilityFormatCodeMismatch(_, _) => STATUS_FORBIDDEN,
            _ => STATUS_BAD_REQUEST,
        }
    }
}

const STATUS_BAD_REQUEST: u32 = 400;
const STATUS_AUTH_FAILED: u32 = 401;
const STATUS_FORBIDDEN: u32 = 403;

#[cfg(test)]
mod tests {
    use super::*;
    use entity_crypto::{IdentityKeypair, Keypair};
    use entity_entity::{Entity, Envelope, TYPE_SIGNATURE};
    use entity_hash::Hash;

    fn test_keypair() -> Keypair {
        Keypair::from_seed([42u8; 32])
    }

    /// Build a complete signed EXECUTE envelope for testing.
    fn build_test_execute(
        keypair: &Keypair,
        local_keypair: &Keypair,
        uri: &str,
        operation: &str,
    ) -> Envelope {
        let identity = keypair.peer_entity().unwrap();
        let identity_hash = identity.content_hash;
        let local_identity = local_keypair.peer_entity().unwrap();
        let local_identity_hash = local_identity.content_hash;

        // Build capability token
        let cap_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("created_at"), entity_ecf::integer(0)),
            (
                entity_ecf::text("grantee"),
                entity_ecf::Value::Bytes(identity_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("granter"),
                entity_ecf::Value::Bytes(local_identity_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("grants"),
                entity_ecf::Value::Array(vec![entity_ecf::Value::Map(vec![
                    (
                        entity_ecf::text("handlers"),
                        entity_ecf::Value::Map(vec![(
                            entity_ecf::text("include"),
                            entity_ecf::Value::Array(vec![entity_ecf::text("*")]),
                        )]),
                    ),
                    (
                        entity_ecf::text("operations"),
                        entity_ecf::Value::Map(vec![(
                            entity_ecf::text("include"),
                            entity_ecf::Value::Array(vec![entity_ecf::text("*")]),
                        )]),
                    ),
                    (
                        entity_ecf::text("resources"),
                        entity_ecf::Value::Map(vec![(
                            entity_ecf::text("include"),
                            entity_ecf::Value::Array(vec![entity_ecf::text("*")]),
                        )]),
                    ),
                ])]),
            ),
        ]));
        let cap_entity = Entity::new(entity_types::TYPE_CAP_TOKEN, cap_data).unwrap();
        let cap_hash = cap_entity.content_hash;

        // Sign capability with local keypair (granter)
        let cap_sig_bytes = local_keypair.sign(&cap_hash.to_bytes());
        let cap_sig_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("algorithm"), entity_ecf::text("ed25519")),
            (
                entity_ecf::text("signature"),
                entity_ecf::Value::Bytes(cap_sig_bytes.to_vec()),
            ),
            (
                entity_ecf::text("signer"),
                entity_ecf::Value::Bytes(local_identity_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("target"),
                entity_ecf::Value::Bytes(cap_hash.to_bytes().to_vec()),
            ),
        ]));
        let cap_sig = Entity::new(TYPE_SIGNATURE, cap_sig_data).unwrap();

        // Build EXECUTE entity
        let exec_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("author"),
                entity_ecf::Value::Bytes(identity_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("capability"),
                entity_ecf::Value::Bytes(cap_hash.to_bytes().to_vec()),
            ),
            (entity_ecf::text("operation"), entity_ecf::text(operation)),
            (entity_ecf::text("params"), entity_ecf::Value::Map(vec![])),
            (
                entity_ecf::text("request_id"),
                entity_ecf::text("test-req-1"),
            ),
            (entity_ecf::text("uri"), entity_ecf::text(uri)),
        ]));
        let exec_entity = Entity::new(entity_types::TYPE_EXECUTE, exec_data).unwrap();

        // Sign EXECUTE with author keypair
        let exec_sig_bytes = keypair.sign(&exec_entity.content_hash.to_bytes());
        let exec_sig_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("algorithm"), entity_ecf::text("ed25519")),
            (
                entity_ecf::text("signature"),
                entity_ecf::Value::Bytes(exec_sig_bytes.to_vec()),
            ),
            (
                entity_ecf::text("signer"),
                entity_ecf::Value::Bytes(identity_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("target"),
                entity_ecf::Value::Bytes(exec_entity.content_hash.to_bytes().to_vec()),
            ),
        ]));
        let exec_sig = Entity::new(TYPE_SIGNATURE, exec_sig_data).unwrap();

        // Assemble envelope
        let mut envelope = Envelope::new(exec_entity);
        envelope.include(identity);
        envelope.include(local_identity);
        envelope.include(cap_entity);
        envelope.include(cap_sig);
        envelope.include(exec_sig);

        envelope
    }

    #[test]
    fn test_verify_request_success() {
        let author_kp = test_keypair();
        let local_kp = Keypair::from_seed([99u8; 32]);
        let local_peer_id = local_kp.peer_id();

        let envelope = build_test_execute(&author_kp, &local_kp, "system/tree", "get");

        let result = verify_request(&envelope, local_peer_id.as_str());
        assert!(result.is_ok(), "verify_request failed: {:?}", result.err());
        let verified = result.unwrap();
        assert_eq!(verified.request_id, "test-req-1");
        assert_eq!(verified.uri, "system/tree");
        assert_eq!(verified.operation, "get");
    }

    /// Microbench mirroring the validator's reuse pattern: same envelope,
    /// same capability hash, called N times. Run with:
    ///   cargo test -p entity-protocol verify_request_perf -- --ignored --nocapture
    ///   cargo test -p entity-protocol --release verify_request_perf -- --ignored --nocapture
    #[test]
    #[ignore]
    fn verify_request_perf() {
        let author_kp = test_keypair();
        let local_kp = Keypair::from_seed([99u8; 32]);
        let local_peer_id = local_kp.peer_id();
        let envelope = build_test_execute(&author_kp, &local_kp, "system/tree", "put");

        // Warmup
        for _ in 0..50 {
            let _ = verify_request(&envelope, local_peer_id.as_str()).unwrap();
        }

        const N: u32 = 1000;
        let start = std::time::Instant::now();
        for _ in 0..N {
            let _ = verify_request(&envelope, local_peer_id.as_str()).unwrap();
        }
        let elapsed = start.elapsed();
        let per_call_us = elapsed.as_micros() as f64 / f64::from(N);
        eprintln!(
            "verify_request_perf: {} calls in {:?} ({:.1} µs/call)",
            N, elapsed, per_call_us
        );
    }

    #[test]
    fn test_verify_request_tampered_execute() {
        let author_kp = test_keypair();
        let local_kp = Keypair::from_seed([99u8; 32]);
        let local_peer_id = local_kp.peer_id();

        let mut envelope = build_test_execute(&author_kp, &local_kp, "system/tree", "get");

        envelope.root.data = entity_ecf::to_ecf(&entity_ecf::text("tampered"));

        assert!(verify_request(&envelope, local_peer_id.as_str()).is_err());
    }

    #[test]
    fn test_verify_request_wrong_signer() {
        let author_kp = test_keypair();
        let wrong_kp = Keypair::from_seed([77u8; 32]);
        let local_kp = Keypair::from_seed([99u8; 32]);
        let local_peer_id = local_kp.peer_id();

        let mut envelope = build_test_execute(&author_kp, &local_kp, "system/tree", "get");

        let wrong_sig_bytes = wrong_kp.sign(&envelope.root.content_hash.to_bytes());
        let wrong_sig_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("algorithm"), entity_ecf::text("ed25519")),
            (
                entity_ecf::text("signature"),
                entity_ecf::Value::Bytes(wrong_sig_bytes.to_vec()),
            ),
            (
                entity_ecf::text("signer"),
                entity_ecf::Value::Bytes(
                    author_kp
                        .peer_entity()
                        .unwrap()
                        .content_hash
                        .to_bytes()
                        .to_vec(),
                ),
            ),
            (
                entity_ecf::text("target"),
                entity_ecf::Value::Bytes(envelope.root.content_hash.to_bytes().to_vec()),
            ),
        ]));
        let wrong_sig = Entity::new(TYPE_SIGNATURE, wrong_sig_data).unwrap();

        let exec_hash = envelope.root.content_hash;
        envelope.included.retain(|_, e| {
            if e.entity_type != TYPE_SIGNATURE {
                return true;
            }
            if let Ok(v) = ciborium::from_reader::<ciborium::Value, _>(e.data.as_slice()) {
                if let Some(m) = v.as_map() {
                    for (k, val) in m {
                        if k.as_text() == Some("target") {
                            if let Some(b) = val.as_bytes() {
                                if let Ok(h) = Hash::from_bytes(b) {
                                    if h == exec_hash {
                                        return false;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            true
        });
        envelope.include(wrong_sig);

        // v7.71 §3.3: a bad EXECUTE signature is a §5.2 step-2 authentication
        // failure → 401 `authentication_failed`, NOT the 403 authorization
        // family. (Chain-level signature failures keep their 403 mapping.)
        let err = verify_request(&envelope, local_peer_id.as_str()).unwrap_err();
        assert!(
            matches!(err, ProtocolError::AuthenticationFailed(_)),
            "got {err:?}"
        );
        assert_eq!(err.wire_status_code(), 401);
        assert_eq!(err.wire_error_code(), Some("authentication_failed"));
    }

    #[test]
    fn test_connection_state() {
        let kp = test_keypair();
        let conn = Connection::new(kp.peer_id());
        assert_eq!(conn.state, ConnectionState::AwaitingHello);
        assert!(!conn.is_established());
    }

    #[test]
    fn test_is_connect_path() {
        assert!(Connection::is_connect_path("system/protocol/connect"));
        assert!(Connection::is_connect_path("system/protocol/connect/hello"));
        assert!(!Connection::is_connect_path("system/tree"));
    }

    /// Find the authenticate entity in an authenticate envelope's included map.
    fn find_auth_entity(envelope: &Envelope) -> &Entity {
        envelope
            .included
            .values()
            .find(|e| e.entity_type == entity_types::TYPE_AUTHENTICATE)
            .expect("authenticate entity not found in included")
    }

    #[test]
    fn test_build_authenticate_envelope() {
        let kp = test_keypair();
        let nonce = vec![1u8; 32];
        let envelope = build_authenticate_envelope(
            &IdentityKeypair::Ed25519(kp.clone_inner()),
            &nonce,
            entity_hash::HASH_ALGORITHM_SHA256,
        )
        .unwrap();
        assert!(envelope.validate_all().is_ok());
        // Root is now EXECUTE; signature targets the authenticate entity (in included)
        assert_eq!(envelope.root.entity_type, entity_types::TYPE_EXECUTE);
        let auth_entity = find_auth_entity(&envelope);
        assert!(envelope
            .find_signature_for(&auth_entity.content_hash)
            .is_some());
    }

    #[test]
    fn test_authenticate_signature_verifiable() {
        let kp = test_keypair();
        let nonce = vec![2u8; 32];
        let envelope = build_authenticate_envelope(
            &IdentityKeypair::Ed25519(kp.clone_inner()),
            &nonce,
            entity_hash::HASH_ALGORITHM_SHA256,
        )
        .unwrap();

        let auth_entity = find_auth_entity(&envelope);
        let sig_entity = envelope
            .find_signature_for(&auth_entity.content_hash)
            .unwrap();
        let sig_data = entity_types::SignatureData::from_entity(sig_entity).unwrap();

        Keypair::verify(
            &kp.public_key_bytes(),
            &auth_entity.content_hash.to_bytes(),
            &sig_data.signature,
        )
        .unwrap();
    }

    // --- New tests for Phase 3 ---

    #[test]
    fn test_hello_data_roundtrip() {
        let hello = HelloData {
            peer_id: "test-peer-123".to_string(),
            nonce: vec![1u8; 32],
            protocols: vec!["entity-core/1.0".to_string()],
            hash_formats: vec![],
            key_types: vec![],
            timestamp: Some(1234567890),
        };
        let entity = hello.to_entity().unwrap();
        assert_eq!(entity.entity_type, entity_types::TYPE_HELLO);
        let parsed = HelloData::from_entity(&entity).unwrap();
        assert_eq!(parsed.peer_id, "test-peer-123");
        assert_eq!(parsed.nonce, vec![1u8; 32]);
        assert_eq!(parsed.protocols, vec!["entity-core/1.0"]);
        assert_eq!(parsed.timestamp, Some(1234567890));
    }

    #[test]
    fn test_hello_data_minimal() {
        let hello = HelloData {
            peer_id: "peer1".to_string(),
            nonce: vec![0u8; 16],
            protocols: vec![],
            hash_formats: vec![],
            key_types: vec![],
            timestamp: None,
        };
        let entity = hello.to_entity().unwrap();
        let parsed = HelloData::from_entity(&entity).unwrap();
        assert_eq!(parsed.peer_id, "peer1");
        assert!(parsed.protocols.is_empty());
    }

    /// Helper: wrap a hello entity in an EXECUTE envelope for testing.
    fn wrap_hello_in_execute(hello_entity: &Entity) -> Envelope {
        let exec_entity = build_connect_execute("test-hello", "hello", hello_entity).unwrap();
        Envelope::new(exec_entity)
    }

    #[test]
    fn test_connection_process_hello() {
        let local_kp = Keypair::from_seed([1u8; 32]);
        let remote_kp = Keypair::from_seed([2u8; 32]);

        let mut conn = Connection::new(local_kp.peer_id());

        let remote_hello = HelloData {
            peer_id: remote_kp.peer_id().as_str().to_string(),
            nonce: vec![42u8; 32],
            protocols: vec!["entity-core/1.0".to_string()],
            hash_formats: vec![],
            key_types: vec![],
            timestamp: None,
        };
        let hello_entity = remote_hello.to_entity().unwrap();
        let hello_envelope = wrap_hello_in_execute(&hello_entity);

        let (response_hello, request_id) = conn.process_hello(&hello_envelope).unwrap();
        assert_eq!(response_hello.peer_id, local_kp.peer_id().as_str());
        assert_eq!(request_id, "test-hello");
        assert_eq!(conn.state, ConnectionState::AwaitingAuthenticate);
        assert!(conn.remote_peer_id.is_some());
    }

    #[test]
    fn test_connection_process_authenticate() {
        let local_kp = Keypair::from_seed([1u8; 32]);
        let remote_kp = Keypair::from_seed([2u8; 32]);

        let mut conn = Connection::new(local_kp.peer_id());

        // Process hello first (wrapped in EXECUTE). `protocols` is spelled out
        // because §4.5 gives it no default and 0.8.2.4 refuses the empty set at
        // `400 invalid_request` — this is a setup step for the authenticate
        // assertions below, so it has to get past the hello gate rather than
        // measure it. `hash_formats`/`key_types` stay empty on purpose: those
        // two DO have defaults, and leaving them so keeps the fixture honest
        // about which fields carry a floor.
        let remote_hello = HelloData {
            peer_id: remote_kp.peer_id().as_str().to_string(),
            nonce: vec![42u8; 32],
            protocols: default_advertised_protocols(),
            hash_formats: vec![],
            key_types: vec![],
            timestamp: None,
        };
        let hello_entity = remote_hello.to_entity().unwrap();
        conn.process_hello(&wrap_hello_in_execute(&hello_entity))
            .unwrap();

        // Build authenticate with our nonce (now wrapped in EXECUTE)
        let auth_envelope = build_authenticate_envelope(
            &IdentityKeypair::Ed25519(remote_kp.clone_inner()),
            &conn.local_nonce,
            entity_hash::HASH_ALGORITHM_SHA256,
        )
        .unwrap();

        let (remote_pid, _request_id) = conn.process_authenticate(&auth_envelope).unwrap();
        assert_eq!(remote_pid, remote_kp.peer_id());
        assert!(conn.is_established());
    }

    #[test]
    fn test_build_execute_response() {
        let result_data = entity_ecf::to_ecf(&entity_ecf::text("hello"));
        let result_entity = Entity::new("test/result", result_data).unwrap();
        let envelope = build_execute_response("req-1", 200, result_entity).unwrap();
        assert_eq!(
            envelope.root.entity_type,
            entity_types::TYPE_EXECUTE_RESPONSE
        );
        let parsed = parse_execute_response(&envelope).unwrap();
        assert_eq!(parsed.request_id, "req-1");
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.result.entity_type, "test/result");
    }

    #[test]
    fn test_build_error_response() {
        let envelope = build_error_response("req-2", 404, "not_found", "path not found").unwrap();
        let parsed = parse_execute_response(&envelope).unwrap();
        assert_eq!(parsed.request_id, "req-2");
        assert_eq!(parsed.status, 404);
        assert_eq!(parsed.result.entity_type, entity_types::TYPE_ERROR);
    }

    /// Cross-impl regression (Go↔Rust pooled-connection desync, 2026-07-19):
    /// Go's `make202Response` sends `result` as a **bare CBOR null** (0xf6),
    /// not a `{type,data,content_hash}` entity wrapper. Rust emits its own 202
    /// as a `primitive/null` entity, so a same-side round-trip never exercised
    /// the bare-null form; a cross-peer 202 ack from Go used to fail
    /// `parse_execute_response` with "params must be a CBOR map (entity)",
    /// which stranded the reader. Tolerate it: a null result parses to the
    /// same `primitive/null` entity we emit.
    #[test]
    fn test_parse_go_style_202_null_result() {
        // Hand-build Go's shape: ECF map {result: null, status: 202,
        // request_id} in canonical key order (result < status by lex,
        // request_id last by encoded-key length — same order as
        // build_execute_response_full).
        let mut data = Vec::new();
        data.push(0xA3); // map(3)
        entity_ecf::encode_cbor_text(&mut data, "result");
        data.push(0xf6); // CBOR null — the Go 202 ack shape
        entity_ecf::encode_cbor_text(&mut data, "status");
        entity_ecf::encode_cbor_uint(&mut data, 202);
        entity_ecf::encode_cbor_text(&mut data, "request_id");
        entity_ecf::encode_cbor_text(&mut data, "req-202");

        let entity = Entity::new(entity_types::TYPE_EXECUTE_RESPONSE, data).unwrap();
        let envelope = Envelope::new(entity);

        let parsed = parse_execute_response(&envelope)
            .expect("a bare-null 202 result must parse (Go make202Response shape)");
        assert_eq!(parsed.request_id, "req-202");
        assert_eq!(parsed.status, 202);
        assert_eq!(
            parsed.result.entity_type, "primitive/null",
            "null result maps to the primitive/null entity we emit for our own 202"
        );
    }

    /// Reader fast-fail path (P1 hardening): a genuinely unparseable result
    /// (here an integer — neither an entity map nor null) still errors the
    /// full parse (we do NOT over-tolerate), but `extract_response_request_id`
    /// can still recover the id so the reader fails exactly that one caller
    /// instead of dropping the frame and hanging it for the request timeout.
    #[test]
    fn test_extract_request_id_from_unparseable_response() {
        let mut data = Vec::new();
        data.push(0xA3); // map(3)
        entity_ecf::encode_cbor_text(&mut data, "result");
        entity_ecf::encode_cbor_uint(&mut data, 7); // not an entity, not null
        entity_ecf::encode_cbor_text(&mut data, "status");
        entity_ecf::encode_cbor_uint(&mut data, 200);
        entity_ecf::encode_cbor_text(&mut data, "request_id");
        entity_ecf::encode_cbor_text(&mut data, "req-bad");

        let entity = Entity::new(entity_types::TYPE_EXECUTE_RESPONSE, data).unwrap();
        let envelope = Envelope::new(entity);

        assert!(
            parse_execute_response(&envelope).is_err(),
            "a non-null malformed result must still error (no silent coercion)"
        );
        assert_eq!(
            extract_response_request_id(&envelope).as_deref(),
            Some("req-bad"),
            "reader can still recover request_id to fast-fail that one caller"
        );
    }

    /// Full wire round-trip: build error response → encode_envelope →
    /// decode_envelope. Every byte must be well-formed CBOR per RFC 8949
    /// (no additional-info 28-30 / reserved).
    #[test]
    fn test_error_response_wire_roundtrip() {
        let envelope = build_error_response(
            "req-wire",
            404,
            "not_found",
            "path not found: /abc/system/tree/root/system/validate/trie-track",
        )
        .unwrap();

        let bytes = entity_wire::encode_envelope(&envelope);

        // Parse through ciborium — same decoder category the Go peer uses —
        // to ensure the bytes are well-formed CBOR, not just our round trip.
        let _value: ciborium::Value = ciborium::from_reader(bytes.as_slice())
            .expect("encoded envelope must be well-formed CBOR");

        let round_tripped = entity_wire::decode_envelope(&bytes).unwrap();
        let parsed = parse_execute_response(&round_tripped).unwrap();
        assert_eq!(parsed.request_id, "req-wire");
        assert_eq!(parsed.status, 404);
        assert_eq!(parsed.result.entity_type, entity_types::TYPE_ERROR);
    }

    /// WB-27 / EXTENSION-CONTINUATION v1.20 §3.10.4: the mirror-pointer
    /// pattern adds an optional `rejected_marker` field to `ErrorData`.
    /// Round-trip pin: building with `Some(hash)` encodes the field; the
    /// extractor reads it back exactly.
    #[test]
    fn test_error_response_with_rejected_marker() {
        let marker_hash = entity_hash::Hash::from_bytes(&[
            0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0xaa, 0xbb,
        ])
        .unwrap();
        let envelope = build_error_response_with_marker(
            "req-wb27",
            403,
            "capability_denied",
            "capability does not grant access",
            Some(marker_hash),
        )
        .unwrap();
        let bytes = entity_wire::encode_envelope(&envelope);
        let _: ciborium::Value = ciborium::from_reader(bytes.as_slice())
            .expect("ErrorData with rejected_marker must be well-formed CBOR");
        let round_tripped = entity_wire::decode_envelope(&bytes).unwrap();
        let parsed = parse_execute_response(&round_tripped).unwrap();
        assert_eq!(parsed.status, 403);
        let extracted = extract_rejected_marker(&parsed.result)
            .expect("rejected_marker must be present on round-trip");
        assert_eq!(extracted, marker_hash, "marker hash round-trips exactly");
    }

    /// Absent `rejected_marker` → wire bytes byte-identical to
    /// `build_error_response` (additive-optional contract).
    #[test]
    fn test_error_response_without_rejected_marker_unchanged() {
        let plain = build_error_response("r", 404, "not_found", "missing").unwrap();
        let with_none =
            build_error_response_with_marker("r", 404, "not_found", "missing", None).unwrap();
        assert_eq!(
            entity_wire::encode_envelope(&plain),
            entity_wire::encode_envelope(&with_none),
            "None rejected_marker MUST be byte-identical to no-marker path"
        );
    }

    /// `extract_rejected_marker` returns None on non-error entities + on
    /// error entities without the field (defensive).
    #[test]
    fn test_extract_rejected_marker_negative() {
        let result =
            Entity::new("test/result", entity_ecf::to_ecf(&entity_ecf::text("x"))).unwrap();
        assert!(
            extract_rejected_marker(&result).is_none(),
            "non-error entity"
        );
        let plain_err = build_error_response("r", 404, "not_found", "missing").unwrap();
        let parsed = parse_execute_response(&plain_err).unwrap();
        assert!(
            extract_rejected_marker(&parsed.result).is_none(),
            "error entity without rejected_marker"
        );
    }

    /// Absent durability marker → response shape is byte-identical to before
    /// (durability-unaware consumers unaffected; EXTENSION-DURABILITY §5).
    #[test]
    fn test_response_without_durability_unchanged() {
        let result =
            Entity::new("test/result", entity_ecf::to_ecf(&entity_ecf::text("x"))).unwrap();
        let plain = build_execute_response("r", 200, result.clone()).unwrap();
        let full_none =
            build_execute_response_full("r", 200, result, std::collections::HashMap::new(), None)
                .unwrap();
        assert_eq!(
            entity_wire::encode_envelope(&plain),
            entity_wire::encode_envelope(&full_none),
            "None durability must not alter the wire bytes"
        );
        assert!(parse_execute_response(&plain).unwrap().durability.is_none());
    }

    /// EXTENSION-DURABILITY §5 — the durability verdict is a bare CBOR map of
    /// the field set (NOT a `{type, data, content_hash}` entity wrapper).
    /// The cross-impl validator decodes it as a flat struct; wrapping it
    /// hides the fields from durability-aware consumers (Rust v7.47 / pre-
    /// extraction bug, now part of EXTENSION-DURABILITY's pinned shape).
    #[test]
    fn test_durability_field_wire_roundtrip() {
        let dur_cbor = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("requested"),
                entity_ecf::text("replicated"),
            ),
            (entity_ecf::text("applied"), entity_ecf::text("none")),
            (entity_ecf::text("committed"), entity_ecf::text("stored")),
        ]));
        let result = Entity::new("primitive/null", vec![0xf6]).unwrap();

        let envelope = build_execute_response_full(
            "req-dur",
            202,
            result,
            std::collections::HashMap::new(),
            Some(dur_cbor),
        )
        .unwrap();

        let bytes = entity_wire::encode_envelope(&envelope);
        let _value: ciborium::Value = ciborium::from_reader(bytes.as_slice())
            .expect("encoded envelope must be well-formed CBOR");

        let round_tripped = entity_wire::decode_envelope(&bytes).unwrap();
        let parsed = parse_execute_response(&round_tripped).unwrap();
        assert_eq!(parsed.request_id, "req-dur");
        assert_eq!(parsed.status, 202);

        let dur = parsed.durability.expect("durability field must be present");
        let m = dur.as_map().expect("durability MUST be a bare CBOR map");
        let field = |name: &str| {
            m.iter()
                .find(|(k, _)| k.as_text() == Some(name))
                .and_then(|(_, v)| v.as_text())
                .map(|s| s.to_string())
        };
        assert_eq!(field("requested").as_deref(), Some("replicated"));
        assert_eq!(field("applied").as_deref(), Some("none"));
        assert_eq!(field("committed").as_deref(), Some("stored"));
        // Defense against re-wrapping regression — a wrapper would expose
        // {type, data, content_hash} as the outer map keys.
        for k in m.iter().map(|(k, _)| k.as_text()) {
            assert!(
                !matches!(k, Some("type") | Some("data") | Some("content_hash")),
                "wire shape MUST be the bare struct, never an entity wrapper"
            );
        }
    }

    // -------------------------------------------------------------------
    // collect_authority_chain + check_creator_authority
    // (V7 §5.5, PROPOSAL-UNIFIED-CHAIN-WALK-PRIMITIVE)
    // -------------------------------------------------------------------

    /// Build a capability entity with the given granter, grantee, and optional parent.
    /// Only the fields the chain-walk reads are populated; signatures are not constructed.
    fn make_cap_entity(granter: Hash, grantee: Hash, parent: Option<Hash>) -> Entity {
        let mut fields = vec![
            (entity_ecf::text("created_at"), entity_ecf::integer(0)),
            (
                entity_ecf::text("grantee"),
                entity_ecf::Value::Bytes(grantee.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("granter"),
                entity_ecf::Value::Bytes(granter.to_bytes().to_vec()),
            ),
            (entity_ecf::text("grants"), entity_ecf::Value::Array(vec![])),
        ];
        if let Some(p) = parent {
            fields.push((
                entity_ecf::text("parent"),
                entity_ecf::Value::Bytes(p.to_bytes().to_vec()),
            ));
        }
        Entity::new(
            entity_types::TYPE_CAP_TOKEN,
            entity_ecf::to_ecf(&entity_ecf::Value::Map(fields)),
        )
        .unwrap()
    }

    #[test]
    fn test_collect_chain_root_only() {
        // Single root cap, parent=None → returns [root], no error.
        let local = Hash::compute("test", b"local-peer-identity");
        let grantee = Hash::compute("test", b"grantee-identity");
        let root = make_cap_entity(local, grantee, None);
        let store: std::collections::HashMap<Hash, Entity> =
            [(root.content_hash, root.clone())].into();
        let chain = collect_authority_chain(&root.content_hash, |h| store.get(h).cloned()).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].0.content_hash, root.content_hash);
    }

    #[test]
    fn test_collect_chain_three_levels_leaf_to_root() {
        // root(granter=A,grantee=B), mid(granter=B,grantee=C,parent=root),
        // leaf(granter=C,grantee=D,parent=mid). Walk from leaf returns [leaf, mid, root].
        let a = Hash::compute("test", b"A");
        let b = Hash::compute("test", b"B");
        let c = Hash::compute("test", b"C");
        let d = Hash::compute("test", b"D");
        let root = make_cap_entity(a, b, None);
        let mid = make_cap_entity(b, c, Some(root.content_hash));
        let leaf = make_cap_entity(c, d, Some(mid.content_hash));
        let store: std::collections::HashMap<Hash, Entity> = [
            (root.content_hash, root.clone()),
            (mid.content_hash, mid.clone()),
            (leaf.content_hash, leaf.clone()),
        ]
        .into();
        let chain = collect_authority_chain(&leaf.content_hash, |h| store.get(h).cloned()).unwrap();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].0.content_hash, leaf.content_hash);
        assert_eq!(chain[1].0.content_hash, mid.content_hash);
        assert_eq!(chain[2].0.content_hash, root.content_hash);
    }

    #[test]
    fn missing_entity_classifies_as_403_capability_denied() {
        // V7 §3.3 / PR-8.2 (TV-RV-1.14): an EXECUTE whose presented cap
        // can't be authenticated because a chain link or its granter
        // identity is absent from `envelope.included` is a 403
        // `capability_denied`, matching Go's `ErrCapabilityDenied`. NOT a
        // 400 verification_failed — the sibling Missing* variants are also
        // 403, and an unverifiable cap is an authority failure.
        for which in ["granter identity", "capability in chain"] {
            let e = ProtocolError::MissingEntity(which);
            assert_eq!(e.wire_status_code(), 403, "{which}: status");
            assert_eq!(
                e.wire_error_code(),
                Some("capability_denied"),
                "{which}: code"
            );
        }
    }

    #[test]
    fn test_collect_chain_unreachable_leaf() {
        // Leaf hash isn't even in the resolver.
        let store: std::collections::HashMap<Hash, Entity> = std::collections::HashMap::new();
        let missing = Hash::compute("test", b"missing");
        let err = collect_authority_chain(&missing, |h| store.get(h).cloned()).unwrap_err();
        assert_eq!(err, ChainWalkError::Unreachable);
    }

    #[test]
    fn test_collect_chain_unreachable_parent() {
        // Leaf is present but its parent is fabricated.
        let writer = Hash::compute("test", b"writer");
        let phantom = Hash::compute("test", b"phantom-parent");
        let leaf = make_cap_entity(writer, writer, Some(phantom));
        let store: std::collections::HashMap<Hash, Entity> =
            [(leaf.content_hash, leaf.clone())].into();
        let err =
            collect_authority_chain(&leaf.content_hash, |h| store.get(h).cloned()).unwrap_err();
        assert_eq!(err, ChainWalkError::Unreachable);
    }

    // -------------------------------------------------------------------
    // is_operator_class_for (GUIDE-CAPABILITIES §10 v1.2.1 Ruling 1)
    // -------------------------------------------------------------------

    /// Build a capability entity with a single grant carrying the given
    /// resources.include list. Other GrantEntry fields are populated with
    /// empty defaults so CapabilityToken::from_entity succeeds.
    fn make_cap_with_resources(
        granter: Hash,
        grantee: Hash,
        parent: Option<Hash>,
        resources_include: &[&str],
    ) -> Entity {
        let res_array: Vec<entity_ecf::Value> = resources_include
            .iter()
            .map(|s| entity_ecf::text(*s))
            .collect();
        let grant_entry = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("handlers"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("include"),
                    entity_ecf::Value::Array(vec![entity_ecf::text("*")]),
                )]),
            ),
            (
                entity_ecf::text("operations"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("include"),
                    entity_ecf::Value::Array(vec![entity_ecf::text("*")]),
                )]),
            ),
            (
                entity_ecf::text("resources"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("include"),
                    entity_ecf::Value::Array(res_array),
                )]),
            ),
        ]);
        let mut fields = vec![
            (entity_ecf::text("created_at"), entity_ecf::integer(0)),
            (
                entity_ecf::text("grantee"),
                entity_ecf::Value::Bytes(grantee.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("granter"),
                entity_ecf::Value::Bytes(granter.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("grants"),
                entity_ecf::Value::Array(vec![grant_entry]),
            ),
        ];
        if let Some(p) = parent {
            fields.push((
                entity_ecf::text("parent"),
                entity_ecf::Value::Bytes(p.to_bytes().to_vec()),
            ));
        }
        Entity::new(
            entity_types::TYPE_CAP_TOKEN,
            entity_ecf::to_ecf(&entity_ecf::Value::Map(fields)),
        )
        .unwrap()
    }

    #[test]
    fn test_operator_class_single_hop_root_grant_passes() {
        // Single-link chain: root cap with resources covering target.
        // Root's granter matches the supplied identity hash → operator-class.
        let identity = Hash::compute("test", b"L0-bootstrap-identity");
        let grantee = Hash::compute("test", b"app-handler");
        let root = make_cap_with_resources(identity, grantee, None, &["system/capability"]);
        let store: std::collections::HashMap<Hash, Entity> =
            [(root.content_hash, root.clone())].into();
        let ok = is_operator_class_for(
            &root.content_hash,
            "system/capability/grants",
            &identity,
            |h| store.get(h).cloned(),
        );
        assert!(
            ok,
            "single-hop explicit-prefix root grant is operator-class"
        );
    }

    #[test]
    fn test_operator_class_wildcard_intermediate_rejects() {
        // Two-link chain: root has explicit resources; intermediate has
        // wildcard `*` resources. Wildcards don't count even when they
        // match → not operator-class.
        let identity = Hash::compute("test", b"L0-identity");
        let mid_grantee = Hash::compute("test", b"middle-actor");
        let leaf_grantee = Hash::compute("test", b"leaf-actor");
        let root = make_cap_with_resources(identity, mid_grantee, None, &["system/capability"]);
        let leaf =
            make_cap_with_resources(mid_grantee, leaf_grantee, Some(root.content_hash), &["*"]);
        let store: std::collections::HashMap<Hash, Entity> = [
            (root.content_hash, root.clone()),
            (leaf.content_hash, leaf.clone()),
        ]
        .into();
        let ok = is_operator_class_for(
            &leaf.content_hash,
            "system/capability/grants",
            &identity,
            |h| store.get(h).cloned(),
        );
        assert!(
            !ok,
            "wildcard at intermediate link must reject — threat-model anchor"
        );
    }

    #[test]
    fn test_operator_class_wrong_root_identity_rejects() {
        // Chain roots at parent=None but the root's granter is not the
        // supplied identity hash → not operator-class.
        let claimed_identity = Hash::compute("test", b"local-peer");
        let actual_root_granter = Hash::compute("test", b"some-other-peer");
        let grantee = Hash::compute("test", b"grantee");
        let root =
            make_cap_with_resources(actual_root_granter, grantee, None, &["system/capability"]);
        let store: std::collections::HashMap<Hash, Entity> =
            [(root.content_hash, root.clone())].into();
        let ok = is_operator_class_for(
            &root.content_hash,
            "system/capability/grants",
            &claimed_identity,
            |h| store.get(h).cloned(),
        );
        assert!(!ok, "root granter mismatch must reject");
    }

    #[test]
    fn test_operator_class_broken_chain_fails_closed() {
        // Leaf is present but references a phantom parent → chain-walk
        // returns Unreachable → fail closed.
        let identity = Hash::compute("test", b"identity");
        let grantee = Hash::compute("test", b"grantee");
        let phantom = Hash::compute("test", b"phantom-parent");
        let leaf =
            make_cap_with_resources(identity, grantee, Some(phantom), &["system/capability"]);
        let store: std::collections::HashMap<Hash, Entity> =
            [(leaf.content_hash, leaf.clone())].into();
        let ok = is_operator_class_for(
            &leaf.content_hash,
            "system/capability/grants",
            &identity,
            |h| store.get(h).cloned(),
        );
        assert!(!ok, "unreachable chain must fail closed");
    }

    #[test]
    fn test_operator_class_target_exact_match() {
        // Edge: resources.include entry equal to target (not a prefix).
        let identity = Hash::compute("test", b"identity");
        let grantee = Hash::compute("test", b"grantee");
        let root = make_cap_with_resources(identity, grantee, None, &["system/capability/grants"]);
        let store: std::collections::HashMap<Hash, Entity> =
            [(root.content_hash, root.clone())].into();
        let ok = is_operator_class_for(
            &root.content_hash,
            "system/capability/grants",
            &identity,
            |h| store.get(h).cloned(),
        );
        assert!(ok, "exact-match resource pattern is operator-class");
    }

    #[test]
    fn test_operator_class_non_prefix_resource_rejects() {
        // Edge: resources.include is path-adjacent but not a prefix
        // (e.g., `system/capability-other` vs target `system/capability/...`).
        let identity = Hash::compute("test", b"identity");
        let grantee = Hash::compute("test", b"grantee");
        let root = make_cap_with_resources(identity, grantee, None, &["system/capability-other"]);
        let store: std::collections::HashMap<Hash, Entity> =
            [(root.content_hash, root.clone())].into();
        let ok = is_operator_class_for(
            &root.content_hash,
            "system/capability/grants",
            &identity,
            |h| store.get(h).cloned(),
        );
        assert!(
            !ok,
            "lexically-adjacent but path-distinct pattern must not match \
             (segment-boundary discipline)"
        );
    }

    // -------------------------------------------------------------------
    // collect_chain_bundle (EXTENSION-CONTINUATION §4.3 / §8.2 C-3)
    // -------------------------------------------------------------------

    /// Build the signer's signature over `cap`, bound at the V7 invariant
    /// pointer path (mirroring `core/peer::ingest`), so the bundle helper
    /// resolves it the same way a real verifier would.
    fn put_signed_cap(
        store: &mut std::collections::HashMap<Hash, Entity>,
        li: &mut std::collections::HashMap<String, Hash>,
        signer_kp: &Keypair,
        signer_id: &Entity,
        grantee: Hash,
        parent: Option<Hash>,
    ) -> Entity {
        let cap = make_cap_entity(signer_id.content_hash, grantee, parent);
        store.insert(cap.content_hash, cap.clone());
        let sig = entity_types::SignatureData {
            target: cap.content_hash,
            signer: signer_id.content_hash,
            algorithm: "ed25519".into(),
            signature: signer_kp.sign(&cap.content_hash.to_bytes()).to_vec(),
        }
        .to_entity()
        .unwrap();
        store.insert(sig.content_hash, sig.clone());
        // hex of the full 33-byte wire form, matching ingest's hex_segment.
        let hex: String = cap
            .content_hash
            .to_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let path = format!("/{}/system/signature/{}", signer_kp.peer_id().as_str(), hex);
        li.insert(path, sig.content_hash);
        cap
    }

    /// For a B-rooted chain the bundle MUST carry every entity a remote
    /// verifier needs: each cap, each granter `system/peer` identity, and
    /// each granter's signature resolved from the invariant pointer path.
    #[test]
    fn test_collect_chain_bundle() {
        let b_kp = Keypair::generate();
        let inst_kp = Keypair::generate();
        let b_id = b_kp.peer_entity().unwrap();
        let inst_id = inst_kp.peer_entity().unwrap();

        let mut store: std::collections::HashMap<Hash, Entity> = [
            (b_id.content_hash, b_id.clone()),
            (inst_id.content_hash, inst_id.clone()),
        ]
        .into();
        let mut li: std::collections::HashMap<String, Hash> = std::collections::HashMap::new();

        // root: B -> installer (B-rooted). leaf: installer -> installer, parent=root.
        let root = put_signed_cap(
            &mut store,
            &mut li,
            &b_kp,
            &b_id,
            inst_id.content_hash,
            None,
        );
        let leaf = put_signed_cap(
            &mut store,
            &mut li,
            &inst_kp,
            &inst_id,
            inst_id.content_hash,
            Some(root.content_hash),
        );

        let bundle = collect_chain_bundle(
            &leaf.content_hash,
            |h| store.get(h).cloned(),
            |p| li.get(p).cloned(),
        )
        .unwrap();

        assert!(bundle.contains_key(&leaf.content_hash), "leaf cap");
        assert!(bundle.contains_key(&root.content_hash), "root cap");
        assert!(bundle.contains_key(&b_id.content_hash), "B identity");
        assert!(
            bundle.contains_key(&inst_id.content_hash),
            "installer identity"
        );
        let sig_count = bundle
            .values()
            .filter(|e| e.entity_type == TYPE_SIGNATURE)
            .count();
        assert_eq!(sig_count, 2, "one bound signature per link");

        // A verifier reconstructing the chain from ONLY the bundle must find
        // the installer in-chain (single-sig granter of the leaf).
        let result =
            check_creator_authority(&leaf.content_hash, &inst_id.content_hash, &bundle, |h| {
                bundle.get(h).cloned()
            })
            .unwrap();
        assert!(
            result.found,
            "installer must be in-chain when verifying from the bundle alone"
        );
    }

    /// EXTENSION-CONTINUATION v1.22 §4.3: an identity the bundle MUST carry
    /// and cannot resolve fails at BUNDLE time. The pre-v1.22 behaviour
    /// omitted it and dispatched anyway, which turned a defect the dispatcher
    /// could name into a `401 UnresolvableGrantee` on the far side.
    #[test]
    fn test_collect_chain_bundle_unresolvable_identity_fails_closed() {
        let kp = Keypair::generate();
        let id = kp.peer_entity().unwrap();
        // Cap present; NO identity entity in the store.
        let cap = make_cap_entity(id.content_hash, id.content_hash, None);
        let store: std::collections::HashMap<Hash, Entity> =
            [(cap.content_hash, cap.clone())].into();
        let li: std::collections::HashMap<String, Hash> = std::collections::HashMap::new();

        let err = collect_chain_bundle(
            &cap.content_hash,
            |h| store.get(h).cloned(),
            |p| li.get(p).cloned(),
        )
        .expect_err("an unresolvable granter identity MUST fail the bundle");
        assert!(matches!(err, ChainWalkError::Unreachable));
    }

    /// The other half of the same rule: signatures stay best-effort. With the
    /// identity present but no bound signature at the invariant-pointer path,
    /// the bundle succeeds and simply carries no signature — B fails closed if
    /// it needed one.
    #[test]
    fn test_collect_chain_bundle_signature_stays_best_effort() {
        let kp = Keypair::generate();
        let id = kp.peer_entity().unwrap();
        let cap = make_cap_entity(id.content_hash, id.content_hash, None);
        let store: std::collections::HashMap<Hash, Entity> = [
            (cap.content_hash, cap.clone()),
            (id.content_hash, id.clone()),
        ]
        .into();
        let li: std::collections::HashMap<String, Hash> = std::collections::HashMap::new();

        let bundle = collect_chain_bundle(
            &cap.content_hash,
            |h| store.get(h).cloned(),
            |p| li.get(p).cloned(),
        )
        .unwrap();

        assert!(bundle.contains_key(&cap.content_hash), "cap bundled");
        assert!(bundle.contains_key(&id.content_hash), "identity bundled");
        assert!(
            !bundle.values().any(|e| e.entity_type == TYPE_SIGNATURE),
            "no signature should be present (none was resolvable)"
        );
    }

    /// v1.22 §4.3: the grantee's identity travels too — "not only for those
    /// that happen to also be a granter". This is the §4.2 case-3 shape: a
    /// third-party grantee that is neither the author nor the serving peer.
    #[test]
    fn test_collect_chain_bundle_carries_grantee_identity() {
        let granter_kp = Keypair::generate();
        let grantee_kp = Keypair::generate();
        let granter_id = granter_kp.peer_entity().unwrap();
        let grantee_id = grantee_kp.peer_entity().unwrap();

        let cap = make_cap_entity(granter_id.content_hash, grantee_id.content_hash, None);
        let mut store: std::collections::HashMap<Hash, Entity> = [
            (cap.content_hash, cap.clone()),
            (granter_id.content_hash, granter_id.clone()),
            (grantee_id.content_hash, grantee_id.clone()),
        ]
        .into();
        let li: std::collections::HashMap<String, Hash> = std::collections::HashMap::new();

        let bundle = collect_chain_bundle(
            &cap.content_hash,
            |h| store.get(h).cloned(),
            |p| li.get(p).cloned(),
        )
        .unwrap();
        assert!(
            bundle.contains_key(&grantee_id.content_hash),
            "grantee identity MUST be in the bundle — V7 §5.5 step 2a resolves \
             every link's grantee against `included`"
        );

        // Drop the grantee identity: the same bundle MUST now fail, which is
        // what makes the row above load-bearing rather than incidental.
        store.remove(&grantee_id.content_hash);
        let err = collect_chain_bundle(
            &cap.content_hash,
            |h| store.get(h).cloned(),
            |p| li.get(p).cloned(),
        )
        .expect_err("an unresolvable grantee identity MUST fail the bundle");
        assert!(matches!(err, ChainWalkError::Unreachable));
    }

    // -------------------------------------------------------------------
    // V7.62 §5.1 is_revoked + capability_path_for_scan
    // -------------------------------------------------------------------

    #[test]
    fn test_is_revoked_marker_revokes_wire_only_cap() {
        // Wire-only cap (capability_path_for returns None) is revoked iff
        // the marker exists at /{peer}/system/capability/revocations/{hex}.
        let local = Hash::compute("test", b"local");
        let grantee = Hash::compute("test", b"grantee");
        let cap = make_cap_entity(local, grantee, None);
        let store: std::collections::HashMap<Hash, Entity> =
            [(cap.content_hash, cap.clone())].into();
        let marker_hash = Hash::compute("test", b"marker");
        let mut li: std::collections::HashMap<String, Hash> = std::collections::HashMap::new();
        li.insert(
            format!(
                "/peer-x/system/capability/revocations/{}",
                cap.content_hash.to_hex()
            ),
            marker_hash,
        );

        let revoked = crate::verify::is_revoked(
            &cap.content_hash,
            "peer-x",
            |h| store.get(h).cloned(),
            |p| li.get(p).cloned(),
            |_| None, // wire-only — no storage path
        );
        assert!(revoked, "marker present at canonical path ⇒ revoked");
    }

    #[test]
    fn test_is_revoked_returns_false_for_fresh_cap() {
        // No marker, no path-binding mismatch — cap is alive.
        let local = Hash::compute("test", b"local");
        let grantee = Hash::compute("test", b"grantee");
        let cap = make_cap_entity(local, grantee, None);
        let store: std::collections::HashMap<Hash, Entity> =
            [(cap.content_hash, cap.clone())].into();
        let li: std::collections::HashMap<String, Hash> = std::collections::HashMap::new();

        let revoked = crate::verify::is_revoked(
            &cap.content_hash,
            "peer-x",
            |h| store.get(h).cloned(),
            |p| li.get(p).cloned(),
            |_| None,
        );
        assert!(!revoked);
    }

    #[test]
    fn test_is_revoked_path_binding_missing_revokes() {
        // capability_path_for returns Some(path), but locate(path) returns
        // None → bound entity deleted → revoked.
        let local = Hash::compute("test", b"local");
        let grantee = Hash::compute("test", b"grantee");
        let cap = make_cap_entity(local, grantee, None);
        let store: std::collections::HashMap<Hash, Entity> =
            [(cap.content_hash, cap.clone())].into();
        let li: std::collections::HashMap<String, Hash> = std::collections::HashMap::new(); // path NOT bound
        let cap_path = "/peer-x/system/capability/grants/local/handler".to_string();

        let revoked = crate::verify::is_revoked(
            &cap.content_hash,
            "peer-x",
            |h| store.get(h).cloned(),
            |p| li.get(p).cloned(),
            |_| Some(cap_path.clone()),
        );
        assert!(
            revoked,
            "path-bound cap whose tree entry vanished ⇒ revoked"
        );
    }

    #[test]
    fn test_is_revoked_path_binding_mismatch_revokes() {
        // locate(path) returns a hash that doesn't match the cap → revoked
        // (the tree binding has been overwritten with a different entity).
        let local = Hash::compute("test", b"local");
        let grantee = Hash::compute("test", b"grantee");
        let cap = make_cap_entity(local, grantee, None);
        let store: std::collections::HashMap<Hash, Entity> =
            [(cap.content_hash, cap.clone())].into();
        let other_hash = Hash::compute("test", b"other");
        let cap_path = "/peer-x/system/capability/grants/local/handler".to_string();
        let mut li: std::collections::HashMap<String, Hash> = std::collections::HashMap::new();
        li.insert(cap_path.clone(), other_hash); // different entity bound

        let revoked = crate::verify::is_revoked(
            &cap.content_hash,
            "peer-x",
            |h| store.get(h).cloned(),
            |p| li.get(p).cloned(),
            |_| Some(cap_path.clone()),
        );
        assert!(revoked, "tree binding mismatch ⇒ revoked");
    }

    #[test]
    fn test_is_revoked_unreachable_chain_fails_closed() {
        // Leaf isn't in the store at all — the chain walk fails, and §5.1
        // requires fail-closed (treat as revoked).
        let phantom = Hash::compute("test", b"phantom");
        let store: std::collections::HashMap<Hash, Entity> = std::collections::HashMap::new();
        let li: std::collections::HashMap<String, Hash> = std::collections::HashMap::new();
        let revoked = crate::verify::is_revoked(
            &phantom,
            "peer-x",
            |h| store.get(h).cloned(),
            |p| li.get(p).cloned(),
            |_| None,
        );
        assert!(revoked, "unresolvable chain ⇒ revoked (fail-closed)");
    }

    #[test]
    fn test_is_revoked_walks_chain_to_root_for_marker_check() {
        // Marker is on the ROOT cap, not the leaf — is_revoked must walk
        // to root before testing the marker path.
        let a = Hash::compute("test", b"A");
        let b = Hash::compute("test", b"B");
        let c = Hash::compute("test", b"C");
        let root = make_cap_entity(a, b, None);
        let leaf = make_cap_entity(b, c, Some(root.content_hash));
        let store: std::collections::HashMap<Hash, Entity> = [
            (root.content_hash, root.clone()),
            (leaf.content_hash, leaf.clone()),
        ]
        .into();
        let mut li: std::collections::HashMap<String, Hash> = std::collections::HashMap::new();
        li.insert(
            format!(
                "/peer-x/system/capability/revocations/{}",
                root.content_hash.to_hex()
            ),
            Hash::compute("test", b"marker"),
        );

        let revoked = crate::verify::is_revoked(
            &leaf.content_hash,
            "peer-x",
            |h| store.get(h).cloned(),
            |p| li.get(p).cloned(),
            |_| None,
        );
        assert!(revoked, "root marker ⇒ entire chain revoked");
    }

    #[test]
    fn test_capability_path_for_scan_hits() {
        let cap_hash = Hash::compute("test", b"cap");
        let path = "/peer-x/system/capability/grants/local/files".to_string();
        let entries = vec![(path.clone(), cap_hash)];
        let result =
            crate::verify::capability_path_for_scan(&cap_hash, "peer-x", |_prefix| entries.clone());
        assert_eq!(result, Some(path));
    }

    #[test]
    fn test_capability_path_for_scan_miss_returns_none() {
        let cap_hash = Hash::compute("test", b"cap");
        let other_hash = Hash::compute("test", b"other");
        let entries = vec![(
            "/peer-x/system/capability/grants/local/files".to_string(),
            other_hash,
        )];
        let result =
            crate::verify::capability_path_for_scan(&cap_hash, "peer-x", |_prefix| entries.clone());
        assert_eq!(result, None);
    }

    #[test]
    fn test_check_creator_authority_root_match() {
        let local = Hash::compute("test", b"local-peer-identity");
        let grantee = Hash::compute("test", b"grantee-identity");
        let root = make_cap_entity(local, grantee, None);
        let store: std::collections::HashMap<Hash, Entity> =
            [(root.content_hash, root.clone())].into();
        let included = std::collections::HashMap::new();
        let res = check_creator_authority(&root.content_hash, &local, &included, |h| {
            store.get(h).cloned()
        })
        .unwrap();
        assert!(res.found);
        assert_eq!(res.chain.len(), 1);
    }

    #[test]
    fn test_check_creator_authority_intermediate_match() {
        // Writer matches mid-level granter; chain returned in full.
        let a = Hash::compute("test", b"A");
        let b = Hash::compute("test", b"B");
        let c = Hash::compute("test", b"C");
        let root = make_cap_entity(a, b, None);
        let child = make_cap_entity(b, c, Some(root.content_hash));
        let store: std::collections::HashMap<Hash, Entity> = [
            (root.content_hash, root.clone()),
            (child.content_hash, child.clone()),
        ]
        .into();
        let included = std::collections::HashMap::new();
        let res = check_creator_authority(&child.content_hash, &b, &included, |h| {
            store.get(h).cloned()
        })
        .unwrap();
        assert!(res.found);
        assert_eq!(res.chain.len(), 2);
    }

    #[test]
    fn test_check_creator_authority_not_in_chain() {
        let a = Hash::compute("test", b"A");
        let b = Hash::compute("test", b"B");
        let c = Hash::compute("test", b"C");
        let stranger = Hash::compute("test", b"stranger");
        let root = make_cap_entity(a, b, None);
        let child = make_cap_entity(b, c, Some(root.content_hash));
        let store: std::collections::HashMap<Hash, Entity> = [
            (root.content_hash, root.clone()),
            (child.content_hash, child.clone()),
        ]
        .into();
        let included = std::collections::HashMap::new();
        let res = check_creator_authority(&child.content_hash, &stranger, &included, |h| {
            store.get(h).cloned()
        })
        .unwrap();
        assert!(!res.found);
        // Chain still returned even when identity not found — caller decides
        // whether to use it (per proposal: persist only on found=true).
        assert_eq!(res.chain.len(), 2);
    }

    #[test]
    fn test_check_creator_authority_unreachable_takes_precedence_over_leaf_match() {
        // Adversarial: leaf granter == writer, parent fabricated. The collect-
        // first design makes Unreachable structurally guaranteed before identity
        // is checked. Go r1_install_chain_unreachable vector.
        let writer = Hash::compute("test", b"writer");
        let phantom = Hash::compute("test", b"fabricated-admin-cap");
        let leaf = make_cap_entity(writer, writer, Some(phantom));
        let store: std::collections::HashMap<Hash, Entity> =
            [(leaf.content_hash, leaf.clone())].into();
        let included = std::collections::HashMap::new();
        let err = check_creator_authority(&leaf.content_hash, &writer, &included, |h| {
            store.get(h).cloned()
        })
        .unwrap_err();
        assert_eq!(err, ChainWalkError::Unreachable);
    }

    #[test]
    fn test_check_creator_authority_resolver_composition() {
        // Resolver pattern: envelope first, store fallback.
        let a = Hash::compute("test", b"A");
        let b = Hash::compute("test", b"B");
        let c = Hash::compute("test", b"C");
        let root = make_cap_entity(a, b, None);
        let child = make_cap_entity(b, c, Some(root.content_hash));
        let envelope: std::collections::HashMap<Hash, Entity> =
            [(child.content_hash, child.clone())].into();
        let store: std::collections::HashMap<Hash, Entity> =
            [(root.content_hash, root.clone())].into();
        let included = std::collections::HashMap::new();
        let res = check_creator_authority(&child.content_hash, &a, &included, |h| {
            envelope.get(h).cloned().or_else(|| store.get(h).cloned())
        })
        .unwrap();
        assert!(res.found);
        assert_eq!(res.chain.len(), 2);
    }

    /// The error-entity payload itself must be well-formed CBOR with the
    /// expected `{code, message}` shape.
    #[test]
    fn test_error_entity_body_is_well_formed() {
        let envelope = build_error_response("r", 404, "not_found", "path not found: abc").unwrap();
        // The inline error entity travels on the wire both as `root.data.result`
        // and as an included entity — both surfaces must decode cleanly.
        for (_, inc) in envelope.included.iter() {
            let value: ciborium::Value = ciborium::from_reader(inc.data.as_slice())
                .expect("error entity data must be well-formed CBOR");
            let map = value.as_map().expect("error data must be a map");
            let code = map
                .iter()
                .find(|(k, _)| k.as_text() == Some("code"))
                .and_then(|(_, v)| v.as_text());
            let msg = map
                .iter()
                .find(|(k, _)| k.as_text() == Some("message"))
                .and_then(|(_, v)| v.as_text());
            assert_eq!(code, Some("not_found"));
            assert_eq!(msg, Some("path not found: abc"));
        }
    }

    // -------------------------------------------------------------------
    // PR-3 / V7 v7.39 §3.6 + §5.5 — TV-CAP-ZERO-GRANTEE
    // (PROPOSAL-ROLE-V2.0-PRODUCTION-READINESS)
    // -------------------------------------------------------------------

    /// Build a single-cap chain (root, parent: null) with the given grantee,
    /// signed by `local_kp`. Returns (cap_hash, included_map).
    fn build_zero_grantee_chain(
        local_kp: &Keypair,
        grantee: Hash,
    ) -> (Hash, std::collections::BTreeMap<Hash, Entity>) {
        let local_identity = local_kp.peer_entity().unwrap();
        let local_identity_hash = local_identity.content_hash;

        let cap_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("created_at"), entity_ecf::integer(0)),
            (
                entity_ecf::text("grantee"),
                entity_ecf::Value::Bytes(grantee.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("granter"),
                entity_ecf::Value::Bytes(local_identity_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("grants"),
                entity_ecf::Value::Array(vec![entity_ecf::Value::Map(vec![(
                    entity_ecf::text("operations"),
                    entity_ecf::Value::Map(vec![(
                        entity_ecf::text("include"),
                        entity_ecf::Value::Array(vec![entity_ecf::text("*")]),
                    )]),
                )])]),
            ),
        ]));
        let cap = Entity::new(entity_types::TYPE_CAP_TOKEN, cap_data).unwrap();
        let cap_hash = cap.content_hash;

        let sig_bytes = local_kp.sign(&cap_hash.to_bytes());
        let sig_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("algorithm"), entity_ecf::text("ed25519")),
            (
                entity_ecf::text("signature"),
                entity_ecf::Value::Bytes(sig_bytes.to_vec()),
            ),
            (
                entity_ecf::text("signer"),
                entity_ecf::Value::Bytes(local_identity_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("target"),
                entity_ecf::Value::Bytes(cap_hash.to_bytes().to_vec()),
            ),
        ]));
        let sig = Entity::new(TYPE_SIGNATURE, sig_data).unwrap();

        let mut included = std::collections::BTreeMap::new();
        included.insert(local_identity_hash, local_identity);
        included.insert(cap_hash, cap);
        included.insert(sig.content_hash, sig);
        (cap_hash, included)
    }

    /// TV-CAP-ZERO-GRANTEE: a cap whose `grantee` is the zero hash MUST be
    /// rejected with `UnresolvableGrantee` (401). Bearer-cap rejection per
    /// PROPOSAL-ROLE-V2.0-PRODUCTION-READINESS PR-3.
    #[test]
    fn test_chain_rejects_zero_grantee() {
        let local_kp = Keypair::from_seed([99u8; 32]);
        let local_peer_id = local_kp.peer_id();
        let (cap_hash, included) = build_zero_grantee_chain(&local_kp, Hash::zero());
        let err =
            verify_capability_chain(&cap_hash, &included, local_peer_id.as_str()).unwrap_err();
        assert!(
            matches!(err, ProtocolError::UnresolvableGrantee),
            "expected UnresolvableGrantee, got {err:?}"
        );
        assert_eq!(err.wire_status_code(), 401);
        assert!(err.is_auth_error());
    }

    /// Same shape as TV-CAP-ZERO-GRANTEE but with a non-zero hash that just
    /// doesn't appear in `included`. Confirms the rejection isn't keyed on
    /// the zero-hash sentinel — any unresolvable grantee is rejected.
    #[test]
    fn test_chain_rejects_unresolvable_nonzero_grantee() {
        let local_kp = Keypair::from_seed([99u8; 32]);
        let local_peer_id = local_kp.peer_id();
        let phantom = Hash::compute("test", b"identity-not-in-included");
        let (cap_hash, included) = build_zero_grantee_chain(&local_kp, phantom);
        let err =
            verify_capability_chain(&cap_hash, &included, local_peer_id.as_str()).unwrap_err();
        assert!(matches!(err, ProtocolError::UnresolvableGrantee));
    }

    /// Sanity check that a wrong-type entity at the grantee hash is also
    /// rejected — `included.get(grantee)` returning a non-`system/peer`
    /// entity must fail closed, not pass.
    #[test]
    fn test_chain_rejects_grantee_resolves_to_wrong_type() {
        let local_kp = Keypair::from_seed([99u8; 32]);
        let local_peer_id = local_kp.peer_id();

        // Build a non-identity entity and use its hash as the cap's grantee.
        let bogus = Entity::new(
            "system/role",
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                entity_ecf::text("name"),
                entity_ecf::text("decoy"),
            )])),
        )
        .unwrap();
        let bogus_hash = bogus.content_hash;
        let (cap_hash, mut included) = build_zero_grantee_chain(&local_kp, bogus_hash);
        included.insert(bogus_hash, bogus);

        let err =
            verify_capability_chain(&cap_hash, &included, local_peer_id.as_str()).unwrap_err();
        assert!(matches!(err, ProtocolError::UnresolvableGrantee));
    }

    /// Build a valid self-rooted single-link chain carrying `resources_exclude`
    /// on its one grant, signed by `local_kp`. Grantee is the local identity, so
    /// the §5.5 grantee-resolution pass is satisfied.
    fn build_self_chain_with_resource_exclude(
        local_kp: &Keypair,
        exclude: &str,
    ) -> (Hash, std::collections::BTreeMap<Hash, Entity>) {
        let local_identity = local_kp.peer_entity().unwrap();
        let local_identity_hash = local_identity.content_hash;

        let cap_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("created_at"), entity_ecf::integer(0)),
            (
                entity_ecf::text("grantee"),
                entity_ecf::Value::Bytes(local_identity_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("granter"),
                entity_ecf::Value::Bytes(local_identity_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("grants"),
                entity_ecf::Value::Array(vec![entity_ecf::Value::Map(vec![
                    (
                        entity_ecf::text("handlers"),
                        entity_ecf::Value::Map(vec![(
                            entity_ecf::text("include"),
                            entity_ecf::Value::Array(vec![entity_ecf::text("*")]),
                        )]),
                    ),
                    (
                        entity_ecf::text("operations"),
                        entity_ecf::Value::Map(vec![(
                            entity_ecf::text("include"),
                            entity_ecf::Value::Array(vec![entity_ecf::text("*")]),
                        )]),
                    ),
                    (
                        entity_ecf::text("resources"),
                        entity_ecf::Value::Map(vec![
                            (
                                entity_ecf::text("exclude"),
                                entity_ecf::Value::Array(vec![entity_ecf::text(exclude)]),
                            ),
                            (
                                entity_ecf::text("include"),
                                entity_ecf::Value::Array(vec![entity_ecf::text("/*/*")]),
                            ),
                        ]),
                    ),
                ])]),
            ),
        ]));
        let cap = Entity::new(entity_types::TYPE_CAP_TOKEN, cap_data).unwrap();
        let cap_hash = cap.content_hash;

        let sig_bytes = local_kp.sign(&cap_hash.to_bytes());
        let sig_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("algorithm"), entity_ecf::text("ed25519")),
            (
                entity_ecf::text("signature"),
                entity_ecf::Value::Bytes(sig_bytes.to_vec()),
            ),
            (
                entity_ecf::text("signer"),
                entity_ecf::Value::Bytes(local_identity_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("target"),
                entity_ecf::Value::Bytes(cap_hash.to_bytes().to_vec()),
            ),
        ]));
        let sig = Entity::new(TYPE_SIGNATURE, sig_data).unwrap();

        let mut included = std::collections::BTreeMap::new();
        included.insert(local_identity_hash, local_identity);
        included.insert(cap_hash, cap);
        included.insert(sig.content_hash, sig);
        (cap_hash, included)
    }

    /// ⛔ **§5.5 / §5.4 (0.8.2.21): a capability carrying an unmatchable scope
    /// pattern is INVALID at chain verification, not merely evaluated as though
    /// the pattern were absent.**
    ///
    /// The verification surface is where the `MUST` earns its strength. An
    /// unmatchable `exclude` carves out nothing, so a peer that honours the
    /// capability and a peer that refuses it reach **different authorization
    /// decisions on the same capability bytes** — a cross-peer divergence, not
    /// a local policy choice, which is the one thing a `MAY` here could not
    /// tolerate.
    ///
    /// The control is the same chain, byte-for-byte except the exclude, with the
    /// intended `/*/…` spelling: it MUST verify. Without it this row is passed
    /// by a verifier that rejects every chain, which is the most likely way to
    /// "implement" the ruling by accident.
    #[test]
    fn a_chain_link_with_an_unmatchable_scope_pattern_is_an_invalid_capability() {
        let local_kp = Keypair::from_seed([99u8; 32]);
        let local_peer_id = local_kp.peer_id();

        let (cap_hash, included) = build_self_chain_with_resource_exclude(&local_kp, "*/secret");
        let err =
            verify_capability_chain(&cap_hash, &included, local_peer_id.as_str()).unwrap_err();
        assert!(
            matches!(err, ProtocolError::CapabilityInvalid(_)),
            "expected CapabilityInvalid, got {err:?}"
        );
        assert_eq!(
            err.wire_status_code(),
            403,
            "§3.3 status normalization: an invalid capability is 403, not a 400 \
             malformed-request"
        );

        // CONTROL: the intended spelling verifies.
        let (cap_hash, included) = build_self_chain_with_resource_exclude(&local_kp, "/*/secret");
        assert!(
            verify_capability_chain(&cap_hash, &included, local_peer_id.as_str()).is_ok(),
            "a well-formed exclude verifies — the refusal above is not a \
             verifier that rejects every chain"
        );
    }

    // -------------------------------------------------------------------
    // V7.62 closeout F2: is_revoked wired into verify_request
    // -------------------------------------------------------------------

    #[test]
    fn test_verify_request_with_ctx_passes_when_revocation_disabled() {
        // supports_revocation = false → never run the marker check, even
        // if a marker exists. Verifies the opt-in semantics: an impl that
        // chooses not to support revocation can still set the flag false.
        let author_kp = test_keypair();
        let local_kp = Keypair::from_seed([99u8; 32]);
        let local_peer_id = local_kp.peer_id();
        let envelope = build_test_execute(&author_kp, &local_kp, "system/tree", "get");

        let ctx = VerifyContext::new(local_peer_id.as_str()).with_revocation(false);
        let res = verify_request_with_ctx(&envelope, &ctx, |_| None, |_| None, |_| None);
        assert!(res.is_ok());
    }

    #[test]
    fn test_verify_request_with_ctx_rejects_wire_only_revoked_cap() {
        // F2's load-bearing case: wire-only cap (no storage path) is
        // revoked iff the marker at /{peer}/system/capability/revocations/
        // {root_hex} is present. verify_request_with_ctx MUST surface
        // ProtocolError::CapabilityRevoked → 401.
        let author_kp = test_keypair();
        let local_kp = Keypair::from_seed([99u8; 32]);
        let local_peer_id = local_kp.peer_id();
        let envelope = build_test_execute(&author_kp, &local_kp, "system/tree", "get");

        let cap_hash = decode_execute_capability(&envelope.root.data);
        let mut li: std::collections::HashMap<String, Hash> = std::collections::HashMap::new();
        li.insert(
            format!(
                "/{}/system/capability/revocations/{}",
                local_peer_id.as_str(),
                cap_hash.to_hex()
            ),
            Hash::compute("test", b"marker"),
        );

        let ctx = VerifyContext::new(local_peer_id.as_str()).with_revocation(true);
        let included = envelope.included.clone();
        let err = verify_request_with_ctx(
            &envelope,
            &ctx,
            |h| included.get(h).cloned(),
            |p| li.get(p).cloned(),
            |_| None, // wire-only — no storage path
        )
        .unwrap_err();
        assert!(matches!(err, ProtocolError::CapabilityRevoked));
        assert_eq!(err.wire_status_code(), 403);
    }

    #[test]
    fn test_verify_request_with_ctx_rejects_bound_path_revoked_cap() {
        // Path-bound cap whose tree entry was unbound: capability_path_for
        // returns Some(path), locate(path) returns None → revoked.
        // Distinguishes from wire-only revocation: this works even with
        // no marker, by the §5.1 path-binding mismatch rule.
        let author_kp = test_keypair();
        let local_kp = Keypair::from_seed([99u8; 32]);
        let local_peer_id = local_kp.peer_id();
        let envelope = build_test_execute(&author_kp, &local_kp, "system/tree", "get");

        let cap_path = format!(
            "/{}/system/capability/grants/local/handler",
            local_peer_id.as_str()
        );
        let ctx = VerifyContext::new(local_peer_id.as_str()).with_revocation(true);
        let included = envelope.included.clone();
        let cap_path_for_closure = cap_path.clone();
        let err = verify_request_with_ctx(
            &envelope,
            &ctx,
            |h| included.get(h).cloned(),
            |_| None, // path NOT bound — unbind already happened
            |_| Some(cap_path_for_closure.clone()),
        )
        .unwrap_err();
        assert!(matches!(err, ProtocolError::CapabilityRevoked));
    }

    /// Pull the `capability` hash from an EXECUTE entity's `data` field.
    /// Test-only helper for the F2 wiring assertions above.
    fn decode_execute_capability(data: &[u8]) -> Hash {
        let val: ciborium::Value = ciborium::de::from_reader(data).unwrap();
        let map = val.as_map().unwrap();
        for (k, v) in map {
            if k.as_text() == Some("capability") {
                let bytes = v.as_bytes().unwrap();
                return Hash::from_bytes(bytes).unwrap();
            }
        }
        panic!("EXECUTE data missing capability field");
    }
}
