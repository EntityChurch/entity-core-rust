//! The keystone-owned canonical §6.9a seed-policy **file** format.
//!
//! V7 §6.9a pins the invariant (a peer derives authenticate-time grants from a
//! declared identity → capability seed policy) and the SDK builder shape; the
//! **cross-peer file format and CLI convention are keystone's**
//! (`protocol-generator/shared/seed-policy/seed-policy.schema.json`, README §3).
//! [`PeerBuilder::with_seed_policy`] stays the builder-first supply mechanism —
//! this module is the file wrapper that desugars to it, so an operator hands
//! the *same* file to a go, python or rust peer and gets the same posture.
//!
//! ```jsonc
//! { "version": 1,
//!   "entries": [
//!     { "grantee": "self | default | <identity-hash-hex> | <base58-peer-id>",
//!       "grants": [ { "handlers":   {"include": ["…"], "exclude": ["…"]},
//!                     "resources":  {"include": ["…"]},
//!                     "operations": {"include": ["…"]},
//!                     "peers":      {"include": ["self"]} } ] } ] }
//! ```
//!
//! Two divergent shapes predate this one and are **rejected**, loudly: go's old
//! `[{pattern, grants}]` top-level array (fixed at go `7887646`) and python's
//! `{"<grantee>": {"grants": […]}}` keyed object. Neither is the convention;
//! accepting them here would re-fork the format we just converged.
//!
//! [`PeerBuilder::with_seed_policy`]: crate::PeerBuilder::with_seed_policy

use entity_capability::{GrantEntry, IdScope, PathScope};
use serde::Deserialize;

use crate::PeerError;

/// The one grantee key a file MUST NOT supply: the peer-owner capability is
/// materialized eagerly at peer-init from the owner identity
/// (`PeerBuilder::with_owner_identity`), per the keystone README §1 / §6.9a.0
/// minimum. A `self` entry in a file is skipped rather than rejected — the
/// canonical examples carry it as documentation of the two always-present
/// entries, and go skips it identically.
const GRANTEE_SELF: &str = "self";

/// The schema's only ratified version.
const SCHEMA_VERSION: u64 = 1;

// Deliberately NOT `#[serde(deny_unknown_fields)]`. The schema says
// `additionalProperties: false`, but keystone's own `examples/operator-admin.json`
// carries a `_comment` inside an entry — and go's `peer-manager --admin-identity`
// emits that comment into every file it writes. A strict parser rejects the
// canonical example and the harness's own output; tolerating the extra key is
// what keeps the cohort readable. (Routed to the format owners: the schema and
// its example disagree.)
#[derive(Deserialize)]
struct PolicyDoc {
    version: u64,
    #[serde(default)]
    entries: Vec<PolicyEntry>,
}

#[derive(Deserialize)]
struct PolicyEntry {
    grantee: String,
    #[serde(default)]
    grants: Vec<PolicyGrant>,
    #[serde(default)]
    bounds: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct PolicyGrant {
    handlers: PolicyScope,
    resources: PolicyScope,
    operations: PolicyScope,
    #[serde(default)]
    peers: Option<PolicyScope>,
    #[serde(default)]
    constraints: Option<serde_json::Value>,
    #[serde(default)]
    allowances: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct PolicyScope {
    include: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
}

/// The expected shape, quoted back in every parse error — the divergent shapes
/// fail deep inside serde with a message that names a field, not a format.
const SHAPE_HINT: &str = r#"expected the keystone canonical seed policy: {"version":1,"entries":[{"grantee":"<self|default|hex|base58>","grants":[{"handlers":{"include":[…]},"resources":{"include":[…]},"operations":{"include":[…]}}]}]}"#;

/// Parse the canonical seed-policy JSON into
/// [`PeerBuilder::with_seed_policy`](crate::PeerBuilder::with_seed_policy) entries.
///
/// Available on every target — a browser peer receives its policy over the wire
/// rather than from a filesystem, and the parse is the same either way.
///
/// # Fail-closed fields
///
/// `bounds`, `constraints` and `allowances` are **rejected**, not ignored. All
/// three narrow authority (temporal bounds, §5.6 narrowing keys), so dropping
/// one silently turns a restricted seed into an unrestricted one — the failure
/// mode a seed policy exists to prevent. Rust's builder has no channel for
/// them, and their JSON representation is the one unresolved corner of the
/// schema (raw CBOR in memory in all three impls; go's loader drops them). A
/// file that needs them has no cross-impl meaning yet, so it errors here.
pub fn parse_seed_policy(json: &str) -> Result<Vec<(String, Vec<GrantEntry>)>, PeerError> {
    let doc: PolicyDoc = serde_json::from_str(json)
        .map_err(|e| PeerError::BuildError(format!("seed policy: {} ({})", e, SHAPE_HINT)))?;
    if doc.version != SCHEMA_VERSION {
        return Err(PeerError::BuildError(format!(
            "seed policy: unsupported version {} (the schema ratifies version {})",
            doc.version, SCHEMA_VERSION
        )));
    }

    let mut out = Vec::with_capacity(doc.entries.len());
    for entry in doc.entries {
        if entry.grantee == GRANTEE_SELF {
            tracing::debug!(
                "seed policy: `self` entry skipped — the peer-owner capability is \
                 materialized at peer-init, not from a file (§6.9a.0)"
            );
            continue;
        }
        if entry.grantee.is_empty() {
            return Err(PeerError::BuildError(
                "seed policy: empty `grantee` (expected `default`, a 66/98-char identity-hash \
                 hex, or a Base58 peer-id — §6.9a.1)"
                    .to_string(),
            ));
        }
        if entry.bounds.is_some() {
            return Err(PeerError::BuildError(format!(
                "seed policy: entry `{}` declares `bounds`, which this peer cannot honor \
                 (the §6.9a builder seam carries no temporal bounds). Refusing rather than \
                 seeding a grant that would never expire.",
                entry.grantee
            )));
        }

        let mut grants = Vec::with_capacity(entry.grants.len());
        for (i, g) in entry.grants.into_iter().enumerate() {
            for (field, present) in [
                ("constraints", g.constraints.is_some()),
                ("allowances", g.allowances.is_some()),
            ] {
                if present {
                    return Err(PeerError::BuildError(format!(
                        "seed policy: entry `{}` grant #{} declares `{}`, which has no ratified \
                         JSON representation yet (raw CBOR in memory in every impl; go's loader \
                         drops it). Refusing rather than seeding an unnarrowed grant.",
                        entry.grantee, i, field
                    )));
                }
            }
            grants.push(GrantEntry {
                handlers: PathScope::with_exclude(g.handlers.include, g.handlers.exclude),
                resources: PathScope::with_exclude(g.resources.include, g.resources.exclude),
                operations: IdScope::with_exclude(g.operations.include, g.operations.exclude),
                // Absent `peers` keeps the GrantEntry default (`{include:
                // [local_peer_id]}` — local peer only), which is what the
                // §4.4 floor and the canonical `default` entry both want.
                peers: g.peers.map(|p| IdScope::with_exclude(p.include, p.exclude)),
                constraints: None,
                allowances: None,
            });
        }
        out.push((entry.grantee, grants));
    }
    Ok(out)
}

/// Read and parse a canonical seed-policy file.
///
/// The CLI (`entity peer start --seed-policy <file>`) and any embedder that
/// takes a path route through here; see [`parse_seed_policy`] for the accepted
/// shape and the fail-closed fields.
#[cfg(not(target_arch = "wasm32"))]
pub fn load_seed_policy_file(
    path: impl AsRef<std::path::Path>,
) -> Result<Vec<(String, Vec<GrantEntry>)>, PeerError> {
    let path = path.as_ref();
    let raw = std::fs::read_to_string(path)
        .map_err(|e| PeerError::BuildError(format!("seed policy {}: {}", path.display(), e)))?;
    // Re-wrap the inner message, not the whole error: `PeerError`'s Display
    // already carries the "build error:" prefix, and nesting it reads as two
    // failures where there was one.
    parse_seed_policy(&raw).map_err(|e| match e {
        PeerError::BuildError(msg) => PeerError::BuildError(format!("{}: {}", path.display(), msg)),
        other => other,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `keystone protocol-generator/shared/seed-policy/examples/operator-admin.json`,
    /// verbatim (comment included) — the exact file go's `peer-manager start
    /// --admin-identity` writes and the shape the admin-seeded-restrictive
    /// posture is declared in.
    const OPERATOR_ADMIN: &str = r#"{
      "version": 1,
      "entries": [
        {
          "_comment": "A named operator identity granted wide admin over the local namespace.",
          "grantee": "0000000000000000000000000000000000000000000000000000000000000000ab",
          "grants": [
            { "handlers": { "include": ["*"] },
              "resources": { "include": ["*"] },
              "operations": { "include": ["*"] },
              "peers": { "include": ["self"] } }
          ]
        },
        {
          "grantee": "default",
          "grants": [
            { "handlers": { "include": ["system/tree"] },
              "resources": { "include": ["system/type/*", "system/handler/*"] },
              "operations": { "include": ["get"] } },
            { "handlers": { "include": ["system/capability"] },
              "resources": { "include": [] },
              "operations": { "include": ["request"] } }
          ]
        }
      ]
    }"#;

    #[test]
    fn canonical_operator_admin_parses() {
        let entries = parse_seed_policy(OPERATOR_ADMIN).unwrap();
        assert_eq!(entries.len(), 2);

        let (grantee, grants) = &entries[0];
        assert_eq!(
            grantee,
            "0000000000000000000000000000000000000000000000000000000000000000ab"
        );
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].handlers, PathScope::all());
        assert_eq!(grants[0].resources, PathScope::all());
        assert_eq!(grants[0].operations, IdScope::all());
        assert_eq!(grants[0].peers, Some(IdScope::new(vec!["self".into()])));

        let (grantee, grants) = &entries[1];
        assert_eq!(grantee, "default");
        assert_eq!(grants.len(), 2);
        assert_eq!(
            grants[0].resources,
            PathScope::new(vec!["system/type/*".into(), "system/handler/*".into()])
        );
        assert_eq!(grants[1].operations, IdScope::new(vec!["request".into()]));
        // Absent in the file → absent here (local-peer-only default), not an
        // empty scope, which would match nothing.
        assert_eq!(grants[1].peers, None);
    }

    #[test]
    fn exclude_is_carried() {
        let entries = parse_seed_policy(
            r#"{"version":1,"entries":[{"grantee":"default","grants":[
                {"handlers":{"include":["*"],"exclude":["system/compute"]},
                 "resources":{"include":["*"]},
                 "operations":{"include":["*"],"exclude":["delete"]}}]}]}"#,
        )
        .unwrap();
        let g = &entries[0].1[0];
        assert_eq!(g.handlers.exclude, vec!["system/compute".to_string()]);
        assert_eq!(g.operations.exclude, vec!["delete".to_string()]);
    }

    #[test]
    fn self_entry_is_skipped() {
        let entries = parse_seed_policy(
            r#"{"version":1,"entries":[
                {"grantee":"self","grants":[{"handlers":{"include":["*"]},
                 "resources":{"include":["*"]},"operations":{"include":["*"]}}]},
                {"grantee":"default","grants":[]}]}"#,
        )
        .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "default");
    }

    #[test]
    fn unsupported_version_rejected() {
        let err = parse_seed_policy(r#"{"version":2,"entries":[]}"#).unwrap_err();
        assert!(err.to_string().contains("unsupported version 2"), "{}", err);
    }

    /// The two pre-convergence shapes. Both must fail — silently reading either
    /// would re-fork the format (go's array is the shape go itself shipped
    /// until `7887646`; the keyed object is python's).
    #[test]
    fn divergent_shapes_rejected() {
        for shape in [
            r#"[{"pattern":"default","grants":[]}]"#,
            r#"{"default":{"grants":[]}}"#,
        ] {
            let err = parse_seed_policy(shape).unwrap_err();
            assert!(err.to_string().contains("expected the keystone"), "{}", err);
        }
    }

    #[test]
    fn bounds_rejected_rather_than_dropped() {
        let err = parse_seed_policy(
            r#"{"version":1,"entries":[{"grantee":"default","grants":[],
                "bounds":{"expires_at":1}}]}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("`bounds`"), "{}", err);
    }

    #[test]
    fn constraints_and_allowances_rejected_rather_than_dropped() {
        for field in ["constraints", "allowances"] {
            let err = parse_seed_policy(&format!(
                r#"{{"version":1,"entries":[{{"grantee":"default","grants":[
                    {{"handlers":{{"include":["system/query"]}},
                     "resources":{{"include":["*"]}},
                     "operations":{{"include":["query"]}},
                     "{}":{{"type_scope":["note"]}}}}]}}]}}"#,
                field
            ))
            .unwrap_err();
            assert!(err.to_string().contains(field), "{}", err);
        }
    }
}
