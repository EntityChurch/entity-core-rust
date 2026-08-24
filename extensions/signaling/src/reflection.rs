//! The `reflection_endpoints` wire form (`EXTENSION-SIGNALING` §4.5.1, v1.1).
//!
//! §9.1 gives this service **two listeners** — the mailbox (TCP, §9.2) and
//! reflection (STUN/UDP, §9.3) — and until v1.1 `advertise` published only the
//! first, so a node that ran §9.3 reflection had no way to say so and a peer
//! reaching it had no way to ask. `reflection_endpoints` is that answer: **this
//! node's own listener(s), never a directory of anyone else's** (a deployment's
//! infrastructure set is `EXTENSION-REGISTRY` §3b's job, and that entity is
//! signed by the deployment identity precisely because it vouches for
//! infrastructure it does not run).
//!
//! **The form is pinned and the node emits it verbatim** (§4.5.1, pinned
//! 2026-08-14; identical to `EXTENSION-REGISTRY` §3b.0 — the two fields describe
//! the same kind of thing and MUST NOT differ in shape). A browser hands each
//! entry to `RTCIceServer.urls` **unchanged**, and a malformed entry does not
//! degrade to host-candidates-only: it **throws at `RTCPeerConnection`
//! construction** and takes the establisher with it. Publishing the final form
//! is what keeps any consumer from running a transform — and every transform is
//! a place two consumers guess differently (given `1.2.3.4:3478` one prepends
//! `stun:` and one does not; given `stun:1.2.3.4:3478` a prepending consumer
//! produces `stun:stun:1.2.3.4:3478`).
//!
//! So the check belongs **here, at configuration time**, not on the emit path:
//! [`SignalingCore::advertise`](crate::core::SignalingCore::advertise) publishes
//! what the operator configured byte-for-byte, and an operator who typed the
//! wrong shape learns it at startup rather than at some browser's first
//! `RTCPeerConnection`.

/// Why a configured reflection endpoint is not the §4.5.1 form.
///
/// Every variant renders the offending string, because the operator's next
/// action is to fix the value they typed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReflectionEndpointError {
    #[error(
        "reflection endpoint {uri:?}: must begin with the RFC 7064 scheme \"stun:\" or \"stuns:\""
    )]
    MissingScheme { uri: String },
    /// The single mistake most likely to be made by hand: RFC 7064 STUN URIs
    /// are **non-hierarchical**, so `stun://host:3478` is invalid however much
    /// it looks like every other URI.
    #[error(
        "reflection endpoint {uri:?}: RFC 7064 STUN URIs are non-hierarchical — there is no \"//\" (§4.5.1)"
    )]
    HierarchicalForm { uri: String },
    #[error("reflection endpoint {uri:?}: host is required")]
    MissingHost { uri: String },
    #[error("reflection endpoint {uri:?}: unterminated IPv6 literal — missing \"]\"")]
    UnterminatedIpv6 { uri: String },
    #[error("reflection endpoint {uri:?}: unexpected {rest:?} after the IPv6 literal")]
    TrailingAfterIpv6 { uri: String, rest: String },
    #[error("reflection endpoint {uri:?}: port {port:?} must be an integer in 1..=65535")]
    BadPort { uri: String, port: String },
    /// The host still holds a `:` after the optional port was split off — an
    /// unbracketed IPv6 literal (`stun:2001:db8::1`), or a doubled scheme
    /// (`stun:stun:relay.example:3478`, exactly what a prepending consumer
    /// produces from an already-prefixed value). RFC 3986 `reg-name`, which RFC
    /// 7064 inherits, admits neither.
    #[error(
        "reflection endpoint {uri:?}: host {host:?} may not contain \":\" — bracket an IPv6 literal (\"stun:[2001:db8::1]:3478\") and give the scheme once"
    )]
    ColonInHost { uri: String, host: String },
}

/// Check one entry against the §4.5.1 form:
///
/// - the scheme is `stun:` (STUN over UDP/TCP) or `stuns:` (STUN over TLS);
/// - there is **no `//`** — `stun://host:3478` is invalid;
/// - a bare `host:3478` with no scheme is invalid;
/// - the host is required; the port is optional and, if present, is `1..=65535`.
///
/// Callers validate **before** configuring a node
/// ([`SignalingCore::with_reflection_endpoints`](crate::core::SignalingCore::with_reflection_endpoints)
/// stores what it is given, because emit is verbatim). `entity-signaling-node
/// --reflection-endpoint` and `entity-peer --reflection-endpoint` both fail at
/// startup on the error this returns rather than silently dropping or "fixing"
/// a value — a node that quietly repaired one would be publishing a form its
/// operator never wrote.
pub fn validate_reflection_endpoint(uri: &str) -> Result<(), ReflectionEndpointError> {
    let host = if let Some(rest) = uri.strip_prefix("stuns:") {
        rest
    } else if let Some(rest) = uri.strip_prefix("stun:") {
        rest
    } else {
        return Err(ReflectionEndpointError::MissingScheme {
            uri: uri.to_string(),
        });
    };

    if host.starts_with("//") {
        return Err(ReflectionEndpointError::HierarchicalForm {
            uri: uri.to_string(),
        });
    }
    if host.is_empty() {
        return Err(ReflectionEndpointError::MissingHost {
            uri: uri.to_string(),
        });
    }

    // Split an OPTIONAL trailing `:port`, honoring an IPv6 literal's own colons
    // by requiring bracket form (`[::1]` / `[::1]:3478`) — RFC 3986 host syntax
    // as RFC 7064 inherits it. Only the segment after the closing bracket can be
    // a port.
    let port = if let Some(inner) = host.strip_prefix('[') {
        let end = inner
            .find(']')
            .ok_or_else(|| ReflectionEndpointError::UnterminatedIpv6 {
                uri: uri.to_string(),
            })?;
        if end == 0 {
            return Err(ReflectionEndpointError::MissingHost {
                uri: uri.to_string(),
            });
        }
        match &inner[end + 1..] {
            "" => None,
            rest => match rest.strip_prefix(':') {
                Some(port) => Some(port),
                None => {
                    return Err(ReflectionEndpointError::TrailingAfterIpv6 {
                        uri: uri.to_string(),
                        rest: rest.to_string(),
                    })
                }
            },
        }
    } else {
        let (name, port) = match host.rfind(':') {
            // `stun::3478` — a port with nothing in front of it.
            Some(0) => {
                return Err(ReflectionEndpointError::MissingHost {
                    uri: uri.to_string(),
                })
            }
            Some(i) => (&host[..i], Some(&host[i + 1..])),
            None => (host, None),
        };
        // Whatever is left is an RFC 3986 `reg-name` or an IPv4 literal, and
        // neither may contain a colon. This is what refuses an unbracketed IPv6
        // literal and, not incidentally, `stun:stun:relay.example:3478` — the
        // value a consumer that prepends a scheme produces from one that already
        // had it (§4.5.1's worked example of why the form is pinned).
        if name.contains(':') {
            return Err(ReflectionEndpointError::ColonInHost {
                uri: uri.to_string(),
                host: name.to_string(),
            });
        }
        port
    };

    if let Some(port) = port {
        match port.parse::<u32>() {
            Ok(p) if (1..=65535).contains(&p) => {}
            _ => {
                return Err(ReflectionEndpointError::BadPort {
                    uri: uri.to_string(),
                    port: port.to_string(),
                })
            }
        }
    }
    Ok(())
}
