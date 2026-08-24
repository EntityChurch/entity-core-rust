//! `EXTENSION-NETWORK.md` §6.7.1 NAT-type classification — the pure half.
//!
//! §6.7.1 states the rule and the whole mechanism:
//!
//! > *"A peer collects `observed_address` from **several** reflectors. Agreement
//! > ⇒ a stable, endpoint-independent mapping (punchable). Disagreement ⇒ the
//! > mapping differs per destination ⇒ symmetric NAT ⇒ a punch will likely fail
//! > ⇒ prefer relay. No extra mechanism […]"*
//!
//! and pins the floor immediately after:
//!
//! > *"**A single reflector is advisory, never trusted.** […] **No security
//! > decision rests on one observed address**"*
//!
//! `EXTENSION-SIGNALING.md` §9.3 repeats it as a MUST and §11.2 lists the
//! behaviour as SHOULD-implement.
//!
//! # Why one observation refuses instead of concluding
//!
//! The tempting shortcut is to conclude from a single reflector when it is the
//! only one that answered — the observation is usually *correct*, after all. It
//! is refused anyway, and the reason is worth keeping in front of whoever edits
//! this next: **being right by luck on an untrusted single source is exactly the
//! failure the MUST exists to prevent.** A lying reflector produces a
//! well-formed observation; agreement across independent reflectors is the only
//! thing that makes the fact usable, so "it was right that time" is not evidence
//! the rule can be relaxed.
//!
//! Note the two claims this module keeps apart. A lone observation is still a
//! perfectly good **srflx candidate** ("here is a mapping I was told about") —
//! it just cannot support a **NAT-type conclusion** ("my mapping is stable
//! across destinations"). [`classify_mapping`] answers only the second.
//!
//! # This is deliberately not the gathering half
//!
//! Everything here is a pure function of observations already collected. The
//! collection — and the §6.7.3 rule that every reflector MUST be consulted from
//! the *same pinned local socket* — lives in `core/peer::srflx`, because it
//! needs sockets and this crate has none. Splitting it that way is what lets the
//! rule be unit-tested without a network.

use std::fmt;
use std::net::SocketAddr;

/// One reflector's answer: who was asked, and what they said they saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// The reflector consulted, as dialed (`host:port`).
    pub reflector: String,
    /// The `observed_address` it reported for our socket.
    pub observed: String,
}

/// The §6.7.1 verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingClass {
    /// Not enough agreeing evidence to conclude anything — including the
    /// one-reflector case, which is a *refusal*, not a fallback guess.
    Unknown,
    /// The observed source equals this socket's own bind address: no NAT in path.
    Open,
    /// Every reflector observed the same mapping, so it does not depend on the
    /// destination — the advertised candidate is what a counterpart will hit.
    EndpointIndependent,
    /// Reflectors disagreed: the mapping differs per destination. A punch would
    /// dial a mapping that was never opened for the counterpart (§6.7.1), so
    /// §10 relay is the correct path.
    EndpointDependent,
}

impl MappingClass {
    /// The wire/CLI spelling. Matches `entity-core-go`'s `MappingClass` strings
    /// exactly so the two drivers' JSON is comparable by a harness.
    pub fn as_str(self) -> &'static str {
        match self {
            MappingClass::Unknown => "unknown",
            MappingClass::Open => "open",
            MappingClass::EndpointIndependent => "endpoint-independent",
            MappingClass::EndpointDependent => "endpoint-dependent",
        }
    }

    /// Whether a punch is worth attempting on this class.
    ///
    /// **Only a *concluded* symmetric NAT rules a punch out.** `Unknown` stays
    /// punchable: failing to reach a conclusion is not evidence against the
    /// punch, and §6.7.1's prefer-relay guidance is triggered by *disagreement*,
    /// not by absence of agreement. (Same rule as Go's `Punchable()`.)
    pub fn punchable(self) -> bool {
        self != MappingClass::EndpointDependent
    }
}

impl fmt::Display for MappingClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A verdict plus the evidence it rests on.
#[derive(Debug, Clone)]
pub struct MappingAssessment {
    pub class: MappingClass,
    /// The agreed mapping — `Some` only when the reflectors agreed on one.
    pub mapping: Option<String>,
    /// Why, in terms a report can print. Carries the divergence itself, never
    /// "the reflectors disagreed" — that is not a diagnosis.
    pub reason: String,
    pub observations: Vec<Observation>,
}

impl MappingAssessment {
    pub fn punchable(&self) -> bool {
        self.class.punchable()
    }
}

/// Classify the mapping from observations gathered on **one** pinned socket.
///
/// `local_addr` is that socket's bind address; pass `""` if unknown, which only
/// costs the ability to distinguish [`MappingClass::Open`] from
/// [`MappingClass::EndpointIndependent`].
///
/// **Caller's obligation:** every observation MUST come from the same local
/// socket (§6.7.3). This function cannot check that and does not try — two
/// reflectors consulted from two sockets produce a well-formed, confidently
/// wrong `EndpointDependent`. See `core/peer::srflx::detect_mapping`, which is
/// structured so the caller cannot get it wrong.
pub fn classify_mapping(local_addr: &str, obs: &[Observation]) -> MappingAssessment {
    let observations = obs.to_vec();

    match obs.len() {
        0 => {
            return MappingAssessment {
                class: MappingClass::Unknown,
                mapping: None,
                reason: "no reflector observations".to_string(),
                observations,
            }
        }
        1 => {
            return MappingAssessment {
                class: MappingClass::Unknown,
                mapping: None,
                reason: format!(
                    "one reflector ({} observed {}) — a single reflector is advisory, never a \
                     NAT-type conclusion (§6.7.1)",
                    obs[0].reflector, obs[0].observed
                ),
                observations,
            }
        }
        _ => {}
    }

    // port -> reflectors reporting it, and the same for the public IP. Both are
    // kept sorted so `describe_split` renders deterministically — a reason line
    // that reorders between runs is not comparable across a harness.
    let mut ports: Vec<(String, Vec<String>)> = Vec::new();
    let mut ips: Vec<(String, Vec<String>)> = Vec::new();

    for o in obs {
        // Parsing rather than string-splitting normalizes the IPv6 spellings, so
        // two reflectors that write the same address differently agree instead of
        // reading as a divergence. (Go compares the raw strings; on the IPv4
        // substrate both harnesses use, the two are identical.)
        let Ok(addr) = o.observed.parse::<SocketAddr>() else {
            return MappingAssessment {
                class: MappingClass::Unknown,
                mapping: None,
                reason: format!(
                    "reflector {} reported an unparseable address {:?}",
                    o.reflector, o.observed
                ),
                observations,
            };
        };
        push_grouped(&mut ports, addr.port().to_string(), &o.reflector);
        push_grouped(&mut ips, addr.ip().to_string(), &o.reflector);
    }

    // Port divergence is the classic symmetric signature: a fresh mapping per
    // destination, so the port a counterpart would dial was never the port any
    // reflector saw.
    if ports.len() > 1 {
        return MappingAssessment {
            class: MappingClass::EndpointDependent,
            mapping: None,
            reason: format!(
                "mapped port differs per destination ({}) — symmetric NAT; a punch dials a \
                 mapping that was never opened for the counterpart (§6.7.1), prefer relay (§10)",
                describe_split(&ports)
            ),
            observations,
        };
    }

    // Same port, different public IP: an egress-address pool picking a source IP
    // per destination. A different mechanism from port divergence, but it defeats
    // a punch for the same reason — the advertised address is destination-specific
    // — so it classifies together and says which one was seen.
    if ips.len() > 1 {
        return MappingAssessment {
            class: MappingClass::EndpointDependent,
            mapping: None,
            reason: format!(
                "mapped port agrees but the public IP differs per destination ({}) — \
                 egress-address pool; the advertised candidate is destination-specific, \
                 prefer relay (§10)",
                describe_split(&ips)
            ),
            observations,
        };
    }

    let mapping = obs[0].observed.clone();
    if !local_addr.is_empty() && same_addr(local_addr, &mapping) {
        return MappingAssessment {
            class: MappingClass::Open,
            reason: format!(
                "{} reflectors agree on {}, which is this socket's own bind address — no NAT in \
                 path",
                obs.len(),
                mapping
            ),
            mapping: Some(mapping),
            observations,
        };
    }

    MappingAssessment {
        class: MappingClass::EndpointIndependent,
        reason: format!(
            "{} reflectors agree on {} — the mapping does not depend on the destination, so the \
             advertised candidate is what the counterpart will hit",
            obs.len(),
            mapping
        ),
        mapping: Some(mapping),
        observations,
    }
}

/// Insert into a key-ordered group list, preserving reflector order within a key.
fn push_grouped(groups: &mut Vec<(String, Vec<String>)>, key: String, reflector: &str) {
    match groups.binary_search_by(|(k, _)| k.as_str().cmp(key.as_str())) {
        Ok(i) => groups[i].1.push(reflector.to_string()),
        Err(i) => groups.insert(i, (key, vec![reflector.to_string()])),
    }
}

/// Renders `20001 (r1, r2) vs 41337 (r3)` — the divergence itself. Matches Go's
/// `describeSplit` so a cross-impl report reads identically.
fn describe_split(groups: &[(String, Vec<String>)]) -> String {
    groups
        .iter()
        .map(|(k, refs)| format!("{} ({})", k, refs.join(", ")))
        .collect::<Vec<_>>()
        .join(" vs ")
}

/// Compare two addresses semantically when both parse, textually otherwise.
fn same_addr(a: &str, b: &str) -> bool {
    match (a.parse::<SocketAddr>(), b.parse::<SocketAddr>()) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(reflector: &str, observed: &str) -> Observation {
        Observation {
            reflector: reflector.to_string(),
            observed: observed.to_string(),
        }
    }

    /// The §6.7.1 happy path: several reflectors agree, so the mapping does not
    /// depend on the destination and a punch is worth firing.
    #[test]
    fn agreement_is_endpoint_independent_and_punchable() {
        let a = classify_mapping(
            "10.1.0.2:20001",
            &[
                obs("10.0.0.254:4050", "10.0.0.1:20001"),
                obs("10.0.0.253:4052", "10.0.0.1:20001"),
            ],
        );
        assert_eq!(a.class, MappingClass::EndpointIndependent);
        assert_eq!(a.mapping.as_deref(), Some("10.0.0.1:20001"));
        assert!(a.punchable());
    }

    /// Port divergence is the symmetric signature — relay-only, and the reason
    /// must name the divergence rather than assert one.
    #[test]
    fn port_divergence_is_endpoint_dependent_and_not_punchable() {
        let a = classify_mapping(
            "10.1.0.2:20001",
            &[
                obs("r1", "10.0.0.1:41000"),
                obs("r2", "10.0.0.1:52000"),
            ],
        );
        assert_eq!(a.class, MappingClass::EndpointDependent);
        assert!(!a.punchable());
        assert!(a.mapping.is_none(), "a divergent mapping has no agreed value");
        assert!(
            a.reason.contains("41000 (r1) vs 52000 (r2)"),
            "the reason must quote the divergence itself: {}",
            a.reason
        );
    }

    /// Same port, different public IP — a different mechanism, same consequence.
    #[test]
    fn egress_pool_is_endpoint_dependent_and_says_which_one() {
        let a = classify_mapping(
            "",
            &[
                obs("r1", "203.0.113.7:20001"),
                obs("r2", "203.0.113.9:20001"),
            ],
        );
        assert_eq!(a.class, MappingClass::EndpointDependent);
        assert!(a.reason.contains("public IP differs"), "{}", a.reason);
        assert!(a.reason.contains("203.0.113.7 (r1) vs 203.0.113.9 (r2)"), "{}", a.reason);
    }

    /// **The load-bearing test.** The lone observation here is *correct* — a
    /// classifier that concluded from it would be right. It must refuse anyway:
    /// being right by luck on an untrusted single source is the failure the MUST
    /// exists to prevent, and a detector that ignored the rule would pass every
    /// other test in this file.
    #[test]
    fn one_reflector_refuses_even_when_the_observation_is_correct() {
        let a = classify_mapping("10.1.0.2:20001", &[obs("10.0.0.254:4050", "10.0.0.1:20001")]);
        assert_eq!(a.class, MappingClass::Unknown);
        assert!(a.mapping.is_none(), "no conclusion means no mapping is asserted");
        assert!(a.reason.contains("advisory"), "{}", a.reason);
        // Still worth punching: refusing to conclude is not evidence against it.
        assert!(a.punchable());
    }

    #[test]
    fn no_observations_is_unknown() {
        let a = classify_mapping("10.1.0.2:20001", &[]);
        assert_eq!(a.class, MappingClass::Unknown);
        assert!(a.reason.contains("no reflector observations"));
    }

    /// Agreement on our own bind address means there is no NAT in path at all.
    #[test]
    fn agreement_on_the_bind_address_is_open() {
        let a = classify_mapping(
            "203.0.113.5:20001",
            &[
                obs("r1", "203.0.113.5:20001"),
                obs("r2", "203.0.113.5:20001"),
            ],
        );
        assert_eq!(a.class, MappingClass::Open);
        assert!(a.punchable());
    }

    /// A garbled reflector answer must not be silently grouped as a distinct
    /// mapping — that would read as a symmetric NAT and steer a punchable peer
    /// to relay.
    #[test]
    fn unparseable_observation_is_unknown_not_a_divergence() {
        let a = classify_mapping(
            "10.1.0.2:20001",
            &[obs("r1", "10.0.0.1:20001"), obs("r2", "not-an-address")],
        );
        assert_eq!(a.class, MappingClass::Unknown);
        assert!(a.reason.contains("unparseable"), "{}", a.reason);
    }

    /// Three reflectors, one dissenter: still a divergence. The majority does
    /// not get to outvote the rule — §6.7.1 requires agreement, not a quorum.
    #[test]
    fn a_majority_does_not_override_a_dissenting_reflector() {
        let a = classify_mapping(
            "",
            &[
                obs("r1", "10.0.0.1:20001"),
                obs("r2", "10.0.0.1:20001"),
                obs("r3", "10.0.0.1:41337"),
            ],
        );
        assert_eq!(a.class, MappingClass::EndpointDependent);
        assert!(a.reason.contains("20001 (r1, r2) vs 41337 (r3)"), "{}", a.reason);
    }
}
