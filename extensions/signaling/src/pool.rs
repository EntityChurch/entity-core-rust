//! Provider selection — **which node of a pool a peer talks to**
//! (`PROPOSAL-REGISTRY-SERVICE-ADVERTISEMENT` §3.1).
//!
//! # The rule
//!
//! > **Both peers of a handshake must meet at the same provider.**
//!
//! It holds for *every* key mode — `pair`, `tag`, `secret`, and `lobby` all
//! rendezvous-hash `K` into the configured pool — so provider selection is
//! invariant across modes, and a mismatch is a silent never-meet exactly like a
//! key-derivation mismatch.
//!
//! §3.1 pins selection **per service type**, and `signaling` is the odd one out:
//!
//! | Service | Selection | Why |
//! |---|---|---|
//! | `reflector` | any member; consult **several** and require agreement | every reflector independently yields the same fact |
//! | **`signaling`** | **client-side rendezvous-hash (MUST)** | two peers must meet at the *same* server for the seconds of the handshake |
//! | `data_relay` / `inbox_relay` | priority-order failover (MX semantics) | any relay carries the data; the sender alone picks |
//!
//! **Not lowest-`priority`, and never a round-robin load balancer.** Either one
//! splits the pair across servers and the punch never completes. Highest-random
//! -weight converges with **zero shared state**: each node owns a shard of the
//! key space, pool capacity is the sum of its members, and a hot key is one
//! handshake rather than a hot shard.
//!
//! # The weight function is pinned to bytes (§3.1.1, ruling 2026-07-28)
//!
//! **"Highest-random-weight" is a family, not a function.** The Stage-1 build
//! routed this upstream as the fourth §1.1-class question, because two impls can
//! each write textbook-correct HRW — disagreeing on operand order, the digest,
//! what identifies a member, or how weights compare — and **split every pair**.
//! That is §2.2's silent-never-meet exactly one layer out. §3.1.1 now pins all
//! four free variables:
//!
//! ```text
//! weight(k, endpoint) = SHA-256( k ‖ endpoint_bytes )
//! server              = argmax over the pool, weights compared lexicographically
//! ```
//!
//! - **`k`** is the 33-byte rendezvous key *exactly as derived* (§2.2) — the
//!   same bytes that go on the wire, not a re-hash of them.
//! - **`endpoint_bytes`** are the advertised string's bytes *exactly as
//!   published*: no normalization, no case-folding, no scheme or default-port
//!   canonicalization. Same rule and same reason as §2.2's string inputs — both
//!   peers read the *same* advertisement, so byte-preservation makes them agree
//!   without either running a URL canonicalizer, and a canonicalizer is
//!   precisely where two impls drift apart.
//! - **No separator**, because `k` is fixed at 33 bytes and the concatenation is
//!   therefore unambiguous by construction. Recorded explicitly so it is not
//!   read as the missing-separator bug §2.2 had to fix in `pair`.
//! - **Highest weight wins**; ties break to the **lower** `endpoint_bytes`. A
//!   tie is a SHA-256 collision away and will never be seen, but "argmax" alone
//!   is not a total order and an impl must not have to invent the rest.
//! - A **plain SHA-256, not the substrate content-hash primitive**: this weight
//!   is a comparison scalar that never appears on the wire and addresses no
//!   content, so the ECF envelope would be ceremony — and a *format-carrying*
//!   digest would reintroduce the very home-format divergence §2.2 exists to
//!   pin away.
//!
//! **`priority` partitions; it does not weight.** "Weight the hash" was
//! withdrawn: a weighting function is itself unpinned bytes, and stacking a
//! second invented rule on the first is worse than not tiering at all. Instead
//! [`select`] takes the **lowest `priority` tier present** and rendezvous-hashes
//! *within* it. Both peers read the same advertisement, so both land in the same
//! tier before the hash ever runs.
//!
//! # Why a one-node deployment cannot validate any of this
//!
//! `argmax` over a one-member pool returns that member *whatever the weight
//! computes* — so every construction agrees and a green single-node gate says
//! nothing. That is why this went unnoticed until the build enumerated it, and
//! why `PROPOSAL-CONNECTION-NODE` §6 step 2 now requires a **two-instance
//! pool**. It is also why the same-impl tests below prove less than they look
//! like they do: both "peers" are this code, so they converge trivially. What
//! they do hold is that the construction *discriminates* and is total.

use sha2::{Digest, Sha256};

use crate::core::RendezvousKey;

/// One member of a service pool, as it appears in the deployment's signed
/// `system/registry/service-advertisement`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolMember {
    /// The member's endpoint URL. This is the identity the weight is computed
    /// over, so it must be the **advertised** string byte-for-byte — a peer that
    /// normalizes it (strips a trailing slash, lowercases a host) weights a
    /// different string and lands on a different member.
    pub endpoint: String,
    /// Priority tier from the advertisement. **Partitions the pool before the
    /// hash runs** (§3.1.1): [`select`] narrows to the lowest tier *present* and
    /// rendezvous-hashes within it.
    ///
    /// Lowest-numbered wins, MX-style. Note it is the lowest tier **present**,
    /// not a fixed tier number — a pool whose tier-0 members are all withdrawn
    /// falls through to tier 1 rather than selecting nothing, which is what
    /// makes tiering usable for failover instead of just for preference.
    pub priority: u32,
}

impl PoolMember {
    pub fn new(endpoint: impl Into<String>, priority: u32) -> Self {
        Self {
            endpoint: endpoint.into(),
            priority,
        }
    }
}

/// The per-member weight — `SHA-256( k ‖ endpoint_bytes )`, pinned by §3.1.1.
///
/// Compared as a big-endian unsigned integer, i.e. lexicographically over the 32
/// digest bytes, **highest wins**. See the module header for why each of those
/// four choices is spelled out rather than left to the implementer.
fn weight(key: &RendezvousKey, endpoint: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hasher.update(endpoint.as_bytes());
    hasher.finalize().into()
}

/// The lowest `priority` tier **present** in the pool (§3.1.1). `None` for an
/// empty pool.
fn lowest_tier(pool: &[PoolMember]) -> Option<u32> {
    pool.iter().map(|m| m.priority).min()
}

/// Pick the member both peers will independently pick for `key`.
///
/// **Two steps, in this order** (§3.1.1): partition to the lowest `priority`
/// tier present, *then* rendezvous-hash within it. The order matters — hashing
/// first and filtering after would let the tier a peer lands in depend on the
/// key, which is not tiering at all.
///
/// Ties break on the endpoint string (byte-wise, lower wins) so the result is
/// total and deterministic even for the vanishingly unlikely digest collision —
/// a tie resolved by iteration order would be a convergence bug that appears
/// only under reordering of the advertisement.
///
/// Returns `None` for an empty pool: a deployment that advertises no signaling
/// service offers no rendezvous, and that is a configuration fact for the caller
/// to surface rather than something to paper over with a default.
pub fn select<'a>(key: &RendezvousKey, pool: &'a [PoolMember]) -> Option<&'a PoolMember> {
    let tier = lowest_tier(pool)?;
    pool.iter()
        .filter(|m| m.priority == tier)
        .map(|m| (weight(key, &m.endpoint), m))
        .reduce(|best, next| match next.0.cmp(&best.0) {
            std::cmp::Ordering::Greater => next,
            std::cmp::Ordering::Equal if next.1.endpoint < best.1.endpoint => next,
            _ => best,
        })
        .map(|(_, m)| m)
}

/// The **top `n`** members in descending weight — the §3.1 stale-pool-skew
/// mitigation.
///
/// Two peers may hold advertisements that differ by a member (one is stale, or
/// the pool just scaled), in which case they rendezvous-hash to different
/// servers and never meet. §3.1's SHOULD: each peer tries its **top-2** choices,
/// which is cheap and covers a single-member pool delta — with `n = 2` the two
/// peers' choice sets intersect whenever their pools differ by at most one
/// member. The heavier mitigation (a "looking-for-you" beacon gossiped within
/// the pool) is explicitly deferred until measured skew justifies it.
///
/// **Ranks within the lowest tier only**, exactly as [`select`] does — the skew
/// mitigation must not become a back door into a tier the operator
/// deprioritized. A single-member tier therefore yields one choice however large
/// `n` is, which is the right answer rather than a truncation: there is no
/// second node in that tier to try.
pub fn select_top<'a>(
    key: &RendezvousKey,
    pool: &'a [PoolMember],
    n: usize,
) -> Vec<&'a PoolMember> {
    let Some(tier) = lowest_tier(pool) else {
        return Vec::new();
    };
    let mut ranked: Vec<([u8; 32], &PoolMember)> = pool
        .iter()
        .filter(|m| m.priority == tier)
        .map(|m| (weight(key, &m.endpoint), m))
        .collect();
    // Descending weight, then ascending endpoint — the same total order
    // `select` uses, so `select_top(..., 1)` and `select` always agree.
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.endpoint.cmp(&b.1.endpoint)));
    ranked.into_iter().take(n).map(|(_, m)| m).collect()
}

/// The default breadth for [`select_top`] — §3.1's "try your top-2".
pub const SKEW_FANOUT: usize = 2;
