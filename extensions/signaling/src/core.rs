//! The three verbs — **specified without reference to the entity system**
//! (`PROPOSAL-CONNECTION-NODE` §1, §1.1, §2).
//!
//! This module is the primitive. It holds no `Entity`, no `Hash`, no
//! `ContentStore`, no capability, and imports nothing from the entity crates —
//! that is the load-bearing property, not a stylistic one. §2.1 pins the core as
//! **wrapper-agnostic and implemented once**, so identical behavior across the
//! wrapped and unwrapped surfaces is *structural*: a divergence between surfaces
//! would mean someone implemented the verbs twice, and **that** is the defect.
//! A shortcut that pushes entity concerns down into this file breaks the
//! guarantee and is explicitly out of bounds (§3).
//!
//! **`reflect` is not here, and never was an operation on the mailbox** (§1.4,
//! ruling 2026-07-28). It is the *unwrapped listener's* verb: the listener owns
//! the socket, so the listener owns the observation. This is what makes §2.1's
//! "identical across surfaces" **exactly** true rather than nearly true — the
//! core is `offer` / `collect` / `advertise`, and every one of them is
//! completable on either surface.
//!
//! **The node is mode-blind.** The four key modes (`pair` / `tag` / `secret` /
//! `lobby`) are *entirely* peer-side key derivation
//! (`PROPOSAL-CONNECTIVITY-SIGNALING-AND-PUNCH` §2.2). Here a rendezvous key is
//! [`RENDEZVOUS_KEY_LEN`] opaque bytes compared byte-wise; the node derives
//! nothing and cannot tell one mode from another. "Prove it connects through all
//! four modes" is therefore **one code path exercised with four derived keys,
//! not four features** (§1).
//!
//! **State silhouette (§1.3):** per-key TTL-reaped buckets and nothing else. No
//! bulk storage, no cross-node coordination, no presence map, no durable data.
//! Losing a node drops in-flight handshakes — peers retry — and loses nothing
//! that mattered.

use std::collections::HashMap;
use std::sync::RwLock;

use sha2::{Digest, Sha256};

/// A rendezvous key is 33 bytes: the substrate content-hash wire form
/// (`algorithm || digest`, `0x00` + 32-byte SHA-256 digest) that the *peer*
/// derives per `PROPOSAL-CONNECTIVITY-SIGNALING-AND-PUNCH` §2.2. The node never
/// derives, parses, or validates the interior — the length is the only thing it
/// checks, and only so a truncated key can't silently collide with a shorter
/// one. §2.2.1's differential properties are a **client-side** obligation.
pub const RENDEZVOUS_KEY_LEN: usize = 33;

// ---------------------------------------------------------------------------
// The key — opaque bytes, byte-wise compared
// ---------------------------------------------------------------------------

/// An opaque rendezvous key. `Debug` renders hex because there is no structure
/// to show: to the node this is a lookup token, not a hash it may interpret.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RendezvousKey([u8; RENDEZVOUS_KEY_LEN]);

impl RendezvousKey {
    /// Accept exactly [`RENDEZVOUS_KEY_LEN`] bytes. A wrong length is the one
    /// key-shaped error the node reports; **the contents are never inspected**.
    ///
    /// The fixed length is also the check §2.2.1 names as catching an otherwise
    /// -correct SHA-384 client: a 49-byte key is rejected loudly here rather
    /// than silently occupying a bucket its counterpart will never look in.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.len() != RENDEZVOUS_KEY_LEN {
            return Err(CoreError::InvalidKeyLength { got: bytes.len() });
        }
        let mut key = [0u8; RENDEZVOUS_KEY_LEN];
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    pub fn as_bytes(&self) -> &[u8; RENDEZVOUS_KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for RendezvousKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RendezvousKey(")?;
        for b in self.0.iter() {
            write!(f, "{:02x}", b)?;
        }
        write!(f, ")")
    }
}

// ---------------------------------------------------------------------------
// Limits (§1.3, §4) — what `advertise` publishes
// ---------------------------------------------------------------------------

/// Node-side operating limits. Published by [`SignalingCore::advertise`] so a
/// peer can size its retries; the node enforces them regardless of what a peer
/// believes (§1.1 pin 3 — TTL is *advisory to peers, binding on the node*).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Largest single deposited blob, in bytes — **8 KiB, §5 pin 5**.
    ///
    /// §4 sizes a handshake at ~1 KB, so this is generous by 8×. The value is
    /// pinned rather than left to the operator because *a limit the client does
    /// not know is a cross-impl reject boundary*: Go offering 64 KiB at a node
    /// that stops at 4 KiB presents as a rendezvous miss, not as the size
    /// refusal it is.
    pub max_blob_bytes: u64,
    /// Largest number of live blobs at one key — **32, §5 pin 5**. `lobby`
    /// and `tag` are inherently multi-party (§1.1 pin 2), so this is not 1.
    pub max_bucket_blobs: u64,
    /// How long a deposited blob survives, **in seconds** — **60 s, §5 pin 6**.
    ///
    /// Node-configurable and published in [`advertise`](SignalingCore::advertise).
    /// The number is bound by the lifetime of what the blob *describes*, not by
    /// node memory: a candidate list's `srflx` entry dies with the NAT binding
    /// that produced it (commonly 30–120 s), so a longer TTL would only serve
    /// candidates that are already unpunchable.
    ///
    /// **Seconds, not milliseconds** (§4.5). The unit is the whole field: a node
    /// publishing `60000` at a client reading seconds is a 1000× TTL, which
    /// presents as blobs that never reap — not as a unit error. Internal clock
    /// math goes through [`Limits::ttl_ms`].
    pub ttl_seconds: u64,
    /// The pool's `lobby` constant, **only when it overrides [`LOBBY_DEFAULT`]**
    /// (§4.5). `None` means "I use the default" and is encoded as an *absent*
    /// field, never null — a peer that sees no `lobby_constant` derives its
    /// lobby key from [`LOBBY_DEFAULT`].
    ///
    /// Bytes on the wire (`primitive/bytes`, §4.5) because it is a **derivation
    /// input**, not a display string: §3.1 hashes it verbatim, and bytes is the
    /// shape that cannot acquire a normalization step on the way in. Held here
    /// as a `String` because every deployment sets a UTF-8 label; the codec is
    /// the boundary.
    ///
    /// The node itself never uses this: it is mode-blind and derives nothing
    /// (§1). This is a value the node *publishes for peers to derive with*,
    /// which is why it rides on `advertise` rather than touching any bucket.
    pub lobby_constant: Option<String>,
    /// Largest number of live keys. The backstop that keeps a stateless
    /// introducer from becoming an unbounded store under abuse.
    ///
    /// **Node-internal, never published.** §4.5's `system/signaling/limits` has
    /// exactly four fields and this is not one of them — emitting it would put
    /// an unspec'd key inside a spec'd type. It is also not a limit a *client*
    /// can act on: a peer cannot size a retry against a number describing the
    /// node's whole keyspace.
    pub max_keys: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_blob_bytes: 8192,
            max_bucket_blobs: 32,
            ttl_seconds: 60,
            lobby_constant: None,
            max_keys: 65_536,
        }
    }
}

impl Limits {
    /// [`ttl_seconds`](Self::ttl_seconds) in milliseconds, for the core's
    /// `now_ms` clock domain. The published contract is seconds; only this
    /// conversion knows about ms.
    pub fn ttl_ms(&self) -> i64 {
        (self.ttl_seconds as i64).saturating_mul(1000)
    }
}

// ---------------------------------------------------------------------------
// Verb results
// ---------------------------------------------------------------------------

/// The outcome of an `offer`. Both variants are success on the wire — the
/// distinction exists for metrics and tests, not for the caller's control flow.
/// §1.1 pin 2 makes a retry idempotent rather than an accumulation, so a peer
/// that re-offers after a timeout gets `Duplicate`, not a second copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfferOutcome {
    /// The message was added to the bucket.
    Stored,
    /// An identical message (same content digest) was already live at this key.
    Duplicate,
}

/// The `lobby`-mode key constant every peer falls back to
/// (`PROPOSAL-CONNECTIVITY-SIGNALING-AND-PUNCH` §2.2).
///
/// §2.2 Finding B: `lobby` previously named **no actual constant**, and "per
/// deployment" alone is a silent-never-meet bug — two peers pointed at the same
/// open node would each invent a different lobby input and never share a bucket.
/// So the constant is pinned, and a pool that wants its own advertises it.
pub const LOBBY_DEFAULT: &str = "lobby:default";

/// What `advertise` returns — `system/signaling/advertise-result` (§4.5): where
/// the node is, what it will accept, and — since v1.1 — whether it also serves
/// reflection.
///
/// **Three top-level fields, and the `lobby` override is not one of them.** It
/// lives inside [`Limits::lobby_constant`] because §4.5 puts it there, and a
/// peer reading the published contract reads one map, not two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advertisement {
    /// The node's reachable endpoint, as configured by the operator.
    pub endpoint: String,
    /// The operating limits above, including the `lobby` override.
    pub limits: Limits,
    /// This node's **own** §9.3 STUN listener(s) (§4.5.1, added v1.1), each an
    /// RFC 7064 `stun:`/`stuns:` URI in the pinned non-hierarchical form.
    ///
    /// **Empty is the whole of "absent."** §4.5.1 makes absent and empty the
    /// same fact — this node serves no reflection — so the decoded shape is a
    /// `Vec` and not an `Option<Vec>`: there is no third state to represent, and
    /// giving one a name would invite an emitter to publish `[]` where the wire
    /// contract is an omitted key. [`crate::data::advertisement_to_entity`] omits
    /// the key entirely when this is empty.
    ///
    /// **Never another node's.** A node publishes here only what it itself
    /// serves; a deployment-wide reflector set is `EXTENSION-REGISTRY` §3b's
    /// job, and a peer MUST NOT read this field as one.
    pub reflection_endpoints: Vec<String>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Everything the core can refuse. Deliberately small: a stateless mailbox has
/// few ways to fail, and every one of these is a refusal **before** any state
/// change — an `offer` that errors deposits nothing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CoreError {
    #[error("rendezvous key must be {} bytes, got {got}", RENDEZVOUS_KEY_LEN)]
    InvalidKeyLength { got: usize },
    #[error("message is {got} bytes, limit is {max}")]
    MessageTooLarge { got: u64, max: u64 },
    #[error("key already holds {max} live messages")]
    BucketFull { max: u64 },
    #[error("node is holding its maximum of {max} live keys")]
    CapacityExhausted { max: usize },
}

// ---------------------------------------------------------------------------
// The core
// ---------------------------------------------------------------------------

/// One deposited message. The `digest` is a **node-internal dedup index only**
/// — it never appears on the wire, is never returned to a caller, and is not a
/// substrate content hash. §1.1 pin 2 says "deduplicated by content hash"; this
/// is that dedup, computed over the opaque bytes the node was handed.
struct Deposit {
    message: Vec<u8>,
    digest: [u8; 32],
    expires_at_ms: i64,
}

/// The stateless keyed mailbox — the whole node, minus every question of how a
/// caller reaches it.
///
/// `now_ms` is a parameter on every state-touching method rather than a clock
/// this owns. Time is the caller's to supply, which keeps TTL behavior exactly
/// testable (mirrors `entity_route::resolve`) and keeps this module free of a
/// platform clock dependency.
pub struct SignalingCore {
    buckets: RwLock<HashMap<RendezvousKey, Vec<Deposit>>>,
    limits: Limits,
    endpoint: String,
    reflection_endpoints: Vec<String>,
}

impl SignalingCore {
    /// Build a core advertising `endpoint`, with default [`Limits`].
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self::with_limits(endpoint, Limits::default())
    }

    pub fn with_limits(endpoint: impl Into<String>, limits: Limits) -> Self {
        Self {
            buckets: RwLock::new(HashMap::new()),
            limits,
            endpoint: endpoint.into(),
            reflection_endpoints: Vec::new(),
        }
    }

    /// Override the pool's `lobby` constant (§2.2). A value equal to
    /// [`LOBBY_DEFAULT`] is normalized back to `None` so the advertisement
    /// stays byte-identical to a node that never set it — "override" and
    /// "explicitly restated the default" must not be two different wire shapes
    /// for the same fact.
    pub fn with_lobby(mut self, lobby: impl Into<String>) -> Self {
        let lobby = lobby.into();
        self.limits.lobby_constant = if lobby == LOBBY_DEFAULT {
            None
        } else {
            Some(lobby)
        };
        self
    }

    /// Declare this node's **own** §9.3 STUN listener(s), published in
    /// `advertise`'s top-level `reflection_endpoints` (§4.5.1, added v1.1).
    ///
    /// Set these **only if this deployment actually serves reflection.**
    /// Advertising a reflector the node does not run is non-conformant (§11.5),
    /// and so is the converse as of v1.1 — serving reflection while advertising
    /// nothing is the exact state that made a reflector undiscoverable. The
    /// reference deployment co-locates reflector and relay on one VM
    /// (`GUIDE-REFERENCE-DEPLOYMENT` §3.2/§5), so there the advertising node
    /// *is* the reflector.
    ///
    /// Each entry MUST be an RFC 7064 `stun:`/`stuns:` URI in the pinned
    /// non-hierarchical form; **validate with
    /// [`validate_reflection_endpoint`](crate::validate_reflection_endpoint)
    /// first**, because [`advertise`](Self::advertise) publishes what it is
    /// given, unchanged. That is the contract, not laxness: §4.5.1 pins the wire
    /// form precisely so that no emitter and no consumer runs a transform.
    ///
    /// Empty (the default) advertises no reflection — the already-legal state
    /// every pre-v1.1 node was in, and an absent key on the wire.
    pub fn with_reflection_endpoints<S: Into<String>>(
        mut self,
        endpoints: impl IntoIterator<Item = S>,
    ) -> Self {
        self.reflection_endpoints = endpoints.into_iter().map(Into::into).collect();
        self
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// The §9.3 listeners this node publishes, in configured order. Empty means
    /// it serves no reflection.
    pub fn reflection_endpoints(&self) -> &[String] {
        &self.reflection_endpoints
    }

    /// The `lobby` constant peers should derive with at this node — the
    /// override if one is set, else [`LOBBY_DEFAULT`]. Client-side convenience;
    /// the node never derives anything itself.
    pub fn lobby_constant(&self) -> &str {
        self.limits
            .lobby_constant
            .as_deref()
            .unwrap_or(LOBBY_DEFAULT)
    }

    // -----------------------------------------------------------------------
    // offer (§1, §1.1 pin 2) — append with content-hash dedup
    // -----------------------------------------------------------------------

    /// Deposit `message` at `key`.
    ///
    /// **Appends** — a key holds a *set* of blobs, deduplicated by content
    /// digest (§1.1 pin 2). Replace would make the last writer erase everyone in
    /// the inherently multi-party `lobby` and `tag` modes; dedup makes a peer's
    /// retry idempotent rather than an accumulation.
    ///
    /// Expired deposits at this key are dropped before the limit checks, so a
    /// bucket that has aged out does not count against `max_messages_per_key`.
    ///
    /// **Refuse, never evict** (§1.1 pin 5). An over-size message is refused
    /// with `message_too_large` rather than truncated; a full bucket is refused
    /// with `bucket_full` rather than making room. Eviction would reproduce
    /// exactly the silent-never-meet shape this surface exists to avoid — the
    /// evicted peer believes it is at the key and waits — while a refusal tells
    /// the offerer it failed and can be retried. (Filling a bucket to deny
    /// service is a rate-limit concern, open item 2, not a bucket-semantics one.)
    pub fn offer(
        &self,
        key: RendezvousKey,
        message: &[u8],
        now_ms: i64,
    ) -> Result<OfferOutcome, CoreError> {
        if message.len() as u64 > self.limits.max_blob_bytes {
            return Err(CoreError::MessageTooLarge {
                got: message.len() as u64,
                max: self.limits.max_blob_bytes,
            });
        }

        let digest: [u8; 32] = Sha256::digest(message).into();
        let mut buckets = self.buckets.write().expect("signaling bucket lock");

        // Drop expired deposits at this key first — an aged-out bucket must not
        // consume capacity, and a re-offer of a message whose earlier copy has
        // expired is a fresh `Stored`, not a `Duplicate`.
        if let Some(deposits) = buckets.get_mut(&key) {
            deposits.retain(|d| d.expires_at_ms > now_ms);
            if deposits.is_empty() {
                buckets.remove(&key);
            }
        }

        match buckets.get(&key) {
            Some(deposits) => {
                if deposits.iter().any(|d| d.digest == digest) {
                    return Ok(OfferOutcome::Duplicate);
                }
                if deposits.len() as u64 >= self.limits.max_bucket_blobs {
                    return Err(CoreError::BucketFull {
                        max: self.limits.max_bucket_blobs,
                    });
                }
            }
            None => {
                if buckets.len() >= self.limits.max_keys {
                    return Err(CoreError::CapacityExhausted {
                        max: self.limits.max_keys,
                    });
                }
            }
        }

        buckets.entry(key).or_default().push(Deposit {
            message: message.to_vec(),
            digest,
            expires_at_ms: now_ms.saturating_add(self.limits.ttl_ms()),
        });
        Ok(OfferOutcome::Stored)
    }

    // -----------------------------------------------------------------------
    // collect (§1, §1.1 pin 1) — non-destructive read
    // -----------------------------------------------------------------------

    /// Return every live message at `key`, **removing nothing** (§1.1 pin 1),
    /// in **deposit order, oldest first** (§1.1 pin 4). TTL is the only reaper.
    ///
    /// The order is a cross-peer pin, not a preference. A reader scans a bucket
    /// for the first message it can act on
    /// (`PROPOSAL-CONNECTIVITY-SIGNALING-AND-PUNCH` §3.2), so two impls scanning
    /// in different orders answer *different peers* out of one shared `lobby`
    /// bucket — a divergence wearing the costume of an implementation detail.
    /// The `Vec` push in [`offer`](Self::offer) plus this in-order iteration is
    /// the whole mechanism; `pin4_` in `tests.rs` is what keeps it from being
    /// "optimized" into a `HashSet`.
    ///
    /// A handshake has both peers polling, and a `pair` bucket may be collected
    /// by both sides and re-read on retry. A draining read would make a retry
    /// lose the peer's offer — a silent handshake failure indistinguishable from
    /// the peer never having offered at all, which is the exact failure mode
    /// this surface exists to avoid.
    ///
    /// An unknown key returns an empty list, not an error: absence and
    /// not-yet-offered are the same state to a rendezvous, and a peer polling
    /// ahead of its counterpart is the normal case, not a fault.
    pub fn collect(&self, key: &RendezvousKey, now_ms: i64) -> Vec<Vec<u8>> {
        let buckets = self.buckets.read().expect("signaling bucket lock");
        buckets
            .get(key)
            .map(|deposits| {
                deposits
                    .iter()
                    // Expired-but-not-yet-reaped deposits are invisible. The
                    // reaper is an optimization; this filter is the contract.
                    .filter(|d| d.expires_at_ms > now_ms)
                    .map(|d| d.message.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    // -----------------------------------------------------------------------
    // advertise (§1)
    // -----------------------------------------------------------------------

    /// Announce the endpoint, its limits, and any `lobby` override, for
    /// `PROPOSAL-REGISTRY-SERVICE-ADVERTISEMENT` pool membership.
    ///
    /// Note what this is *not*: it is the node describing **itself**. The
    /// deployment-level `system/registry/service-advertisement` — the signed,
    /// priority-ordered **pool** two peers rendezvous-hash into — is a separate
    /// entity in the registry zone. This verb supplies a member's facts; the
    /// registry publishes the pool.
    pub fn advertise(&self) -> Advertisement {
        Advertisement {
            endpoint: self.endpoint.clone(),
            limits: self.limits.clone(),
            // Verbatim (§4.5.1): the configured strings, in configured order, no
            // normalization and no default. There is deliberately no
            // public-STUN fallback — a node must never enrol a third-party
            // reflector it does not run, so empty stays empty and means
            // host-candidates-only to the peer that reads it.
            reflection_endpoints: self.reflection_endpoints.clone(),
        }
    }

    // -----------------------------------------------------------------------
    // Reaping (§1.1 pin 3 — binding on the node)
    // -----------------------------------------------------------------------

    /// Drop every expired deposit and every key left empty. Returns the number
    /// of deposits removed.
    ///
    /// Purely a memory reclaim: [`collect`](Self::collect) already refuses to
    /// return expired deposits, so calling this never changes what a peer
    /// observes. That ordering is deliberate — correctness must not depend on a
    /// reaper having run, or a node under load would serve stale rendezvous.
    pub fn reap(&self, now_ms: i64) -> usize {
        let mut buckets = self.buckets.write().expect("signaling bucket lock");
        let mut removed = 0;
        buckets.retain(|_, deposits| {
            let before = deposits.len();
            deposits.retain(|d| d.expires_at_ms > now_ms);
            removed += before - deposits.len();
            !deposits.is_empty()
        });
        removed
    }

    /// Live key count — for the node's own metrics and for tests. Counts keys
    /// still present, including any holding only expired deposits that
    /// [`reap`](Self::reap) has not yet visited.
    pub fn key_count(&self) -> usize {
        self.buckets.read().expect("signaling bucket lock").len()
    }
}
