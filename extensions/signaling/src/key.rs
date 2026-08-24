//! The rendezvous key — **peer-side** derivation
//! (`PROPOSAL-CONNECTIVITY-SIGNALING-AND-PUNCH` §2.2, revised 2026-07-28).
//!
//! ```text
//! payload        = "entity:rdv:v1" ‖ SEP ‖ mode ‖ SEP ‖ canonical(mode_input)
//! rendezvous_key = varint(0x00) ‖ SHA-256( ecf_for_hash( "system/signaling/rendezvous-key",
//!                                                        cbor_bstr(payload) ) )
//! ```
//!
//! **This binds peers only.** The node is mode-blind — it compares 33 opaque
//! bytes and derives nothing ([`crate::core`]). Everything here is a client
//! obligation, which is why it lives beside the server in this crate but shares
//! none of its state.
//!
//! # Why every free variable is pinned
//!
//! Both peers MUST produce byte-identical hash input **and** byte-identical key
//! bytes. Divergence means the two peers derive different keys and **silently
//! never meet** — nothing errors, nothing logs, the handshake just never
//! completes. That failure is invisible to a same-impl test (encoder and decoder
//! agree with themselves), so §2.2 pins each variable and §2.2.1 supplies
//! *differential* properties instead of authored vectors. `tests.rs` holds all
//! six.
//!
//! The load-bearing one is the **format code**. A content hash is normally
//! self-describing and format-carrying, and that is correct everywhere else
//! *because* content is authored once and its hash travels with it. A rendezvous
//! key inverts that: it is a **lookup token two independent parties must
//! reproduce**. So it is pinned to the SHA-256 floor (`0x00`) **regardless of
//! the deriving peer's home format** — otherwise a SHA-384-home peer and a
//! SHA-256-home peer derive different keys for the same agreed input and never
//! meet, having passed every other check.
//!
//! Concretely that means this module MUST NOT build an [`entity_entity::Entity`]
//! to get a hash: `Entity::new` hashes under `entity_hash::default_hash_format()`,
//! a **process-global** set at peer construction. [`Hash::compute`] is
//! unconditionally SHA-256, which is why it is what we call.
//! `tests/home_format_independence.rs` flips that global and proves the
//! derivation ignores it.

use entity_ecf::{bytes, to_ecf};
use entity_hash::Hash;

use crate::core::{CoreError, RendezvousKey};

/// The `type` half of the hash input — pinned by §2.2, since the substrate
/// content-hash primitive hashes ECF `{data, type}` and has no bare-byte form.
pub const RENDEZVOUS_KEY_TYPE: &str = "system/signaling/rendezvous-key";

/// The domain-separation prefix. Versioned so a future derivation change is a
/// new domain rather than a silent reinterpretation of the same bytes.
pub const DOMAIN: &str = "entity:rdv:v1";

/// `SEP` = ASCII US. It appears **after the domain string and after the mode
/// tag** — not only before the input.
pub const SEP: u8 = 0x1F;

/// The exact ASCII mode tags (§2.2). These are wire-visible through the derived
/// key, so they are spelled here once and never constructed by formatting.
pub const MODE_PAIR: &str = "pair";
pub const MODE_TAG: &str = "tag";
pub const MODE_SECRET: &str = "secret";
pub const MODE_LOBBY: &str = "lobby";

// ---------------------------------------------------------------------------
// The derivation
// ---------------------------------------------------------------------------

/// Build the pre-hash payload. Exposed because §2.2.1's stage-bisect names it
/// as the first place two disagreeing impls compare bytes: if the payloads
/// match and the keys don't, the fault is in the CBOR framing or the digest,
/// not the concatenation.
pub fn rendezvous_payload(mode: &str, canonical_input: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(DOMAIN.len() + mode.len() + canonical_input.len() + 2);
    payload.extend_from_slice(DOMAIN.as_bytes());
    payload.push(SEP);
    payload.extend_from_slice(mode.as_bytes());
    payload.push(SEP);
    payload.extend_from_slice(canonical_input);
    payload
}

/// Derive a key from a mode tag and an already-canonicalized input.
///
/// Prefer the four named constructors below — they own the canonicalization,
/// which is where `pair`'s sort-and-separate rule lives. This is the escape
/// hatch for a mode added upstream before this crate knows about it.
pub fn derive(mode: &str, canonical_input: &[u8]) -> RendezvousKey {
    let payload = rendezvous_payload(mode, canonical_input);
    // `data` = payload wrapped as a single CBOR bstr with a minimal-length head
    // (§2.2). `ecf_for_hash` then embeds these bytes verbatim under the "data"
    // key — the same double-encoding every entity has, where `data` is itself a
    // CBOR value.
    let data = to_ecf(&bytes(payload));
    // Hash::compute is unconditionally SHA-256 → format 0x00, 33 bytes on the
    // wire. NOT Entity::new, which would follow the process home format.
    let hash = Hash::compute(RENDEZVOUS_KEY_TYPE, &data);
    RendezvousKey::from_slice(&hash.to_bytes())
        .expect("a SHA-256 content hash is exactly 33 bytes on the wire")
}

// ---------------------------------------------------------------------------
// The four modes (§2.2)
// ---------------------------------------------------------------------------

/// `pair` — exactly those two peers meet. Identity *is* the key, so no secret
/// is needed and none is implied: peer-ids are public.
///
/// Canonicalization: the two peer-ids **byte-wise sorted ascending**, joined
/// **with `SEP` between them** (`lo ‖ SEP ‖ hi`).
///
/// Both halves are load-bearing. The sort makes `pair(A,B) == pair(B,A)`, so
/// either peer may derive first. The separator disambiguates: bare
/// concatenation makes `sorted("ab","c")` and `sorted("a","bc")` both yield
/// `abc`, so two *different* pairs would share one bucket.
pub fn pair_key(peer_a: &str, peer_b: &str) -> RendezvousKey {
    let (lo, hi) = if peer_a.as_bytes() <= peer_b.as_bytes() {
        (peer_a, peer_b)
    } else {
        (peer_b, peer_a)
    };
    let mut input = Vec::with_capacity(lo.len() + hi.len() + 1);
    input.extend_from_slice(lo.as_bytes());
    input.push(SEP);
    input.extend_from_slice(hi.as_bytes());
    derive(MODE_PAIR, &input)
}

/// `tag` — anyone who knows the label meets. A **public** discovery
/// convenience, explicitly **not** access control: the label is guessable by
/// design.
///
/// The label is byte-exact UTF-8: no case-folding, no Unicode normalization
/// (see the module note on `_key`).
pub fn tag_key(label: &str) -> RendezvousKey {
    derive(MODE_TAG, label.as_bytes())
}

/// `secret` — anyone who knows the string meets, so knowing it *is* a
/// lightweight admission gate.
///
/// **Only as strong as its entropy** (§2.2). A short, human-memorable phrase is
/// enumerable — anyone who guesses it lands in the same bucket — and is really
/// a [`tag_key`] wearing a different name. A `secret` used as a gate MUST be a
/// generated high-entropy string exchanged verbatim. Even then it *introduces*;
/// it never authorizes: the coordination entities are still signed end-to-end
/// and the resulting connection still runs the ordinary handshake and capability
/// flow. The capability-gated admission mode is the real access control.
pub fn secret_key(secret: &str) -> RendezvousKey {
    derive(MODE_SECRET, secret.as_bytes())
}

/// `lobby` — "just connect me to anyone here, right now."
///
/// Pass the pool's constant: [`crate::LOBBY_DEFAULT`] unless the node's
/// `advertise` published an override, in which case pass that. §2.2 Finding B:
/// "per deployment" without an actual named default is a silent-never-meet bug,
/// because two peers on the same open node would each invent a different input.
pub fn lobby_key(lobby_constant: &str) -> RendezvousKey {
    derive(MODE_LOBBY, lobby_constant.as_bytes())
}

// ---------------------------------------------------------------------------
// Parsing a key back off the wire
// ---------------------------------------------------------------------------

/// Accept 33 key bytes from a foreign client, rejecting a wrong width.
///
/// This is the §2.2.1 "fixed format code" check at the edge: an otherwise
/// -correct SHA-384 implementation produces a 49-byte key and passes every other
/// differential property. Refusing it loudly here converts a silent never-meet
/// into a visible error at the first request.
pub fn key_from_wire(bytes: &[u8]) -> Result<RendezvousKey, CoreError> {
    RendezvousKey::from_slice(bytes)
}
