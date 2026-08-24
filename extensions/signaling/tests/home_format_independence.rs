//! The load-bearing §2.2 pin, proved against the thing that would break it.
//!
//! `PROPOSAL-CONNECTIVITY-SIGNALING-AND-PUNCH` §2.2: the rendezvous key's digest
//! format is pinned to the **SHA-256 floor (`0x00`) regardless of the deriving
//! peer's home format**. The staging handoff §7 calls this the load-bearing one
//! of the three free variables — a content hash is self-describing and
//! format-carrying, which is correct everywhere else *because* content is
//! authored once and its hash travels with it. A rendezvous key inverts that:
//! it is a lookup token two independent parties must reproduce. Let it follow
//! the home format and a SHA-384-home peer and a SHA-256-home peer derive
//! different keys for the same agreed input and **silently never meet**, with
//! nothing failing loudly.
//!
//! # Why this lives in its own test binary
//!
//! `entity_hash::set_default_hash_format` writes a **process-global** atomic.
//! Cargo runs the tests within one binary on parallel threads, so flipping it in
//! a shared binary would leak into unrelated tests. An integration-test file
//! gets its own process, so the flip is contained. That containment is the whole
//! reason for the extra file.
//!
//! # What it actually catches
//!
//! Not an arithmetic slip — a plausible refactor. `Entity::new` hashes under
//! `default_hash_format()`, so deriving the key by constructing an entity (the
//! obvious-looking way, and how every other value in this crate is built) is
//! wrong in exactly this invisible manner. The assertion below fails the moment
//! someone makes that swap.

use entity_hash::{HASH_ALGORITHM_SHA256, HASH_ALGORITHM_SHA384};
use entity_signaling::{key, LOBBY_DEFAULT};

#[test]
fn derivation_ignores_the_peers_home_hash_format() {
    // Derive under the SHA-256 floor — the ordinary case.
    entity_hash::set_default_hash_format(HASH_ALGORITHM_SHA256);
    let baseline = [
        key::pair_key("alice", "bob"),
        key::tag_key("chess"),
        key::secret_key("s3cr3t"),
        key::lobby_key(LOBBY_DEFAULT),
    ];

    // Now become a SHA-384-home peer. Everything this process authors from here
    // carries a 49-byte content hash — except the rendezvous key, which MUST NOT
    // move a single byte.
    entity_hash::set_default_hash_format(HASH_ALGORITHM_SHA384);

    // Sanity: the flip really is in effect, so a passing assertion below is
    // meaningful rather than vacuous.
    let home_authored = entity_entity::Entity::new(
        "test/home-format-probe",
        entity_ecf::to_ecf(&entity_ecf::text("probe")),
    )
    .expect("probe entity");
    assert_eq!(
        home_authored.content_hash.algorithm, HASH_ALGORITHM_SHA384,
        "the home-format flip must actually be live, or this test proves nothing"
    );

    let under_sha384 = [
        key::pair_key("alice", "bob"),
        key::tag_key("chess"),
        key::secret_key("s3cr3t"),
        key::lobby_key(LOBBY_DEFAULT),
    ];

    for (before, after) in baseline.iter().zip(under_sha384.iter()) {
        assert_eq!(
            before, after,
            "a SHA-384-home peer must derive byte-identical rendezvous keys, \
             or it never meets a SHA-256-home peer"
        );
        assert_eq!(after.as_bytes().len(), 33);
        assert_eq!(after.as_bytes()[0], 0x00);
    }

    // Leave the process as we found it.
    entity_hash::set_default_hash_format(HASH_ALGORITHM_SHA256);
}
