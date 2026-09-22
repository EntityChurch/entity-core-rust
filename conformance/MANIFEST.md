# Vendored ECF Conformance Vectors

This directory holds the canonical ECF conformance corpus vendored from
the spec repo. The Rust `wire-conformance` harness loads it via
`--input`.

The `.cbor` is the build-fixture output produced by Go's
`cmd/internal/wire-conformance build-fixture` against the `.diag` source
at its canonical path in the spec repo:
`entity-core-protocol` `specs/test-vectors/ecf-conformance/conformance-vectors.diag`.

Per the ECF conformance cross-team assignment §2.2, this
impl does NOT regenerate `.cbor` from `.diag` — that would defeat the
cross-bless of the loaded fixture.

## Current — `conformance-vectors.cbor`

- File: `conformance-vectors.cbor`
- SHA-256: `9695b1f1d939cfdfdd4297f8ad32122d424b1ec180cfae74c92d509d88f7c6dc`
- Source: `entity-core-protocol`
  `specs/test-vectors/ecf-conformance/conformance-vectors.cbor` (canonical)
- Spec: `ENTITY-CBOR-ENCODING.md`, Appendix E
- Vector count: 71

### ⛔ This digest is PARTIALLY UNBLESSED — `CQ-22` / `S-1`, open as of 2026-09-16

**`9695b1f1…` is no longer blessed on the `signature` category, and the other
68 vectors are unaffected.** `0.8.2.26` ruled `CQ-22`: a signature signs the
target entity's **full `content_hash`** (format code ‖ digest), and
`ENTITY-CORE-PROTOCOL` §7.3 is now declared its single normative home. The
`signature` category's Appendix E entry read *"signs the canonical bytes"* —
a different message — and the fixture was generated to match the entry.

⭐ **The sole implementation of the losing reading was the fixture.** This
peer is already right: every signing site passes `Hash::to_bytes()`, which is
the full wire form including the leading format byte
(`core/capability/src/mint.rs`, `core/peer/src/ingest.rs`), and 8 of 8 live
peers complete the handshake on the §7.3 reading. **Nothing in this tree
moves for `CQ-22`.**

**Do NOT re-pin yet (`S-2`).** `entity-core-go` has recomputed
`signature.1/.2/.3` and authored `signature.4`; the new `.cbor` sha256 is
`16861cd06be9d2dca71137f55551d693538d3b1885f581ab55eb3541f63b00b6`. It
publishes only after two things that are not ours — `entity-system-conformance`
cross-blessing the four canonicals with a second independent codec (s1-py),
and the protocol seat landing the `.diag` diff plus the rebuilt `.cbor`. Re-pin
the digest above when that lands; until then the line above is the corpus we
actually vendor and this block is why a `signature`-category result from it is
not evidence.

⚠ **Worth carrying past this entry:** nobody had ever *executed* a Class-B
category before `entity-system-conformance` executed one. Reading a normative
artifact and running it are different acts, and only one of them is a
measurement.

**Verify by DIGEST, never by filename.** The corpus was renamed upstream
(`conformance-vectors-v1.cbor` → `conformance-vectors.cbor`), and a vendor gate
keyed on the filename does not fail when the name moves — it becomes *unable to
look*, and that reports as a warning sitting next to errors rather than as a
stale corpus. The digest above is the identity; the name is a convenience.

## Superseded

- `vectors-v1.cbor`, SHA-256
  `9d96f00754238928557b8c3462b9078ca31cdf0d0ff8d6065c0b9a61e783a4bd`,
  69 vectors, vendored from `entity-core-go/test-vectors/v1/` (pre-cross-bless
  starter, pre-F29/F30). Removed when the canonical corpus was republished at
  the spec-repo path this file had already named as the re-vendor trigger.
