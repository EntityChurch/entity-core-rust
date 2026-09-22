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
