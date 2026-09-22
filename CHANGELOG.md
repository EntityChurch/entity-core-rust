# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Conformance is the contract, not the version number** ([ADR-0012]). Entries that
claim a wire behaviour name the cross-impl evidence; a green unit suite is not a
release. Published numbers are oracle-pinned and reproducible.

## [Unreleased]

Development lands on `dev`; `master` carries the last release.

### Changed in ways that can break an existing caller

**Breaking: yes**, on all three counts — an exported signature moved, a published path
went away, and refusals that a peer can observe changed their `status`/`code` pair. This
section had said *Documentation* and nothing else, which was a false summary of the
tree: read it as the correction, not as a late addition.

**A published file is gone.** `conformance/vectors-v1.cbor` has been in every release
since `v0.8.0` and is **not** in this one. The corpus it carried was superseded and
de-versioned; the file that replaces it is `conformance/conformance-vectors.cbor`, and
`conformance/MANIFEST.md` carries both digests so the two are distinguishable by content
rather than by filename. **Anything pinning the old path gets a 404** — repoint it. The
new corpus is 71 vectors and is not a rename of the old 69; it is a different corpus.

**Exported items that moved.** Each needs a caller edit, not a recompile:

- `entity_capability::canonicalize` returns `String`, not `Option<String>`. The two
  reserved shapes it used to answer `None` for — a `./`- or `../`-leading path, and a bare
  `*/rest` — now canonicalize to the `NEVER_MATCH` sentinel, which matches nothing in
  either operand of `matches_pattern`. A caller that treated `None` as *reject* and
  `Some` as *admit* now admits a grant that covers no path, which is the intended
  §5.4 reading; a caller that needs the old rejection must test for the sentinel.
- `entity_relay::CODE_UNKNOWN_OPERATION` is removed. Use
  `entity_relay::CODE_UNSUPPORTED_OPERATION`. The string moved too — see the wire note
  below; this is not a pure rename.
- `entity_relay::ModeStore::put` takes two further arguments, `cost: u64` and
  `now_ms: i64`, so the store can account for live bytes against a retention window.
- `entity_signaling::webrtc::find_counterpart_offer` takes `&[Collected]` where it took
  an `IntoIterator`, plus a third argument, the caller's own peer id. It now returns the
  **newest** unanswered counterpart offer rather than the first one it finds, and skips
  offers this peer has already answered.
- `entity_peer::remote::RemoteState::remove_inbound` is removed; the eviction it wrapped
  is reached through the teardown path that owns it.

**Error enums gained variants, and neither is `#[non_exhaustive]`.** An exhaustive `match`
downstream stops compiling until the new arms are handled:

- `entity_protocol::ProtocolError` — `IncompatibleProtocol`, `InvalidRequest(&'static str)`,
  `InvalidNonce(&'static str)`, `IdentityMismatch(&'static str)`.
- `entity_wire::WireError` — `CborTag { offset }`, `IncludedKeyMismatch { key, actual }`,
  `TruncatedFrame`.

**Public structs gained public fields**, so a full struct literal no longer compiles
(`..Default::default()` is unaffected where a `Default` exists): `PeerConfig`
(`relay_store_retention_ms`, `relay_max_storage_bytes`), `Connection` (`local_protocols`),
`ForwardRequest` (`expires_at`), `AdvertiseLimits` (`max_retention_ms`), `StoredEntry`
(`cost`).

**Refusals a peer can observe changed.** These are wire-visible and a conformance
expectation pinned to the old pair will fail:

- An unimplemented relay operation answers **`501 unsupported_operation`**, not
  `400 unknown_operation`. The old code was a minted synonym in no spec code set, and the
  old status told the caller its request was malformed when the request was fine.
- A CBOR **tag** (major type 6) anywhere in a frame is refused `400 non_canonical_ecf`
  rather than being decoded. Tags are not part of ECF; this is a pre-admission refusal
  distinct from *these bytes do not decode*.
- An EXECUTE whose handler URI names a peer that is not us is refused
  `400 invalid_request`. It was previously served — our handler ran under their address.
- A pre-`hello` `authenticate` is discriminated on the frame's operation rather than on
  connection state, so it is no longer processed as a `hello` and no longer answers
  `400 handshake_failed`.
- Capability `exclude` is honoured at sites where it previously failed open, and the
  authorization subject is the first effective target rather than the raw request path.
  A grant that was accepted before may now be refused; that is the fix.
- Relay storage is bounded: entries carry a byte cost against a retention window, and a
  `put` over the ceiling is refused `507`. A payload over the frame ceiling is `413`.

**Kernel consumers should expect to edit, not just re-pin.** `PeerConfig`, `ProtocolError`
and `WireError` are all on the embedding path, so a downstream peer moving to this release
does more than bump a ref.

### Documentation

- **`AGENTS.md` split into `AGENTS.md` + `docs/agents/memory/`.** It had reached
  217,374 bytes — one file, loaded in full by every agent, holding both *how to
  work here* and every failure mode this implementation has earned. `AGENTS.md`
  is now ~17 KiB of the first thing; the 55 catalogued anti-patterns moved
  verbatim into eight topic files indexed **by symptom** in
  `docs/agents/memory/INDEX.md`. Nothing was deleted, and the scripts that
  performed the move are in `tools/` so the diff is checkable as a move.
- **`README.md`** gained a *Working on this repo* section and had two lines
  corrected that had been wrong for some time: `make check` is `lint + test +
  godot` (not `lint + test`), and the downstream-consumer example pinned a
  release tag that does not exist. The **standalone-build contract is now
  measured** rather than asserted: a clean clone with no sibling checkouts
  present runs `make test` green — 131 suites, 2,774 tests, exit 0.
- **Routing packets moved to `docs/outbox/`**, with the receiving half
  (per-counterpart watermarks) in `docs/status/TRACKER-*.md`. Internal;
  neither publishes.
- **`CANONICAL-DOCS.toml`** now declares what each documentation directory *is*,
  so the release gates stop inferring it from path names.

## [0.9.0] — 2026-08-23

_This number is this implementation's own, not the protocol's_ ([ADR-0002]:
3-field SemVer per implementation, spec level carried out-of-band). **0.9.0 and
not 0.8.1** because the changes below are breaking for a consumer — the `log`
decoder split from `fetch`, optional arrays remodelled from `Option<Vec>` to
`Vec`, the §10.3 seam returning `Result` where it returned `Option`, a new
dispatch-ceiling type in the peer's signature — and pre-1.0 SemVer puts breaking
in MINOR. **0.9.0 and not 0.8.2** because 0.8.2 is `entity-core-protocol`'s
release number and this repo never chose it. `entity-core-go` and
`entity-core-py` independently reached 0.9.0 by their own derivations; that is a
coincidence, not a fleet version.

Work since `v0.8.0` (311 commits on the development line). Curated by consequence
rather than exhaustive — `docs/STATUS.md` carries the per-packet narrative, and
every measurement quoted below is stated here in full: the validation reports it
was drawn from are internal working memory and do not publish.

**Cross-impl state at this entry.** `scripts/validate-complete.sh rust` (core-go's
release gate) — **`REAL_EXIT=0`, all six passes exit 0**, which had not previously
been true at this seat. Pass 1 **1611 · 1601P · 10W · 0F · 0S**; pass 1b **755 · 645P
· 7W · 0F** (103 profile-keyed skips, exempt by V7 §9.0); pass 2 **55/55**; pass 3
**registry_issuer 32/32** + **substitute 8/8**. Two declared exclusions
(`docs/validation/CONFORMANCE-EXCLUSIONS.md`) are *not* passes and are not counted.

### Security

- **Persisted private keys are `0600`, set at creation** — both the Ed25519 and
  Ed448 `save_to_file` arms route through one `write_private_key_file` (`O_CREAT`
  with mode, plus a permission clamp on the open fd so re-minting over an existing
  `0644` key repairs it). Previously world-readable. Release blocker B-1.
- **A tampered interior HAMT node is a forgery, not an absence** — a node whose
  bytes failed verification left `VerifyingFetchStore::get` by the same door as a
  node that was never published, so `resolve` answered `Ok(None)` ("the publisher
  never bound that key") about an origin that had just served a forgery. Reached
  every consumer of a signed root. The mismatch is now latched and checked before
  `resolve` believes a `None`.
- **The in-process sub-dispatch path ran no authorization check of any dimension**
  (§5.2 D1) — proven by enumerating every authorization symbol across the whole
  function, not by grep. Fixed with a new `DispatchCeiling::{PeerRoot,
  Handler(Option<_>)}`, because `Option<CapabilityToken>`'s `None` had to mean
  *deny* for a grantless handler and *allow* for the peer's own entry points.
- **Capability temporal terms cannot wrap on either side of the wire** (CAP-6) — an
  `expires_at` above `i64::MAX` was encoded negative, and an unrepresentable one was
  *decoded as absent*, i.e. ingested as a capability that never expires while
  core-go refused the same bytes. Mint, encode and decode are all bound now.
- **`request`-minted root tokens are clamped** to `MIN(caller_cap.expires_at, now +
  policy.ttl_ms, now + request.ttl_ms)` (§6.2 step 4), and the hypothetical probe
  that made the mint unreachable — every expiring caller got a 403 — is built with
  the clamped value.
- **The §4.3 pin-delta predicate compares raw field bytes**, never decoded structs:
  a decode-then-re-encode compare drops forward-compat keys and reads a changed pin
  list as "no change", rewriting the registry's most privileged row under
  `registry-configure` alone.
- **`compute/apply` on a builtin path rejects a carried `capability`/`resource`**
  (§2.1 Q23) at both arms, including the unrecognized-bare-name fall-through that
  reached external dispatch with them still attached.
- Registry `revoke`/`renew` verify the caller at all three layers; the §6a.6
  by-target revocation index is consistent across its read *and* write shapes;
  `--signaling-node` no longer seeds a `default` capability policy.

### Added

- **COMPUTE v3.24→v3.26** — the four collection primitives (`range`, `group-by`,
  `concat`, `assoc`), their five spec-pinned args types, the v3.25 corner rulings,
  and the contained-error boundary. C-11 Corner 1 (`map`'s output element is a
  contained position, with a carve-out keyed on the shared-resource criterion and
  on the error `code`), C-12, and D3 (`concat-args.collections` as a scalar hash).
- **REGISTRY** — v1.13 TTL cascade and ceilings, v1.19's §4.1b broad/narrow
  classifier, §4.3 `set-resolver-config`/`get-resolver-config`, the §6a.9 peer-issued
  carrier with its manual-approval path, and R-27's four pin-authority clauses.
- **SIGNALING / NETWORK / WebRTC** — the §6.1 sealed deposits, the §6.3 container
  (parametric over key type), §6.5 symmetric originate and mutual minting, §7
  rendezvous-key narrowing, §6.7.1 multi-reflector NAT probing, §6.7.2
  check-reachability, and the browser arm of the §10.3 establisher seam across the
  wasm worker boundary.
- **wasm worker stack** — control plane versioned to `PROTOCOL_VERSION` 12, WebRTC
  provisioning, per-peer install reporting, ICE gathering observability.
- **SDK** — `follow()` subtree mirroring, `FollowMode::Continuation`,
  `ContinuationSpec`, and the §10.3 seam exposed on the builders.
- **Peer/CLI** — §6.9a `--seed-policy` (the third posture between open access and
  the bare floor), `--signaling-node`, `--ws-listen`, signed-root republish on every
  tree-root change, and single-flight establishment per peer.
- **Continuation §3.10 marker collection** — a MUST-write now has a named reaper,
  swept at the top of the bind path, wired at every binder.
- `docs/validation/CONFORMANCE-EXCLUSIONS.md` — declared exclusions, each with the
  in-process satisfaction and the mutation that proves it has teeth.

### Changed

- **`log` takes `start_at`; `fetch` keeps `since`** (§4.4.2). The two operations had
  shared one decoder while `since` meant an exclusive watermark walking newer on one
  and an inclusive cursor walking older on the other — the same argument returned
  disjoint sets with no error anywhere. The decoder and the SDK builder are split.
- Optional arrays are encoded by **absence**, not `[]`, and modelled as a plain
  `Vec` rather than an `Option<Vec>`.
- `system/inbox/delivery` and `system/subscription/notification` are cut — the
  one-round MUST.
- The §4.1 registry filter is a pure function of the name, and `name_constraints`
  is §4's one matcher (both arch rulings; neither seat's original reading survived).

### Fixed

- §4.4.17 V6 exclude-pattern validation at the writer, covering `exclude_types` as
  well as `exclude`; the REGISTRY §4 dispatch grammar refuses nothing, and says so
  at the matcher.
- §4.4.18 revision merge total order at both sites; §4.6 type patterns defer to the
  §5.4 matcher.
- Hash-width assumptions swept per SPECIFICATION-FORMAT §8.4.5 — the content-URL
  builders were already right but one guarding test was a tautology; two genuine
  fixed-width pins (`revision::is_prefix_config_path`, `store::opfs` framing) were
  write-shape/read-shape asymmetries inside a single file.
- The v1.22 §4.3 fail-closed bundler no longer 502s reentrant
  `system/validate/dispatch-outbound` — it reads in-band authority for transport
  assembly while still refusing an unresolvable granter.
- The §A1 eviction no longer kills the loop that owes the §5.4 escalation.
- `canonicalize` resolves `entity://` to the address it names.
- Four v3.24 args-type descriptors were answerable but unadvertised — the third
  registration site.
- **`system/substitute/http` is registered on the peer** (EXTENSION-SUBSTITUTE §6/§7)
  — it was built, tested and reachable from nothing, which is why the release gate
  scored it as an unexercised surface. Registering it exposed four conformance
  defects, all now fixed: §2.3's `entry` was encoded as a CBOR `bstr` where go and py
  carry the source entity as a **value** (our encoder and decoder were wrong
  together, so the round-trip was green throughout); the §7 plaintext refusal
  answered 400 rather than **403**; and §2.2's `content_url_prefix` — REQUIRED, with
  the spec naming optional-with-derivation non-conformant — was derived from
  `tree_url_prefix`, in both the absent and the empty-string forms.

### Known gaps

- The §3 substitute chain-consult orchestrator (`ChainConsultHook`) is not registered
  as a `MissResolver` on any peer. This does not affect wire conformance — Ruling 4
  makes `claimed_source_peer_id` local dispatcher context, so the §3 chain is
  undrivable over the wire in all three implementations by design — but the
  `TV-SS-*` vectors remain satisfied in-process only. Declared in
  `docs/validation/CONFORMANCE-EXCLUSIONS.md`.
- COMPUTE §5.2 has no request field for evaluation **depth**, so a depth-declaring
  conformance vector has no wire representation at any seat. Logged in
  `docs/SPEC-AMBIGUITIES.md` and routed upstream.
- Remaining items tracked in `docs/BACKLOG.md`; spec under-specifications in
  `docs/SPEC-AMBIGUITIES.md`.

## [0.8.0] - 2026-06-21

- Initial public research-preview release.

[ADR-0012]: https://github.com/entity-church/entity-core-rust/blob/master/docs/adr/
</content>
