# Spec Ambiguities (Rust implementation)

Questions and under-specified areas encountered during implementation that
should go back to the architecture team. Each entry names the spec, the
passage, what is unclear, and the interim implementation choice (if any).

---

## CAPABILITY §5.5 / SUBSCRIPTION §4.2 — `entity://` deliver_uri vs capability-scope canonicalization

> **RULED 2026-07-16 — arch ruling 24. RESOLVED; the core half is fixed
> (`canonicalize`, `core/capability/src/lib.rs`).** The ruling: "Answered by
> Go's code, no arch trip — **cleaning ≠ canonicalizing**. Rust unblocked."
> Verified against `capability.Canonicalize` (`core/capability/check.go`),
> which resolves `entity://{p}/x` → `/{p}/x`. So this was never a cross-impl
> question — Rust had conflated two different jobs: `EntityUri::clean_path`
> *preserves* the scheme (correctly — it cleans a URI **as** a URI), while
> canonicalization must *resolve* it to the address it names, exactly as
> dispatch routing already did. Rust's `canonicalize` simply had no
> `entity://` branch, so the URI fell through to the bare-path arm and came
> out as `/{local}/entity://{peer}/x` — unmatchable, hence the 403.
> Pinned by `canonicalize_entity_uri_tests` (verified to fail pre-fix, with
> the mangled scope in the failure output).
>
> **Lesson worth keeping:** this sat as a "cross-impl blocker pending Go/Python
> alignment" while the answer was a branch in one function, readable in the
> sibling's source the whole time. Logging an ambiguity is not free — it
> deferred a fix by a cycle. The standard's "read the source, not memory"
> applies to our own blockers too: check whether the sibling's code already
> answers it before routing it as a question.
>
> **Still open (not this entry's):** the SDK-side `deliver_token`
> grantee/signature/handler-scope mismatches behind this
> (`bindings/sdk/src/subscription.rs`, `extensions/subscription/src/lib.rs`)
> remain diagnosed-but-unlanded — the rest of the Rust-subscriber cross-peer
> delivery stack.

**Spec:** ENTITY-CORE-PROTOCOL-V7 §5.4/§5.5 (capability resource scoping +
canonicalization) ⨯ EXTENSION-SUBSCRIPTION §4.2 / §1.2 (cross-peer
`deliver_token` + `deliver_uri`).

**Passage.** EXTENSION-SUBSCRIPTION uses the `entity://` URI form for a
cross-peer `deliver_uri` (example § line 715:
`deliver_uri: "entity://peer_c/system/inbox/sensor-data"`). The cross-peer
`deliver_token` (§4.2) authorizes delivery to that URI, so its `resources` scope
naturally carries the `entity://` form. At **delivery time** the receiver checks
the delivery EXECUTE's resource against that scope via the §5.4/§5.5 path,
which runs `canonicalize` on both the request target and the grant's resource
patterns.

**Ambiguity.** `core/capability::canonicalize` does not recognize the
`entity://` scheme. An `entity://{A}/path` resource pattern is neither absolute
(`/…`) nor bare-wildcard, so it is treated as a **bare relative path** and
becomes `/{A}/entity://{A}/path` — which can never match the normalized request
target `/{A}/path`. The result is a 403 "operation permission denied" on any
cross-peer delivery whose `deliver_token` resource scope uses the spec's
`entity://` deliver_uri form. This bites **even the spec-model inbox delivery**,
not just custom delivery handlers.

The spec does not state whether `entity://{p}/x` and `/{p}/x` are
interchangeable *addresses* for the purpose of capability-scope canonicalization
(i.e. whether `canonicalize` MUST strip the `entity://` scheme). The two forms
ARE treated interchangeably for **dispatch routing** (`is_remote_uri` /
`extract_peer_id_from_uri` accept both), which makes the scoping divergence
easy to miss.

**Interim choice.** None — not patched. Stripping `entity://` in `canonicalize`
is shared, cross-implementation capability semantics; doing it unilaterally
risks diverging from Go/Python. Needs an architecture ruling: either (a)
`canonicalize` MUST treat `entity://{p}/x` ≡ `/{p}/x`, or (b) capability
`resources` scopes MUST be authored in `/{p}/x` form even when the
corresponding `deliver_uri` is `entity://`. There are four other layers that
gate Rust-as-subscriber cross-peer delivery.

---

## CONTENT §5.3 — descriptor path hex convention under-stated inline; Go diverges

> **Rust is conformant; no Rust change.** The Go validate-peer check
> `local_files.v3_descriptor_publish_exercised` FAILs Rust, but the FAIL is a
> **Go bug**, not a Rust gap. Routing correction: this routes to **Go +
> architecture**, NOT the Rust team (contra the cohort handoff note that called
> it "Rust descriptor write not landing").

**Spec:** EXTENSION-CONTENT v3.6 §5.3 (descriptor path convention) + V7 §3.5
(invariant-pointer hex convention).

**Passage.** §5.3 binds a descriptor at
`/{publisher_peer_id}/system/content/descriptor/{B_hex}/{D_hex}` and defines
`B_hex` = "hex encoding of the blob's entity hash", `D_hex` = "hex encoding of
the descriptor's own entity hash" — *without restating whether the format-code
byte is included*. But §5.3 explicitly calls this an **invariant-pointer path**
("the invariant-pointer path at which descriptors are bound", §5.3 intro) and
draws the normative parallel to the capability-signature invariant path
`/{signer}/system/signature/{target_hex}`. V7 §3.5 governs all such paths:

> **Hex encoding convention.** Content hashes in invariant pointer paths use hex
> encoding (lowercase, format code included). … a stable format code prefix
> (`00` = ECFv1-SHA-256). *(V7 §3.5)*

and V7 §3.5 on `target_hex`: "the hex-encoded content hash of the entity that
was signed (**including the format code byte**). For ECFv1-SHA-256, this is 66
hex characters starting with `00`." CONTENT §6.4.2 (sibling namespace path
`{namespace}/{hex(H)}`) *does* restate this explicitly: "format-code byte
included, 66 chars beginning `00` … NOT the 64-char digest-only form."

**The determinate reading.** A §5.3 descriptor path is an invariant-pointer
path ⇒ V7 §3.5 hex convention applies ⇒ `B_hex`/`D_hex` are **format-code-byte-
included** (66 chars for SHA-256, `00`-prefixed). This is unambiguous when §5.3
is read against V7 §3.5; the only defect is that §5.3 does not restate the rule
*inline* the way §6.4.2 does, which let an implementer drift.

**Cross-impl state (verified):**

| Impl | `B_hex`/`D_hex` derivation | Form | Conformant |
|------|---------------------------|------|------------|
| Rust | `Hash::to_hex()` (`core/hash`) | `00`+digest (66ch) | ✅ |
| Python | `blob_hash.hex()`; `Hash = [algo]+digest` bytes | `00`+digest (66ch) | ✅ |
| Go | `hash.EffectiveDigest()` (`ext/content/descriptor.go:55-56,120`) | digest-only (64ch) | ❌ |

Go is also *internally inconsistent*: its §6.4.2 namespace binding uses
`h.Bytes()` (format-byte-included, `ext/content/handler.go:495`) but its §5.3
descriptor path uses `EffectiveDigest()`. The Go validator
(`cmd/internal/validate/local_files.go:961`) lists
`system/content/descriptor/{EffectiveDigest_hex}/` — Go's own wrong convention —
so it cannot see Rust's correctly-bound `…/{00+digest}/` leaf and reports a
FAIL. The check asserts against Go's bug, not the spec.

**Interim Rust choice:** none — Rust stays on `to_hex()` (spec-correct, and
byte-compatible with Python). Changing Rust to match Go would (a) violate V7
§3.5, (b) break Rust↔Python descriptor interop (Python agrees with Rust), and
(c) re-introduce Go's internal namespace-vs-descriptor inconsistency on the Rust
side.

**Recommended resolution (Go + arch):**
1. **Go:** switch `DescriptorPath` + `LookupDescriptors` (`descriptor.go`) and
   the validator listing (`local_files.go`) from `EffectiveDigest()` to
   `Bytes()` (format-byte-included). 2-of-3 impls already agree; this is the
   spec-correct convergence.
2. **Arch:** add an explicit one-sentence restatement to §5.3 mirroring §6.4.2
   line ~1051 ("`B_hex`/`D_hex` follow the V7 §3.5 invariant-path hex
   convention — format-code byte included, NOT the digest-only form") so no
   implementer drifts again.

---

## PHASE P — publish-path root selection + trie key convention

> **PARTIALLY RESOLVED (arch ratification `24a4a97`, Amendment 10 +
> Go cohort handoff).** NETWORK §6.5.6 Amendment 10 pinned the serving floor:
> when `signed_pointer` is advertised, the served set MUST cover the transitive
> trie-node closure of `published-root.root_hash` (root + interior nodes +
> leaf-bound content + published-root + signature). Rust now ships
> `ClosureScope` (`core/peer/src/http_live/scope.rs`) + `collect_node_closure`
> (`core/tree/src/trie.rs`); `--publish-root` selects it and publishes even an
> empty subtree (the canonical empty CHAMP root is a real served node). This
> closes validate-peer published_root **v4** (MANIFEST_GET served) and **v7**
> (CONTENT_GET(root_hash) → trie node).
>
> **(3) auto-republish-on-change — RESOLVED 2026-08-08.** `--publish-root` now
> installs a `system/tree/tracking-config` for the served prefix and re-signs on
> every trie-root change (`PublishRootHook`, `core/peer/src/published_root.rs`),
> which is what Go's `2026-08-07-f` report measured us failing (one manifest
> state across 5m45s, `seq` 0 and staying 0). Point 1's multi-prefix→single-root
> question is answered by construction rather than pinned: the publisher follows
> exactly one tracked prefix, the one the operator's serving flag selects.
>
> **(2) cross-impl trie key convention — REOPENED 2026-08-08. The 2026-07-31
> closure was wrong.** It read "Go's `published_root` swept 7·0·0·0" as proof
> the key convention byte-matches. It is not: `v5_outbound_dial` fetches the
> manifest and verifies the **signature**, and `v7_trie_closure_content_get`
> CONTENT_GETs `root_hash` and asserts the entity **type** is a trie node
> (`cmd/internal/validate/published_root.go`, Go `05d1fca`). **Neither resolves
> a key**, so neither can distinguish the conventions. No vector in any category
> walks a path from a published root today. See `## PHASE P — the published
> trie's key convention is unproven cross-impl` below for the live divergence.

**Spec:** STRATEGY-REGISTRY-DISCOVERY-IMPL §0.5 P1/P2 +
`PROPOSAL-PEER-MANIFEST-STATIC-HANDSHAKE.md` §1.1/§4.

**Context:** the publisher commits to a tree `root_hash`; the consumer walks the
HAMT from it by `relative_key`. Three cross-impl coordination points are NOT
pinned in the locked spec (they'll be pinned by Go's P4 conformance vectors):

1. **Which root.** `--publish-root` publishes the trie root over the
   `--serve-namespace` subtree (one root per served namespace). A peer tracking
   multiple prefixes has multiple roots; the published-root carries exactly one
   `root_hash`. Rust assumes the single-served-namespace case.
2. **Trie key convention.** Rust keys the published trie by **peer-prefix-
   stripped paths** (a binding at `/{peer}/system/content/public/x` keys as
   `system/content/public/x`), matching the root_tracker convention. The
   consumer's `resolve(relative_key)` must use the same key. Cross-impl, the key
   must byte-match Go/Python for a dial to resolve — the http_poll_outbound
   vector will pin it.
3. **Re-publish on tree change.** P1 says "on tree-root change, sign + write a
   new published-root." Rust ships a **static one-time** publish (the coral-reef
   §7.4 case: build once, serve). Auto-republish-on-change is a clean follow-up
   once the multi-prefix→single-root selection (point 1) is pinned.

**Interim choice:** Rust implements the publisher engine + verify/walk consumer
(both self-consistent + threat-model-tested) and a one-time `--publish-root`
startup publish over `--serve-namespace`, bare-path-keyed. The
`peer.publish_root(root_hash)` programmatic primitive is unambiguous (caller
picks the root). Cross-impl byte alignment on these three points reconciles at
the validate-peer reconvene (P5/P7).

---

## PHASE P — the published trie's key convention is unproven cross-impl

> **OPEN — filed 2026-08-08, routing to arch + cohort.** Reopens point (2) of
> the entry above, whose 2026-07-31 closure rested on two vectors that do not
> test what was claimed.
>
> **Updated 2026-08-08 (later) — Go withdrew the closure and built the missing
> vector.** `published_root.v8_trie_key_convention` (Go `5eab686`) mirrors the
> served trie over the wire, rebuilds it locally, and asserts the rebuilt root
> equals the served one. It measures the cohort three ways and **confirms this
> entry from the other side**, with one result better than expected and one
> worse. See "What v8 measured" below; the two asks stand unchanged.

**Spec:** `PROPOSAL-PEER-MANIFEST-STATIC-HANDSHAKE.md` §1.1 (walk from the
signed root by `relative_key`) + `EXTENSION-TREE.md` §3.4.1a.

**Passage / gap.** §1.1 has the consumer resolve a path by walking the HAMT from
the signed `root_hash`. It does not say what a key **is** — relative to what.
The trie is keyed by `relative_key`; the publisher and the consumer must agree
on the frame, and nothing normative fixes it.

**Where the two impls actually stand (both at `2026-08-08`):**

| | tracked prefix under the operator's publish flag | resulting key for a binding at `/{peer}/system/content/public/x` |
|---|---|---|
| rust | `"/"` — the §3.4.1a universal tree root | `system/content/public/x` |
| go | `"system/"` — `publishedroot.PrefixForLocalPeer` | `content/public/x` |

The **rule** is now identical on both sides — keys are relative to the tracked
prefix (rust converged on it here; it previously stripped only the peer prefix
regardless of the tracked prefix). What differs is **which prefix the flag
picks**, and that difference is enough: a Go consumer resolving `content/public/x`
against a rust peer misses, and a rust consumer resolving `system/content/public/x`
against a Go peer misses. Neither is *wrong* under the spec as written; they
just cannot dial each other's manifests.

There is a second, smaller consequence of the same choice: rust's universal
prefix puts `local/files/...` inside the published closure and Go's `system/`
does not, so the two peers serve different sets under `--serve-closure-root`.

**Why no test caught it.** `published_root` v5 verifies a signature; v7 fetches
`root_hash` and asserts the entity type. Neither resolves a key. An exhaustive
read of Go's `cmd/internal/validate/` at `05d1fca` finds no vector that walks a
path from a published root in any category.

**What v8 measured (Go `5eab686`, three fresh peers).** The gap is real and the
table above was two-thirds of it:

| | key frame | observed keys | bindings |
|---|---|---|---|
| go | `system/`-relative | `attestation`, `capability` | 401 |
| rust | peer-relative | `system/attestation`, `local/files` | 415 |
| python | absolute | `/{peer_id}/system/signature/…` | 490 |

Two findings, and **the good one is as load-bearing as the bad one**:

- **The trie ALGORITHM agrees across all three impls.** All three PASS the
  rebuild equality — §3.3 routing, the pinned `bitWidth=5` / `bucketSize=3`, the
  §3.1 canonical form and the bucket sort all reproduce byte-identical roots.
  This had never been measured cross-impl before. It holds. We pass it at
  `703bb7b` (`published_root 8·0·0·0`).
- **The keys do not agree, and it is three-way, not two-way.** rust and Go
  differ by exactly the `system/` segment; python trims nothing. Go explicitly
  did *not* file python's absolute keys as a defect — under the universal tree
  "the peer_id" is not a single value, so it is a defensible third reading. That
  is arch's call, and it strengthens ask (1): three impls read the same silence
  three different ways.

**The root cause is sharper than "which prefix the flag picks."**
`system/peer/published-root` carries `peer_id`, `root_hash`, `seq`,
`published_at`, `predecessor` — and **no prefix field at all**. §3.3's "the
prefix is an operational parameter, not stored in the snapshot entity" holds for
snapshot / extract / merge, where the prefix rides the request; a **published**
root has no such channel, so the consumer receives the keys and never the
operand they are relative to. Our `"/"` → `/{peer}//` finding (see
`HANDOFF-2026-08-08-…-two-defects.md` §2) is the same gap from the publisher's
side. This is why ask (1) is the load-bearing one: no key convention is
self-describing until the entity carries the frame.

**One limit v8 states in its own header, and it matters for reading a PASS.**
The rebuild takes its keys *from the trie*, so it is self-consistent by
construction with respect to key **form** — an impl keying by absolute path
rebuilds to its own root perfectly and passes. The equality proves the
algorithm; the printed key classification is what surfaces a wrong form.
Neither substitutes for the other, and "v8 passes" is therefore **not** a claim
that our keys are cohort-correct.

**Interim choice:** rust keeps `"/"`, because it is the prefix that preserves
what rust already published (the whole peer subtree, peer-prefix-stripped keys)
and because §3.4.1a names it explicitly as the universal-tree value. Not a
claim that it is the right cohort answer.

**For architecture / cohort:** two asks, in order.
1. **Pin the frame** — now a three-way choice, not two:
   (a) "keys are relative to the tracked prefix, and the published-root MUST
   carry which prefix that was" — what rust and Go both do now, self-describing
   only with one new field;
   (b) "keys are always peer-prefix-stripped regardless of tracked prefix" —
   needs Go to change, needs no field;
   (c) "keys are absolute universal-tree paths" — python's reading, which needs
   no field either and is the only one of the three that survives a peer serving
   more than one peer-id's subtree.
   Whichever lands, (a)'s field is worth having on its own: without it a
   consumer cannot tell (a) from (b) from (c) by inspection.
2. **Arm a vector that resolves a key**, whichever way (1) lands. Go's v8 proves
   the *algorithm* but by construction cannot fail on key **form** (see the
   limit above), so this ask is **not** closed by v8 — it needs a check that
   resolves a *known* path against a *published* root, which is a different
   assertion. Until one exists, form stays unprovable from a green suite —
   exactly how the 2026-07-31 closure happened.

---

## REGISTRY — revocation discovery path is impl-defined

> **RESOLVED (cohort convergence — Go `RevocationStoragePath`,
> validate-peer registry v6).** The cohort stores revocation entities at
> `system/registry/revocation/{hex(revocation_entity.content_hash)}` — keyed by
> the **revocation's own hash**, not the binding it revokes. Rust originally did
> an O(1) lookup keyed by the binding hash, which missed the cohort's path and
> let a revoked local-petname binding still resolve (the bug was masked
> pre-R3: the `system/protocol/status` wrap returned empty data so the v6
> "binding NOT resolved" assertion passed vacuously; fixing R3 exposed it).
> Rust now **scans** `/{peer}/system/registry/revocation/` and matches on the
> `revokes:` field (`is_revoked` in `extensions/registry/src/resolver.rs`) —
> path-convention-agnostic. Local-petname bindings are excluded on presence of
> any type-valid revocation (§6.3 carve-out: the local store is the trust
> source, no signature needed); signed kinds still require a same-authority
> signed revocation. Same fix shape Python shipped at `fb71b16`.

**Spec:** `EXTENSION-REGISTRY.md` §3.1 + §6.6 + §11.1.

**Passage:** "`:resolve` MUST check for a `system/registry/revocation` targeting a
candidate binding before returning `status: resolved`." The spec pins the
revocation **entity type** and its **signature carriage** (invariant-pointer at
`system/signature/{hex(revocation.content_hash)}`) but does NOT pin **where a
revocation entity is stored / how `:resolve` discovers one** targeting a given
binding.

**Interim choice:** Rust stores/looks up revocations at the keyed convention
`system/registry/revocation/{hex(revokes_binding_hash)}` (O(1) lookup by the
binding they revoke), plus an `included`-envelope scan. A present, type-valid
revocation excludes a petname binding unconditionally (petname has no issuing
authority to verify against); signed kinds would additionally verify the
revocation signature against the same authority as the binding.

**For architecture / cohort:** the R5 `meta_resolver_revocation_honored` vector
tests *behavior* (revoked binding excluded, chain advances), not the storage
path — so this is converged at the behavior level. But if a revocation entity
must be **cross-peer discoverable** (e.g. arriving via sync for a peer-issued
binding), the cohort should pin a canonical revocation path the way petname
two-layer storage is pinned. Flag for the validate-peer reconvene.

---

## PHASE P — `system/peer/published-root.peer_id` wire shape

> **RESOLVED (arch ratification `24a4a97`, Ruling-1).** §4 erratum
> changed `peer_id: <hash>` → `peer_id: <Base58 peer-id per V7 §1.5>`, and
> dropped any `refs:` carriage in favor of the §5.2 invariant-pointer
> `system/signature/{hex(published_root.content_hash)}`. Rust's interim Base58
> choice was ratified verbatim — no code change; the type-def comment in
> `core/types/src/core_types.rs` now cites the ratification. The Go cohort
> handoff lists Rust v1/v2/v3/v6 as PASS, confirming the byte shape.

**Spec:** `PROPOSAL-PEER-MANIFEST-STATIC-HANDSHAKE.md` §4 (NORMATIVE-LOCKED).

**Passage:** §4 defines the entity as:
```
type: "system/peer/published-root"
data: {
  peer_id:     <hash>          ; whose root this is
  root_hash:   <hash>          ; the current tree root the publisher commits to
  ...
}
```

**Ambiguity:** `peer_id` is typed `<hash>`. But (a) the Go coordinator's P1
build target (STRATEGY-REGISTRY-DISCOVERY-IMPL §0.5) writes
`peer_id: <Base58 peer-id per V7 §1.5>`; (b) the closest sibling entity,
`system/peer/transport/http-poll`, carries `peer_id` as the Base58 id
`system/peer-id` per NETWORK errata `bdfb545` (cross-impl F1) precisely because
it must match the `{peer_id}` path segment, not a content hash; (c) REGISTRY
§3/§4.4 pinned `target_peer_id` as Base58 (V7 §1.5) over the same "this is an
identity, not a content-hash" reasoning. The §4 `<hash>` shorthand appears
inherited from the manifest's `source_peer_id` lineage (which IS a hash), but
`published-root.peer_id` is consumed as a self-identifying label cross-checked
against a pinned Base58 identity in the §7.4 ESR flow.

**Interim choice:** Rust encodes `peer_id` as a **Base58 peer-id string**
(`system/peer-id`), matching the cohort convergence target (Go P1 + http-poll
sibling + REGISTRY precedent). `root_hash` and `predecessor` remain bare
`system/hash`. This is the byte-level shape Rust will present at the validate-peer
reconvene.

**For architecture:** amend §4's `peer_id: <hash>` to `peer_id: <Base58 peer-id
per V7 §1.5>` to match the cohort, OR — if a content-hash was genuinely intended
— flag it so Go/Python/Rust converge before the P7 three-peer byte-equality
fixture is pinned. The two encodings are not wire-compatible.

---

## V7.64 PEER-IDENTITY BUNDLE — Rust pickup findings

Five findings surfaced during Rust impl of the v7.64 three-proposal
bundle (identity-multihash + path-encoding-alignment + policy-dual-form).
None block ratification; all are heads-ups / cross-impl coordination
items for architecture + Go/Python peers.

### F1. `system/peer` entity stores `key_type` as text `"ed25519"`, not the uint code

**Passage:** `PROPOSAL-V7-PEER-ID-IDENTITY-MULTIHASH.md` §2.7 talks about
`key_type` in the §1.5 uint sense (`KEY_TYPE_ED25519 = 0x01`). The Rust
`system/peer` entity (and the Go reference, last we checked) encodes
the `key_type` field as the **text literal `"ed25519"`** in the entity's
ECF map — not as the uint code.

**Ambiguity:** v7.64 doesn't address the encoding of the `key_type`
**field** in the entity body — only the `key_type` **byte** in the
PeerID's varint framing. v7.65 sketch §1.1 then specifies
`key_type: uint` for the proposed slim entity, implying a future
encoding switch.

**Interim choice:** Rust v7.64 keeps the text form (no change). This
matches Go's existing entity shape and avoids touching the entity's
content_hash for an unrelated reason.

**For architecture:** is it intentional that v7.64 leaves the entity's
`key_type` field encoding alone, and v7.65 switches it from text to
uint together with the `peer_id`-field drop? If so, the v7.65 proposal
should say so explicitly when drafted.

### F2. Rust does not support SHA-256-form remotes for `system/peer/transport/**` or `system/revision/.../remotes/**`

**Passage:** `PROPOSAL-V7-PEER-ID-PATH-ENCODING-ALIGNMENT.md` §2.5
acknowledges the API-break at dial / session / transport-profile
resolver sites and says: for SHA-256-form remotes, the impl needs the
peer's `system/peer` entity from a cached lookup; the dialer pattern
"works unchanged."

**Rust state:** `resolve_transport_address` (core/peer/remote.rs:550)
and `peer_remote_hex` (extensions/revision/src/lib.rs:90) currently
fail-fast for SHA-256-form PeerIDs with a clear error citing v7.64
§1.4. No cached-`system/peer` lookup is threaded through these sites.

**Interim choice:** Rust = identity-form-only for these two surfaces.
Per v7.64 §2.1 every new peer defaults to identity-form, and Rust has
no deployed cohort with SHA-256-form peers; this is operationally
fine for now. The error message points at the spec.

**For architecture / Go+Python:** worth confirming the **policy on
SHA-256-form remote support at non-policy surfaces.** Policy-dual-form
covers the policy surface explicitly. The other path families (session,
transport, revision remotes) are not enumerated for dual-form support
— but legacy SHA-256-form peers in the wild will hit these paths.
Should the spec mandate that impls thread a cached-`system/peer`
lookup at these sites, or is fail-fast acceptable (operator must
migrate their peer to identity-form before they can dial / push)?

### F3. No migration tool shipped for Rust

**Passage:** `PROPOSAL-V7-PEER-ID-PATH-ENCODING-ALIGNMENT.md` §2.5
("MUST migrate; dual-read fallback is prohibited") + §3 ("each impl
ships its own one-shot migration tool").

**Rust state:** No migration tool. Rust is a clean-rewrite implementation
with no deployed cohort holding Base58-segment paths on disk. The
test fixtures use freshly-generated identity-form peers; production
deployments do not yet exist.

**Interim choice:** No migration binary, no orphan-recovery loop.
The v7.64 path-rewrite is purely a code change — no on-disk data
needed migrating because no on-disk data exists.

**For architecture:** acceptable, or does the proposal want a
placeholder + exit-code convention even for impls without a cohort?
Recommend the proposal explicitly allow this clean-slate skip in §2.5.

### F4. Stability rule (§2.6) not enforced at Keypair layer

**Passage:** `PROPOSAL-V7-PEER-ID-IDENTITY-MULTIHASH.md` §2.6 — impls
MUST NOT silently change a running peer's `hash_type` across upgrades.
Satisfied by (a) persisting `hash_type` alongside the keypair, (b)
persisting the full Base58 PeerID, or (c) explicit operator opt-in.

**Rust state:** `Keypair` PEM file persists only the 32-byte seed.
The `.pub` sidecar carries the derived Base58 PeerID + base64 pubkey,
but `Keypair::load_from_file` reads only the seed and re-derives the
PeerID using the current default (identity-form, post-v7.64). No
hash_type persistence; no .pub-sidecar consultation at load time.

**Interim choice:** Rust pre-v7.64 had no deployed Keypair PEMs with
SHA-256-form PeerIDs that callers depend on. Post-v7.64 every
freshly-derived Keypair produces identity-form. The stability rule
is **trivially satisfied** in practice (the implementation never
changes the form for a given Keypair instance in-process), but is
**not structurally enforced** at the file-format boundary.

**For architecture:** is structural enforcement at the keypair-load
boundary a MUST for impls that already have deployed cohorts, or is
"current default forever" acceptable when no migration burden exists?
Go/Python may need to weigh this against their deployed bases.

### F5. POL-DF-4 conformance vector collapsed into POL-DF-2

**Passage:** `PROPOSAL-V7-POLICY-DUAL-FORM-PRE-CONFIGURATION.md` §2.7
enumerates POL-DF-1..POL-DF-6, with POL-DF-4 specifically covering
canonicalization mechanics ("write Base58-form entry; peer connects;
verify (a) policy applies, (b) impl that canonicalizes per §2.3
produces a hex-form entry and deletes the Base58 entry").

**Rust state:** The Rust suite has POL-DF-1, POL-DF-2, POL-DF-3,
POL-DF-5, POL-DF-6. POL-DF-2 asserts both behaviors that POL-DF-4
enumerates separately: policy applies AND canonicalization writes
hex / removes Base58 (in one test). No separate POL-DF-4 test exists.

**Interim choice:** Rust canonicalizes by default (it doesn't carry
the "MAY skip" branch), so the two vectors collapse to one. The
spec says canonicalization is SHOULD-tier; impls that skip it would
need POL-DF-4 split out to assert non-canonicalization behavior.

**For architecture / Go+Python:** if Go's vector authoring keeps
POL-DF-4 split, Rust can add a separate test that just asserts the
canonicalized state (redundant with POL-DF-2 but matches the vector
naming). Worth a quick alignment on whether the proposal's
"canonicalize / not canonicalize" split is normative or naming-only.

---

## ~~PROPOSAL-REVISION-AUTO-VERSION-FIX §6D.4 — "reject at config-write time at the handler boundary"~~ RESOLVED

**Resolution:** PROPOSAL-CASCADE-SEMANTICS-AND-STATE-MANAGEMENT (adopted)
§7.2 resolved this: revision adds a `config` handler operation
that validates before writing. The `revision/config` op validates against
required-exclude rules, writes the config entity, and coordinates the
tracking-config — all within one handler invocation. Direct tree.put to
`system/revision/config/**` is guarded by capability (only the revision
handler's self-grant can write there).

Defense-in-depth: `ConfigCoordinationHook` remains as a Phase 1 emit
consumer that halts the cascade on invalid config writes that bypass the
handler op (§7.2 MAY).

---

## EXTENSION-REVISION §2.1 vs Go impl: config storage path

**Spec passage (§2.1):** "Stored at `system/revision/config/prefixes/{name}`."

**Go implementation:** writes configs at `system/revision/config/{prefix}`
(no `/prefixes/` segment). See
`entity-core-go/ext/revision/handler.go:186`:
`return "system/revision/config/" + prefix`.

**Validator:** the Go `validate-peer -category auto_version` tool follows
Go's convention, so cross-impl validation runs against
`system/revision/config/{prefix}` regardless of what the spec says.

**Rust interim:** listens on the broader `system/revision/config/` prefix
and filters by entity type (`system/revision/config`) so both conventions
resolve correctly. Writes configs at `system/revision/config/{prefix}` to
match the validator and interop with Go.

**Question for architecture team:** reconcile §2.1 with Go's convention.
Either amend the spec to match the de-facto path, or ask Go to move. The
type-filtered listing is an interim tolerant reader — resolution would let
us narrow it.

---

## ~~Implementation gap: SyncTreeHook cannot halt the emit cascade~~ RESOLVED

**Resolution:** `SyncTreeHook::on_tree_change` now returns
`Result<(), CascadeHalt>`. `NotifyingLocationIndex::dispatch_event` short-
circuits the hook loop on `Err`, collects completed/halted/skipped consumer
names into `CascadeResult`, and skips the Phase 2 broadcast on halt.
`TreeHandler::handle_put` translates an incomplete `CascadeResult` into a
207 Multi-Status response with a `system/tree/partial-result` entity.

All six hooks updated. `RevisionEngine` (auto-version) now returns
`Err(CascadeHalt)` when the tracking-config invariant is violated,
satisfying §6D.5's MUST-halt.

---

## EXTENSION-IDENTITY v1.2 — five gaps surfaced during Phase A implementation

The identity extension was implemented in a Phase A scope (handler ops,
entity codecs, `verify_k_of_n_signatures` at the entity level). Five
spec gaps surfaced that the implementation had to choose conventions for.
None block Phase A from working end-to-end on a single peer; all need
architect attention before Phase B (cross-peer interop) lands.

### IDENTITY-1 — "signature entity" structure not pinned

**Spec passage (§3.10):** the `verify_k_of_n_signatures` pseudocode says
`find_signature where target = entity_hash, signer = candidate`. The
operation is treated abstractly. The spec never names the type of these
signature entities, where they live in transit, or where they live at rest.

**What's unclear:** Are these the existing V7 `system/signature` entities
(used for cap envelopes) reused for identity attestations, or a distinct
`system/identity/signature` type? Where are they discoverable from? In
transit (`included` map of the EXECUTE), at rest under a tree path, or
both?

**Rust interim choice:** reuse `system/signature` entities (same shape as
V7 cap signatures, `entity_types::SignatureData`); scan only the request's
`included` map at validation time. Async signature gathering (§7) is not
yet wired — when it lands it will need a tree-path convention for
persisted in-flight signatures (Phase A defers).

**Why it matters:** §7's async signature gathering (SHOULD) requires a
durable signature path; without one, K-of-N can only be assembled in a
single transaction. Affects compromise-recovery ergonomics (collecting
quorum signatures across devices).

### IDENTITY-2 — `signer_resolution: "identity-resolved"` recursion bound

**Spec passage (§3.1):** identity-resolved mode "resolves through its
identity layer to its current operator-delegation; the signature is
verified against the current Op for that public identity." Cross-refs
`EXTENSION-GROUP §G3.7` for group quorum semantics.

**What's unclear:** Recursion termination. If constituent A is
identity-resolved to Public_A whose own quorum is identity-resolved with
constituent B, and B's quorum references A, the resolution is cyclic. The
spec doesn't specify a bound, a cycle-detection rule, or a max depth.

**Rust interim choice:** Phase A returns
`ValidationError::IdentityResolvedUnimplemented` for any identity-resolved
quorum. Single-identity deployments use `concrete` exclusively (the
overwhelmingly-default per §3.1 prose). Group quorums are
`EXTENSION-GROUP` territory anyway.

**Why it matters:** Will block Group extension implementation when it
lands. Architect call: pick a bound (depth N, cycle detection that fails
closed), or specify the resolution as iterative-not-recursive (resolve
each constituent once, no transitive walk).

### IDENTITY-3 — live-operator-delegation enumeration convention

**Spec passage (§5.2 step 2 / §5.3 step 4):** "enumerate all live
operator-delegations under this quorum"; "find_current_operator_delegation_for(ctx, quorum, operator)".
Per IA1, the supersedes chain is per-(quorum, operator).

**What's unclear:** No tree-path convention for tracking which delegations
are "live" vs. superseded. Implementations have to scan
`system/identity/quorum/{q}/operator-delegation/` and apply supersedes
chains per-operator. Or maintain a per-operator current-pointer subtree.
The spec doesn't pick.

**Rust interim choice:** maintain a per-operator current pointer at
`system/identity/quorum/{q}/current-operator-delegation/{operator}` →
delegation hash. `process_delegation` updates the pointer; `retire_operator`
removes it. `find_live_operator_delegations` walks the subtree.

**Why it matters:** Cross-impl interop (Go peer reading Rust's tree, vice
versa). If Go uses a different convention, neither can enumerate the
other's live set. Architect call: pin a convention, or specify each
implementation MUST scan the operator-delegation subtree itself and apply
supersedes (slower but no shared state).

### IDENTITY-4 — TOFU PQA cache storage convention

**Spec passage (§3.6 / §5.8):** "Bob's peer caches this at TOFU (first
contact with Public_alice). ... When Bob's peer processes a rotation
entity with `quorum_recovery: true`, it MUST validate the K-of-N
signatures against the cached `public-quorum-attestation` for Public_alice.
... MUST reject if no `public-quorum-attestation` is cached (fail-closed)."

**What's unclear:** Storage location of Bob's cache. The spec mandates
the cache exists; doesn't specify where Bob's peer keeps it. Multiple
public_identities, multiple supersedes chains.

**Rust interim choice (Phase B planning):** suggested path
`system/identity/contacts/{contact_public_identity}/public-quorum-attestation`
(see `attestation::path_contact_pqa_cache`). Not yet wired into a
Bob-side verifier (Phase B work).

**Why it matters:** compromise-recovery interop depends on this.
Different impls will diverge unless pinned.

### IDENTITY-5 — verifier cache-miss policy `fetch-on-demand` registry protocol

**Spec passage (§10.1 / §10G.4 of PROPOSAL-IDENTITY-RECOVERY-VALIDATION):**
"implementations MUST expose a deployment-level configuration for
verifier behavior on missing per-peer `runtime-peer-attestation`:
`fetch-on-demand` (default for online deployments; resolves through the
grantee's registry), `reject-and-escalate` (fail-closed), or
`embedded-only` (rejects unless the cap envelope embeds the attestation)."

**What's unclear:** `fetch-on-demand` requires a registry/discovery
protocol that the spec doesn't define. What request is sent, what
response shape, against what endpoint, with what auth? `EXTENSION-NETWORK`
references `PLAN-REGISTRY-AND-DISCOVERY-LANDSCAPE` but the protocol is
not yet pinned.

**Rust interim choice:** Phase A handler doesn't enforce the policy at
the cap-verifier level (cap-chain hook is Phase B work). Phase B will
ship `embedded-only` and `reject-and-escalate` first; `fetch-on-demand`
gates on the registry protocol landing.

**Why it matters:** the rotation-recovery surface across runtime peers
(§9.4 long-lived cap survival, §3.5 mode promotion) depends on this for
production deployments. `embedded-only` works for short-TTL flows;
long-lived flows need `fetch-on-demand`.

### Cross-cutting (Phase B work, not gaps): cap-chain attestation hook

§12.3 documents that "cap-chain verification consults attestation state
for grantee identity-binding lookup" but the implementation seam between
`verify_capability_chain` (in `core/capability`) and the identity
extension's attestation cache is undefined. Phase B will pin a
`AttestationStore` trait or similar and inject it into the verifier;
needs cross-team agreement on the interface shape.


---

## EXTENSION-IDENTITY v1.2 — Phase A self-review log

After Phase A landed (handler + 27 tests), self-review against the spec
surfaced four implementation bugs (B1-B4) and four spec ambiguities (A1-A5).
Bug fixes land in Phase B. Ambiguities go back to the architecture team.

### Bugs in Phase A (fix in Phase B)

**B1 — `handle_rotate_pi_recovery` validates against wrong quorum.**
§10.1 MUST: "validate K-of-N signatures against the cached
`public-quorum-attestation` for Public_alice." Current code validates
against the local peer's `cfg.trusts_quorum`, which is correct only for
the case of the local peer rotating its OWN public identity. For the more
general case (a peer processing a contact's recovery rotation), the
validation must look up the cached PQA for `rot.old_identity` and use ITS
signers/threshold. Fail-closed if no PQA cached for that identity.

**B2 — `handle_revoke_peer` doesn't revoke caps to the revoked peer.**
§5.9 scope=internal/all: "delete attestation; revoke local caps from this
peer to the runtime peer being revoked; remove peer-config bindings."
Current code does the attestation delete and binding removal but doesn't
touch any caps. Need to walk cap bindings whose grantee == runtime_peer
and remove them from the tree.

**B3 — `rotate_quorum` doesn't update `peer-config.trusts_quorum`.**
After rotate_quorum, a NEW quorum entity exists at a new content_hash.
`peer-config.trusts_quorum` still points at the OLD hash. Future calls to
`process_delegation` with `del.quorum = new_quorum_hash` will fail the
`del.quorum != cfg.trusts_quorum` mismatch check, even though the new
delegation legitimately follows the rotation. §5.7 says "future
operator-delegations and quorum-updates validate against the new
constituent set" — peer-config must move to the new quorum hash atomically
with rotate_quorum.

**B4 — `rotate_quorum` validates new PQA against new_signers, but spec
ambiguously says previous quorum signs.** §3.6: "the supersedes chain
[on PQA] is signed by the previous quorum so updates are validated against
cached state." Current code validates the new PQA against `qu.new_signers`
(the new quorum's constituents). §5.7 says PQA is "K-of-N signed by
quorum constituents themselves" — which constituents? If the new ones,
contacts with cached PQA-v1 can't validate the chain (they don't trust the
new signer set yet). If the old ones, they can. See A4 below for the
ambiguity; B4 is the impl bug if A4 resolves to "previous quorum signs."

### Spec ambiguities (architecture team)

**A1 — §13.2 example contradicts IA1.** §13.2 step 2 has Cold1+Cold2 sign
"a new operator-delegation: `{quorum: ..., operator: Op_v2_id,
supersedes: hash(previous_delegation)}`." Per IA1 (v1.2), supersedes is
per-(quorum, operator); a delegation cannot supersede a delegation for a
DIFFERENT operator. The §13.2 flow predates IA1 and is incompatible with
v1.2's handler logic. The IA1-correct flow is: (a) add Op_v2 with
`supersedes: null`, (b) `retire_operator(Op_v1)`. §13.2 should be
rewritten for v1.2.

**A2 — How does the contact-PQA cache get populated?** §3.6 / §5.8 / §10.1
mandate the cache exists ("Bob's peer caches this at TOFU"), but the spec
doesn't pin the mechanism. Three plausible candidates: (a) sync extension
delivers PQAs from contacts' `system/identity/public/`, peer auto-caches;
(b) explicit `register_public_identity` call carries the contact's PQA
in `included` and writes it to the cache; (c) manual `tree:put` to the
cache path. Without pinning the mechanism, cross-impl interop on the
recovery flow is undefined.

**A3 — §5.6 `rotate_operator` prose contradicts IA1.** §5.6: "The handler
issues a quorum-signed operator-delegation naming `new_operator` with
`supersedes: <old_operator's current delegation hash>`." Per IA1, supersedes
is per-(quorum, operator) — you can't supersede a different operator's
delegation. Either the §5.6 prose needs updating, or rotate_operator
should be redefined as a compound op (add new + retire old) rather than a
single supersedes step. The data structures already support multi-Op (per
§6.3 Pattern B step 2 / §11.7); only the §5.6 prose is stale.

**A4 — §3.6 vs §5.7 — who signs the new PQA on rotate_quorum?** §3.6:
"the supersedes chain is signed by the previous quorum so updates are
validated against cached state." §5.7: "K-of-N signed by quorum
constituents themselves." If "themselves" means the new constituents,
contacts with a cached previous PQA cannot validate the chain (they don't
trust the new signers yet — that's circular). If it means the previous
constituents, the chain is verifiable against cache. §3.6's TOFU-and-chain
model only makes sense with previous-quorum signing. §5.7 prose appears
ambiguous and possibly wrong. Architect call: confirm previous-quorum
signing for PQA updates, or define how contacts validate against a chain
of "self-signed" PQAs.

**A5 — §5.5 publish_runtime_peer_attestation: signature-only
authorization.** §5.5: "This operation is authorized by access to
Public_alice's keypair ... Public_alice's signature on the attestation
entity is what makes it valid." Phase A interpreted this as "signature
alone authorizes" — the handler doesn't check that Public_alice is one
of the local peer-config's bound public identities. This means anyone
with Public_alice's keypair can publish attestations on any peer. That's
likely intended (the keypair access IS the auth model), but worth
confirming. If a peer-config-binding check is also required, the handler
needs to add it.

### Methodological note (also a feedback loop)

In an earlier pass on Phase B planning I framed the work as building
"Bob's identity engine" — a SyncTreeHook that watches tree writes for
attestations. This was invented infrastructure; the spec does not specify
or require an engine. The actual shape of the spec's MUST is much
narrower: a single rule about how the recovery handler does its lookup
(§10.1 MUST against cached PQA). Caught and corrected before any code
landed; logged here as a guardrail for future identity work — match the
spec's surface area; do not invent infrastructure.


### Status update (post-Phase B fixes)

**B1, B2, B3 fixed.** B4 deferred pending A4 resolution.

- **B1:** `handle_rotate_pi_recovery` now looks up cached PQA for
  `rot.old_identity` and validates K-of-N against its signers/threshold.
  Fail-closed if no PQA cached. Cache populated by `configure` (when
  `publish_quorum_attestation: true`) and by `rotate_quorum`. Two new tests
  cover the fail-closed path and a two-peer cross-recovery scenario.
- **B2:** `handle_revoke_peer` (scope=internal/all) now also revokes the
  peer→Op cap if the revoked runtime_peer is one of the live operators.
  Broader cap-grantee revocation (caps issued by other extensions to the
  revoked peer) is out of scope for the identity handler — would need a
  cap-grantee index, logged as future work.
- **B3:** `rotate_quorum` now updates `peer-config.trusts_quorum` to the
  new quorum's hash atomically with the rotation. Future delegations
  validate against the new constituent set per §5.7.
- **B4:** `rotate_quorum` still validates new PQA against `qu.new_signers`.
  Per §3.6's TOFU-and-chain semantics, this should be against the previous
  quorum's signers (so contacts with cached PQA-v1 can validate the chain
  to PQA-v2). §5.7 prose reads ambiguously; deferred until A4 resolves.

**Two-peer integration test landed** exercising §13.5 across two real
`IdentityHandler` instances with a manual TOFU step (sync extension not
yet implemented). Validates both the happy-path and insufficient-signature
rejection.


---

## ATT-1: `is_attestation_live` direct vs transitive supersedes walk

**Spec:** EXTENSION-ATTESTATION v1.0 §4.3 (`is_attestation_live`) vs §5.7 TV-A4
**Status:** Implementation chose transitive walk (TV-A4 intent); awaiting architect confirmation

**Passage:**
```
; Supersession check
; If a later attestation in this chain supersedes att and is itself live,
; att is not the current live state.
later = find_attestations_with_supersedes(att.content_hash, ctx)
for l in later:
  if is_attestation_live(l, ctx, as_of=now):
    return false
```

**Ambiguity:** `find_attestations_with_supersedes` returns DIRECT supersedes
successors only (per §5.6a). Recursion through `is_attestation_live` produces a
counter-intuitive result for chains of length ≥ 3:

Setup: `A → A' → A''`, all signed and not expired.
- `is_attestation_live(A'')`: no successors → live
- `is_attestation_live(A')`: A'' is direct successor and live → DEAD ✓
- `is_attestation_live(A)`: A' is direct successor but A' is DEAD → A keeps
  searching, finds no live successor → A is LIVE

But TV-A4's normative result requires `A''` to be the live head when starting
from A's `attested` peer. With A also "live" per the strict reading,
`default_find_authorizing` produces `live = [A, A'']` (two distinct heads),
tie-broken by content_hash — non-deterministically A or A''.

**Interim choice:** Implemented transitive forward walk. `is_attestation_live`
returns `false` if ANY transitively-reachable supersedes-descendant is
self-valid (not expired/not_before, not self-revoked). `find_live_head` walks
through dead intermediates to surface the deepest live link. Both choices
needed to satisfy TV-A4.

**Impact:** TV-A4 passes. Single-link chains and the other 10 TV-A vectors
behave identically under both interpretations.

**Action requested:** Architect to confirm whether the spec text in §4.3
should be amended to reflect transitive semantics (matching TV-A4 intent), or
TV-A4 should be amended to match the strict direct-only reading.

---

## ATT-2: `identity_verify_cert` signature-validation order

**Spec:** EXTENSION-IDENTITY v3.2 §3.6 `identity_verify_cert` pseudocode
**Status:** Implementation reordered to dispatch-on-topology first; awaiting architect confirmation

**Passage:**
```
identity_verify_cert(att, ctx) → bool
  ; ...
  # Generic signature validation (single-sig default; topology may require more)
  if not ATTESTATION.verify_attestation_signature(att, ctx):
    return error("invalid_signature")
  # Liveness check (generic)
  if not ATTESTATION.is_attestation_live(att, ctx):
    return error("not_live")
  # Authority-revocation check (identity-specific authority rules)
  ...
  # Topology dispatch + validation
  topology = identity_topology_for(att, ctx)
  match topology.mode:
    "k-of-n":
      if not QUORUM.verify_k_of_n_signatures(...):
        return error("k_of_n_failed")
```

**Ambiguity:** The pseudo runs `verify_attestation_signature` (single-sig
from `att.attesting`) BEFORE topology dispatch. For top-level controller
certs, `att.attesting = quorum_id` — and a quorum_id is a structural entity
hash, NOT a peer with a keypair. So the single-sig check necessarily
fails ("no signature found from quorum_id as a single signer"), and
control never reaches the K-of-N topology dispatch which could actually
validate the cert.

**Interim choice:** Reordered `identity_verify_cert` to dispatch on
topology first. Signature validation runs in the topology-appropriate
variant: `Single` calls `verify_attestation_signature`; `Dual` calls
`verify_specific_signer` for each signer; `KofN` calls
`verify_k_of_n_signatures`. The spec's stated invariants
(signature must be valid; cert must be live; chain must terminate at
quorum) are all preserved; only the phase ordering changes.

**Impact:** Three-key default ceremony validates correctly (top-level
controller cert + agent cert chain). Without the reorder, no top-level
controller cert can ever validate.

**Action requested:** Architect to amend §3.6 pseudocode to dispatch on
topology before signature validation, OR introduce a separate
`is_quorum_signed` predicate that the pseudo checks before calling
`verify_attestation_signature`.

---

## RATIFIED: ATT-1 and ATT-2

Both ambiguities ratified by `PROPOSAL-IDENTITY-V3.2-MIGRATION-FIXES.md`
in the architecture-team's cross-impl-feedback batch:

- **ATT-1 → SI-2.** Architecture-team confirms the transitive walk
  (the impl behavior). Spec text in EXTENSION-ATTESTATION v1.1 §4.3
  rewritten to specify `has_live_transitive_descendant` explicitly.
  Predecessor-revival side effect documented as intentional.
  **Rust impl is conforming.** New TV-A4a–TV-A4d test vectors all pass
  (verified: 24 attestation tests, 0 fails).

- **ATT-2 → SI-23.** Architecture-team confirms topology-first dispatch
  (the impl behavior). Spec pseudocode in EXTENSION-IDENTITY v3.3 §3.6
  rewritten to dispatch on topology before signature validation.
  **Rust impl is conforming.** New TV-I-V23 test vector covers top-level
  controller cert validation via K-of-N path (verified: 17
  identity tests, 0 fails).

Both ratifications shipped without wire-format change; the existing impl
behavior was correct. Other items from the proposal landed: SI-7 (path_required
error code), SI-10 (process_attestation fail-closed unbind), SI-13
(identity_confers_function for lifecycle-kind chain walks), SI-16 (`as_of`
historical resolution on current_signer_set), SI-17 (resolve_peer_pubkey
vocabulary), IDENTITY-2 (resolver max_depth=8 + cycle detection).

Workspace: 853 tests pass, 0 fail.

---

## SPEC-24 — Op request/result type-name convention not pinned

**Specs:** EXTENSION-ATTESTATION v1.1 §6, EXTENSION-QUORUM v1.1 §6, EXTENSION-IDENTITY v3.3 §6
**Status:** Implementation adopting V7 precedent; awaiting architect ratification

**Passage:** Each handler op section defines the params and result *shapes*
inline:
```
### 6.1 `system/attestation:create`
**Params:** `{attesting: hash, attested: hash, properties: map, ...}`
**Result:** `{attestation_hash: hash}`
```
…but never says "register this params shape as a type at
`system/type/system/attestation/create-request`." The shapes are defined
but the registered type-names are not specified.

**Ambiguity:** The wire-conformance validator (Go's `validate-peer`)
verifies type registrations at canonical names like
`system/attestation/create-request`, `create-result`, `supersede-request`,
`supersede-result`, `revoke-request`, `revoke-result`, `verify-request`,
`verify-result` (and the same for quorum + the missing identity result
types). Cross-impl convergence depends on all impls registering the same
names. The spec does not enumerate them.

**Interim choice:** Adopt V7's existing precedent in `core/types`:
- `TYPE_TREE_GET_REQ = "system/tree/get-request"`
- `TYPE_TREE_PUT_REQ = "system/tree/put-request"`
- `TYPE_HANDLER_REGISTER_REQ = "system/handler/register-request"`

The pattern is `{handler-namespace-path}/{op-name}-request` and
`{handler-namespace-path}/{op-name}-result`. The Rust impl now registers
all 21 substrate + identity result types under this convention. Field
shapes follow the spec §6 inline definitions verbatim.

**Action requested:** Architect to either (a) explicitly normatively
define the convention in each spec's §6 (or in a shared editorial
section), or (b) ratify the existing impl convergence by listing canonical
type-names in the spec text.

---

## SI-11 envelope.included signature ingestion — IMPLEMENTED

Per spec EXTENSION-IDENTITY v3.3 §6.2 (sharpened SI-11 ruling). Rust impl
landed at `extensions/identity/src/ingest.rs` with helper
`ingest_signatures_from_included(included, content_store, location_index)`,
called at the top of the identity handler's `handle()` before any op
dispatch. Mechanism:

- Phase 1: persist any `system/identity` entities in `included` first
  (so signature ingestion can resolve `signer` → peer_id).
- Phase 2: persist + bind each `system/signature` entity at
  `/{signer_peer_id}/system/signature/{target_hash_hex}`.
- Idempotent on hash collision; fail-closed on path conflict
  (`signature_path_conflict` error).

Tests: `si11_ingestion_persists_and_binds_signature_at_v7_path`,
`si11_ingestion_fail_closed_on_path_conflict`,
`si11_ingestion_includes_referenced_identity_entities`.

This closes the prior `IDENTITY-1` Rust ambiguity entry around the
ingestion mechanism — the spec amendment (SI-11) defined the canonical
path + conflict semantics, and the impl follows.

---

## RUST-FAILURES — Cross-impl validator gap report (Go team)

**Source:** the Go team's cross-impl validator gap report on Rust.

**Items closed (M1 + M2, multi-sig primitive):**

- **§M1 polymorphic `granter`** — `system/capability/token.granter` was
  registered as `system/hash`; spec mandates
  `union_of(system/hash, system/capability/multi-granter)`. Fixed: added
  `FieldSpec::union(...)` constructor in `core/types/lib.rs`, updated
  `system_capability_token` registration. CBOR major-type discrimination
  per §M8 (bstr vs map) handled by existing union_of infrastructure.
- **§M2 `system/capability/multi-granter`** — type was unregistered.
  Added `system_capability_multi_granter()` per spec §3.2:
  `{signers: array_of(system/hash), threshold: primitive/uint}`.
  Constant `TYPE_CAP_MULTI_GRANTER` exposed in `core/types/lib.rs`.
- New regression test `test_multisig_primitive_types_registered` asserts
  both items.

**Items deferred (local/files):**

- 31 cascading failures from missing `local/files` handler. Spec
  `DOMAIN-LOCAL-FILES.md` (v1.1, 890 lines, status "Draft — prototype
  domain for sync milestone validation") is unimplemented in Rust. This
  is NOT a v3.3 substrate gap — it's an unimplemented prototype domain
  extension covering filesystem mapping, file watcher, reverse-write
  subscription, two-entity model. Go report itself notes the cleaner
  fix may be on the validator side: "Go's peer-manager passes `--files`
  only when the user specifies it. ... The same skip pattern should
  apply on Rust if the extension exists but isn't enabled." Logged as
  scoped-elsewhere; awaiting user direction on whether to implement.

**Items not actionable (origination):** Requires `-reference-peer`
flag; not a Rust gap.

---

## Failure #4 (RUST-FAILURES update) — TV-A4a/b/c/d behavioral failures CLOSED

**Symptom:** All four TV-A4 behavioral tests over the wire returned
`reason=attestation_not_indexed` from `system/attestation:verify`.

**Root cause:** The `AttestationIndexHook` (SyncTreeHook adapter) was
*defined* in `extensions/attestation/src/hook.rs` but never *registered*
with `core/peer`'s `emit_dispatcher`. So the index was only populated
when an attestation entered the tree via the substrate's `:create` op
(handler-side direct insertion); writes via `tree:put` (the kernel op)
bypassed it.

**Spec source:** EXTENSION-ATTESTATION v1.1 §9.1 invariant I1 — "When
`system/attestation:create` (or `:supersede`, `:revoke`, **or any
operation that writes a `system/attestation` entity to the tree**)
completes successfully, the entity MUST appear in the [...] indexes."

**Fix:** Register `AttestationIndexHook` with `emit_dispatcher` inside
the `#[cfg(feature = "attestation")]` block of `core/peer/src/lib.rs`,
right after the substrate handler is wired. The hook fires on every
tree mutation; if the written entity is `system/attestation` it
populates the index regardless of which op produced the write.

Registration position: early in the cascade (before downstream hooks
that might call `find_attestations_*`). Hook name: `attestation/index-maintainer`.

**Test:** `invariant_i1_hook_populates_index_on_external_tree_put` in
`extensions/attestation/src/tests.rs` exercises the kernel-write path
directly (synthesizes a TreeChangeEvent without going through the
substrate handler) and asserts the index gets populated.

---

## V7 v7.37 Amendment 1 — SPEC-25 closure (dispatcher-level ingestion)

**Spec source:** ENTITY-CORE-PROTOCOL-V7 v7.37 §6.5 (replaces SI-11
in EXTENSION-IDENTITY §6.2; original §6.2 is now a one-paragraph
pointer at V7 §6.5).

**Reading divergence resolved:** Go/Python (Reading A — dispatcher
level) vs Rust (Reading B — IdentityHandler entry). Architecture team
ratified Reading A. Per spec §6.5: "Ingestion runs once per envelope
at the dispatcher's envelope-unwrap step, before any handler is
selected. It applies uniformly to ALL handler ops: kernel ops
(`system/tree:put`), substrate ops (`system/attestation:verify`,
`system/quorum:verify`, etc.), identity ops, and any extension's
handler ops."

**Rust changes landed:**

1. **Helper moved.** `ingest_signatures_from_included` (in
   `extensions/identity/src/ingest.rs`) → `ingest_envelope_signatures`
   in **`core/peer/src/ingest.rs`**. No extension dependency; uses
   only core/store + core/crypto + core/types.

2. **Dispatch wiring.** `core/peer/src/connection.rs::dispatch_request`
   calls `ingest_envelope_signatures(&envelope.included, ...)` AFTER
   `verify_request` succeeds and BEFORE handler resolution. Failure
   semantics per §6.5: 400 `signature_path_conflict` on path conflict;
   500 `ingest_io_error` on transient I/O. Either short-circuits
   dispatch.

3. **IdentityHandler::handle()** no longer ingests; comment notes the
   dispatcher already did it. Substrate `find_signature_by_signer`
   reads pre-bound signatures from the tree.

4. **Tests.** Removed three `si11_*` tests from
   `extensions/identity/src/tests.rs` (the helper isn't in identity
   anymore). Added four equivalent tests in `core/peer/src/ingest.rs`
   tests module covering: persists+binds at canonical path; idempotent
   re-run; picks up identity entity from envelope; fail-closed on
   path conflict.

**Workspace status:** 859 tests pass, 0 fail. The behavioral_v33 4/0/0
gap on Rust should now flip to 4/4/4 because TV-A4a/b/c/d harness sends
attestations + signatures via envelope.included → tree:put; the
dispatcher now binds the signatures at canonical V7 paths before
`tree:put` runs; the attestation index hook (Failure #4 fix) populates
the attestation index on the same write; substrate `:verify` finds
both via tree lookup.

**SPEC-24 status:** ratified at V7 §3.7 per Amendment 1 (handler-op
input/output type-registration convention). Rust impl already adopted
this convention; no code change required, just a doc pointer update
(deferred — cosmetic).

## Rust-side implementation gap: OPFS LocationIndex durable-write failure is unreportable

**Type:** Rust infrastructure limitation (NOT a spec ambiguity — logged
here per CLAUDE.md "note Rust-side implementation gaps ... separately").
**Severity:** correctness (durability divergence on I/O error; bounded
by OPFS reliability — OPFS rarely fails mid-session).

**The MUST.** The protocol treats a storage write failure as a normal
error condition that produces an error *response* to the caller (the
peer keeps running) — same shape as `ContentStore::put` failing, which
propagates `StoreError` → `TreeError::StoreError` → handler error → wire
error response.

**The gap.** The Rust `LocationIndex` trait cannot express this for the
durable `locations.log` write:

- `LocationIndex::set` / `set_with_context` / `remove` /
  `remove_with_context` return `()` / `Option<Hash>` / `CascadeResult` —
  **no error channel.** The common (non-CAS) tree:put binding write goes
  through `set_with_context` (`core/tree/src/lib.rs:613`).
- `compare_and_swap` / `compare_and_remove` return `Result<_, CasError>`,
  but `CasError` is a closed enum spec-pinned to 409 `hash_mismatch`
  (`Mismatch(Hash)` | `NotFound`, `core/store/src/lib.rs:866`). A journal
  I/O failure is not a 409; overloading `CasError` with an `Io` variant
  would be semantically wrong and is a core-trait + cross-impl change
  (Go/Python share the trait shape).

So when `OpfsLocationIndex`'s `entities.log` mirror write succeeds but
the `locations.log` append fails, the in-memory index is ahead of the
durable journal and the binding is **lost on the next restart**, silently
breaking restart equivalence — and there is no trait path to surface it
as the spec-required error response.

**Interim choice.** `log_swallowed_journal_failure()` in
`core/store/src/opfs.rs` logs the failure loudly at `tracing::error!`
(op, path, error, "lost on restart") and continues. This matches the
codebase's existing accepted behavior for the trait's infallible-`set`
contract (`MemoryLocationIndex`/`SqliteLocationIndex` also assume `set`
cannot fail). It is NOT a chosen "swallow" policy — it is the only thing
this layer can do without a trait-shape change. (An earlier patch made
this `panic!` to halt the peer; reverted — panicking takes down the
whole worker, including all co-hosted peers under the single-worker
topology, for what the spec says is a returnable error. Disproportionate
and not spec-compliant.)

**Proper fix (architect's call — cross-cutting, cross-impl).** Give the
`LocationIndex` write methods a fallible signature (e.g. `set` →
`Result<CascadeResult, IndexError>`, and an I/O-distinct error on the CAS
methods) so the tree handler can map a durable-write failure to a
spec-compliant error response. Affects every backend
(Memory/Sqlite/Opfs/Notifying/Journaled/Indexing) and must stay in
lock-step with the Go/Python `LocationIndex` equivalents. Not undertaken
unilaterally.

## Rust-side implementation gap: worker snapshot/live mirror-population asymmetry

**Type:** Rust worker-host design inconsistency (not a spec issue).
**Severity:** correctness (stale cache entries for non-subtree
subscriptions); contained by the proxy's `prefix_covers` read gate.

**The asymmetry.** A `WorkerProxy::observe(prefix)` subscription's
main-thread mirror is populated from two sources that use *different*
path-matching rules:

- **Initial `Event::Snapshot`** — host `build_initial_snapshot` →
  `PeerContext::list_entities(prefix)` → `LocationIndex::list(prefix)`,
  a **raw `path.starts_with(prefix)` prefix scan** with the wire prefix
  verbatim.
- **Live `Event::Change`** — host registers the SDK subscription with
  `prefix_to_pattern(prefix)` and the engine delivers per
  `entity_subscription::engine::pattern_matches` (`"*"` → all;
  `pat.strip_suffix("/*")` → `starts_with(stem) && longer`; else exact).

For a **subtree** wire prefix (`/a/b/` or `/a/b/*`) the two roughly
agree. For an **exact-match** wire prefix (`/a/b/state`, no trailing
slash) they diverge: the snapshot scan pulls in every string-prefix
sibling (`/a/b/state2`, `/a/b/state/child`) but live delivery only ever
updates the exact path `/a/b/state`. The mirror is born over-populated
with siblings the worker will never keep current.

**Interim handling (proxy-side, landed).** `wasm-worker-proxy`'s
`prefix_covers(prefix, path)` is the exact composition of
`pattern_matches(prefix_to_pattern(prefix), path)`, and `cache_get` /
`cache_list` / `put_and_wait_for_cache` all gate reads through it. This
makes reads return only live-maintained entries — the stale snapshot
siblings are present in the `BTreeMap` but never surfaced. Correct for
consumers, but the mirror still wastes memory holding entries that can
never be read or updated, and it means an exact-match subscription's
snapshot does work (fetch + ship siblings) that is then unreachable.

**Proper fix (worker-host side, architect's call).** Make the snapshot
scan honor the same `prefix_to_pattern` semantics as live delivery —
i.e. for an exact-match prefix the snapshot should contain at most the
single exact path, not a `starts_with` sibling set. Small host-side
change (filter `build_initial_snapshot`'s `list_entities` result through
the resolved pattern), but it changes the `Event::Snapshot` wire payload
shape for exact-match subscriptions, so it wants cross-team sign-off
with the browser app (the Dom frontend) before landing. Logged rather than silently
patched: the proxy gate makes it safe, not correct.

## Spec under-specification: EXTENSION-CONTINUATION §3.4 A.1 lost-error marker — `step_index` and marker entity type


**Spec:** EXTENSION-CONTINUATION v1.9 §3.4 (A.1), §8.2 SHOULD.
**Type:** Spec names a path component / entity it does not fully define.
**Severity:** low (A.1 is a SHOULD; the marker is an observation sink with
no reactive behavior). Implemented in Rust with the interim choices below.

§3.4 specifies the lost-error marker is bound at
`system/runtime/chain-errors/lost/{chain_id}/{step_index}` capturing
"the original error code and status, the on_error delivery URI that
failed, the original request ID, a timestamp." Two gaps:

1. **`{step_index}` is undefined.** No continuation type (§2.1–§2.7) nor
   any handler-context field carries a per-chain step counter, and §3.4
   does not say how a continuation determines its own step index. The
   `chain_id` correlates the chain (§6.2) but the step ordinal is
   nowhere defined.
   - **Interim choice (Rust):** `step_index` = the dispatch-layer
     `Bounds.cascade_depth` (monotonic per chain, already threaded, no
     new entity field). Defensible — it is *a* monotonic per-chain
     ordinal — but not necessarily the "step index" a cross-impl
     conformance test would expect; Go/Python may pick differently,
     producing different marker paths for the same logical failure.
   - **Architect ask:** pin `step_index`'s source (a chain-step counter
     in `Bounds`/`EmitContext`? the continuation entity? `cascade_depth`
     ratified as the definition?) so the marker path is cross-impl
     stable.

2. **Marker entity type name is not pinned.** §3.4 describes the payload
   fields but names no `type_ref`. Rust uses `system/runtime/chain-error`
   (unregistered — markers are informational, not schema-validated).
   Cross-impl marker readers/aggregators need an agreed type string.
   - **Architect ask:** pin the marker entity type (and whether it
     registers in the type system) so aggregators are cross-impl.

Both are logged rather than silently chosen because the marker path and
type are observable cross-impl surface; A.1 being a SHOULD made shipping
the interim acceptable, but the conformance contract needs the pins.

## Rust-side sequenced work item: EXTENSION-CONTINUATION §4.2 case 3 / §8.1 — cross-peer continuation dispatch threading (G2)


**Spec:** EXTENSION-CONTINUATION v1.9 §4.2 case 3, §4.3, §8.1 (G2).
**Type:** Rust impl threading **not yet wired** — extension-layer
composition. **NOT a core-protocol change; zero new protocol primitives.**
**Conformance status:** **No present conformance failure.** §4.2 case 3
specifies advance-time `VerifyChain` failure as the *conformant interim*
where the remote target is resolved only at advance. The cross-peer §8.1
bullet is the required *shape* **when an impl performs cross-peer
continuation (L2) dispatch**; an impl that does not yet do so is **not
non-conformant**. Local/system continuations are wholly unaffected (chain
resolves from the install-persisted local store; in-chain ⇔
rooted-at-installer locally).

**Layer (architecture-team review — agreed).** G2 adds no
new protocol primitives. It composes primitives already normative in V7
and already shipped in Rust: capability authority chains +
`check_creator_authority` (V7 §5.5), `VerifyChain` at the verifying peer
(V7 §5.2), envelope `included` for hash-referenced entities (V7
§3.1/§3.2), content-addressed dedup on ingest. It specifies how a
continuation *composes* these for the cross-peer case — the same shape
EXTENSION-SUBSCRIPTION §1.2/§1.3 already specifies (B-rooted caller cap +
A-rooted deliver_token). **Relocating G2 to core would be wrong** — it
would re-open shipped core primitives to express something the extension
layer already has the vocabulary for. What is genuinely first-of-kind in
Rust is **L2 (continuation chains) working cross-peer at all** — that is
extension + SDK + impl scope, not core, and is explicitly sequenced
(below), not a present conformance gap.

**One honest impl note (verified, not inferred).** The arch-team framing
"do for continuation what subscription already does" is correct at the
*spec/primitive* layer. At the Rust *impl-threading* layer there is no
shipped cross-peer scoped-cap dispatch to copy: the continuation remote
path is not wired (evidence below), and the subscription cross-peer
caller-cap *dispatch threading* in Rust was not confirmed during this
review (only the install-time deliver_token chain check, SB1, is
confirmed shipped). So C-3 + the dispatch threading are first-of-kind in
Rust — which *reinforces* the sequenced, careful approach the spec
prescribes; it does not contradict the arch-team conclusion.

**Spec requirement (§4.2 case 3 / §4.3 / §8.1).** For a continuation
step whose `target` is a remote peer B, the continuation's
`dispatch_capability` MUST be the EXECUTE's capability, and the **full**
authority chain (leaf → B-recognized root) MUST travel in the dispatched
envelope's `included` map (the leaf-only V7 §3.1/§3.2 reading is
insufficient cross-peer).

**What Rust actually does (verified, file:line).** The continuation
handler resolves `dispatch_capability` and passes it as
`ExecuteOptions.capability` (`extensions/continuation/src/lib.rs`
`advance_forward`). But on the remote path that value is **dropped**:

- `core/peer/src/connection.rs:1322-1406` (`make_execute_fn`, remote
  branch) calls `remote::send_execute(conn, keypair, uri, op, params,
  resource, deliver_to)` — `opts.capability` is **not a parameter** and
  is never forwarded.
- `core/peer/src/remote.rs:451` `send_execute` →
  `build_authenticated_execute(keypair, &conn.capability,
  &conn.auth_included, …)` — uses the **connection-level** capability
  from the authenticate handshake.
- `core/peer/src/remote.rs:348` sets EXECUTE `capability` =
  `conn.capability.content_hash`; lines 417/421-425 bundle that
  connection cap + `auth_included` into `included`. The continuation's
  `dispatch_capability` and its authority chain are never on the wire.

So cross-peer continuation dispatch currently authorizes with the
caller's *connection* grant, not the continuation's scoped
`dispatch_capability` — and §4.2 case 3's chain-transport MUST cannot be
met by any handler-side change alone.

**Why this is logged + sequenced (not patched in this pass).** This is
not "scary infrastructure deferred" — logging + sequencing is exactly
what the spec's own ordering prescribes. The work: thread
`opts.capability` through `make_execute_fn`'s remote branch →
`send_execute` → `build_authenticated_execute`, use it as the EXECUTE
capability for continuation dispatch, bundle `collect_authority_chain
(leaf)` into the envelope `included`. Its end-to-end correctness is
**only verifiable cross-peer**, and the proposal/guide explicitly scope
that proof as workbench-owned and the T2-closure gate — with
advance-time-fail as the *specified conformant interim* until then
(so nothing is being deferred *below* its required conformance level):

- `PROPOSAL-CONTINUATION-CROSS-PEER-AND-TRANSFORM-OPS.md`: "Remaining
  (post-merge, not spec-side): V-1 — Phase C (G2) … owned by
  workbench-go; T2 is 'done' on that proof, not on this landing."
- `GUIDE-CONTINUATION-IMPLEMENTATION.md`: the §8.2 SHOULD re-attenuation
  **mint helper (C-3)** — B-rooted cap, installer as leaf granter — is a
  prerequisite, and "Phase C … proves G2 after the SDK mint helper
  exists."

Landing a large speculative rewrite of the remote dispatch path with no
cross-peer harness to validate it would be unverified infrastructure —
the failure mode this repo's recent review lessons explicitly call out.

**Scoped plan to close (coordinated, not unilateral).**
1. Add `ExecuteOptions.included: HashMap<Hash, Entity>` (backward-compat;
   existing `..Default::default()` callers unaffected).
2. Continuation `advance_forward`: when `dispatch_capability` resolves,
   `collect_authority_chain(cap_hash, resolve)` and put every chain
   entity into `opts.included`.
3. `make_execute_fn` remote branch + `send_execute` +
   `build_authenticated_execute`: accept the dispatch capability +
   `included`, set EXECUTE `capability` to the dispatch cap for
   continuation dispatch, bundle the full chain into envelope `included`
   (dedup by hash — content-addressing makes over-inclusion free, §4.2
   "Chain transport").
4. Validate against workbench Phase C with the C-3 mint helper.

Until (4) exists this stays advance-time behavior (B's `VerifyChain`
rejects a non-conformant chain — which the spec §4.2 case 3 explicitly
accepts as "current behavior" where the remote target is only known at
advance). Local and system-created continuations are unaffected
(in-chain ⇔ rooted-at-installer locally; chain resolves from the local
store the install step persisted).

**Update — C-3 SDK helpers LANDED (the prerequisite, not the
threading).** The two §8.2 SHOULD helpers proposal §9.1 assigns to
entity-core-rust are implemented + unit-tested, mirroring the Go
reference shape (`MintReattenuated` / `CollectChainBundle`) but written
from spec:

- `entity_capability::mint_reattenuated` (`core/capability/src/mint.rs`)
  — produces the §4.2 case-3 shape: leaf cap `granter = grantee =
  installer`, `parent = the B-conferred cap`, so the chain is rooted at
  B's conferred authority with the installer in-chain as the
  re-attenuation leaf granter. Rejects zero-hash parent / empty grants.
  Returns `(cap_entity, sig_entity)` (canonical 4-field sig, same shape
  as `generate_deliver_token` / envelope ingest expects). 2 tests
  (shape + bad-input).
- `entity_protocol::collect_chain_bundle`
  (`core/protocol/src/verify.rs`, next to `collect_authority_chain`) —
  generic over content + location resolver closures (the verify.rs
  idiom; no store-trait dep). Walks the chain, bundles every cap + each
  link's granter `system/peer` identity + the granter's signature
  resolved from the V7 invariant pointer path
  `/{peer_id}/system/signature/{hex33(target)}` (byte-identical to
  `core/peer::ingest`'s `hex_segment`). Best-effort per link;
  over-inclusion free (content-addressed dedup). 2 tests (full bundle
  verifiable from the bundle alone via `check_creator_authority` +
  best-effort omission). Both re-exported via the `entity-core` facade.

This closes the **C-3 prerequisite** the proposal/guide gate Phase C on.
Steps **1–3 (the actual remote-dispatch wire threading)** and step 4
(workbench Phase C end-to-end proof) remain exactly as scoped above:
sequenced, coordination-gated, advance-time-fail is the specified
conformant interim until workbench validates them. No present
conformance gap; nothing in this update changes wire behavior.

**Update — Amendment 2 (spec v1.11): mint helper grantee
pin LANDED.** The v1.9 §4.2 case 3 model pinned chain *root* (B-rooted)
and *granter* (installer in-chain) but was **silent on the grantee** —
an incomplete port of the EXTENSION-SUBSCRIPTION §1.2/§1.3 caller-cap
analog (which is B-rooted *and* grantee-determinate). entity-core-go
proved by wire trace, with each impl as originator, that **none of
Go/Rust/Python conform**: the cross-peer dispatched EXECUTE is authored
by the **host peer** (the continuation handler signs with that peer's
keypair — the only key it holds), so B's `grantee == author` check (V7
§5.2) rejects a cap self-wielded to the installer. Go silently escalated
onto the connection cap (the *unsafe* failure — V7 §6.8 leak); Rust
failed closed. Arch resolved it as Amendment 2 → **spec v1.11 §4.2 case
3 (iii)**: `grantee` MUST be the dispatching host peer (the EXECUTE
author); installer unchanged as in-chain leaf granter; chain still
B-rooted. (Amendment 3 / V7 §5.2 v7.43 names the general *three-slot
model* — root = resource owner, grantee = EXECUTE author, in-chain
granters = attenuators incl. installer — that collapses only locally;
clarification, no Rust action.)

My prior `mint_reattenuated` set `grantee = signer_identity.content_hash`
(self-wielded to the installer) — **was non-conformant per v1.11**.
Fixed: `mint_reattenuated` now takes an explicit `grantee: Hash`
parameter (positioned after `signer_identity`, mirroring Go's
`MintReattenuated` arg order for cross-impl review) = the dispatching
host peer; new `MintError::MissingGrantee` zero-check; module/fn docs
rewritten to the three-slot (i)/(ii)/(iii) model; tests assert
`leaf.grantee == host_peer && != installer`. 2 capability tests green;
workspace `--all-features` 0 failed; no other callers (only the facade
re-export — the dispatch consumer is still unwired = step 2). This is
proposal §10.1's entity-core-rust deliverable ("explicit grantee
parameter… solo, unit-testable. **Prerequisite for everything
below**"), now done.

**The remaining Rust work is unchanged in scope but better-equipped.**
The G2-dispatch-grantee continuation note
§RESOLUTION gives a proven 4-step conformance recipe; for Rust the
mapping is: **step 1 (explicit-grantee mint) = DONE** (above); **steps
2–4 = the steps 1–3 dispatch threading scoped above** (authorize the
cross-peer dispatch with the scoped `dispatch_capability` not the
connection cap — V7 §6.8; full chain staged at install + bundled at
advance via `collect_chain_bundle`; subtree-scope prefix ops). What is
*new and changes the calculus*: there is now (a) a Go-proven
end-to-end recipe and (b) a **portable conformance harness** —
`entity-core-go validate-peer -peers <rustPeer>,<goPeer> -category
convergence` with Rust as originator (`clients[0]`); green on
`c3_scope_setup` / `c3_inscope_lands` / `c3_outofscope_denied` ⇒
conformant. So steps 2–4 are no longer "only verifiable cross-peer with
no harness" — the harness exists and pinpoints which step is missing
(failure-mode decoder in the peer doc §RESOLUTION). Still sequenced
(workbench Phase C owns the gate) and still the larger core/peer
wire-path change, but the unverifiability objection that justified
deferring it is now resolved; it is a deliberate next work item, not a
blocked one.

**Update — G2 dispatch threading IMPLEMENTED + PROVEN
CONFORMANT (cross-impl, Rust as originator).** Recipe steps 2–3 landed:

- `core/peer/src/remote.rs` — `build_authenticated_execute` +
  `send_execute` take an optional dispatch-cap override + a
  chain-bundle map. The override (the continuation's scoped
  `dispatch_capability`) becomes the dispatched EXECUTE's `capability`
  instead of the connection grant; the bundle is included (dedup via
  `find_included`). `None` + empty bundle ⇒ byte-identical to pre-G2
  (every existing caller — async inbox delivery, etc. — unaffected;
  passes `None, &empty`).
- `core/peer/src/connection.rs` — `make_execute_fn` remote branch: when
  `opts.capability` is `Some` (a continuation dispatch), it calls
  `entity_protocol::collect_chain_bundle(&cap.hash,
  content_store.get, location_index.get)` (the C-3 helper) and threads
  cap + full chain into `send_execute`. The chain is resolvable because
  continuation install already persists it (§3.2 step 5, verified
  `extensions/continuation/src/lib.rs:927-935`). `collect_chain_bundle`
  `Err` ⇒ send the scoped leaf cap only and warn — B fails closed on
  its `VerifyChain`; that is safe and conformant, **never** a fallback
  to the connection grant, so no V7 §6.8 escalation.
- Unit test `core/peer/src/remote.rs::test_scoped_dispatch_cap_and_chain_transport`
  locks the wire shape (override cap referenced as EXECUTE
  `capability`; every chain entity in envelope `included`; `None`/empty
  byte-identical). Workspace `--all-features` 1003 pass / 0 fail; zero
  new clippy warnings (pre-existing-only, unrelated files).

**Proven conformant by the canonical portable harness.** Ran
`entity-core-go validate-peer -peers <rustA>,<goB> -identity
framework-admin -category convergence` with **Rust as originator
(clients[0])** against a Go reference verifier (B), via
`peer-manager` (rebuilds `entity-cli` from this tree). Result:
`c3_scope_setup` **PASS**, `c3_inscope_lands` **PASS**,
`c3_outofscope_denied` **PASS** (the negative control: an out-of-scope
cross-peer dispatch is *denied* — proves the scoped cap is enforced and
there is no §6.8 silent escalation to the connection grant). Per the
the G2-dispatch-grantee continuation note
§RESOLUTION: "Green on all three c3 checks ⇒ conformant." `rexec_*`,
`chain_*`, `cache_extract_merge/verify`, `bisync_*` also green
(unblocked by this). **The cross-peer continuation G2 work is therefore
no longer a sequenced/interim item — it is implemented and proven; the
SPEC-AMBIGUITIES "advance-time-fail interim" no longer applies to
Rust.**

*Method note (verify, don't infer — recorded because it nearly produced
a false finding).* A first harness run **without** `-identity
framework-admin` failed at continuation `install` with 403
`embedded_cap_unauthorized`. Root cause: `validate-peer`'s
`NewPeerClient` calls `crypto.Generate()` **per address**, so each
PeerClient gets a distinct keypair; the scoped cap was minted
granted-from the B-connection identity but the install was authored by
the A-connection identity → Rust's §3.1a in-chain check **correctly**
rejected (the install author genuinely was not a granter in the
chain). This is **Rust behaving per spec**, not a bug — the
convergence harness is *designed* to run under one shared operator
identity (`-identity framework-admin`, `crypto.LoadIdentity`), as
`scripts/test-cross-peer.sh:80` does and the peer doc's
"Distinct-identity provenance" second-order finding documents
("c3/rexec/chain/bisync are genuinely green under this model"). Rust's
strict §3.1a enforcement was *not* weakened to chase a misconfigured
run — the run was corrected. The remaining convergence reds
(`psync_all_synced`/`psync_path_usable`/`psync_query_namespace`,
`cache_hop2_verify`, `filesync_synced`) are the Go-side
legacy-validator-cap second-path residual + the unimplemented Rust
local-files extension — neither continuation/Amendment-2 nor caused by
this change.

---

## Durability Contract (EXTENSION-DURABILITY v0.1) implementation notes

**Update — architecture extraction.** The §10 durability material
was extracted from EXTENSION-INBOX into a new standalone
`EXTENSION-DURABILITY.md` (v0.1, **EXPLORATORY / OPTIONAL / NOT ACTIVELY
DEVELOPED**). V7 was reverted v7.47 → v7.46 (no durability
material in core); EXTENSION-INBOX restored to v5.6 surface (stamped v5.9);
`PROPOSAL-DELIVERY-AND-DURABILITY` marked RETRACTED. **Wire shape and
behavior unchanged** — the Rust impl below is still correct against the
new file; only spec references shifted (`§10.x → §x`; `V7 §3.2/§3.3
silent-ignore / 412 reservation → EXTENSION-DURABILITY §5/§8`). The 412 /
durability-use-of-202 reservations no longer live in V7's core status
table — they exist only within the surface of a peer that installs
EXTENSION-DURABILITY. EXTENSION-INBOX §7.1's 202 (inbox-ack) is unchanged.
Handoff: the Go team's durability-extraction handoff.

**Status: spec clean (against EXTENSION-DURABILITY v0.1), no ambiguity in
the surface that landed.** The new file is self-consistent and explicitly
implementation-defined where it leaves room (§7 illustrative strength
vocabulary; §4/§8 implementation-defined policy + replication topology).
The §5 verdict table maps cleanly onto a small reconcile function gated on
(a) `requested.self_determinable() && requested.rank() ≤ policy.max`,
(b) `must_have`, (c) async pathway presence (`deliver_to`).

**Implementation choices worth surfacing** (none require architect input,
but worth noting for cross-impl alignment):

1. **Strength vocabulary chosen for this peer:** `none` / `stored` /
   `replicated`. Unknown strings parse to a separate `Unknown(String)`
   variant whose rank is `u8::MAX` — never self-certifiable, so required
   unknown → 412, best-effort unknown → take less observably. Reason code
   spellings pinned at `core/peer/src/durability.rs`:
   `REASON_NO_DURABLE_STORE = "no_durable_store"`,
   `REASON_REQUIRED_UNMET = "durability_required_unmet"`.

2. **Policy → store mapping:** `MemoryContentStore` → `None`;
   `.sqlite()` / `.opfs()` builders auto-set `Stored`. `Replicated` is
   never set automatically — this peer is **not configured for any
   replication topology**, so per §5 row 4 ("not configured for the
   required topology") a *required* replication request is refused with
   412; a best-effort one takes less, observably. This is faithful, not
   a gap; replication topology config is explicitly implementation-defined
   per §8.

3. **Async pathway = `deliver_to`:** the inbox write completes
   asynchronously, so at the moment of the 202 response nothing is
   physically in place yet — `applied` is always `"none"` on the async
   branch (faithful to §5 "never claim durability you don't have"),
   and the achievable strength is carried in `committed` (gated to 202)
   only when the store is durable.

4. **§6 handle = the existing inbox storage key.** The Rust inbox
   handler already stores delivered messages at
   `{deliver_to.uri}/{request_id}` (`extensions/inbox/src/lib.rs` ~L99–104).
   The `(author, request_id)` uniqueness scope (V7 §3.2/§3.3) is satisfied
   when the deliver_to URI is author-scoped at the recipient (the
   prevailing convention); a shared inbox URI with non-UUID request_ids
   could in principle collide across authors. V7 §3.3 RECOMMENDS UUIDs,
   making collisions statistically negligible — flagging for cross-impl
   awareness, not a Rust-side fix.

5. **§3 advertise (SHOULD) deferred.** The receiver's supported
   durability levels are not yet exposed via a discovery surface
   (system/peer/self/status or hello result). The MUST contract is
   complete; advertisement is a follow-up.

6. **Pre-acceptance error responses do not carry a `durability` field.**
   Per §4 reconcile is gated on *accepting* the request; auth /
   path / handler-resolution failures (401/403/404) return before
   acceptance and their explicit status is itself the observable answer
   — not a silent discard. Durability field appears only on the
   post-acceptance response (sync 200/err, deliver_to 202, and the 412
   refusal at acceptance).

**Cross-impl interop:**

- Wire field added to `system/protocol/execute`: `durability_request`
  (optional inline map `{level, must_have}`), same convention as
  `deliver_to`.
- Wire field added to `system/protocol/execute/response`: `durability`
  (optional inline `system/durability-result` entity).
- ECF key ordering on EXECUTE_RESPONSE with durability:
  `result(7) < status(7) < durability(11) < request_id(11)`. Wire
  round-trip test at `core/protocol/src/lib.rs::test_durability_field_wire_roundtrip`
  asserts well-formedness + the bare-map field shape.
- **Wire shape lesson (durability-1 fix; pre-extraction):** the `durability` field
  is typed `system/durability-result` (a specific struct), NOT `core/entity`,
  so the wire value is a **bare CBOR map** of `{requested, applied,
  committed?, max_available?, reason?}` — same convention as `deliver_to`
  (typed `system/delivery-spec`) and `bounds` (typed `system/bounds`).
  The first Rust pass wrapped the field as `{type, data, content_hash}`
  (the `core/entity` convention used for `result`/`params`); the cross-impl
  validator decoded it as a flat struct and reported all fields blank.
  Self-round-trip tests missed it because both encoder + decoder shared the
  same wrong shape. Resolved by replacing `DurabilityResult::to_entity()`
  with `to_cbor()` and threading raw CBOR bytes through
  `build_execute_response_full` / `build_202_response`.

- **§6 preservation (durability-2 fix; pre-extraction):** the §5 invariant
  "applied = physically in place at response time" is honest only if the
  receiver actually writes the originating EXECUTE into a `(author,
  request_id)`-addressable slot when it claims `applied: stored`. Rust's
  first sync-path pass returned `applied: stored` without preserving
  anything — the strengthened `durable_entry_preserved` validator caught
  it. Resolved by `connection.rs::preserve_durable_request`: when the
  verdict's `applied` rank ≥ Stored AND `deliver_to` is absent, the
  dispatcher write-aheads `env.root` to the content store and binds the
  hash at `/{local_peer}/system/inbox/{request_id}` BEFORE handler
  dispatch. On store failure, the verdict downgrades to
  `applied:none, reason:no_durable_store` (observable downgrade — never
  overclaim). The deliver_to path's inbox handler already preserves via
  its existing write-ahead (`extensions/inbox/src/lib.rs::handle_receive`
  L99–104), so dispatcher-level preservation only fires on the no-
  deliver_to path — no double-write. Mirrors Go's `preserveDurableRequest`
  in `core/protocol/durability.go`.

**Post-fix cross-impl status:**

- Single-peer durability category: 13 PASS / 1 WARN / 0 FAIL (sqlite
  backend). Remaining WARN is `advertisement_present` — §3 SHOULD,
  the absence of which "does not change the response contract".
- Scenario 5 (companion peer as outbox), Rust↔Go both directions:
  **5 / 5 PASS each way** — Rust now works both as preserver and as
  durable host of another peer's inbox namespace.
- Status codes: `STATUS_ACCEPTED = 202`, `STATUS_PRECONDITION_FAILED = 412`
  added to `core/handler/src/lib.rs`.


---

## IMPL-TEAM-CHANGELOG absorption

Spec source: the architecture team's impl-team changelog.
Cross-impl items A.2 / A.3 / A.4 / A.8 / I-7 / I-8 all landed on this
branch.

### Background — spec-issue taxonomy

Three categories of spec issue exist; this file tracks all three so the
architecture team has one place to look:

- **Spec ambiguity** — spec is right but ambiguous; multiple valid reads;
  impls diverge without anyone being wrong. Fix is more text.
- **Spec failure / missing spec** — a MUST whose mechanism isn't
  enumerated, missing op in the manifest, missing field definition,
  internally inconsistent rules. Fix is amending the spec.
- **Spec bug** — wrong pseudocode, broken cross-references, inconsistent
  field types. Fix is correcting the spec.

All three are surface-able here; the architecture team categorizes on
intake. (Prior versions of this doc conflated "ambiguity" with "spec
issue I worked around" — that posture was wrong; spec failures get
flagged, not absorbed silently.)

### RESOLVED — landed in REVISION v3.3 / CONTINUATION v1.14 same-day

All four spec issues raised below were resolved in same-day architecture
amendments (the architecture team's impl-team changelog addendum; canonical reference =
REVISION v3.3 + CONTINUATION v1.14).

- ~~**Spec failure: merge-config canonical write path**~~ — EXTENSION-
  REVISION v3.1 §2.3 mandated config-write-time rejection of `lww` /
  `keep-both` but §4.1 op manifest had no merge-config op. Landed in
  **REVISION v3.3 §4.4.18** (`merge-config` op + result type with
  `status: "set" | "deleted" | "no_change"`; §2.3 "Handler-owned
  namespace" declaration). Rust diff: result-shape rewrite + idempotency
  + CAS code rename + bootstrap manifest entry. See `core/peer/src/
  lib.rs:803`, `extensions/revision/src/lib.rs:488`.

- ~~**Spec ambiguity: `chain-error-lost.step_index` for v1.13**~~ —
  CONTINUATION §3.4 v1.13 named `{step_index}` but didn't pin it for the
  v1.13 case; Rust drifted to `cascade_depth`, Go used `RequestID`.
  Landed in **CONTINUATION v1.14 §3.4** ("MUST be the original request
  ID … identical to the A.1 convention"). Rust diff: `ChainErr.step_index`
  field changed `u64 → String`, populated from `ctx.request_id`. See
  `extensions/continuation/src/lib.rs:30,139`.

- ~~**Spec ambiguity: `deterministic` tie-break direction**~~ — §2.3
  table named the strategy but not the direction. Landed in **REVISION
  v3.3 D2** ("the **lower** of `entity_hash` and
  `CANONICAL_DELETION_MARKER_HASH` under byte-wise lexicographic
  comparison wins"). Rust was already lower-hash-wins; no diff needed.

- ~~**Spec ambiguity: §6.1 marker-augmentation vs §6.2 dedup ordering**~~
  — §6.1 didn't enumerate ordering vs the dedup-against-prior-head
  check. Landed in **REVISION v3.3 D3** ("augmentation MUST precede
  dedup"). Rust's `perform_commit` was already in this order; comment
  refreshed to cite v3.3 D3.

### Cross-impl validator FAIL absorbed (impl-side, not spec)

Per `entity-core-go/docs/archive/validation/peer-tracking/RUST-CHANGELOG-2026-
05-20-VALIDATION.md`:

- `revision.revert_file_removed` — Rust's revert built its own trie via
  the shared merge classifier but didn't augment V_target's bindings
  with markers at paths V_revert added. Under v3.1 absence-is-preserve
  the classifier kept the local entity instead of unbinding. Fixed by:
  (a) extracting `augment_bindings_with_markers` as a shared helper used
  by `perform_commit` and `handle_revert`; (b) correcting the merge
  classifier's marker-vs-entity branch to consult `base_hash` first —
  if `base == one side`, it's clean three-way (take the other side),
  not "both changed differently" (which is what `deletion_resolution`
  is for). Test: `revert_unbinds_file_added_by_target_version` in
  `extensions/revision/src/lib.rs:4067`.

  This was a genuine impl bug (not a spec issue): the spec was clear,
  the classifier had a path-by-path logic error I'd introduced when
  rewriting for v3.1 semantics. Mentioning here because the validator
  surfaced it via the same cross-impl absorption pass.

## revision:pull §4.4.8 landed (was stubbed → 501)

**Status:** landed. No arch flag.

`revision:pull` was previously dispatched to `handle_remote_stub` (501
not_implemented) and was not even advertised in `operations()`. Closed
per workbench-go handoff: implemented per EXTENSION-REVISION §4.4.8.

  - `extensions/revision/src/lib.rs::handle_pull`: outbound fetch
    against `entity://{remote}/system/revision` (via `ctx.execute_fn`),
    ingest envelope.included → local store, decode `head` from
    fetch-result, walk the remote's trie locally + iteratively
    fetch-entities (max 32 rounds, matches Go's `pullMaxRounds`), local
    merge against the freshly-fetched remote head.

  - `decode_fetch_params`: new decoder for `system/revision/fetch-params`
    that picks up the `remote` + `remote_prefix` fields (Rust's prior
    `decode_log_params` silently dropped them; pull plumbing now
    threads them end-to-end).

  - Helpers: `build_fetch_params_entity`, `build_fetch_entities_params_entity`,
    `decode_envelope` (entity-revision-local; reuse of `entity_wire::decode_envelope`
    would have required a new crate dep, ~20 LoC inline preferred),
    `inline_to_entity`, `decode_fetch_result_head`,
    `collect_missing_pull_hashes` (mirrors Go), `clone_ctx_with`
    (synthetic ctx for the inner merge invocation).

  - `STATUS_BAD_GATEWAY = 502` added to `core/handler/src/lib.rs` for
    the `remote_fetch_failed` error class.

**Op-list parity survey (Rust vs Go):**

  - revision: now full parity (19/19 ops). `pull` was the only gap.
  - clock: `tick` is a 501 stub in Rust (Go has it); other ops parity.
  - Every other extension: dispatch parity. Field-level audits (like
    the `remote`-on-fetch-params miss this fixed) would require
    per-op param-struct diffing against Go's typed structs and are
    not yet done as a pass. Worth a follow-up sweep, but the
    cross-impl probe is the authoritative source of truth — fields
    that don't surface in conformance probes are unobservable.

## v1.16 / v3.4 / v3.15 landing pass

**Status:** landed. Tracking entry only — no architect attention needed
unless the cross-impl probe flags a divergence.

Three coordinated landings absorbed in this session per
the workbench-go cross-impl fetch/diff/merge-mode handoff:

  1. **EXTENSION-TREE v3.15 (withdrawal).** Removed `tree:extract` since-
     mode in `core/tree/src/lib.rs` — the `since` param handling,
     `handle_extract_since`, the revision-head deref helpers
     (`resolve_revision_head`, `decode_version_root`,
     `decode_version_parents`, `since_appears_in_revision_chain`,
     `extract_peer_segment`, `prefix_hash_hex`,
     `materialize_current_root_from_bindings`), `collect_branch_nodes`,
     `make_included_pair`/`build_envelope`, and all the since-mode tests.
     Per the spec deletion + the "no backward-compat shims" rule.
     Supersedes the older "since-mode diff cost" and "scope-validation
     mechanism" entries below (kept for historical context).

  2. **EXTENSION-REVISION v3.4 (`revision:fetch-diff`).** New op in
     `extensions/revision/src/lib.rs::handle_fetch_diff`. Shape B
     (single-dynamic-field, chain-expressible): `(prefix, base)` — target
     is implicit (handler peer's current head). Calls
     `trie::collect_reachable_hashes` and `trie::collect_trie_entities_except`
     downward into `core/tree/src/trie.rs` (new public primitives modeled
     on the Go reference). Error codes pinned to the workbench probe:
     `400 invalid_params`, `404 no_local_state`, `404 base_not_found`,
     `400 base_not_a_version`, `500 internal_error`. Cap-denied surfaces
     at the dispatch layer (handler-internal cap check is not how the
     Rust revision crate is structured — none of its existing ops do
     in-handler cap checks).

  3. **EXTENSION-CONTINUATION v1.16 (`result_merge` + per-reason marker
     path).** Added `result_merge: bool` to `ContinuationData` with
     encode/decode + omitempty round-trip. Install-time mutex check
     against `result_field` returns `400 invalid_continuation` per §3.2.
     New `assemble_params_merge` helper for §3.6 Step 2 Merge dispatch-
     mode: shallow-union of post-transform map into static params, result
     keys win on collision. Non-map post-transform value degrades to
     static-only params and fires the `merge_value_not_map` lost-error
     marker. `write_lost_error_marker`'s path moved from
     `.../{chain_id}/{step_index}` to
     `.../{chain_id}/{step_index}/{reason}` per §3.4.

**Bug found and fixed: error entities used wrong type name (cross-impl R-1, R-2).** The cross-impl probe at
the workbench-go cross-impl fetch/diff/merge-mode validation note
flagged Rust's `revision:fetch-diff` returning `code="not_found" msg="status 404"` instead of the spec-pinned
`base_not_found` / `no_local_state`. Root cause: 10 extension `error_result` helpers were constructing the
error entity with type `"system/error"` instead of the canonical `"system/protocol/error"`. Go's SDK
(`entitysdk/errors.go::ErrorFromResponse`) only reads `{code, message}` from the result entity when its type
matches `TypeError` (= `"system/protocol/error"`); otherwise it falls back to status-default codes, masking
the handler's actual code+message. Rust's type-registry constant `entity_types::TYPE_ERROR` was already
correct — the helpers just hardcoded the wrong string. Swept all 10 sites (revision, clock, handlers, inbox,
quorum, role, attestation, subscription, query, identity); workspace tests green. Not an arch flag — pure
Rust absorption miss across the extensions.

**Bug found and fixed: tree:extract envelope-type was wrong.** Noticed
while wiring fetch-diff: Rust's `tree:extract` was returning
`system/protocol/envelope` (a protocol-message type for EXECUTE-wrapped
data) instead of `system/envelope` (a data-bundle type). Spec is
unambiguous — `EXTENSION-TREE.md` §6 pins `output_type: "system/envelope"`
on the extract signature row, and
`PROPOSAL-CONTINUATION-TRANSFORM-AND-ENVELOPE-AMENDMENTS.md` S3 is the
landed amendment that explicitly renamed it (Rust just never absorbed
S3). Fixed in this commit: `core/tree/src/lib.rs::handle_extract` now
emits `entity_types::TYPE_ENVELOPE` (`system/envelope`), matching Go,
Python, query, history, and the new `revision:fetch-diff`. Not an arch
flag — a Rust-side absorption miss.

## Rust-side implementation note: EXTENSION-TREE v3.14 §6.2b — scope-validation mechanism — SUPERSEDED by v3.15 withdrawal

**Status:** impl note, not a spec ambiguity. §6.2b is explicit that the
validation **mechanism is impl-defined** (the rejection contract is the
normative part). This entry documents the Rust impl's choice for future
readers; it is NOT a flag for architect attention.

The earlier draft of this entry called this a spec ambiguity. That was
overclaiming — the spec deliberately left the mechanism flexible, and
"the spec's example mechanisms don't fit my model perfectly" is not the
same as "the spec is ambiguous." The spec did exactly what it intended.

**Spec passage** (EXTENSION-TREE.md §6.2b, v3.14):

> The validation mechanism is impl-defined (e.g., walking the trie's
> structural metadata, looking up the snapshot entity that wrapped it);
> the rejection contract is normative.

**Rust's mechanism choice.** `core/tree/src/lib.rs::handle_extract_since`
layers two checks:

  1. **Structural.** `since` MUST resolve to a structurally-valid
     `system/tree/snapshot/node` (correct type + decodable as
     `SnapshotNodeData`). Catches obvious misuse — a non-trie hash like
     a data entity or a snapshot wrapper.
  2. **Revision DAG-walk** (revision-tracked prefixes only). `since`
     MUST appear as a `root` somewhere in this prefix's revision chain,
     walking parents from `head`. Catches the genuine cross-scope case:
     a valid trie root from a *different* prefix's DAG. This is what the
     Go cross-impl validator's R-3 probe exercises.

For non-revision-tracked prefixes there is no chain to walk; only the
structural check fires. That mirrors the spec's MAY-reject/MAY-
materialize stance for non-revision-tracked since-mode (§6.2a) — the
scope guarantees are weakest where the underlying tracking is weakest.

**Cross-impl posture.** Python and Rust have converged on rejecting the
cross-scope case the Go probe exercises. The probe is one
acceptable-subset conformance vector; whether to lift it to a normative
SHOULD/MUST cross-impl test is a workflow question for the conformance-
suite owners, not a spec change.

**Workbench-go acknowledgment.** The workbench-go signoff review noted
"POC did not exercise cross-scope rejection" — added on the arch
edge-case sweep, per PROPOSAL-TREE-EXTRACT-SINCE.md §2.3b. That punt to
"cross-impl conformance vectors at ratification" is now closeable on the
mechanism Rust + Python both implement.

## Rust-side implementation note: EXTENSION-TREE v3.14 since-mode diff cost — SUPERSEDED by v3.15 withdrawal

**Status:** known — not a spec ambiguity; honest accounting.

The Rust `handle_extract_since` resolves the current trie root via the
revision head when the prefix is revision-tracked (per spec §6.2a) —
O(1). The subsequent "diff between since_root and current_root" step does
NOT use the content-addressed subtree-skipping `compute_trie_diff`
algorithm described in `EXTENSION-TREE.md` §4.3. It collects all bindings
from both tries (`trie::collect_all_bindings`) and compares the binding
sets directly.

For the bundling step (trie nodes on changed branches), the impl walks
the current trie from root following each changed path, collecting
visited nodes via `collect_branch_nodes` — that part is O(diff × depth)
as the spec wants.

Combined cost: O(workspace) for the diff classification, O(diff × depth)
for the bundling — NOT the pure O(diff × depth) total the spec's scale
claim implies.

For the canonical workbench-go-POC workload (50-leaf workspace, 1-leaf
change) this is irrelevant. For workspaces in the 10K-100K range it
becomes load-bearing.

Lift when needed: port the `compute_trie_diff` algorithm from
`EXTENSION-TREE.md` §4.3 (recursive trie walk with content-addressed
subtree skip) into `core/tree/src/trie.rs`; call it from both
`handle_extract_since` and the existing `handle_diff` (the latter has
the same shortcut today). Estimated ~100 LoC + tests. Currently NOT a
blocker — the incremental-sync envelope is still materially smaller
than full extract regardless of how the diff is computed server-side.

---

EXTENSION-COMPUTE v3.14 findings live in their own file:
`docs/archive/COMPUTE-V314-FINDINGS.md`. That document carries the categorized
record (spec issues / spec ambiguities / architecture feedback / impl
notes) for the v3.14 cross-impl convergence work and is the artifact
fed back to the architecture team.

---

## ~~EXTENSION-IDENTITY §12.3 — when does the IdentityBindingChecker hook fire on cap-chain grantees?~~ RESOLVED

**Resolution (EXTENSION-IDENTITY v3.8, arch commit c7e51b1).**
Spec now explicitly **excludes cross-peer dispatch-cap grantees** from
the IdentityBindingChecker hook's scope — strict and permissive impls
interoperate. Rust's interim (permissive — no hook installed) is
conformant; no impl change required. Go relaxes its strict policy at
`ext/identity/binding.go` + `core/protocol/auth.go:130` to match. This
unblocks the four failing directions of the cross-impl
`convergent_mirror` matrix.

Original ambiguity (preserved below for the round-trip trail):



**Spec passage (§12.3):**
> "Cap-chain verification MAY read attestation state via the
> `IdentityBindingChecker` hook (read-only; for grantee-binding lookup);
> cap-chain verification MUST NOT validate attestations as caps."

**Surfaced by:** cross-impl `convergent_mirror` validate-peer matrix
(memo at
the Go cross-impl convergent-mirror matrix).
Of 6 directional A→B pairs, only the 3 with Go-as-source pass cleanly;
all 3 with Go-as-B (or Go in the path) reject installs and subscribes
with **403 authentication_failed** carrying server-side log:

```
execute: auth failed: identity binding checker: no live identity-cert
binding found for grantee ecf-sha256:a357c0b438e1b19af102781c833e366d0260854a603178aeb45177ac97750eaf
```

Go-side reproducer: `core/protocol/auth.go:110`
(`VerifyRequestWithBinding`) runs on every wire-EXECUTE's cap grantee
unless the grantee is local self; checker at
`ext/identity/binding.go:64-95` requires a live `identity-cert`
(`function=agent` or `controller`) bound to the grantee on the local
tree; policy wired unconditionally at `cmd/entity-peer/main.go:347-348`
as `PolicyAllowAnyAttestedAgent`.

**The ambiguity.** §12.3 says the hook **MAY** read attestation state.
It does not pin **when** the hook fires:

| Reading | Implication | Behavior |
|---|---|---|
| Strict (Go's): hook fires on every cap-chain grantee, cross-peer included | Cross-peer grantees MUST have a live local `identity-cert` binding | The receiving peer must have pre-synced or accepted (e.g., TOFU per §12.4) an agent-cert for the remote peer's identity before any cap whose grantee is that identity will validate |
| Permissive (Rust/Python's de-facto): hook is optional; cross-peer grantees out of scope; the connect handshake's verified peer-identity is sufficient | A cap-chain grantee that is a foreign peer's identity hash validates without a local identity-cert binding | The receiver trusts that the wire authentication verified the EXECUTE author; cap-chain checks the cap's authority chain, not the grantee's identity provenance |

The spec gives no normative discriminator. §12.4 (TOFU + supersedes for
cross-peer attestations) suggests cross-peer identity provenance is
something receivers establish over time — which lines up with the
strict reading IF the strict reading is the intent — but doesn't pin
this hook firing on cap chains specifically. §1185-1284 talks about
agent-keys signing caps and revocation cascading on agent retirement,
which also fits either reading.

**Rust's interim choice: permissive (no IdentityBindingChecker installed).**
A `grep` across `core/` and `extensions/` finds **no**
`IdentityBindingChecker` hook, no `binding_checker`, no
`PolicyAllowAnyAttestedAgent` analog wired in cap-chain verification.
`verify_capability_chain` in `core/protocol` walks per-link signatures
and granter resolvability; it does not consult attestation state to
verify grantee identity-binding. Cross-peer caps whose grantee is a
foreign peer's identity hash validate as long as the chain itself
verifies. This matches Python's de-facto behavior and matches the 3
passing convergent_mirror directions where Go isn't the strict party.

**Impact if §12.3 is meant to be strict.** Rust currently fails closed
on the wrong side: rather than rejecting unbound-grantee cross-peer
caps, it accepts them. Adopting the strict reading is mechanical —
factor an `IdentityBindingChecker` trait, wire it through
`verify_capability_chain`, and install a policy in `core/peer`'s
default setup that resolves grantees against
`system/identity/identity-cert` attestations on the local tree. The
EXTENSION-IDENTITY substrate (3-key default; controller+agent certs)
is fully implemented in `extensions/identity` already; the missing
piece is the cap-chain-side hook.

**Impact if §12.3 is meant to be permissive.** Then Go is enforcing a
policy beyond what the spec requires, and Go's pass should relax to
make the cross-impl matrix symmetric. The wire authentication (peer
identity verified at connect, EXECUTE signature verified per
request) already attests that the foreign peer is who it claims to be;
cap-chain just verifies the authority delegation chain on top of
that.

**Question for the architecture team.** Which reading is normative?
The answer determines whether Rust (and Python) needs to wire the
hook, or whether Go should relax `auth.go:110`'s default policy.
Until settled, the cross-impl `convergent_mirror` gate stays asymmetric
on cap-chain handling. The four failing directions in the cross-impl
matrix all collapse to this one root cause; landing it cleanly unblocks
the gate.

**Note:** The convergent-mirroring spec arc itself (CAS-create v7.50,
include_payload v3.13/v3.14, deref_included v1.17, request-side
included preservation v7.51) is fully implemented and verified in Rust;
this ambiguity is upstream of the mirror recipe — about which peer
identities are even allowed to **dispatch** a cross-peer continuation
or subscribe.


---

## EXTENSION-TYPE v1.1

### type_pattern narrowing — "more specific" not algorithmically pinned

**Location.** §6.2 narrowing table, `type_pattern` row:
> Child pattern is more specific (longer prefix or exact match)

**Ambiguity.** The spec defines `pattern` and `format` narrowing as
**equal-only** with the explicit rationale that sub-pattern
recognition is undecidable / interop-unsafe. `type_pattern` is then
given a more permissive narrowing rule ("longer prefix or exact
match") without pinning the recognition algorithm — when does
`system/capability/grant-entry` qualify as "more specific than"
`system/capability/*`? Different glob comparators may answer
differently for non-trivial patterns (consider `a/**/foo` vs
`a/x/foo` — is the latter "more specific" or are they incomparable?).

**Interim choice (Rust v1.1 baseline).** Equal-only, mirroring
`pattern` and `format`. Logged in
`extensions/type-system/src/narrowing.rs` module doc. Deployments
wanting richer narrowing layer it explicitly per the §6.2 framing.

**Question for architecture team.** Pin the algorithm (e.g., child
pattern's literal prefix ≥ parent's literal prefix and child does
not weaken any wildcard), or formally adopt equal-only.

### ENTITY-NATIVE-TYPE-SYSTEM structural validator absent (Rust impl gap)

**Status.** Rust impl gap, not a spec ambiguity. Logged here because
EXTENSION-TYPE §2.3 Phase 1 says "structural validation first
(delegated to ENTITY-NATIVE-TYPE-SYSTEM core)". Rust has
`TypeDefinition` / `FieldSpec` / `TypeRegistry` but no general
structural validator — no `validate(entity, type_def)` that checks
CBOR major-type compatibility against `type_ref`, union dispatch,
generic-type resolution, etc.

**Interim Rust impl.** `extensions/type-system/src/validate.rs`'s
Phase 1 covers `entity.type == type_def.name` and required-field
presence. Deep CBOR-type coercion is **not checked** in Rust today.
Constraint dispatch (Phase 2) is fully implemented.

**Cross-impl risk.** Conformance vectors that depend on Phase 1
catching structural violations (e.g., a string supplied where an
integer is required) will silently pass on Rust today. The
`type` category in `validate-peer` will surface this at the
cross-impl run.

**Resolution path.** Implement
ENTITY-NATIVE-TYPE-SYSTEM v4.2.0 §7 structural validation in
`core/types`. Independent of EXTENSION-TYPE; once landed, Phase 1
delegates to it. Not blocking the type extension MUST gate, but
required for the SHOULD "constraint validation at system boundaries"
to be meaningful.


---

## EXTENSION-CONTENT v3.5

### system/content:ingest envelope-mode with null root + empty included (edge case)

**Location.** §6.3 ingest algorithm.

**Ambiguity.** The pseudocode for envelope-mode says `if envelope.root
is not null: ctx.content_store.put(envelope.root); count += 1`, then
iterates `included`. It returns `root_hash = content_hash(envelope.root)`
unconditionally. If a caller passes `envelope.root: null` and an empty
`included`, `content_hash(null)` is undefined — the spec doesn't pin
the return shape for this corner.

**Interim choice (Rust impl).** When `envelope.root` is absent/null,
`result.root_hash` is the all-zero hash (`format_code=0`,
`digest=[0u8; 32]`). `result.root` is absent (the §11.1 MUST applies
only when `envelope.root` is non-null). `ingested_count` is the
count of `included` entries actually stored. This matches the spirit
of the §6.3 algorithm (don't put what isn't there) without inventing
a new error shape — the caller can observe `root` absent +
`ingested_count == |included|` and infer the no-root path.

**Question for architecture team.** Either (a) confirm zero-hash +
absent-root is fine; (b) pin a different sentinel; or (c) reject the
shape outright as `missing_input` (no root, no included = ambiguous).
Not blocking — pre-v3.5 callers don't exercise this; flag only so the
behavior across impls converges before any consumer relies on it.


---

## ~~Local self-execute `caller_capability` synthesis~~ RESOLVED

**Resolution (same session as discovery).** Adopted SDK-OPERATIONS
§11.2A open-grants posture matching the Go SDK convergence target.
`PeerContextBuilder` mints a wildcard owner self-cap (granter ==
grantee == local identity hash; wildcards on all four scope
dimensions) at peer build time, persists the cap entity + signature
in the content store, and stamps it onto every local L1 dispatch as
`caller_capability` (see `bindings/sdk/src/sdk.rs::mint_owner_self_cap`
and the `Some(owner_cap)` argument on both `PeerContext::execute`
variants). Rust analog of Go's `mintOwnerSelfCap`
(`workbench-go/entitysdk/app.go:782`) + `Executor.SetCallerCapability`
(`executor.go:132`).

V7 §6.5 says "for autonomous operations the caller capability is
absent"; the SDK chooses to materialize the local peer's authority
instead so handlers that voluntarily gate on caller-specified-path
authorization (role:define/assign/re-derive/delegate; identity /
quorum mint paths) work uniformly across local L1 and remote-
connection-cap-bearing dispatch. When kernel-side §11 grant
enforcement lands (Cut 2+), the owner cap becomes opt-in /
overridable rather than the default.

Wrapper docstrings reference §11.2A so consumers know the posture is
intentional and time-bounded, not a permanent papering-over.

---

Original analysis below preserved for traceability:

**Spec passages:**
- `EXTENSION-ROLE §4.3` and §4.2 — define/assign/re-derive/delegate
  enforce RL2 via `is_attenuated(hypothetical, caller_cap, peer_id)`.
  Missing `caller_capability` → `403 missing_caller_capability`.
- V7 §6.5 — "For autonomous operations (no external caller), the
  author is the local peer identity and the caller capability is
  absent."
- V7 §6.8 — "Propagated caller capability is not a dispatch gate
  (normative)" — caller_capability is for (a) voluntary caller-path
  checks the handler performs and (b) history attribution only.

**Discovery path:** RoleOps tests failed 403 on define/assign/
re-derive/delegate. Initial read framed it as a deferrable gap; on
closer reading of V7 §6.5/§6.8 + workbench-go (the blessed
convergence reference), the answer was a tiny SDK
layer addition. The role wrapper's behavior was correct; the SDK
was missing one piece.

---

## EXTENSION-REVISION fetch-diff D4: Rust rejects cross-peer; Go SDK Reconcile requires it

**Spec passage** (PROPOSAL-CONVERGENT-MIRRORING §2.3 D4, also surfaced
in `extensions/revision/src/lib.rs:2484` rationale):
> "this op reads receiver-local state (self.local_peer_id's head);
> if invoked cross-peer it would return the executor's diff, not the
> caller's — the trap that sank the original
> PROPOSAL-REVISION-DIFF-SINCE-LOCAL-HEAD POC. Reject inbound wire
> dispatch with `400 invalid_dispatch`."

**Rust impl:** the handler rejects any `ctx.is_external` invocation
with 400 `invalid_dispatch`. Local internal sub-dispatch is fine
(SDK's `PeerContext::execute` doesn't set is_external, so the
wrapper added in commit c0508e5 works for local fetch-diff).

**Go SDK collision (workbench-go reconcile.go:79):**
`ReconcileSinceLastSeen` wraps the documented `revision:fetch-diff +
tree:merge` chain — and **requires** cross-peer fetch-diff to do its
job:

```go
envEnt, err := a.RevisionAt(remotePeerID).FetchDiff(ctx, types.RevisionFetchDiffParamsData{
    Prefix: prefix,
    Base:   lastSeen,
})
```

A is asking B for B's diff so A can merge into its local prefix. Under
the Rust D4 rule this call returns `400 invalid_dispatch` from B,
making `ReconcileSinceLastSeen` unimplementable in Rust as Go shaped
it.

**Tension:**
- The Rust rule's stated reason (returning the executor's diff when
  the caller expected their own) is real for the **naive** cross-peer
  use — but Reconcile is the **intentional** opposite: the caller
  explicitly wants B's perspective so they can apply B's state.
- The D4 prose forbids "cross-peer dispatch" categorically when the
  legitimate use case is "cross-peer dispatch from a caller who
  understands the receiver-local-state semantics."

**Interim choice (Rust SDK):** the `RevisionOps::fetch_diff` wrapper
landed in c0508e5 is local-only (matches the handler's current
behavior). `ReconcileSinceLastSeen` is **deferred** from Ask 4 until
this tension resolves. Three plausible resolutions:

1. **Relax D4 to allow cross-peer fetch-diff** when the caller
   passes an explicit `target_peer_id` field (signals "I know I'm
   asking for receiver-local state on purpose"). Matches Go's
   current behavior.
2. **Replace fetch-diff with a different op for Reconcile** — e.g.,
   `fetch-since` whose contract is "the executor's perspective is
   what you want." Go's reconcile call site updates; D4 stays.
3. **Compose at a higher layer** — fetch-diff stays local-only;
   Reconcile becomes `(remote.commit_log_walk + fetch_entities)` or
   similar. Substantial spec redesign.

Cross-impl conformance currently diverges silently: Go reconcile
works against Go peers; against a Rust peer the call would 400.
Worth pinning before two-impl prod deployments rely on it.

---

## RestorePriorSubscriptions depends on missing SubscribeAt (cross-peer subscribe wrapper)

**Status (during Ask 4 push):** Go SDK has both pieces
(`workbench-go/entitysdk/subscription_restore.go:109` enumerates +
re-issues; `SubscribeAt` is the cross-peer wrapper it composes on).
Rust SDK has only the local subscribe surface
(`bindings/sdk/src/subscription.rs::subscribe_with_options`); there
is no cross-peer subscribe wrapper, no tracking-sidecar write on
subscribe-success, no tracking-sidecar removal on unsubscribe.

**Why this is a non-trivial follow-up:** RestorePriorSubscriptions is
the thin enumerate-and-re-issue layer (~150 LOC), but it requires
~300+ LOC of prerequisite work first:

1. **SubscribeAt** — cross-peer subscribe wrapper. The existing
   `subscribe_internal` does (a) register a local delivery handler,
   (b) mint a delivery grant, (c) dispatch the subscribe op locally.
   The cross-peer variant routes (c) to
   `entity://{remote_peer_id}/system/subscription:subscribe` and
   ensures the delivery grant + return path is reachable from the
   remote.
2. **Tracking sidecar** — on cross-peer subscribe success, write
   `sdk/subscription-tracking/{id}` capturing `{remote_peer,
   pattern, events, include_payload}`. Not part of the V7 protocol
   surface — workbench-side state per Go's
   `subscriptionTrackingPrefix = "sdk/subscription-tracking/"`. On
   subscription handle drop / explicit unsubscribe, remove the
   sidecar so explicit cancellations don't auto-restore.
3. **RestorePriorSubscriptions** — list the prefix, decode each
   sidecar, re-issue via SubscribeAt, swap the old sidecar path
   for the new id (new SubscribeAt writes a fresh tracking entry).

**Spec authority:** EXTENSION-SUBSCRIPTION v3.15 §5.7 places
"subscriber-side restoration" at the application/SDK layer, not in
the substrate. So the Rust SDK needs to provide this as a wrapper
chain — there's no handler-side help coming. Matches Go's design.

**Not blocking:** the entity-browser-rust consumer-side validation doesn't drive
RestorePriorSubscriptions today (Gap 5 is the persistence concern,
not the restore concern). When subscription-restoration becomes a
real consumer requirement, the implementation order is SubscribeAt
→ tracking → restore, and the substrate boundary stays exactly
where Go put it.

---

## IdentityBundle: Go filesystem-shape vs entity-browser-rust entity-shape cross-impl divergence

**Discovery context:** Implementing Ask 4 IdentityBundle per
the entity-browser-rust IdentityBundle position paper.

The two implementations have fundamentally different abstractions
for what an IdentityBundle is, and the entity-browser-rust position paper
explicitly asks core-Rust to "coordinate with workbench-go on the
field set so their existing bundles can round-trip." The two shapes
do not currently round-trip.

### Go shape (filesystem-oriented)

`entity-workbench-go/entitysdk/identity_bundle.go::IdentityBundle`
contains:
- `SchemaVersion`, `Name`, `CreatedAt`, `QuorumName` (metadata)
- `QuorumID`, `ControllerCertHash`, `Threshold` (verification pins)
- `ControllerKeypair` (the local peer's keypair)
- `QuorumMembers []Keypair` (the quorum constituent keypairs)

**Reload model:** `ApplyIdentityBundle` re-runs
`runBootstrapCeremony` with the loaded keypairs to **re-mint** all
entities (quorum, controller-cert, signatures, peer-config) from
scratch. Ed25519 is deterministic per RFC 8032, so the recomputed
content hashes match the manifest's pinned hashes — that's the
integrity check. The bundle ships only *keypairs + a manifest*; the
entities themselves never travel.

### entity-browser-rust position-paper shape (entity-oriented)

The entity-browser-rust IdentityBundle position paper proposes:
- `identity_hash: Hash`
- `keypair_pem: String` (caller's keypair)
- `identity_entity: Entity`
- `quorums: Vec<Entity>`
- `attestations: Vec<Entity>`
- `signatures: Vec<Entity>`
- `label`, `properties`

**Reload model:** `restore_from_bundle` writes the entities
directly into the content store + binds them at canonical paths,
then dispatches configure to issue the local-peer cap. No ceremony
re-run — the entities themselves are the portable artifact.

### Why this matters

The entity-browser-rust side wants entity-oriented because:
1. Browser WASM consumers don't have filesystems for keypair
   directories — they store one CBOR blob in OPFS/IndexedDB.
2. Quorum members on different peers can't have their keypairs
   shipped (custody concern §8.2); the entity-oriented bundle
   carries the *signatures* instead, which is what the verifier
   actually needs.
3. Multi-signer quorums where the SDK never had the member
   keypairs (signatures came from other peers) can still be
   exported.

The Go side has the filesystem layout because:
1. Workbench is a desktop daemon — filesystem is native.
2. Deterministic re-mint is a clean integrity check (any drift
   in the bootstrap code = hash mismatch caught at load).
3. Reloading the same keypair into a fresh peer literally re-
   creates the same identity, which is the spec's intent.

Both shapes are internally coherent; they're optimized for
different constraints.

### Cross-impl portability gap

Bundle bytes produced on one side cannot currently round-trip to
the other:
- A Go-produced bundle (keypairs only) can't be loaded into a
  Rust SDK using the entity-shape — the Rust side would need to
  re-run the ceremony with the keypairs to reconstruct entities,
  which is what Go does internally. So the Rust SDK would need
  *both* an "entity bundle" path *and* a "keypair bundle ceremony
  re-run" path to be truly cross-impl.
- A Rust-produced bundle (entities only) can't be loaded into the
  Go SDK at all without a Go-side adapter that writes the entities
  to the content store directly, bypassing `ApplyIdentityBundle`.

### Interim implementation choice

**Ship the entity-shaped bundle per the entity-browser-rust position paper.**
Reasons:
1. The consumer (entity-browser-rust) explicitly drove this surface and is
   committed to consuming whatever lands.
2. The entity-shape covers the multi-signer custody case that
   Go's keypair-shape cannot.
3. Per the position paper §"Coordination": "If workbench-go can't
   easily refactor their existing layout, fine — the abstract
   Bundle ships independently; workbench-go's existing filesystem
   layout becomes 'the workbench-go consumer's storage helper'
   wrapping the same abstract Bundle bytes." Backwards-compatible
   on the Go side; Go can add an entity-bundle adapter later.

**Cross-impl deferral:** the Rust SDK ships entity-bundle CBOR
serde + `IdentityOps::export_bundle()` + `restore_from_bundle()`
now. Cross-impl round-trip with workbench-go is **not** claimed
until Go adds the corresponding entity-bundle path.

**Open for architecture decision:** is "entity-shape" or
"keypair+ceremony-shape" the canonical cross-impl bundle? The
spec (`SDK-IDENTITY-INFRASTRUCTURE` §8.4 covers the filesystem
layout but is silent on the cross-impl portable wire shape) needs
to pin one or the other.


---

## CONTENT-SUBSTITUTE-SOURCES §2.5 consult-cap on the 4D grant axis

`PROPOSAL-CONTENT-SUBSTITUTE-SOURCES.md` §2.5 specifies
`system/capability/content-substitute-consult` as an in-process cheap
pre-flight cap gating whether the substitute chain is consulted at all
(MUST). The cap path is a substrate-level identifier under the
`system/capability/*` namespace.

V7's 4D `GrantEntry` model has axes `{ handlers, resources, operations,
peers, ... }`. None of these axes is "capability path." Two faithful
readings:

1. **Handlers-axis encoding.** A grant that includes the path
   `system/capability/content-substitute-consult` in its `handlers`
   include list is treated as conveying the cap. Misuse of axis intent
   (handlers is for dispatch patterns, not cap path).
2. **New `caps` axis.** Extend `GrantEntry` with a `caps: PathScope`
   field whose values are cap paths. Clean axis-of-intent but a wire
   shape change.

The proposal doesn't say. core-go's substrate review of the W2 proposals
flagged the analogous question for REGISTRY's `registry-resolve` cap.

### Rust interim choice

**v1 ships with default-permit posture.** The substitute miss-hook is
offered to the resolver only when the caller has any capability token at
all; absence of a token denies. Strict per-cap enforcement deferred until
arch pins the axis. Logged so the cap surface doesn't silently land as
permissive-forever.

Source surface: `extensions/content/src/handler.rs::caller_has_consult_cap`.

### RESOLVED — named-capability-mapping ruling

Arch closed both faithful readings with a third: **named caps reduce to
the existing 4-axis grant model.** No new mechanism; no fifth `caps`
axis; the cap-path string is impl shorthand only. Concretely, every
`system/capability/{name}` gate maps to a `(handler, operation)` pair
checked by V7 §5.2 `check_permission`; per-cap narrowing lives in the
grant's `constraints` map (byte-equal under delegation per V7 §5.6);
**absent or non-matching grant → deny (fail closed)**.

Worked mapping for this cap:

| named cap | handler | operation | constraints |
|---|---|---|---|
| `content-substitute-consult` | `system/substitute/sources` | `consult` | `source_peer_id?`, `substitute_types?` |

Rust impl landed in transport-family Chunk B: the substrate
(`ChainConsultHook::consult`) now calls `entity_capability::
check_permission(consult, /{local}/system/substitute/sources, local,
resource_target, caller_cap, local)`. CONTENT no longer carries a
permissive `is_some()` helper; it plumbs through
`ctx.caller_capability` + `ctx.resource_target`. Tests cover
absent-token / wrong-handler / wrong-op / resource-outside-scope each
denying. The same mapping applies to `registry-resolve` →
`(system/registry, resolve)` and (erratum-tier) `bridge-http-fetch` →
`(system/bridge/http, get)` per ruling §4 — neither is on Rust's v1
critical path.

---

## V7 §6.2 capability handler — A1..A5

**Trigger.** Implementing `extensions/capability/` (Resolution B per
the capability-handler advertisement ruling) surfaces the same
five under-specified surfaces Go logged in
`entity-core-go/docs/archive/validation/spec-issues/
the capability-handler ambiguities log. Our impl picks match Go's
for cross-impl interop; each entry below names our position so the
record is on both sides.

### A1 — SHOULD vs default-grant tension

**Spec passage (V7 §6.2:2516):**

> Implementations MUST provide the tree, handlers, and connection
> handlers. Implementations SHOULD provide the capability handler.

**But** V7 §4.4 puts `system/capability:request` in
`default_connection_grants`. Advertising a grant for a SHOULD handler
turns the advertisement into a contract callers will exercise — exactly
the defect Godot caught.

**Our impl choice (Resolution B).** Register the handler at
`system/capability` and keep the grant in `default_connection_grants`.
This satisfies V7 §6.2 SHOULD and the ruling's discipline pin
("advertised SHALL only reference registered") in a single config; the
two stay in lockstep via the `capability-handler` feature in core/peer.

**For arch.** Three viable resolutions; pick one:
- **A1.a — Promote §6.2 to MUST.** Reflects what §4.4 already implies
  in practice. Cleanest. Matches Go's stated preference.
- **A1.b — Keep SHOULD; drop from default grants.** Make the
  advertisement conditional on registration. Matches Rust's pre-impl
  posture and the ruling's *recommended* Resolution A.
- **A1.c — Codify the discipline pin into the spec.** "An advertised
  grant SHALL only reference handlers registered on this peer at
  connection time." Pins discipline general-case; leaves §6.2 SHOULD;
  consistent with both impl postures.

Rust's lean: **A1.a** for cross-impl interop simplicity. Once the
handler is normative MUST, validate-peer harnesses (Go's
`expectedHandlers`) can assert presence unconditionally without the
adverse-conditional-skip the current SHOULD framing requires.

### A2 — `request` default policy

**Spec passage (V7 §6.2:985):** "evaluates the request against the
peer's configured policy and returns a `system/capability/grant`".
"Configured policy" is undefined; no default.

**Our impl choice.** Same as Go: **attenuate from the caller's
authenticated grant.** The request handler verifies
`is_attenuated(child={request.grants, …}, parent=caller_capability)`
using the existing §5.2 `matches_scope` machinery. Cannot widen.

**For arch.** Pin in §6.2: "Absent a configured policy, `request` MUST
return a token whose grants are a subset (per `matches_scope`, §5.2) of
the caller's authenticated capability." This is the only
privilege-escalation-safe default and composes cleanly with
EXTENSION-ROLE policies (which can deny / narrow further on top).

### A3 — revocation storage path

**Spec passage (V7 §6.2):** "MAY write to a revocation list at
`system/capability/revocations/*` (implementation-specific)."

**Our impl choice.** Same as Go:
`system/capability/revocations/{token-hash-hex}`, entity type
`system/capability/revocation` carrying `{token, reason?, revoked_at}`.
Path is *peer-qualified* on the wire
(`/{peer_id}/system/capability/revocations/{hex}`) per V7 §6.5
invariant-pointer semantics; the bare form in spec text is shorthand
for the per-peer namespace.

**For arch.** Pin the path scheme as normative. Cross-peer chain
validation that needs to walk revocations otherwise breaks on impls
that pick different schemes — the substrate primitive is only useful
if the path shape is identical across peers.

### A4 — `delegate` input shape

**Spec passage (V7 §6.2:2503-2509):** `delegate: { input_type:
"system/capability/token", output_type: "system/capability/grant" }`.
"Input is the parent token" — but the caller needs a slot for the
*attenuated child scope* and the spec defines none.

**Our impl choice.** Same as Go (interpretation D3-ish): on the wire
the manifest's `input_type` is the canonical `system/capability/token`
for forward compatibility, but the params we actually accept are a
`system/capability/request` (same shape as `request`) carrying the
desired child grants, and the **parent hash rides in the
`resource_target`** as `system/capability/grants/{parent-hash-hex}`.
Handler walks: load parent from store, verify type, verify peer-issued
(`granter == identity_hash`), validate attenuation, mint child with
`parent: Some(parent_hash)`.

**For arch.** Two viable fixes:
- Define a richer dedicated type: `system/capability/delegate-request
  := { parent: hash, grants: [grant-entry], ttl_ms?: uint }` and pin
  it as `input_type`.
- Or document the convention used here (request shape in params +
  parent in resource) as normative.

Either is fine; the current spec doesn't even tell a reader where the
attenuation lives, which is the actionable gap.

### A5 — `request`/`delegate` result envelope

**Spec language:** `output_type: system/capability/grant`,
`grant := { token: hash }`.

**Gap.** Result is a 1-field wrapper. Where does the actual token
entity live so the caller can use it?

**Our impl choice.** Same as Go: **`included`-map (E1).** The
handler emits `system/capability/grant {token: <hash>}` as `result`
and the response envelope's `included` carries the token entity, its
signature entity, and the granter identity entity (so cross-peer chain
verification can resolve all three without follow-up tree:get calls).
No tree writes from `request`/`delegate` (matches V7 §6.2:2544
"returns tokens inline").

**For arch.** Pin in §6.2: "The result envelope's `included` MUST
carry the issued token entity and its signature; MAY carry the
granter identity entity." Without this pin, callers can't safely
distinguish "token doesn't exist locally because the issuer hasn't
mirrored it yet" from "this impl wrote it to the tree and you need to
fetch it" — two completely different recovery paths.

### Cross-refs

- Architecture ruling that triggered Resolution B:
  the architecture team's capability-handler advertisement ruling.
- Go's parallel log (identical findings, picks aligned):
  the Go team's capability-handler ambiguities log.
- Our impl: `extensions/capability/src/lib.rs` (8/8 unit tests cover
  attenuation, delegation, revocation, and the negative cases for
  scope/parent/granter mismatch).

**RESOLVED — V7 v7.62 amendment landed (arch commit 4b82043).**
All five A1..A5 ambiguities resolved by `PROPOSAL-V7-CAPABILITY-HANDLER-
AMENDMENT.md`:

- **A1 → A1.a**: §6.2 promoted to MUST (capability handler is now a
  conformance MUST). Removes the SHOULD-vs-advertisement tension entirely.
- **A2 → spec-pinned**: §6.2 "Evaluation contract for `request`" pins the
  subset-validation against BOTH caller's auth cap AND matched policy
  entry; pure-attenuation flow works without policy entry by skipping
  the policy ceiling.
- **A3 → spec-pinned**: §3.6 + §6.2 universal-revocation-entry-point. The
  marker entity (`system/capability/revocation`) is **distinct from the
  input type** (`system/capability/revoke-request`) — input is `{token,
  reason?}`, marker is `{token, reason?, revoked_at}`. Path is
  normatively `system/capability/revocations/{cap_hash_hex}` (peer-
  qualified locally per §6.5 invariant-pointer semantics).
- **A4 → A4.a (richer dedicated type)**: §3.6 pins
  `system/capability/delegate-request := {parent, grants, ttl_ms?}` as
  input_type — parent moves off the resource_target and into params.
  Self-attenuation only: `grantee = caller's authenticated identity
  always`. Auth check is `parent.grantee == caller's authenticated
  identity` (direct hold, not chain-walk).
- **A5 → spec-pinned**: §6.2 result-envelope MUST carry the issued token
  entity + its signature entity + the granter identity entity; MAY carry
  the full authority-chain bundle for cross-peer use; SDKs targeting
  cross-peer dispatch SHOULD include the chain by default.

**New surfaces in v7.62 also implemented this pass:**

- **`configure` operation** (V7 §6.2 manifest): accepts
  `system/capability/policy-entry`; writes at
  `system/capability/policy/{peer_pattern}` where `{peer_pattern}` is the
  literal `default` (closeout F8 — see below) or a 66-hex peer-identity
  hash (partial prefixes MUST be rejected — done).
- **501 unsupported_operation**: distinct from 404/403 per §6.2 status-code
  table. Rust returns 501 for unknown ops on registered handler.
- **§4.4 union**: at authenticate-response, the connect handler unions
  the SHOULD floor with any matched `system/capability/policy/{peer_hex}`
  entry (fallback to `default`). Conditional on capability handler being
  registered.

### v7.62 closeout amendments landed (F1, F2, F8)

`PROPOSAL-V7-CAPABILITY-HANDLER-CLOSEOUT-AMENDMENTS.md` (awaiting arch
ratification). Rust implements all three;
Rust-seat concur memo filed at
the Rust V7 capability-handler closeout response.

- **F1 — `delegate` scoped to same-peer-only.** The C1 chain-link gap
  (logged previously: cross-peer self-attenuation produces a chain
  `parent.grantee = remote ↔ child.granter = local` that fails §5.5
  verification because the handler signs with the local keypair) is
  resolved by scoping: v1 enforces `caller == local_peer` and returns
  **501 unsupported_operation** for cross-peer callers. Implemented at
  `extensions/capability/src/lib.rs::handle_delegate` (the first branch).
  Cross-peer self-attenuation moves to the client (construct + sign the
  child locally). The closeout proposal §2.5 flags an open question on
  whether `delegate` earns its keep as a wire op at all (deferred,
  follow-up cycle).

- **F2 — `is_revoked` wired into `verify_request` (MUST when
  `supports_revocation = true`).** v7.62's marker mechanism is
  operationally inert unless verify reads it. Rust now ships a
  `VerifyContext { local_peer_id, supports_revocation }` + a
  `verify_request_with_ctx` variant that runs §5.2 Step 4 on every
  capability presented for verification. `core/peer/src/connection.rs`
  uses `supports_revocation = true` (Rust ships the full marker
  mechanism). Closures are: store-first-then-included `resolve`,
  location-index `locate`, and `capability_path_for_scan` over the
  location index (Rust uses the §5.1 MAY-level scan fallback; a future
  reverse-index optimization is straightforward). Surfaces as new
  `ProtocolError::CapabilityRevoked → 403` (matches Go's
  `revoked_cap_denied_on_use` matrix vector; same family as
  `CapabilityExpired`, NOT `UnresolvableGrantee`/401 — initial Rust
  pick was 401 on faulty analogy; corrected after Go
  matrix flagged the divergence).

- **F8 — `system/capability/policy/{peer_pattern}` fallback segment
  renamed from `*` to `default`.** In v7.62 the literal segment was `*`,
  which collided with `*`-as-glob everywhere else in V7 (resource
  patterns, grant-entry wildcards, free-text path globs). Renamed to
  `default` — unambiguous, cannot collide with a 66-hex peer-ID. Single
  source of truth at `entity_capability::POLICY_FALLBACK_SEGMENT` (re-
  exported from the handler crate); used at the handler's `configure`
  validation, the handler's policy-lookup fallback, and `core/peer`'s
  §4.4 connection-time policy reader.

## `system/revision/commit-result` field names: protocol spec vs SDK spec contradict

**Type:** spec-vs-spec contradiction (two architecture documents disagree on a
wire shape). Surfaced by the cross-impl validate-peer matrix
(the Go cross-impl conformance matrix
§2.3, `commit_version_nonzero` + ~62 cascade failures).

**The two passages.**

- **Protocol domain — EXTENSION-REVISION §4.3.1 (line 699):**
  ```
  return {type: "system/revision/commit-result",
          data: {version: version_hash, root: trie_root_hash}}
  ```
  Field **names** are `version` and `root` (values are the version-entry hash
  and the trie-root hash). The merge-result is consistent: §4.3.4 line 863
  returns `{status: ..., version: ...}`.

- **SDK domain — SDK-EXTENSION-OPERATIONS §4 (lines 276-277, 314):**
  ```
  version_hash: hash    ; Hash of the new version entry
  trie_root:    hash    ; Root of the snapshot trie
  ```
  Field names are `version_hash` and `trie_root`; merge there also uses
  `version_hash`.

**Impact.** Go and the conformance oracle decode per the protocol-domain spec
(`version`/`root`). Our prior "G5" change (commit `2dacb9c`) re-shaped the Rust
emitter to the SDK-domain names `{version_hash, trie_root, parent?}` — which
made every Rust commit read as a *zero* version hash on the oracle (absent
`version` key), and because the whole revision suite gates downstream checks on
a successful commit (`v1_hash` is only stored on commit pass), this single
field-name divergence cascaded to ~62 revision failures. Note the values were
always computed correctly — this was purely a wire-key-name regression, not a
logic bug.

**Our interim choice (this commit).** Reverted the Rust commit-result to the
protocol-domain names `{version, root}` — emitter, SDK decoder, the
`system/revision/commit-result` type schema, and three unit tests. Rationale:
EXTENSION-REVISION is the **handler's own wire spec** and is authoritative for
the result-entity shape; SDK-EXTENSION-OPERATIONS is an SDK-domain *descriptive*
document and its `_hash`/`_root` suffixes read as prose labels, not wire keys.
This also restores cross-impl conformance with Go + the oracle. Also dropped the
G5 `parent` field — §4.3.1 does not define it (extra, undefined wire key).

**For arch (the actionable ask).** Reconcile the two documents so a peer author
reading either lands on the same wire shape. Recommended: correct
SDK-EXTENSION-OPERATIONS §4 to `version`/`root` to match EXTENSION-REVISION
§4.3.1, OR (if the intent really is to migrate the wire to `version_hash`/
`trie_root`) amend EXTENSION-REVISION + the oracle + Go together and re-issue as
a coordinated wire break. The current state — protocol spec and SDK spec naming
the same wire field differently — will keep biting every new peer generated from
these docs, which is exactly the "what's spec vs impl" risk the conformance
program exists to catch.

**Cross-refs.**
- Authoritative: EXTENSION-REVISION §4.3.1 (line 699), §4.3.4 (line 863).
- Contradicting: SDK-EXTENSION-OPERATIONS §4 (lines 276-277, 314).
- Regression introduced: commit `2dacb9c` ("G5"); reverted here.
- Our impl: `extensions/revision/src/lib.rs` (commit emitter),
  `bindings/sdk/src/revision.rs` (`decode_commit_result`),
  `core/types/src/core_types.rs` (`system_revision_commit_result`).

## ~~9 conformance-tested type defs: 3 field disputes resolve per spec; 3 types live only in proposals~~ CLOSED (arch ruling `e748be4` R1+R2; conformance green, no impl change)

**Type:** (a) cross-impl field-type disputes the spec actually settles, plus
(b) a process gap — the conformance suite tests types that are not yet in a
ratified spec. Surfaced by validate-peer matrix §2.1. Rust is missing all 9
type definitions (404 on fetch); this entry is the arch-facing analysis, not a
registration (see disposition).

**The 9 types and where they're DEFINED:**

| Type | Defining doc | Ratified? |
|---|---|---|
| `system/peer/transport/http-poll` | EXTENSION-NETWORK §6.5.3 (L895-925) | ✅ published spec |
| `system/type/{adopt,converge,reconcile}-request`, `reconcile-result` | EXTENSION-TYPE §7.4-7.6 (L879-982) | ✅ published spec |
| `system/substitute/endpoint` | RULINGS-STORAGE-SUBSTITUTE (R1) + PROPOSAL-…-HTTP | ⚠️ proposal/ruling only |
| `system/substitute/snapshot-manifest` | PROPOSAL-…-STORAGE-SUBSTITUTE-HTTP L78-92 | ⚠️ proposal only |
| `system/substitute/source` | PROPOSAL-…-STORAGE-SUBSTITUTE-SOURCES §2.1 | ⚠️ proposal only |
| `system/substitute/try-request` | PROPOSAL-…-SOURCES §2.3 + RULINGS R2 | ⚠️ proposal/ruling only |

**The 3 disputed fields — the spec settles all three (do NOT "match Go"):**

1. **`http-poll.peer_id`** → `system/peer-id` (EXTENSION-NETWORK §6.1 L69),
   not `primitive/string` and not `system/hash`. Python's `primitive/string`
   is wrong.
2. **`substitute/source.priority`** → `primitive/int` (SOURCES §2.1 L59:
   "ascending; lower = consulted first"). NETWORK Amendment 8's `uint` (L729)
   is for **live transport profiles**, a *different* entity type — it does not
   reach `substitute/source`. Python's `uint` is wrong **unless** arch
   deliberately extends Amendment 8 to substitute sources (open question →
   arch).
3. **`substitute/try-request.entry`** → the **full** `system/substitute/source`
   entity (`core/entity`), per SOURCES §2.3 L131 + RULINGS R2 ("the full
   source entity, NOT its hash"). Python's `primitive/any` is too loose;
   `core/entity` is the precise type.

**The process gap (the part that matters for "what belongs in the spec").**
Four of the nine types the conformance suite gates on
(`substitute/{endpoint,snapshot-manifest,source,try-request}`) are defined
**only in proposals + a cross-impl ruling**, never lifted into a published,
ratified spec. The suite is therefore asserting conformance against
pre-ratification shapes. This is exactly the failure mode the conformance
program exists to prevent: a "MUST register type X" with shape Y, where Y has
never been pinned anywhere a peer author would look. It is also why the cohort
disagrees on `priority`/`entry` — each impl read a different proposal draft.

**Disposition (Rust).** **Not registering these 9 in Rust this session.**
Registering proposal-stage shapes would (a) bake in a shape arch may revise on
ratification and (b) risk minting a *fourth* divergence on the disputed fields.
Per impl-role boundaries, type-definition field shapes are protocol-design
decisions, and the matrix itself routes §2.1 "to arch first to confirm the
canonical field types." This entry is that confirmation request.

**For arch (actionable).**
1. Ratify the `system/substitute/*` family into a published spec (lift from
   PROPOSAL-…-STORAGE-SUBSTITUTE-{HTTP,SOURCES} + the cross-impl rulings), with
   the three disputed fields pinned as resolved above — OR scope these four
   types out of the conformance suite until ratified.
2. Confirm `substitute/source.priority` signedness: `int` (per SOURCES §2.1, my
   reading) vs `uint` (if Amendment 8 is meant to generalize). One line in the
   ratified spec closes it.
3. Once ratified, Rust registers all 9 (substitute family in
   `extensions/storage-substitute-*`, type-analysis family in
   `extensions/type-system`, http-poll in the network/types layer) in one pass.

**Cross-refs.** Matrix §2.1; EXTENSION-NETWORK §6.5.3/§6.1; EXTENSION-TYPE
§7.4-7.6; PROPOSAL-EXTENSION-STORAGE-SUBSTITUTE-{HTTP,SOURCES};
the cross-impl storage-substitute rulings (R1, R2).

**RESOLUTION (later same day) — registered.** The two gating
rulings landed, so the prior "not registering this session" disposition is
superseded: A-F1 via arch errata `bdfb545` ("NETWORK §6.5.1 profile peer_id
Hash→system/peer-id") pins `http-poll.peer_id = system/peer-id`; A-F2 via
RULINGS R2 pins `try-request.entry = system/substitute/source` (the **full
source entity**, NOT the looser `core/entity` my earlier reading above
proposed — Go converged to the precise type in `1034f82` and is the validator
reference). All 9 types are now registered in `core/types/src/core_types.rs`
(centralized, matching Go's single `RegisterCoreTypes` pathway — the existing
`system_revision_*` extension types already live there). Field shapes match
Go's converged registration, verified field-by-field and **proven over the
wire**: `validate-peer -category type_system` against a live Rust peer →
291 pass / 5 warn (all pre-existing open-type-tolerable) / **0 fail**, all 18
new-type checks (9 × fetch+match) PASS, `types_all_present` PASS. Disputed
fields landed as: `peer_id=system/peer-id`, `source.priority=primitive/int`,
`try-request.entry=system/substitute/source`, `source_peer_id=system/hash`.

**~~Still open for arch (the substantive asks survive registration):~~ CLOSED — both asks ruled.**
Architecture ruled both asks in the cycle-closeout-0.3 ruling (arch
commit `e748be4`, ratified — ancestor of arch master). Verified against the
ruling text; no Rust impl change required (both already converged):

- **Ask #1 — substitute family: R1 DESCOPE (do not ratify this cycle).** The
  family stays proposal-stage by design — ratification is W3 CDN-corridor
  release work on its own track, deliberately not folded into a peer-cleanup
  cycle (same discipline that keeps the capability amendment separate). The
  cohort **keeps** its implementations (all three converged on the ruled shapes,
  so eventual ratification is mechanical, not wasted); `validate-peer` substitute
  categories are **marked provisional / proposal-stage — NOT part of the
  ratified-core conformance floor** (V7 §2.11 / GUIDE-CONFORMANCE §7). The ruling
  explicitly names this as resolving "Rust's process-gap finding": answer is
  *descope + mark-provisional*, not *ratify-mid-cycle*. **Rust action: none** —
  the four `system_substitute_*` builders stay registered to the ruled shapes;
  if the CDN-corridor track revises a shape on ratification they update in one
  pass (carries its own conformance regen).
- **Ask #2 — `source.priority`: R2 `int` confirmed (no change).** SOURCES §2.1
  L59 pins `priority: int` ("ascending; lower = consulted first"); Python's
  earlier `uint` was the divergence and has converged to `int`. NETWORK
  Amendment 8's `priority: uint` (§6.5.1 L729) is a *different field on a
  different entity* (live transport profiles) and does not generalize. Rust
  registered `primitive/int` (`core_types.rs` `system_substitute_source`) →
  **correct, confirmed.** (Zero wire impact — all real priorities ≥ 0, so
  canonical bytes are identical either way; this was a type-declaration
  confirmation only.)

**Net: this entry is fully closed.** Conformance green (291/5-warn/0-fail), impl
matches the ratified rulings, and the two arch asks are adjudicated. No further
action on either side.


---

## V7.67 PHASE-2 BYTE-PIN COHORT — empty scope `include` encodes as `[]` not `null`

> **RESOLVED — RULED in Rust's favor.** Architecture ruling
> the empty-scope-include ruling: an unconstrained scope
> dimension is **present-with-empty-`include`** (`{include: []}` → `0x80`), NOT
> `{include: null}` (`0xf6`) and NOT absent. No spec change — both halves were
> already bound by existing normative text (ENTITY-CBOR-ENCODING §232 forbids
> field drop; V7 §3.6 `list_of(pattern)` typing excludes `null`). This answers
> BOTH questions below: (1) `[]` is the canonical form (Go's `null` was an
> fxamacker `[]string(nil)` artifact, fixed at `core/types/system.go`
> `3cfb353`); (2) present-with-empty, never absent. 3-way green: Go `3cfb353` ×
> Rust `d38d1f8` × Python `a2463be`, byte-equal on all 7 gates × M2/M3/M6 ×
> `.cbor` sha256. Rust's `0x80` was correct from the start — no impl change. The
> stale `.cbor` was regenerated from the folded `.diag` at F16 close
> (`8e7c5232…f31f982e`). Original surfacing report retained below.

Surfaced running the Phase-2 matrix byte-pin round-trip (SEEDS.md §5 step 3)
in `core/peer/tests/cohort_compare_v767_phase2.rs` against the Go cohort pins
(the V7.67 phase-2 byte-pins cohort record).

**§7 gates 1–4 (peer-identity layer) converge byte-for-byte Rust ↔ Go** on all
three vectors (pubkey, peer_id, `system/peer.data` CBOR, home-format
content_hash — including the SHA-384 home cases M3-A / M6-A). **Gates 5–7
diverge** (cap-token CBOR → content_hash → signature), isolated to one cause
repeated across M2/M3/M6.

**Passage / shapes:** the matrix cap's `GrantEntry` (SEEDS.md §2.3) constrains
only `resources`; `handlers` and `operations` are unconstrained. Their
`include` (a `list_of: pattern` field, V7 §3.6) is a zero-element list.
- Rust emits `{include: []}` → `a1 67696e636c756465 80`.
- Go's pins emit `{include: null}` → `a1 67696e636c756465 f6`.

**Why Rust holds (not arbitrary):** the locked v1 ECF corpus pins these as
DISTINCT canonical forms — `length.1` empty array → `h'80'`, `primitive.1`
null → `h'f6'` (`ecf-conformance/conformance-vectors-v1.diag`), and
ENTITY-CBOR-ENCODING §232 forbids dropping fields. An empty `list_of` value is
`0x80`; `0xf6` (null) is a different value. Go's `f6` is a
`[]string(nil) → CBOR null` serialization artifact of its `GrantEntry`, not a
spec mandate. SEEDS.md §7 names the spec/SEEDS the arbiter, not Go.

**Why it stayed latent:** handshake caps are each self-signed by the minting
peer and verified against received bytes (byte-fidelity, never re-encoded
cross-impl). The byte-pin round-trip is the first surface forcing independent
re-derivation of the same logical cap by two impls. `default_connection_grants`
in Rust already emits `resources: {include: []}` today — interop never broke
because nobody re-encodes a peer's self-signed cap.

**Interim choice:** Rust keeps `0x80`. The Phase-2 test pins Rust's
spec-correct cap-token CBOR / content_hash / signature (peer-layer constants
remain Go's verbatim — they match). Full cap-layer convergence + corpus lock
wait on Go regenerating its pins with `0x80`.

**For architecture (decision needed before the Phase-2 `.diag` fold, SEEDS §5
step 4):**
1. Confirm empty scope `include` canonicalizes to `[]` (`0x80`), making Go's
   `null` pins the ones to regenerate. (Rust + the locked corpus say yes.)
2. SECONDARY (non-blocking, neither impl exercises it today): should a fully
   unconstrained scope dimension be ABSENT entirely (`handlers`/`operations`
   keys omitted, grant = `{resources: {…}}`) per the §1.8 "optional fields
   SHOULD be absent" guidance, rather than present-with-empty-`include`? If so
   that is a third encoding distinct from both impls and a wire-affecting
   GrantEntry canonicalization change across all three SDKs — wants an explicit
   ruling, not silent per-impl drift.

---

## V7.72 CORE-PROFILE COHORT CLOSEOUT — §1.4 path control-char rejection: spec text says "null bytes", cohort floor rejects all C0+DEL

**Passage:** V7 §1.4 (line 370): *"All other UTF-8 characters are valid in path
segments. Paths MUST NOT contain null bytes. Paths MUST NOT contain empty
segments (consecutive `/` separators)."* And §9.5a `CORE-TREE-PATH-FLEX-1`:
*"reject null byte (400)"* — singular.

**Ambiguity:** The normative text mandates rejecting **only** null bytes, and
explicitly says "All other UTF-8 characters are valid." A C0 control byte
(`0x01`–`0x1F`) or DEL (`0x7F`) is, by the letter of §1.4, a valid path-segment
character. But the Go reference's v7.72 fix added `ValidatePathChars` rejecting
the full `0x00`–`0x1F` + `0x7F` range, and the cohort punch list
(`IMPL-TEAM-ALIGNMENT-V7.72-CLOSEOUT-PEER-FIXES`, Class A1) instructs Rust +
Python to reject "NUL/C0/DEL". The conformance vector only *tests* a NUL byte,
so either policy passes the oracle — but the impls now reject a superset of what
§1.4's text forbids.

**Interim choice:** Rust rejects the full C0 range + DEL (`first_illegal_path_byte`
in `core/tree/src/lib.rs`), matching the Go reference and the punch list, so a
path one peer binds is bindable on every peer in the shared tree. This is
stricter than §1.4's literal text.

**For architecture:** tighten §1.4 to say control characters (the C0 range +
DEL), not just "null bytes" — so the normative text matches what all three
impls now enforce. Otherwise the spec permits paths the conformant cohort
rejects, and a future impl reading §1.4 literally would accept C0-control paths
and silently diverge from the shared-tree address space. (Cosmetic: §9.5a
`CORE-TREE-PATH-FLEX-1`'s "reject null byte" bullet could note the broader set.)

## V7.75 RESOURCE-BOUNDS COHORT — `chain_depth_exceeded`/400 is settled for the EXECUTE auth path, but the install-time creator-authority walk still maps too-deep → 404 `chain_unreachable`

**Passage:** V7 §4.10(b) (v7.75, folded RESERVED → §9.1 floor MUST at arch
`414b892`): *"the peer MUST reject a presented chain exceeding its configured
maximum depth with `400 chain_depth_exceeded` rather than walking an
attacker-controlled chain unboundedly... The status is 400, not 403 — a
too-deep chain is a client-correctable structural excess, not an authorization
denial."* The bound is justified by §5.5 cost: *"Capability-chain verification
(§5.5) costs O(depth) signature verifications."*

**Ambiguity:** §4.10(b) names "a presented capability chain" verified under
§5.5. Rust runs the **same** `collect_authority_chain` walk (with the same
`MAX_CHAIN_DEPTH = 64` ceiling) on two boundaries:
- the **EXECUTE auth path** (`verify_capability_chain`) — now correctly maps
  `ChainWalkError::TooDeep` → `ProtocolError::ChainTooDeep` → **400
  `chain_depth_exceeded`** (this turn, against §4.10(b)).
- the **install-time creator-authority path** (`check_creator_authority`, used
  by continuation install / subscription subscribe / compute install audit) —
  documented to map both `Unreachable` *and* `TooDeep` → **404
  `chain_unreachable`** (`core/protocol/src/verify.rs:688`).

The install path incurs the identical O(depth) DoS surface §4.10(b) is written
to bound, but §4.10 scopes itself to "inbound EXECUTE" / "presented chain" and
does not mention the install-time creator check. So it is unclear whether
§4.10(b)'s 400/`chain_depth_exceeded` rule reaches the install boundary, or
whether that boundary keeps its own 404/`chain_unreachable` surface (where
too-deep is folded into unreachable because the walk never reaches root).

**Interim choice:** Rust leaves the install-time path mapping `TooDeep` → 404
`chain_unreachable` unchanged. Only the EXECUTE auth path was remapped, matching
the `resource_bounds` gate's r2 probe (which exercises the EXECUTE path only).
The `resource_bounds` category does not test the install boundary, so either
mapping passes the oracle today.

**For architecture:** clarify whether §4.10(b)'s `chain_depth_exceeded`/400 is a
property of the **§5.5 chain-walk primitive itself** (and therefore applies
everywhere a chain is walked, including install-time creator checks) or only of
the **inbound-EXECUTE auth boundary**. If the former, the install path's
too-deep case should split out from `chain_unreachable`/404 to
`chain_depth_exceeded`/400 across the cohort; if the latter, the spec should say
so, since the install walk shares the same O(depth) cost that motivates the
bound.

## ~~EXTENSION-DISCOVERY §2.1/§2.2 — `candidate.peer_id` null-until-IDENTIFY: explicit-null vs absent~~ RESOLVED (arch Ruling-6, commit 7626026 — ruled **absent**, Rust's interim choice; pinned spec-wide for every `<X | null>` field; Python re-pins F2 fixture, Go+Rust unchanged; cross-impl byte-equal on `candidate_0.content_hash` is the D6/D7 gate)

**Passage:** §2.1 declares `candidate.peer_id: <Base58 peer-id per V7 §1.5 | null>`
with the inline comment *"null until IDENTIFY completes"*; §2.2 reinforces:
*"A candidate's `peer_id` field is **null** when the candidate is first surfaced
by a backend."* The successor pattern (§2.2) then derives a new candidate whose
`content_hash` is referenced by `supersedes` and by `decision.candidate`.

**Ambiguity:** the spec says `peer_id` is **null** pre-IDENTIFY, but the
project-wide interop convention (V7 "Optional fields: SHOULD be absent (key not
present), not null" — also [[feedback_typed_struct_field_wire_convention]]) says
an unknown optional is encoded **absent**. These produce **different CBOR** and
therefore **different `content_hash`** for `candidate_0` — which is exactly the
hash that `supersedes` / `decision.candidate` pin. If Go emits an explicit
`peer_id: null` and Rust omits the key, the two impls compute different
candidate hashes and the §2.2 supersedes-chain / §2.1 decision references
silently fail to match across impls. This is the same silent-divergence class
§3.2 was written to close for the mDNS wire — but on the entity layer.

**Interim choice:** Rust encodes `peer_id: None` as **absent** (key not present),
per the project-wide convention, and decodes both absent and explicit `null` as
`None` (tolerant read). This is the unblocked, convention-consistent choice. The
TOFU-candidate byte-equal fixture pin (`extensions/discovery/src/tests.rs`,
`fixture_candidate_tofu_hash` →
`00b613881ab1f301c47d1b567ba639d59c82a782df2ddaca0a1b0919da573fd1a4`) is computed
under the **absent** encoding.

**For architecture / cohort:** confirm the candidate `peer_id`-pre-IDENTIFY
encoding is **absent**, not explicit-null, and pin it in §2.1 (one sentence) so
Go's D5 handler and Python converge on the same `candidate_0` `content_hash`.
The TOFU fixture above is the convergence anchor — if Go/Py disagree, this is
the field. (Same question technically applies to `identity_hint` /
`supersedes` / `decision.grant`, but those are already `<... | null>` optionals
that Rust encodes absent-when-None with no semantic "is null meaningful?"
tension; `peer_id` is the one the spec prose explicitly calls "null".)

---

## EXTENSION-RELAY v1.0 — `envelope_inner` `refs:` placement (cohort-convergence pin)

**Status:** ✅ RESOLVED — Go's R5 cohort handoff
§4.1 confirms `envelope_inner` lives **in the data field** (not a refs block), the
same reading Rust shipped. Proven byte-equal: Rust's F1/F2/S1/S2 fixtures reproduce
Go's pinned content_hashes exactly (`extensions/relay/src/tests.rs::fixture_*`). The
secondary `stored_at` pin is likewise resolved — Go's R5 amend 1 corrected to bare
namespace (Rust's catch); Rust's R2 fixture matches Go's pin (`beb909b6…047e801c`).
Original concern kept below for the record.
**Spec:** `EXTENSION-RELAY.md` §3.1 / §3.2 / §3.0.

**Passage.** The `forward-request` (§3.1) and `store-entry` (§3.2) entity
schemas list the inner-envelope pointer under a separate `refs:` heading:

```
type: "system/relay/forward-request"
data: { destination, next_hop, ttl_hops }
refs:
  envelope_inner: <system/hash>
```

**Ambiguity.** This Rust codebase's `Entity` is `{type, data, content_hash}`
with `content_hash = SHA-256(ECF({data, type}))` — there is **no** wire-level
`refs` field, and `refs` is **not** part of the hashable basis. So a `refs`
block can only be represented one of two ways, which produce **different
`content_hash`** for the same logical entity:
1. `envelope_inner` is a field **inside `data`** (a bare 33-byte `system/hash`)
   — the only placement where it contributes to the entity's content hash in
   this model. **This is what Rust does.**
2. `envelope_inner` is a top-level sibling map `refs: {envelope_inner: <hash>}`
   that some impl folds into the hashable basis as `{data, refs, type}`.

If Go encodes (2) while Rust encodes (1), the `forward-request` / `store-entry`
content hashes diverge, and any cross-impl reference to a stored entry by hash
(poll → `entry_hash`, fallback rendezvous) silently fails to match. Same
silent-divergence class as the DISCOVERY `candidate.peer_id` pin above.

**Interim choice.** Rust encodes `envelope_inner` as a **`data` field**, bare
33-byte `system/hash` bstr (`extensions/relay/src/data.rs`). This matches the
project-wide typed-struct-field convention
([[feedback_typed_struct_field_wire_convention]]) and the only hashable model
the codebase has. Decode reads it from `data`.

**For architecture / cohort.** Confirm at R5/R8 whether Go places
`envelope_inner` in `data` (matching Rust) or in a distinct `refs` map that
participates in the content hash. If the latter, the spec's `refs:` heading is
load-bearing on the hashable basis and §3.0 needs one sentence pinning how
`refs` serializes + hashes. The `forward-request` / `store-entry` content hashes
are the convergence anchors.

**Secondary (minor):** `forward-result.stored_at` is typed `<path | null>` but
its §4.2 comment + §6.2.1 say "namespace, if queued-fallback." Rust returns the
bare **namespace** (= destination `peer_id`), since that is what the destination
passes to `:poll`. Confirm Go returns the same (namespace, not the full
`system/relay/store/{ns}/{hash}` path) at R8.

---

## EXTENSION-RELAY v1.0 — §3.1.1 terminal hop: spec mandates raw-frame, Go reference + shared validator implement decode-then-redispatch

**Status:** ✅ RESOLVED (same day) — Rust's
raw-frame reading was correct and is now the cohort-settled interpretation. The
cohort gap turned out to be a **validator-shape bug, not a Rust dispatcher bug**:
the prior validator sent an unsigned `ExecuteData` inner, which Rust's
already-correct raw-frame dispatcher refused. Once the validator was fixed to
send a fully-signed `system/envelope` (Go `validate-peer` HEAD `c28dad1`,
`CreateAuthenticatedExecute`), **Go migrated its dispatcher to raw-frame**
(`DeliverInner` → `SendRawFrame`/`SendRawFrameTo`, `c28dad1`) and **Python landed
the same** (`b8034d5`). `relay_multi_peer` mp1–mp4 are now **3-way GREEN**
(Go/Rust/Python self + Python→Go→Rust mixed); §5.1 author-transparency enforced
end-to-end in three impls. Rust needed **no code change** — `PeerRelayForwarder`
was already raw-frame. Close record: the Go relay-R8 cohort-close;
Rust response memo: the relay-R8 raw-frame Rust response.
**Spec:** `EXTENSION-RELAY.md` §3.1 / §3.1.1 / §9 / §5.1.

_Original finding (retained as the record of the divergence and its resolution):_

**Passage (§3.1.1, "Terminal hop — raw-frame forwarding (§2.1 ruling)").**

> The relay **writes the inner envelope's raw bytes verbatim into the
> destination's inbound frame** and dispatches them as a normal inbound message
> — exactly the bytes the destination would have received on a direct
> connection. The relay **MUST NOT decode-then-re-encode** the inner envelope …
> Raw-frame (not decode-then-redispatch) is required to deliver true
> byte-identity-to-direct … **This resolves the Rust (raw-frame) vs Python
> (decode-then-redispatch) divergence in favor of raw-frame** … the destination
> verifies the inner envelope's signature + capability chain *exactly as on a
> direct connection*, and therefore **MUST NOT need the RELAY extension
> installed merely to receive** a forwarded message.

§3.1 likewise pins the inner as **a full materialized `system/envelope`
`{root, included}`** carrying its own signatures/caps, "so the terminal hop
delivers a self-contained, independently-verifiable message; a bare root would
arrive unverifiable."

**The conflict.** The Go reference dispatcher
(`ext/relay/peerwiring/dispatcher.go::DeliverInner`) and the shared cross-impl
validator (`cmd/internal/validate/relay_multipeer.go`) implement the **opposite**
of the ratified ruling:

1. The validator's `buildInnerExecute` constructs the inner as a **bare,
   unsigned `system/protocol/execute` ExecuteData entity** (`execData.ToEntity()`)
   — *not* a `{root, included}` envelope and *not* signed.
2. `DeliverInner` **decodes** that ExecuteData and **re-dispatches** it via
   `peer.RemoteExecute` — i.e. the relay **re-signs the EXECUTE under its own
   identity** to the destination.

These two facts make the two models mutually exclusive, decisively:

- True raw-frame of the validator's inner is **undeliverable**: the destination
  runs `decode_envelope`, finds no `root`/`included` (it's an ExecuteData map),
  and rejects the frame; and even structurally, an **unsigned** EXECUTE fails the
  destination's mandatory non-connect auth (V7 §5.2). Raw-frame **requires** the
  source to build a fully-signed `system/envelope` the destination can verify
  standalone — which the validator does not do.
- Go's decode-then-redispatch "works" only because (a) it re-signs at the relay
  (defeating §5.1 author-transparency — the destination sees the *relay* as
  author, not the source) and (b) ECF round-trips are *usually* (not guaranteed)
  byte-identical (defeating §3.1.1's exactness promise).

So no impl currently realizes §3.1.1, and the validator **cannot** test it (its
inner is the wrong shape). The cohort is mid-migration: §3.1.1 ratified raw-frame
but Go + the validator predate it.

**Interim choice (Rust).** Rust implements **§3.1.1 literally**:
`core/peer/src/relay_forwarder.rs::PeerRelayForwarder` writes the opaque inner
envelope's bytes **verbatim** into the destination's inbound frame
(`RemoteEndpoint::dispatch_raw`, a byte-exact send added alongside the
convenience `dispatch_envelope`), never decoding/re-encoding/re-signing. It reads
only the inner's embedded `request_id` (to demux the destination's
EXECUTE_RESPONSE), never the payload. The destination verifies the source's own
signature + capability chain; the session peer (the relay) is decoupled from the
EXECUTE author (already true in Rust — `verify_request` does not bind author to
session peer). Proven end-to-end by
`core/peer/src/lib.rs::tests::test_relay_terminal_raw_frame_delivery` (live
3-peer TCP: A's signed inner delivered byte-for-byte through relay B to C, C's
tree payload `content_hash`-identical to source). **Consequence:** Rust's
same-impl `relay_multipeer` mp2 vector will **FAIL against the current Go
validator** (validator builds an undeliverable unsigned ExecuteData inner). This
is expected and correct — the red is the validator's, not Rust's.

**For Go / cohort (owed, user-directed).** Go should migrate to raw-frame to
match the §3.1.1 ruling:
1. `DeliverInner` → write `inner.Data` verbatim into the destination's inbound
   frame (no decode/re-encode, no re-sign).
2. `buildInnerExecute` (validator) → build a **fully-signed `system/envelope`
   `{root, included}`** inner (the source authors + signs the EXECUTE and bundles
   its cap chain), so mp2 actually exercises raw-frame + standalone verification
   at the destination.
3. mp2's assertion stays "payload byte-equal at C's tree," but now also implies
   "C verified the *source's* signature, not the relay's."

Until Go migrates, Go-as-relay (decode-redispatch) and Rust-as-relay (raw-frame)
disagree on the wire for the *terminal hop only*: Go re-signs as the relay, Rust
preserves the source's envelope. Mixed rotations with Go-as-B will still observe
a payload at C (Go re-signs a valid EXECUTE), but the **author identity at C
differs** (relay vs source) — a §5.1 transparency divergence, not just an
encoding one. Python is in the same pre-migration state (decode-redispatch).

---

## EXTENSION-RELAY v1.1 source-routed multi-hop + EXTENSION-ROUTE v1.0 — landed Rust-side

**Status:** ✅ IMPLEMENTED (Rust), awaiting cross-impl
validate-peer. No ambiguity — the specs landed clean (arch fold `32ae3e3`; Go
build-test `8ae1c9b`, `relay_source_route` 6/6 + `route` 8/8 self-GREEN, **no
spec deltas**). Logged here as the implementation record + the cross-impl pins to
watch. **Specs:** `EXTENSION-RELAY.md` v1.1 §3.1 / §3.1.1 / §5.4 / §6.8;
`EXTENSION-ROUTE.md` v1.0. **Cohort handoff:**
the Go relay v1.1 cohort-close handoff.

**What landed (Rust):**
- **`route: [peer_id]` on `forward-request`** (`extensions/relay/src/data.rs`),
  CBOR-omitempty: a v1.0 single-hop request (no `route`) encodes byte-identically
  (fixtures F1/F2 digests unchanged — proven in `tests.rs`).
- **§3.1.1 per-hop algorithm** (`extensions/relay/src/handler.rs::handle_forward`):
  precedence **source route > `next_hop` > route table > no_route**. Cross-field
  invariant `next_hop == route[0]` (when both set) → `invalid_request`/400
  **pre-dispatch**. Terminal iff `next == destination`. Intermediate pops the head:
  `route' = route[1:]`, `next_hop' = route'[0]` (or none), `ttl_hops − 1`
  (`core/peer/src/relay_forwarder.rs`).
- **EXTENSION-ROUTE v1.0** as a new sibling crate (`extensions/route`): the
  `system/route` entity codec, canonical `route_path` (= `hex(hash.to_bytes())`,
  the `Hash.Bytes()`-equivalent form — avoids cross-impl trap #1's padded 130-char
  path), the `route-configure` cap, and the pure §3 `resolve` match (exact > `*`
  default, lowest metric, expiry-skip, cross-field-invalid skip). RELAY consumes it
  (`relay → route` edge, documented in `CLAUDE.md`); RELAY does the local-tree read,
  ROUTE owns the match semantics. No `system/route` handler in v1 (writes via
  `tree:put`; reads are relay-internal).

**Architectural call (Rust-side, owned per the no-punt discipline).** ROUTE is a
**separate crate**, not folded into relay. The spec defines ROUTE as a sibling
extension (storage plane; store/consume/produce role separation is "the whole
point", ROUTE §1). The Go reference put `RouteData` in `core/types` for expedience;
Rust implements from spec → a dedicated `entity-route` crate with the documented
`relay → route` composition edge (RELAY §6.8 / ROUTE §6), added to `CLAUDE.md`'s
permitted-edges list alongside `quorum→attestation` etc.

**Cross-impl pins to watch on the next validate-peer (from handoff §6 traps):**
1. Canonical route path uses `hash.to_hex()` (66 hex chars SHA-256), not a padded
   digest — verified by `entity-route` unit test `canonical_path_is_hex_of_canonical_bytes`.
2. `next_hop ≠ route[0]` rejects pre-dispatch — `source_route_next_hop_mismatch_rejected_pre_dispatch`.
3. Intermediate sets `next_hop' = route'[0]` — `source_route_intermediate_pops_head`
   + live `test_relay_source_route_three_hop` (A→B→C→D over real TCP, inner
   byte-identical across both hops).
4. §9 opacity holds across intermediate + terminal — same live 3-hop test
   (`content_hash` identical at D).
5. Route table consulted **only** when both `route` and `next_hop` absent
   (precedence) — `source_route_takes_precedence_over_table`.
6. `"*"` is a string token, not a peer-id — `entity-route` treats it as a literal
   `match` string (never decoded as a peer-id).

**Test evidence:** `entity-route` 12/12, `entity-relay` 41/41 (incl. 8 new
source-route + route-table tests), `entity-peer` (relay) 146/146 (incl. the live
3-hop test). Full workspace builds; route + relay compile for wasm32; standard CI
wasm build green. **Next:** Go `validate-peer -category relay_source_route` +
`-category route` against a Rust peer for 3-way close.

## Rust impl gap — `published_root::verify_content` / `verify_signed_root` are incompatible with the live CONTENT_GET wire form AND trust the wire hash (§1.2 hole)

**Status. RESOLVED** — fix landed (see *Resolution* below). Was: Rust impl
gap, NOT a spec ambiguity. Arch reclassified Gap B to a **v1-release blocker for Rust**
(the architecture network/relay-cycle closeout §3; the Go cohort
relay-v1 pre-tag checklist §3.1) — an
authentication bypass in shipped consumer code, the exact v6 host-bytes-distrust threat.
Surfaced while implementing the Tier-1 `publish_fetch_http_poll` cohort gate (Thread B,
the Go publish-fetch-http-poll cohort handoff).
The Thread B self-PASS itself was GREEN (`core/peer/tests/publish_fetch_http_poll.rs`,
6/6) because that test drives a *correct* Mechanism-A consumer; this note recorded the
defect in the shipped consumer helpers that the test had to route around.

**The two gaps (same root cause).** The live http-poll CONTENT_GET route serves
`ecf_for_hash(type, data)` — the **2-key `{data, type}` form, NO `content_hash`**
(`core/peer/src/http_live.rs:791`, arch ruling 1b5c125 §1: the consumer is
contractually required to *re-hash*). But the consumer helpers in
`core/peer/src/published_root.rs` were written against the 3-key `encode_entity` form:

- **Gap A (live-wire incompatibility).** `verify_content` (`published_root.rs:175`)
  and `verify_signed_root` (`:193`) both call `entity_wire::decode_entity`, which
  **requires** a `content_hash` field (`core/wire/src/lib.rs:144`, errors "missing
  'content_hash' field"). On a real CONTENT_GET body (2-key) this fails outright. It
  hits both the content path *and* the signature path (the `system/signature` entity
  is fetched via CONTENT_GET → 2-key → undecodable). So `HttpPollFetcher` +
  `PublishedRootClient` cannot drive the live route end-to-end — consistent with the
  `HttpPollFetcher` doc-comment flagging live wiring as deferred "Phase P P7."

- **Gap B (§1.2 host-bytes-distrust hole).** Even on the 3-key form, `verify_content`
  compares a **wire-provided** `content_hash` to `expected` (`:178`) instead of
  recomputing `Hash::compute(type, data)`. A host serving
  `{type, data:<evil>, content_hash:<expected>}` passes the check. The unit test
  `consumer_rejects_tampered_content` only catches the naive attacker (whose served
  entity carries its *own* honest hash ≠ expected); a hash-lying host is not caught.
  This is a §1.1/§1.2 Mechanism-A trust-gate violation. (Go's `httplive.Outbound.
  FetchContent` re-hashes the body — handoff Trap 5 — so this is a Rust-only hole.)

**Why the in-tree unit tests don't catch it.** The `StoreFetcher` in
`published_root.rs` tests serves `encode_entity(e)` (3-key, honest content_hash) —
NOT the `ecf_for_hash` form the real server emits. So the tests are green while the
live path is broken on both counts.

**Fix sketch (deferred — not in the Thread B scope; flagged for a follow-up).** Make
the consumer verification content-addressed and form-agnostic: decode `(type, data)`
tolerating presence/absence of `content_hash` (extract `data` as raw bytes for
fidelity, never re-encode), **always** recompute `Hash::compute(type, data)`, and
trust iff it equals the requested hash. A `wire::decode_entity_rehash` primitive
(wire already depends on `entity_hash`) would serve `verify_content`,
`verify_signed_root`, and the `VerifyingFetchStore` walk; the existing 3-key
`StoreFetcher` unit tests stay green (type+data extracted, recompute matches, the
extra wire `content_hash` ignored). This has cross-impl surface (it changes how Rust
verifies published roots) so it warrants a cohort note rather than a silent patch.

**Test evidence / interim:** `core/peer/tests/publish_fetch_http_poll.rs` 6/6 GREEN
(real wire, correct re-hash consumer). The broken helpers are untouched pending the
fix decision.

**Resolution.** Fixed per the blessed sketch.
- New `core/wire::decode_entity_parts(bytes) -> (type, data)` — form-agnostic: tolerates
  both the 3-key authored form and the 2-key `CONTENT_GET` form, and **ignores any wire
  `content_hash`** (it captures `data` as the raw on-wire slice for byte fidelity).
- `published_root::verify_content` now decodes via `decode_entity_parts` and **recomputes**
  `Entity::new_with_format(type, data, expected.algorithm)` (recompute under the requested
  hash's own format, §1.8), trusting iff it equals `expected`. Closes Gap A (2-key decodes)
  + Gap B (hash-lying host rejected). `VerifyingFetchStore::get` inherits the fix (it calls
  `verify_content`), so the trie walk re-hashes every node.
- `published_root::verify_signed_root`: the manifest (3-key per the §6.5.3.1 MANIFEST_GET
  "wire entity" contract) now passes `Hash::validate(type, data, content_hash)` before its
  `content_hash` is used as `root_hash` — defeats a data-swap that keeps a publisher-signed
  outer hash. The signature entity decodes form-agnostically (`decode_entity_parts`); its
  trust is the Ed25519 verify against the pinned key, not its self-hash.
- New unit tests: `verify_content_accepts_2key_content_get_form`,
  `verify_content_rejects_hash_lying_host`. The 3-key `StoreFetcher` tests stay green.
- **§3.2 cohort audit catch (same class, also fixed):**
  `extensions/storage-substitute-http/src/handler.rs` fetched content from an **untrusted
  HTTP origin** and compared the *wire-provided* `content_hash` to `target_hash` — its
  comments falsely claimed a `Hash::compute(type,data)==target_hash` recompute that did not
  exist. Now decodes form-agnostically and recomputes under `target_hash.algorithm`,
  rejecting bytes that do not re-hash. (No integration coverage exists for that fetch path —
  pre-existing; the recompute primitive is the same as the unit-tested `verify_content`.)
- Verified: published_root 10/10, publish_fetch_http_poll 6/6, http_live 43/43, peer suite
  148/0, storage-substitute-http 12/12, wire 15/15, clippy clean on touched files.

---

## EXTENSION-RELAY §3.1 — `forward-request.route` element type: `[<peer_id>]` notation vs Go's `array_of(primitive/string)`

**Passage (EXTENSION-RELAY §3.1):** the source-route field is written `route: [<peer_id>]`
— a list whose elements are peer-ids.

**Ambiguity / divergence.** The spec notation implies each hop is a `system/peer-id`-typed
value. The Go reference, however, reflects `ForwardRequestData.Route []string` to
`array_of(primitive/string)` with **no** `OverrideField` pin to `system/peer-id` — unlike
`destination`, `next_hop`, `put_by`, and `forward-result.next_hop`, which Go *does* pin. So
the `route` element type is `primitive/string` in the type-definition entity Go advertises.

**Interim choice (Rust, F1 cohort).** Rust registers `forward-request.route` as
`opt_arr(t("primitive/string"))` to byte-match the Go reference (the validate-peer oracle):
the `system/relay/forward-request` type-definition entity must hash-equal Go's or the
cohort type_system check FAILs. Confirmed OK via `compare-types` (3-way hash match). Pinning
`route` to `system/peer-id` Rust-side would diverge from Go and break green.

**Routes to:** architecture + Go — decide whether `route` hops should be pinned to
`system/peer-id` (matching the spec notation and the other peer-id surfaces) in *all* impls
together, or whether the spec notation should be read as informal and `primitive/string`
ratified. Either way it is a cohort-wide one-line change, not a Rust-local one. Not gating
release-green (current state is internally consistent across the cohort).

**RESOLVED (arch Q5).** Arch ratified the cohort pin as
`array_of(primitive/string)?` (the spec `[<peer_id>]` notation is read as informal prose for
"peer-ids carried as strings," NOT a `system/peer-id` *type* pin). Rust's interim choice
(`opt_arr(t("primitive/string"))`) already matches, so no Rust change is required — this was
the Q5 cohort decision and Rust conformed at F1. Cross-impl `compare-types` 3-way hash match
stands. Anchored in the cohort handoff Rust punch list item R2.

---

## EXTENSION-TYPE §7.4/§7.5/§7.6 — `converge` / `adopt` / `reconcile` ops unimplemented (ACCEPTED)

**Passage (EXTENSION-TYPE §7, §10 conformance table line 688).** The type-analysis
operations `converge` (§7.4), `adopt` (§7.5), and `reconcile` (§7.6) are **MAY** — the §10
conformance table marks all of §7 "Reference," and the operation set a `system/type` handler
*must* serve is `validate` + `compare` + `compatible` (§7.1–§7.3). The three merge/adoption
ops are optional.

**Rust state.** `extensions/type-system/src/validate.rs` (`TypeHandler::operations()` →
`["validate", "compare", "compatible"]`) serves the three required ops and returns a clean
`400 unknown_operation` for `converge` / `adopt` / `reconcile` (the `other =>` arm). This is
the conformant response for an unimplemented MAY op — the handler advertises its op set and
fail-closes on anything outside it, identical to the existing `unknown_operation` posture for
the constraint handler.

**Decision: ACCEPT (do not implement for v1).** The validate-peer gates
`type.op_{converge,adopt,reconcile}_roundtrip` exercise these ops and observe the 400. Per
arch Bucket B dispatch (cohort handoff R4), these are MAY ops not required for v1 conformance,
so the 400 is correct-by-design, not a failure. No infrastructure invented to satisfy a
non-MUST. If a deployment later needs cross-peer type convergence, `converge`/`adopt`/
`reconcile` become a scoped follow-on against §7.4–§7.6 (their result entities —
`compatibility-report`, `reconcile-result`, etc. — are already registered as core types, so
only the op handlers would be new). Anchored in the cohort handoff Rust punch list item R4.

---

## ENCRYPTION §16.4 — ENC-GROUP-KAT-1 does not pin the per-wrap ephemeral seeds

**Spec:** EXTENSION-ENCRYPTION v1.0 §16.4 (ENC-GROUP-KAT-1 pinned inputs).

**Passage.** §16.4 pins: 3 members with X25519 seeds `0x50`/`0x51`/`0x52`,
outer nonce `0x53×24`, per-wrap nonces `0x60+i`, and `group_aead_key = 0x54×32`.
It does **not** pin the per-wrap *ephemeral* X25519 private seeds. But each
`wrapped_keys[i]` is a peer-mode hybrid encryption (§8.3 step 5) whose
`ephemeral_key` and `wrapped_aead_key` bytes are a function of that fresh
per-wrap ephemeral keypair. Without a pinned wrap-ephemeral seed, the wrap
ciphertexts are non-deterministic and cannot be byte-pinned across impls — the
outer ciphertext locks (it depends only on group_aead_key + outer nonce + outer
AAD, all pinned), but the per-wrap blobs do not.

**Impact.** The outer-ciphertext byte-pin and the commitment are lockable now;
the per-wrap `wrapped_aead_key`/`ephemeral_key` byte-pins are not until §16.4
adds wrap-ephemeral seed pins (suggest `0x70+i`, the value the Rust seat used).
Group-mode round-trip + ENC-GROUP-COMMIT-1 + ENC-RESOURCE-BOUNDS-1 are fully
exercised regardless (they don't depend on a fixed wrap-ephemeral seed).

**Interim Rust choice.** Per-wrap ephemeral seed `0x70+i` (member i). Recorded
in `docs/archive/ENCRYPTION-BYTE-PINS-RUST.md`. Surfaced, NOT self-folded (per the
cohort handoff §4 discipline). Routes to **architecture** to pin in §16.4
alongside Go/Python so the wrap byte-pins lock 3-way.

**Secondary (§16.2/§16.3/§16.4 plaintext framing).** All three KATs mark the
inner-entity plaintext as "TBD by cohort+arch joint authoring (a fixed test
entity)". Until that lands, the `expected_ciphertext_hex` values are provisional
on the placeholder plaintexts the spec text lists (`"hello world"` etc.); the
AAD hex + pubkey-hash derivation are firm regardless.

> **Update: Go independently chose the same `0x70+i`.** `go test
> ./ext/encryption -v` emits wrap ephemerals/ciphertexts byte-identical to
> Rust's, so Go's `group_test.go` also pins wrap-ephemeral seed `0x70+i`. The
> value is already de-facto cohort-converged; the gap is only that §16.4 prose
> doesn't state it — write it in so Python + Keystone don't reverse-engineer it.

> **RESOLVED (arch v2.5, `entity-core-architecture` @ `8b7ac3b`).**
> **R1** pins the per-wrap ephemeral seed at `0x70+i` (Rust's interim choice
> ratified). **R3** pins the §16.2/§16.3/§16.4 KAT plaintext as ENC-KAT-INNER —
> the ECF of a real `system/note{body, created:0}` entity, not a bare string —
> closing the "plaintext framing TBD" secondary. **R4** blesses Go's named
> sub-shapes `system/encryption/kdf-params` + `system/encryption/wrapped-key`,
> resolving the deferred inline-`{fields:…}` modeling call: the 5 encryption
> entity types + 2 sub-shapes (+ `system/note`) are now registered in
> `core/types/core_types.rs` (clears the 5 `validate-peer` type-registration
> FAILs from `e5bd49a`). The §16 `expected_*_hex` re-derivation against the R3
> ENC-KAT-INNER plaintext is **DONE** — `kat::enc_kat_inner_plaintext()` is
> byte-pinned to the 79-byte ECF and `tests/modes.rs` asserts the 95-byte
> self/peer/group ciphertexts byte-equal to Go + Python (3-way §16.5 lock). R6
> key-separation (`separation.rs`), §10/§11 sender resolution, and §8.5 group
> lifecycle primitives also landed. No spec gap remains here.

---

## NETWORK §5.1 — keepalive ping authorization: no grant covers `system/protocol/connect`

> **RULED 2026-07-16 — arch ruling 17 (`entity-system-architecture`
> `docs/status/ROUTING-2026-07-16-arch-rulings-to-cohort.md`). Rust's interim
> choice was ratified as written:** ping is **cap-free on an established
> connection**, and the established-only gate (the inverse of
> hello/authenticate) "is right". Option (a) — ping is protocol-level; §4.4's
> default grant set does NOT grow. The connect manifest advertises `ping`
> (`core/peer/src/lib.rs`, landed `33289bc` — the routing doc still lists this
> as a Rust to-do; it is done, with `["authenticate", "hello", "ping"]` pinned
> by a test). No code change owed. Retained for the reasoning trail; the
> related §5.4 "is a 4xx a miss?" reading below is **still open** and belongs
> to the convergence pass.

**Spec:** EXTENSION-NETWORK §5.1–§5.4 (keepalive is an EXECUTE on
`system/protocol/connect`, operation `ping`; §12.1 makes the exchange MUST) ⨯
ENTITY-CORE-PROTOCOL-V7 §4.4 (default connection grants) ⨯ NETWORK §3.2
(network-handler capability model).

**Passage.** §5.1: `EXECUTE system/protocol/connect operation: "ping"` with
`system/network/ping` params, answered by `system/network/pong`. The ping
rides the ordinary post-handshake EXECUTE path, so it reaches the receiver's
handler-scope authorization check like any other dispatch.

**Ambiguity.** Nothing grants it. The §4.4 default connection grants cover
`system/tree` (get on types/handlers) + `system/capability` (request) only;
NETWORK §3.2's grant-entry covers `system/network` (and its `internal_scope`
names connect's `hello`/`authenticate` — not `ping`). A spec-literal
implementation therefore 403s (`capability_denied`) every conformant
keepalive ping, making the §12.1 MUST unsatisfiable under default grants.
`hello`/`authenticate` don't hit this because they run pre-Established,
before the capability layer exists.

**Interim choice.** Treat `ping` as the **third protocol-level connect
operation**: the receiving dispatch answers it after signature/capability
*verification* but exempt from the handler-scope *grant* check (seam:
`dispatch_request` in `core/peer/src/connection.rs`, just before the
`handler_authorized` check). Not widening the §4.4 default grant set — that
is shared cross-impl capability surface. Needs an architecture ruling:
(a) ping is protocol-level (this choice — then the connect manifest ops list
and §3.1 `internal_scope` should say so), or (b) §4.4/§3.2 grow an explicit
connect/ping grant. Related observation for the same ruling: whether the
bootstrap connect-handler manifest advertises `ping` in its `operations`
(Rust currently advertises `["authenticate", "hello"]`, unchanged).

**Related §5.4 reading routed with it.** "if result is timeout or result is
error: missed += 1" — Rust counts only transport error/deadline as a miss;
an EXECUTE_RESPONSE with a non-200 status counts as *liveness* (the peer
demonstrably answered a frame; also keeps the floor from killing live
connections to impls that haven't built §5 yet, e.g. rung-1-only cohort
members during the convergence build). If the cohort converges on "4xx is a
miss," that's a one-line change in `keepalive.rs::ping`.

---

## V7 §1.4 / CONTINUATION §3.10.5 — path-segment rules don't name `.` or `..`

**Spec:** ENTITY-CORE-PROTOCOL-V7 §1.4 (path-segment rules), as invoked by
EXTENSION-CONTINUATION v1.19 §3.10.5: "Codes used as `{reason}` path segments
MUST conform to ENTITY-CORE-PROTOCOL.md §1.4 path-segment rules (UTF-8; no
null bytes; no empty segments; no embedded `/`)."

**Ambiguity.** That enumeration does not name the reserved dot tokens, so `.`
and `..` are "path-safe" by its letter — non-empty, UTF-8, slash-free, no
nulls. They are nonetheless traversal tokens the moment they are concatenated
into a path. Rust's `{reason}` sanitizer implemented §3.10.5's enumeration
faithfully and therefore passed `..` through verbatim; the same blind spot in
the `{chain_id}` / `{step_index}` coordinates is the live defect Go's
`security.marker_path_injection_contained` probe found in Rust's and Python's
trees (a tree node literally named `..`, bound by an unauthorized peer —
`entity-core-go` `docs/validation/reports/2026-07-16-marker-path-injection-cohort.md`).
§1.4 is a general rule, so any spec passage deferring to it inherits the gap;
the chain-error marker path is simply where an untrusted value reaches it
first.

**Interim choice.** Reject `.` and `..` as path segments everywhere untrusted
values are interpolated (`entity_entity::sanitize_path_segment`,
`core/entity/src/lib.rs`), and treat §1.4's enumeration as non-exhaustive
rather than as the definition of safe. Suggest §1.4 state the dot tokens
explicitly (and ideally state the rule as a positive grammar rather than a
list of prohibitions, so the next reserved token isn't a third finding).

**Second, narrower question — `{reason}` diverges cross-impl today.** §3.10.5
prescribes **sentinel-substitution** for a non-path-safe code (`{reason}` =
`unspecified_error`, raw code preserved in the marker body's `code` field).
Rust does that. Go instead hashes this coordinate to `invalid-<8 bytes of
sha256>` under arch ruling 13's general "hash, don't collapse" rule
(`store.SanitizePathSegment`, applied to `reason` at
`ext/continuation/advance.go`), which reads as a deviation from §3.10.5's
SHOULD. Both are defensible: the sentinel loses the distinction between two
hostile codes but §3.10.5 recovers it in the body, whereas ruling 13's
rationale ("collapsing merges distinct failures onto one coordinate") was
written for `chain_id`, where nothing preserves the original. Rust holds the
spec's shape and routes the conflict rather than picking. **Arch: does ruling
13 override §3.10.5's sentinel for `{reason}`, or is `{reason}` deliberately
the exception because its raw value survives in the body?** Whichever way it
lands, one of Go and Rust changes — this is a live cross-impl divergence on a
coordinate, not a style question.

---

## EXTENSION-NETWORK §2.2 / §3.13 — `failing_since` has no writer for a peer that never connected

**Spec:** EXTENSION-NETWORK §2.2 (retry pacing) + ENTITY-CORE-PROTOCOL §3.13, as
ruled by arch rulings 7/8 (`entity-system-architecture`
`docs/status/ROUTING-2026-07-16-arch-rulings-to-cohort.md`): retry state lives in
the tree as ONE field, `failing_since`, written at the transition only;
`attempt` / `next_attempt_at` are derived, never stored.

**Ambiguity.** The durability of that derivation rests on a transition a
never-connected peer never makes. `failing_since` is stamped at the transition
OUT of `connected`; a peer that has never connected has never been `connected`,
and a failed **dial** writes no status entity (only a transport error on an
*established* connection demotes — `demote_peer_on_transport_error`,
`core/peer/src/liveness.rs`). So for `maintain-peer` against a peer that is not
up yet — a node booting before its neighbour, an address that is right but early
— the tree holds no stamp, and a derivation reading only the tree computes
`attempt = 0` on every attempt: no backoff growth at all. Whether a failed dial
against a MAINTAINED peer should itself write a §3.13 demotion is the open
question; it is a question about the model, not about one seat.

**Not our question first — Go routed it.** `entity-core-go`
`docs/validation/spec-issues/2026-07-16-failing-since-never-connected.md` states
it in full and notes "Rust/Python not probed". **Rust is now probed: the gap is
real here, identically.** Logged for our own traceability and to confirm the
cohort reading; arch should answer Go's issue, not two copies of it.

**Interim choice — converged with Go's, deliberately.** Prefer the tree's
`failing_since` when present (the authoritative, restart-surviving copy); keep an
in-memory episode start on the session as the FALLBACK for the never-connected
case only (`SessionState::failing_since`, resolved by `NetworkHandler::retry_state`,
`extensions/network/src/lib.rs`). The month-dead-peer win lands fully — that peer
*was* connected, so its stamp is in the tree and a restart re-derives from it
(pinned by `a12_retry_pacing_resumes_from_the_trees_stamp_after_a_restart`). The
never-connected case keeps today's behaviour: the curve grows within the process
and resets on restart. No regression, and no write site invented to paper over
the gap.

**One Rust-specific note for the cohort.** Reading the tree's stamp requires the
status-path key (the remote's identity hash) with NO live connection. Rust
previously set that key only on a successful establish, which would have made the
durable stamp unreadable in exactly the restart case that motivates it — the
ruling's headline win would have silently not landed. It is now derived from the
`peer_id` alone at session creation (`identity_hash_from_peer_id`), mirroring
Go's `types.ComputePeerIdentityHashFromPeerID` at the top of `maintain-peer`.
Seats deriving pacing from the tree should check they can *address* the stamp
before they can be said to read it.

## EXTENSION-CONTINUATION §3.4/§5 (marker retention) — MUST-collect vs. a peer that has no GC (ruling 19 / #19)

**Date:** 2026-07-17. **Status:** routed back to architecture; NOT built here.

Ruling 19 affirmed `PROPOSAL-CONTINUATION-LOST-ERROR-MARKER-MUST` §5, which
elevates marker collection from **MAY** (the landed text — *"Implementations MAY
garbage-collect markers after a configured retention window; suggested default:
24 hours"*, EXTENSION-CONTINUATION §3.4/§5.x, unchanged in `70c52b4`) to a
**MUST**: self-collection at a `system/config/chain-errors` → `retention_ms` key,
default 24h, mirroring EXTENSION-DISCOVERY's `candidate_history_retention` shape.
Ruling 19's own words: *"the retention MUST prevents unbounded growth by accident,
not a deliberate opt-in — spell it as a value of the retention key, one knob not
two"* (i.e. `RetainMarkersForever` is a sentinel VALUE of `retention_ms`, not a
separate boolean).

**Why this is logged rather than built.** Three facts pull against building the
MUST here now, and they are a question about the model, not about one seat:

1. **Rust has no marker-collection machinery at all** — no retention config, no
   sweep, no GC of `system/runtime/chain-errors/**`. Neither does the pattern the
   proposal says to mirror: `candidate_history_retention` is **not implemented**
   in Rust's `extensions/discovery` (exhaustive grep, 2026-07-17). So the MUST is
   not "add a value to an existing knob" — it is "build a whole background
   collection subsystem," with a WASM-timer story, that no seat has today.
2. **The landed spec still says MAY.** The MUST lives in an affirmed-but-unfolded
   proposal. Building a background deleter of a peer's own audit trail ahead of
   the fold is a real behavior change (markers *disappearing*) that deserves the
   fold's scrutiny, not a rider.
3. **The blast radius already shrank to near-zero.** Rulings 2+3 (landed,
   `d7d0d79`) took a dead peer's marker tree from ~1,440 nodes/day to **empty** —
   the retry loop no longer generates markers at all. Retention is no longer the
   line of defense against an unbounded generator; it is ordinary hygiene against
   a slow trickle of genuine exceptional failures. A MUST-delete is a heavy
   instrument for that.

**Also: it is effectively untestable as specified.** The observable is "markers
gone after `retention_ms`"; with the 24h default that is a wall-clock test no
conformance run exercises. A convergence vector would have to inject a tiny
`retention_ms` and assert deletion — which tests the *config plumbing*, not the
"prevents unbounded growth" property the MUST is for.

**Interim choice:** none needed — nothing collects today, and with the empty
dead-peer tree nothing accumulates from the retry path. If a marker sink ever
does grow, an operator can prune `system/runtime/chain-errors/**` out of band.
**Routed to architecture** (`docs/status/ROUTING-2026-07-17-marker-feasibility-and-retention-rust.md`):
is a self-collection MUST warranted for a surface this small, or should §5 stay a
MAY (a peer that never collects is then conformant)? If the MUST stands, the
one-knob spelling is confirmed and the sweep is a scoped follow-on, not this
cycle. **Answer the model question before three seats each build a background
deleter.**

---

## V7 §3.3 — EXECUTE_RESPONSE `result` shape on a `202`/accepted ack: bare CBOR null vs `primitive/null` entity

**Date:** 2026-07-19. **Status:** Rust made tolerant (consumes both); the "which
shape is canonical" question routed to the cohort. Surfaced by entity-core-go's
Go↔Rust desync report (`docs/validation/reports/2026-07-19-go-rust-response-frame-desync.md`);
Rust root-cause + fix in `docs/validation/reports/2026-07-19-go-rust-response-null-result.md`.

**Spec:** ENTITY-CORE-PROTOCOL-V7 §3.3 (EXECUTE_RESPONSE: `{request_id, status,
result}`). The spec types `result` as an entity but does not pin what a response
that has *no meaningful result* (a `202`-accepted async ack, where the operation
completes later) puts in the field.

**The divergence (both live impls, confirmed in source).**
- **Go** (`core/protocol/async.go::make202Response`): `Result: []byte{0xf6}` — a
  **bare CBOR null**, no `{type, data, content_hash}` wrapper.
- **Rust** (`core/peer/src/connection.rs::build_202_response`): a **`primitive/null`
  entity** — `{type:"primitive/null", data:0xf6, content_hash}`.

Each impl's encoder and decoder agree with themselves, so same-side round-trips
pass and neither caught it — the classic cross-impl-fidelity trap. Rust's reader
rejected Go's bare null (`params must be a CBOR map (entity)`), stranding the
async ack and cascading into a serving outage under load.

**Interim choice (landed).** Rust's reader is now **tolerant**: a bare CBOR null
`result` parses to the same `primitive/null` entity Rust emits, so both shapes
are accepted (Postel / MUST-ignore spirit). A non-null malformed `result` still
errors — the tolerance is scoped to null exactly. Rust's *emit* is unchanged
(still the `primitive/null` wrapper); only the read path was widened.

**Question for the cohort.** Is the `202` `result` canonically **bare null** or a
**`primitive/null` entity**? A tolerant reader unblocks interop today, but the
three seats should agree on one *emit* shape so the wire is single-valued. Rust
can switch its emit to bare null trivially if that is the ruling — the read path
already accepts both either way. Low urgency (tolerance holds), but worth a pin
so a future byte-exact `202` vector isn't ambiguous.

---

## ~~PROPOSAL-CONNECTION-NODE §1 — `collect` result: `[<hash>, ...]` or the blobs themselves?~~ RESOLVED

> **RESOLVED 2026-07-28 — arch ruling 1**
> (`ROUTING-2026-07-28-signaling-rulings-and-go-py-packet` §2), landed in
> `PROPOSAL-CONNECTION-NODE` §1. **Blobs**, exactly as the interim shipped — no
> Rust change. `[<hash>, ...]` was residue from a content-addressed sketch and is
> unimplementable as written: a hash reply needs a fetch surface §1.3 denies the
> node and §5.1 denies an unwrapped client, and it would make one verb
> completable on one surface only — the precise divergence §2.1 rules out.

**Date:** 2026-07-28. **Status:** interim choice landed (blobs); routed to arch.
Surfaced building Stage 1 (`extensions/signaling`, `feat/signaling-connection-node`).

**Spec:** `PROPOSAL-CONNECTION-NODE` (DRAFT 2026-07-28) §1 verb surface, read
against §0 and §1.3.

**Passage.** §1 gives the signature as

> `system/signaling:collect(rendezvous_key)   → { messages: [<hash>, ...] }`

while §0 describes the node as one that "holds an opaque blob at an opaque key
for a few seconds **so the other peer can pick it up**."

**Ambiguity.** Those read differently. If `messages` carries content **hashes**,
`collect` is not self-sufficient — the caller needs a fetch surface to turn a
hash into bytes, and the node has none to offer: §1.3 pins the state silhouette
at "per-key TTL-reaped buckets and nothing else. No bulk storage," and §5.1 says
a public node "is **not** an entity peer ... Clients hold no entity machinery to
talk to it." A hash-only reply would leave the unwrapped surface with a verb it
structurally cannot complete, which would contradict §2.1's pin that the two
surfaces reach the *same* operations.

**Interim choice.** `messages` is a CBOR array of **`bstr`** — the deposited
blobs themselves (`CollectResult`, `extensions/signaling/src/data.rs`). This
keeps `collect` self-sufficient on both surfaces, keeps the core entity-free per
§2.1, and matches §0's "pick it up." Reading `[<hash>, ...]` as loose notation
for "the opaque content-addressed thing that was deposited" is the reconciliation
we assumed.

**Question for arch.** Confirm the blob reading, or — if hashes really are
intended — say what fetch surface the node exposes for them, and how that
survives §5.1's "not an entity peer." This is a cross-peer-observable wire shape
on a **single-impl server** (§1.2), so it is exactly the class §1.1 says must be
pinned before code rather than settled in the Rust. Cheap to change now,
expensive after the go/py clients are written against it.

---

## ~~PROPOSAL-CONNECTION-NODE §1 — `reflect` has no source of an observed address on the wrapped surface~~ RESOLVED

> **RESOLVED 2026-07-28 — arch ruling 2**, landed in `PROPOSAL-CONNECTION-NODE`
> §1.4 (new), §2.1, §5.1. **`reflect` is the unwrapped listener's verb, not one
> of the core's operations** — the alternative this entry asked for (option (b),
> plumb a source address) was rejected, and option (a) confirmed and generalized.
> Not plumbed: *moved*.
>
> The reasoning went past the plumbing question. Even fully plumbed, a wrapped
> `reflect` reports the **TCP/WS** mapping of an already-established entity
> connection while the punch needs the **UDP** one — so it answers the wrong
> question, and a peer concludes its NAT type from *agreement across reflectors*,
> which makes a plausible-but-wrong address worse than none.
>
> **Rust delta (landed):** `ObservedAddressSource` and the 501
> `observed_address_unavailable` are **deleted**; `SignalingCore::reflect`,
> `Reflection`, its codecs, `SignalingClient::reflect`, `OP_REFLECT` and
> `CAP_SIGNALING_REFLECT` with them. The core is three verbs, `OPERATIONS` is
> three, and a `reflect` call is an ordinary unknown-operation 400. The two gate
> tests were kept and their assertions flipped from *blocked pending plumbing* to
> *not served here by design*.
>
> **The honest cost, recorded rather than dropped:** this shrinks Stage 1. It had
> been credited with standalone NAT-type-detection value; that value moves to
> Stage 2 with `reflect`. What it buys is that §2.1's "identical across surfaces"
> becomes *exactly* true rather than nearly true — `reflect` was the one verb
> that never could have been, because it was never an operation on the mailbox.

**Date:** 2026-07-28. **Status:** Stage-1 limit; refuses loudly (501). Needs an
arch call before `reflect` can ship on the wrapped surface at all.

**Spec:** `PROPOSAL-CONNECTION-NODE` §1 (`reflect` → `{ observed_address, ... }`),
§2 (the wrapped surface is "an ordinary entity handler operation"),
`HANDOFF-2026-07-28-connection-node-staging-and-sequence` §8 sequence step 1
("`reflect` first, then `offer`/`collect`").

**Passage.** The build sequence puts `reflect` first in Stage 1, and Stage 1's
handler shape is "plain dispatch, both sides" — i.e. `reflect` is expected to be
servable over cross-peer `execute`.

**The gap (verified in source at `ae93443`).** A handler cannot learn the
caller's source address:

- `Connection` carries it — `remote_addr: String`, set at accept time
  (`core/peer/src/transport.rs`, both the TCP and WebSocket listeners).
- The dispatch seam drops it. `handle_request` (`core/peer/src/connection.rs`)
  derives only `session_peer_id` from `conn.remote_peer_id` and calls
  `dispatch_request(envelope, shared, session_peer_id)`; `remote_addr` is in
  scope at that call site and is not passed.
- `HandlerContext` has no field for it, and its doc comment declares the
  16-field count "a reviewed ceiling ... Reject convenience additions; if an
  extension needs more, find a side channel."

Adding a 17th field would be precisely the "new context field to paper over a
gap" that `AGENTS.md` routes upstream instead of inventing, and would also break
`PROPOSAL-CONNECTION-NODE` §3's isolation constraint ("no edits to shared core
crates to accommodate it").

**Interim choice.** The extension declares its own injected
`ObservedAddressSource` trait (`extensions/signaling/src/handler.rs`) — the same
shape RELAY uses for `RelayForwarder`, owned entirely by the extension. **Nothing
in-tree can satisfy it over the wrapped surface**, so `cmd/entity-signaling-node`
wires none and `reflect` returns **501 `observed_address_unavailable`**. A loud
refusal, never a fabricated address: a peer derives its NAT type from *agreement
across reflectors* (`PROPOSAL-NETWORK-REACHABILITY-FACTS` §0), so a plausible lie
would be concluded on rather than discarded. `offer`/`collect`/`advertise` are
unaffected and fully live.

**The observation worth arch's attention.** This may not be a plumbing gap so
much as `reflect` belonging to the **unwrapped** surface by nature. Its whole job
is to report a transport-level source address — precisely the layer the entity
wrapper exists to abstract away. Even fully plumbed, the wrapped surface could
only ever report the *TCP/WebSocket* mapping of an already-established entity
connection, while the punch needs the *UDP* mapping; §5.1 already names "plain
STUN" as the obvious fit for `reflect`. If that is right, then §8's "reflect
first" is the one Stage-1 item that is actually Stage-2 work, and Stage 1's
honest deliverable is `offer`/`collect`/`advertise` — mechanism for the
rendezvous, with NAT-type detection arriving with the unwrapped surface.

**Question for arch.** Either (a) confirm `reflect` is unwrapped-surface-only and
drop it from the Stage-1 gate, or (b) rule on how an observed source address
legitimately reaches a handler — a decision about the handler abstraction's
boundary, not about signaling, and plausibly in scope for
`PROPOSAL-SDK-HANDLER-OWNED-SERVICES` (a handler that owns a listener owns the
socket, and therefore the observation).

---

## ~~PROPOSAL-CONNECTION-NODE open item 3 — bucket TTL default has no number~~ RESOLVED

> **RESOLVED 2026-07-28 — arch ruling 3**, landed as `PROPOSAL-CONNECTION-NODE`
> §1.1 pin 6; open item 3 closed. **60 s**, exactly as the interim shipped — no
> Rust change beyond documenting it as a pin. Node-configurable and published in
> the `advertise` limits.
>
> The rationale arch attached is worth keeping, because it is not the one the
> interim was chosen on: the TTL is bound by the lifetime of *what the blob
> describes*, not by node memory. An `srflx` candidate dies with the NAT binding
> that produced it (commonly 30–120 s), so a longer TTL only serves candidates
> that are already unpunchable.

**Date:** 2026-07-28. **Status:** interim value chosen; arch owns the number.

**Spec:** `PROPOSAL-CONNECTION-NODE` §5 open item 3, which pins the TTL's
*semantics* in §1.1 ("advisory to peers, binding on the node") and explicitly
leaves the value open: "pinned advisory in §1.1; the default *value* still needs
a number."

**Interim choice.** `Limits::default().bucket_ttl_ms = 60_000` (60s), overridable
via `--ttl-ms` (`extensions/signaling/src/core.rs`). Rationale: generous for a
handshake with retries, short enough to keep §4's "transient ~1 KB per handshake"
footprint honest. The sibling limits are interim on the same basis —
`max_message_bytes = 4096` (§4 sizes a handshake at ~1 KB),
`max_messages_per_key = 32` (`lobby`/`tag` are multi-party), `max_keys = 65_536`.

**Why it matters slightly more than a tuning knob.** The TTL is published through
`advertise`, so peers size their retry loops against it; and open item 2 (the
public mode's rate-limit shape, where "the rate limiter is the *entire* admission
story") will want to be set against the same capacity model. Worth one number
from arch rather than three impls each picking their own.

---

## ~~PROPOSAL-REGISTRY-SERVICE-ADVERTISEMENT §3.1 — rendezvous-hash is pinned as a *rule*, but its weight function is unpinned bytes~~ RESOLVED

> **RESOLVED 2026-07-28 — arch ruling 4**, landed as
> `PROPOSAL-REGISTRY-SERVICE-ADVERTISEMENT` §3.1.1 (new). All four free variables
> this entry enumerated are pinned to bytes:
> `weight(k, endpoint) = SHA-256( k ‖ endpoint_bytes )`, argmax with weights
> compared lexicographically, **highest** wins, ties to the **lower** endpoint;
> `k` is the 33-byte key exactly as derived; `endpoint_bytes` are the advertised
> string exactly as published (no normalization — same rule and reason as §2.2's
> string inputs); no separator, *because* `k` is fixed-width; and a plain
> SHA-256, explicitly **not** the substrate content-hash primitive, since a
> format-carrying digest would reintroduce the home-format divergence §2.2 exists
> to pin away.
>
> **One substantive change from the interim: `priority` partitions, it does not
> weight.** "Tier the pool by weighting the hash" is withdrawn — a weighting
> function is itself unpinned bytes, and stacking a second invented rule on the
> first is worse than not tiering. The rule is now: take the **lowest `priority`
> tier present**, then rendezvous-hash within it.
>
> **Rust delta (landed):** the construction was already right, including the
> direction (this entry's write-up said "lexicographic" without saying which end
> wins; the code picked highest, which is the pin). Added: the tier partition
> ahead of the hash in both `select` and `select_top`, and tests for the
> partition, the lowest-tier-**present** failover, and the argmax direction
> checked against an independently recomputed digest.
>
> **The validation gap this entry flagged was accepted and acted on.**
> `PROPOSAL-CONNECTION-NODE` §6 step 2 now requires a **two-instance pool** in
> the gate, on the reasoning quoted from here: `argmax` over one member returns
> that member whatever the weight computes, so §1.2's "three independent clients
> converge" mitigation does not reach the selection rule. A second instance is a
> second port on the same box (§1.3, stateless), so an unvalidatable pin became a
> validated one for a config line. Landed locally as
> `gate_step_2_pool_selection_converges_over_a_two_instance_pool`.

**Date:** 2026-07-28. **Status:** interim construction landed; **routed to arch as
the fourth §1.1-class question.** Surfaced building the Stage-1 client
(`extensions/signaling/src/pool.rs`, `feat/signaling-connection-node`).

**Spec:** `PROPOSAL-REGISTRY-SERVICE-ADVERTISEMENT` §3.1 (intra-pool selection),
read with `PROPOSAL-CONNECTION-NODE` §2.1 (same-provider rule) and §1.2 (what to
do with a question of this kind).

**Passage.** §3.1 pins signaling's intra-pool selection as a **MUST**:

> **client-side rendezvous-hash (MUST).** Both peers compute
> `k = rendezvous_key(sorted(peer_a, peer_b))` and
> `server = rendezvous_hash(k, pool)` (highest-random-weight) → **both
> independently pick the *same* server** for the handshake. **NOT** lowest-`priority`.

and states the failure it prevents: "Naive priority-order or a round-robin LB
**splits the pair across servers** and the punch never completes."

**Ambiguity.** §3.1 pins **that** selection is rendezvous-hash, and pins why. It
does not pin **what bytes go into the weight**. "Highest-random-weight" names a
family, not a function. At least four free variables, each of which two impls
can resolve differently while both being "correct HRW":

1. **Operand order** — `H(key ‖ endpoint)` vs `H(endpoint ‖ key)`.
2. **The digest** — SHA-256 is the obvious floor, but nothing says so, and the
   substrate's own hashes are format-carrying (the §2.2 trap, one layer up).
3. **Member identity** — the advertised `endpoint` URL byte-for-byte, or the
   node's `peer_id`, or a normalized URL. A peer that strips a trailing slash or
   lowercases a host weights a different string.
4. **Weight comparison** — the digest as a big-endian integer, little-endian, or
   a truncated prefix; and how a tie breaks.

**This is the same failure shape as §2.2, one layer out.** Two peers that derive
a byte-identical rendezvous key and then select different pool members meet
nobody — no error, no log, nothing to bisect. It is equally invisible to a
same-impl test (one impl always agrees with itself, so a "both peers converge"
test passes trivially), and it becomes load-bearing the moment a pool has more
than one member. `PROPOSAL-CONNECTION-NODE` §1.2 says: "If a fourth question of
the §1.1 kind surfaces during the build, it comes back here as a spec fix — it
does not get settled in the Rust." **This is that fourth question.**

**Interim choice (landed, explicitly not a pin).**
`weight = SHA-256( key_bytes ‖ endpoint_utf8 )`, compared lexicographically over
the 32 digest bytes (highest wins), ties broken on the lower endpoint string. No
separator between operands — the key is a fixed 33 bytes, so the concatenation is
self-delimiting and §2.2's `pair` ambiguity cannot arise. `priority` is **not**
folded into the weight: §3.1 allows a pool to be tiered by weighting the hash,
but that weighting is itself unpinned, so v0 ignores it rather than inventing a
second unpinned rule on top of the first.

Also implemented: §3.1's stale-pool-skew SHOULD as `select_top(key, pool, 2)`,
with a test that two peers whose pools differ by one member still share a choice.

**Urgency: not a Stage-1 blocker.** §4 deploys **one** instance, and against a
single node there is nothing to select — a client can be pointed straight at it,
and `argmax` over a one-member pool returns that member whatever the weight
function computes. So Stage 1 ships regardless, and the Rust client's
implementation is ahead of what Stage 1 needs rather than blocked on this.

**But it is also not *validatable* by Stage 1, for the same reason.** Unlike §2.2
— which the live cross-impl run genuinely settles — this one is invisible to the
gate as sequenced (`HANDOFF-2026-07-28...` §8 step 4: go and py peers against one
Rust node). Every HRW construction agrees on a single-member pool, so a green gate
says nothing about it. Two impls first disagree at pool size ≥ 2.

**Question for arch.** Pin the weight construction — the four variables above —
**before the first deployment runs a signaling pool of two or more**, which is
also before the go/py clients implement selection rather than a configured single
endpoint. Since experiment can't settle it at Stage-1 scale, it wants pinning by
inspection, or a deliberate two-node pool added to a later gate. Flagging the
*validation* gap explicitly because §1.2's mitigation — "three independently
-written clients hitting the server from outside is a real convergence signal" —
does **not** reach this one: the clients converge trivially here no matter what
they implement.

---

## PROPOSAL-CONNECTIVITY-SIGNALING-AND-PUNCH §3 — the message table still calls `fire_at` an *instant*, which §4.1 pins as the one thing it MUST NOT be

**Date:** 2026-07-29. **Status:** built to §4.1 (the pin); **the §3 table's wording routed
to arch as a one-line strike.** Surfaced implementing the §4.1 pin
(`extensions/signaling/src/coordination.rs`, `feat/signaling-connection-node`).

**Spec:** §4.1 (`fire_at` derivation, pinned 2026-07-28) read against §3 (the
coordination-message table) and §9 conformance MUST #5.

**Passage.** §4.1 pins the clock domain as a MUST, and names the failure:

> **Clock domain — relative, never absolute (MUST).** `fire_at` is a **delay from the
> receiving peer's moment of receipt** of the `punch-sync` entity, encoded as
> **unsigned integer milliseconds**. It is *not* a timestamp.

§9 carries the same thing as conformance MUST #5. But §3's message table — the part an
implementer reads to build the wire shape — still says:

> `data: { nonce: <echo>, fire_at: <carrier-RTT-derived instant> }`

**The contradiction.** "Carrier-RTT-derived" is right and is the half that survived; the
noun is wrong. An implementer building from the table encodes an instant, which is
precisely what §4.1 forbids, and §3 is the section a wire shape is naturally built from.

**Why this is worth a strike rather than a note.** It is the same class as §10's
`SEP`/mode-tag bullet (closed 2026-07-28), but with more teeth, and this repo is the
existence proof: **Rust built `fire_at` as a signed `i64` holding milliseconds since
epoch, with a test vector of `1_700_000_000_500`** — a wall-clock instant, from the
pre-pin text, and it round-tripped green. §4.1 says why that is not caught: the failure
"passes every same-host test", because both peers read the same clock. Two facts make it
urgent rather than cosmetic:

- **Every impl in the cohort is about to build this field.** The go/py packet is issued;
  §3 is where its message shapes come from.
- **The error is silent and terminal.** Skew between two machines' wall clocks is
  routinely larger than the entire punch window, so the punch simply never lands while
  each side reports every step succeeding.

**Rust delta (landed, no interim needed — §4.1 is pinned):** `PunchSync.fire_at` is `u64`
milliseconds-from-receipt, encoded as a CBOR uint (major 0) and refused at decode if
negative. `punch_delay(rtt) = max(rtt, 250)` implements §4.1's default with its `d ≥ rtt/2`
MUST held as a property test across the range, so the guarantee survives someone retuning
the floor — which §4.1 and §9 explicitly sanction — without touching the derivation, which
they do not. The encoding is asserted **on the bytes**, not through the decoder, since a
same-side round trip agrees with whatever the encoder wrote.

**Question for arch.** Strike or reword the §3 table's `<carrier-RTT-derived instant>` to
name the delay — e.g. `<uint ms, delay from receipt (§4.1)>` — **before go/py build item 1**.
One line, and it closes the last place in the corpus that still describes the field the way
the trap wants it described.

---

## ~~PROPOSAL-NETWORK-REACHABILITY-FACTS §2.1(b) — how the observed address reaches the handler serving `observe-address` is unspecified, and in Rust there is no path~~ RESOLVED

> **RESOLVED 2026-07-29 — folded as `EXTENSION-NETWORK` §6.7.1** (v1.5, Amendment 13). The
> question this entry asked is answered in the landed spec, in the passage *"What it costs to
> implement, stated plainly"*: the general handler context is deliberately **not** widened, and
> **"a narrow, NETWORK-scoped accept-side path from the connection to this operation is the
> intended shape,"** with where it sits in a given impl's layering left explicitly to that impl.
> The cost is now in the spec rather than attached to a ruling — *"that it is a real addition,
> and not free, is not in dispute."*
>
> **Correction — one claim in this entry was wrong, and it was ours.** This entry asserted:
> *"No `peer_id → remote_addr` registry exists — searched for specifically."* **There is one.**
> `system/connection/{peer_id}` (ENTITY-CORE-PROTOCOL.md §3.13) is keyed by peer, carries an
> `address` field, and is already reachable from a handler — it lives in this very tree at
> `core/peer/src/connection_state.rs` (`ConnectionData::address`). Our search looked for
> Rust-level `HashMap`-shaped registries in three files and never looked for the entity-level
> connection-state record, then stated the absence as proven. That is exactly the failure
> `AGENTS-STANDARD` names: *"an absence claim from a partial grep is how false spec gaps get
> filed."* Ours was stated more strongly than it had been earned.
>
> **The conclusion survived, for a better reason than we gave — and arch found the better
> reason.** `system/connection` is the wrong record *twice*: its `address` means *the endpoint I
> dial to reach this peer* and is written **dialer-side** (this tree's own module doc says the
> responder "holds no dialable address for the remote and records nothing"), and one record per
> peer cannot express §6.7.3's **per-socket** mapping. So there is still no path to an observed
> source — but because the nearest record is semantically wrong, not because no record exists.
>
> **That correction produced a MUST.** §6.7.1 MUST #2 now forbids persisting `observed_address`
> to `system/connection.address`, a transport profile, or `system/peer/status`, naming
> `system/connection/{peer_id}` as *"the record an implementer reaches for first."* An ephemeral
> source port written there is a routable-**looking** value that routes nowhere, in the field §10
> and `system/peer/status` both consume as dialable. The cheap fix for the missing plumbing
> would have corrupted dispatch for every other reader.
>
> **Rust status: buildable, unbuilt, and not on this branch.** §6.7 is OPTIONAL as a whole
> (§12.3); every rule inside it is a MUST when offered (§12.1). It is NETWORK-scoped work with a
> core/peer accept-side seam, and it must not land on `feat/signaling-connection-node`, whose
> distinguishing property is `install.rs` asserting zero core edits.

**Date:** 2026-07-29. **Status:** ~~**not built** — arch ruled 2026-07-29 that (b) is the v1
path but `REACHABILITY-FACTS` is still DRAFT, so nothing is implementable yet.~~ **Superseded:
landed as `EXTENSION-NETWORK` §6.7.1 the same day.** Logged as an
input to the fold. Surfaced verifying that ruling's cost claim against this tree.

**Spec:** §2.1(b) (`system/network:observe-address() → {observed_address}`), read with §5's
`system/capability/network-reflect`.

**Passage.** §2.1(b) defines the op and its result, and the ruling that selected it states:

> an ordinary NETWORK extension op … no core edit, no handshake change, no shared-core file
> touched in any impl.

**The ambiguity.** §2.1(b) specifies *what the op returns* and never *where the responder gets
it*. That is normally an impl detail and would not be logged — except that in this
implementation there is currently **no path at all**, which makes it a shape the fold should
pin rather than leave to three impls independently.

**Evidence (Rust).** `system/network` is an ordinary handler pattern (`HANDLER_PATTERN`,
`extensions/network/src/lib.rs`), so the op dispatches through `dispatch_request` →
`HandlerContext`:

- `dispatch_inbound` (`core/peer/src/connection.rs`) extracts **only** `remote_peer_id`.
  `conn.remote_addr` is on the same struct at the same expression and is dropped; its only
  other use in the file is a `tracing::instrument` field.
- **No `peer_id → remote_addr` registry exists** — searched for specifically, since a lookup
  keyed on `ctx.session_peer_id` would have made the op free. `remote_addr` never escapes
  `core/peer`.
- `HandlerContext` carries no address, and its doc forecloses the easy fix: *"Reject
  convenience additions; if an extension needs more, find a side channel."*

**This is the same blocker as the deleted wrapped `reflect`** (the entry above,
*"§1 `reflect` cannot be served on the wrapped surface"*), which was RESOLVED by **moving the
verb**, not by building the plumbing. Mechanism (b) is an entity-protocol op over an
established connection, so it returns to that surface and meets the same wall.

**Question for arch.** At fold, say once how the observed source address reaches the handler —
a context field or the side channel this repo's ceiling doc prefers — so the three impls do
not each invent one. **No interim choice is recorded because nothing is built:** the op is
ruled but not landed, and `AGENTS-STANDARD`'s implement-against-the-landed-spec rule applies
to (b) exactly as it did to (a).

---

## PROPOSAL-NETWORK-REACHABILITY-FACTS §4.2 — the same-local-endpoint MUST implies a socket-options requirement on the v1 TCP substrate that is not stated

> **ACCEPTED 2026-07-29 — recorded by arch as signaling §5.1 + an open item.** The MUST itself
> folded as `EXTENSION-NETWORK` §6.7.3; the **TCP port-reuse cost** this entry identified is
> recorded against the substrate choice rather than the fact. Arch's read: it is a **G1 input,
> not a G1 reversal** — leaning that TCP-simopen-first stands, since "our-QUIC doesn't exist
> yet" remains the dominant term and the socket options are bounded work. **That is the
> operator's call, not arch's, and nothing is blocked on it.** Kept open here because the Rust
> position below is unchanged and unbuilt.

**Date:** 2026-07-29. **Status:** **not built** (Stage 2); routed as an input to the fold,
**accepted** and recorded against signaling §5.1. Surfaced tracing §4.2 against the 2026-07-29
gate-2 ruling.

**Spec:** `REACHABILITY-FACTS` §4.2 (added 2026-07-29), read with §2.1(b) and
`PROPOSAL-CONNECTIVITY-SIGNALING-AND-PUNCH` §5.

**Passage.** §4.2:

> A peer publishing a `srflx` candidate MUST punch from the **same local endpoint** whose
> mapping was observed. One gathered on one ephemeral socket and punched from another is not
> the peer's address — it describes a hole that will never open.

**The unstated consequence.** Three decisions now compose: §2.1(b) observes the mapping on an
**established entity-protocol connection** (so it is that connection's socket), §5 sequences
**TCP simultaneous-open** as the v1 substrate, and §4.2 requires the punch to leave from that
same local endpoint. On TCP that is **not satisfiable by discipline** — it requires
`SO_REUSEADDR`/`SO_REUSEPORT` plus an explicit local bind, the standard TCP hole-punch
technique, because a NAT allocates a mapping per local socket and a fresh ephemeral socket
gets a different external port (which is §4.2's own reasoning).

On UDP/QUIC the requirement is trivial — one socket, many destinations — which is why standard
STUN over UDP is clean, and §5 already notes NATs punch UDP better. §5 chose TCP first
*because it reuses what ships*; this is the one thing it does not reuse.

**Rust position.** Unbuilt and correctly so — Stage 1 does not punch. The dial path is
`TcpStream::connect(host_port)` (`TcpTransport::connect`, `core/peer/src/transport.rs`) with an
OS-assigned ephemeral local port: no `socket2`, no bind control, no reuse. Noted here because
it is a Stage-2 cost that is currently invisible, not because it is wrong today.
**Narrower than our first read:** `handle_connection` is public and documented as accepting any
transport's `Connection`, so *adopting* a punched connection needs no new seam — only the dial
side is missing.

**Why it wants stating rather than discovering.** It is §4.2's own failure costume one layer
down: the symptom is "the punch didn't land", indistinguishable from a `fire_at` miss, and
§4.2's instruction to bisect endpoint identity before timing does not reach an implementer who
does not know a socket-options requirement exists.

**Question for arch.** Make the socket requirement explicit in §4.2 (or in §5's TCP-simopen
row) — that same-local-endpoint on TCP means binding the punch socket to the reflector
connection's local port with address/port reuse.

---

## `EXTENSION-SIGNALING` §8.1 — capability names, and the missing one for `advertise`

**Passage.** §8.1 Admission: *"`system/capability/signaling-use` gates `offer` / `collect`. A
deployment serving a private device mesh grants it narrowly; `advertise` is typically
operator-only."* (`EXTENSION-SIGNALING.md` v1.0 @ arch `4241b96`.)

**The ambiguity.** The passage names **one** capability and covers **two** verbs with it. For
the third verb it gives a *policy* ("typically operator-only") but **no capability name**, so
"implement §8.1" is underdetermined: an implementation must either invent a name for
`advertise`'s capability — the thing an implementation is not allowed to do — or gate
`advertise` on `signaling-use` too, which contradicts the sentence that distinguishes them.

**Interim choice.** Rust keeps its three existing names (`system/capability/signaling-offer`,
`-collect`, `-advertise`) unchanged pending a ruling. Renaming to `signaling-use` unilaterally
would change the grant strings on the live node every cross-impl run uses, and would move Rust
away from Py — which carries `signaling-offer` / `signaling-collect` — while moving it toward
the spec. That is a cohort migration, not a spec-conformance edit, and it is not completable
for `advertise` from the text as written.

**Question for arch.** Confirm `system/capability/signaling-use` as the single offer+collect
capability, and either name the `advertise` capability or rule that `advertise` is grant-policy
over `signaling-use` rather than a distinct capability. Then all three impls move together.

## `EXTENSION-SIGNALING` §9.2 — does the closed error enum bind the wrapped surface?

**Passage.** §9.2: *"Error codes (closed enum)"* — `message_too_large`, `bucket_full`,
`bad_request`, `rate_limited` — *"Services MUST NOT invent codes outside this set."* The
section sits inside **§9, The Unwrapped Protocol**.

**The ambiguity.** §2.1 pins the core as wrapper-agnostic and implemented once, and §2.2 warns
against a verb "completable on one surface only." An error vocabulary that differs by surface
is arguably that same divergence — but §9.2 is scoped to §9 by placement, and the wrapped
surface's error entities are `SDK-OPERATIONS`'s vocabulary, not this spec's. The text does not
say which reading holds.

Two concrete consequences in Rust today (`extensions/signaling/src/lib.rs`): the wrapped
surface emits `invalid_params` where §9.2 says `bad_request`, and it emits
`capacity_exhausted` for a `max_keys` refusal — **a condition §9.2's enum has no member for
at all**, so the closed enum cannot express a refusal the node genuinely makes.

**Interim choice.** Unchanged. Rust serves only the wrapped surface, so nothing is
non-conformant today under either reading; the codes are left as they are rather than guessing
at a mapping that a §9 build would then have to unpick.

**Question for arch.** Does §9.2's closed enum bind the wrapped surface too? If so, what is the
unwrapped code for a keyspace-capacity refusal — `rate_limited`, or does `max_keys` have no
unwrapped expression (in which case the enum needs a member or §5 needs to say the limit is
unpublishable)?

---

## ~~`EXTENSION-SIGNALING` §7.1 step 4 — who dials and who accepts is unpinned~~ RESOLVED

> **RULED 2026-08-01 — arch `b3ff6ad`, `ROUTING-2026-08-01-punch-dual-hole-ruling-and-rung3`.
> The interim choice below was WRONG and is retracted.** §7.1 step 4 now carries a
> `[cross-peer seam — MUST]` note: *"Each peer **MUST** issue an outbound connection attempt at
> `fire_at`; **listening alone opens no hole**, because only an outbound packet creates the local
> NAT mapping. A peer that merely accepts (TCP-passive) never opens its own hole, so the
> counterpart's SYN reaches a closed NAT and the punch **cannot traverse**."* §7.4.1 gains the
> matching de-conflation: *"'Serves' is a handshake role, not a socket role."*
>
> **The three layers, which the retracted shape collapsed into one:**
>
> | Layer | Rule | Decided by |
> |---|---|---|
> | Hole-opening | **both** peers fire outbound at `fire_at` | *nothing* — always both |
> | Socket selection | one of the racing sockets survives | peer-id compare (local, MAY) |
> | Handshake role | initiator speaks HELLO; responder serves | §7.4.1 (signaling role) |
>
> **Built in Rust 2026-08-01.** `punch.rs::cross` runs the dial loop and the listener concurrently
> and unconditionally on both sides; `crossing_role` survives demoted to socket selection
> (`CrossingRole::{KeepDialed, KeepAccepted}`). Both peers' outbound attempts are asserted
> explicitly — `punch::tests::initiator_and_responder_meet_and_cross` and
> `punch_establisher::tests::two_peers_punch_through_a_real_node` via
> `PeerPunchEstablisher::outbound_attempts` — because that assertion is the *only* part of the MUST
> loopback can reach. Both were confirmed to fail against a re-injected listen-only build.
>
> **Still unproven, and the ruling says so:** every punch to date is loopback. Whether the holes
> actually open is the §11.5 cross-NAT gate (G3 emulated / G4 real), which has never run anywhere.
>
> **One residual, routed rather than filed.** The tiebreak's stated premise — *"two connections can
> form, each side's dial landing on the other's listener"* (Go's `fire` comment, and this entry
> below) — does not hold under the punch's own geometry: both peers dial from a fixed local endpoint
> to the counterpart's fixed advertised endpoint, so there is exactly **one** possible 4-tuple and
> therefore one connection. Which local socket holds our end of it is the kernel's call and the two
> peers may answer differently *about the same connection*. Rust therefore takes whichever socket
> materializes and applies the tiebreak only when both do; insisting on the preferred socket cost
> `two_peers_punch_through_a_real_node` 1.0 s → 7.7 s waiting for a second connection that cannot
> exist. Two connections *can* form where a counterpart dials from an endpoint other than the one it
> advertised, which is what keeps the tiebreak. Carried to Go in the 08-01 routing packet.

*Original entry, retained for the record:*

**Passage.** §7.1 step 4: *"**Simultaneous open.** Each side sends to the other's `srflx`. Each
side's *outbound* packet punches its own hole; the other's packet, arriving after that hole is
open, gets through."* (`EXTENSION-SIGNALING.md` v1.0 @ arch `acf3b24`.)

**The ambiguity.** Taken literally — both sides only dial — the crossing completes solely in the
narrow instant both sockets sit in `SYN_SENT` simultaneously. Outside that window each dial is
refused, because neither peer is listening. **Both reference implementations therefore also listen
on the shared `SO_REUSEPORT` port**, which is sound and which §7.2 arguably licenses ("socket
options... stay local and MAY diverge"). But listening creates a second question the spec does not
answer: *two* connections can now form — each side's dial landing on the other's listener — and the
two peers must agree on which one survives, or they keep opposite ends of different connections.

**This is a cross-peer convention wearing the costume of a socket detail.** It is the §7.4.1 shape
exactly: a rule two peers must share, derived from nothing on the wire, invisible to any
same-implementation test (both ends of a Go↔Go punch make the same choice), and reported as *"the
punch didn't land"* — which sends the investigation to the NAT layer, where nothing is wrong.

Concretely, if the two impls pick opposite rules then in **half of all pairings** both peers listen
and neither dials; in the other half both dial into a closed port. Neither half completes.

**Interim choice.** Rust matches Go: **the lower peer-id dials, the higher listens and accepts**
(`crossing_role`, `extensions/signaling/src/punch.rs`; Go's `fire`, `ext/signaling/punch.go`).
Chosen for interop, not on merit — Go built it first and a divergence here is unrecoverable
without a cohort round trip. Note this is independent of §7.4.1's *handshake* role, which follows
the signaling role regardless of which end dialed the TCP connection.

**Also unresolved beneath it:** Go's own comment records that the dial/listen split is
*loopback*-reliable, and that under real NAT the **listening** side must additionally emit an
outbound packet toward the dialer's `srflx` to open its own mapping before the dial arrives.
Neither impl has built that dual-hole sequencing, and the §7.5 cross-NAT gate has never run
anywhere — so the convention above is agreed but **unproven against a real NAT**.

**Question for arch.** Pin the crossing role beside §7.4.1's handshake role — the lower-peer-id
convention if it stands — and state whether listening on the shared port is conformant with step
4's "each side sends", since the answer determines whether the dual-hole sequencing is a §7.5
hardening detail or a correction to step 4 itself.

## ~~§6.3's peer-id derivation is the legacy form both implementations refuse to mint~~ RESOLVED

> **RULED 2026-08-04 — arch `PROPOSAL-EXTENSION-SIGNALING-COORDINATION-ENVELOPE` §2, cohort-reviewed
> (Go blocking 1 absorbed). The interim choice below was RIGHT and is now normative — with one
> addition it did not anticipate.** Check (a) is restated as a derivation rather than a spelled-out
> byte string: derive the id canonically from `(public_key, key_type)` and require the envelope's
> `signer` to equal it **in full**. The addition is *verified-then-used*: `signer` is a wire field
> and therefore forgeable, so it is never trusted as given, and a well-formed but **non-canonical**
> `hash_type` is `unusable_key` rather than an accepted alternate form. Admitting it would give one
> key two valid ids, and every §6.5 decision is a sort over that id — a chosen id is a chosen glare
> role and a split rendezvous bucket.
>
> **Built in Rust 2026-08-04.** `extensions/signaling/src/envelope.rs::open` steps 1–2; fenced by
> `a_non_canonical_hash_type_is_unusable_even_though_it_names_the_right_key` and by the
> `ed25519/non-canonical-hash-type` cross-impl row (`cmd/webrtc-vectors`, surface 5).
> The stale form is also corrected in `coordination.rs`'s module doc; arch is routing the same
> correction through `ENTITY-SYSTEM-REFERENCE.md:75/601` (#67).

<details><summary>Original entry</summary>


**Passage.** `EXTENSION-SIGNALING.md` §6.3 *The signature* `[security — MUST]`:

> A verifier (a) recomputes `Base58(0x01 ‖ 0x01 ‖ SHA-256(public_key))` and checks it equals the
> claimed `initiator` / `responder` peer-id […]

**The ambiguity.** That literal derivation is `key_type = 0x01` ‖ `hash_type = 0x01` — the
**SHA-256 form**, which the core protocol made legacy-decode-only in V7 §1.5 v7.65 Amendment 3
(canonical form is identity-multihash, `hash_type = 0x00`). Both reference implementations
therefore **refuse to mint it**, by explicit design and with the amendment cited in the refusal:

- Rust — `PeerId::from_public_key_with_hash_type` returns `InvalidPeerId` for `HASH_TYPE_SHA256`
  ("SHA-256-form is legacy-decode-only for Ed25519", `core/crypto/src/lib.rs`).
- Go — `PeerIDFromPublicKeyWithHashType` errors with "v7.65 §4 / v7.66 §3 — Ed25519 canonical
  hash_type is 0x00 […] no mint API path is provided" (`core/crypto/peerid.go`).

So an implementer following §6.3 **literally** cannot perform check (a) with either implementation's
API. The failure mode is quiet in the worst way: a derivation that did produce the legacy form would
compare unequal against every canonical-form peer-id, and §6.3 says a message failing the check
**MUST be skipped exactly as an undecodable one is** — never an error. Every coordination message
would be silently discarded and the rendezvous would simply never complete.

**Interim choice.** Derive the peer-id with the ordinary canonical derivation
(`PeerId::from_public_key`, identity-multihash) rather than §6.3's literal string, matching Go's
`PeerIDFromPublicKey` — which selects `CanonicalHashType(keyType)` for the same reason. The two
impls already agree here, so this is spec staleness rather than an interop divergence; it is logged
because a third implementer reading §6.3 alone would build the broken form and see only silence.

**Question for arch.** Restate §6.3's check (a) in terms of *the* canonical peer-id derivation
rather than a spelled-out byte string, so it cannot drift from the core spec's canonical-form
mandate again. If the spelled-out form is retained for clarity, it needs to be the identity-multihash
form and to carry a pointer to V7 §1.5 v7.65 Amendment 3.

</details>

## ~~§6.3's `key_type = 0x01` — is a coordination signer restricted to Ed25519, or is that a simplification?~~ RESOLVED

> **RULED 2026-08-04 — same proposal, §4. Illustrative, not a constraint — the interim choice below
> was right, and one sentence of it is now WRONG and retracted.** `key_type` is parametric; Ed25519
> (`0x01`) is the **MUST-implement floor, not the ceiling**. A well-formed but *unsupported*
> `key_type` MUST be treated as an undecodable blob and **skipped** (MUST-ignore, ADR-0002) —
> never hardcode-rejected.
>
> **Retracted:** the last line of the interim choice below — *"An unallocated or sign-incapable
> `key_type` is refused as `SignerMismatch` (a signer fault)"*. That name codes the case as *"this
> peer is lying,"* which is the reading that justifies a hardcoded reject — and a hardcoded reject
> is exactly what locked out an Ed448 identity this codebase mints. It is now **`unusable_key`**,
> the third of the cohort's three settled names; `signer_mismatch` is reserved for the §6.1 claim
> comparison, where a peer really did assert an identity its signature does not support.
>
> **Built in Rust 2026-08-04.** `SignalingError::UnusableKey`; `verify_coordination_signature` and
> `envelope::open` remapped. Fenced by `a_well_formed_unsupported_key_type_is_unusable_not_a_false_claim`
> and the `unsupported-key-type/0xfe` cross-impl row. No already-crossed vector row changed outcome.

<details><summary>Original entry</summary>


**Passage.** `EXTENSION-SIGNALING.md` §6.3 *The signature* `[security — MUST]` — the same sentence as
the entry above:

> A verifier (a) recomputes `Base58(0x01 ‖ 0x01 ‖ SHA-256(public_key))` […]

**The ambiguity.** The entry above treats the *second* `0x01` (the `hash_type` axis). This one is
about the **first**: `key_type = 0x01` is Ed25519. §6.3 never says whether that is a *constraint on
who may sign a coordination entity* or merely the common case written out longhand. The two readings
are not distinguishable from the text, and they differ in observable behaviour:

- **Restriction reading** — an Ed448 identity may not sign `webrtc/offer` / `answer` / `candidate`,
  and a verifier must refuse `key_type = 0x02`.
- **Simplification reading** — §6.3 describes the derivation generically and the key type travels
  with the key, as it does everywhere else in V7.

This matters because Ed448 is not hypothetical here: V7 §1.5 v7.67 §3 allocates `KEY_TYPE_ED448 =
0x02`, both implementations mint Ed448 identities (`Ed448Keypair::peer_id`,
`PeerIDFromPublicKeyWithHashType`), and `core/peer/tests/cohort_compare_v767_phase1.rs` already
cross-validates ed448-goldilocks against Go's CIRCL. So an Ed448 peer is a peer this ecosystem
produces, and under the restriction reading it simply cannot use WebRTC coordination.

The failure mode is the same quiet one as the entry above, and for the same reason: §6.3 says a
message failing the check **MUST be skipped exactly as an undecodable one is**. An Ed448 peer's
offers would vanish with nothing anywhere naming the key type as the cause.

**Interim choice.** Dispatch on `key_type` rather than hardcoding Ed25519 —
`verify_coordination_signature` (`extensions/signaling/src/webrtc.rs`) decodes it via
`KeyType::from_byte`, verifies through `verify_for_key_type`, and derives via
`PeerId::from_public_key_with_key_type`. This interoperates with **either** ruling: under the
simplification reading it is correct, and under the restriction reading it is over-permissive in a
way that admits no confusion attack, because the peer-id embeds the key type — an Ed448 key derives
an Ed448 peer-id and cannot present itself as an Ed25519 one. An unallocated or sign-incapable
`key_type` is refused as `SignerMismatch` (a signer fault), distinct from `BadSignature`.

Go implemented the same way and reached it independently; this was surfaced by their §6.5 vector file
(`docs/validation/vectors/webrtc-coordination-go.cbor` @ `f464e0a`), which crosses an `ed448/valid`
row **deliberately** to localize exactly this bug. Rust's pre-fix
`verify_coordination_signature` refused `key_type != 0x01` outright and would have failed that row.
Carried by core-go as the third of three pins on their §6.3 spec issue.

**Question for arch.** State explicitly whether §6.3's `0x01` constrains the signer's key type or is
illustrative. If illustrative, spell check (a) parametrically over `key_type` as the rest of V7 does.

</details>

---

<details>
<summary><b>§6.5 symmetric originate — who authorizes the answerer's outbound dispatch?</b>
(EXTENSION-SIGNALING §6.5 trigger (b) × GUIDE-CONFORMANCE §7a.2a) — <i>2026-08-05, live rung-1 run</i></summary>

> **RESOLVED — IMPLEMENTED + VALIDATED (2026-08-05):** ruling **option 1 (mutual minting)** selected
> by the maintainer, implemented in this repo, and proven on the rung-1 two-browser rig (BIDIRECTIONAL
> 2/2, roles swapped) plus a native regression guard (`test_s65_acceptor_originates_after_reciprocal_
> grant`). The acceptor now acquires originating authority from the dialer's reciprocal reentry grant.
> Design spec + validation: `docs/PROPOSAL-SYMMETRIC-REENTRY-MUTUAL-MINTING.md`. Routing to
> `entity-system-architecture` for cross-impl pinning (the wire addition is protocol-visible).
>
> **SCOPED AND CLOSED ON OUR SIDE (2026-08-05):** arch reframed the proposal on establishment
> symmetry (rev 3, `entity-system-architecture` `5f62374`) and ruled the discriminator onto the
> **rendezvous key**: mint iff a §3 key (`pair`/`tag`/`secret`/`lobby`) was mutually brought —
> locally derived, never wire-carried. Narrowing built here: `LivePath.established_via_rendezvous_key`
> gates the mint, so a dial-by-address no longer grants reciprocal authority (both establishers in
> this crate report `true` — the §7 punch meets at the §3.2 `pair` key). The §6.11(b) consumer this
> repo reported is resolved by the same ruling as **row 2**, not row 3: async inbox delivery now
> authorizes under the caller's `deliver_token`. Remaining: arch folds the spec text on core-go's
> ack. See `docs/status/ROUTING-2026-08-05-the-narrowing-is-in-and-the-discriminator-confirmed-to-arch.md`.
>
> **FOLDED (2026-08-06):** arch folded Q1–Q4 + a new reach-back-serving MUST at
> `entity-system-architecture` `f8f736a`. Absorbed here: **Q2** — the reciprocal grant is now the
> §4.4 **assembled** inbound-dialer grant, not the flat floor (`connection::assemble_inbound_grants`,
> one assembly, two callers); **Q3** — `remote::RECIPROCAL_GRANT_VECTOR_FLOOR_MS` names the
> conformance floor separately from our impl-local `REENTRY_GRANT_POLLS`; the **reach-back-serving
> MUST** was already satisfied (dialer-side §6.11(b) reentry has been wired since `0eccb3f`). One
> sub-clause of Q2 is *not* closed here — see the advertisement-filtering entry below. **Q1 (carriage)
> is core-go's push-back, not ours**, and this repo ships the same connect-phase-frame shape they do.
>
> **Q1 update, 2026-08-05.** Arch ruled a two-phase carriage: deliver the cap's **content hash**,
> wield via the §7a.2a triple **as references** the granter resolves. `entity-core-go` reviewed it and
> recommends **adopting phase (2), keeping phase (1)** — a bare hash contradicts the mint bullet two
> paragraphs above it in the same §6.5 (b) ("verify the granter signature at acceptance … MUST check
> only the legs the frame carries": a hash carries none) and leaves the acceptor holding something it
> cannot open or fail closed on. It also reuses §7a.2a's ratified field names with a different payload
> type, which is a ×N keystone change or a type-discriminate-by-context ambiguity. **This repo concurs
> and has built the phase (2) receiver only.** The carrier question we filed is answered by Go and
> needs no ruling: `EXECUTE uri=system/protocol/connect operation=reentry-grant` is a new *operation*,
> not a new frame, and is already what both impls ship — only the `params` payload was ever at issue.
>
> **What is built here (`connection::dispatch_request`, `PeerShared::minted_reentry_grants`):** the
> receiver supplies the triple from what it minted **and delivered** to that specific counterpart, on
> a retry taken only after a first verification failure. That ordering is what makes it landable ahead
> of the flag day: a frame carrying today's inlined chain verifies on the first attempt and never
> reaches the new path, so the shipped wire shape cannot move. **The sender still inlines** —
> `originating_chain_bundle` is untouched, and deleting it is the flag day proper, to be flipped with
> Go and the vector file re-emitted. Two things the build confirmed that the text does not say, both
> matching Go's findings independently reproduced here:
>
> 1. **The supplier must not be a content-store lookup.** Read literally, "resolves from its own
>    content store" makes *naming* a cap equivalent to *holding* it — a cap minted and never delivered
>    becomes wieldable. `grantee == author` still binds it to the named peer, so this is not
>    third-party escalation, but it erases "we minted this for you" from "you hold this". Scoped to
>    minted-and-delivered, keyed by recipient, written only after the frame write succeeds.
> 2. **A naive flip emits a *partial* reference frame, not a references-only one.**
>    `build_authenticated_execute` inlines the capability unconditionally (Go's
>    `CreateAuthenticatedExecute` likewise), so dropping the supporting set yields cap-present /
>    signature-and-granter-absent, which dies at the chain walk as **`missing_signature`** — not as a
>    missing cap. Any impl that flips by "stop attaching the chain" ships exactly this and will
>    misread the failure. A true references-only sender needs an envelope-builder change.
>
> Pinned by `test_q1_phase2_references_only_wielding_is_scoped_to_minted_and_delivered`, whose third
> assertion fails if resolution ever widens past the recipient key.

**The passages.**

`EXTENSION-SIGNALING.md` §6.5, *Two establishment triggers*, trigger (b): two peers that publish no
`webrtc` profile "agree a rendezvous key **out of band** … and drive `establish_live` **off that
key**". Both peers therefore originate over the **one** data channel that negotiation produces.

`GUIDE-CONFORMANCE.md` §7a.2a is the only text covering how a non-dialing peer acquires authority to
originate back:

> the last three are the caller-minted authority for the reentry direction (this peer → caller)

> **The reentry direction can only be authorized by the caller (a cap valid *at the caller*).** …
> **(a) in-band params** (`reentry_capability`/`reentry_granter`/`reentry_cap_signature`)

**The ambiguity.** §7a.2a describes *caller-authorizes-reentry*: the caller EXECUTEs an operation and
hands the reentry capability in-band, so the handler dispatches back with an explicitly supplied cap.
That shape presumes the reentry dispatch is **triggered by, and authorized within, an inbound
request**.

§6.5 trigger (b) produces a different shape the guide does not address: **both peers originate
spontaneously and independently** over one channel, neither as a consequence of the other's request.
The §7.4.1 role assignment settles who runs the HELLO *client* half, but says nothing about
authority to *originate application dispatch* afterwards. After the handshake:

- the **initiator** (offerer, dialer) holds the responder's grant — `held_capability` is written
  dialer-side only — and can originate;
- the **responder** (answerer, acceptor) has *minted* a capability for the initiator and holds
  **nothing from** it, so it has no authority to originate at all.

So on the browser↔browser leg the exchange is authorized in one direction only, while §6.5's own
design has both peers driving the seam.

**How it presents.** Not as a missing-authority error. The acceptor falls back to the connection's
capability — which is the one it *granted to the remote* — and authors a request under a cap whose
`grantee` is the counterpart. The far side answers `401 unresolvable_grantee` (the grantee is not in
the envelope), and supplying that identity would only convert it to `403 grantee_mismatch`. Both
statuses point at marshalling; neither names the real condition, which is *this peer was never
granted anything*. Observed live, two browsers over a real data channel, 2026-08-05.

**Interim choice.** Refuse locally instead of emitting an unauthorized request. The acceptor's
endpoint stops offering the minted-for-remote capability as an originating credential, so a
spontaneous dispatch fails **named and local** rather than as a remote authz status. This is
deliberately *not* a mechanism for acquiring authority — it makes the gap loud instead of guessing at
a grant the spec does not describe. The §7a.2a in-band path is untouched and still works.

**Question for arch.** For §6.5 trigger (b), where both peers originate over one channel: does the
acceptor acquire originating authority, and how? The candidate answers each have consequences worth
ruling on rather than having two implementations pick differently:

1. **Mutual minting at handshake** — the client also mints a cap for the server, so both hold a
   `held_capability`. Protocol-visible and cross-peer observable; would need pinning, not local
   choice.
2. **§7a.2a is the only path** — the acceptor may originate *only* in response to an inbound request
   carrying a reentry cap, and a spontaneous browser↔browser dispatch from the answerer is simply not
   authorized. Then §6.5 trigger (b) should say so, because it currently reads as symmetric.
3. **Out-of-band, like the rendezvous key** — the two peers that agreed the key also agree caps.

`[§11.5.1]` flavour worth noting: this is invisible to a same-implementation *loopback* test, because
it only appears once the two peers occupy genuinely different roles across a real negotiated channel.
Our native suite never constructs the acceptor's originating path at all.

</details>

---

<details>
<summary><b>§6.5 (b) Contents — what does "advertisement-filtered" match against?</b> — <b>RULED
and built; two sub-questions re-routed</b>
(EXTENSION-SIGNALING §6.5 (b) × ENTITY-CORE-PROTOCOL §3 advertisement discipline) — <i>2026-08-06,
folding arch `f8f736a`; ruled by arch `977667f`, built 2026-08-05</i></summary>

**The passage.** The Q2 ruling defines the reciprocal grant as the §4.4 handshake union
"**advertisement-filtered** (`ENTITY-CORE-PROTOCOL.md` §3 advertisement discipline — a peer MUST NOT
grant authority it does not advertise it serves)", and §11.1's client-role row repeats it.

**What is unclear.** The filter's *matching rule* is not stated, and a grant's handler scope is a
`PathScope` — an include/exclude list that may hold wildcards. So a filter has to answer, at minimum:

1. Does a grant entry survive if **any** of its `handlers.include` patterns resolves to a registered
   handler, or only if **all** do? (An entry naming `system/tree` and `app/echo` on a peer serving
   only the first is the case that decides it.)
2. What does a wildcard include (`app/*`, `*`) match against — the registry's *current* pattern set,
   evaluated when? A grant assembled at handshake outlives the handshake; a handler registered a
   second later was not advertised then and is now.
3. Is the filter over grant **entries** (drop the whole entry) or over the patterns **inside** one
   entry (rewrite the scope)? These differ observably for a mixed entry, and a rewritten scope is a
   grant the operator did not author.

**Interim choice — no filter, and a reason it is not merely deferral.** This repo already absorbed
the *capability-handler-advertisement ruling* the other way round: rather than filter an advertised
grant it could not serve, it **registers the handler** (Resolution B — `core/peer/src/lib.rs`, the
`capability-handler` block), so the §4.4 floor names only handlers this peer serves, by construction.
That is the discipline's substance for the floor. What is unfiltered is the **policy-table union** —
operator-authored entries, which is exactly where the three questions above bite and where a wrong
answer silently narrows an operator's intent.

Crucially, this is **not** an asymmetry between the two directions, which is what the Q2 ruling was
about: the reciprocal mint and the §6.6 handshake read the *same* `assemble_inbound_grants`, so
whatever discipline the inbound direction has, the reciprocal direction has identically. A filter
added later lands in one function and moves both.

**Question for arch.** State the matching rule (entry-level vs pattern-level, any-vs-all, wildcard
semantics, evaluation time), or rule that Resolution B — refusing to *advertise* a grant naming an
unregistered handler at the point the grant is authored — discharges the MUST, in which case the
policy table is the surface to validate at write time rather than the mint to filter at read time.
`entity-core-go` implemented an entry-level filter with a regression test; two impls converging by
reading each other's source is the cohort-consistency trap, so the rule wants writing down.

---

**RULED (arch `977667f`) and built.** The matching rule is: an assembled entry is retained iff the
advertised served-scope **covers** it under the same four-axis `scope_subset` relation the chain uses
for attenuation. Entry-level, **drop not narrow**; exact-op-match and namespace-prefix-match are
non-conformant. That answers all three questions above: entry-level (Q3), all-not-any (Q1 — every
include must be covered), and the chain's own pattern semantics (Q2). Evaluation time is assembly
time, the only time the assembly exists.

Landed in `entity_capability::advertisement_covers` + `connection::advertised_served_scope`, applied
once at the end of `connection::assemble_inbound_grants` — so the §6.6 handshake and the §6.5 (b)
reciprocal mint filter identically, which is the property the Q2 extraction bought. Skipped under
`debug_open_grants`, which already documents itself as bypassing all authorization scoping.

**Two sub-questions the ruling does not reach, both re-routed:**

1. **The `operations` axis of the advertised scope.** The ruling says an unexpressed axis question is
   settled by "covers", but not what a handler manifest *expresses*. Our `system/handler/{pattern}`
   interface entities carry an `operations` list, so constraining that axis is the more faithful
   reading of "MUST NOT grant authority it does not advertise it serves". `entity-core-go`
   (`advertisedServedScope`, `core/peer/peer.go`) advertises `operations: ["*"]` and routes
   per-handler narrowing through a handler-declared `MaxScope` instead. **We converged on Go's
   shape**, against our own reading: the filter only ever *drops*, so the stricter reading would hand
   a counterpart strictly less authority than a Go peer in the same configuration — a cross-impl
   divergence in grant *contents*, invisible to a same-side round-trip. Which is right is arch's call.
   `resources` and `peers` are unconstrained on both impls; that half is not in question, and the
   *empty* reading is ruled out by construction — the §4.4 floor's first entry carries
   `resources: [system/type/*, system/handler/*]`, so under "empty" the floor filters itself away.
   Pinned by `test_advertisement_filter_drops_unserved_entries_from_the_assembly`, whose floor-survives
   assertion fails loudly if any axis is ever read as empty.

2. **The universal-handler carve-out.** No finite advertised scope covers a `handlers: ["*"]` claim,
   so a literal "drop, not narrow" deletes every open-access grant and such a peer hands its
   counterparts nothing. That does not close a divergence: a `*` grant dispatched at a registered
   handler works and at an unregistered one 404s — the same outcome an absent grant reaches one layer
   later. Both impls retain bare `*` iff the peer serves anything at all. **State the provenance
   precisely:** `entity-core-go` reached this independently and filed it; we adopted their landed
   shape after reading their source, so this is convergence on one impl's answer, **not** independent
   convergence. Pinned by `test_advertisement_filter_keeps_the_universal_carve_out` so a ruling for
   the literal reading is a visible test change rather than silent drift.

Also settled in passing: the ruled relation is **four axes**, so it is not the whole of
`grant_subset`. §5.6's allowance rule ("child MUST NOT add keys the parent lacks") is right for
delegation and wrong here — a manifest expresses no allowances, so applying it would drop every
operator entry carrying one, entry-wide and silently. Split out as `grant_axes_subset`; delegation's
behavior is unchanged. Go reached the same split (`coversFourAxes`) for the same reason.

</details>

---

## ~~`EXTENSION-DURABILITY` §5 — `durability/result.handle` is typed `system/path`, which is not a type~~ RESOLVED

**Resolution (arch `c78b3dc`, 2026-08-07):** the ask was taken as filed —
`EXTENSION-DURABILITY.md` §5 now reads `handle: {type_ref: "system/tree/path", optional: true}`.
It was a typo, and both impls had already read through it. Rust needs no further change: we
moved to `system/tree/path` in `69324cd`, ahead of the ruling, and `entity-core-go` was already
there — so the descriptors agree and §1.5 invariant 4 is satisfiable again.

The original entry is kept below as filed.

---


**Spec:** `EXTENSION-DURABILITY.md` §5, the `system/durability/result` shape:

> ```
> handle:        {type_ref: "system/path", optional: true}
> ```

**The ambiguity:** there is no `system/path` type. The naming-space address type is
`system/tree/path` — one of the six bootstrap meta-types (`ENTITY-SYSTEM-REFERENCE` §4:
*"The entity system has two typed address spaces: `system/hash` for content-space and
`system/tree/path` for naming-space"*), with its own row in the §8 core-type table. An
exhaustive search of `specs/` finds the string `system/path` at this one site and nowhere
else — no definition, no other reference.

So the field is declared against a name that resolves to nothing, and §1.5's graph-integrity
invariant 4 (a type is sound iff every type reachable via `type_ref` resolves) is unsatisfiable
for `system/durability/result` as written.

**Interim choice:** read it as the typo it evidently is and publish
`handle: {type_ref: "system/tree/path", optional: true}`. The prose supports this directly —
§6 says the handle *"carries the absolute tree path of the durable entry"* and *"the sender
reads it as any tree path — `tree:get` / sync / subscription"*.

**Cross-impl state:** neither impl adopted the literal text. `entity-core-go` publishes
`system/tree/path?`; we published `primitive/string?` behind a comment claiming it matched Go's
registry declaration for hash agreement — the claim was stale and had never been re-checked
(core-go's `compare-types` surfaced the divergence, 2026-08-07). We have moved to
`system/tree/path?`, so the two now agree. Since `system/tree/path` extends `primitive/string`,
this narrows the descriptor without changing what any conformant value looks like on the wire.

**Ask:** a wording fix — `system/path` → `system/tree/path`. Routed in
`ROUTING-2026-08-07-the-flag-day-is-closed-and-6.7-is-built-both-halves-to-cohort.md` §4.1.

---

## ~~`EXTENSION-NETWORK` §12.3 vs the ratified type table — are §6.7's types mandatory when §6.7 is not?~~ RESOLVED

**Resolution (arch `c78b3dc`, 2026-08-07):** ruled **(b)** — *the types follow the section*.
`EXTENSION-NETWORK.md` §12.3 gains a MUST, stated generally rather than about §6.7: **a type is
owed by the surface that uses it**, so a peer that declines an OPTIONAL section does not owe that
section's types in its `--profile full` publication. It follows core `ENTITY-CORE-PROTOCOL.md`
§9.5 (*"absence of extension handlers means absence of their types"*) one level down, at the
section. The competing reading — ours, (a) — was recorded as coherent but resting on §6.13(a),
which governs a **mandatory** handler where publication sits beneath a required behavior; §6.7 has
no required behavior to sit beneath. Arch credits the question as routed independently by us and by
`entity-core-go` the same day.

**Consequence for Rust: none, and that is not luck — it is why the interim choice was safe.** We
implement both §6.7 operations, so we *are* the surface that uses those types and we owe all three
(`system/network/candidate`, `observe-address-result`, `check-reachability-result`). We publish all
three. What the ruling changes is the reason: we publish them because we offer the section, not
because the §13 table lists them.

**The related pushback resolved with it.** `entity-core-go`'s `validate-peer` reported
`check-reachability returned 400 unknown_operation` as a FAIL; §12.3's *"or an unimplemented
response"* said otherwise. That is now moot for us from both ends — Go's `section67TypesOnly`
suppresses rather than merely annotates as of their `2305008`, and we implement the operation as of
`1db5b02`, so we answer 200/403 and never 400. The ruling also pins the **consumer** half: a
consumer MUST NOT infer support from the type registry — the discovery signal is the operation's
response.

**Also folded, from the same commit:** §6.7.5 is recorded **PARTIALLY DISCHARGED**, not closed. Its
reflect half is cross-impl 4/4; the dial-back half across a real NAT is un-run, and arch classes it
with the §11.5 S5 and §10.3 seam gates as **missing cohort infrastructure — not implementation debt
against any repo.** That matches what we said at closeout: our §6.7.5 gate proves the mechanism, not
the traversal.

The original entry is kept below as filed.

---


**Spec:** §12.3 makes the section optional as a whole:

> **Reachability facts (§6.7, Amendment 13)** — a peer MAY offer `observe-address`,
> `check-reachability`, both, or neither. Offering neither is fully conformant: a requester that
> gets a 403 **or an unimplemented response** proceeds to another reflector [...]

while §13's ratified type table lists `system/network/candidate` and
`system/network/check-reachability-result` alongside every mandatory core type, with no marker
distinguishing them as conditional.

**The ambiguity:** a peer that conformantly declines §6.7 entirely still publishes no descriptor
for either type — and so fails a `types_all_present`-style check that reads the §13 table as the
mandatory set. Two readings, both defensible:

(a) **Types are mandatory independently of the operations.** The registry is the machine-readable
spec; publishing a descriptor costs nothing and says "this is what the shape *would* be", which
is useful to a caller deciding whether to ask. Declining an operation is not the same as denying
its vocabulary.

(b) **The types follow the section.** A peer advertising types for operations it does not serve
invites a caller to conclude it serves them, and §12.3's whole point is that offering is a
deployment choice.

**Interim choice:** (a) — we publish both descriptors and implement both operations, so the
question does not bind us either way. Logged because it *will* bind the next impl that declines
§6.7, and because the answer should be deliberate rather than inherited from whichever validator
ran first.

**Related, and the reason this surfaced:** `entity-core-go`'s `validate-peer` currently reports
`check-reachability returned 400 code "unknown_operation"` as a FAIL on the stated grounds that
*"nothing else is conformant"* besides 200 or 403. §12.3's "or an unimplemented response" says
otherwise. Routed to core-go in the same routing doc, §3.

---

## REGISTRY §6a.9 — the two status codes on `register-request` that the spec never names

**Spec (`EXTENSION-REGISTRY.md` §6a.9, arch `ed3de7a`):** the handler pseudo-code
fixes the *outcomes* and, for one of them, the response *body* — but no status
code for either:

```
system/registry/peer-issued:register-request(request) → binding_hash | rejection
  1. verify request signature by target_peer_id          ; layer-1 (always)
  ...
  4. on reject:  error (name_taken | not_entitled | policy_rejected)   ; REGISTRY code domain
  5. on queue:   status "pending_review"                  ; manual mode
```

Step 4's code domain covers **layer-2** rejections only; a layer-1 signature
failure appears in no list. Step 5 pins the body (`status: "pending_review"`)
and says nothing about the code. Both answers are **cross-impl observable** —
a client written against one registry sees a different code from another.

**The ambiguity, and how the cohort answered it:**

| | rust (until 2026-08-10) | go | py |
|---|---|---|---|
| layer-1 proof failure | `403 invalid_signature` | `401 signature_invalid` | `401 proof_failed` |
| `manual` queue | `200` + status body | `202 pending_review` | `202` + status body |

**Interim choice: converge on 401 / 202** (`registration.rs`), and route the
pair upstream for ratification.

Two things make this convergence rather than oracle-following, and the
distinction is the one this repo declined to blur on `published-root.prefix`
three sessions ago — there the spec *did* say `system/tree/path` and the oracle
disagreed, so we held. Here:

1. **The spec is silent, not contradicted.** Nothing is being overridden.
2. **It is 2-of-3, reasoned independently.** go and py each recorded *converging
   on the other* in their own source comments, and py's reasoning is the one we
   would give unprompted: layer-1 is an **authentication** result (the requester
   failed to prove key control) and 403 is layer-2's *answer* (`not_entitled` —
   proof accepted, policy says no), so collapsing them loses the distinction the
   two proof layers exist to draw. Likewise 200 says "done" for an operation
   whose entire point is that **nothing was signed**.

**What is still owed upstream, and why a ruling and not just a convention:**
arch pinned the adjacent code four days earlier for exactly this reason —
§6a.9.2's stored-`domain-control` `501`, ratified because *"this is a
cross-impl-observable answer with four plausible codes, so it is pinned rather
than left to converge."* These two are the same class and are unpinned by
accident, not by decision.

**And the code *strings* still diverge three ways** (`signature_invalid` /
`proof_failed` / `invalid_signature`) on a `register-request` failure that is
part of `REG-REGISTER-PROOF-1`. No conformance check reads them today — go's
`layer1_unsigned_request_rejected` asserts the status only — which is precisely
why it can stay divergent indefinitely. We kept `invalid_signature` rather than
adopt either sibling's spelling, because picking one of three arbitrarily is not
convergence and would only obscure that the question is open.

**Found by:** the first `validate-peer -category registry_issuer` run ever made
against a rust peer (2026-08-10). The category had been unreachable for us — it
needs a peer armed with an issuer policy, and rust has no CLI arming flag — so
§6a.9.2's `set-issuer-policy` is what made these two visible. Neither is new;
both had been shipping since the handler landed, unmeasured.

---

## DISCOVERY §3.3 vs §8.1 — `:announce-stop` cannot be both 400-on-unknown and idempotent

**Spec (`EXTENSION-DISCOVERY.md` §3.3, arch `140a1bf`, added 2026-08-10):**

> When `:announce(backend, profile_ref)` **or `:announce-stop(backend,
> profile_ref)`** names a `profile_ref` that does not resolve to a
> `system/peer/transport/{peer}/{profile-id}` entity, the handler MUST likewise
> return **`400`** (`unknown_profile_ref`) — **not `500`**.

**The ambiguity:** §8.1's symmetric lifecycle makes `:announce-stop` idempotent
— stopping a session that was never started is a success, not an error — and
the cohort's own conformance check encodes that. core-go's
`v7_announce_stop_idempotent` dispatches `:announce-stop` with
`profile_ref: "validate-peer-never-announced-profile"` and **requires 200**.
That profile_ref resolves to nothing, so §3.3 read literally requires 400 and
the check requires 200. They cannot both hold.

**Interim choice:** enforce §3.3 on `:announce` only. Both measured checks pass
under that reading (`v7b_announce_unknown_profile_ref` → 400,
`v7_announce_stop_idempotent` → 200), and it is what go ships — their sentinel
is raised by the announce-side resolver, not the stop path. So the corpus and
the cohort agree on behaviour and disagree only with §3.3's sentence.

**Suggested resolution:** drop `:announce-stop` from §3.3's rule. The two ops
are not the same class. `:announce` must resolve the ref because it is going to
*advertise* it — an unresolvable ref means there is nothing to publish. `:stop`
only needs to end a session keyed by that ref, and "no such session" is exactly
the idempotent-success case §8.1 already rules on. §3.3's justification ("a 500
additionally tells the caller to retry something that can never succeed") argues
against a 5xx, not for a 4xx over a 200.

---

## DISCOVERY §3.3 — the mechanism it names does not exist in any impl

**Spec:** §3.3 defines an unknown `profile_ref` as one that "does not resolve to
a `system/peer/transport/{peer}/{profile-id}` entity."

**The ambiguity:** that namespace holds the transport profiles a peer has
learned for **other** peers. A peer publishes no such entity for **itself**, so
on `:announce` — where the ref names the announcer's own transport — there is
nothing in the tree to resolve against. Implemented literally, every announce
would 400, including the one core-go's `v7a_announce_lifecycle` requires to
succeed.

Neither shipping impl does what the sentence says. core-go resolves against a
fixed set driven by its configured listeners (`tcp` / `http-poll`, a `switch`
in `cmd/entity-peer/main.go`), and rust now matches that set
(`mdns::MDNS_V1_PROFILE_REFS`). The observable behaviour converges; the stated
mechanism is what neither implements.

**Interim choice:** match the cohort's effective rule — the backend declares the
profiles it serves — and record that this is a deliberate divergence from §3.3's
wording rather than an oversight.

**Suggested resolution:** reword to "a `profile_ref` the backend does not serve",
which is what both impls mean and what the erratum's own reasoning supports. If
the entity-resolution reading is intended, it needs a companion rule saying a
peer MUST publish its own transport profiles, and that is a larger change than
an erratum.

---

## v767 M3/M6 corpus pins contradict §4.5a item 1a (CORROBORATED, awaiting arch)

**Status:** not ours to resolve — core-go raised it first and proposed values.
**Spec:** `ENTITY-CORE-PROTOCOL` §4.5a item 1a (v7.77, core-protocol `fc54930`)
vs `specs/test-vectors/v767/SEEDS.md` §2.4 + `conformance-vectors-v1.cbor`
(core-protocol `56d4de4`).

**The conflict:** item 1a pins `system/peer` to the ECFv1-SHA-256 floor
**whatever the peer's home format**. SEEDS.md §2.4's "home-format reference
discipline" predates it, and M3/M6 are the SHA-384-home rows — so their
`expected_peer_a_content_hash_sha384` pins (`01…`, 49 B) can no longer be
produced by any conformant implementation. The corpus was landed verbatim, so
it still self-verifies; it just no longer agrees with the ruling.

**What rust adds:** core-go's re-stamp proposal
(`entity-core-go/docs/validation/spec-issues/2026-08-11-d-v767-m3-m6-restamp-proposal.md`)
lists six derived values. **Rust derived all six independently and matched go's
bytes exactly** — both peer content hashes, both root-cap content hashes, and
both signatures (Ed25519 64 B, Ed448 114 B). Two ground-up implementations
agreeing is corroboration of the proposal, **not** ratification.

**Interim choice:** implement item 1a (it is landed, normative text) and carry
go's proposed values in `cohort_compare_v767_phase2.rs`, with the header stating
plainly that they are proposed and that this test is what will say so if arch
lands different ones. We did **not** hand-edit a red run green: the ruling moved
the values, and the test names the ruling.

**Note carried from go's proposal, which we agree with:** the field name
`expected_peer_a_content_hash_sha384` is now a misnomer — under 1a that value
can never again be SHA-384.

---

## §6a.9's status table pins two rows it calls derived rather than measured

**Status:** measured by rust, reporting back rather than assuming.
**Spec:** `EXTENSION-REGISTRY` §6a.9, "Statuses `[MUST]` `[RATIFIED 2026-08-11]`".

The table pins four rows and says the `409 name_taken` / `403 not_entitled` rows
are **derived** from V7 §3.3's class rules rather than measured, asking impls to
"report a divergence rather than assuming it is yours".

**No divergence to report.** rust answers `409 name_taken` and `403 not_entitled`
and both pass against the go oracle (`policy_allowlist_rejects_unlisted`,
`register_open_name_taken`). Recorded so the rows stop being derived-only: two
impls now agree on the wire, which is a stronger basis than the derivation alone.
