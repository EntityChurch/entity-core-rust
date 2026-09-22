# entity-core-rust — status

_Updated: 2026-09-17 · public: v0.8.0 (master)_

> **A note on the citations below.** Entries name the routing packet, handoff or
> validation report that produced them — files under `docs/outbox/`,
> `docs/status/`, `docs/archive/` and `docs/validation/reports/`. Those are
> **internal working memory and are not part of the public source mirror**, so in a
> published checkout those paths will not resolve. They are provenance for the
> cohort, not links. **Every claim an entry makes is stated in the entry itself**;
> nothing here requires opening one.

## Where it is

entity-core-rust is the Rust reference implementation of the Entity Core
Protocol (v7.9) — a clean, ground-up implementation, one of three independent
references alongside the Go (oracle) and Python peers. Downstream, the
entity-browser and Godot apps consume its crates as an external dependency — a
Cargo git dependency pinned to a release tag, or a path dependency on a sibling
checkout while they are developed together. **A lone clone of this repo builds
standalone**: measured 2026-09-17 against a clean clone with no siblings present,
`make test` exit 0 — 131 suites, 2,774 tests.

The workspace is a strict, cycle-free crate DAG — `core/*` (ECF deterministic
CBOR → hash → entity → crypto/store/types → capability/wire/handler →
protocol/tree/peer, with `entity-core` as the facade re-export) — plus opt-in
protocol extensions (`extensions/*`), language/runtime bindings (`bindings/*`:
C FFI, Godot GDExtension, a higher-level SDK, and the wasm-worker stack), and
CLI tools (`entity`, `wire-conformance`, `fetch-published-fixture`). One
codebase serves three deployment roles: data toolkit, embedded peer, and
standalone server.

**Maturity: public research-preview, tagged v0.8.0.** Broad feature coverage —
all seven base extension handlers (inbox, continuation, subscription, clock,
revision, history, query), the identity/role/quorum/attestation trust stack,
the messaging/transport extensions (relay, route, discovery, registry),
encryption, compute, type-system, and WASM compatibility across every crate.
Crypto agility (Ed25519 + Ed448 keys, SHA-256 + SHA-384 hashes) is a
runtime/connection property negotiated in the handshake, not a build flag.
Known gaps are tracked in `docs/BACKLOG.md`; spec under-specifications found
while implementing are logged in `docs/SPEC-AMBIGUITIES.md` and routed upstream.
The protocol is **not** locked at 1.0, but the core wire format, capabilities,
and tree semantics are interop-validated against the Go and Python peers, not
just self-tested.

## Where we left off

_2026-09-17: **Release hygiene — the repo's own documentation got the treatment the code
gets.** `AGENTS.md` had grown to 217 KiB doing a job it was never meant to do: holding every
anti-pattern this implementation has earned, in one file that every agent loads in full. It is
now ~17 KiB of *how we work here*, and the 55 catalogued failure modes moved — verbatim, by line
range, with the script that did it kept in `tools/` so the move is auditable — into
`docs/agents/memory/`, eight topic files indexed **by symptom**, because a symptom is what a
reader arrives with. Nothing was deleted. The standing rule that bounds it: **an entry that
could become a check should become one, and is then deleted from memory.**_

_Routing packets moved from `docs/status/` to `docs/outbox/`, and the receiving half — a
watermark per counterpart in `docs/status/TRACKER-*.md` — was written for the first time. **Its
first scan immediately found six packets addressed to this seat that nothing in this tree
cites**, including a spec version bump (`0.8.2.27`) and a ruling on §4.11 row 5a, which we
landed under our own reading two days ago. That is the discovery gap the convention exists to
close, and finding it on the first run is the convention working, not a surprise. Those six are
the next work; none of them is closed by this commit._

_2026-09-16: **`.26` was relayed to us as "nothing in your tree moves." Three of the four asks
confirm that exactly. The fourth withdrew a prohibition, and the rule it handed the input to had
never been implemented here at all.**_

Arch's `.26` fold is a clarity revision — *"not one delta adds an obligation to a conformant
peer; eight of the nine withdraw a prohibition"* — and `entity-core-go` relayed the rust section
faithfully. Recomputed against this tree rather than accepted, the scoring holds for three:
**`DR-1`** folded `EXTENSION-TREE` to **v4.12** with §2.2a's `resource` column now three-valued
and `diff`/`create`/`destroy` moved to *no path subject*, which vindicates the hold we took and
is a no-op here (our `path_required` arm is on exactly `get`/`snapshot`/`extract` and on none of
those three); **`DR-7`** ruled permissive, so our deliberate zero-bound stays; **`DR-6`** ruled,
with arch correcting our *"26 files"* denominator to 9 and then, by opening all of them, to
**zero** — no resource-optional operation exists outside `EXTENSION-TREE`. `DR-2`'s `(a1)`/`(a2)`
split and `DR-10`'s class-vs-code ruling were checked too and are already carried in code, as is
`CQ-22` (every signing site passes the full `content_hash`, format byte included).

**`DR-3` is the one that moved, and the way it moved is the finding.** It withdrew §4.11's ban on
`non_canonical_ecf` at the framing arm — scored *"no, a prohibition was withdrawn"* — and what it
did with the input was **partition** it: bytes that decode and carry a CBOR tag go to
`ENTITY-CBOR-ENCODING` §6.3, a rule older than the fold. Measured before any edit, **this peer
ran no tag check on any inbound path.** `cbor_item_end` walked past major type 6 as an ordinary
item and `decode_entity` holds `data` as a raw slice, so a tagged frame decoded and was admitted.
*The delta obliged nothing; the rule on the far side of the partition obliged everything.*

⭐ **And the reason no gate could see it: `is_canonical_ecf` — a complete strict-ECF validator
with an explicit major-6 arm, shipped since the initial release, with its own F29/F30 suite —
had zero callers on any protocol boundary.** Its only consumer is `cmd/wire-conformance`. That is
the third instance of *a validator with no consumer* and it ratifies the entry. Worse for the
cohort: go's `tag_reject` gate compares each impl's **emission file**, so three seats have been
passing a tag gate that scores their conformance CLI rather than their peer — `entity-core-py`
found the identical thing about itself this week, independently.

⭐ **Our own §5.4 fix two commits back moved which half of §6.3 we violate, without touching the
file.** §6.3 forbids *both* "silently strip" and "preserve through forwarding." Before `23513a0`,
`to_ecf` dropped tags on the forward path; after it, `data` rides raw and we preserved them.
Green suite both ways, because no row anywhere drove a tag.

Fixed at the primitive rather than at N call sites: `cbor_item_end` already recurses to the
bottom of every `data` field to resolve its extent and every inbound decode reaches it, so the
check is total over every nesting depth §6.3 names at **no additional traversal**. Typed
`WireError::CborTag`, so the caller can pick between the two halves of the partition. Driven over
the connection stack: tagged frame `400 invalid_request` → **`400 non_canonical_ecf`**, with the
untagged twin as control — pre-fix the two gave the *same* answer, which is what made it
invisible. Both mutations run with `--no-fail-fast` and **disjoint by site**: restoring the
walk-past reddens 4 rows in 2 suites and **nothing else in 2774 tests**; deleting the disposition
arm reddens only the 2 wire-crossing rows.

**Not re-pinned:** `S-1`/`S-2`. `conformance/MANIFEST.md` still carries `9695b1f1…` and now
explains why that digest is unblessed on the `signature` category and what gates the move to
`16861cd0…`. Nothing is owed from us until the cross-bless and the protocol land.

Gate: `make test` **131 suites / 2774P/0F** · clippy · fmt · wasm · godot 263P/0F. `5dac802`.
`docs/outbox/ROUTING-2026-09-16-a-*`.

_2026-09-15 (c): **`0.8.2.25` §4.11 landed. Arch named one site; it was four — and one mutation
that reddened nothing was the most useful result of the session.**_

No routing was addressed to us for `.25`, so the fold diff was read directly
(`entity-core-protocol` `1a8e0c1`). §4.11 states the pre-admission refusal once: a coded
EXECUTE_RESPONSE is mandatory, the close is optional, and a **silent drop and a bare close are
two distinct non-conformances**. Arch's `951bc1b` recorded us as the silent seat at
`connection.rs:481`. Accurate, and one of four — the other three were the oversize/truncated
arms (bare close, in the message loop *and* at both handshake frame reads), §3.3's wrong-root
type (no gate at all), and the dialer-side `reader()`, which `break`s on an undecodable frame
and so ends the demux for **every** response in flight.

`read_frame` had to change underneath all of it: `read_exact` reports "hung up between frames"
and "sent three bytes and vanished" as the same `UnexpectedEof`, and §4.11 gives those opposite
dispositions. Any seat whose frame reader uses a read-exactly primitive has this and cannot see
it from the caller.

**The session's real finding was a green mutation.** Restoring the exact pre-`.25` bare close on
the message loop's read arm left all six original wire rows green — they drove the *handshake*
emission site, and the `(status, code)` table is one shared function while the emission is two.
A shared helper makes two sites look like one. Closing it took a **tapping proxy** (byte-level
MITM between a real dialer and a real acceptor) so a forged length prefix can be written at an
*established* connection — the raw-frame injection `entity-core-go` records as owed by their
harness. 8 rows now, 8 mutations run, reddening by arm-group with no mutation crossing a group.

**Wire-measured**, peer rebuilt (`dirty=true` at HEAD): go's two new `.25` arms driven against
us — `resolution_integrity` **3P/1F → 4P/0F** across the fix (the pre-fix `20.006s` elapsed is
their harness waiting out our drop; post-fix the category runs in `0s`), and
`resource_effective` **9P/0F** including their new extract N6 arm. That half-discharges the
3-way drive go recorded as owed; **py is still open.**

**Held and routed, not implemented:** `EXTENSION-TREE` v4.11 §2.2a's `required` column. Its
`diff` row contradicts **§4.2 — the section the row cites** (*"the `resource` field is
optional"*), and its `create`/`destroy` rows contradict §7.4's untouched authorization table
(*"Handler scope only"*); all three take no path subject. core-go's `handleDiff` requires no
resource either, so implementing the column verbatim would make us the only seat refusing
`diff`. The **BROAD** column is right and we already conform to it. Three further asks went with
it: the per-operation declaration exists in **1 of 26** extension specs (so
`CORE-RESOURCE-TWO-EMPTIES-1` arm (c) has no subject anywhere and is undrivable), §4.11's
"non-canonical CBOR → `invalid_request`" collides with `ENTITY-CBOR-ENCODING` §5.4's
`non_canonical_ecf` MUST on the same bytes at the same boundary, and §4.11 mandates an emission
per refused frame while bounding nothing — with arm (f) pressuring every seat toward `continue`.
`docs/outbox/ROUTING-2026-09-15-d-*`.

Gate: `make test` 2769P/0F · clippy · fmt · wasm · features · godot 263P/0F. `cfde6b5`.

_2026-09-15 (b): **a live §5.4 byte-fidelity violation at eight sites. The `tree:merge` lead we had
answered as "narrow" was the visible corner of a rule our own type system could not express.**_

`entity-browser-rust` read `handle_merge` at the line and found it rebuilds each `source_envelope`
entity's `data` from a decoded CBOR value. We had answered that as real but narrow, and deferred it.
Sweeping the boundary the spec sentence names — *every site that carries an entity's `data` across a
decode* — found **eight**, and the cause is a type: `entity_ecf::Value` is `ciborium::Value` and
cannot hold raw bytes, so every place we inline an entity inside another entity's data had to reach
for decode + re-encode. Two helpers existed for exactly that, which is how it spread.

Four of the eight are nowhere near `tree:merge`: the outbound EXECUTE builder, the receive-side
dispatch boundary that produces **every handler's `ctx.params`**, the in-process sub-dispatch
builder, and the EXECUTE_RESPONSE reader — that last one asymmetric, since the *writer* had always
spliced raw, which is the one shape a round-trip test structurally cannot see.

**Observable cost:** a merge of any entity this peer did not author bound `path → hash` from the
source trie while storing the entity at a different hash — `200 applied:N` over bindings that resolve
to nothing. A re-addressed trie *node* drops an entire subtree the same way.

**Why nothing caught it, and it is the transferable part:** the re-encode is the **identity** on
every value an ECF encoder authors, so no fixture in any tree can tell the broken implementation from
the fixed one. Our 133-suite `make test` and a clean `validate-complete.sh rust` both sat on top of
it. The fixture that works is `{"v": 1}` with the `1` written non-minimally — valid CBOR,
self-consistent, unauthorable by ECF.

Fixed with the missing primitive rather than eight edits (`entity_wire::cbor_map_set_raw`), both
lossy helpers deleted. The handler-side rows were green with the defect fully live on the wire — N6
again — so the evidence is a two-peer wire vector, and **both of its axes were measured as
load-bearing**: with the target sharing the source's store, the pre-fix code passed. Six mutations
run; all six redden that row and none reddens any pre-existing row.

Routed to `entity-core-go`: their `tree_operations.roundtrip_verify_entity` is the check that would
have caught this and misses on the same two axes at once, and their cross-peer `extractAndMerge`
helper re-encodes the envelope in the harness. go itself reads as immune — `Entity.Data` is
`cbor.RawMessage` — but that is a code read of their tree, not a drive, and the packet says so.
`validate-complete.sh rust` exits 0 on all six passes after the change (PASS 1: 1658 · 0F);
`tree_operations` 64 · 0F before and after, which is what says the wire *shape* did not move.

_2026-09-15: **long-running browser peers. Three WebRTC signaling fixes landed, and the remaining
items are written up in `docs/BACKLOG.md`.**_

A browser consumer (two browsers that meet through a signaling node and then chat) reported that long
sessions stop reconnecting. Checked against our source, both of the causes they named were ours, and
fixing them surfaced a third:

- **An answerer took the oldest offer at the node, not the newest.** Offers from an abandoned attempt
  stay at the node for its TTL, so every retry answered a session nobody was waiting on. It now takes
  the newest.
- **The §6.5 carrier cached its node connection outside the connection pool** and never evicted it,
  so the first transport failure was permanent. It now redials when the node closes the connection or
  a request fails at the transport.
- **An answerer re-answered an offer it had already answered.** After a successful negotiation that
  offer is usually the only one at the node, so "newest" did not skip it, and each later attempt sent
  an answer no offerer reads. The consumer measured this as extra deposits at the node. It now skips
  offers whose session already carries an answer this peer signed.

Each has a test that fails with the fix removed. Deferred, each with its reason and next step in the
backlog: why the answerer re-negotiates at all (needs the consumer's peer-side logs), `merge`'s
`source_envelope` byte fidelity (**closed 2026-09-15 (b) — it was eight sites, not two**),
`system/content:get`'s namespace
binding (held until grants narrow), the SDK's hardcoded `debug_open_grants` (a migration), and a stale
`connected` status surviving a restart (a spec gap, logged in `docs/SPEC-AMBIGUITIES.md`).

_2026-09-11 (c) — **`0.8.2.21` absorbed. The exclude fail-open had four sites here, not the three
the ruling counts, and the third one is not fail-closed by accident.**_

No routing came to this seat — the packet went to `entity-core-go`, keystone and formalization,
with §6 relaying three lines to us. We took the packet's own header at its word (*"a per-seat
section is the delta from that seat's last reported state; the RULING is the obligation"*) and
recomputed the whole revision against our tree. All three findings below came out of that, and
none of them is in §6.

**`H1` — the fail-open, which was our filing, upheld, with our option (c) promoted from
*permitted* to *required*.** An unmatchable `exclude` carves out nothing, so a grant is silently
wider than its author wrote with no error anywhere. Closed in both directions: an unmatchable
exclude now **denies** at evaluation, and a capability carrying an unmatchable scope pattern is
refused at mint, at delegate (`400 invalid_path`) and at §5.5 chain verification (403). Two
layers, neither substituting for the other.

**It is four evaluation sites here, and the two the ruling missed have opposite causes.** The
**pattern** arm of `check_resource_scope` is exempted by the fold as *"fail-closed BY ACCIDENT via
a negated test"* — and the negated test is never reached, because `patterns_overlap` against the
path-shaped sentinel is `false` and the loop `continue`s first. Measured: built spec-literally, it
**allows**. The fourth site, `check_path_permission`, was **ours** — the spec delegates that
dimension to `matches_scope` and so inherits the fix for free, while we had open-coded it as
`is_covered_by(include) && !is_covered_by(exclude)`, which is `matches_scope`'s body minus the new
arm. That is the site where it costs most: §6.3 is *sole* resource enforcement when `resource` is
absent.

**`H3` + `EXTENSION-TREE` v4.9 — path validation is a property of the boundary, not the channel.**
Both layers, which v4.9 states as independent. `extract.paths[]` is validated **every entry before
reading any** → `400 invalid_path` for the whole request, while a well-formed entry that binds
nothing stays silently omitted; `merge`'s `target_prefix` likewise, and merge reads *no resource
target at all*, so nothing upstream had ever seen those paths. On the store side,
`path_is_storable` at the two `LocationIndex` write sites. Two boundary panics went with it:
`clean_path`'s assert — sitting under a `#[should_panic]`, the same construction that hid the
wire-reachable `qualify_path` panic one revision ago — and `SqliteLocationIndex::set`'s `.expect`
on a database error, which was a panic in the dispatch task.

**`H4` — our ask, ruled, and two rows of the new table are deliberately not applied.** §6.3's
parameter is now `authority` with §6.8's who-named-the-path table at the `fn`. But that table
classes *"a listing entry"* and *"a merge expansion"* as handler-derived → the handler's own
grant, while §6.3's Listing-filter MUST — **unchanged in the same revision** — says each entry is
checked against the *request's* capability. Applying the table would filter a listing against the
`/*/*` default self-grant and hand back exactly the entries `F71`/`CP-12a` closed. Held §6.3,
written the conflict at the code, routed.

**Evidence.** Twelve mutations run, each reddening its own row with the neighbours green, and
every `H1` row paired with **both** controls `CORE-EXCLUDE-UNMATCHABLE-1` demands — a well-formed
exclude that still denies *and* one that still allows, because every row in this family is a
denial and a peer that denies everything would pass all of them. Gate: `make test` 2728/0F across
129 suites, `lint`, `godot` 261/0F, `wasm`, `features`. Cross-impl at this tree with the peer
rebuilt (`dirty=true`): `validate-complete.sh rust` — passes 0/0b/1/1b/2/3/4 all exit 0. ⚠ Neither
new vector is in `entity-core-go`'s check set yet (grepped, zero hits), so that green is a
regression check and says **nothing** about the two things this revision is for; keystone owns the
wire arm.

---

### Earlier

Dated entries from 2026-06 through 2026-09-16 are archived in
`docs/archive/status/STATUS-HISTORY-2026-06-to-09.md` (internal — they cite
handoffs and routing packets that do not resolve in a published checkout). What
they add up to is in **Where it is** above and in **Done recently** below; nothing
in this document depends on opening one.

## Backlog

From `docs/BACKLOG.md` (see it for full detail and fire-triggers):

- **Capability / authorization:** per-write capability selection in handlers
  (caller vs handler grant — infrastructure is in place on `HandlerContext`,
  individual handlers need domain logic); handler-specific `internal_scope()`
  declarations (currently wildcard grants); bootstrap a `system/capability`
  handler (request/delegate/revoke); `system/handler` register/unregister with
  grant creation; R-3 strict `path_required` on the remaining identity ops
  (`create`/`supersede`/`publish` attestation still accept a computed-canonical
  fallback).
- **Tree handler:** `mode:hash` hash-only reads; pagination (offset/limit) for
  large subtrees.
- **Protocol gaps:** full 6-message mutual-auth handshake (currently 3+3, one
  direction; validator does not test the mutual path yet); post-connect 409
  duplicate-connection detection.
- **Extensions:** revision Phase 2 (recursive trie diff/merge, vs today's
  flatten-and-diff); history accessed-events audit mode + config caching;
  identity §9.2 op-key confinement enforcement, a live-Op cache, a SyncTreeHook
  for the tree-write boundary, and `AttestationStore` consultation at
  `verify_request` (needs a cache-miss policy choice).
- **Bindings / SDK:** a `PeerSurface` trait to unify the SDK/WorkerProxy arms
  (gated on a second mixed-mode consumer); detached-`'static`-future rework for
  `get`/`list`/`remove`/`has`/`put_cas`; SQLite pool-split + a
  storage-concurrency posture doc; a `Batch`/`Transaction` primitive (gated on
  the cross-impl shape design).
- **Cleanup:** dedupe `error_result()`/`spawn_task()` helpers across extensions;
  remove dead `local_peer_id` fields; drop legacy snapshot-format handling and
  the deprecated `persist` feature; loom-based permutation testing for the SEC-2
  race (today covered by a multi-thread soak test).

Performance items from the per-put regression sweep are deferred (the remaining
candidates shrank to single-digit µs once the big-rock fixes landed) — pick them
up only if a future profile shows `verify_request` back on the hot path.

## Waiting on

- **Signaling — three arch-owned items, none blocking Rust's Stage 1** (merged and
  verified), all blocking what comes after it. (a) **The signaling spec corpus is
  uncommitted upstream** — `PROPOSAL-CONNECTION-NODE` is untracked and the §2.2/§3.1/§3.2/
  §3.3/§4.1 and §3.1.1 pins are uncommitted modifications, so go/py cannot build against the
  spec from a clone; verified read-only 2026-07-30 against arch HEAD `46ef024`. (b)
  **`PROPOSAL-CONNECTION-NODE` §5.1**, the public listener's wire protocol — unwritten, gates
  the unwrapped surface in all three languages. (c) **`HANDLER-OWNED-SERVICES` §6 open item
  1**, the manifest declaration's field shape — DRAFT, no cohort review, gates the
  service-owning half of Stage 2. Detail and the ask in
  `docs/status/HANDOFF-2026-07-30-signaling-go-py-client-brief.md` §1 and §9.
- **On the standing-model / network rounds, nothing is blocked on architecture.** Rounds 1
  and 2 are both absorbed.
  The `{reason}` sentinel-vs-hash divergence is **closed** — round-2 ruling 1
  ruled sentinel everywhere, which is the shape Rust already held; all three
  coordinates now use it and Go has converged. Two questions stay routed and
  block nothing: §1.4 not naming the dot tokens, and whether ruling 11's
  "keepalive carries `network-maintain-{session}`" is reachable without
  inverting the core/peer ← network layering. Both in
  `docs/SPEC-AMBIGUITIES.md`.
- **`failing_since` for a never-connected peer** — a real cross-impl gap in the
  rulings-7/8 model (the stamp is written at the transition out of `connected`;
  a peer that never connected never makes one). **Go routed it and Rust
  converged on their interim**; arch should answer Go's spec-issue, not two
  copies. Logged in `docs/SPEC-AMBIGUITIES.md` with the pointer.
- **Protocol spec (upstream):** this repo implements the landed spec and does
  not define it. Several backlog items (mutual-auth test coverage, the cross-impl
  `Batch`/`Transaction` shape) are gated on upstream design landing.
- **Cross-peer subscription delivery to a Rust subscriber** — no longer blocked
  on the `entity://` question (ruled + fixed), but still open: the SDK-side
  `deliver_token` grantee/signature/handler-scope mismatches
  (`bindings/sdk/src/subscription.rs`, `extensions/subscription/src/lib.rs`)
  are diagnosed but unlanded.
- **Cross-impl coordination on SDK-surface items** (`PeerSurface` trait, SQLite
  pool split mirroring the Go peer) waits on those consumers/decisions.

## Done recently

- **Initial public research-preview release tagged v0.8.0.** Clone-fresh gate
  green from a no-siblings checkout (`make build` → release runtime image with
  the `entity` binary; `make wasm` → wasm32 cross-compile of the canonical
  feature set; `make test`). `make` over podman is the build door (bare host
  needs only `make` + podman); `compose.yaml` is demoted to an explicit
  developer convenience. All workspace crates carry the 0.8.0 version, licensed
  **Apache-2.0**.
- **Cross-peer subscription delivery — reported bug fixed + substrate completed
  (subscriber side still open):**
  - The publisher now presents the subscriber-granted `deliver_token` (and
    bundles its delegation chain) as the delivery EXECUTE's capability for
    cross-peer delivery, instead of falling back to the connection grant — which
    on the reentry path is a publisher-authored placeholder the subscriber can't
    root (EXTENSION-SUBSCRIPTION §4.2). This unblocks the Rust-publisher →
    Go-subscriber direction.
  - Completed the dialer-side reentry receive path: a pooled outbound connection
    now dispatches inbound EXECUTE requests through the local handler stack and
    writes the response back over the same connection (previously the dialer
    reader handled only EXECUTE_RESPONSE and silently dropped reentry
    deliveries).
  - The core `entity://` canonicalization gap is **fixed** (ruling 24). The
    remaining Rust-*subscriber*-side stack is diagnosed but unlanded: SDK-level
    `deliver_token` grantee/signature/handler-scope mismatches
    (`bindings/sdk/src/subscription.rs`, `extensions/subscription/src/lib.rs`).
- **Trust stack — Role extension v1.0 → v2.0:** root-cap shape, SEC-2
  assign/exclude atomicity, and bearer-cap rejection (the new
  `unresolvable_grantee` 401).
- **Capability hardening:** granter-aware canonicalization at the dispatch
  boundary, per-link granter frame at chain-walk, grant-signature convergence,
  and a self-owner seed cap at bootstrap.
- **Transport / interop extensions:** relay v1.0 (opaque-envelope transport,
  exercised live Go↔Rust), route (routing table), discovery v1.0 (mDNS
  find-and-prompt) + registry v1.0 (petname→local-name) and the published-root
  flow with cohort absorption. Live cross-impl publish→fetch verified
  (Go-publish → Rust-consume).
- **Encryption extension v1.0:** group/self AEAD modes, key-separation, and the
  associated entity-type registrations.
- **Storage:** an IndexedDB main-thread durable backend (Phase 1) for the
  browser peer, with the SDK builder/checkpoint reach to drive it; a
  multi-tab `versionchange` deadlock guard.
- **Wire-fidelity:** on-receipt hash validation in `verify_request` (a forged
  *included* entity now fails the same as a forged root); §1.2 host-bytes-
  distrust (recompute content hashes, never trust the wire `content_hash`).
- **Performance:** per-put cost ~66.4 ms → ~0.72 ms in debug (~92×) via TCP
  NODELAY, sync-hook config caches, a dev-profile crypto/CBOR optimization
  override, and decoding chain fields once.
- **WASM:** compatibility across all crates (wasm32-unknown-unknown build check
  via `make wasm`).

## Next

> **This list was swept 2026-08-04.** Three items below had gone stale and one of
> them cost a session: 5b named §6.7.1 as unvalidated when it had been closed
> four ways on 2026-08-02, and it was picked up and recommended as "next" on that
> basis. A cold-start reference that is wrong about what is *done* is worse than
> one that is merely incomplete. The punch/WebRTC arc (2026-08-01 → 04) now leads
> the list, because that is where the work actually is.

00. **Conformance parity — what is left after 2026-08-08 (third session).** _(rewritten
    2026-08-08, third session.)_ Every item this entry carried is now **closed or routed**.
    rust reads `1540 total · 1525 P / 9 W / 0 F / 6 S` at `5c58195` against Go `5eab686`,
    pass 2 `54/54` — **matching Go's published cohort table exactly**, verified from our own
    run. Details in
    `HANDOFF-2026-08-08-c-alignment-confirmed-and-the-peer-issued-seam-is-built.md`.

    **a. The two Go-side asks landed** (their `8a25d90`). `-signaling-node` is forwarded for
    `--type rust` and the 7 `signaling` vectors converted SKIP → PASS exactly as predicted;
    `--publish-descriptors`' stale help is fixed. Nothing owed either way.

    **b. The peer-issued seam is BUILT** (`5c58195`) — `RegistryTreeReader` +
    `HttpPollRegistryReader` over the new `poll_read` module, warming the store in the
    handler before the sync chain, plus `--peer-issued-registry <peer_id>@<url>`. **The 6
    vectors still read SKIP**, and will until Go flips its `go|python` gate; that is a
    sibling-repo change, routed in
    `ROUTING-2026-08-08-the-peer-issued-read-seam-is-built-to-go.md` along with the exact
    fetch pattern we emit. Quote `1525 P / 6 S` until they do.

    **Not claimed:** the seam is proven against our own recording origin, not against Go's
    fixture bundle — same-tree evidence, which AGENTS-STANDARD warns reads stronger than it
    is. The first real measurement is theirs. One caveat is in the routing doc: if their
    fixture serves revocations only under the own-hash-keyed path, REVOKED-1 will read as
    "not revoked" against us and the finding would be the fixture's, since we probe the
    §6a.6 by-target index directly.

    **c. Both internal fixes landed.** `CapTokenScope` got its universal-tree top-level arm
    (`144da10`), with one test now pinning all three scope predicates to the convention. The
    seed-policy floor/ceiling collision is **diagnosed and visible, not fixed** (`ac299d9`):
    the lookup reports which form matched, the request path warns when a matched entry
    attenuates to nothing, and `with_seed_policy`'s doc states both meanings. The two
    readings still share a key — the real fix is separate floor and ceiling entries, and it
    is worth doing before someone else seeds a narrow `default`.

    **d. What is genuinely left here:** wait on Go's gate flip and measure honestly; decide
    whether `poll_read::list_children` (built, currently unused — the peer-issued fetch plan
    resolves everything by direct lookup) gets a consumer or gets deleted.

0. **The browser leg — S5.** S3 is built here (`worker_webrtc`, the §6.3
   container, §6.5 `Require`); S4 is `entity-browser-rust`'s and built; **S5 has
   never run** and **rung-1 is still red** — but the transport layer is now
   repeatably sound and both remaining blockers are outside this repo.

   **State as of 2026-08-05 (`d2850e5`), four consecutive rig runs from this
   tree:** data channel opens (1/peer/run), handshake completes 4/4, responder
   receives frames 4/4, zero panics, zero relay fallback, and **initiator→responder
   application payload reaches the handler 4/4**. Roles swapped in run 4 and
   behaviour followed the role, not the peer.

   **Four faults found and fixed to get there, all ours:** the unconditional
   `Drop` destroying working connections (`5e0c131`); the §7.4.1 handshake-role
   collision (`f00170c`); `verify_request` panicking on wasm32 — `std::time`
   instead of `web_time`, our own documented rule (`81ae207`); and inbound frames
   dropped between channel-open and pump-wiring (`9e65317`). Plus the acceptor
   authority refusal (`d2850e5`).

   **The two blockers are no longer ours:** (a) the rig calls `list`, which is not
   a `system/tree` operation — browser-rust's; (b) an acceptor holds no
   originating authority under §6.5 trigger (b) — a spec gap logged at `8e0eabf`
   and routed to arch, where one candidate ruling (mutual minting at handshake) is
   protocol-visible and not ours to pick
   (`ROUTING-2026-08-05-rung1-transport-is-solid-two-asks-out-of-our-court.md`).

   **Caveat:** the frame-buffering fix targets a race that reproduced ~1-in-2.
   4/4 clean is reasonable evidence, not proof, and `webrtc_session.rs` has no
   automated coverage of any kind — rig runs are the only check it gets.
   Coordination-green is not transport-works, and transport-works is not S5.

   **Their acceptance re-run has now happened (2026-08-04) and it moved the wall.**
   `included_count=0` is gone: rendezvous is sound end-to-end, both peers derive
   one key and share one bucket. The failure is now a §6.5 negotiation that ends
   in `Timeout` with a populated bucket — no `RTCDataChannel`. **That is ours**
   (`worker_webrtc.rs` + `wasm-worker-proxy/webrtc_session.rs`; browser-rust owns
   no `RTCPeerConnection`), so this item is no longer "nothing is owed to them."

   Instrumented at `40294ed` — `Timeout` carries `role` / `sdp_exchange` /
   `counterpart_msgs` / `channel wait`, plus a per-tick `trace!`. **Diagnosis, not
   a fix.** Two structural hypotheses were checked and cleared (data-channel
   create/receive symmetry; every broker arm replies), and one piece of their
   evidence was retracted: the missing main-thread "data channel did not open"
   line was never a log line, so its absence never pointed anywhere.

   **Their re-run against that HEAD discriminated in one run (3×, 2026-08-04).**
   Offerer: `role=offerer, sdp_exchange=complete, channel wait: data channel
   closed before it opened`. So it is **not** rendezvous and **not** SDP
   correlation. Load-bearing control: their bare-WebRTC falsifier on the same
   containers/bridge, `iceServers:0`, host candidates → connects, opens,
   round-trips, PASS. **§6.5 fails where bare WebRTC succeeds**, which clears the
   network and puts it on the trickle path.

   **Verdict in (2026-08-05, their run vs `3dcd484`):** `role=answerer,
   sdp_exchange=complete, candidates posted=3/fed=3, channel wait: closed before
   it opened (ice=Disconnected)`. `fed=3` **refutes both leading theories** —
   theirs (candidates not landing) and mine (`candidates_for` correlation) — by
   counter, not argument. Three lifecycle faults found and fixed at `5e0c131`:
   (1) `webrtc_call` awaited with **no timeout** while `negotiate` checks the
   deadline only at loop top, so every round trip ignored `deadline_ms` — the
   tick=2 hang; now `call_bounded` against the remaining window. (2) the
   post-answer iteration paid `wait_open` *plus* a full `sleep(poll_interval)`,
   doubling the period exactly while ICE holds a pair; now only the shortfall.
   (3) **`Drop` posted `WebRtcClose` unconditionally**, and the broker answers it
   with `pc.close()` — so on the success path every negotiation that *worked*
   would have been torn down before a byte moved. Latent only because rung-1 has
   never gone green; unexercised by any gate.

   **Reframe that matters:** `pc.close()` on any peer gives its counterpart
   exactly `ice=Disconnected` + closed channel. So the answerer's line is the
   offerer's teardown *observed* — the open question is why the offerer's window
   closed, and no round has yet quoted the offerer's terminal warn
   (`ROUTING-2026-08-05-three-lifecycle-faults-and-your-answerer-is-the-victim-to-browser-rust.md`).

   Answered at `3dcd484` with the two instruments that decided it: `wait_open`
   errors now append the `ice=`/`conn=` verdict (`Failed` = pairs tried and none
   worked; `New` = remote candidates never reached the agent; `Connected` = ICE
   fine, trickle hypothesis wrong), and `Timeout` carries
   `candidates posted=N/fed=M`. The whole trickle chain was read for the
   `67e6d96` shape first and no defect found — session adoption, blob-exact
   skip-own, `addIceCandidate` always after `setRemoteDescription`, ufrag
   absent-stays-absent, monotonic `negotiation_id` all hold. **Not found, not
   proven absent.** Next fact is their re-run; `fed=0` is mine in
   `candidates_for`, `fed>0` + `ice=Failed` is a timing/usability bug and a
   different fix
   (`ROUTING-2026-08-04-the-ice-verdict-is-now-readable-and-the-trickle-is-counted-to-browser-rust.md`).
0a. ~~**The §10.3 seam takes `Result` — ruled 2026-08-04.**~~ **LANDED `f43f0e0`
   (2026-08-05)**, after both peer repos endorsed (browser-rust: "land it,
   independent of rung-1"; Go deferred the call here). `LiveEstablishError` draws
   `NoPath` / `Refused` / `NotAttempted`. **Control flow unchanged** — every
   variant falls through to relay exactly as `None` did; only the log differs
   (`Refused` is `warn!` and names itself as policy, not connectivity).
   Two call sites stopped lying: `cmd/signaling-punch` reported "no direct path
   within the deadline" for every outcome *including* a `Require` refusal, and
   the punch round-trip test's panic said which half failed but not why.
   Original ruling follows.
   `LiveEstablish::establish_live` returns `Option<Connection>`, so a failure
   reason is destroyed inside the impl and `try_establish_live` has nothing to
   log. Go's suggestion that the reason may already be available at the call site
   does not transfer — theirs returns `(*Connection, error)`; a `None` carries
   nothing. Decided on three instances of the same patch in two days: the browser
   establisher (`485e269`), the punch establisher, and `negotiate`'s
   `if let Ok(channel) = io.wait_open(..)` (`40294ed`), which cost browser-rust a
   root-cause. ~8 sites (trait, two impls, real call site, test double, test call
   sites). **Constraint: every `Err` maps to the same relay fall-through** —
   reason for observability, never a branch for control flow; "no live path →
   relay" (§7.1 step 6 / §7.3.1 pin 1) stays deliberate. Both peer repos have
   registered and deferred the call here
   (`ROUTING-2026-08-04-the-6.1-row-now-lies-in-the-payload-and-the-seam-ruling-to-go.md`).

0b. **The §6.1 false-claim vector row — re-emitted, awaiting Go's `-verify`.**
   The row lied only in its own `claimed_peer_id` over a truthful payload, so a
   payload-driven collector (which every real §6.1 read path is) saw a consistent
   message and returned ok — it could not catch the regression it names. Go found
   it by running their verifier against our file and reported `40·1W·0F`. Fixed at
   `36fce4a`, re-emitted `40·0F @ 36fce4a` (`50b99c3`). **Our count could not
   move** — our verifier is row-driven for signed-blob rows — so this is only
   decidable from Go's seat. Until their `W` clears, the payload-lying §6.1 shape
   is crossed **one way only**. Pin adopted and seconded to arch: on a §6.1 row,
   `claimed_peer_id` MUST equal the author field inside the signed payload.

1. **Two questions routed to architecture — waiting on the model answer, not on
   Rust.** (a) Retention: is a self-collection MUST warranted, or does §5 stay a
   MAY? (`ROUTING-2026-07-17-marker-feasibility-and-retention-rust.md`).
   ~~(b) `chain_depth` — held pending fold / a second wired seat.~~ **STALE —
   built 2026-07-18** and cleared cross-impl 2026-07-31; see item 2, which
   contradicted this on the same list. The ruled list is **closed** (#18 landed,
   feasibility answered, #14 N/A).
2. **Cross-peer chain bound build — DONE (2026-07-18).** The wired `chain_depth`
   brake is built (field + CBOR, cross-peer bounds propagation, step-6
   inherit/increment, O1 signal, §3.9 suspend + §3.7 resume) plus the standing-model
   §3 (Q2) `reactive_trigger` convergence marker
   (`ROUTING-2026-07-18-bounds-and-q2-build-rust.md`). ~~**Owed:** the cross-impl
   `continuation_bounds` anchor-1 run.~~ **CLEARED 2026-07-31** — 3·0·0·0 vs Rust
   `c043c7f`. This was the oldest owed item in the tree.
3. **The cross-impl backlog is clear — nothing is owed to Go's seat.** All seven
   categories swept green 2026-07-31 (`docs/validation/reports/`
   `2026-07-31-seven-categories-cleared-and-rust-joins-the-meet.md`): `signaling`,
   `authz`/F40, `security`, `connectivity`/RT-6, `concurrency`/RT-13b,
   `network_reconnect_anchor`, `continuation_bounds`, `published_root`. Keep it that
   way — **run `validate-peer` on any wire-shape touch rather than banking a
   same-seat green**, which is precisely how RT-6 sat WARNing on top of a real fix.
4. ~~**Run the 3×3 signaling meet.**~~ **DONE 2026-07-31 — 27/27**, all six Rust
   off-diagonal cells live. Signaling Stage 1 is settled cross-impl.
5. ~~**Stamp the podman image with its git commit.**~~ **DONE 2026-07-31** — both
   halves of the stale-image trap are closed. **Owed:** confirm the stamp on a real
   `make build`; the label mechanism was proven on a minimal equivalent image, not
   the full one.
5a. ~~**Re-diff signaling against the arch corpus when it lands.**~~ **DONE
   2026-07-31** — arch `4241b96` folded the connectivity family and the re-diff ran
   against the committed text, six findings, two logged as ambiguities
   (`docs/validation/reports/2026-07-31-signaling-rediff-against-committed-v1.md`).
5b. ~~**Validate `EXTENSION-NETWORK` §6.7.1**~~ **DONE 2026-08-01/02 — the matrix is
   closed four ways.** The client half is `core/peer/src/srflx.rs`; Rust also built a
   **responder** (`NetworkHandler::handle_observe_address` + the §6.7.4 rate limit),
   and standing it up immediately found a real grant bug — Go's client got `403`
   from our responder because reflection was reachable only to a caller already
   holding a `system/network` grant, fixed in `default_connection_grants`
   (`observe-address` only; §6.7.2 `check-reachability` stays restricted, since a
   broad grant there makes every peer a DDoS reflector). Go↔Go, Go→Rust, Rust→Rust,
   Rust→Go all exercised, plus the two-NAT topology on Go's harness
   (`ROUTING-2026-08-02-rust-reflects-too-and-the-403-you-would-have-hit.md`).
5c. **The punch ladder — G0–G3 green, G4 is operator infra.** Rust and Go punch
   cross-impl through a real node; the §6.1 exchange is now **sealed on both sides
   and `Require` on ours** (2026-08-04, four live runs plus a firing negative
   control). Two things are genuinely open and both are Go's to run: their `-verify`
   against our vector file (`40·0F @ 007e078`), and a `Require`-side punch from their
   seat — their `cmd/signaling-punch` hardcodes `VerifyTolerant` with no flag.
   **Still unexercised by anybody:** the racing-socket tie-break, and everything is
   still one box — the cohort has never crossed two real networks.
6. **Cross-peer subscription delivery to a Rust subscriber** — unblocked at the
   core by ruling 24; land the SDK-side grantee/signature/handler-scope fixes.
7. Keep the green gate (`make check` = lint + test) and `make wasm` passing on
   any change.
