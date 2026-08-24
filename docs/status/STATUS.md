# entity-core-rust — status

_Updated: 2026-07-31 · public: v0.8.0 (master)_

## Where it is

entity-core-rust is the Rust reference implementation of the Entity Core
Protocol (v7.9) — a clean, ground-up implementation, one of three independent
references alongside the Go (oracle) and Python peers. Downstream, the
entity-browser and Godot apps consume it via a Cargo **git dependency pinned to
a release tag**, so a lone clone builds standalone (no sibling checkouts
required).

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

_2026-07-31 — **the owed cross-impl backlog is clear, and Rust joined the signaling meet.**_
(`docs/validation/reports/2026-07-31-seven-categories-cleared-and-rust-joins-the-meet.md`.)

Go ran all seven owed categories against a Rust peer built from the committed tree — **clean
sweep, zero warn/fail/skip**, oracle-pinned Go `a2e2076` vs Rust `c043c7f`: `signaling` 5·0·0·0,
`authz` 11·0·0·0, `security` 30·0·0·0, `connectivity`/RT-6 24·0·0·0, `concurrency` 6·0·0·0,
`network_reconnect_anchor` 5·0·0·0, `continuation_bounds` 3·0·0·0, `published_root` 7·0·0·0.
**RT-6 now fires on the wire** — the case that was unreachable before the intercept moved
pre-verification, and the reason the whole backlog was worth clearing: it had been fixed,
shipped, and still WARNing, green on our own seat. `published_root` beat the prediction — the
trie-key convention **byte-matches Go**, so that known-open is resolved.

**The 3×3 meet is green — 27/27.** Go ran `{go,py,rust}` initiator × `{go,py,rust}` responder ×
`{tag,secret,lobby}` live through one Rust `--open` node, using Rust's driver @ `879a327`
(their `docs/validation/reports/2026-07-31-signaling-meet-3x3-cross-impl.md`). **The six
off-diagonal Rust cells are the new evidence** — Rust↔Go and Rust↔Py, both directions, had never
met live. Signaling Stage 1 is settled cross-impl; closeout and next steps in
`docs/status/HANDOFF-2026-07-31-signaling-closeout-and-next.md`.

**Both halves of the stale-image trap are closed.** Go's peer-manager keys provenance on the
sibling's git HEAD (`3c46cb3`); this repo now stamps the commit into the image
(`org.entity.git.commit` / `org.opencontainers.image.revision`, `<sha>-dirty` on a dirty tree),
so image contents are inspectable rather than merely probably fresh. Owed: confirm the stamp on
a real `make build` — the mechanism was proven on a minimal equivalent image, not the full one.

**Rust now has a client seat.** `cmd/signaling-meet` speaks the same CLI/JSON/exit contract as
Go's and Python's drivers, and its derived keys are **byte-identical to their published vectors
across all four modes** (six for six, `pair` symmetry included) — obtained read-only, no build
or git op in a sibling tree. Live Rust↔Rust meets pass at `tag`/`secret`/`lobby` through a real
`--open` node. That closes the last piece of this feature with no cross-impl evidence: every
other signaling test here is Rust↔Rust, and we were the *node* in Go's matrix, never a
participant. **Not yet run:** a live Rust↔Go / Rust↔Python meet — one command from either side
now, and the key agreement says it should be uneventful, which is exactly the claim this
exercise exists to distrust.

Gate: `cargo test --workspace` **2276 passed / 0 failed / 12 ignored**, fmt clean, clippy clean
but for the pre-existing `assertions_on_constants` in `extensions/continuation`.

_2026-07-30 — signaling Stage 1 merged to `dev`; the go/py client brief is issued_
(`docs/status/HANDOFF-2026-07-30-signaling-go-py-client-brief.md`, following
`HANDOFF-2026-07-29-signaling-merged-cross-impl-next.md`). The connection node's Stage 1 —
`extensions/signaling/` (the three verbs, the §2.2 key derivation, §3.1.1 pool selection, the
§3 coordination messages) plus `cmd/entity-signaling-node/` — is on `dev` at `7f76321`,
fast-forward, **zero edits to `core/` or `bindings/`**. Verified 2026-07-30: `cargo test
--workspace` **2260 passed / 0 failed / 12 ignored**, 72 of them signaling; `cargo fmt --check`
clean; clippy clean but for the already-logged pre-existing `assertions_on_constants` in
`extensions/continuation/`.

_2026-07-30 (same day) — the go and py clients landed, and both found the same Rust defect:_
**the shipped `entity-signaling-node` granted a connecting peer no signaling authority.** The
§4.4 floor is `system/tree:get` + `system/capability:request`, and `request` is pure
attenuation, so there was no path from the floor to `system/signaling` and no flag, config, or
file to add one — every foreign call was 403 before reaching a verb. Invisible from inside this
repo because the only Rust tests that connect to a node seed a **wildcard**, which authorizes
everything and so proves nothing about admission. The class of thing a second implementation
finds first.

Fixed: `entity_signaling::signaling_seed_grants()` (the caps in the shape
`with_seed_policy` consumes, narrow — exactly the three verbs, empty resource scope) wired to
`--open` (serve anyone; the posture the §6 gate needs) and `--grant <peer>` (serve named peers;
the private-mesh posture), which compose. **Closed stays the default** — §2.1 makes the grant
*the* admission control on the wrapped surface, and the open-to-strangers posture belongs to
the unwrapped listener whose protocol is unwritten — but the node now prints its posture at
startup instead of failing silently. New `cmd/entity-signaling-node/tests/admission.rs` (5) +
5 flag unit tests assert what the wildcard harness structurally cannot: a stranger admitted
under the narrow grant, refused without it, no spill onto other handlers, and a named grant
admitting only its peer. Suite **2270 passed / 0 failed / 12 ignored**, 82 signaling.

Go then ran its client against two live `--open` nodes: **`validate-peer -category signaling`
5/5 PASS**, PASS again on a rerun inside the TTL, and the two-instance pool discriminating
across all four modes. Go and Python also derive **byte-identical keys** for all four modes
over fixed inputs and make identical §3.1.1 selections — the highest-risk unknown, closed. The
caveat is theirs and it is the right one: both built against *this brief*, not the committed
spec, so that is **cohort-consistent agreement, not independent convergence**, and the live
go↔py meet through one node is still owed.

Their report also named a "resource-target trap", now pinned here empirically: the identical
`advertise` call is 200 without a resource target and **403 with one**, because signaling
addresses no tree resource and the seeded grant's resource scope is empty by design. Kept
narrow rather than widened to `*`; recorded as a client rule in the brief's §5.1.

One behaviour change that reached the brief: **`reflect` is a 403 against an `--open` node**,
not the 400 the wildcard harness sees — the capability check runs before dispatch, so an
enumerated grant refuses an operation it does not name. Both are correct; clients must not
treat 400 as the only signal that `reflect` is unserved. Also recorded from Python: a
responder that answers the first request in a `pair`/`lobby` bucket adopts a **stale** one on
any rerun inside the 60 s TTL, since those keys are stable by construction.

_2026-07-30 (same day) — the full `validate-peer` packet is issued to Go_
(`docs/status/HANDOFF-2026-07-30-validate-peer-packet-for-go.md`). Go's client then ran the
**live cross-impl meet** — go↔py through a Rust node, both directions, `tag`/`secret`/`lobby`,
byte-identical keys, rerun-safe on the stable `lobby` bucket. §2.2 and §3.1.1 are validated
**live across independent implementations**, not just statically — the highest-risk unknown in
this feature, and the one thing no amount of Rust-side testing could settle. `pair` is covered
statically only (needs an out-of-band peer-id exchange — harness plumbing, not a protocol
unknown).

The packet exists because signaling is not the only thing owed: **six categories are green only
on our own seat** — `authz` (F40), `security` (incl. RT-6), `concurrency` (RT-13b Part A),
`network_reconnect_anchor`, `continuation_bounds` anchor-1 (owed since 2026-07-18), and
`published_root`. RT-6 is the cautionary one and the reason to clear the rest: it was fixed,
shipped, and *still* WARNed, because the intercept sat after generic verification and the
oracle's bare-authenticate replay never reached it — green on our side, unfireable on the wire.

**Our own next build:** Rust has never been a *client* in a cross-impl meet. Every Rust live
test is Rust↔Rust; we are the node in Go's matrix, not a participant. A Rust `signaling-meet`
driver speaking the CLI+JSON contract Go and Python already share would make it a 3×3 matrix and
close the last same-impl assumption on our side.

**Rust's part is done and the next move is not ours.** Stage 1 proves mechanism, not
connectivity — it does *not* connect two NAT'd peers, which is Stage 2. And nothing in this
repo can validate the two things most likely to be wrong: every peer in every test is the
same Rust, so a wrong-but-self-consistent §2.2 derivation or §3.1.1 weight function passes
exactly as a correct one does. **go/py clients + `validate-peer -category signaling` (go as
oracle, two-instance Rust pool) are the first real evidence.** One blocker sits ahead of
that, routed and unactioned: the signaling spec corpus is uncommitted/untracked in the arch
working tree, so the packet's "build against the spec, not the Rust" is currently
unexecutable from a clone — see the brief's §1.

_2026-07-28 — STANDING-MODEL §4 O5 (sweep-all) landed — the last Rust-side §4 residual_
(`docs/status/ROUTING-2026-07-28-standing-model-4-o5-sweep-all-rust.md`; answers
`entity-core-go`'s `HANDOFF-2026-07-28-rust-py-finish-s4-residuals.md`, the one item routed
to Rust — O4 and fire-partial were already correct per the handoff's own table). Ruled by
arch (`PROPOSAL-CONTINUATION-STANDING-MODEL` §7 O5): converge on Go's sweep-all, since a
standing deadline-join that goes silent while the peer stays continuation-active was reaped
by Go but never by Rust's touched-only reap — a permanent cross-peer liveness-marker
divergence. Extended (not replaced) the existing reap-on-touch: any continuation advance
now runs a throttled (60s floor, matching Go's `joinSweepThrottle`) pass over every tracked
deadline-carrying join (`join_paths`, filled from install + touch, matching Go's
`noteJoinPath`) and reaps expired rounds via the existing `reap_join_round`. No background
timer/goroutine — driven entirely by continuation traffic, same as Go.

New test: `test_sweep_reaps_untouched_expired_join` — join A arms and expires with a slot
missing, only join B is ever advanced again, B's advance sweep reaps A anyway (one
`join_incomplete` marker, A's round reset, neither join fires).

Gate: `cargo test -p entity-continuation` 72/72 (was 71/71). `cargo build --workspace`
clean; `cargo build --target wasm32-unknown-unknown -p entity-peer` (CI feature set)
clean; `cargo fmt --check -p entity-continuation` clean; clippy clean except the
already-logged pre-existing `assertions_on_constants` failure (`docs/BACKLOG.md`).

**§4 folds once Python lands O4 (`slot` key) + fire-partial + its own O5 and the live
three-way (liveness/network/continuations/continuation_bounds) re-runs green** — nothing
further gates on Rust.

_2026-07-28 — STANDING-MODEL §4 Facet B (join completion policy) built from zero_
(`docs/status/ROUTING-2026-07-28-standing-model-4-facet-rust.md`; answers
`entity-core-go`'s `HANDOFF-2026-07-28-rust-py-convergence-standing-model-s3-s4.md` Item
2). **Scope correction found before building:** the handoff assumed Rust already had §4
mechanism 2 (deadline+abandon self-heal) and just needed the round_id addendum (§4.1) —
Rust actually had none of §4 (confirmed by exhaustive grep: no `completion_deadline`,
`on_incomplete`, `round_id`, or per-slot status tracking anywhere in
`extensions/continuation`), matching the tracker's `⬜ zero-impl`, not the handoff's
premise. Built the full facet in one pass rather than a partial addendum:

- **Mechanism 2** — `completion_deadline_ms`/`on_incomplete` ("abandon" default |
  "fire-partial") on the join entity; reaped via **lazy reap-on-touch** at the top of
  `advance_join_slot` (at the time, Rust had no background sweep subsystem to extend, unlike
  Go's `CollectExpired*` — documented as a deliberate tradeoff: a round with no further slot
  arrivals is never proactively reaped, every §6 anchor scenario is itself a touch). O5,
  landed the same day (see above), extends this to a sweep-all — the tradeoff above no
  longer holds.
- **Mechanism 1** — a non-2xx slot fills its slot and is preserved in a new
  `received_status` map; the round still fires with the error payload passed through
  untouched (matches Go's actual code, not the handoff's summary — a `join_error_slot`
  lost marker is bound alongside so the failure is observable, and it's the target's job
  to reject an error slot, not the join's).
- **§4.1** — `round_id: u64` on the join (0/omitted-on-wire unless deadline-carrying),
  optional `round_id` on the slot-advance request; a stale-round slot is dropped with a
  `join_late` marker and a 200 `{advanced:false, dropped:"stale_round", slot,
  targeted_round, current_round}` response, never accumulated.

New tests (`extensions/continuation/src/lib.rs`): `test_join_self_heals_after_deadline`
(anchor 3), `test_join_error_slot_preserved_and_marked` (anchor 4),
`test_join_straggler_bleed_caught` (anchor 5, the load-bearing one — proves the fired
round is stitched from a single generation), `test_join_untagged_advance_still_admitted`
and `test_join_round_id_stays_zero_without_deadline` (no-silent-change),
`test_join_fire_partial_dispatches_with_incomplete_marker`.

Two pin candidates beyond the handoff's four §6-R3 pins, both confirmed by reading Go's
actual source (not just the prose): the lost-marker body's `join_path`/`join_slots`
fields (present in Go's real `ChainErrorLostData`, absent from the handoff's abbreviated
list), and the drop-response's `"slot"` key alongside `advanced`/`dropped`/
`targeted_round`/`current_round`.

Gate: `cargo test -p entity-continuation -p entity-peer` 71/71 + 190/190, 0 failures;
`cargo fmt --check` clean; `cargo build --workspace` clean; `entity-peer` clippy clean;
`entity-continuation` clippy clean except the already-logged pre-existing
`assertions_on_constants` failure (`docs/BACKLOG.md`).

_2026-07-28 — STANDING-MODEL §3 authority (AT-1..AT-4) confirmed + pinned_
(`docs/status/ROUTING-2026-07-28-standing-model-authority-at1234-rust.md`; answers
`entity-core-go`'s `HANDOFF-2026-07-28-rust-py-convergence-standing-model-s3-s4.md` Item
1). Go ran all three impls live and found the substrate already three-way GREEN
(liveness 4/4, network 5/5, continuations 61/61, continuation_bounds 3/3); this closes the
one dedicated-test gap the §3 fold gates on. Rust's architecture makes the split correct
by construction — the reactive path (inbox delivery → internal `execute_fn`) never
capability-checks the caller at all, while the administrative path is gated only at the
wire dispatch seam (`connection.rs::dispatch_request`), never inside the continuation
handler. Landed:

- **AT-1** (reactive, no caller cap → advances) — already covered by pre-existing
  `test_reactive_advance_runs_under_own_authority` (`extensions/continuation/src/lib.rs`).
- **AT-2** (administrative, caller holds a cap but not `advance` → 403) and **AT-4/O1**
  (administrative, caller holds nothing relevant → 403 fail-closed) — new two-peer wire
  tests in `core/peer/src/lib.rs` (`test_standing_authority_at2_administrative_wrong_operation_denied`,
  `test_standing_authority_at4_administrative_no_capability_denied`); `Peer::execute()`
  can't exercise this gate at all (bypasses the wire seam), so both had to be full
  connect+authenticate+EXECUTE tests, not handler-level.
- **AT-3** (reactive reconnect, no advance rights) — Rust has exactly one
  `reactive_trigger` production site (inbox delivery); no separate reconnect/browser-defer
  mechanism exists, so AT-3 is the same code path as AT-1. Go's own oracle test pins it the
  same way (byte-identical `setup()` as AT-1). Added
  `test_reactive_reconnect_continuation_advances_at3` as the explicit pin rather than
  inventing a second mechanism.

Gate: `cargo test -p entity-peer -p entity-continuation` 190/190 + 65/65, 0 failures;
`cargo fmt --check` clean; `entity-peer` clippy clean. `entity-continuation` clippy was
already red pre-existing (unrelated `assertions_on_constants` lint, confirmed via
`git stash` — logged in `docs/BACKLOG.md`, not fixed here). Next: STANDING-MODEL §4.1
`round_id` join straggler guard (Item 2, genuinely new — no `round_id`/`completion_deadline`
machinery exists yet in `extensions/continuation`).

_2026-07-27 — 0.8.1 bucket-B (F40/RT-6/RT-13a/RT-13b/RT-14) landed_
(`docs/status/HANDOFF-2026-07-27-core-rust-0.8.1-bucketB-fixes-and-selfreport.md`;
answers arch's `entity-system-architecture`
`HANDOFF-2026-07-27-cohort-0.8.1-bucketB-update-packet.md`, which Rust had not yet
responded to). Two real conformance gaps fixed:

- **F40 (§5.2 id-scope literal matching).** Rust had the same bug keystone found in
  42/43 of the cohort — `operations`/`peers` routed through the §5.4 path-canonicalizing
  matcher instead of a literal string compare. Added `matches_id_scope`
  (`core/capability/src/lib.rs`) and switched `check_permission`,
  `check_permission_with_grant`, and delegation-attenuation's `scope_subset_id` to use it.
- **RT-6 (§4.6 nonce single-use).** Rust had *no* handling at all for a same-connection
  `authenticate` replay (worse than Go's pre-fix 409). Added an explicit intercept in
  `dispatch_request` (`core/peer/src/connection.rs`) returning `401 invalid_nonce`.
- **RT-13a** attested trivial/exempt (not a manual-memory substrate); **RT-13b** confirmed
  already-conformant (single-writer-task / mutex-held-writer serialization) with a new
  peer-side atomicity attestation test added; **RT-14** confirmed already-conformant
  (`Hash::to_hex()` is the only path-segment hex producer, lowercase by construction).

_2026-07-27 (same day) — RT-6 relocated after cross-impl re-validation caught it dead on the
wire._ `entity-core-go` re-validated the above on fresh peers (not the claims in the handoff)
and found F40 genuinely closed (authz 10/10) but **RT-6 still WARN**: the intercept sat *after*
`verify_request_with_ctx`, and the oracle's replay resends the bare connect-EXECUTE shape (no
`author`/`capability`, same as the original pre-Established authenticate) — which fails generic
verification first (`401 authentication_failed`) and never reaches a post-verification check.
Rust's own regression test used a different (fully-authenticated) replay shape and didn't catch
it. Fixed: moved the intercept to a pre-verification peek at `uri`/`operation` (via a newly
`pub` `entity_protocol::decode_execute_fields`, which needs only the three mandatory
`ExecuteFields` and succeeds regardless of `author`/`capability`); the unreachable
post-verification duplicate was deleted. New test
`test_rt6_bare_authenticate_replay_returns_401_invalid_nonce` reproduces the exact shape the
oracle sends. Full detail in the "Correction" section of the same handoff doc.

~~Owed: cross-impl `validate-peer` re-run to confirm RT-6 now PASSes on the wire; the F40 vector
run; the RT-13b Part-A wire probe against a live Go peer.~~ **All three CLEARED 2026-07-31** —
Go's sweep vs Rust `c043c7f`: `connectivity`/RT-6 24·0·0·0 (fires on the wire), `authz` 11·0·0·0,
`concurrency` 6·0·0·0. See `docs/validation/reports/2026-07-31-seven-categories-cleared-and-rust-joins-the-meet.md`.

_2026-07-16:_ NETWORK Amendment 12 **rung 3** landed on `dev` — the
`system/network` maintain-peer reconnect lifecycle in a new
`extensions/network` crate, composed on the rungs-1+2 §A3 liveness floor
(`docs/status/HANDOFF-2026-07-15-network-a12-rung3-rust.md`). Rust's rung-3
anchor passes at the spec-default ~100s envelope. Since then, on `dev`:
`entity peer start` gained the §2.3 `--keepalive-*-ms` overrides (Rust's half
of the cohort's Ask B — test-speed tooling, not conformance); the
wasm-worker stack gained `DisconnectPeer` connection eviction at protocol
**v10**; and the lint gate was widened — `cargo clippy --workspace` is now
`-D warnings` clean across every `bindings/*` crate for the first time
(`make clippy` only ever covered default-members, which excludes them), with
`cargo fmt --check` clean workspace-wide.

_Latest 2026-07-16 — arch rulings absorbed + a security fix_
(`docs/status/HANDOFF-2026-07-16-arch-rulings-and-injection-rust.md`). The arch
packet came back **empty — every open question across three rungs is ruled**
(`entity-system-architecture`
`docs/status/ROUTING-2026-07-16-arch-rulings-to-cohort.md`). Landed on `dev`:

- **Marker path injection — CONFIRMED and contained** (ruling 13). Go's new
  `security` probe FAILed Rust 29/30: a tree node literally named `..`, put in
  our marker tree by an **unauthorized** peer — the §3.10.3 rejected marker is
  bound *because* the cap check failed, so an attacker reaches the binding site
  by construction. Reproduced here, fixed at all three binding sites, with
  `sanitize_path_segment` converging byte-for-byte with Go's.
- **The retry loop survives** (ruling 1 — STANDING). Last session's held fix,
  unheld: **2 → 16 attempts** in 3s at min 60/max 200, stable 3/3. A peer that
  goes offline is recovered again.
- **Marker coordinates mean something** (rulings 9 + 11):
  `.../lost/chain-8a1c.../internal/...` →
  `.../lost/network-maintain-4814.../network-backoff-advance-{nanos}/...`.
  `"internal"` was `ExecuteOptions::request_id`'s default — the seam's name for
  a *category* of dispatch, shared by every handler-to-handler dispatch in the
  workspace.
- **`entity://` canonicalization — RESOLVED** (ruling 24): `canonicalize` now
  resolves `entity://{p}/x` → `/{p}/x`. Rust's longest-standing "cross-impl
  blocker" was never one; cleaning ≠ canonicalizing, and the answer was
  readable in Go's source the whole time. Does **not** close cross-peer
  delivery to a Rust subscriber (the SDK-side stack behind it is still open).

_Latest 2026-07-17 — arch round 2 absorbed + the ruled list nearly closed_
(`docs/status/HANDOFF-2026-07-17-round2-and-derived-pacing-rust.md`). Landed on
`dev` (`ae2bf31`, `32403c1`, `d7d0d79`, `de42323`):

- **Retry pacing is DERIVED, not counted** (#7/#8). `failing_since` is the one
  durable field — stamped at the transition out of `connected`, preserved
  across escalation, cleared on recovery; `attempt`/`next_attempt_at` are a
  pure function of (`failing_since`, cfg, now). The §A6.5 formula is pinned as
  a vector table ported from Go's `core/types/network_backoff_test.go` and
  reproduces its numbers value-for-value. **The table could not see the bug
  that mattered:** the status-path key was only set on a successful establish,
  so a restarted process could not *address* the stamp it was meant to
  re-derive from — restart-hammering, the ruling's headline win, would have
  silently not landed under a green table.
- **Collapse to sentinel, not hash** (round-2 ruling 1, amending 13). Rust was
  the last seat hashing. An attacker could mint unbounded path nodes — the
  pollution vector the injection fix closed, re-opened one layer up. Pinned:
  1000 distinct hostile values → exactly 1 node. The body now carries the
  originals (round-2 ruling 2), which is what makes collapsing lossless.
- **A dead peer's marker tree is EMPTY** (#3 + #2). ~1,440 nodes/day → 0.
  **#2 and #3 are not independent** despite being numbered that way: the
  `on_error` only removes the `reconnect` path's markers; the rest come from
  the backoff's own `maintain-peer` re-EXECUTE returning 502, which ruling 2's
  200-on-armed is what removes.
- **The §2.2 give-up says so** (#6): `max_attempts`/`max_elapsed_ms` decode,
  and exhaustion writes `disconnected` + `reason: retry-exhausted` (no fourth
  status value). Retry-forever remains the normative default.

Ruling 14 is **N/A for Rust** (no synthesized fallback key — `{step_index}` is
`ctx.request_id` directly; evidence in the handoff).

_Latest 2026-07-17 (later) — the ruled list is now CLOSED_ (`53d928b`, `840a2cb`;
routing docs `ROUTING-2026-07-17-marker-feasibility-and-retention-rust.md`,
`ROUTING-2026-07-17-bounds-propagation-rust-position.md`):

- **§4.7 subscription markers record who caused the substrate write** (#18, now
  MUST — `53d928b`). Every §4.7 lost-error bind — four synchronous limit/token
  sites + the async delivery worker — now uses `set_with_context` with the W6
  split: `capability`/`handler_grant` = the subscription component's own grant
  (resolved lazily; `None` degrades, never drops), `caller_capability`/`author`/
  `request_id` = the triggering caller (captured into `DeliveryWork` for the
  worker, which has no ctx). Also converged the `{reason}` sanitizer to the
  shared `sanitize_path_segment` (ruling 1 straggler — the hand-rolled copy
  wrongly rejected spaces §1.4 permits).
- **Marker handler-grant feasibility — ANSWERED** (owed to the cohort). Option
  (ii) works on Rust with no cap-check rework, for a stronger reason than Go's:
  the bind is a substrate write through `set_with_context`, and Rust enforces
  caps at the dispatch seam, not the write seam — `set_impl` reads no
  `dispatch_capability`, so the F2 trap cannot occur by construction. option (i)
  MUST-provision not needed here.
- **Retention / `RetainMarkersForever` (#19) — ROUTED, not built.** Rust has no
  marker-collection machinery (nor does the DISCOVERY pattern the proposal says
  to mirror), the landed spec still says MAY, and rulings 2+3 already took the
  dead-peer marker tree to empty — so a self-collection MUST is a heavy,
  effectively-untestable (24h) instrument for a surface that barely grows. Asked
  arch: is the MUST warranted, or does §5 stay a MAY? Logged in SPEC-AMBIGUITIES.
- **Cross-peer chain bound (`chain_depth` in `system/bounds`) — shape + O1
  confirmed, build HELD.** core-go's bounds-propagation proposal is DRAFT and
  touches wire-core; core-go itself held the cross-peer half. Rust has no
  `chain_depth` mechanism at all. Rather than lead a speculative wire-shape solo,
  Rust confirmed the field shape and the O1 causal-vs-standing signal (key on the
  presence of inherited `bounds.chain_depth`, matching Go) and will build the
  wired brake once the proposal folds or a second seat lands the field.

_Latest 2026-07-18 — both held builds UNBLOCKED and landed_
(`ROUTING-2026-07-18-bounds-and-q2-build-rust.md`; Go's
`ROUTING-2026-07-18-go-standing-model-q2-and-o1.md` landed the wired field + pinned
both O1s — the exact hold conditions Rust's 2026-07-17 note set):

- **Wired `chain_depth` brake built** (bounds-propagation, from the field up — Rust
  had no `chain_depth` at all). `chain_depth` on `Bounds` + CBOR + `system/bounds`
  type; **Delta 1 fixed** — the remote branch dropped bounds entirely (no encoder
  existed), now `build_authenticated_execute`/`send_execute` carry a bare-map
  `system/bounds` so `chain_depth`/`chain_id`/`ttl` survive the hop; inherit+`+1`
  on causal advance, root-at-0 on a fresh trigger (O1 = presence of inherited
  `bounds.chain_depth`, verbatim with Go); **§3.9 suspend** persists a resumable
  `system/continuation/suspended` entity with `reason: chain_depth_exceeded` and
  stops the chain; **§3.7 resume roots `chain_depth` at 0**. `chain_depth` is the
  independent brake regardless of ttl (Q1 §4a).
- **Standing-model §3 (Q2) — split holds by construction, marker adopted for
  convergence.** Rust has no advance-time caller-cap check (caps at the dispatch
  seam), so anchor 1 passes by construction — no Q2 defect, same shape as the
  marker-grant feasibility answer. Adopted the explicit per-dispatch
  `reactive_trigger` signal (Go's `ReactiveTrigger` analog) set by the inbox
  deliverer and threaded through `make_execute_fn` — the declared O1 signal, not
  an inference.
- **Gate green:** clippy `-D warnings` clean, 119 test-suites pass (6 new unit
  tests + a wire round-trip), fmt clean, wasm32 CI build green. ~~**Owed:** the
  cross-impl `validate-peer` / Go↔Rust anchor-1 run.~~ **CLEARED 2026-07-31** —
  `continuation_bounds` 3·0·0·0 vs Rust `c043c7f`. ttl-refill parity (§6) is still
  flagged, not built.

_Earlier 2026-07-16:_ Go's `network` category asked two questions it had never
asked before, and **both found real defects on all three seats**
(`docs/status/HANDOFF-2026-07-16-network-retry-survival-rust.md`; the cohort
report is `entity-core-go` `docs/validation/reports/`
`2026-07-16-retry-survival-cohort.md`). Yesterday's `network` 4/4 stands — it
was true; the category simply did not ask.

- **The reconnect retry loop stops after 2 attempts** — confirmed on Rust from
  our own substrate (2 attempts in 3000ms where §2.2 predicts ~20,
  reproducible 3/3), by counting §3.10 markers in-process rather than Go's
  external dial socket. §4.1's one-shot backoff continuation is re-armed by
  the very `maintain-peer` it dispatches, so the advance's post-dispatch
  consume deletes the re-arm. A peer that goes offline is never recovered.
  **Not fixed here — blocked on the §4.1 lifecycle ruling** (arch's call;
  Go's standing-continuation fix is explicitly not offered as a cohort
  answer). Pinned by `a12_retry_survives_outage`, `#[ignore]`d because it
  asserts the *current, defective* behavior.
- **`chain_id` must be a single path segment** (§3.11) — §4.1's literal
  `network/maintain/{sid}` forks the marker tree. Landed (opaque, shim-free).
- **§3.6 step 6 was unimplemented** — the advance dispatched with no bounds,
  so a chain-less trigger left every marker binder inventing a coordinate;
  Rust's fallback was the request id, which is the literal `"internal"` for
  handler-to-handler dispatch. Landed: mint the chain once, use it for both
  the marker and the dispatch bounds.

Still queued: cross-peer subscription delivery to a Rust subscriber; the
§7.2 second-half arch call and the rung-3 convergence pass (tracker #7).

The most recent substantive engineering thread before the release was
**cross-peer subscription delivery** (see Done recently / Waiting on): the
reported publisher-side bug is fixed and
the substrate completed, but the Rust-*subscriber* side of cross-peer delivery
remains a diagnosed-but-unlanded stack, bottoming out on a cross-impl
capability-canonicalization question logged in `docs/SPEC-AMBIGUITIES.md`.

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

1. **Two questions routed to architecture — waiting on the model answer, not on
   Rust.** (a) Retention: is a self-collection MUST warranted, or does §5 stay a
   MAY? (`ROUTING-2026-07-17-marker-feasibility-and-retention-rust.md`). (b)
   `chain_depth` in `system/bounds`: Rust confirmed the shape + O1 signal and
   held the wire build pending fold / a second wired seat
   (`ROUTING-2026-07-17-bounds-propagation-rust-position.md`). The ruled list
   itself is otherwise **closed** (#18 landed, feasibility answered, #14 N/A).
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
5a. **Re-diff signaling against the arch corpus when it lands.** The highest-value
   outstanding item and the one that upgrades every green result in the signaling
   arc from cohort-consistent to independent convergence. Not ours to schedule.
5b. **Validate `EXTENSION-NETWORK` §6.7.1** (`observed_address` on HELLO,
   Amendment 13) — buildable in all three impls **now**, never validated by anyone,
   and the source of the v1 punch's `srflx`. The cheapest real progress toward
   Stage 2, and unlike Stage 2 itself it is not blocked on arch.
6. **Cross-peer subscription delivery to a Rust subscriber** — unblocked at the
   core by ruling 24; land the SDK-side grantee/signature/handler-scope fixes.
7. Keep the green gate (`make check` = lint + test) and `make wasm` passing on
   any change.
