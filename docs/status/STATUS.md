# entity-core-rust — status

_Updated: 2026-07-18 · public: v0.8.0 (master)_

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
  tests + a wire round-trip), fmt clean, wasm32 CI build green. **Owed:** the
  cross-impl `validate-peer` / Go↔Rust anchor-1 run (a same-side round-trip cannot
  prove wire fidelity); ttl-refill parity (§6) is flagged, not built.

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

- **Nothing is blocked on architecture.** Rounds 1 and 2 are both absorbed.
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
   (`ROUTING-2026-07-18-bounds-and-q2-build-rust.md`). **Owed:** run the cross-impl
   `validate-peer` / Go↔Rust `continuation_bounds` anchor-1 and file the report
   under `docs/validation/reports/` — a same-side round-trip cannot prove wire
   fidelity, and it needs the Go peer this tree cannot drive alone.
3. **Cross-peer subscription delivery to a Rust subscriber** — unblocked at the
   core by ruling 24; land the SDK-side grantee/signature/handler-scope fixes.
4. Keep the green gate (`make check` = lint + test) and `make wasm` passing on
   any change; run `validate-peer` / `wire-conformance` on any wire-shape touch.
   **Two re-probes are owed from Go's side and neither has run:** the `security`
   category (30/30 — the injection FAIL is fixed here, and the coordinate has
   since churned from the hash to sentinels, so the probe's expected value moved
   with it), and `network_reconnect_anchor` (was 4/5 on Rust; #3 + #2 are the
   fix). Our own vectors are green on both; a same-seat suite cannot close
   either.
