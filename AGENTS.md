
# entity-core-rust

Read **AGENTS-STANDARD.md** first. This file adds entity-core-rust specifics.

## Overview

Rust implementation of Entity Core Protocol v7.9 — a clean rewrite replacing
`entity-core-rs`. This repo **implements** the spec; it does not design protocol.
Three deployment roles from one codebase: data toolkit, embedded peer, standalone
server. The crate DAG and design rationale live in `docs/ARCHITECTURE.md`; WASM
compatibility and the worker stack live in `docs/ARCHITECTURE-WASM-AND-TRANSPORT.md`
— this file does not repeat them.

## Committing & pushing — standing authorization

**Commit and push finished work without asking.** When a change is complete and the
gate is green (`make test` / `make clippy` / `make fmt`, plus `make wasm` when it
applies), `git commit -s` it and `git push origin <branch>` — do not stop to ask
whether to commit or push, and do not end a turn leaving finished work uncommitted.
Sibling repos pin our commits; an uncommitted tree is an unciteable one.

The golden rules still bind: **never force-push**, never rewrite shared history, and
never push to the `codeberg` mirror (append-only, ADR-0014) — `origin` is the push
target. Ask only when a push would be non-fast-forward, or when the work is genuinely
unfinished.

## How we work here — tier **CORE**

This repo runs the entity-OS methodology at the **Core** tier — the framework is
`METHODOLOGY.md` (injected, identical everywhere; read it once). Conformance gates the wire
here. It does **not** catch process drift, stale build-state claims, unaccounted accumulation,
or a discipline quietly eaten by a competing legitimate pressure. Those need the ratchet.

What binds today:

- **Universal disciplines D1–D12** (`METHODOLOGY.md` §4) — apply as written; nothing to re-derive.
- **The review questions** (§6) — run on every diff.
- **The Audit Doctrine A0–A12** (§7.2) — open it for *"Y is broken"* or *"something feels
  wrong,"* including when the thing that feels wrong is our own process. **A1 is the prime:
  trace a value before you theorize.** The Foundation Audit Doctrine (§7.3) when opening a new
  surface to design against.
- **The ratchet** — every audit ends by syncing what it taught into this file, same session.
  **If it didn't land here, it didn't land.**
- **The promotion ladder** (§3) — bit us once → an anti-pattern entry; a second time in a
  different shape → a ratified discipline. Candidates are applied, not yet claimed to generalize.
  **A discipline with no enforcement point is theater** — name the grep, the lint rule, or the
  gate test.

**Owed:** a standing `DISCIPLINE-*` doc assembling this repo's own rules with an anti-pattern
catalog, each entry grounded by a source commit. The near-term native candidates are the ones
this stack actually forces — ownership/`Drop` accounting across the extension boundary, and the
cargo-feature-gating hazard where a `#[cfg(feature)]`-gated handler reads as an absent substrate
surface and tempts a reinvention (the `local-files` reinvention is the worked instance of that
class ecosystem-wide).

## Setup / environment

- **Cargo workspace.** Build via `make` over podman (host needs only `make` + podman);
  see `Makefile` for the verb set — `make test` / `make clippy` / `make fmt` / `make godot` /
  `make wasm`.
- **Edition / MSRV:** edition 2021; toolchain pinned to **1.94.1** via `rust-toolchain.toml`
  (ships `clippy`, `rustfmt`, and the `wasm32-unknown-unknown` target).
- Cross-compile target for browser builds: `wasm32-unknown-unknown`.
- Idioms: `tokio` (async, base `features = ["sync"]`), `ciborium` (CBOR),
  `thiserror` (per-crate typed errors), `async-trait`. Godot binding: `gdext 0.4`;
  FFI: `cdylib` + `cbindgen`.

## Build & test

```bash
make test                      # full suite over default-members (see below)
make clippy                    # lint
make fmt                       # format
cargo test -p entity-core      # single crate (use -p <crate> for any other)
make godot                     # bindings/godot lane — NOT in default-members (see below)
make wasm                      # wasm32 CI build (see below)
make features                  # 27-configuration cfg matrix — see below
make check                     # lint + test + godot
```

**Run `make features` whenever a change adds or moves a guard, and always when it
touches `core/peer`.** `make test` and `make clippy` both run the *default* feature
set, so neither sees a symbol that only exists under some `#[cfg(feature = …)]`.
That gap is not theoretical: the §5.2 sub-dispatch denial (`90e60c0`) built its 403
body with `make_error_response_entity`, which was `#[cfg(feature = "compute")]` —
so with `compute` off the security guard did not merely lose its message, it
**failed to compile**, and had that helper been infallible the guard would have
compiled away silently. Green `test` + green `clippy`, defect intact. This is the
cfg-gating hazard already named below, from the other direction: not a gated symbol
misread as an absent surface, but a gated symbol quietly removing a guard that
depends on it. **A security invariant of the dispatch core must not be reachable
only through an extension's feature gate** — say so at the `fn` when you un-gate one.

**And the same shape one level IN, at the TEST set: `make features` runs
`cargo clippy -p entity-peer …`, with no `--tests`, so the 27-configuration matrix
never compiles the test module — a `#[cfg(feature = …)]` mistake in a TEST is
invisible to the one gate that exists to find cfg mistakes.** *(Candidate: bit us
once, 2026-09-01, caught before landing.)* The FM-1 rows for the http-live transport
call `dispatch_session_envelope`, which is `#[cfg(all(feature = "http-live", …))]`;
written without a gate they compiled fine under the default set and would have broken
every config in the matrix that drops `http-live` — and all six `make` verbs would
still have gone green, because none of them builds `entity-peer`'s tests off-default.
**Enforcement:** when a test touches a cfg-gated symbol, run
`cargo check -p entity-peer --tests --no-default-features` (and `--all-features`)
directly — `make features` does not cover it, and the fix is not to widen that verb
casually, because `--tests` across 27 configurations is a different cost class.
**The corollary is the sharper half, and it is about where a CONTROL row lives.** A
fix's control — the row that fails if you "fixed" the defect by relabelling a
catch-all rather than by discriminating — is worthless in any configuration it does
not compile into. FM-1's anti-rename control is therefore on the **ungated TCP**
path, with the http-live rows gated beside it: the same rule as the `fn`-level one
above (*a security invariant must not be reachable only through a feature gate*),
applied to the test that proves the invariant rather than to the invariant.

**And the same shape one level out, at the PACKAGE set: `make test` / `make clippy` /
`make fmt` run `default-members`, so a member left out of that list is out of the gate
entirely — and the gate will report a green number for the set it ran.** This repo has
no CI workflows; every other `make` verb names its packages explicitly (`build` → `-p
entity-cli`, `wasm` → `-p entity-peer` + the worker crates, `features` → `-p
entity-peer`), so `default-members` **is** the coverage boundary, not a build-speed
knob. Six members sat outside it with no stated reason: `7c21d04` then changed
`make_execute_fn`'s signature and broke `entity-sdk`'s **compile**, `90e60c0` repaired
the call sites, and the §5.2 ceiling it introduced left `entity-sdk`'s
`follow_continuation_standing_leg_fires_cross_peer` red on `dev` for five days. Both
commits reported *"make test 115 suites green"* and both were honest about the set they
ran. Five of the six joined the list (2220 → 2628 tests, 116 → 127 suites, cold peak
2.12 → 2.37 GiB); `bindings/godot` got **`make godot`** instead, because `godot 0.4`'s
`codegen-full` is one rustc peaking at **4.44 GiB** against 2.12 GiB for the entire rest
of the workspace, and folding it in would have forced `CAP_MEM` from 4g to 8g for every
`make test` on every machine. That lane also selects `-p entity-sdk`: the sdk's
`identity`/`role`/`quorum`/`attestation`/`compute` features are default-off and godot is
the only crate that enables them, so 43 sdk tests live only in that unification group
(216 in `make test`, 259 in `make godot`). **A second lane is not a place to put a crate
you'd rather not build — it is a place where something is actually run, and you owe the
count that proves it.** **Enforcement, written at the `default-members` block
itself: an excluded member owes a comment naming the lane that covers it, exactly as the
four `bindings/wasm-worker-*` crates do** (`make wasm`) — or it belongs in the list. The
wrong fix is `--workspace` on `make test`: it compiles the wasm-only crates natively to
empty modules, which is coverage that reads as coverage and is not. Same check for any
*new* crate: `cargo metadata --no-deps --format-version 1 | jq -r '.packages[].name'`
against the default set before you claim the gate covers it. And when the reason for an
exclusion is **cost**, measure it — `cat /sys/fs/cgroup/memory.peak` inside the run
container, against a fresh `CARGO_TARGET_DIR` — rather than asserting the crate is heavy.

**So the gate is now four commands, not three: `make test` · `make lint` · `make godot`
· `make wasm`** (`make check` = the first three; `make features` on top whenever a change
adds or moves a `cfg` guard). Two of them exist because two members are deliberately out
of `default-members`, and each of those exclusions names its lane at the exclusion.

If the podman build fails with `could not parse/generate dep info … Permission
denied (os error 13)`, that is an SELinux MCS relabel race against the shared
`~/.cache/cargo-target-entity-core-rust` volume (`:Z` on a concurrently-used
mount), not a code error. Re-run; it is not a signal about the diff.

WASM CI build excludes `websocket` (tokio-tungstenite doesn't compile for wasm32):

```bash
cargo build --target wasm32-unknown-unknown -p entity-peer --no-default-features \
  --features "inbox,continuation,subscription,clock,revision,query,history,compute,handlers,identity,role,registry,discovery,type-system,content,signaling,network"
```

Add `-p entity-wasm-worker-host -p entity-wasm-worker-proxy -p entity-wasm-worker-protocol`
when touching the worker crates. `attestation`/`quorum` are transitive via `identity`
(list only when testing without identity). `local-files` MAY be enabled on wasm32 but is
conventionally left out for clarity. Check WASM only for changes to async/await, time,
networking, or spawn.

`signaling` and `network` joined the lane at S1. Both extension crates are socket-free,
so what the wasm build carries is the **carrier half** (rendezvous-key derivation, the
§6.1 coordination messages, candidate selection). The TCP wiring in `core/peer` —
`punch_establisher`, `srflx`, `reuseport` — stays `not(target_arch = "wasm32")`; a
browser gets its traversal from a WebRTC `LiveEstablish` impl at the §10.3 seam, which
is already `#[async_trait(?Send)]` on wasm32 for exactly that reason. Don't "fix" those
gates by making the TCP path compile on wasm32.

## Code style

- **Spec-first, minimal-diff.** Every decision traces to a spec section; read the passage
  before coding. No opportunistic refactors; closeout-tier tasks ship ~the proposed LOC.
- Errors: `thiserror` enums per crate, no string errors. Wire: **CBOR only** (no JSON).
  Concurrency: `tokio` + `Arc<RwLock<>>`.
- **WASM handler impls** use cfg-gated `async_trait`; use `web_time` not `std::time`. See
  `docs/ARCHITECTURE-WASM-AND-TRANSPORT.md` for the exact pattern and the worker-boundary rules.
- **Hot paths:** `SyncTreeHook`/`on_tree_change` engines MUST cache their decoded config in
  `RwLock<...>` and refresh only on events under their own config subtree — never
  `location_index.list()` + `content_store.get()` + decode per put (that was a 100×+
  regression). Canary: `core/peer/src/lib.rs::perf_treeput_1100` (`--release`).
- **A comment asserting a concurrency invariant MUST name the construct that enforces it —
  and a read-modify-write on shared state is a defect until it does.** *(Candidate: bit us
  once, `7776675`, and it cost a sibling ten days of wrong analysis.)* `auto_version_once`
  advanced the revision head with a plain `set()` under a comment reading *"SyncTreeHooks fire
  synchronously within a single cascade thread; cross-thread contention is handled by the
  NotifyingLocationIndex cascade discipline. A plain set() is conformant under that
  serialization property."* **There is no such property.** `set_impl` mutates the inner index
  and then calls `dispatch_event` holding no lock, so N writers run N cascades — and N copies
  of every hook — in parallel. The comment named a mechanism (*"the cascade discipline"*) that
  does not exist as code, and nobody checked, because prose that sounds like an invariant reads
  like one. `RootTrackerEngine::apply_event` had the same shape with no comment at all. The
  cost was not only ours: meta's cross-impl read declared rust *"structurally exempt"* from
  go's last-burst-write loss **on the strength of this comment**, so the analysis that should
  have found our bug cited it as the reason we could not have one.
  **Enforcement.** Grep the pattern, not the prose: a `get(...)` / `list(...)` followed by a
  `set(...)`/`put(...)` to the **same path** in one function is a read-modify-write, and on any
  path a `SyncTreeHook` can reach it needs CAS+retry or a lock, named at the `fn`. When you
  write a comment claiming serialization, cite the **type and the field** that provides it
  (`Mutex<_>` at `X::y`) — if you cannot, you have found the bug. And prefer CAS to a lock on
  any path whose write re-enters the cascade: a per-prefix mutex in `auto_version_once` would
  deadlock, because a universal-prefix config routes that write back through the root tracker
  into the same function for the same prefix.
  **The other half, and it is why the in-tree suite could never have caught this: an
  in-process load test is not a net for an in-process race.** An 8-writer × 40-round burst
  through the real `NotifyingLocationIndex` + tracker + revision chain **passed with the head
  advance mutated back to the broken `set()`** — the window between the read and the write is
  nanoseconds when there is no socket in the path, so the scheduler never interleaves. It was
  written, measured against the mutation, found toothless, and **deleted rather than kept as
  reassurance**. What works is a forced interleave: a `LocationIndex` decorator that fires a
  one-shot injected write on the first read of the watched path, *after* sampling the value the
  caller gets back (`InterleaveOnRead`, in both `core/tree` and `extensions/revision`). That is
  deterministic, single-threaded, and mutation-RED every time — the same conclusion core-go
  reached from the other side (*"net it with a deterministic forced-interleave test, not
  `-race` or test-starved"*). Corollary for reporting: **a concurrency fix's wire number is the
  evidence; the in-tree green is not.** Ours went 4-of-8-lost → PASS 5/5 at ~30ms, and the
  image label must read `dirty` at your HEAD or you measured a stale binary.
- **A MUST-write owes a named collector, swept BEFORE the write.** A spec'd write with no
  reaper is a leak by construction (CONTINUATION v1.23 §3.4 A.1 — ~1,440 marker nodes/day
  against one dead peer). When adding the reaper: sweep at the top of the bind path, never
  after it — an entry whose *origination* timestamp already predates the window would
  otherwise be removed by the very call that wrote it, which reads from outside as the write
  silently failing. Wire it at **every** binder you actually run, not just the one that owns
  the sweep code (here: the continuation handler *and* the dispatcher's `rejected` markers,
  which are caller-driven and unbounded). Reference: `extensions/continuation/src/marker_collect.rs`;
  the ordering is held by `test_distinct_timestamps_yield_distinct_paths` /
  `test_path_safety_sanitization` / `test_mirror_pointer_in_body`, which fail if the sweep
  moves after the bind.
- **A guard's own comment is an INVENTORY of the checks it owes — read it as a checklist
  against the code beneath it, because a loop that binds a variable and uses it only in the
  error message has discarded half the invariant.** *(Candidate: bit us once, 2026-09-13, and
  it had been shipping since the guard was written. Severity: capability forgery.)*
  `verify_request` step 2b exists to close *"a forgery surface where a peer could substitute
  an entity for a known hash via envelope manipulation — downstream hash-keyed lookups like
  `included[h]` would index the substitute under h, even though h ≠ recomputed(substitute
  .bytes)"*. That sentence names **two** checks. The loop was
  `for entity in envelope.included.values() { entity.validate()?; }` and ran **one**:
  `validate()` recomputes `Hash::compute(type, data)` against the entity's **own**
  `content_hash` field — *self-consistency*, which any honestly-built entity satisfies,
  **including the attacker's**. The half about the **map key** — the address every downstream
  lookup actually uses — was thrown away by `.values()`.
  **What that bought an attacker, measured (`core/protocol/tests/included_key_binding.rs`,
  `verify_capability_chain` returned `Ok(())`):** file your own `system/peer` entity under a
  victim's identity hash, and every per-link check passes on its own terms —
  `sig.signer == cap.granter`, the resolved entity is a `system/peer`, and
  `verify_peer_data_sig` verifies **your** signature against **your** key, because that is the
  key it just looked up under the victim's hash. You need no key and no identity entity of the
  victim's, only the victim's identity *hash*, which is the public `grantee` field of any
  capability they present. So an observer of any chain could mint a leaf off it, up to the
  parent's own scope. The root link stays genuine, attenuation holds because you wrote the
  leaf, and nothing anywhere looks wrong.
  **Three transferable parts.**
  (a) **`validate()`-shaped and `is-this-the-right-one`-shaped are different questions that
  read alike.** *Self-consistent* and *correctly addressed* are one word apart in English and
  are unrelated properties; a function named `validate` answers the first and will be read as
  answering both. Same family as *one representation carrying two meanings*, at the level of a
  method name.
  (b) **In a content-addressed map the KEY is the hash of the VALUE, and that is a property of
  the TYPE, not of a code path.** Enforce it at the constructor — `decode_envelope`, which is
  where such a map is built from received bytes — and at any `pub fn` whose return value is a
  security verdict and whose callers build their maps differently
  (`verify_capability_chain`: `verify_request` builds from `envelope.included`,
  `presented_authority_authorizes` from a §7a.2a bundle merged with the parent envelope's).
  An invariant that lives in the callers is one the next caller does not inherit.
  (c) **The greps.** `grep -rn '\.values()' --include=*.rs` over any loop that validates a
  hash-keyed map, and `grep -rn 'included.get(' --include=*.rs` to enumerate what addresses it
  by key (here: `granter`, `grantee`, `parent`, `collect_authority_chain`'s resolver,
  `handle_diff`'s snapshot resolution). If a lookup keys on a hash read out of *another
  entity's data*, the key is load-bearing and something must bind it.
  **Enforcement and the measured per-site result**, because this rule is satisfiable at three
  sites and three sites is where one becomes an unmeasured claim: the decoder mutation reddens
  the decoder row, the `verify_capability_chain` mutation reddens the forgery row — **disjoint**
  — and the `verify_request` step-2b mutation reddens **nothing**, so that call is recorded at
  the code as defence in depth with the property it *would* cover (non-chain `ctx.included`
  lookups on an in-process `Envelope`) named as **unmeasured**. The control
  (`a_correctly_filed_delegation_chain_still_verifies`) is not optional: the fix is a
  comparison of two `Hash`es and getting it backwards refuses every well-formed envelope in
  the system.
  **Cohort note, and the evidence level is stated because it differs by seat.** Read at the
  line, core-go's `Envelope.ValidateAll` (`core/entity/envelope.go:57-62`) has the identical
  shape — it binds `h` in `for h, ent := range e.Included` and uses it only in the error
  string — and `grep -rn '!= ent.ContentHash' core/` finds no key comparison. That is a code
  read, **not a drive**: routed to go and py to confirm and drive in their own trees. Our own
  finding is measured; theirs is not, and the report says which is which.
- **A hypothetical you check MUST carry the shape you will write.** *(Ratified: bit us
  twice, in opposite directions.)* When a decision is made by probing a synthetic value
  through the real validator — `is_attenuated(&child, parent)`, an RL2 hypothetical, any
  "would this pass?" construction — build the probe with **every** field the persisted
  value will actually carry, and compute the derived ones *before* the probe, not after.
  A probe that differs from the write is a check against a value that never exists:
  - **Too permissive** → passes at issue, rejected at use. ROLE v1.7 §5.3 names this
    verbatim ("RL2 OK at issue, chain-invalid at use") — `build_hypothetical_token` +
    `effective_expires_at`, `extensions/role/src/handler.rs`.
  - **Too strict** → nothing issues at all, and the 403 looks like a scope defect. §6.2
    `request` built its probe `expires_at: None` while `is_attenuated` enforces §5.6's
    "child expiry ≤ parent's" — so **every** request from a caller whose cap expires was
    403, and the arch proposal that measured us read the symptom backwards. Fix: clamp
    first, probe with the clamped value (`clamp_mint_expiry` → `child`).
  **Enforcement:** the probe's assertion belongs in a test that fixes the derived field on
  the *parent* — `request_mint_cannot_outlive_the_caller_capability` fails (403, not a
  wrong expiry) if the probe and the mint drift apart again. Grep for `is_attenuated(&`
  and any `hypothetical`/`probe`/`would_` construction when touching a mint path.
- **One representation carrying two meanings is the bug — split it so the distinction
  cannot be a mistake.** *(Ratified: bit us twice, in two representations.)* The first was a
  type (`7c21d04`, below). The second was a **field name**: `since` meant an *exclusive
  watermark walking newer* on `fetch` and an *inclusive cursor walking older* on `log`, so
  the same argument returned **disjoint** sets from the two operations with no error
  anywhere — and in our tree the collision was literally one function, `decode_log_params`,
  serving both handlers, with the SDK's `build_log_params` serving both encoders. **When two
  operations share a decoder, they share a vocabulary; check they mean the same thing by
  it.** The fix is never to pick one reading: §4.4.2 removed the collision (`log` takes
  `start_at`, `fetch` keeps `since`) and we split both the decoder and the builder, because
  a shared code path is what lets the two meanings drift back together (`59e6f55`).
  **Third shape, and it is an ARGUMENT rather than a type or a name: one parameter carrying more
  than one rule, so passing the wrong value silently deletes a check instead of mis-formatting a
  value.** *(2026-09-09; it is the same family, so it strengthens this entry rather than opening
  one.)* `verify_capability_chain(hash, bundle, local_peer_id)` reads as a canonicalization frame,
  and mostly is. It is also the input to **§5.5 root-trust** — *"the single-sig root's granter must
  be the local peer"* — and to the absent-`peers` default. Verifying a capability the **target**
  minted requires passing `target_peer` there; passing our own peer id does not mis-canonicalize a
  path, it answers `NotLocalPeer` on every credential the check exists to accept, and in the other
  direction it would default `peers` to `{include: [local]}` where the minter meant *"at me."* The
  tell is the same as the `Option<T>` one: you catch yourself explaining what an argument means
  **twice with different answers** depending on who granted the thing. Remedy here was not a new
  type — the call sites are two — but naming every rule the argument decides at the call site, so
  the next reader cannot "simplify" it back to our own pid
  (`connection.rs::presented_authority_authorizes`). Grep `local_peer_id` on any path that
  verifies a **foreign-granted** artifact and ask, per rule, whose frame it is.
- **A closed grammar needs a writer that refuses, not just a matcher that omits — and
  where nothing *can* be refused, say so at the `fn`.** *(Ratified: bit us twice, and the
  second time the correct answer was the opposite one.)* §2.4 pinned the exclude matcher to four forms; the
  matcher is only half the rule. A peer that drops `**` from its matcher and a peer that
  rejects `**` at config write are **indistinguishable until a config carries one** — and
  then they silently disagree about trie membership, which decides the version root, which
  is the version's identity. §4.4.17 V6 is the load-bearing half, and it belongs **before**
  any check that interprets the value: our required-exclude coverage test would otherwise
  have read `system/**` as coverage and stored a pattern we refuse to evaluate. Same shape
  for any pinned vocabulary — validate at the boundary that persists it, and put the
  refusal ahead of the interpretation.
  The second bite inverted it. REGISTRY §4's `name_format_dispatch` grammar is *also*
  closed — `*` only, every other byte literal — and reaching for the same V6 shape would
  have been wrong: **no pattern is invalid there**, because every non-`*` byte is a literal,
  so §4 says outright that a registry MUST NOT reject a pattern for containing `?`, `[`, or
  `\`. Two closed grammars, opposite write-time dispositions, and the difference is whether
  the grammar *can* be violated. So the rule has two halves: refuse at the writer when the
  grammar admits a violation, and **state the absence of a refusal at the matcher when it
  does not** — otherwise the next reader ports V6 across and starts 400-ing legal configs
  (`9f02618`, `dispatch_match`).
- **An `Option<T>` whose `None` must mean opposite things is the wrong type — name the
  third state.** *(Ratified with the rule above; this is the first of the two shapes,
  `7c21d04`.)* §5.2's resource dimension needed a
  ceiling for in-process sub-dispatch. Modelled as `Option<CapabilityToken>`, `None` had to
  mean **deny** for a handler holding no grant and **allow** for the peer's own SDK/engine
  entry points, which present no capability because they are the root authority. Both are
  correct readings of "absent," and either default is a shipped bug: deny breaks every
  `Peer::execute_with_options`, allow reinstates the escalation for exactly the grantless
  caller. `DispatchCeiling::{PeerRoot, Handler(Option<_>)}` makes the distinction
  unrepresentable-as-a-mistake and forces every call site to state which it is. **Reach for
  the enum the moment you catch yourself writing "`None` here means…" twice with different
  answers** — the compiler then finds the call sites for you, which is how the sweep stayed
  honest across 14 of them.
- **A check added to a path that ran none starts READING fields that were written when
  nothing read them — audit the values it will now consult, not just the call sites the
  compiler makes you touch.** *(Candidate: bit us once, `7c21d04` → found 2026-08-23.)*
  D1 gave `make_execute_fn` a §5.2 resource ceiling. The type change forced 14 call sites
  and every one got a considered answer; what nobody looked at was the **`resources` field
  of the grants the ceiling would now consult**, because until that commit no code path
  read it. §6.9's default per-handler self-grant is described as *"all resources"* and was
  written `PathScope::all()` — bare `*`, which `canonicalize` resolves to `/{local}/*`.
  Harmless as an unread field; as a ceiling it means **own namespace only**, so the peer's
  own engine could no longer write the foreign-namespace subtrees its store legitimately
  holds (V7 §1.4 Category A — a cached foreign site, a `follow` mirror at `/{them}/app/…`).
  `follow(Continuation)`'s standing leg 403'd at its `system/tree:merge` step and stayed
  red for five days. The same trap was already documented one function over: `debug_open_grants`
  carries an R-5 note saying bare `*` excludes `/{X}/…` and uses `/*/*` for exactly this
  reason — a *written* precedent that the new reader did not inherit. Fix is
  `default_handler_self_grant()` (`/*/*`), kept distinct from `wildcard_handler_grant()` so
  the own-namespace call sites that want confinement still say so.
  **Enforcement:** when a commit turns an inert field into an authorization input, grep every
  constructor of that field (`grep -rn 'resources:' --include=*.rs`) and ask what each one
  **means** versus what it **encodes** — the two are only the same once something checks. And
  pin the answer at *both* ends: `default_handler_grant_ceiling_reaches_a_foreign_namespace_path`
  (core/peer) fails against the pre-fix `wildcard_handler_grant()`, and its narrow-deputy
  control fails if the new check is neutered — verified by running both mutations, because
  "widening the default" and "putting a hole in D1" are one edit apart.
- **Prove an absence by construction, not by grep, before you report it.** *(Ratified: bit
  us twice, and the second time the region was the build graph, not the file.)* The
  `substitute` category skipped against our peer and core-go's report read that as *"a 1-skip
  coverage artifact, not a defect."* Checking rather than adopting the reading: enumerate
  **every `Cargo.toml` in the tree** and ask who depends on `entity-storage-substitute-http` —
  the workspace root and the crate itself, nothing else. `core/peer` has a `dep:` feature for
  every other extension and none for this one. So `system/substitute/http` is built, tested,
  and **unreachable from any peer binary** — a real gap, not an artifact, and the shape our
  own charter already names (a surface present in the tree and absent from the substrate).
  **The bounded region is whatever makes the enumeration exhaustive**: a function body when
  the question is "does this path check X" (below), the dependency graph when it is "can
  anything reach this handler." Pick the boundary that closes, then enumerate over it —
  `59e6f55`.
  Arch routed §4a as a read-and-report and explicitly made no absence claim. Answering it
  with `grep check_permission core/peer/` would have been worthless — the call could sit in
  any helper. What settled it was a **brace-balanced extraction of the whole function** and a
  count of every authorization symbol inside it (`check_permission`, `check_resource_scope`,
  `check_grant_covers`, `matches_scope`, `STATUS_FORBIDDEN`: all zero across 628 lines). That
  turned "we did not verify" into "the path runs no check of any dimension," which is a
  stronger and *different* finding than the one asked about — go at least reaches its L1
  check. The standard's "prove a negative before you claim it" has a method: **bound the
  region syntactically, then enumerate over the bounded region.**
  **And the rule binds hardest OUTSIDE your tree, where the bounded region is a sibling's
  dispatch table and you cannot see it from here.** *(Candidate: bit us once, 2026-09-03,
  caught by the cross-impl run rather than by review.)* We told arch that TYPE §7.4–§7.6's
  `converge` / `adopt` / `reconcile` *"exist in **no tree**"*, to argue a fold should not wait
  on a rust build. Arch **adopted the sentence verbatim** into `ROUTING-2026-09-03-a` §4 item
  6. It is false: core-go ships `ext/type/{converge,adopt,reconcile}.go` — 650 lines with test
  files — and dispatches all three at `ext/type/handler.go:80-84`. The claim was true about
  *our* tree and we generalized it to the cohort, which is the exact move
  `AGENTS-STANDARD`'s *"prove a negative before you claim it"* forbids, made easier by the
  fact that nothing in our own repo can contradict it. **A negative about a sibling needs the
  sibling's own closed table read** — for an operation that is one grep with a boundary that
  closes (`grep -rn 'case "<op>"' ../entity-core-go/ext/`, the `switch` in `Handle` **is** the
  inventory). Same shape as the routed-item rule below: a claim written from your seat is a
  claim about your seat. And the cost is not symmetric — a wrong absence handed *upstream*
  gets ratified into a routing and comes back as everyone's premise.
- **A fix that rewrites its own test's expectation has destroyed the evidence that it is a
  fix — the mutation still goes red, and it goes red against the new belief.** *(Candidate:
  bit us once, `aaa591e` → `cf570b2`, caught by the cross-impl gate in the same session.)*
  Cohort item R-4 said `is_revoked` scans where the spec mandates an O(1) index. Implemented
  as written; the fixture that filed a revocation the old way was updated to the new way in
  the same commit; `entity-registry` went 77 green and the mutation *did* bite. All of it
  was worthless: go's `registry.v6` writes a revocation at the own-hash path via `tree-put`
  and requires exclusion, so the index-only reader was **non-conformant**, and the armed gate
  scored 1586/**1F** where the same gate had scored 1587/0F an hour earlier. **A mutation
  proves a test is coupled to the code; it cannot prove the test asserts the right thing** —
  and a test edited in the same commit as the behaviour is not an independent witness of
  anything. **Enforcement:** when a change alters *what a test asserts* rather than whether it
  passes, the in-tree suite is downgraded from evidence to a smoke check — run the cross-impl
  instrument (`scripts/validate-complete.sh <impl>` in core-go, not a bare `validate-peer`)
  **before** reporting the item closed, and say which fixtures you rewrote. The bare run is
  not the instrument: it prints posture noise for every impl and says so itself.
  **Applied as written, 2026-08-20 (`6c889df`), and it stays a candidate** — by the outcome
  the rule predicts, not by a second bite. REGISTRY v1.19's §4.1b classifier inverted two rows
  of our own in-tree table (`alice` broad→narrow, `*.lab` narrow→broad), so the rewritten table
  could not witness itself. What settled it was **mutating on the wire**: revert the classifier,
  **rebuild the peer**, score it — `registry` 17/18·1F. Two things the run added. First, the
  mutation is evidence only if the harness rebuilds from the dirty tree; check the build line
  (`peer-manager` prints `working tree dirty at <sha>`) or you have mutated a binary nobody
  re-made. Second, and cheaper than it looks: `peer-manager start --type rust` +
  `validate-peer -category <one>` is a ~2-minute loop, so *"the cross-impl instrument is too
  slow to mutate against"* is not true for a single category and should not be offered as a
  reason. `validate-complete.sh` is the **gate**; the single-category start/stop is the
  **probe**, and it is what turns a PASS into a measurement.
- **A ledger's description of an item is not evidence about its severity — a "one-line
  hygiene fix" can be a scored cross-impl FAIL.** *(Candidate: bit us once, `6c889df`.)*
  Cohort item R-17 rode the board as *"rust's one-liner"* (a `type_ref` reading `core/entity`
  where REGISTRY §4.3's own table names the precise token). Landing it and then reverting it on
  the wire scored `type_system` **431/438 · 1F** — it had been a live scored failure against us
  the whole time, because the sibling that fixed it first makes its descriptor the one every
  seat is compared to. **A cohort item touching a *published contract* — a type descriptor, an
  advertised handler interface, a status code — is measured by a check somewhere; find the
  check before you accept the ledger's adjective.** Enforcement: `grep -rn <symbol>
  cmd/internal/validate/` in core-go for the item's surface, and if a check names it, report
  the item's state as that check's verdict rather than as the ledger's wording.
- **An unobservable branch is not shipped, even when it is "obviously" faster.** *(Same
  session, same entry's other half.)* Fixing R-4 by consulting the index *first* and falling
  back to the scan looked strictly better. Mutation: delete the fast path — **no test failed**,
  because `by-target/{hex}` sits *inside* the scanned prefix, so the keyed lookup can only find
  what the scan finds. A branch that reads as covered and cannot fail is worse than its
  absence: it is an unmeasured claim in the shape of an optimization. Ship the scan, pin the
  containment that makes the fast path pointless (`revocation_by_target_is_inside_the_scanned_prefix`),
  and let it fail loudly if the two paths ever diverge.
- **A byte-exactness claim tested with a value your own codec authored proves nothing — the
  fixture must carry a field the codec cannot emit.** *(Candidate: bit us once, caught by the
  mutation before landing, §4.3 `set-resolver-config`.)* "Stores the submitted bytes verbatim"
  and "re-encodes the decoded struct" are **the same address** for any value the codec models
  completely, because `to_entity(from_entity(x)) == x` is exactly what the round-trip test one
  file up already asserts. So a `assert_eq!(got.content_hash, submitted.content_hash)` over a
  config built by `ResolverConfigData::to_entity` is green under both implementations, and the
  mutation *"replace the verbatim store with `config.to_entity()`"* survived it. What separates
  them is a **forward-compat key** — `schema_version_2027` here, the shape §4.2 exists to permit
  — which the decoder ignores, the encoder cannot produce, and a re-encoding peer silently drops.
  Same shape as the ratified probe rule and pointed the other way: there, the probe must carry
  every field the *write* will; here, the fixture must carry a field the *codec* will not.
  **Enforcement:** any test whose name or assertion says *byte-exact* / *as written* / *verbatim*
  owes one unmodelled key, and the mutation to prove it (`set_resolver_config_stores_the_
  submitted_bytes_and_get_returns_them`, whose modelled rows pass the re-encode mutation and
  whose last row is the one that fails).
  **Broadened 2026-08-20, and the second shape is a DECISION rather than a storage path** —
  *"byte-identical" in a spec MUST is a comparison whose answer is a security verdict, and the
  same decode-then-re-encode loss becomes a fail-open instead of a hash mismatch.* §4.3's
  pin-delta is that shape: the predicate decides whether a write needs pin authority, so a
  decoded compare that drops a §4.2 forward-compat key reads a changed pin list as *"no
  change"* and rewrites the registry's most privileged row under `registry-configure` alone.
  We read the word literally and compared raw field bytes; **core-go's typed-struct decode did
  not, and that is where it bit** (go `f44ed4d`, mutation-verified). Arch adopted the reading
  into R-27 §5 rather than ruling it, because *"the operation name and the byte rule are the
  two halves of one check."* **Provenance stated exactly: this did not bite us a second time —
  we found it in a sibling.** So the rule is broadened on evidence but stays a **candidate**
  at this seat, per the ladder. **Enforcement, the new half:** when a spec MUST turns on
  *byte-identical* — or you are comparing two encodings of the "same" value to reach an
  authz / dedup / change verdict — extract the **raw field bytes**
  (`entity_wire::cbor_map_field_raw`) from both sides; never compare decoded structs.
  Grep for `from_entity(` on a value that feeds a comparison rather than a read. Teeth:
  `a_pin_field_this_codec_does_not_model_still_counts_as_a_pin_change`, which is the one row
  of that suite the decoded-compare mutation fails.
  **And the corollary the same packet taught: a green in-tree suite cannot see this class at
  all.** Our own codec never emits the unmodelled key, so only a hand-built forward-compat
  fixture — or a sibling's peer — can bite. That is the same *"cross-impl FAIL is the true
  signal"* shape as the invariant-pointer path, and it is why the fixture rule above is written
  as *the codec cannot emit it* rather than *the codec does not use it*.
  **Broadened again 2026-08-21, and the third shape is the cheapest to write and the hardest to
  see: a test whose EXPECTED value is computed by the code under test.** NETWORK §6.5.3's
  hex-strictness item routed as *"`BuildContentURL` must render `hex(h.Bytes())`, not
  `hex(h.EffectiveDigest())`"*. Our builder was already right — but the test guarding it was
  `assert_eq!(content_url(base, &h), format!("{base}/content/{}", h.to_hex()))`, which compares
  the builder against **the very function the builder calls**, so any mutation of the shared
  helper moves both sides together and the assertion cannot fail. Measured, not assumed:
  mutating `Hash::to_hex` to the digest-only form — *the precise shape core-go shipped* — leaves
  `url_construction_matches_http_live_routes` **green** and reddens only the new property test.
  A round-trip is not a claim about bytes; it is a claim that the encoder and decoder agree,
  which is exactly the thing that is true under both implementations. **Enforcement:** a test
  whose expected value invokes a helper the implementation also invokes is a tautology — assert
  the **property** instead (here: the hex begins with the format-code byte and its length is
  `2 + 2*digest_len(format)`, exercised at **two** formats so a hardcoded 66 fails the SHA-384
  row), and **run the mutation on the shared helper, not on the caller** — mutating the caller
  alone makes a tautological test look like it bites. Teeth:
  `content_url_hex_is_the_full_wire_form_at_every_format_width` (`published_root.rs`) and
  `content_url_hex_width_follows_the_format_byte_at_every_layout` (`storage-substitute-http`).
  **Provenance stated exactly: no defect escaped here — what the mutation caught was the test
  being theater**, so this stays a **candidate** rather than promoting the entry.
  **The sweep that same rule's boundary demanded, and what it found.** SPECIFICATION-FORMAT
  §8.4.5 states its own enforcement point — *"grep a draft for `33`, `66`, `49`, `98`,
  `hex33`, 'fixed-length'; every hit is either a worked instance labelled as one, or a
  defect"* — and the boundary is **every site that pins a hash width**, not just the routed
  http-poll routes. Run over our tree it surfaced two genuine ones the routing did not name,
  both invisible while one algorithm ships: `revision::is_prefix_config_path` gated on
  `rest.len() != 66 + "/config".len()` while its **own writer** emits format-relative
  `Hash::to_hex`, and `store::opfs`'s replay framed the head hash at a fixed 33 while
  `encode_entity_record` writes variable-length `Hash::to_bytes`. **Both are a write-shape /
  read-shape asymmetry inside a single file** — the inverse of the by-target index bite below,
  and closer to home, because there is no sibling to blame and no cross-impl check that would
  ever see it. When a routed item is about a hash's *encoding*, run §8.4.5's grep before
  reporting it closed.
- **A census of a code SLOT must key on the status VALUE, not on a spelling of the status —
  a local `const` alias hides the sites from the grep that looks for the canonical one. And a
  census cannot ask the one question that decides a slot sweep: whether a site names a DIFFERENT
  FAILURE that merely shares the status.** *(Candidate: bit us once, 2026-09-03; the second half
  added 2026-09-04, `daef7c4`, and it is the cost of the first half's own remedy.)* 0.8.2.7 makes
  the unit of conformance the **code slot** — the set of `code` values emitted at a given
  status — precisely because `grep -c <token>` says nothing about what else occupies the
  token's position. Censusing our own 500 slot against that ruling, arch put our debt at
  **3** bare `internal`; the tree had **19**. The 16 they could not see live in
  `extensions/capability` and `extensions/handler-ops`, which each declare their own
  `const STATUS_INTERNAL: u32 = 500;` and emit through `error_entity("internal", …)`, so a
  census reading `STATUS_INTERNAL_ERROR` misses every one. A seventeenth, `handler_error`,
  was mis-filed into our **501** row and is the dispatcher's whole generic-500 surface.
  **The slot is a property of the wire, and every layer of indirection between the emit site
  and the number is a place a census stops.** Enforcement, in order: `grep -rn 'const STATUS_'
  --include=*.rs` to enumerate the aliases FIRST, then census on the resolved integer, and
  treat any helper that fixes a status internally (`bad_request(code, msg)`,
  `error_result(STATUS, code, msg)`) as its own emit shape to enumerate. A census whose method
  you cannot state is a grep, and a grep is what produced the claim this ruling struck.
  **And one layer BELOW the slot, which is where the recursion ends: a code is
  `(status, FIELD, spelling)`, and a census keyed on the first and third is blind to the
  second.** *(Candidate: bit us once, 2026-09-03, found by a sibling's harness and not by any
  gate of ours.)* `extensions/type-system/{validate,constraint}.rs` each declared a local
  `fn error_entity(error_type: &str, …)` shadowing `entity_handler::error_entity` and wrote the
  code under key **`type`**, not `code` — so all 14 of their emit sites decoded to
  `code = absent` at a conformant reader. The 501 sweep of `4d888f8` had just landed
  `unsupported_operation` at two of those sites and **could not be observed on the wire**: the
  spelling was right, the slot was right, the field was wrong, and every census we ran counted
  it as closed. `system/protocol/error` declares `code` **REQUIRED**
  (`core/types::system_protocol_error`), so the local shape also violated our own published
  descriptor — and `validate.rs` imported the canonical *decoder* while using its own encoder,
  so the crate's internal constraint dispatch silently dropped the code from its own
  `DispatchFailed` reason. The canonical helper's doc comment states the intent verbatim
  (*"keeps the wire shape in one place so extensions can't drift on field names"*); a local
  copy is exactly how that intent is defeated, and `impl`-local `fn`s are invisible to a
  call-site grep.
  **Why nothing here could catch it, and it is the transferable half.** Our own test for that
  body — `a_malformed_validate_request_is_invalid_request_never_bad_request` — scans
  `res.result.data` for the **substring** `invalid_request`, which is present under `type` and
  under `code` alike. It passes under both shapes and stayed green through the whole defect:
  a byte scan measures the spelling, which is the layer the census was already blind at.
  Same class as the same-side round-trip pitfall — the assertion and the defect share a
  vocabulary.
  **Enforcement:** the mint sites of a wire error are a closed region — enumerate them
  (`grep -rn 'Entity::new(TYPE_ERROR\|Entity::new("system/protocol/error"' --include=*.rs`;
  25 here) and extract the **field key** written at each, not the code value. Any local
  `fn error_entity` outside `core/handler` is the finding, whatever its body says. An assertion
  about a code MUST read the decoded **key** (`Value::Map` lookup), never a substring of the
  body and never a round-trip through our own reader. Teeth:
  `every_type_handler_error_carries_its_code_in_the_code_field`
  (`extensions/type-system/tests/validate_integration.rs`), one row per handler because both
  files shadowed the helper independently — verified RED per file, and verified **on the wire**
  (`validate-peer -category type`: `27P/3W/0F` fixed vs `27P/0W/3F` against the restored local
  helper, peer rebuilt `dirty=true` at HEAD). Note the category: the op rows live in `type`,
  while `type_system` is the descriptor category and scores `438P/8W/0F` under **both** shapes.
  **The third layer is not a layer of the KEY at all, and it is where a slot sweep does damage:
  a code is `(status, field, spelling)` — but whether a site BELONGS to the slot is a question
  about the FAILURE, and no census asks it.** *(2026-09-04, `daef7c4`.)* Our 0.8.2.7 sweep read
  §9.1's 501 blacklist as owning the whole status and rewrote every 501 in the tree to
  `unsupported_operation`, including `registry`'s stored-`domain-control` refusal. 0.8.2.8 then
  ruled the opposite and named that exact row as the worked case: *"A domain code defined for a
  different failure that also answers 501 is not a synonym and is not blacklisted"* — the handler
  is registered and `register` **is** implemented, so it was never the unimplemented-operation row.
  **The sweep was mechanically correct and semantically wrong**, because a census enumerates
  *sites at a status* and the slot is defined by *the failure named*. Nothing about the grep could
  have caught it. **Enforcement: a slot sweep is not a rename — for each site, state in one line
  what failed, and if that sentence is not the slot's own row, the site is out of scope and owes a
  domain table row instead** (OP-3's whole subject). The tell is a site whose message names a
  *thing* rather than an *operation*: "mode X cannot be enforced" is a domain failure wearing a
  shared status; "op X is not implemented" is the row. And when a ruling later un-retires a token,
  the seats that swept it are the seats that must move — we and go both did, and py, which never
  swept, was right the whole time.
  **And the layer ABOVE all of them, which is where a SIBLING's census of your tree goes wrong: a
  code-shaped token in a MESSAGE is not an emit site, and a returned `Err(HandlerError)` has no
  code of its own — the dispatcher's slot map is the emit site.** *(Candidate: bit us once,
  2026-09-05, and it was a sibling's report that carried the error.)* core-go routed EXTENSION-TREE
  v4.4 to us as *"`invalid_entity` ×2 at `core/tree/src/lib.rs:708,713`"*, read out of our source.
  Neither line emitted it. Both were
  `.map_err(|e| HandlerError::InvalidParams(format!("invalid_entity: {e}")))` — the token sat in
  the **message**, and `connection::handler_error_slot` supplied the code, so the wire carried
  `400 invalid_params` at both sites. Driven before and after (`peer-manager start --type rust`,
  image label `dirty=true` at HEAD, code read from the decoded `code` **key**): row 1
  `invalid_params` → `invalid_request`, row 2 `invalid_params` → `hash_mismatch`, control `200`
  unchanged. **The misreading is symmetric and that is what makes it worth an entry.** It
  *over*-stated — we never shipped the undefined spelling the report is titled after, and go's
  own worklist hedged (*"may surface as `invalid_params`; drive a put and read
  `result.data.code`"*), which is the sentence that turned out to be the finding. And it
  *under*-stated — the real defect was a **defined but wrong** specific standing where v4.4 pins
  `hash_mismatch`, which is invisible to any census that greps for undefined tokens, because
  `invalid_params` is one of §3.3's five legal 400 specifics. A wrong-but-legal code is the
  expensive half: it reads as conformant at every seat and it silently costs the caller the one
  branch the row exists to give them.
  **Enforcement, and it is the cheap half of an already-cheap loop.** (a) When a report names a
  code at a `file:line` in **your** tree, check whether that line *is* the emit site before
  scoping: in this tree the emit sites are `error_result(...)` / `bad_request(...)` / an
  `Entity::new(TYPE_ERROR, …)`, and an `Err(HandlerError::X)` is a *slot reference* whose real
  spelling lives in `handler_error_slot` — one function, closed `match`, and it is the inventory.
  (b) Then run the probe, because the token census cannot see the wrong-but-legal case: a
  `peer-manager start` + a hand-driven EXECUTE reading the decoded `code` key is ~3 minutes, and it
  is the only thing that distinguishes *"we emit the undefined token"* from *"we emit a defined
  token that is not this row's."* (c) The same rule pointed outward is the reason to reply with the
  before/after pair rather than *"landed"* — a seat that closes the item as written leaves the
  ledger asserting a defect we never had and silent about the one we did.
  **Corollary, and it is the sweep half: the sibling could only see the sites where the token was
  NOT a code, and missed the one where it was.** `extensions/content/src/handler.rs:422` passed
  `invalid_entity` to `bad_request` — a genuine wire emission of a spelling with zero occurrences
  in either spec corpus, in a handler whose extension defines no error table at all (its one named
  400 is `path_required`), which is precisely 0.8.2.9's *"the absence of a table is not an unfilled
  slot"* case. Straight re-application of *"a MUST NOT on a token means `grep -rn '\"<code>\"'`,
  and the region is the whole tree"* — with the twist that the routing's `file:line` pointed away
  from the only real instance. Teeth:
  `ingest_rejects_an_undecodable_entity_with_the_defined_400_default`, mutation-verified RED.
- **A comment explaining why a surface is UNTESTED is a standing instruction not to try, and it
  never expires on its own — re-price it before you believe it.** *(**Ratified 2026-09-11**: bit
  us twice, and the second time the comment was in a CONFORMANCE CHECK rather than in our own
  test tree — see the end of this entry.)* `handle_pull`'s three
  test rows sat under *"End-to-end behavior requires a wire-connected remote peer and is exercised
  by the cross-impl probe."* True when written. The consequence is that every row drove a
  **precondition** failure — missing `remote`, absent `execute_fn` — and the entire path *past* the
  outbound dispatch had zero coverage, which is where REVISION §4.4.8's `remote_empty` answered
  `500` for as long as it has existed, behind `revision 103P/0F` on the wire. What it actually took
  to reach the branch was a stub `execute_fn` returning the envelope an empty remote sends: about
  fifteen lines. **The comment was not wrong, it was load-bearing** — it answered the question
  *"why is this untested?"* convincingly enough that nobody re-asked it, which is the same failure
  mode as a code comment citing a superseded proposal, one directory over and pointed at the test
  suite instead of the implementation.
  Note the second half, because it is what makes this cheap to enforce: **the deferral named a
  substitute — *"exercised by the cross-impl probe"* — and no probe existed.** A category can be
  green at 103 rows and touch none of the branch, and the comment is what stops you checking.
  **Enforcement:** grep the test tree for deferral prose (`requires a wire`, `covered by`,
  `exercised by`, `end-to-end`, `integration only`) and for each hit answer two questions in the
  diff you are already writing — *does the named substitute exist and does it drive this branch?*
  and *what would a stub cost today?* If the substitute cannot be named as a **row**, the surface
  is untested and the comment should say that instead. Same rule as *"a declared exclusion whose
  ground is 'nothing installs it' is a gap wearing an exemption"*, applied to a deferral rather
  than an exclusion.
  **Second bite, and it ratifies the entry by moving it out of our own tree: the deferral was in
  a CONFORMANCE CHECK, so the surface it left untested is the whole cohort's — and the check
  carries the vector's `[MUST]` while measuring something else.** `CORE-TREE-LISTING-1` is §6.3's
  cap-coverage listing filter (*"entries for which `check_path_permission` returns DENY MUST be
  omitted… `count` MUST reflect the filtered count"*), in the `--profile core` set. core-go's
  `core_tree_listing_1` seeds two paths **with the connection's broad cap**, lists, and asserts
  **both appear** — a positive-presence assertion, so **a peer that filters nothing passes by
  construction**. Its comment declares the narrower scope honestly and names the substitute:
  *"a full cap-coverage filter test requires a narrowed delegated cap, which the broader security
  category exercises."* Grepped the harness: **no check anywhere asserts a listing entry is
  omitted.** The substitute does not exist, and the sibling whose tree it scores has no per-entry
  filter at all (`handleListing`'s signature takes no capability).
  **The half that is about us: the row was green against US too, and our filter is real.** A PASS
  there was never evidence of `handle_listing_filtered`; it was a return-shape check wearing a
  security vector's name, and we had cited it. **So the deferral rule binds a category name as
  well as a comment: before citing a vector ID as covering what its §9 row says it covers, read
  the check's ASSERTIONS** — `grep -n 'r.Run("<check_name>"' -A 40` in the sibling harness — and
  ask whether any arm could fail against a peer that does nothing. A vector whose every assertion
  is positive-presence cannot witness an omission MUST. This is the *"a green category is not
  evidence about a surface the category does not check"* entry one level finer: there the check
  was absent, here it is present, correctly named, and measuring a different property.
- **A precondition guard on a TEST FIXTURE can make the behaviour under test unreachable — and
  it reads as strictness, not as a hole.** *(Candidate: bit us once, 2026-09-09, found by a
  sibling's check scoring us FAIL for a reason unrelated to what it measures.)* 0.8.2.17's §9.1
  negative arm is driven by core-go's `origination.dispatch_outbound_ambient_refused`, which sends
  `system/validate/dispatch-outbound` **with the §7a.2a authority triple deliberately absent** so
  the sub-dispatch rides ambient authority. Our conformance handler *required* the triple and
  answered `400 invalid_params`, so the probe never reached the outbound branch: we scored FAIL on
  an arm that was correctly implemented and never entered. The 400 looked careful. It was
  unmeasurability — **a handler that refuses early makes its peer look strict and makes the thing
  under test unobservable**, and `400` and `403` are one word to a reader and two different facts
  to a check.
  Same family as the deferral-comment entry above, one layer out: there a *comment* stopped anyone
  driving a branch, here a *guard* did, and a guard leaves no prose for a reviewer to disbelieve.
  **Enforcement:** when a ruling adds an arm selected by the ABSENCE of a field, grep the fixture
  handlers on that path for a required-field check over the same field
  (`extensions/conformance/`, and any `--validate`-only scaffolding) — an absent-field 400 there is
  the arm's off-switch. And the fix owes a discriminator, because relaxing a guard and deleting it
  are one edit apart: **all-or-none**, with *partial* still refused
  (`a_partial_reentry_triple_is_still_a_malformed_request`, mutation-verified — collapsing the
  partial arm into the absent arm reddens the control and leaves the relaxed row green). Note the
  ladder position: this commit rewrote a test's own expectation, so per the rule above the in-tree
  green is a smoke check and the evidence is that control plus the cross-impl row.

- **When a ruling moves a check to a NEW PARTY, audit what that party is guaranteed to hold — the
  material may have been assembled best-effort for someone else.** *(Candidate: bit us once,
  2026-09-09; the defect had been shipping invisibly since the code existed.)* 0.8.2.17's
  presented-authority arm requires the **dispatcher** to chain-verify a capability the target
  minted. Every input already existed, so it reads as a composition. It is not: §5.5 verification
  needs a detached signature per link, and `EXTENSION-CONTINUATION` §4.3 makes bundled signatures
  explicitly **best-effort** — *"B fails closed if it needed it"* — because the design had always
  assumed the **recipient** verifies. Move the check to the dispatcher and it inherits a bundle
  nobody promised would be complete.
  Underneath that was a real defect: §6.5 envelope-signature ingestion ran on **inbound EXECUTEs
  only, never on the connect response**, so this peer held a connection grant whose granter's
  signature sat live on the connection (`auth_included`) and bound at **no path** — unreachable to
  `collect_chain_bundle`, which resolves signatures only through the §3.5 invariant pointer. Every
  chain rooted at that grant was unverifiable *locally*, and nothing could see it because the far
  side verifies against its own store where its own signature **is** bound. It surfaced as
  `MissingSignature` on `follow(Continuation)`'s standing leg — a legitimate credential refused
  for want of a proof we were holding.
  **Enforcement:** for any rule that relocates a verification, name the artifact it consumes and
  find the site that PRODUCES that artifact locally; if the producer's own contract says
  *best-effort*, *silently omitted*, or *the verifier fails closed*, the relocation has a material
  gap and the fix is to close the gap, not to soften the check. In this tree the pair is
  `ingest_envelope_signatures` (producer) and `collect_chain_bundle` (consumer), and the question
  that closes it is *"which envelopes does ingestion run on?"* — the answer was one, and the code
  said so nowhere.
  **Ratified 2026-09-10, and the second bite was the SAME producer at a THIRD surface.** 0.8.2.19
  E4 generalizes §6.5 ingestion to *any received envelope carrying an `included` map*, and the one
  we still did not run it on was the **`EXECUTE_RESPONSE`** — which §6.2 names as the *deliberate*
  runtime carrier of a target-minted credential (*"the capability handler is the runtime entry
  point for in-band capability management, while §4.4 covers initial-grant delivery"*). So a peer
  that goes and **acquires** a credential in order to make a presented-authority sub-dispatch
  acquired it with its signature bound at no path: the identical `MissingSignature`, one surface
  later, and mutation-measured as `left: None` — the binding did not exist at all
  (`a_capability_minted_in_an_execute_response_lands_with_its_signature_bound`). **Two surfaces
  were each enumerated one at a time, each after a failure; the rule is the fix, not a third
  enumeration** — the enforcement question is now *"does this code path receive an envelope?"*,
  and every `yes` owes an `ingest_envelope_signatures` call. Grep `parse_execute_response(` and
  `\.included` on any receive path.

- **A ruling that says "X is IN scope" is answered by an INVENTORY, not by the one site the
  routing named — and a seam that re-roots its own dispatch to peer authority is how the scope
  rule gets emptied.** *(Candidate: bit us once, 2026-09-10; both instances found by our own
  sweep, neither named by the sibling's routing.)* 0.8.2.19's E2 decides §1.4 scope by **authority
  provenance** — *does this dispatch spend a handler's grant, or the peer's own root authority?* —
  and adds *"a peer MUST NOT exempt the class on the ground that no caller was on the stack."*
  The sibling's routing flagged one class (subscription delivery). Enumerating **every**
  `DispatchCeiling::PeerRoot` construction in the tree instead found **two** that fail the test:
  the delivery engine (`core/peer/src/lib.rs`) and `PeerLink::self_execute`
  (`core/peer/src/network_link.rs`), whose §9.2 close notification is a real outbound dispatch to
  a **caller-supplied** peer id, originated inside the `system/network` handler.
  **The transferable half is the argument, not the count.** `self_execute`'s doc comment said
  *"dispatch as the local peer identity — the same path `Peer::execute_with_options` takes"*, and
  that reads as a fact about the mechanism rather than as a claim about authority. It is a claim
  about authority: **if a handler may declare its own dispatch `PeerRoot`, the provenance rule is
  evadable by every handler and means nothing.** Prose describing a seam is not a scope argument,
  which is the same failure as a comment asserting a concurrency invariant without naming the
  construct that enforces it.
  **Enforcement:** when a ruling defines a scope, the region that closes is the **constructor of
  the thing being classified** — here `grep -rn 'DispatchCeiling::PeerRoot' --include=*.rs`, a
  closed list — and each site owes one line saying which side of the test it falls on and why.
  Sites legitimately out of scope (the SDK entry points, `Peer::execute_with_options`) say so;
  sites in scope and not yet flipped say **what blocks the flip**, because *"we know"* with no
  stated blocker is indistinguishable from an exemption. Both are pinned at the code citing
  `ROUTING-2026-09-10-a`. And note which way the cost runs: the subscription instance cannot be
  flipped from one seat — our `deliver_token` is A-rooted (conformant, §1.2) but minted as a
  **self-grant**, so its leaf `grantee` is not this engine and it relaxes nothing; flipping the
  ceiling alone refuses every cross-peer delivery. **A restrictive fix whose correctness depends
  on a credential shape three seats must mint identically is a coordination item, not a fix.**

- **Two ALTERNATIVE authorities is a bypass wearing a design; the shape that is not is one gate
  with a named exemption — and the two vectors everyone writes are the two that cannot tell them
  apart.** *(Candidate: bit us once, 2026-09-10, **F67**; found by `entity-core-keystone`, not by
  us, not by go, not by py, not by arch. We wrote design prose defending it.)* 0.8.2.17 said a
  target-minted credential's *"own four dimensions authorize the sub-dispatch"* while exempting
  the handler's `peers` scope **by name**. Three independent ground-up implementations read the
  first clause as sufficient and returned *authorized* before the executing handler's grant was
  ever consulted. Because that credential arrives as a **caller-supplied parameter**, a caller
  holding a copy of any `T → P` capability could steer **any** handler on P past its own grant —
  the confused deputy, with the ceiling removed by name. 0.8.2.19 corrects it to **one gate and
  one exemption**: the handler's grant decides all four dimensions, a valid target-minted
  credential relaxes **Dimension 4 only**. *The target answers where; the handler's grant answers
  what.*
  **Three things to carry, and none of them is "read §1.4 harder."**
  1. **The reading was available and cheap.** §6.8 states the gate *positively and
     unconditionally* — *"the authorization decision for an internal sub-request is made on the
     executing handler's grant, never on the propagated caller capability"* — and that sentence
     has **two halves**. Everyone answered the second (a target-minted credential is not the
     propagated caller capability — true, and it survives) and nobody answered the first.
     `EXTENSION-CONTINUATION` §3.6b had already resolved the identical shape as *Level 1 = the
     dispatch gate, Level 2 = the caller capability*; we made a credential Level 1 for the first
     time in the corpus, on the surface where it costs most. **When a fold hands you a new
     authority, open the section that already states the gate and reconcile the two — an
     over-broad clause is a spec-issue to ROUTE, not a licence to implement from.**
  2. **The test set could not see it, and the reason generalizes past this bug.** Our two PD-2
     rows were *credential + covering grant → allow* and *no credential → refuse*. Under a bypass
     and under a compose those give the **same** answers, because in both rows the two authority
     sources **agree**. The discriminating vector is the one where they **disagree**: a valid
     credential presented to a handler whose grant does NOT cover the request → MUST refuse.
     **Whenever an outcome can be reached by more than one source of authority, the check set
     needs a row where the sources disagree — otherwise it measures their union, and a bypass and
     a composition have the same union.**
  3. **The structure is the fix; the condition is not.** Do not patch it as an `&&`. The
     credential check is now a **predicate that produces a bit**
     (`presented_credential_relaxes_peers`), never an authorizer, feeding one call to
     `check_permission_relax_peers`; the relaxation is a flag threaded into the *same* loop body
     so §5.2's all-dimensions-from-one-grant-entry rule cannot drift, and there is **no code path
     by which a credential authorizes alone**. Reinstating F67 requires adding a new early return.
     **`-> bool` meaning "authorized" and `-> bool` meaning "one dimension is relaxed" are the
     same type and opposite facts** — the function name and the doc comment are the only thing
     stopping the next reader from re-fusing them, so both say so.
  **Enforcement:** the pair is mandatory and **both mutations must be RUN, not predicted**, and
  their reddened rows must be **disjoint** — restore-the-bypass reddens the discriminator and
  leaves the relaxation control green; neuter-the-relaxation reddens the control and leaves the
  discriminator green (measured: `5P/2F` each way, `core/peer/tests/conformance_reentry_7a2a.rs`).
  A negative security test can PASS for the wrong reason — refused upstream of the gate — so
  "refused" is worth nothing until the restore mutation shows the probe *reaches* the gate. And
  note what a green cross-impl run was worth here: three seats passed both arms and the report
  read *"PD-2 both arms converged."* **Convergence on a shared reading of one spec sentence is
  cohort-consistency, not independent verification** (ADR-0012, verbatim) — and here it actively
  masked a security hole for as long as it stood.

- **When a carrier goes from singular to PLURAL, the empty array is a new state the old code
  could not express — and if the field selects an authorization ARM, reading presence off the
  MAP KEY instead of the array's length silently deletes the arm.** *(Candidate: bit us once,
  2026-09-10, caught by writing the row before the code.)* `GUIDE-CONFORMANCE` §7a.1's reentry
  carriers went plural at `0.8.2.19` (`reentry_granters` / `reentry_cap_signatures`) so a K-of-2
  multi-sig root could be expressed on the wire at all. The all-or-none rule then selects §1.4's
  **presented** arm from *credential + ≥1 granter + ≥1 signature*, the **ambient** arm from all
  three absent, and `400 invalid_params` from anything between. `reentry_granters: []` is the row
  that separates the two readings: key present, array empty. Our own already-ratified rule says
  absent and empty are the same fact for an optional array — so it is the **ambient** arm, and a
  peer whose presence test is `cbor_map_field_raw(...).is_some()` calls it partial and 400s it.
  That is the *exact* unmeasurability `0.8.2.17` fixed (an early refusal makes a peer look strict
  and the arm under test unreachable), reintroduced by a params change made for an unrelated
  reason. **The pluralization is where an optional-array rule stops being an encoding nicety and
  becomes an authorization branch.**
  **Enforcement:** when a scalar field becomes an array, enumerate the three states the change
  creates — absent key, present-and-empty, present-and-non-empty — and write the row for the
  middle one first; if the answer to *"is this the same as absent?"* is yes, the presence test
  must read the decoded **length**, never the key. Grep `cbor_map_field_raw` on any path whose
  result feeds a `match`/`if` that picks a code path rather than a value. Teeth:
  `all_keys_present_but_both_arrays_empty_is_the_ambient_arm` (`extensions/conformance`),
  mutation-verified as the **only** row the key-presence reading reddens — the five partial rows
  beside it stay green under it, because under that reading they are still partial.

- **A STRUCTURAL fix landed for an earlier ruling can make a later ruling's branch UNREACHABLE —
  when a new rule turns a field into a decision, enumerate every seam that TRANSFORMS that field
  before implementing it at the site the worklist names.** *(Candidate: bit us once, 2026-09-14,
  found by the wire vector after the in-tree rows were green.)* `0.8.2.24`'s `N6` splits the two
  empties of `resource`: a **genuinely absent** one takes the operation's absent-case behaviour, a
  **present** one whose effective list is empty is `400 path_required`. Landed exactly where the
  routing names it — `core/tree`'s three resource-optional ops, plus the one derivation they share
  — with 108 in-tree rows green and three mutations reddening disjoint sets. **Over a real socket
  it answered `200` anyway.** `0.8.2.20`'s structural boundary narrowing (`rt.targets =
  effective_targets(...)` in `dispatch_request`, the fix that made the subject rule *structural
  rather than an obligation re-discharged at ~20 handlers*) had already rewritten the request to
  `targets: []` — which is the absent case — so the new `SelfExcluded` arm was **dead code at the
  only door that matters**. Two rulings, one field, and the earlier one's fix silently deletes the
  later one's input.
  **Three transferable parts.**
  (a) **The tell is a PROJECTION that is lossy about its own emptiness.** Narrowing `[P]` with
  `exclude:[P]` to `[]` is not a smaller answer, it is a *different fact*. The remedy is not to
  revert the narrowing — it is a defence, and `the_dispatch_boundary_hands_the_handler_only_the_
  effective_targets` exists because a cross-impl oracle cannot attribute which of the two layers
  earned its green. It is to exempt the case that would erase the distinction: **narrow when
  narrowing leaves something, keep the pair when it would not.** The effective set is identical
  either way (`effective_targets` is idempotent and every consumer calls it), so nothing downstream
  computes a different subject.
  (b) **There were TWO seams, and the first read stopped one statement short.** The inbound wire
  path and the in-process sub-dispatch path both narrow. Reading `extract_resource_target` — which
  does hand back the raw pair — and concluding the wire seam was safe was wrong by two lines:
  `dispatch_request` narrows immediately after qualifying. A comment asserting that asymmetry was
  written, and the wire run deleted it. **Grep the field, not the function you happened to open**
  (`grep -rn 'effective_targets(' --include=*.rs` — the transform sites are the inventory), and
  keep the seams in step: a seam that narrows and one that does not is how the same request gets
  two answers depending on which door it came in.
  (c) **This is the third instance of *an in-process row is a floor under a vector, not one*, and
  the first where the floor was green while the peer was non-conformant.** The earlier two were
  about what a row *proves*; this one is about what it *cannot see* — every layer between the
  socket and the branch gets a vote, and a `HandlerContext` built by hand skips all of them.
  **Enforcement: any ruling that turns a request field into a branch owes a row that crosses a
  socket, written BEFORE the item is reported closed** — `core/peer/tests/two_empties_vector.rs`
  is the shape, and the mutation to run is *narrow unconditionally at the boundary*, which reddens
  the wire row and **nothing** in the handler's own suite.
  **Cohort note, and it is why this was routed rather than just fixed:** the boundary narrowing is
  `0.8.2.20`'s recommended structural shape, so **any seat that adopted it has this defect and a
  handler-only `N6` does not close it** — while a seat that only ever narrowed inside the handler
  is unaffected and will read the item as done. The two populations cannot tell each other apart
  from a green category.

- **An authorization check evaluates the target it was GIVEN; a handler acts on the set that target
  DERIVES — and where those differ, the dimension does not bind however correct the check is.**
  *(Candidate: bit us once, 2026-09-10, found by recomputing arch's `CP-12a` against our tree rather
  than by the routing.)* `CP-12a` names one instance — a target the caller also excludes is *skipped*
  by `check_resource_scope` and then acted on anyway — and its fix (count the **effective** set) is
  about arity. The class is wider and the fix does not reach it: **a prefix, a wildcard, a snapshot
  root, a merge source is one string to the authorizer and a subtree to the handler.** Driven at our
  line: a grant `{include:[app/*], exclude:[app/secret]}` **authorizes** `system/tree:get` on
  `/{p}/app/` — the exclude does not match the prefix *string* — and `handle_listing` then returns
  `secret` and its hash, while the child's own path is correctly refused. The direct read is denied,
  the enumeration is not, so nothing looks wrong from either side. §5.2's own pseudocode comment
  states the property (*"Otherwise the effective target includes paths the grant forbids"*) and its
  pattern arm makes the caller's `exclude` **load-bearing for the authorization decision** — a promise
  no consumer in any tree applies.
  **The second half is ours and is the same *sibling arms* miss one layer down.** `handle_snapshot`
  carries a documented confused-deputy check for its `params.prefix` fallback; `handle_merge`
  (287 lines) and `handle_extract` (173 lines) carry **zero authorization symbols** — brace-bounded
  extraction, counting `check_permission` / `check_resource_scope` / `check_path_permission` /
  `caller_capability` / `STATUS_FORBIDDEN` / `capability_denied` / `access_denied` / `matches_scope`.
  `merge` reads no resource target at all and writes wherever `params.target_prefix` says, which is
  `EXTENSION-TREE` §11's *"MUST verify authorization before applying any writes"* and §12.1's atomic-403
  MUST, unimplemented. **core-go implements all three** (`core/tree/operations.go` — snapshot,
  per-path inside the merge loop, extract); we implement one, and one arm getting the fix is how the
  other two stayed invisible.
  **Enforcement, and the tell is a primitive rather than a rule:** when a change touches an
  authorization input that is a path, grep the handlers for the **expansion** primitives —
  `location_index.list(`, any prefix walk, any pattern match against stored paths — and for each,
  state whether the authorizer evaluated the *string* or the *set*. Where it evaluated the string, the
  handler owes either a per-entry filter against the grant (`extensions/query`'s post-filter is the
  in-tree model, and it is the one enumerating consumer that gets it right) or a refusal. A negative
  control is mandatory and it is the non-obvious half: the **child's own path must still be refused**,
  because that row passing is exactly what makes the leak read as a working guard.
  **Ratified 2026-09-13, and the third enumerating consumer is the one where the disclosure is
  DEFERRED: a path-check EXEMPTION is a claim about the exempt operation's upstream PRODUCER.**
  `listing` and `extract` disclose in their own response, so the entry above found them by asking
  what leaves the function. `snapshot` leaves a **33-byte root** and discloses nothing — the caller
  spends it one operation later at `diff`, which `EXTENSION-TREE` §11 exempts from path checks
  *entirely*. Compose them and `diff(empty, scoped_snapshot).added` returns the excluded key **and
  its content hash**, with no authorization run anywhere in the composition: `snapshot` authorized
  the prefix string, and `diff` is exempt by construction. Nothing about §11 or `handle_diff` is
  wrong; the exemption's unstated premise — *a root cannot commit to what the caller may not see* —
  is a proof obligation on `handle_snapshot`, and the entire fix is there.
  **Enforcement:** for every operation a spec exempts from a check, write down what the exemption
  assumes about its inputs and name the function that has to make it true — then test THAT function.
  The grep is the exemption, not the check: `grep -n 'exempt\|no path check\|not authorized here'`
  over the extension specs, and each hit names a producer. And the assertion cannot stop at the
  response: a snapshot body contains neither the key nor the hash under either implementation, so
  the row has to **walk the root** (`collect_all_bindings`) — which is also why no in-tree suite and
  no single-operation vector could have caught it, and why it took a cross-impl check composing two
  operations (`exclude_matrix.snapshot_diff_no_leak`).
  **The second half is about the FAST PATH, and it is the one that would have shipped a green
  suite over a live leak.** The tracked trie root (§3.4) is a *peer-level* artifact built over every
  binding with no caller in scope, so a filter placed only on the rebuild branch is skipped whenever
  a root happens to be tracked — the same request under the same cap leaking or not depending on
  whether a `system/tree/root/{prefix}` binding exists. **A fast path that returns a precomputed
  answer must be bypassed on exactly the condition that makes the filter decide something**, and the
  way to stop those two conditions drifting is to not spell them twice: `cap_filter_active(ctx)` is
  one predicate, used by the bypass and documented as tracking `authorize_path`'s early returns.
  **And the fixture lesson, which is a new shape of *a control the code path can MASK*: a control
  armed with the CANONICAL value cannot observe which branch produced it.** The first draft armed
  the tracker with `build_trie` over exactly the indexed bindings and asserted the cap-free answer
  `== tracked_root` — a **tautology**, because that is precisely what the rebuild branch also
  produces. Measured rather than reasoned: deleting the fast path outright left it GREEN and
  reddened only the pre-existing `test_handler_snapshot_uses_tracked_root_when_present`, which uses
  a fabricated root for this exact reason. The fix is a **sentinel** the other branch cannot mint (a
  key present in the tracked root with no binding in the index). **When a test asserts that an
  optimization ran, the expected value must be one only the optimization can produce** — otherwise
  it measures the answer, and both branches agree on the answer, which is the whole point of an
  optimization. Teeth: `a_snapshot_root_omits_a_binding_the_callers_grant_excludes` and
  `snapshot_under_a_scoped_cap_does_not_take_the_tracked_root_fast_path`, whose three mutations were
  RUN and redden **disjoint** rows (filter removed → both; fast path un-bypassed → only the
  fast-path row, the plain filter row **stays green**, which is what earns that row its existence;
  fast path deleted → the fast-path row and the §3.4 row).
  **⚠ And the boundary this closed does NOT reach, stated because an unstated gap is an exemption:**
  `check_path_permission` has exactly **two** production consumers in this tree (`core/tree`,
  `extensions/query` — `grep -rn 'check_path_permission(' --include=*.rs`), while
  `grep -rn 'location_index.list(' --include=*.rs extensions/` returns ~15 enumerating handlers that
  run **zero** per-entry filter (registry name listing, role assignment/derived sweeps, subscription,
  revision branch/tag listing, relay, identity, local-files). §6.3's sentence says *"the **tree
  handler** returns a listing"*, so whether it binds a **domain** listing is a spec question and not
  ours to decide — routed. Do not read the three-green tree filters as covering the class.

- **An identifier in a relayed packet is a citation — resolve it in the ISSUING repo's register before
  you propagate it, and never mint one for a finding that arrived unnamed.** *(Candidate: bit us
  once — as readers — 2026-09-10.)* Arch's ruling used *"`F68`'s exact shape"* as an **analogy** for a
  fix landing in one home that the next revision moves; `F68` itself is keystone's floor finding,
  closed at `entity-core-protocol` `dd5f785`, and the bypass the packet actually found is registered
  as `CP-12a` / `COHORT-OPEN-ITEMS` §0af.2. The relay read the analogy as the bypass's **name** and
  carried it into two routings and a charter entry, so one identifier now denotes two findings in
  three trees — and both usages are locally coherent, which is why nobody catches it inside one repo.
  Same family as *one representation carrying two meanings*, applied to a ledger key, where the cost
  is that every later citation is ambiguous and the ratchet entries cannot be joined.
  **Enforcement:** before repeating an `F`/`CP`/`R` number from a packet, grep the issuing repo
  (`grep -rn '<id>' ../entity-system-architecture/docs/{DESIGN-REGISTER,COHORT-OPEN-ITEMS}.md`) and
  check the finding under it is the one in front of you. A finding that arrives with a section
  reference and no number **has** no number — cite the section.

- **A CROSS-IMPL oracle scores the UNION of your layers — when a rule can be satisfied at two
  sites, a green row says nothing about which one earned it, and the redundant one is an
  unmeasured claim.** *(Candidate: bit us once, 2026-09-11, caught by running the mutation the
  report would otherwise have asserted.)* `0.8.2.20`'s subject rule can be discharged at the
  dispatch **boundary** (narrow `resource.targets` to `effective_targets` once, so no handler can
  see a skipped target) or at **each handler** (`require_single_resource_path`), and the spec says
  so outright: *"this document does not mandate two sites."* We shipped both. core-go's
  `resource_effective` oracle then scored `6P/0F` — and **restoring the exact bypass arch flags in
  ⛔ capitals, `targets.first()` inside `handle_get`, still scored `6P/0F`**, because by then
  `rt.targets` *is* the effective list. Only disabling BOTH reddened `case_d_witness` (`5P/1F`);
  restoring the handler half alone with the boundary off scored `6P/0F` again. Three runs, and the
  one-line report *"the oracle confirms the selection"* would have been false about which code it
  confirmed.
  **Enforcement.** When a rule is satisfiable at two sites, run the mutation **per site**, not per
  behaviour — and if a site's mutation cannot be reddened by any cross-impl row, it owes an in-tree
  test that observes it *directly*. For the boundary that meant a probe handler which reads
  `targets[0]` **on purpose** (`the_dispatch_boundary_hands_the_handler_only_the_effective_targets`,
  `core/peer`): every conformant consumer draws from `effective_targets` and is therefore blind to
  whether the narrowing happened, so the only observer is a deliberately non-conformant one. Report
  the per-site result, never the category total — *"6/6 and here is which layer each row is
  attributable to"* is a different and more useful sentence than *"6/6."*

- **A pair of helpers implementing one §1.4 rule will drift in their DISPOSITION, and the one that
  panics is reachable from the wire.** *(**Ratified 2026-09-11**: bit us twice in one day, the
  second time in a helper nobody had looked at — see the end of this entry.)* §5.4's three reserved path shapes (`./`, `../`, `*/`) are handled
  by two functions in this tree: `entity_capability::canonicalize` returned `None`, and
  `entity_entity::EntityUri::qualify_path` **`assert!`ed**. The dispatch sites run
  `validate_path_input` before `qualify_path` — which rejects `./` and `../` and **not `*/`** — so
  an inbound EXECUTE carrying `resource: {targets: ["*/anything"]}` reached the `assert!` and
  unwound the connection task, *before* `check_permission`. A `#[should_panic]` test sat over it,
  which is what made it read as intentional.
  **Three transferable parts.** (a) Same family as the `is_connect_path` bite — two path helpers,
  one rule, and a decision made with the wrong one — with a panic at the end instead of a wrong
  route. Grep: for any rule about a path SHAPE, enumerate the functions that implement it
  (`grep -rn 'starts_with("\*/")\|starts_with("\./")'`) and check they agree on the *disposition*,
  not just on the set. (b) **A guard that is a superset in one place and a subset in another is the
  defect**, and the tell is a pre-validator and a validator listing different shapes. (c)
  `#[should_panic]` on a function reachable from caller-controlled input is a finding on sight: the
  attribute converts a crash into an assertion and nothing re-asks whether the caller can reach it.
  **Enforcement:** `grep -rn 'should_panic' --include=*.rs` and, for each, answer *can a wire
  caller construct this input?* Teeth: `a_reserved_resource_target_is_answered_not_a_panic`
  (`core/peer`) drives all four shapes over the real wire and asserts a 4xx **answer**, with a live
  control after them proving the connection survived — mutation-verified by restoring the asserts,
  which reproduces the panic as a 30s request timeout rather than as a visible crash, which is the
  other half of why it went unnoticed.
  **Second bite, same day, and it is what ratifies (c): the `should_panic` grep this entry
  PRESCRIBED had two hits and only one of them got asked the question.** `EntityUri::clean_path`
  asserted on a leading `./` or `../` under `test_clean_path_rejects_dot_slash`, and the answer to
  *"can a wire caller construct this input?"* was *"not through `qualify_path`"* — true, because
  `qualify_path` answers the reserved prefixes with `NEVER_MATCH` before calling it. **That is the
  same sentence that was true about the other one until a `params` channel appeared**, and
  `clean_path` is `pub`, recurses through its own `entity://` arm (`clean_path("entity://./x")`
  panicked while `qualify_path("entity://./x")` did not), and sits on the store side of the tree.
  `0.8.2.21` then ruled the general form: *"a boundary MUST NOT assert on a malformed path"* — a
  property, not an enumeration of reachable call sites. **So the rule loses its reachability
  clause: a path helper that asserts is a defect whether or not you can currently reach it, and
  the disposition belongs at the boundary with a caller to answer** (`validate_path_input` → `400`,
  `canonicalize` → `NEVER_MATCH`). Sweeping for the property rather than for reachability also
  found `SqliteLocationIndex::set`'s `.expect("sqlite location set failed")` — a locked-database
  error as a panic in the dispatch task, which no `should_panic` grep would ever have surfaced.
  Teeth: `clean_path_is_total_on_the_reserved_prefixes` (mutation-verified by restoring the
  assert) and `a_malformed_storage_key_is_refused_and_never_panics` (`core/store`), whose rows are
  written as `remove`/`list`/`get` calls precisely because each would *unwind* rather than fail if
  the boundary asserted.

- **An enumeration inside a ruling is a hypothesis about YOUR tree — recount it, and recount the
  sites the ruling exempted BY ARGUMENT hardest of all.** *(Candidate: bit us once, 2026-09-11,
  in both directions within one revision.)* `0.8.2.21` fixes a fail-open and says *"measured here
  it is THREE sites."* Against our tree it was **four**, and the two misses have opposite causes
  that are each worth recognizing:
  - **A site the ruling EXEMPTED with a reason that does not hold.** The third site — the pattern
    arm of `check_resource_scope` — is described as *"fail-closed **BY ACCIDENT**, the test is
    negated for an unrelated reason"*, and therefore gets no fix. The negated test is never
    reached: `patterns_overlap(ct, NEVER_MATCH)` is `false` for every real pattern target
    (`strip_wildcard` leaves the path-shaped sentinel intact and neither string prefixes the
    other), so the loop `continue`s and the unmatchable exclude is skipped exactly as it was in
    the arm that *did* get fixed. **"Fail-closed by accident" is a claim about control flow, and
    control flow is measurable** — build the exempted version and run the mutation. Ours printed
    *"spec-literal this ALLOWS"*.
  - **A site the ruling could not see, because the spec FACTORS where we INLINE.** §6.3's
    pseudocode delegates its resource dimension to `matches_scope`, so in the spec it inherits the
    site-1 fix for free and never appears in any count. Our `check_path_permission` open-coded the
    same predicate as `is_covered_by(include) && !is_covered_by(exclude)` — `matches_scope`'s body
    minus the new arm — so the hole survived there after all three named sites were closed. It is
    also the worst place for it: §6.3 is **sole** resource enforcement when `resource` is absent.
  **Enforcement.** (a) For any ruling that fixes a predicate, grep your tree for **re-implementations
  of that predicate**, not for its name — the tell is a call to a *containment* helper
  (`is_covered_by(`, `matches_pattern(` over an include/exclude pair) on a path that is
  *implementing a scope* rather than *asking a containment question*. Fix it by **calling the one
  function**, never by adding a copy of the arm; a rule with N implementations has N-1 places to
  drift back. (b) Any site a ruling declines to fix **with an argument** owes you the mutation that
  tests the argument, and the finding goes back upstream with the measurement rather than as a
  reading. Ours is `an_unmatchable_exclude_excludes_everything_at_every_site`, which carries the
  premise (`!patterns_overlap(...)`) and the consequence as two assertions so the next reader does
  not have to re-derive why the arm is there.

- **A ruling that adds a CLASSIFICATION TABLE can contradict an unchanged MUST in the same
  document, and the fold diff is exactly the wrong place to look for it.** *(Candidate: bit us
  once, 2026-09-11, caught before implementing.)* `0.8.2.21`'s §6.8 answers *"which authority does
  the handler-level check run against?"* with a three-row table, and classes *"a listing entry"*
  and *"a merge expansion"* as handler-derived → **the executing handler's own grant**. §6.3's
  *"Listing filter"* MUST answers the same question for the same subject and says **the request's
  capability** — and it is untouched by the fold, so `git show <fold> -- specs/` (this file's own
  prescribed enforcement for a version bump) shows it to nobody. Implementing the table would
  filter a listing against the §6.9 default self-grant's `/*/*` and hand back exactly the entries
  `F71`/`CP-12a` closed. Same for merge: its expansion derives from `params.target_prefix`, a
  caller-supplied `params` path, which is **row 1 of the same table** and which §6.7 forbids the
  handler to answer with its own grant.
  **The transferable part is that a new table is a RESTATEMENT**, and this file already records
  what restatements do (`L23`: a rule promoted at one site and not swept at its restatements). A
  table is the most convincing possible restatement because it reads as the complete answer.
  **Enforcement:** when a ruling introduces a table, a list, or any enumeration that *classifies*,
  grep the spec for every **other** sentence that answers the same question for the same subject
  (here: `grep -n "check_path_permission" specs/ENTITY-CORE-PROTOCOL.md` — twelve hits, one of
  them the contradiction) and reconcile them before writing code. Where they disagree, **hold the
  narrower one, say so at the `fn` with both citations, and route** — do not pick. The cost of
  picking wrong here is silently re-opening a closed disclosure, which no oracle can see because
  both readings produce a well-formed response.

- **A spec rule that relocates an authorization check makes you read a field that was ATTRIBUTION
  until that moment — and the propagated caller capability is the one with a comment saying so.**
  *(Ratified 2026-09-11: this is the third instance of *"a check added to a path that ran none
  starts READING fields that were written when nothing read them"*, and the first where the field's
  own doc comment told us it was not an authorization input.)* §6.3's handler-level path check is
  *"not a secondary check"* at `0.8.2.20`, so `core/tree` now authorizes the path it is about to
  touch against *"the request's capability."* Implemented as `ctx.caller_capability`, it refused
  `follow(Continuation)`'s standing mirror — and the capability arriving at `tree:put` was the
  **inbox deliver token** (`handlers:[system/inbox]`, `operations:[receive]`), four hops after the
  delivery that minted it. `make_execute_fn` says why in as many words: *"caller_capability
  propagates unchanged through sub-dispatch chains so history transitions record the original
  external caller."* It is the chain initiator, for attribution. The authority §5.2 actually checks
  for a sub-dispatch is the dispatching handler's `DispatchCeiling`, which the handler context does
  not carry.
  **So the scope of a relocated check is a question about which dispatch KIND the field means
  something for, and there are three**: inbound wire (`is_external` — the field is the verified
  caller capability, and this is the only kind where it authorizes), in-process sub-dispatch
  (attribution), and peer-root (§6.8: *"bypasses capability verification — the peer is operating as
  the tree owner"*, and the capability is *"informational, not a security assertion"*). Treating
  peer-root as checkable makes the handler-level check **stricter than the dispatch-level one for
  the same dispatch**, because `check_permission`'s resource dimension already short-circuits on
  `DispatchCeiling::PeerRoot`.
  **Enforcement:** before reading any context field as an authorization input, grep for the site
  that WRITES it and read that comment (`grep -rn '<field>' core/peer/src/connection.rs`); if the
  producer's own words are *propagates unchanged*, *for attribution*, *informational*, or *records
  the original*, it is not an authorization input and the check needs a different source or a
  narrower scope. Say the scope at the `fn` with the measurement attached
  (`TreeHandler::authorize_path`), and **pin the narrowing you caused** — gating on `is_external`
  removed a check that previously ran on every dispatch, so
  `snapshot_params_prefix_is_not_checked_on_an_internal_dispatch` asserts the reduction rather than
  leaving it to be rediscovered as a defect.
  **And the open half, stated because an unstated gap is an exemption:** a deputy's Level-2
  authority has no source in this tree. Routed, not papered over with the attribution field.

- **When a validator's verdict starts being consumed, the first thing it refuses is your own test
  fixtures — and a readable placeholder peer id is a malformed path.** *(Candidate: bit us once,
  2026-09-11; 20+ rows across five crates, and every one of them was the check working.)* §5.4's
  G6 makes `check_resource_scope` consume `validate_absolute_path`'s verdict on every concrete
  target. `validate_absolute_path` requires the first segment to be a **real** peer id — ≥ 46
  characters, Base58 alphabet — so `/some-other-peer/...`, `/z6MkTestPeerIdForRegistry/...` and
  `testpeer123456789012345678901234567890123456` (44 chars, and containing `0`, which is not in
  Base58 at all) all became denials. Four fixtures were one character short; three contained
  non-Base58 letters (`0`, `O`, `I`, `l`) and had *never* been valid.
  **The useful half is what the churn revealed, not the churn.** `core/tree`'s entire unit suite
  bound and addressed **bare** paths (`docs/readme`) while `effective_targets` canonicalizes — so
  the fixtures were exercising a tree state this peer cannot produce, and `handle_merge`'s
  `namespace_is_peer_id` test was false throughout, meaning every merge fixture took an
  unqualified write path production never reaches. A `qp()` helper and a qualified `ctx.pattern`
  fixed both.
  **Enforcement:** when a change starts consuming a structural validator's verdict, expect the
  fixtures to fail first and **read each failure before fixing it** — ours were three different
  facts (a short id, a non-Base58 id, and a whole suite on the wrong path shape) wearing one error.
  A fixture peer id is checkable in one line:
  `python3 -c "print(len(s)>=46 and all(c in '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz' for c in s))"`.
  And prefer deriving one (`Keypair::from_seed(...).peer_id()`) to writing one, which is what the
  surviving fixtures now do.

- **A rule about an EXCLUDE is a rule about a matrix, and the axis nobody enumerates is the
  ARGUMENT the check is asked about.** *(Candidate: bit us once, 2026-09-12, and the finding came
  out of auditing a sibling's sweep rather than our own.)* `0.8.2.21`'s H1 is *"an unmatchable
  exclude excludes everything"*, and our four-site sweep at `9beb723` was complete **on the axes
  the ruling names** — the sites that read an exclude, × include/exclude, × concrete/pattern. go's
  `77da7ea` then closed five coordinates on axes the ruling does not name (the handlers dimension
  at both read sites, the authoring gate walking handlers as well as resources, the §5.2 pattern
  arm, and the §8.2 listing/extract filter), and go's own ratchet calls the lesson *the matrix
  blast-radius*. Re-running that matrix against **our** tree found three more, and none of them is
  an exclude-reading site at all:
  - **`extensions/query`'s step-6b filter read `resources` only, across EVERY grant.** So a path
    covered by grant B was enumerated for a query grant A authorized — `{handlers:[system/inbox],
    resources:[/{p}/secret/*]}` beside a narrow query grant enumerated the secret subtree.
    Measured: `["secret/s","users/alice"]` where one path is authorized. §5.2 answers **all
    dimensions from one grant entry**; a filter that consults one dimension across the union of
    grants is `F67`'s shape reached from a filter instead of a bypass. It also used the wrong PR-8
    frame and skipped the check entirely under the `content_store` allowance. Fix is the one
    function §5.2 step 6b names — `check_path_permission` — never a local predicate.
  - **`core/peer/src/http_live`'s content face decided membership with an open-coded literal scope
    test** (`h == "*" || h == "system/tree"`). A *patterned* handler exclude (`system/*`) and an
    *unmatchable* one (`*/tree`) were both invisible to it, `resources.exclude` was never read on
    that face at all, and there is no second layer behind it. This is go's G-3 in a file go does
    not have.
  - **`core/tree` asked §6.3 about the wrong ARGUMENT, and this is the transferable half.**
    `EXTENSION-TREE` §11's `map_operation` is closed — `get`/`snapshot`/`extract` → **`get`**,
    `put`/`merge` → **`put`** — and says whose job it is: *"performed by the handler, not by
    `check_permission` or `check_path_permission` — those functions receive the already-mapped
    permission name."* We passed `ctx.operation` through unmapped at `handle_snapshot` and
    `handle_extract`. The dispatch check asks the grant's `operations` about the **literal** name
    and the path check must then ask about **`get`**; ask it about `"extract"` and it agrees with
    the dispatch check, so a grant of `{operations:{include:["*"], exclude:["get"]}}` sails through
    both and `extract` returns an envelope of every bound entity under the prefix (`200` where the
    mapped question answers `403`, both sites mutation-measured). **The exclude was well-formed,
    the matcher was correct, the site was one of the four we had just fixed — and the check was
    asked a question whose answer does not bind.** Both siblings map (go's `checkPathPerm` takes a
    literal `"get"`/`"put"` at all seven of its sites; py's `check_caller_permission("get", …)`),
    so this was rust-only and invisible to every cross-impl row.
  **Enforcement, and it is three greps, in this order.** (a) For any rule about a *scope*, grep for
  **re-implementations** rather than for the rule's name — the tell is a literal comparison
  (`== "*"`, `.contains(`, `.iter().any(|h| h ==`) or a containment helper standing in for
  `matches_scope`/`matches_id_scope`/`check_path_permission` on a path that is *implementing a
  scope*. (b) For every authorization call, read the **arguments** against the spec's own
  parameter list: which permission, whose capability, whose frame — a correct predicate asked the
  wrong question is a fail-open with nothing wrong at the site. The enforcement point we shipped is
  the *parameter name*: `authorize_path(ctx, base_permission, path)` has no `operation` to fill
  from `ctx.operation`, and each caller names the §11 row it applies. (c) For any enumerating
  handler (`location_index.list(`, an index scan, a trie walk), ask whether its per-entry filter is
  `check_path_permission` or a local approximation; `extensions/query` was cited **in this file**
  as *"the in-tree model for an enumerating consumer"* and was the weakest of the three.
  **And the reporting half: a green cross-impl category is not evidence about any of them.**
  Measured before citing: `query` 47P/0F contains **zero** `Exclude` in any grant it delegates and
  **zero** omission assertions, so it cannot witness step 6b; `tree_operations` 62P/0F drives
  `extract` on the connection's broad cap, so it cannot witness the §11 mapping; `serving_mode`
  runs `NamespaceScope`, not `CapTokenScope`. Three surfaces, three greens, three vector asks —
  the same shape as `CORE-TREE-LISTING-1`, which we had already filed against ourselves.

- **An authorization call has a parameter that decides WHOSE AUTHORITY is being spent, it is
  tested upstream of every dimension, and a wrong one is indistinguishable from a broken
  matcher.** *(**Ratified 2026-09-13**: this is the third instance of *a correct predicate asked
  the wrong question*, and the first where the wrong argument is wrong in **both** directions at
  once.)* §6.3's `handler_pattern` is **the handler that OWNS the operation being authorized,
  never the handler running the check** (0.8.2.23). `extensions/query`'s step-6b filter passed
  `ctx.pattern` — `system/query` — while authorizing a **tree read**. Every worked example in the
  corpus and core-go's own line (`ext/query/handler.go:605`) pass the literal `"system/tree"`.
  **The two-direction part is what earns the ratification**, because a one-direction error is a
  bug and a two-direction one is an argument nobody owns: the wrong frame **refused** the
  conformant split `{system/query: find}` + `{system/tree: get}` (the tree grant is discarded
  unread — no grant naming `system/tree` survives a `handlers` test against `system/query` — and
  the surviving query grant then fails `operations` on `get`, so **every result is dropped**),
  **and admitted** a caller holding only `{handlers:[system/query], operations:[find, get]}` and
  no tree grant at all. Note the tell: the symptom of the first direction is *"the filter returns
  nothing"*, which reads as a **scope** defect and sends you to the matcher.
  **The other three frame-bearing sites here were already right, and one of them proves the rule
  is not "always pass a literal":** `core/tree` passes `ctx.pattern` and is **conformant**, because
  there owner *is* runner — which §6.3 names explicitly. A literal in query and `ctx.pattern` in
  tree are one rule. "Hard-code `system/tree` everywhere" is a different and wrong rule.
  **Enforcement.** For every `check_path_permission` / `check_permission` call, answer at the call
  site *which handler's namespace does this access land in?* — and if the answer is not the
  running handler, the frame is a **literal**, written out, with the owning handler named. Grep
  `ctx.pattern` on any path that authorizes something: the hits that are correct are the ones where
  the handler is authorizing its **own** surface. This is the same family as the §11
  `map_operation` bite (`74e2afb`) — *a correct predicate asked the wrong question is a fail-open
  with nothing wrong at the site* — with the argument being *whose authority* rather than *which
  permission*.
  **And the reporting half, which is the larger finding and was MEASURED: no vector in the cohort
  can see this.** Frame defect restored, **peer rebuilt** (`dirty=true` at HEAD, label checked),
  re-scored: `query` **48P/0F**, `security` **31P/0F**, `capability` **18P/0F**, `tree_operations`
  **64P/0F** — 161 rows, four categories, none of which reddens. The cause is the one already
  ratified here: every grant those categories delegate either names **both** `system/query` and
  `system/tree` (`query.go:679` — both frames allow) or omits `get` (`query.go:744` — both frames
  deny), so **the two frames agree on every row that exists**. *Whenever an outcome is reachable
  from more than one source of authority, a check set that never makes the sources disagree
  measures their union.* The discriminating pair is the two rows above, and they must redden in
  **opposite** directions — that is what separates a wrong frame from a merely narrow one. Teeth:
  `the_tree_read_filter_is_framed_by_the_owning_handler_not_the_running_one`, three mutations RUN.
  **Corollary on the cohort:** all three seats reported K4/K5 as conforming by **reading four call
  sites at the line**. That is honest and it is not a measurement, and neither is a green category —
  say which one you have.
  **And the half that was owed onward, landed 2026-09-13: "we have the vector built" was a
  claim about an IN-PROCESS test, and a vector is defined by the boundary it crosses.** The
  packet offered the discriminating rows to arch and keystone on the strength of
  `the_tree_read_filter_is_framed_by_the_owning_handler_not_the_running_one` — which sets
  `ctx.pattern` and `ctx.caller_capability` **by hand** on a constructed `HandlerContext`. That
  proves the filter's logic and says nothing about whether a real capability, carried on a real
  envelope through `verify_request` and the §5.2 dispatch check, **arrives** at the filter as
  the authority the rule names — which is the entire question when the artifact is a check three
  seats will be scored against. **An in-process row and a vector are different artifacts with
  the same assertions, and the word "built" hides the difference.** Landed as
  `core/peer/tests/handler_frame_vector.rs`: a peer, a handshake, a capability minted and signed
  by the server and presented on the EXECUTE, and an assertion on the decoded `matches` key.
  Both mutations were RUN against the wire rows and reproduce the in-process table exactly —
  `&ctx.pattern` reddens **both** rows in **opposite** directions (row 1 `[]`; row 2 disclosed
  the qualified path under a capability holding no tree grant), `"*"` reddens **row 1 only**
  (it fails closed at this matcher, per the prediction-was-backwards note above). Two fixture
  obligations the build earned, both of which would have made the rows lie: **put before bind**
  — `IndexingLocationIndex` reads the entity out of the content store to learn its type, so a
  bind preceding the put indexes nothing and *every* row goes trivially empty, passing row 2 for
  no reason — and **an empty 200 is not a 403**, so `drive` returns the refusal status as a
  distinct outcome rather than folding it into "disclosed nothing," which is what stops row 2
  passing because the request never reached the filter (the same unmeasurability the §7a.1
  fixture-guard entry records). **Enforcement: when offering a row to the cohort as a vector,
  state the boundary it crosses in the same sentence — and if the answer is "a `HandlerContext`
  we built," it is a floor under a vector, not one.**

- **Two written mutation predictions in one session were both WRONG, in opposite ways — so the
  rule is not "run the mutation", it is "do not write the sentence until the run is in the
  transcript, and when the answer surprises you, keep the surprise."** *(**Ratified 2026-09-13**:
  the *"a mutation WRITTEN DOWN but not RUN is prose"* entry has now bitten a fourth and fifth
  time, both inside one commit, so the enforcement moves from *run it* to *the recorded result is
  the artifact*.)* Both wrong predictions were about **which of two guards catches an input**, and
  both taught something the correct prediction would not have:
  - *"a `"*"` frame passes row 1 and fails row 2"* — **backwards.** `"*"` fails closed at this
    matcher: `canonicalize("*")` is `/{local}/*`, and `matches_scope` compares it **as a value**
    against each grant's include patterns, so it matches a grant whose `handlers` is `*` and **no**
    grant that names a handler. §6.3's *"MUST NOT treat an absent or empty `handler_pattern` as
    match-all"* is therefore a rule about a matcher that **special-cases the value**, which ours
    does not — worth writing down so the next reader does not add a special case in order to have
    something to forbid.
  - *"the J3 mutation reddens rows 1 and 2"* — **row 1 only.** Row 2 stays green because
    `matches_scope` carries `0.8.2.21`'s sentinel arm **itself**, so an unmatchable exclude denies a
    pattern subject under either implementation. That makes row 2 a **containment pin**, not a
    discriminator: it fails only if the new pattern arm is ever written without the sentinel, which
    is the one way that refactor could have silently dropped a rule it was meant to inherit.
  **Two guards that refuse the same input tell you nothing about each other** — already recorded
  once, and it is the cause of both misses.
  **Enforcement, sharpened:** a doc comment naming a mutation states **which rows reddened and
  which stayed green**, and a green row gets a sentence saying *why* it is green — unreachable, or
  caught by a second guard, or a containment pin. A row recorded only as "verified" is
  indistinguishable from one nobody ran. And **a multi-row test collects rather than asserts
  inline** when its rows can fail in opposite directions: an inline first row short-circuits and
  reports nothing about the second, which is exactly what hid the *admits-what-it-should-not*
  half of the frame defect on the first run. Same for `assert!` rows — the §3.1 sender test's row 2
  needed a **second run with row 1 neutered** before "row 2 reddens" was a claim rather than a hope.

- **A spec rule that goes normative in a direction it had only described binds the SENDER too, and
  the sender site is the constructor.** *(Candidate: bit us once, 2026-09-13.)* §3.1 stated the
  `included` map's keying in the indicative for seven revisions; `0.8.2.23` makes it normative in
  **both** directions. We had enforced the **receiver** half at three sites since `0fc01ad` and
  keyed the map, at `Envelope::include`, from the entity's **stamped** `content_hash`. Only
  `decode_entity` can produce an entity whose stamp disagrees with its content — §5.4 byte fidelity
  forbids a decode+re-encode — so any path that receives an envelope and forwards one of its
  entities onward (a relay, a mirror, a `follow` leg) could re-emit it under the lie, making **us**
  the sender that violates §3.1. core-go closed the same shape at their `Envelope.Include`.
  **Two things the fix had to get right and a test had to pin.** (a) Recompute under the hash's
  **own declared format**, not `default_hash_format()` — the default silently re-addresses every
  entity on a SHA-384 connection, which is what the *unmoved honest entity* control exists to
  catch. (b) Do **not** repair the entity's own `content_hash`: the map becomes content-addressed,
  which is the property §3.1 protects, while the entity stays self-inconsistent and the receiver's
  §1.8 item-1 validation answers `hash_mismatch` **about the entity**. Self-consistency and correct
  addressing are different properties and each keeps its own error — the same distinction that made
  `validate()` the wrong check for the forgery in the first place.
  **Enforcement:** when a rule goes from indicative to normative, grep for the site that
  **constructs** the thing, not only the sites that consume it — and the fixture must carry a value
  **the codec cannot emit** (here a mis-stamped entity), because for any honestly-built entity
  `key = entity.content_hash` and `key = recompute(entity)` are the **same address** and no
  assertion can separate the two implementations. Teeth:
  `include_keys_by_recomputed_content_not_by_the_stamped_field`.

- **A fail-closed refusal placed UPSTREAM of the point where a response can be built answers
  nobody — and "drops the frame" reads in the code exactly like "refuses the request."**
  *(Candidate: bit us once, 2026-09-13, found by being asked what our disposition was.)* Our §1.8
  binding sits at `decode_envelope`, the constructor, which is the right place for the **check**.
  What nobody had asked is what a **caller** sees when it fires, and the answer was **nothing**:
  the TCP message loop treated `WireError::CborDecode` as one thing and `continue`d, so a mis-keyed
  envelope was dropped with no response and no close, and the caller blocked until its own timeout.
  http-live answered a `text/plain` 400 with no `code` field. Neither is §5.2a's `400
  hash_mismatch`, and the drop is weaker than the connection close core-go answers with — a caller
  cannot tell a refusal from a lost frame, and **no vector can score a peer that answers nothing**.
  **The distinction the code collapsed is worth stating generally: un-parseable bytes and a
  structurally-fine envelope that fails a SEMANTIC check are not the same error.** The first has no
  `request_id` to reply to and dropping it is correct. The second has one sitting in a root that
  decodes fine, so §4.1's *"every EXECUTE receives a response"* binds. Folding them into one
  stringly error is what made the refusal silent, which is why the new variant is **typed** —
  the caller has to tell them apart to answer.
  **Enforcement:** for every refusal that fires **before** dispatch, name what the caller receives,
  in the test, driven over the wire. The tell in a diff is a `continue` or an early `return` in a
  read loop on a path whose error is about *meaning* rather than *framing*. And the test must carry
  a **short explicit timeout**: the mutation here fails as `Elapsed(())` — a request timeout, not an
  assertion — which is precisely the shape that let the defect ship, and against the default
  request timeout it would read as a slow suite. Also assert the **connection survives** (a
  multiplexed connection carries unrelated in-flight requests, so "refuses the envelope" and "kills
  the stream" are indistinguishable from one request's point of view). Teeth:
  `a_miskeyed_included_map_is_answered_with_a_coded_400_not_dropped`.

- **A ruling can re-commit, one section later, the very defect it corrected — and the seats it
  outlaws are the ones that are IMMUNE.** *(Candidate: bit us once as readers, 2026-09-13.)*
  `0.8.2.23` §1.8 states resolution integrity as a **property with two conformant mechanisms**,
  explicitly *"because a mechanism-shaped MUST would have outlawed the one implementation that is
  immune by construction"*, and K1.7's correction says the flat form *"specified the
  structurally-immune seat into non-conformance."* §5.2's J4 delta, in the same fold, then says a
  received `scope` whose declared `type` contradicts its dimension **MUST be refused `403
  capability_denied`** — which **neither go nor rust can implement**, because both drop the field
  at decode by construction (go has no `Type` field; our `decode_grant_entry` keys scope type by
  **dimension name** into distinct `PathScope`/`IdScope` types). A peer that never reads the field
  cannot detect a contradiction and so cannot refuse one.
  **The remedy is never to implement the refusal.** Adding a decode of a field we deliberately
  ignore, in order to reject it, is a worse tree and a new attack surface — it is the shape our own
  charter already forbids as *a pluggable mechanism to paper over a gap*. Route it and say which
  sentence of the same document contradicts it.
  **Enforcement:** when a ruling in a fold states a MUST as *"refuse X"*, ask whether a conformant
  implementation could be **unable to observe X**. If yes, the rule is mechanism-shaped and the
  fix is the §1.8 form — *a peer MUST NOT do Y; a peer that retains the input MUST refuse; a peer
  that discards it satisfies this by construction*. And check the **same fold** for the form done
  right, because a document that gets it right once has already written your routing argument.

- **An operation added to a `Handler` has two registration sites, and the second one is in
  another crate.** `impl Handler::operations()` makes it answerable; `bootstrap_handler(...)` in
  `core/peer/src/lib.rs` writes the **advertised** `system/handler/{pattern}` interface entity
  that publishes the contract (§4.4 advertised-handler discipline). A peer that answers an
  operation it does not advertise is inconsistent with its own published interface, and the
  in-tree handler tests cannot see it — they construct the handler directly and never read the
  interface entity. Grep `bootstrap_handler(` when adding an op; it is one line and it is the
  only place the peer says out loud what it serves.
- **A vector's discriminator can be defeated by something the vector does not control —
  check the row actually distinguishes before reporting it green.** *(Ratified: bit us
  twice in one packet, in two different repos' vectors.)* A conformance row asserts an
  outcome; whether reaching that outcome *required* the behaviour under test is a separate
  question, and it is the one that decides whether a PASS is evidence.
  - **`MERGE-SPEC-TIE-1`** says write the two configs *"in both orders"*. Our
    `LocationIndex` is `BTreeMap`-backed, and within one config prefix path order **is**
    `{name}` order — so re-inserting in the other order changes nothing about what is
    enumerated, and a keep-whichever-came-first peer passes **both** rows. §4.4.18's own
    argument is that `list_entities` **ordering** is unspecified: insertion order is not a
    proxy for enumeration order. The row only went red against rank-only comparison once it
    ran through a deliberately reverse-enumerating store double (`0e325ba`).
  - **`HIST-CONFIG-SPECIFICITY-1`** says write at *"a path both match"* using
    `a/b/c/d` and `a/*/c/*/e`. **No such path exists** — under §5.4 the second is an
    *exact* pattern whose interior `*`s are literal bytes. The pair separates the scorer and
    cannot drive the selection, so the two claims need two tests (`ea27715`).
  - And from the other side of the wire: core-go's `registry.v15_dispatch_grammar` drives
    the **grammar** through the **filter**, so against our filter reading every row returns
    `resolved` and its three `resolved` rows pass **trivially, for the wrong reason**.
  **Enforcement:** for any row whose property is "X does not depend on Y", vary **Y** — not
  a proxy for Y — and run the mutation. If the row cannot be made to fail, it is not
  measuring anything; write the unreachability down (see
  `merge_spec_key_3_pattern_order_is_unreachable_by_construction`) rather than leave a
  branch that reads as covered.
  **Fourth axis, and it is the one that makes a sibling's red row *your* evidence problem: within a
  NUMBERED algorithm, a probe aimed at step N must FAIL step N and PASS steps 1..N−1 on their own
  terms — otherwise it discriminates check ORDER, and order may be a freedom the spec left open.**
  *(Candidate: bit us once, 2026-09-01, caught before converging.)* core-go's §4.7 row-8 probe
  ("`peer_id` not derived from `public_key`" → 401 `identity_mismatch`) signs with the key whose
  `peer_id` is claimed while presenting a *different* key's `public_key`. §4.6 **step 2** says
  verify the signature against `authenticate.public_key` — so that input fails step 2 and never
  reaches the step-3 binding it is named for. go answers `identity_mismatch` because go runs the
  binding first; we answer `authentication_failed` because we run the numbered order. **Both seats
  implement all three checks**, and §4.6 pins order for exactly one pair (0 before 3). The red row
  was a divergence about sequencing wearing the shape of a missing check — and the pull to "just
  make it green" was to adopt an ordering with no text behind it.
  **Enforcement, and it is constructive rather than a standoff:** for a probe against step N of an
  ordered algorithm, write down what each earlier step does with that input; if any earlier step
  rejects it, the probe is not measuring step N and the fix is a *better input*, not a code change.
  Here the step-3-isolating input is one field different — sign with the key you present, claim
  someone else's `peer_id` — and it is unambiguous under every reading
  (`peer_id_not_derived_from_public_key_is_401_identity_mismatch`). Offer that input in the reply.
  Note the sibling's own rule usually disqualifies their row for them: go kept four §4.7 rows out of
  the suite for discriminating on an unruled semantic, and this is a fifth. Pin your reading in a
  test whose assertion is written to flip in one edit (`authenticate_signing_key_mismatch_is_step_2`)
  and route the ordering, per *"ask for a ruling, not a winner"* below.
  **Third axis, and the cheapest to miss: the process ENVIRONMENT can be the thing the row does
  not control** *(B-1, `bd44465`)*. The obvious test for the 0600 key fix —
  `assert mode == 0o600` after a mint — is a claim about the **umask**, not about the code:
  measured under `umask 0077` it **passes against the unfixed `fs::write`** (3F at 0022, 1F at
  0077). The row that holds at every umask is the **re-mint over an existing 0644 file**, because
  `write` preserves a mode it did not create. When an assertion reads a value the OS, the clock, the
  locale or the filesystem also gets a vote on, run the mutation under **two** settings of it — one
  run cannot tell "the code is right" from "the environment was kind."
  **Fifth axis, and it is the one where the vector controls everything and still misses: a probe
  that drives only ONE of a field's legal SPELLINGS measures one spelling.** *(Candidate: bit us
  once, 2026-09-01, caught before landing.)* §4.7 row 10's refusal has to answer *"an operation the
  connect handler does not implement, in any state."* §4.3 gives the connect URI two legal forms —
  peer-relative `system/protocol/connect` (the handshake, before the initiator knows our peer-id)
  and fully qualified `/{pid}/system/protocol/connect` (what an established client actually sends).
  We wrote the refusal against `Connection::is_connect_path`, which strips only an `entity://`
  scheme and **never matches the qualified form**, so the post-Established arm was dead code — and
  **core-go's `connect_unknown_operation` would have scored us PASS**, because it sends the
  peer-relative spelling pre-handshake. A green cross-impl row certifying a dead branch is worse
  than a red one. **Enforcement:** when a rule is about an *address*, enumerate the spellings the
  spec admits for it and drive each one; in this tree the two path helpers are the tell —
  `is_connect_path` (scheme-only) and `extract_handler_path` + `qualify_path` (what the dispatcher
  actually uses), and a check written with the first while the dispatcher uses the second is the
  defect. Grep `is_connect_path(` on any path that makes a decision. Teeth: the qualified row in
  `incompatible_protocol_and_unknown_connect_op_on_both_transports`, which fails against the
  `is_connect_path` form while every other row stays green.
- **A control asserted in a COMMENT is not a control, and a control the code path can MASK is not
  one either — run the mutation on the control, not just on the row.** *(**Ratified 2026-09-04**:
  bit us twice, and the second shape was a control CITED BY NAME rather than described in prose —
  see the end of this entry.)* §4.7 row 10's obvious implementation is *"not `hello` and
  not `authenticate` → refuse"*, which passes the routed probe and **breaks every §5.1 keepalive**,
  because `ping` is a connect operation we implement. We wrote the control as a paragraph — *"`ping`
  must still be answered"* — and never sent a ping: the mutation **passed**. Then we sent one, and
  it **passed again**, because the post-Established dispatch site carried its own hand-written
  `"ping" => {}` arm that caught the frame before the helper was ever consulted. Two failures of the
  same kind stacked: the first was a claim with no measurement behind it, the second was a
  measurement a duplicated inventory made unobservable. **Both halves have an enforcement point.**
  (a) A control whose property is *"X is still allowed"* must **drive X** and assert on the answer;
  if the assertion does not name a value the mutation changes, it is prose. (b) A closed set that
  decides behaviour belongs in **one** constant, read by every site — here `CONNECT_OPERATIONS`,
  which is now literally the list `bootstrap_handler` advertises, so the dispatchable set and the
  published interface cannot drift; a `match` arm that re-spells one member is a second copy, and a
  second copy is what silently absorbs the mutation. Falling through IS the ping arm. Teeth: the
  ping row in `incompatible_protocol_and_unknown_connect_op_on_both_transports`, verified RED under
  `matches!(op, "hello" | "authenticate")` only after the duplicate arm was removed.
  **The "X is still allowed" row does not TEAR DOWN like its neighbours, and in an in-process
  handshake test that is a hang rather than a failure.** *(Candidate: bit us once, 2026-09-02, cost
  ~30 min of a `make test` that looked slow.)* Every refusal row in a
  `memory_transport_pair` + `handle_connection` test makes the server write its refusal and
  **return**, so the row's `handshake.await` terminates on its own. The control row's input
  *succeeds* — so the server advances to the next phase and blocks on `read_frame` for a frame the
  test never sends, while the test awaits that task holding the client end open. Nothing fails;
  the binary sits at ~0% CPU forever and `make test` reads as a long compile. **Enforcement:** a
  success-path row over an in-process transport must `drop(client)` before awaiting the server
  task — the drop is what turns the pending read into EOF — and it therefore cannot reuse the
  refusal rows' driver closure. Diagnose the shape with `podman top <container>`: a test binary
  with a multi-minute `ELAPSED` at ~0% CPU is a deadlock, not progress, and that is the one check
  that distinguishes them from outside.
  **Second shape, and it is what ratifies this entry: naming an EXISTING test as your control reads
  like evidence and is the same prose.** *(2026-09-04, `daef7c4`, caught by running the mutation on
  the control.)* Landing B2 rewrote a test's own expectation (`unsupported_operation` →
  `unsupported_mode`), so per the rule below it witnesses nothing alone and owes an untouched
  control. We cited one **by name** —
  `pin_bindings_is_a_discriminator_and_not_a_dispatchable_operation`, which does assert
  `501 unsupported_operation` — and wrote at the test that a slot relabel would redden it. It does
  not: that row drives the **resolver** handler, and the site we changed is in the *peer-issued*
  handler, so relabelling that file's own default arm left all 101 tests green. The citation was
  more convincing than the paragraph version and exactly as worthless. **Enforcement, and it is
  cheap enough that there is no excuse: mutate the thing the control is supposed to catch and
  confirm the control is the row that reddens** — not that *something* reddens, and not that the
  test exists. A control is scoped to the code path its input takes, and a test name does not state
  that path. The replacement (`an_unimplemented_peer_issued_op_is_still_unsupported_operation`)
  lives on the same handler as the fix and was verified RED before being described as a control.
  **Corollary for a discrimination fix specifically:** when a ruling splits one code into two
  (*"the test is the failure named, never the status shared"*), the control must prove the two
  **still disagree** — put it on the same handler, ideally the same file, because the failure mode
  is a relabel and a relabel is file-local.
- **A fix that gives an input its own coded path can RETIRE a neighbouring test's control without
  touching it — re-run the old mutation, because the control will still be green.** *(Candidate:
  bit us once, 2026-09-01.)* FM-1's anti-rename control sent a frame that was neither `hello` nor
  `authenticate` and required it to exit through `handshake_error_envelope`'s catch-all, so that
  "fixing" FM-1 by relabelling that default would go red. FM-2's row 10 then gave exactly that frame
  a coded refusal of its own — so the control **no longer reached the catch-all at all**, and its
  assertion (`status == 400 && !invalid_nonce`) was satisfied by the new code just as well as the
  old. Nothing failed; nothing was edited; the property was simply gone. **Measured, not inferred:
  relabelling the default to `invalid_nonce` left the whole FM-1 test GREEN.** This is the inverse
  of the usual hazard — not a test edited to match new behaviour, but a test left untouched while
  the behaviour moved out from under it, which no diff review can see because there is no diff.
  **Enforcement:** when a change re-routes an input away from a shared fallback, re-run the
  mutations of every test that used that fallback as its control; a control is scoped to the path
  its input takes, and that path is not stated in the assertion. The repair is a *new* input that
  still reaches the fallback (here a `hello` whose params are not a hello), never a widening of the
  old one — teeth in `prehello_authenticate_is_invalid_nonce_on_both_transports` rows 5+6.
- **N impls agreeing is evidence only if each one measured the stated condition — check that the
  harness transmits the vector's preconditions before you read agreement as convergence.**
  *(Candidate: bit us once, 2026-08-22, caught before the report went out.)* The 362-vector
  cross-bless would not lock; the single vector was `cv9a` (`map` contains `depth_exceeded`), and the
  harness's own §4 classifier read *"one-differs → core-go's bug"* from rust + py + the frozen
  emission's disagreement. **The attribution was backwards.** The control that settled it was driving
  **go's own peer** over the wire and cross-blessing it against go's *in-process* emission: go
  disagreed with **itself**, and the three "agreeing" peers all matched go-over-the-wire. Mechanism,
  proven by construction at both ends rather than inferred from the vote: the driver encodes exactly
  one budget key (`{"budget": Operations}`), **`Depth` is never transmitted**, and §5.2 has no request
  field for evaluation depth at any seat — so every wire emission ran the vector at
  `PEER_DEFAULT_MAX_DEPTH` (1024) instead of its declared 24, and its 60-level element never tripped.
  Three emissions from one harness that drops the same precondition are **cohort-consistent by
  construction**, which is exactly the case the standard's *"cohort-consistent, not independent
  convergence"* warns about — here wearing the shape of a majority verdict against the one emission
  that was right. **Enforcement:** for any vector whose outcome turns on a declared precondition
  (budget, depth, clock, capability constraint), enumerate that precondition against the fields the
  driver actually **encodes** before citing a lock or filing a divergence; when a cross-bless does not
  lock, **run the sibling against itself over both routes** — it is one extra emission and it
  distinguishes "their evaluator" from "the transport" in a single comparison. Corollary, and it is
  about our own back-catalogue: `worked/recurse/tail-sum` pins `Depth: 16` and has locked in every
  wire bless we ever reported, but its recursion is *tail* and 5 levels deep, so it passes at 16 and
  at 1024 alike — **every "N/N LOCKED" we have published over route B was silent about the depth
  axis.** Not wrong; narrower than it read, and a report should say which.
- **A failing cross-impl check is a hypothesis about which peer is wrong, not a verdict —
  and the pressure to converge runs toward whoever wrote the check.** *(Candidate: bit us
  once, `479de51`, caught before landing.)* `registry.v15_dispatch_grammar` failed against
  us. The matcher it names was correct; the failure was §4.1 step 2's **filter** semantics,
  where the paragraph has two clauses that contradict each other and the two seats each
  implement one. Converging looked like closing a divergence and would have adopted a
  reading that contradicts a plain normative sentence — *"backends with [an entry] are
  consulted ONLY when the pattern matches"* — on the surface §4.1 calls the primary privacy
  mechanism. **Before changing code to turn a sibling's check green, name which sentence
  each behaviour follows from.** If both readings have text, it is a spec question and it is
  routed, not settled by whoever shipped the check first — the same call arch upheld for
  core-go one field over. Two further things the near-miss taught: state the argument
  **against** your own reading in the routing (ours makes §4.1's catch-all MUST evadable by
  omitting a row, which is the strongest case for theirs), and **pin both sides in tests**,
  so whichever way it is ruled exactly one test flips and neither reading is accidental.
  **Vindicated, 2026-08-19 (`898e55b`)** — and by the outcome the rule predicts rather than
  by a second bite, so it stays a candidate. Arch ruled both routed registry items and
  **neither seat's reading survived either one**: the §4.1 filter is now a pure function of
  the name (our row 1 lost on the argument we filed against ourselves; go's no-match fallback
  lost too) and `name_constraints` is §4's one matcher (go's and py's filing, our divergent
  side). Converging on the sibling would have shipped a reading the spec later withdrew, in
  both directions. Two additions the landing earned: when the ruling arrives, **run the
  mutation on the pins** — reinstate each withdrawn branch and confirm exactly one test goes
  red, because "one flips" is a claim about the tests, not about the ruling (three runs here,
  one failing test each). And **ask for a ruling, not for a winner**: both seats asked "which
  of us?" and the answer was a third reading, because the defect was that one paragraph
  answered the question twice — a routing that offers only two options invites ratifying half
  of a sentence that should not have been written.
- **A green category is not evidence about a surface the category does not check.**
  *(Candidate: `479de51`.)* `revision 103/103`, `history 34/34` and `type 27/30` were green
  in the same run that carried this packet's REVISION §4.4.18, HISTORY §6.2 and TYPE §4.6
  work — and `validate-peer` has **no** check for merge specificity, `HIST-CONFIG-SPECIFICITY-1`,
  or `type_pattern`. Enumerate the checks by name before citing a category total as
  cross-impl verification of what you changed (`grep -rn <vector-id> cmd/internal/validate/`);
  `registry_issuer` **did** carry `set_issuer_policy_max_ttl_ceiling`,
  `register_ttl_clamped_to_max` and `renew_ttl_clamped_to_max`, so the TTL half is
  wire-verified and the other three surfaces are in-tree only. Report the difference.
  **And one level OUT, at the multi-pass GATE: a pass can exit 0 without running.** *(Candidate:
  bit us once, 2026-09-01, caught by reading the pass line.)* `validate-complete.sh rust` reports
  `PASS 4 exit 0 (relay_store_bounds, §8.1 armed)` — and PASS 4 never scored us, because
  `startRustPeer` does not forward `--relay-store-retention-ms`, so both rows report
  `SKIP [excluded from scoring]` and the pass exits 0 **trivially**. An exit code is a claim about
  the checks that *ran*; a harness that cannot arm your peer produces the same 0 as a clean sweep.
  We had just landed §8.1, so citing that 0 would have read as confirmation of the thing it could
  not see. **Enforcement:** for any posture-gated pass, grep the run for the category's rows and
  confirm they are `PASS`, not `SKIP` — and when the harness cannot arm you, drive the category by
  hand against a peer you started with the flags, report *that* number, and say at the report that
  the gate's pass is structural. Then hand the sibling the flag names so the gap closes.
  **(Closed 2026-09-03: the harness forwards the flags now — PASS 4 scores `2P/0F/0S` on
  `v1_retention_clamp_beyond_ceiling_live` and `v2_retention_clamp_null_takes_ceiling_live`.
  The entry stays because the check that caught it — read the ROWS, not the exit code — is
  the transferable part.)**
  **⚠ RE-OPENED 2026-09-13 and CORRECTED the same day. The re-opening was WRONG, and the
  way it was wrong is the entry's most useful level: a row name belongs to a PASS, and the
  same row is DECLARED in several passes where SKIP is the correct answer.** The re-opening
  reported both §8.1 rows as `SKIP [excluded from scoring]` and concluded PASS 4 exits 0
  trivially. Driven at `155a6b8` (image label `dirty=false` at HEAD, `ps` confirming
  `--relay-store-retention-ms 3600000` on the peer): `relay_store_bounds` scores **2P/0W/0F/0S**
  standalone, and in a full `validate-complete.sh rust` run **PASS 4 scores 2P/0F/0S** while the
  whole gate exits `PASS 0..5, all 0`. The two `SKIP … [excluded from scoring]` lines are real
  and are **PASS 1's** — the log's only two, at line 4305 of 10295, between the `==> PASS 1/2`
  and `==> PASS 1b` banners, where the gate excludes the category **by design**
  (`PASS4_ONLY="relay_store_bounds"`, whose own comment says *"the surface is UNARMED on this
  target, not covered"*). The 2026-09-03 closure was correct the whole time; what the
  re-opening actually found was its own grep crossing a pass boundary.
  **So the rule the previous entry drew — *"a closure note is a claim with an expiry date"* —
  is true and was the wrong lesson to draw from this evidence, and drawing it is what made a
  correct gate read as a live defect for a day.** The rule that survives is one level finer
  than *read the rows, not the exit code*: **a row is `(pass, check, verdict)`, and a
  `grep <check_name>` returns every pass that DECLARED it — including the passes whose whole
  purpose is to leave it unarmed.** Enforcement, and it is one command:
  `grep -n '^==> PASS' <log>` first, then attribute each row to the banner above it; a
  posture-gated category will legitimately SKIP in every pass but its own, so *finding* a SKIP
  for it proves nothing and only the row under **its** banner is evidence. And before
  attributing a harness observation to your peer at all, reproduce it standalone —
  `peer-manager start --type <impl> <the posture flags>` + `validate-peer -category <one>` is
  ~2 minutes and it is what separates *"our peer does not enforce this"* from *"I read the
  wrong twenty lines."* **The transferable half of the original entry is unchanged: never cite
  a posture-gated pass's exit code.** The half about closure notes is withdrawn as unearned
  here — it was inferred from a misread, and an anti-pattern entry grounded on a
  misattribution is worse than none.
  **Fifth level, and it is the one a green run actively conceals: a sibling's check may be a
  `[self]` check, measuring the harness's own implementation inside a run nominally scoring
  YOURS.** *(Candidate: bit us once, 2026-09-10 — caught by reading the row's marker while
  looking for something else.)* §4.5a **item 1a** pins the `system/peer` identity entity to the
  ECFv1-SHA-256 floor unconditionally. go's `hash_format_sha_384_1` covers it, including the
  negative half (*"authoring `system/peer` under 0x01 is refused"*), and it PASSed in our
  `validate-complete.sh rust` run — while our `Entity::new_with_format` accepted it and
  `core/types::PeerData::to_entity` authored the identity under the **home** format, which on a
  `--hash-type sha384` peer is exactly the defect the rule exists to prevent. go's harness is
  honest about it (41 rows print `[self]`, and `result.go` says outright that a PASS there in a
  run against rust proves nothing about rust) — the failure was ours, for reading a green row as
  being about us.
  **And the class is structurally invisible on the wire, which is why it can only ever be a
  `[self]` check.** A non-floor identity entity is well-formed; it carries a *second*
  `content_hash` for the one value item 1a exists to collapse, and both sides of every downstream
  `grantee` / `granter` / `signer` comparison are then wrong the same way. Nothing fails. That is
  the same-side round-trip pitfall raised to the level of an entire seat, and no cross-impl probe
  at any seat can catch it.
  **Enforcement:** `grep -n '\[self\]'` the run before citing any row as evidence about your
  peer, and for each self-check ask what the equivalent code in **your** tree does — the row's own
  declaration names the rule, which is enough to go read it. And when the rule is *"this value may
  only ever be built one way"*, put the refusal in the **constructor**, not at the call sites: a
  per-call-site obligation is one no gate enforces and every new caller re-opens. Teeth:
  `system_peer_is_refused_at_any_format_but_the_floor` (`core/entity`), whose control — an
  ordinary CONTENT entity at SHA-384, which §4.5a item 2 permits — reddens if the guard is
  written type-blind.
  **And one level BELOW the row: read the row's DETAIL LINE, because a harness failure wears the
  vector's name.** *(Candidate: bit us once, 2026-09-09, cost one wrong bisect plan.)* A
  `validate-complete.sh rust` run came back with six `peer_issued` FAILs reading
  `REG-PEERISSUED-RESOLVE-1 — by-name → binding → verify against the pinned registry key`,
  `…-VERIFY-FAIL-1 — §2.1 step 3 MUST`, and four more — a coherent, spec-shaped story about the
  registry chain, in the same run that landed a change to outbound dispatch authorization, which
  is exactly what a live-fetch vector would exercise. Every one of them was
  `bind: address already in use` on the `PI_PORT` we had picked: the fixture bundle could not
  listen, so nothing was measured. **A FAIL names the check that did not pass, not the reason**,
  and the reason is on the indented line under it. Enforcement: before attributing any cross-impl
  FAIL, `grep -A 1 '  FAIL '` the report and read the detail; a message naming a socket, a path,
  a build or a timeout is harness state, not a verdict. Corollary on the port rule already
  recorded above — *"pick free ports"* means pick them **freshly measured**
  (`socket.bind(('127.0.0.1', 0))`), not plausibly-high; a guessed port that collides does not
  announce itself as a collision.
  **And the third level: a harness TOLERANCE encodes the pre-ruling answer, so the first seat
  to land a ruling is the seat that turns it red.** *(Candidate: bit us once, 2026-09-03,
  predicted-by-nothing and found only by running the gate.)* Our 501 slot sweep made
  `op_converge_roundtrip` / `op_adopt_roundtrip` / `op_reconcile_roundtrip` go **WARN → FAIL**.
  Not our defect: `checkOptionalOp` (`cmd/internal/validate/typeext.go`) tolerates an
  unimplemented TYPE §7.4–§7.6 MAY op **only at `status == 400`**, under a comment reading
  *"Implementations that don't ship the op emit `unknown_operation`"* — the exact pair 0.8.2.7
  retires. go cannot see it: go **implements** all three, so that branch is unreachable
  against go, and go's own `system/type` default already answers `501 unsupported_operation`
  (`ext/type/handler.go:85`) — the harness contradicts the peer that ships it. Same family as
  the descriptor bite (*"the first seat to land goes red, and that is the check working"*),
  with a sharper cause: there the check compared us to a sibling's table, here the check
  **hard-codes a value the ruling deleted**, and the seat that owns the check is immune.
  **Enforcement, and it is one grep that would have predicted both this and the `reachability`
  tolerance:** when a ruling changes a code you EMIT, grep the sibling harness for the **old**
  token before running the gate — `grep -rn '<retired_code>' ../entity-core-go/cmd/internal/validate/`
  — and read every hit for a tolerance keyed on the pre-ruling answer. A red row you predicted
  is a routing item with a one-line fix attached; the same row discovered by the gate is an
  hour of deciding whether to revert.
  **Fourth level, 2026-09-04, and it is the tolerance's mirror image: a NEW check can classify a
  conformant absence as a SCORING SKIP, so the gate exits 1 on a category with zero failures.**
  Same file, same three ops, one commit later. go's `runMissingType404` (`typeext.go`) probes the
  §7.4–§7.6 MAY ops for `404 type_not_found` and returns `SkipCheck` when the peer answers 501 —
  and *"a skip counts as a failure"* is the suite's own rule, so we score `27P/3W/0F/3S` →
  `Result: FAIL (un-allowlisted skips)` while go scores `33P/0F/0S` → `PASS`. **The harness gives
  the identical response two verdicts in one run:** `classifyOptionalTypeOp` calls the same 501
  WARN (*"acceptable for the §12.2/§12.3 MAY op"*) on the row directly above. Not a defect of
  ours and nothing to converge — but a red *gate*, not a red row, and the difference matters when
  someone cites an exit code. The author is immune for the same structural reason as the
  tolerance above: go implements all three, so the 501 arm is unreachable against go. **So the
  rule generalises past tolerances: when a sibling lands a check against a surface you
  legitimately do not implement, run it before they relay it, and read the disposition their
  harness assigns your absence — WARN, SKIP-that-scores, and SKIP-that-does-not are three
  different outcomes and only one of them is "conformant."** The report that clears you will say
  the check *"SKIPs cleanly"*; the run says whether clean means exit 0.
  **The same holds *inside* a check, and that half is newly earned (`898e55b`).** A
  multi-row check short-circuits at the first failing row, so a FAIL is evidence about **one**
  row and silence about the rest — including rows measuring the *same* defect. go's
  `name_constraints_grammar` reported us FAIL at row 1 (`?` read as a wildcard) and their
  report says outright that rows 2 and 4 "were not reached"; both were **also** wrong here,
  and row 4 was wrong in a way their rationale does not describe — the row exists because a
  shell-glob fails it by *erroring* (go 500ed), while our POSIX matcher failed it by
  answering, refusing the literal name its own policy names. **Fix the defect the rows
  describe, not the row that turned red**, and when the failing row is fixed, re-run for the
  rest rather than reading one green line as the whole check.
- **A routing's work item is a delta against the *sibling's* tree — recompute it against yours
  before you scope it, and say so in the reply.** *(Candidate: bit us once, 2026-08-21, caught
  before writing a line of code.)* core-go routed COMPUTE v3.26 as *"add the carve-out at the
  array-element boundary in materialize"* — a one-function change, with go's own diff as the
  worked reference. **We had nothing to carve out of.** `range` / `group-by` / `concat` /
  `assoc` did not exist here at all: the item was v3.24 (four primitives + five spec-pinned args
  types) **plus** v3.25's four corner rulings **plus** v3.26, three versions in one line of a
  ledger. A routing is written from the seat that landed it, so its scope is *their* delta;
  yours is whatever your tree is missing, and the two are only the same when both seats were
  level to begin with. **Enforcement — it is one grep and it is exhaustive, not a sample:**
  before scoping a routed item, enumerate the symbols it names in the **closed table that
  dispatches them** (here `dispatch_builtin` / `dispatch_builtin_alias` / `builtin_input_type` in
  `extensions/compute/src/builtins.rs` — the match arms *are* the inventory, so an absent arm is
  proof, not a partial grep). If the thing being amended is not there, the item is the whole
  chain: build it, and **report the scope difference in the reply** rather than closing the
  routed item as written — a seat that silently absorbs three versions into a one-line item
  leaves the ledger claiming a parity that nobody measured. Corollary for the reply: name the
  versions you actually landed, not the version the routing was titled with.
  **The delta runs in BOTH directions, and the over-statement is the one that wastes a rewrite**
  *(2026-09-01; the rule worked, so it stays a candidate — vindicated by the outcome it predicts,
  not by a second bite).* core-go's §4.7 report read our collapsed `403 invalid_signature` as
  *"rust does not distinguish an identity mismatch from a signature failure"* — but our §4.6 step-3
  binding was there all along, just ordered after step 2 where their probe could not reach it.
  Implementing the item as written would have added a check we already had. Recomputing found the
  real gap one sentence over, which the routing did not name: §4.6's *"MUST **also** verify
  `authenticate.peer_id == hello.peer_id`"*, absent here, so the handshake could change its claimed
  identity between frames. **A red row tells you the OUTPUT is wrong; it does not tell you which
  input produced it** — read your own function before believing a report about it, and put the
  correction in the reply as a measurement rather than leaving the ledger wrong.
- **A ruling that changes a PUBLISHED DESCRIPTOR cannot be landed seat-by-seat — the first
  seat to land it goes red, and that is the check working, not a defect.** *(Candidate: bit us
  once, 2026-08-21, caught on the wire and backed out the same session.)* C-11 Corner 2 (D3)
  narrows `system/compute/concat-args.collections` from `array_of system/hash` to a scalar. We
  implemented it from the routing's §4 worklist; `cargo test`, `clippy` and `make features` were
  all green, and `validate-peer -category type_system` scored **1F** on
  `type_system_compute_concat_args_match`. The check compares our *published* descriptor against
  **the sibling's local type table** (`allLocalTypes` → `compareTypeDefsOutcome`), so a descriptor
  edit is a divergence the moment one seat makes it and until the last seat does. Two things this
  earns, and the second is the one that generalises:
  - **The grep that says "not scored" has to match the check's *construction*, not its name.**
    `grep -rn concat-args cmd/internal/validate/` returned nothing and we read that as "no check
    names this surface" — but the check name is **generated** (`"type_" + sanitizeName(def.Name) +
    "_match"`), so no literal ever appears. For a per-item check, grep the **loop that declares
    it**, not the item. This is the same "published contract is measured somewhere" entry as R-17
    above, failing from the other direction: there the ledger's adjective was wrong, here our own
    absence-proof was.
  - **DRAFT is a status, and it binds.** The proposal carrying D3 is `Status: DRAFT` targeting
    v3.27, and the standard says implement the **landed** spec, not an in-flight proposal — arch's
    own packet said *"do not implement from this packet's prose"* two sections after the worklist
    that asked for it. When a routing's worklist and its "what arch still owes" table disagree,
    the **spec's landed text wins** and the disagreement is the thing to report. Ship the
    behaviour a ruling calls existing non-conformance (Corner 1 was explicitly ungated: the
    asymmetry violates the *landed* §2.4); hold the ones that edit a declaration until the fold,
    and say so at the code with the measurement attached.
- **A cross-impl vector suite is a fixture set — re-bless at every new SHA, because "we blessed
  at N" says nothing about N+3.** *(Candidate, same session.)* We reported `352/352 LOCKED` and
  routed it as the evidence for C-6. go then seeded CV-7a/b/c (→355) and CV-8a/b/c (→358), and
  bisect at our own `145cd1c` measured **3 two-way**, not 0: `cv7c` (a real, un-caught defect —
  `concat` answered `type_mismatch` where an error *sub-collection* must short-circuit), `cv8a`,
  and `sweep/0281` — **a vector nobody named in any routing**, which the same fix closed. The
  defect was live under a green PASS for the same reason go's was: *the two readings agree
  everywhere the fixtures live.* **Enforcement:** a corpus SHA in a report is a claim with an
  expiry date. Before citing a LOCK as evidence, re-generate and re-bless at the sibling's current
  freeze; and when a bless comes back dirty, **bisect before attributing** — `git stash` →
  `peer-manager start` → emit → cross-bless is ~4 minutes and it is the difference between "this
  is pre-existing" and "I measured that this is pre-existing." Both of ours turned out to be
  pre-existing; the run is what makes that sentence worth anything.
- **A carve-out on a value rule must key on the value's CODE, never on its in-flight variant —
  and name the criterion, not the category.** *(Candidate, same session, decided as lead.)* C-11
  Corner 1 makes `map`'s output element a contained position. go carved out the three
  *evaluation-limit* codes (`budget_exhausted` / `depth_exceeded` / `cascade_limit`) so they
  propagate. The carve-out is right for the wrong-sized reason: what makes containment incoherent
  is a resource **shared across the elements** — `budget.operations` is one counter pinned at 0 by
  `saturating_sub`, so containing it fills the array at a split point decided by cost accounting
  and then reports **success** for an aborted evaluation. `depth_exceeded` does not share that
  property (`budget.depth` is restored on unwind), so it is element-wise and contains, exactly like
  `div(x, 0)`. **Named divergence from go, routed, and deliberately kept out of the frozen corpus
  at both seats.** The half that is not a judgement call: the predicate MUST read the `code`, because
  keying on `ComputeValue::Error(_)` vs the SA-1 entity form would reinstate the precise §2.4
  provenance-dependence the ruling exists to remove — with the consequence, stated rather than
  hidden, that an *authored* `compute/error{code: budget_exhausted}` also aborts a `map`. Teeth:
  `the_map_carve_out_is_shared_resource_not_limit_code`, whose two halves fail under go's wider set
  and under no carve-out at all.
- **A recovery test that only exercises the seed does not reach the loop.** *(Same session; the
  mutation caught it, review did not.)* `fold`'s accumulator is bound, not consumed, so a closure
  that ignores it recovers — and there are **two** branches that must not short-circuit: the
  `initial`, and each `fn` result threaded into the next invocation. Our first test set only
  `initial` to an error and the closure never produced one, so restoring the per-iteration
  `if acc.is_error() { return acc }` left it **green**. The discriminator has to make the *loop*
  produce the error: `fold(λ(acc, x). div(1, x), 0, [0, 1])` → `1`, where iteration 1 mints the
  error and iteration 2 ignores it. **Run the mutation per branch, not per behaviour** — "the
  feature is tested" and "this branch is tested" are different claims, and only the second one is
  what a mutation measures.
  **And the mutation itself needs scoping, because a MULTI-ROW test short-circuits at its first
  failing assertion — an older row will absorb the mutation and tell you nothing about the row you
  just added.** *(Candidate: bit us once, 2026-09-04, caught in the same minute it happened.)*
  Adding the SA-PY-35 half-open `ping` row to
  `incompatible_protocol_and_unknown_connect_op_on_both_transports`, the obvious mutation —
  exempt `ping` from `out_of_order_connect_operation_refusal` — went RED on the **pre-hello**
  `ping` row three blocks earlier and stopped. The run reddened, and it was evidence about a row
  that already existed. The scoped mutation (`fields.operation == "ping" && expected ==
  "authenticate"`) isolates the new arm and reddens exactly it. This is the sibling's
  short-circuit rule (below) turned on our own suite: **a mutation is only evidence about the
  first assertion it reaches, so mutate the narrowest thing the new row depends on and check the
  failure message names *your* row** — a green neighbour list is part of the result, not a
  formality.
  **And the other way the same test lies: a mutation WRITTEN DOWN but not RUN. A doc comment that
  says "mutation verified" is prose in exactly the way a cited control is.** *(2026-09-05, and it
  is the third instance of the entry above, so it ratifies as the enforcement rather than as a new
  rule.)* Landing the EXTENSION-TREE v4.4 `put` rows, the test's own doc comment claimed
  *"collapsing the validate branch to a bare `hash_mismatch` reddens the non-decoding row."* Run,
  it went **green** — the non-decoding row exits at `decode_entity_from_cbor` and never reaches
  `validate`, so a mutation of one 400 arm says nothing about the other. The sentence was written
  because both rows live in one `fn`, one screen apart, and *look* like one path. **Two error
  arms in one function are two code paths, and a claim about a control's reach is a claim about
  which arm the input takes — which the test name, the file, and the visual proximity all fail to
  state.** Enforcement: every *"mutation verified"* in a comment names the mutation **and the row
  it reddened**, and no such sentence is written before the failing run is in the transcript; the
  three that bite here are recorded at
  `put_error_codes_are_the_three_appendix_a_rows`, along with the fourth that deliberately does
  **not** bite, so the next reader does not re-derive its greenness as a defect. Recording the
  no-op mutation is the new half: an unreachable-by-construction arm looks identical to a
  toothless test from the outside, and only the paired containment pin
  (`validate_on_the_put_path_can_only_fail_with_hash_mismatch`) tells them apart.
  **Fourth instance, 2026-09-06, and it failed in BOTH directions inside one commit — which is
  what the two failure modes are.** (a) *Too weak.* *"Removing the non-bstr `else` reddens both
  rows"* — run, it went **green**: a later `ok_or_else` refuses the same input with the same code,
  so the two spellings are **behaviourally equivalent** and the mutation was a no-op wearing the
  shape of a defect. The biting mutation was the *combination* with a second edit. **When a
  function has two guards that can refuse the same input, mutating one proves nothing about
  either** — and if nothing reddens, the honest finding is that the new guard is defence in depth,
  not that the test is toothless. (b) *Scope-shifted.* *"Dropping the SDK's hash leaves every
  put/get test green, which is the finding"* — **true at the parent commit, false by the end of
  the same commit**, once the peer half landed and made ~12 tests red. **A mutation's result is
  scoped to the tree state at the moment you ran it**, so in a two-half flag-day change (encoder +
  decoder, writer + reader, SDK + peer) a claim measured after the first half describes a tree
  that no longer exists. Enforcement: re-run the first half's mutation once the second half lands,
  and if the answer moved, **write down both** — the change in the answer is the compensating pair
  becoming visible, and it is the most useful sentence in the commit.
- **A CROSS-SEAT drive that does not cross the seat boundary looks exactly like one that does —
  assert on a value only the FAR seat can produce, never on the status alone.** *(Candidate: bit
  us once, 2026-09-06, caught by reading an error message.)* The acceptance test for the
  0.8.2.11 SDK half was *"drive our `put` against a strict go peer: 400 before the fix, 200
  after."* Written with `PeerContext::put` against a path in the remote peer's namespace, it
  produced **exactly that pair** — and measured our own peer twice. `put` dispatches at the bare
  `system/tree` URI, which resolves to the **local** tree handler even when the resource target
  names a foreign namespace (that is the site-cache / `follow` mirror shape, and it is a local
  write); only the qualified `entity://{peer}/system/tree` form routes. Both halves of the
  before/after were locally produced, so the mutation "worked," the status codes were right, and
  the whole thing was a tautology of the kind already named above — with the twist that the
  tautology was **which peer answered**, not which function computed the expectation.
  **The tell was the 400's MESSAGE.** Ours reads *"submitted entity is not a core/entity: missing
  'content_hash' field…"*; go's reads *"entity missing required content_hash field"*. A status
  code is the one part of a refusal that every seat spells identically, which is precisely why it
  cannot witness *whose* refusal it is. **Enforcement:** any test whose name or docstring says
  *cross-impl*, *foreign*, *boundary*, or *strict peer* must assert on something the far seat
  authored — its error wording, its `peer_id`, a hash only it holds — and the run must print it.
  In this tree the discriminator is the URI helper: `execute` at a bare handler name is local,
  `entity://{pid}/…` is remote, and `grep -n 'entity://' bindings/sdk/src/sdk.rs` finds the sites
  that actually leave the process. Same family as the `is_connect_path` bite — a path helper that
  reads plausibly and routes somewhere else — pointed at a test instead of a guard.
- **A per-seat worklist reads as exhaustive PER SEAT, and the row that binds you may be filed
  under someone else's name.** *(Candidate: bit us once, 2026-09-06.)* `ROUTING-2026-09-06-b`
  splits into a `### rust` and a `### py` relay section, each two items, under a shared ruling.
  Ours did not name `unsupported_content_hash_format` — `EXTENSION-TREE` Appendix A **v4.5**'s
  fourth `put` row — because that row was item **3 of go's own worklist**, go being the seat that
  noticed it. It binds every seat that ingests a `put`, and we were answering `invalid_request`
  for it. **A named section addressed to you is a claim about what the author measured at your
  seat, not an enumeration of what the version obliges you to do** — the same grammar as the
  *"nothing you shipped moves"* and *"no action owed"* traps already recorded, one level down:
  there the reassurance was a sentence, here it is the **document's structure**, which is more
  convincing because nobody wrote it as a claim at all. **Enforcement:** when a routing carries
  per-seat sections, read the **other seats' items** and ask of each whether the rule behind it is
  seat-specific or version-wide — and read the spec diff, not the routing, for the answer
  (`git show <fold> -- specs/`). A row in a shared Appendix A table is version-wide by
  construction. Cheap tell: an item whose fix is a **code value** rather than a code path.
  **Ratified 2026-09-10, and the second shape is a DEFECT filed under another seat's name that
  is also in your tree — at a site the author could not have known you had.**
  `ROUTING-2026-09-10-e`'s §4 table gives rust *"`grantee` = the delivering engine"* and gives py
  *"stop minting `peers:["*"]` — it makes Dimension 4 vacuous."* Recomputed against our tree,
  **both** were here, split across two mint sites: `bindings/sdk::mint_delivery_grant` had the
  wrong grantee with `peers` correctly absent, and `core/peer::generate_deliver_token` had the
  right grantee with `peers: ["*"]`. Neither seat could have seen the other's half — arch read
  each tree's *one* deliver-token minter and each tree has a different number of them. The first
  shape was *"your section is not an enumeration of what binds you"*; this one is sharper,
  because the row addressed to someone else names a **rule**, and a rule is checked against your
  whole tree rather than against the site the author happened to read. Note which way the error
  runs: taking the table at face value would have left a vacuous Dimension 4 shipping behind a
  green gate and a routing reply claiming the item closed.
  **Enforcement:** for every row in a per-seat table — *including the other seats'* — extract the
  rule, then enumerate **your** constructors of the artifact it governs and answer per site
  (`grep -rn 'CapabilityToken {' --include=*.rs` for a credential; the type's constructor list is
  the region that closes). A site that is legitimately fine says so at the code with the criterion
  it was checked against, not with the shape it happens to have — `network_link::mint_deliver_token`
  is a self-grant and conformant, because for a lifecycle subscription the delivering engine IS
  the local peer, and that sentence is the difference between checked and pattern-matched.
- **A declared exclusion whose ground is "nothing installs it" is a gap wearing an exemption —
  register the surface and let the wire tell you what it was hiding.** *(Candidate: bit us once,
  2026-08-22.)* `CONFORMANCE-EXCLUSIONS.md`'s substitute entry rested on two grounds: Ruling 4
  (`claimed_source_peer_id` is dispatcher context, not a wire field — a property of the *protocol*,
  cohort-convergent, a real exclusion) and *"nothing installs the surface"* — exhaustively true, and
  **not an exclusion ground at all**. The second one is the shape our own charter already names, a
  surface present in the tree and absent from the substrate, and writing it into the exclusions doc
  is how it survived: `substitute 0P/**1S**` read as *declared* rather than as *undone*, and a skip
  counts as a failure. It was the sole reason this seat's release gate exited 1 while go's exited 0.
  **Wiring it (one `builder.handler(...)` line) turned an unmeasured surface into `5P/3F`
  immediately, and a fourth defect surfaced while fixing those three.** All four had been shipping,
  invisible, behind a fully green in-tree suite:
  - §2.3's `entry` travelled as a **`bstr`** where go (`Entry entity.Entity`) and py (a dict) both
    carry the entity as a **value**, so every cross-impl call died at the first field. Our encoder
    and our decoder agreed with each other — the same-side round-trip pitfall already stated at the
    top of this section, realized as completely as it can be, because no cross-impl caller existed
    to disagree.
  - The §7 plaintext refusal answered **400** where it is a **403** (an authorization decision about
    the scheme, not a malformed request).
  - §2.2's *"`content_url_prefix` is REQUIRED, no derivation default"* was implemented as a
    derivation — and then, after the absent case was fixed, **still failed on the empty-string
    case**, because go's `TransportEndpoint` carries no `omitempty` and "unset" arrives as
    `Some("")`. *"Absent and empty are the same fact"* is already a rule here for optional arrays;
    it binds a REQUIRED string too, from the other direction — both mean "the publisher committed
    to nothing", and refusing only `None` let the empty string fall through to the scheme gate and
    report the **wrong defect**, which is what kept the check red through a fix that looked complete
    in-tree.
  **Enforcement, two greps.** (a) Any entry in `CONFORMANCE-EXCLUSIONS.md` whose *"not drivable"*
  paragraph cites our own build rather than the protocol is a work item, not an exemption — re-read
  them at each release. (b) For every `impl Handler` in `extensions/`, grep the peer binary for its
  constructor; a handler no `cmd/` crate depends on is unreachable, and the dependency graph is the
  region that makes that enumeration exhaustive (`grep -rn <crate-name> --include=Cargo.toml .`).
  **And the corollary about citations:** our decoder cited *"D-14, §6.4 — workbench-go review"* by
  name and implemented it faithfully; the spec later pinned the opposite and said outright that an
  impl doing what D-14 asked *"is non-conformant."* **A code comment citing a proposal or a review
  item is a claim with an expiry date, and the comment will never tell you it expired** — when a
  ruling lands on a surface, grep the tree for the superseded item's identifier, not just for the
  behaviour.
- **SDK '`static` futures:** any `pub async fn(&self, ...)` on borrowed accessors
  (`IdentityOps`/`ComputeOps`/…) plumbed through a `BoxFuture<'static>` consumer trait must
  instead return `impl Future + Send + 'static` (drop `Send` on wasm32): capture Arcs/owned
  state up front, run in `async move`. `PeerContext` is not `Clone`. Retrofitting is a large
  refactor — reach for this shape from the start.

## Project structure

The strict crate DAG (a crate may import only crates above it; never introduce cycles)
is documented in `docs/ARCHITECTURE.md`. Two invariants that govern where changes may
land: only four extension-to-extension substrate edges are permitted (`quorum→attestation`,
`role→attestation`, `identity→attestation+quorum`, `relay→route`) — no others; and entity
storage (bootstrap, handler emit, tree put) goes through the single `emit()` path, never a
direct `store.put()`. Other key facts:

- `entity-core` is the facade crate re-exporting `core/*` as namespaced modules.
- `bindings/wasm-worker-*` crates are **wasm32-only** (`#![cfg(target_arch = "wasm32")]`).
- Naming: the L3 frontend team is **"Dom"**, not "EGUI".

## Boundaries — do NOT modify

- **No protocol design.** No new primitives, wire messages, or handler operations not in the
  spec; no pluggable validator registries / new hook types / new context fields to paper over
  a gap. Log ambiguities to `docs/SPEC-AMBIGUITIES.md` (exact passage + ambiguity + interim
  choice) and route upstream — don't invent a mechanism.
- `../entity-core-rs/` (old Rust impl) — **reference only**; do not replicate its patterns.
  `../entity-core-go/` and `../entity-core-py/` — interop context only; do not copy structure.
- **wasm-worker-\* crates must not affect native bindings.** Godot/FFI/CLI stay unaffected by
  worker changes (the crates are wasm32-only at lib root).
- **Private keys** belong only in the per-peer keystore (PEM on disk / OPFS / app config) or
  in a live in-memory `Keypair`. Never into bundles/exports/"portable" structs, capability or
  delegation chains, wire messages, logs, or anything `Serialize`/`Debug`-derived. When
  porting a Go field, confirm the Rust shape actually needs it (Bundle v1 shipped a vestigial
  `keypair_pem` — Go's ceremony-rerun shape needed it, Rust's entity-shape didn't).

## Protocol / interop invariants agents get wrong

Cross-impl wire fidelity. Same-side round-trip tests pass with the **wrong** shape too
(encoder + decoder agree); only a cross-impl validator catches these. Run
`validate-peer -category <touched>` on any wire-shape change.

- **Byte fidelity:** entity `data` must be preserved as-is — never decode+re-encode.
- **ECF is deterministic:** sorted keys, minimal integers, definite lengths (RFC 8949 §4.2).
- **Hash input is only `{type, data}`** — never the `content_hash` itself.
- **A routed pointer is a starting point, not the boundary — derive the boundary from the
  normative sentence, then sweep it.** *(Ratified: bit us twice in two shapes, same day.)*
  A routing note names the site somebody **measured** or the line they **read**; the spec
  names the sites that **bind**. Those are not the same list, and stopping at the pointer
  closes the routing item with the defect still in the tree, behind a green gate. Before
  implementing any ruling, write down the boundary in the spec's own terms — then find every
  place in *our* code that falls inside it. The two that earned this:
  - **Sibling *sites*.** §2.4's code-only `compute/error` rule names the §7.2 `result_path`
    write and the SA-9 `store` crossing in one sentence. Arch routed only `store`;
    `result_path` was broken identically (minted form handled, SA-1 value form passed
    through verbatim). `materialize_error_value` now serves both — `d149915`.
  - **Sibling *arms*.** ROUTING-2026-08-16-i routed `apply.rs:187`, the builtin intercept.
    That same function had a second arm — the unrecognized-bare-name fall-through — which
    reached external dispatch with `capability`/`resource` still attached, where they *would*
    be honored. §2.1 keys on the **path**, not on the name resolving, so both arms bind —
    `747b41a`.
  - **Sibling *directions*.** A rule about what may appear on the wire binds the **encoder,
    the decoder, and every construction that feeds them** — and the lenient direction is the
    fail-open one. CAP-6 ("an unrepresentable temporal term MUST be absent, never wrapped or
    saturated") was routed as a mint-side clamp; the same field was also encoded through
    `x as i64` (negative above `i64::MAX` — and ROLE §5.3's `saturating_add` produces exactly
    that input) and decoded through `try_from(...).ok()`, which read a value **go refuses**
    as *absent*, i.e. as a cap that never expires. Fixing only the mint leaves us honoring
    the tokens the cohort's unfixed peers already emitted — `entity_ecf::uinteger` +
    `decode_temporal_field`.
  - **Sibling *derivations*.** A rule about how a value is *derived* binds every site that
    derives it, and the sites are found by the argument, not by the grep. §5.2's
    `target_peer = extract_peer(execute.data.uri, local)` was routed as one conformance FAIL
    at `connection.rs`; compute's `compute/apply` F2 dual-check computed the same argument
    the same wrong way, from an *expression-supplied* path, and it is the ceiling that check
    exists to enforce. Of 15 `check_permission` callers, 13 build a local-qualified pattern
    themselves and are correct — the two that take a caller-influenced path are the two that
    bind. Sweep by *"where does this argument come from"*, not by the callee's name —
    `80d9f67`.
  - **Sibling *producers*.** A rule about what a value may be binds every site that
    *mints* the artifact carrying it, and the routing names the ones somebody exercised.
    §6a.9.1's ttl cascade and ceiling were routed as `register-request` + `renew-request`;
    `approve-request` is a **third** producer of peer-issued bindings, minting from a body
    queued days earlier, and it had neither. A manual-mode registry could therefore sign
    above a ceiling the operator had already lowered. Found by asking *"who else calls
    `issue_binding`"* rather than by following the two op names in the packet — the boundary
    is the mint path, not the routed operations (`c06a6ab`).
  - **Sibling *halves of one index*.** When a lookup changes shape, the **write** that feeds
    it is inside the boundary. §6a.6's by-target revocation index was routed as a read-side
    scan-vs-lookup finding; the fetch path already *read* by-target remotely but **cached
    under the own-hash key**, because the local side scanned. Landing only the lookup would
    have made every fetched revocation invisible — a silent fail-**open** on the check that
    excludes a compromised binding, strictly worse than the scan it "fixed". A read-shape
    change with no corresponding write-shape audit is half a change — `a23bb27`.
    **And the inverse, from the same index one packet later: a routed pointer can name the
    wrong *layer*, so check that the sentence cited governs the site cited.** Ledger item R-4
    quoted §6a.6 (*"an O(1) index lookup, not a scan"*) at `resolver::is_revoked`. §6a.6's
    argument is a **`registry`** and it is called from **§6a.4**, the peer-issued algorithm —
    the reader `a23bb27` already converted. The site R-4 named implements **§3.1**, a different
    sentence that constrains no storage path, and conformance drives it as a scan. Implementing
    the citation made a green peer red. **A section number in a routing is a claim about which
    rule binds your code, not a fact** — read the sentence, check its arguments and its caller,
    and answer with the measurement when they do not line up (here: core-go scans at the same
    layer, so the divergence the item describes does not exist between the seats) — `cf570b2`.
  - **Sibling *fields named by one sentence*.** §4.4.17 V6 says *"every `exclude` /
    `exclude_types` pattern"* and §2.4 gives both the same matcher. The routing, and every
    example anyone quotes, is about `exclude` — so `exclude_types` sat there as an **exact
    string compare**, silently ignoring every patterned entry a peer had stored, and it is
    the field where the four forms are *most* visible (`app/*`, `*-draft`). Same packet, same
    shape one layer out: the SDK built `fetch`'s params through the **log** builder, so a
    rename to `log`'s field would have left `fetch` emitting a type that no longer declares
    it. When a rule's sentence names two fields, grep for the second one — it is the one with
    no example — `59e6f55`.
  - **Sibling *methods of one trait* — a DECORATOR inherits every default it does not name,
    and a defaulted method that is documented as unsafe-for-real-use is a trapdoor under
    every wrapper in the stack.** `LocationIndex` gives `compare_and_swap` /
    `compare_and_remove` / `compare_and_create` default bodies that are a non-atomic
    `get`+`set`, and says so at the definition: *"Real backends MUST override this with an
    atomic implementation."* Every **backend** did (`Memory`, `Sqlite`, `Opfs`, `Idb`). Both
    **decorators** — `IndexingLocationIndex` (query) and `JournaledLocationIndex` (persist) —
    forwarded `get`/`set`/`remove`/`list`, named none of the CAS trio, and so silently
    supplied the broken default *in front of* a correct backend. `IndexingLocationIndex` sits
    unconditionally between the base index and `NotifyingLocationIndex` whenever `query` is
    on (the default), so `MemoryLocationIndex`'s atomic CAS was reachable **in unit tests and
    unreachable in the peer**: every CAS the shipping peer performed was a read followed by
    an unconditional write, §3.9's `expected_hash` on `system/tree:put` included. The
    observable was two root-tracker updates logging a successful CAS from the *same* expected
    root and a write leaving the tracked trie for good (`7776675`). Note the direction: the
    wrapper did not *break* a method, it **declined to mention one**, so there is no diff to
    review and no compiler error — `impl Trait for Wrapper` is the one construct where doing
    nothing is an active choice.
    **Enforcement, and the test shape is the load-bearing half.** (a) For any trait with
    defaulted methods where a default is documented as degraded, enumerate `impl <Trait> for`
    across the tree and check each **wrapper** forwards the whole contract, not just the
    methods it had a reason to touch — the region that closes is the `impl` list, not a grep
    for the method name (which finds the backends and misses exactly the wrappers that are
    the bug). (b) **Assert which method the inner layer SAW, never the value it returned.** A
    decorator on the non-atomic default returns the *correct answer* single-threaded — it
    reads, compares, writes — so no value-based assertion can separate the two
    implementations, and a suite full of them stays green through the whole defect. The
    discriminator is a counting spy on the backend
    (`cas_is_forwarded_to_the_backend_not_synthesized_from_get_and_set`, `extensions/query`):
    forwarded → the backend's `compare_and_swap` is entered; inherited → the backend sees
    `get`+`set` and zero CAS calls. Its neighbour `a_losing_cas_does_not_disturb_the_indexes`
    is deliberately kept **green under the same mutation** as the standing proof that the
    value assertion cannot see this class.
  - **Sibling *rulings in one fold* — when a routing relays a spec VERSION, the boundary is
    that version's diff, not the relay's worklist.** *(**Ratified 2026-09-04**: bit us twice,
    the second time through a cross-impl validation report rather than a fold relay — see the
    second half below.)* Arch's relay named one item (FM-2e, the
    `protocols` absent/empty arm) and added *"rows 1 and 10 as you built them are conformant;
    **nothing you shipped moves**."* Both sentences were true and neither is a statement about
    a row we had **never shipped**. `0.8.2.4` folded six normative changes; reading the fold
    commit's own diff against our tree found that the same edit splitting row 10 had also
    moved the *state* half's status **400 → 409** and given it `connection_sequence_error` — a
    §9.1 conformance line we answered `400 handshake_failed` pre-hello and `400
    authentication_failed` at the second frame, **neither of which is a pair in any row of
    §4.7**. A relay is written from the seat that landed the fold, so it names the items that
    seat had open; a fold is a diff against the *spec*, and every seat's delta against it is
    its own. **The trap is specific to the reassuring sentence:** "nothing you shipped moves"
    scopes to what you shipped, and a missing row is not in that set — the more confidently a
    relay clears you, the more precisely it is talking about the code you have.
    **Enforcement:** when a routing cites a version bump, `git show <fold-commit> -- specs/…`
    in `entity-core-protocol` and enumerate the normative changes yourself before scoping the
    work — the fold commit's own message lists them, and the §9.1 conformance-profile block is
    where a new obligation gets a line a check can read. Then diff *that* list against your
    tree, and report the items the relay did not name rather than closing the one it did.
    Same shape as the *"a routed work item is a delta against the sibling's tree"* rule below,
    one level up: there the routing under-described the work, here it under-described the
    ruling.
    **Second shape, 2026-09-04, and it is what ratifies this: the clearing sentence came from a
    CROSS-IMPL REPORT, and the item it did not name was in the SAME proposal one section over.**
    core-go's type-op 404 report is addressed to us as *"informational — the ops are a
    §12.2/§12.3 MAY; if you do not build them the check SKIPs cleanly, **no action owed**"*, and
    every word is true of `converge`/`adopt`/`reconcile`, which we do not build. But
    `PROPOSAL-TYPE-OPERATION-ERROR-TAXONOMY` §6a.3's closing sentence — *"rust's row-4 `404
    not_found` narrows to `type_not_found`"* — is about `compare`/`compatible`, the SHOULD ops
    all three seats **have** built. A sibling gates what they had a divergence on; the ruling
    binds whatever it binds. **The tell is the same reassuring grammar as the fold relay, so
    treat "no action owed" exactly like "nothing you shipped moves": it is a claim about the
    surface the author measured, and it is at its most confident precisely where its scope is
    narrowest.** And the boundary here is cheaper to enumerate than a fold's — the proposal is
    one document: read the ruling itself before accepting a report's summary of it, and grep it
    for your own seat's name (`grep -n -i rust <proposal>`), which returns the sentences written
    *about* you rather than the ones the sender happened to gate. Landed as `29a6f5a`, and it was
    hiding a second defect (a `404` answering an encode failure) that no report would ever have
    named because no seat can see it from outside.
  - **Sibling *inputs* reaching one call site — a MUST NOT on a CODE binds everywhere that
    code is written, and the routing will scope it to the input somebody measured.**
    *(Candidate: bit us once, 2026-09-02, caught before reporting the item closed.)* `0.8.2.5`
    ruled CE-1 and, in the same note, said flatly *"Implementations MUST NOT emit
    `connection_required` or `handshake_failed`"* — with the ground *"both are minted codes in
    no spec code set"*, which is a property of the code wherever it appears, and the precedent
    `invalid_signature`, a spelling §4.7 retired everywhere rather than at one site. The relay
    routed only CE-1's input. But `handshake_failed` was a **call-site default**, and the input
    the relay named was not the only one arriving there: a `hello` whose params are not a hello
    reached the same two defaults and had nothing to do with CE-1. Fixing the routed input alone
    leaves a MUST NOT violation behind a green gate. **The tell is grammatical**: read whether
    the MUST NOT's object is the *input* ("this frame is refused X") or the *token* ("MUST NOT
    emit X"). The second one's boundary is `grep -rn '"<code>"'`, and it is the whole tree.
    **And the sweep will cost you a control, which is the second half of this entry.** Rows 5+6
    of `prehello_authenticate_is_invalid_nonce_on_both_transports` existed to pin that residual
    to its private code, so relabelling the catch-all went red. After the sweep the catch-all and
    §4.7 row 10 share `invalid_request` **because the ruling says they are the same class** — the
    property is gone by ruling, not by oversight, and no rewrite brings it back. That is the
    inverse of the "a fix can retire a neighbouring control" entry below: there a re-route moved
    an input off a shared fallback, here a ruling merged the fallback's code with a coded row's.
    Same remedy: say at the test which property died and assert what still discriminates (here
    the pair against the three coded pairs around it, plus a `!handshake_failed` term that is
    now the only assertion in the tree that reddens if either default is reverted).
  Also check every **form** the value arrives in: a kind-based predicate (`is_error`) makes
  the enum variant and the entity variant one fact, so a site fixed for one is not fixed.
  And when a swept site turns out to be **fine**, prove it and say so at the code rather than
  "fixing" it silently — three `n as u64` casts read as truncations and are not, because
  `ciborium::value::Integer` is bounded to CBOR's integer range. An unproven negative in a
  sweep is how a no-op change gets reported as a fix.
  **Enforcement:** each swept site owes a test that is verified to fail against the prior
  behaviour — run the mutation, don't assume the assertion bites. For a wire-shape change,
  the cross-impl half is `validate-peer -category <touched>` against a live peer, and check
  the **check's own message**, not the summary line: go's CAP-6 strong probe is conditional,
  so a skipped probe and a passed one both read as `PASS` in the table.
- **Where our ordering deliberately departs from §4.1 pseudocode, say so at the code and
  name the filed issue.** Q23's rejection is structural — before args, `resource` or
  `capability` are resolved — while the pseudocode places it *after* resource evaluation
  (which would return the resource's error instead of `invalid_expression`). Go, rust and py
  all reject early; the ordering is filed as go spec-issue `2026-08-16-d`. §8.3 says
  implementations follow the pseudocode, so an undocumented departure reads as a bug and
  invites a "fix" that would diverge us from the other two seats to match text under
  correction. Gate the ordering with a test that can tell the two apart —
  `test_builtin_apply_rejects_capability_or_resource` uses unresolvable hashes, so early
  rejection yields `invalid_expression` and late would yield `not_found`.
- **`system/hash` is always a 33-byte CBOR bstr** (`algorithm || digest`, 0x00 + 32-byte
  digest) — as a single field, array element, or map key. NOT a flat `{format_code, digest}`
  record and NOT a CBOR map. (§4.5 bstr-extension overrides §2.8's named-type→record rule.)
- **Typed-struct fields are bare CBOR maps**, not entity wrappers. Only fields typed
  `core/entity` (`result`, `params`) get the `{type, data, content_hash}` wrapper; fields
  typed as a specific struct (`deliver_to`, `bounds`, `durability`/`durability_request`) are
  bare maps. Reference: `core/peer/src/durability.rs::to_cbor` (encoder),
  `connection.rs::extract_deliver_to` (parser).
- **Optional fields SHOULD be absent** (key not present), not null (null is valid). For an
  optional *array*, absent and empty are the same fact, so **absent is the encoding** — emit
  no key rather than `[]`, decode absent to an empty collection, and model it as a plain
  `Vec` (an `Option<Vec>` invents a third state the wire cannot carry). Reference:
  `advertisement_to_entity` / `advertisement_from_params` (`extensions/signaling/src/data.rs`),
  gated by `a_node_serving_no_reflection_omits_the_key_entirely` and the Go-pinned vector
  `go_encoded_advertise_result_decodes_here_byte_for_byte`.
- **Signature signer field = `system/hash`** (content hash of the identity entity), not a
  `peer_id` string.
- **Capability `delegation_caveats` = flat struct**, not an array of objects.
- **Worker peer-scoping:** every peer-targeted `Request` variant MUST carry an explicit
  `peer_id: String` — never let "defaults to primary" be silent (see the v6 Subscribe fix).
  New fields on existing variants use `#[serde(default)]`; bump `PROTOCOL_VERSION` on any
  wire-shape change.
