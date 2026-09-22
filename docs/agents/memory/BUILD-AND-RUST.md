# Build, feature gates, and Rust idioms

> How the gate is scoped and where it does not reach: the cfg matrix, the package set, the rebuild traps, and the two Rust shapes that are expensive to retrofit.

Working memory for `entity-core-rust`, indexed from
[`INDEX.md`](INDEX.md). Entries are **findable by symptom** — the bolded lead
sentence is the shape you arrive with. Each carries its mechanism, its
enforcement point, and its provenance (the promotion ladder needs the source
commit; that is provenance, not session narration).

**An entry that could become a check SHOULD become one — and is then deleted
from here.** Memory is where a finding waits while it is still only prose.

## The cfg matrix — a gated symbol on both sides of a guard

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

## The package set — `default-members` IS the coverage boundary


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

## Rebuild and mutation hygiene

- **⚠ A restore that preserves the backup's mtime makes `cargo` skip the rebuild, and the test you
  then run is about the PREVIOUS binary.** Cost ~10 minutes here chasing a "failure" that was a
  reverted mutation still linked in. `shutil.move`/`cp -p` back over a source file is the trap.
  `touch` every file you restored before re-running, and treat a `Finished … in 0.0Ns` with no
  `Compiling` line as the tell — it is the in-tree twin of the charter's *"check the build line or
  you have mutated a binary nobody re-made."*

## SDK `'static` futures

- **SDK '`static` futures:** any `pub async fn(&self, ...)` on borrowed accessors
  (`IdentityOps`/`ComputeOps`/…) plumbed through a `BoxFuture<'static>` consumer trait must
  instead return `impl Future + Send + 'static` (drop `Send` on wasm32): capture Arcs/owned
  state up front, run in `async move`. `PeerContext` is not `Clone`. Retrofitting is a large
  refactor — reach for this shape from the start.
