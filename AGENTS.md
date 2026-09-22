@AGENTS-STANDARD.md

# entity-core-rust

**`AGENTS-STANDARD.md` is imported above and is always loaded with this file** — it
holds the ecosystem-wide conventions and wins on those; this file wins on
entity-core-rust specifics. `METHODOLOGY.md` sits beside them, carried but **not**
loaded: open it by trigger (below). `CLAUDE.md` is a shim to this file and nothing
else.

⚠ **Our copy of the standard is behind the 2026-09 doc/memory/routing standard** — the
outbox, watermark and memory rules below are written here so they bind in the meantime,
and they come out when the re-synced overlay carries them. **Do not re-sync the overlay
file unilaterally**: it is byte-identical fleet-wide and owned at the release boundary.
A repo **MAY** edit it locally when it judges a change justified — the next publish
reconciles, adopting the edit for everyone or dropping it with a reason — but that is a
deliberate act, not tidying.

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

## Our addressable name, and where packets go

**This repo's addressable name is `entity-core-rust`** — its directory name. That is
what other seats write in a `To:`/`cc:` line and what we answer to; it is stated here
because two seats have inferred a third repo's name differently.

Packets we send live in **`docs/outbox/`**, one directory, nothing else in it;
acknowledged ones move to `docs/archive/outbox/`. **Neither is ever declared in
`CANONICAL-DOCS.toml`** — routing is internal, and publishing the corpus is the
expensive mistake.

Every packet opens with an addressee block, each field on its own line, **before**
the prose title does any addressing:

```
**To:** `entity-system-architecture`
**From:** `entity-core-rust`
**cc:** `entity-core-go`, `entity-core-py`
**Re:** <full stem of what this answers — never an abbreviated form>
**Tip:** `dev` @ <sha>
```

`To:`, `From:` and `Tip:` are required — **a packet whose claim cannot be re-derived
is an opinion.** `To:` names **repositories**, never people; a brace list
(`entity-core-{go,py}`) is fine. Title the packet with the **finding**, not a label.

**Delivery in this polyrepo is: you commit a document to your own tree and the other
seat reads it.** There is no queue and no notification, so a packet nobody can
*enumerate* is a packet nobody receives. Naming recipients in the title line — which
is what this repo did through `ROUTING-2026-09-15-d` — parses as **`unaddressed`**,
and arch's `spec inbound` then files it as **UNKNOWN rather than "not ours"**: our
four `.26` asks reached the architecture seat only because `entity-core-go` relayed
them.

### Receiving — the watermark

One line in each `docs/status/TRACKER-<counterpart>.md`:

```markdown
_Last read `<counterpart>`'s outbox through 2026-09-16, at `dev` @ `9f1c3ab`._
```

**Fetch their repo first**, list their `docs/outbox/` for a filename dated after the
watermark, read the header, act or ignore, then move the line and record the tip you
scanned at. Two things keep it honest and skipping either turns it into a control
that lies:

- **Go by the date in the filename, never file mtime.** A checkout you have not
  pulled lists nothing new and looks exactly like a clean scan — and then the
  watermark advances **past** packets nobody saw. That miss is permanent, not late.
- **If you cannot reach a counterpart's tree, write that in the tracker.** *Could not
  look* is not *nothing to see*, and an omitted row reads as clean.

Every packet addressed to us gets a row **including the ones we decline** — from the
sender's side a refusal and a silence are indistinguishable.

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

## Memory — where the rest of what we know lives

This file answers *how do I work here today*. **`docs/agents/memory/` answers *what
will bite me when I hit it*** — start at
[`docs/agents/memory/INDEX.md`](docs/agents/memory/INDEX.md), which indexes the
entries **by symptom**, because that is what a reader arrives with.

| home | answers | lifecycle |
|---|---|---|
| `AGENTS.md` | how do I work here today? | living, **bounded** (≤ 30 KiB), edited in place |
| `docs/agents/memory/` | what would I otherwise rediscover the hard way? | living, **indexed** |
| `docs/status/` | where are we this week? | dated, written once, ages out |

**One question decides where a finding goes:** *would a competent newcomer need this
**before** their first change, or only when they hit the thing it describes?* The
second one is memory, not this file.

⭐ **And an entry that could become a check SHOULD become one — and is then deleted
from memory.** Memory is where a finding waits *while it is still only prose*; it is
not where findings retire. The ratchet still binds: every audit ends by syncing what
it taught into this file **or** into a memory file, same session. **If it didn't
land, it didn't land.**

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

**The gate is four commands, not three: `make test` · `make lint` · `make godot`
· `make wasm`** (`make check` = the first three; `make features` on top whenever a change
adds or moves a `cfg` guard). Two of them exist because two members are deliberately out
of `default-members`, and each of those exclusions names its lane at the exclusion.

**Where the gate does not reach is written down, not remembered**:
`docs/agents/memory/BUILD-AND-RUST.md` carries the cfg matrix (a `#[cfg(feature)]`
symbol can remove a security guard, and `make features` never compiles the *tests*)
and the package set (`default-members` **is** the coverage boundary — an excluded
member owes a comment naming the lane that covers it). Read it before you add a
`cfg` guard, a crate, or a `make` verb.

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
- **Hot paths, concurrency, and shared state** have their own rules and they are
  enforcement-bearing, not advice: `docs/agents/memory/CONCURRENCY-AND-STATE.md`
  (`SyncTreeHook` config caching, read-modify-write under a cascade, a MUST-write
  owing a collector).
- **Before writing an authorization check, a test you intend to cite as evidence, or
  a reply to a routed item**, open the matching memory file — the failure modes there
  are ours, measured, with the grep and the gate test named:
  `AUTHORIZATION-AND-CAPABILITY.md` · `TESTING-AND-EVIDENCE.md` ·
  `CONFORMANCE-GATES.md` · `SPEC-RULINGS-AND-ROUTING.md` · `WIRE-AND-ENCODING.md` ·
  `PATHS-AND-VALIDATION.md`.

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
- **A routed pointer is a starting point, not the boundary — derive the boundary from
  the normative sentence, then sweep it.** *(Ratified.)* The worked instances — sibling
  sites, arms, directions, derivations, producers, index halves, fields, trait methods,
  rulings in one fold, inputs at one call site — are in
  `docs/agents/memory/SPEC-RULINGS-AND-ROUTING.md`, along with our deliberate,
  filed departure from §4.1's pseudocode ordering. **Read it before implementing a
  routed item**; closing the item at the pointer leaves the defect in the tree.
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
