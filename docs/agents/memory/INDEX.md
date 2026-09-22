# Agent memory — index

What this repo would otherwise rediscover the hard way. **`AGENTS.md` answers *how
do I work here today*; this directory answers *what will bite me when I hit it*.**
Nothing here is needed before your first change — open a file when its symptom is
the one in front of you.

Every entry states the **mechanism**, an **enforcement point** (a grep, a gate
test, a lint rule — a rule with none is theatre), and its **provenance**: the
promotion ladder is earned on our own bugs, so entries carry the commit or the
date that earned them. That is provenance, not session narration.

> ⭐ **An entry that could become a check SHOULD become one — and then it is
> deleted from here.** Memory is where a finding waits *while it is still only
> prose*. The maintenance pass is not "trim the file"; it is, per entry: *could a
> test, a lint rule, a build assertion or a gate make this impossible instead of
> merely documented?*

## The files

| file | answers |
|---|---|
| [`BUILD-AND-RUST.md`](BUILD-AND-RUST.md) | Which `make` verb sees what; where the cfg matrix and the package set stop; two Rust shapes that are expensive to retrofit |
| [`CONCURRENCY-AND-STATE.md`](CONCURRENCY-AND-STATE.md) | Read-modify-write under a cascade; hot-path config caching; collectors for spec'd writes; residue a previous attempt left |
| [`AUTHORIZATION-AND-CAPABILITY.md`](AUTHORIZATION-AND-CAPABILITY.md) | §5.2/§6.3: whose authority is spent, which argument decides it, what a relocated check starts reading |
| [`PATHS-AND-VALIDATION.md`](PATHS-AND-VALIDATION.md) | One path rule implemented by two helpers; what a boundary may do with a malformed path; fixture peer ids |
| [`WIRE-AND-ENCODING.md`](WIRE-AND-ENCODING.md) | Byte fidelity, ECF, closed grammars, the `(status, field, spelling)` of an error code, the sender half of a rule |
| [`TESTING-AND-EVIDENCE.md`](TESTING-AND-EVIDENCE.md) | Whether a test measures anything: controls, mutations actually run, fixtures the codec cannot author, the boundary a row crosses |
| [`CONFORMANCE-GATES.md`](CONFORMANCE-GATES.md) | Reading a cross-impl run — what a green category, a WARN, a SKIP, a `[self]` row and a FAIL detail line are each evidence of |
| [`SPEC-RULINGS-AND-ROUTING.md`](SPEC-RULINGS-AND-ROUTING.md) | Reading a ruling, a fold, a routed item; deriving the boundary from the normative sentence; answering with a measurement |

## By symptom — what you arrived with

| you are seeing | start at |
|---|---|
| "the suite is green and the wire is not" | `TESTING-AND-EVIDENCE.md`, then `CONFORMANCE-GATES.md` |
| "a sibling's check scores us FAIL" | `CONFORMANCE-GATES.md` → a failing check is a hypothesis, not a verdict |
| "a sibling's check scores us PASS and I want to cite it" | `CONFORMANCE-GATES.md` → a green category is not evidence about a surface it does not check |
| "a routing/ruling landed and I am scoping the work" | `SPEC-RULINGS-AND-ROUTING.md` → the boundary is the normative sentence, not the routed pointer |
| "the packet says nothing I shipped moves" | `SPEC-RULINGS-AND-ROUTING.md` → a delta is against the *sibling's* tree; a withdrawal redirects the input somewhere |
| a 403 on a request that should be authorized | `AUTHORIZATION-AND-CAPABILITY.md` → probes that differ from the write; the propagated caller capability is attribution |
| a 200/disclosure on a request that should be refused | `AUTHORIZATION-AND-CAPABILITY.md` → the authorizer's subject vs the handler's derived set; two authorities that agree on every row |
| an enumerating handler (`location_index.list`) with no per-entry filter | `AUTHORIZATION-AND-CAPABILITY.md` |
| a caller that hangs, or a frame dropped with no answer | `WIRE-AND-ENCODING.md` → a refusal upstream of the response answers nobody |
| an error `code` that a conformant reader cannot see | `WIRE-AND-ENCODING.md` → a code is `(status, field, spelling)`, and the failure named decides the slot |
| a merge/put that returns `200` over bindings resolving to nothing | `WIRE-AND-ENCODING.md` → byte fidelity the type cannot express |
| a panic or `assert!` reachable from caller input | `PATHS-AND-VALIDATION.md` |
| twenty fixtures suddenly refused after a validator change | `PATHS-AND-VALIDATION.md` |
| a race that the in-process load test cannot reproduce | `CONCURRENCY-AND-STATE.md` → forced interleave, not `-race` |
| a retry, reconnect or re-negotiation that works once and then never | `CONCURRENCY-AND-STATE.md` → residue is an input |
| a 100×+ slowdown on put | `CONCURRENCY-AND-STATE.md` → hot paths |
| green `make test` + green `make clippy` over a defect | `BUILD-AND-RUST.md` → the cfg matrix and the package set |
| `Finished … in 0.0Ns` with no `Compiling` line after a mutation | `BUILD-AND-RUST.md` → the mtime trap |
| a `Send`/lifetime wall in the SDK accessors | `BUILD-AND-RUST.md` → `'static` futures |

## Adding to this directory

- **One file per part of the system.** Never `MISC`, `NOTES`, `TIPS`, `GOTCHAS` —
  a file named for a category of feeling accepts anything and becomes the next
  catch-all.
- **Supersede, do not append.** Git holds the history; an entry that has been
  overtaken is edited, not annotated.
- Point at code — `file:line`, a symbol, a test name. Never paste a secret or a
  matched scan finding: name the `file:line` and describe the shape.
- **Both directions have to agree**: a file here is listed above, and everything
  listed above exists. Every file is declared in `CANONICAL-DOCS.toml`.
