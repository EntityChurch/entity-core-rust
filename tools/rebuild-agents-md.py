#!/usr/bin/env python3
"""One-shot companion to split-agents-memory.py: rebuild AGENTS.md from the
ranges that STAY, so every kept paragraph is byte-identical to the parent
commit and the diff is provably a move plus the new connective sections.

Usage: python3 tools/rebuild-agents-md.py <AGENTS.md-at-parent-commit> > AGENTS.md
"""
import sys
import pathlib

lines = pathlib.Path(sys.argv[1]).read_text().splitlines(keepends=True)


def keep(start, end):
    return "".join(lines[start - 1:end])


ADDRESSABLE = """## Our addressable name, and where packets go

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
"""

MEMORY = """## Memory — where the rest of what we know lives

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
"""

BUILD_POINTER = """**Where the gate does not reach is written down, not remembered**:
`docs/agents/memory/BUILD-AND-RUST.md` carries the cfg matrix (a `#[cfg(feature)]`
symbol can remove a security guard, and `make features` never compiles the *tests*)
and the package set (`default-members` **is** the coverage boundary — an excluded
member owes a comment naming the lane that covers it). Read it before you add a
`cfg` guard, a crate, or a `make` verb.
"""

CODE_STYLE_POINTER = """- **Hot paths, concurrency, and shared state** have their own rules and they are
  enforcement-bearing, not advice: `docs/agents/memory/CONCURRENCY-AND-STATE.md`
  (`SyncTreeHook` config caching, read-modify-write under a cascade, a MUST-write
  owing a collector).
- **Before writing an authorization check, a test you intend to cite as evidence, or
  a reply to a routed item**, open the matching memory file — the failure modes there
  are ours, measured, with the grep and the gate test named:
  `AUTHORIZATION-AND-CAPABILITY.md` · `TESTING-AND-EVIDENCE.md` ·
  `CONFORMANCE-GATES.md` · `SPEC-RULINGS-AND-ROUTING.md` · `WIRE-AND-ENCODING.md` ·
  `PATHS-AND-VALIDATION.md`.
"""

WIRE_POINTER = """- **A routed pointer is a starting point, not the boundary — derive the boundary from
  the normative sentence, then sweep it.** *(Ratified.)* The worked instances — sibling
  sites, arms, directions, derivations, producers, index halves, fields, trait methods,
  rulings in one fold, inputs at one call site — are in
  `docs/agents/memory/SPEC-RULINGS-AND-ROUTING.md`, along with our deliberate,
  filed departure from §4.1's pseudocode ordering. **Read it before implementing a
  routed item**; closing the item at the pointer leaves the defect in the tree.
"""

HEAD = """@AGENTS-STANDARD.md

# entity-core-rust

**`AGENTS-STANDARD.md` is imported above and is always loaded with this file** — it
holds the ecosystem-wide conventions and wins on those; this file wins on
entity-core-rust specifics. `METHODOLOGY.md` sits beside them, carried but **not**
loaded: open it by trigger (below). `CLAUDE.md` is a shim to this file and nothing
else.
"""

out = []
out.append(HEAD)
out.append(keep(5, 27))                 # overview, committing & pushing
out.append("\n" + ADDRESSABLE)
out.append("\n" + keep(57, 84))         # how we work here — tier CORE
out.append("\n" + MEMORY)
out.append("\n" + keep(86, 110))        # setup/environment + the make verbs
out.append(keep(175, 179))              # the four-command gate
out.append("\n" + BUILD_POINTER)
out.append("\n" + keep(180, 204))       # SELinux, wasm lane
out.append("\n" + keep(206, 213))       # code style — the short rules
out.append(CODE_STYLE_POINTER)
out.append("\n" + keep(2228, 2265))     # project structure, boundaries, interop intro
out.append(WIRE_POINTER)
out.append(keep(2471, 2492))            # the wire shapes agents get wrong

sys.stdout.write("".join(out))
