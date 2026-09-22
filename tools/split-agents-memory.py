#!/usr/bin/env python3
"""One-shot: slice AGENTS.md's catch-all sections into docs/agents/memory/.

Content is MOVED, never rewritten — every slice is copied verbatim from the
source line range. The only new text is each file's header and the sub-topic
headings that group the slices. Run once; kept in-tree so the split is
reproducible/auditable against the parent commit.

Usage: python3 tools/split-agents-memory.py <AGENTS.md-at-parent-commit>
"""
import sys
import pathlib

SRC = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "AGENTS.md")
OUT = pathlib.Path("docs/agents/memory")

# filename -> (title, purpose, [(sub-heading, [(start, end), ...]), ...])
# Line numbers are 1-based inclusive against the source file.
PLAN = {
    "BUILD-AND-RUST.md": (
        "Build, feature gates, and Rust idioms",
        "How the gate is scoped and where it does not reach: the cfg matrix, the "
        "package set, the rebuild traps, and the two Rust shapes that are expensive "
        "to retrofit.",
        [
            ("The cfg matrix — a gated symbol on both sides of a guard", [(111, 143)]),
            ("The package set — `default-members` IS the coverage boundary", [(144, 174)]),
            ("Rebuild and mutation hygiene", [(2216, 2221)]),
            ("SDK `'static` futures", [(2222, 2227)]),
        ],
    ),
    "CONCURRENCY-AND-STATE.md": (
        "Concurrency, shared state, and residue",
        "Read-modify-write on state a cascade can re-enter, hot-path caching, "
        "collectors for spec'd writes, and what a previous attempt leaves behind.",
        [
            ("Hot paths", [(214, 217)]),
            ("Read-modify-write and the comment that claims serialization", [(218, 253)]),
            ("A MUST-write owes a collector", [(254, 264)]),
            ("Residue from a prior attempt", [(1510, 1554)]),
        ],
    ),
    "AUTHORIZATION-AND-CAPABILITY.md": (
        "Authorization, capabilities, and the dispatch gate",
        "The §5.2/§6.3 checks: which authority is spent, which argument decides it, "
        "what a relocated or newly-consuming check starts reading, and how a correct "
        "predicate gets asked the wrong question.",
        [
            ("What a guard's own comment owes, and content-addressed keys", [(265, 320)]),
            ("Probes, hypotheticals, and mint paths", [(321, 338)]),
            ("Ceilings: the third state, and a field that was inert", [(385, 397), (398, 421)]),
            ("A check that moves to a new party, or into a new scope",
             [(758, 795), (796, 825), (902, 946), (1228, 1261)]),
            ("Two authorities, and the row where they disagree", [(826, 877)]),
            ("Carriers that go plural", [(878, 901)]),
            ("The authorizer's subject vs the handler's set", [(947, 1028)]),
            ("Tables, matrices, and the argument that decides whose authority",
             [(1168, 1227), (1285, 1340), (1341, 1408)]),
        ],
    ),
    "PATHS-AND-VALIDATION.md": (
        "Path helpers, boundary dispositions, and fixtures",
        "One rule implemented by two path helpers, what a boundary may do with a "
        "malformed path, and what happens to the fixtures when a structural "
        "validator's verdict starts being consumed.",
        [
            ("A pair of helpers, one rule, two dispositions", [(1094, 1136)]),
            ("When a validator's verdict starts being consumed", [(1262, 1284)]),
        ],
    ),
    "WIRE-AND-ENCODING.md": (
        "Wire shapes, byte fidelity, and error codes",
        "What may appear on the wire and what a peer must preserve: byte fidelity, "
        "closed grammars, the `(status, field, spelling)` of an error code, the "
        "sender half of a normative rule, and validators with no caller.",
        [
            ("One representation carrying two meanings", [(339, 364), (365, 384)]),
            ("Error codes: the slot, the field, and the failure named", [(578, 689)]),
            ("The sender half, and refusals that answer nobody",
             [(1439, 1462), (1463, 1488)]),
            ("Advertised interfaces", [(1555, 1562)]),
            ("Validators with no consumer, and byte fidelity the type cannot express",
             [(2126, 2162), (2163, 2215)]),
        ],
    ),
    "TESTING-AND-EVIDENCE.md": (
        "Tests, mutations, and what counts as evidence",
        "The difference between a test that passes and a test that measures "
        "something: controls, mutations actually run, fixtures your own codec "
        "cannot author, and the boundary a row crosses.",
        [
            ("A test edited beside the behaviour witnesses nothing", [(459, 486)]),
            ("Unobservable branches", [(498, 505)]),
            ("Fixtures your own codec cannot author", [(506, 577)]),
            ("Comments that stop anyone driving a branch",
             [(690, 734), (735, 757)]),
            ("Attribution: which layer earned the green", [(1044, 1093)]),
            ("Predictions are not results", [(1409, 1438)]),
            ("Discriminators and controls",
             [(1563, 1633), (1634, 1684), (1685, 1700), (1975, 2030)]),
            ("A cross-seat drive that does not cross the seat", [(2031, 2052)]),
        ],
    ),
    "CONFORMANCE-GATES.md": (
        "Reading a cross-impl run",
        "What a green category, a passing gate, a WARN, a SKIP and a FAIL detail "
        "line are each evidence of — and the several ways a run can say `clean` "
        "about a surface it never touched.",
        [
            ("A ledger's adjective is not a severity", [(487, 497)]),
            ("Agreement is evidence only if each seat measured the condition",
             [(1701, 1724), (1725, 1752)]),
            ("A green category is not evidence about a surface it does not check",
             [(1753, 1891)]),
            ("Published descriptors and fixture corpora",
             [(1921, 1945), (1946, 1958)]),
            ("Declared exclusions", [(2088, 2125)]),
        ],
    ),
    "SPEC-RULINGS-AND-ROUTING.md": (
        "Reading a ruling, a fold, and a routed item",
        "A routed pointer is where somebody looked; the spec says what binds. How "
        "to derive the boundary, recount an enumeration against this tree, and "
        "answer a packet with a measurement.",
        [
            ("Prove an absence by construction", [(422, 458)]),
            ("Citations and identifiers", [(1029, 1043)]),
            ("An enumeration in a ruling is a hypothesis about your tree",
             [(1137, 1167), (1489, 1509)]),
            ("A routed item is a delta against the sibling's tree",
             [(1892, 1920), (2053, 2087)]),
            ("Named divergences", [(1959, 1974)]),
            ("The boundary is the normative sentence, then sweep it", [(2266, 2470)]),
        ],
    ),
}

HEADER = """# {title}

> {purpose}

Working memory for `entity-core-rust`, indexed from
[`INDEX.md`](INDEX.md). Entries are **findable by symptom** — the bolded lead
sentence is the shape you arrive with. Each carries its mechanism, its
enforcement point, and its provenance (the promotion ladder needs the source
commit; that is provenance, not session narration).

**An entry that could become a check SHOULD become one — and is then deleted
from here.** Memory is where a finding waits while it is still only prose.
"""


def main():
    lines = SRC.read_text().splitlines(keepends=True)
    OUT.mkdir(parents=True, exist_ok=True)
    used = set()
    for name, (title, purpose, groups) in PLAN.items():
        parts = [HEADER.format(title=title, purpose=purpose)]
        for heading, ranges in groups:
            parts.append(f"\n## {heading}\n\n")
            for start, end in ranges:
                for n in range(start, end + 1):
                    if n in used:
                        raise SystemExit(f"overlap at source line {n}")
                    used.add(n)
                parts.append("".join(lines[start - 1:end]).rstrip("\n") + "\n")
        (OUT / name).write_text("".join(parts))
        print(f"{name}: {len(''.join(parts))} bytes")
    print(f"moved {len(used)} source lines")


if __name__ == "__main__":
    main()
