# Path helpers, boundary dispositions, and fixtures

> One rule implemented by two path helpers, what a boundary may do with a malformed path, and what happens to the fixtures when a structural validator's verdict starts being consumed.

Working memory for `entity-core-rust`, indexed from
[`INDEX.md`](INDEX.md). Entries are **findable by symptom** — the bolded lead
sentence is the shape you arrive with. Each carries its mechanism, its
enforcement point, and its provenance (the promotion ladder needs the source
commit; that is provenance, not session narration).

**An entry that could become a check SHOULD become one — and is then deleted
from here.** Memory is where a finding waits while it is still only prose.

## A pair of helpers, one rule, two dispositions

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

## When a validator's verdict starts being consumed

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
