# Reading a cross-impl run

> What a green category, a passing gate, a WARN, a SKIP and a FAIL detail line are each evidence of — and the several ways a run can say `clean` about a surface it never touched.

Working memory for `entity-core-rust`, indexed from
[`INDEX.md`](INDEX.md). Entries are **findable by symptom** — the bolded lead
sentence is the shape you arrive with. Each carries its mechanism, its
enforcement point, and its provenance (the promotion ladder needs the source
commit; that is provenance, not session narration).

**An entry that could become a check SHOULD become one — and is then deleted
from here.** Memory is where a finding waits while it is still only prose.

## A ledger's adjective is not a severity

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

## Agreement is evidence only if each seat measured the condition

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

## A green category is not evidence about a surface it does not check

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

## Published descriptors and fixture corpora

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

## Declared exclusions

- **A declared exclusion whose ground is "nothing installs it" is a gap wearing an exemption —
  register the surface and let the wire tell you what it was hiding.** *(Candidate: bit us once,
  2026-08-22.)* `CONFORMANCE-EXCLUSIONS.md`'s substitute entry rested on two grounds: Ruling 4
  (`claimed_source_peer_id` is dispatcher context, not a wire field — a property of the *protocol*,
  cohort-convergent, a real exclusion) and *"nothing installs the surface"* — exhaustively true, and
  **not an exclusion ground at all**. The second one is the shape our own charter already names, a
  surface present in the tree and absent from the substrate, and writing it into the exclusions doc
  is how it survived: `substitute 0P/**1S**` read as *declared* rather than as *undone*, and a skip
  counts as a failure. It was the sole reason this implementation's release gate exited 1 while go's exited 0.
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
