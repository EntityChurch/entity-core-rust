# Reading a ruling, a fold, and a routed item

> A routed pointer is where somebody looked; the spec says what binds. How to derive the boundary, recount an enumeration against this tree, and answer a packet with a measurement.

Working memory for `entity-core-rust`, indexed from
[`INDEX.md`](INDEX.md). Entries are **findable by symptom** — the bolded lead
sentence is the shape you arrive with. Each carries its mechanism, its
enforcement point, and its provenance (the promotion ladder needs the source
commit; that is provenance, not session narration).

**An entry that could become a check SHOULD become one — and is then deleted
from here.** Memory is where a finding waits while it is still only prose.

## Prove an absence by construction

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

## Citations and identifiers

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

## An enumeration in a ruling is a hypothesis about your tree

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

## A routed item is a delta against the sibling's tree

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

## Named divergences

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

## The boundary is the normative sentence, then sweep it

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
    **Third shape, 2026-09-16, and it is the one a CLARITY revision produces: when a ruling
    WITHDRAWS a prohibition, it hands the withdrawn input to some OTHER rule — and the question
    you owe is not *"does this delta oblige me?"* but *"do I implement the rule it just handed the
    input to?"*** `0.8.2.26` opens *"not one delta adds an obligation to a conformant peer … eight
    of the nine withdraw a prohibition"*, scores `DR-3` **"no — a prohibition was withdrawn"**, and
    `entity-core-go` relayed it as *"nothing in either of your trees moves."* All of that is
    accurate. What `DR-3` withdrew is §4.11's ban on answering `non_canonical_ecf` on the framing
    arm, and what it did with the input was **partition** it: tagged-but-decodable bytes move to
    `ENTITY-CBOR-ENCODING` §6.3, a rule older than the fold and one we had never implemented. The
    delta obliged nothing; the rule on the far side of the partition obliged everything, and a
    reader tracking obligations-added sees zero.
    ⚠ **The tell is the word *partition* — or *"is not this arm, it is that one"*, or a table row
    that MOVES rather than appears.** A withdrawal is a redirection, so read the destination.
    **Enforcement: for every delta a fold scores as a withdrawal or a clarification, name the rule
    the input now lands on and grep your tree for that rule's enforcement point** — not the fold's.
    Here that was one grep (`grep -rn 'non_canonical_ecf' --include=*.rs`), and the answer was five
    hits of which **none was an emission site**: four comments explaining why the code does *not*
    apply, and one `cmd/` conformance harness. A code with no emission site is a rule with no
    implementation, whatever the comments around it say.
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
