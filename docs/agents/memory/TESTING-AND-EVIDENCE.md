# Tests, mutations, and what counts as evidence

> The difference between a test that passes and a test that measures something: controls, mutations actually run, fixtures your own codec cannot author, and the boundary a row crosses.

Working memory for `entity-core-rust`, indexed from
[`INDEX.md`](INDEX.md). Entries are **findable by symptom** — the bolded lead
sentence is the shape you arrive with. Each carries its mechanism, its
enforcement point, and its provenance (the promotion ladder needs the source
commit; that is provenance, not session narration).

**An entry that could become a check SHOULD become one — and is then deleted
from here.** Memory is where a finding waits while it is still only prose.

## A test edited beside the behaviour witnesses nothing

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

## Unobservable branches

- **An unobservable branch is not shipped, even when it is "obviously" faster.** *(Same
  session, same entry's other half.)* Fixing R-4 by consulting the index *first* and falling
  back to the scan looked strictly better. Mutation: delete the fast path — **no test failed**,
  because `by-target/{hex}` sits *inside* the scanned prefix, so the keyed lookup can only find
  what the scan finds. A branch that reads as covered and cannot fail is worse than its
  absence: it is an unmeasured claim in the shape of an optimization. Ship the scan, pin the
  containment that makes the fast path pointless (`revocation_by_target_is_inside_the_scanned_prefix`),
  and let it fail loudly if the two paths ever diverge.

## Fixtures your own codec cannot author

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

## Comments that stop anyone driving a branch

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

## Attribution: which layer earned the green

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
  **Ratified 2026-09-15, and the second bite is the inverse of the first: there the two sites were
  REDUNDANT and a green row could not say which earned it; here the two sites were
  COMPLEMENTARY — one per connection PHASE — and a green suite could not say that one of them was
  never entered.** §4.11's pre-admission refusal has two emission sites in this tree, because the
  serial writer task does not exist until the handshake completes: `write_preadmission_refusal` at
  the two hello/authenticate frame reads, and `send_preadmission_refusal` through `resp_tx` in the
  message loop. They share the `(status, code)` table — `preadmission_disposition`, one function,
  deliberately — and that shared half is exactly what made the split invisible. Six rows drove the
  handshake site; restoring the **exact pre-`0.8.2.25` bare close** on the message loop's read arm
  left all six **green**.
  **The tell is that a "shared helper" makes two sites look like one.** A single `fn` answering
  *what code* reads as the whole rule, and the half it does not answer — *who puts it on the wire,
  and on which socket half* — is the half with the phase-specific bug in it. Factor the decision,
  never the delivery, and then ask per delivery site what drives it.
  **Enforcement, and it is the same rule pointed at coverage rather than at attribution: a mutation
  that reddens NOTHING is a finding about the test set, not a no-op.** The first instinct on a green
  mutation is *"the two guards must be equivalent"* — which was true the last time this shape
  appeared (`extensions/tree`'s double refusal) and false here. Resolve it by naming the input that
  reaches each site and checking a row drives it; if no row can, build the driver. Here that meant a
  **tapping proxy** (`core/peer/tests/preadmission_refusal_vector.rs::tapped_pair`): a byte-level
  man-in-the-middle between a real dialer and a real acceptor, so a **forged length prefix** — which
  `dispatch_raw` cannot express, because it frames what it is handed — can be written at an
  **established** connection and the acceptor's answer read back. That is the raw-frame injection
  `entity-core-go` records as owed by their validate harness, and it is ~60 lines. Two fixture traps
  it cost, both of which silently pass a conformant peer: **a dropped half of a `tokio::io::split`
  signals no EOF at all**, so `drop(writer)` where `shutdown().await` is meant turns *"EOF part-way
  through a frame"* into *"a slow sender"* and the row times out against correct code — and a proxy
  must **propagate** that EOF rather than merely stopping its copy loop.

## Predictions are not results

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

## Discriminators and controls

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

## A cross-seat drive that does not cross the seat

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
