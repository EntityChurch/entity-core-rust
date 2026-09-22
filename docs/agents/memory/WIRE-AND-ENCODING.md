# Wire shapes, byte fidelity, and error codes

> What may appear on the wire and what a peer must preserve: byte fidelity, closed grammars, the `(status, field, spelling)` of an error code, the sender half of a normative rule, and validators with no caller.

Working memory for `entity-core-rust`, indexed from
[`INDEX.md`](INDEX.md). Entries are **findable by symptom** — the bolded lead
sentence is the shape you arrive with. Each carries its mechanism, its
enforcement point, and its provenance (the promotion ladder needs the source
commit; that is provenance, not session narration).

**An entry that could become a check SHOULD become one — and is then deleted
from here.** Memory is where a finding waits while it is still only prose.

## One representation carrying two meanings

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

## Error codes: the slot, the field, and the failure named

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

## The sender half, and refusals that answer nobody

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

## Advertised interfaces

- **An operation added to a `Handler` has two registration sites, and the second one is in
  another crate.** `impl Handler::operations()` makes it answerable; `bootstrap_handler(...)` in
  `core/peer/src/lib.rs` writes the **advertised** `system/handler/{pattern}` interface entity
  that publishes the contract (§4.4 advertised-handler discipline). A peer that answers an
  operation it does not advertise is inconsistent with its own published interface, and the
  in-tree handler tests cannot see it — they construct the handler directly and never read the
  interface entity. Grep `bootstrap_handler(` when adding an op; it is one line and it is the
  only place the peer says out loud what it serves.

## Validators with no consumer, and byte fidelity the type cannot express

- **⭐ RATIFIED 2026-09-16 — *a validator with no consumer* has now bitten three times in three
  different disguises, and the third one was WEARING A GREEN CROSS-IMPL GATE.** The first was a
  handler built, tested and unreachable from any peer binary (`storage-substitute-http`). The
  second was a `LocationIndex` decorator declining to forward the CAS trio. The third is the
  sharpest and is the one that promotes this to a discipline: `is_canonical_ecf` — a complete
  strict-ECF validator with an explicit major-type-6 arm, shipped since the initial release,
  carrying its own F29/F30 unit suite — **had zero callers on any protocol boundary.** Its only
  consumer was `cmd/wire-conformance`, scoring `decode_reject` *vectors*. So
  `ENTITY-CBOR-ENCODING` §6.3's *"MUST reject any received protocol frame containing a CBOR tag on
  a data field"* was unimplemented in the peer for the whole life of the tree, behind a suite that
  tested the validator and a cohort gate that scored its output.
  **Three transferable parts, and the third is new.**
  (a) **The enforcement point is a question asked of the VALIDATOR, not of the rule.** For every
  `fn` in this tree whose name or doc says *validate / canonical / reject / is_\**, grep its call
  sites and ask **which of them is on a path a remote caller reaches**. A validator whose only
  callers are `cmd/`, `tests/`, or a conformance emitter is a validator the peer does not run, and
  the rule it implements is unimplemented however good the function is. `grep -rn 'fn is_canonical\|fn validate_' --include=*.rs`
  then `grep -rn '<name>(' --include=*.rs` per hit; a hit list with no `core/peer` or `core/wire`
  entry **is** the finding.
  (b) **A fix in one direction can move you from one half of a two-sided MUST NOT to the other.**
  §6.3 forbids **both** *"silently strip"* and *"preserve through forwarding"*. Before the §5.4
  byte-fidelity fix (`23513a0`) `to_ecf`'s `Value::Tag(_, inner)` arm stripped tags on the forward
  path; after it, `data` rides raw and we preserved them. **The tree was on one side or the other
  of that sentence the entire time, the fix swapped sides without touching the file, and the suite
  was green for both** — because no row drove a tag. When a rule forbids two dispositions, a
  change that alters which one you have is not a fix, and the only thing that can tell them apart
  is a row that drives the input.
  (c) ⛔ **A conformance category driven from an EMISSION FILE scores the emitter, not the peer —
  and that is invisible from inside a green run.** go's `tag_reject` gate
  (`cmd/internal/validate/conformance.go`) collects each impl's `decode_results` / `decode_codes`
  and asserts *"rejected by all N impls with code `non_canonical_ecf`"*. Every seat emits those
  from its **conformance CLI**, so three seats passed a tag gate while at least two peers admitted
  the frame. This is the `[self]`-check rule one level out: there the check measured the harness's
  own implementation, here the check measures an **artifact the peer does not produce**.
  **Before citing a conformance category as evidence about your peer, ask what the harness
  actually drove — a socket, or a file your CLI wrote.** If it is a file, the category is a
  statement about your emitter and the peer is unmeasured.
- **A byte-fidelity rule the TYPE cannot express is a rule every site re-decides, and every site
  will get it wrong the same way — find the missing primitive, not the missing call.** *(Candidate:
  bit us once, 2026-09-15, at **eight** sites simultaneously; found by a sibling's read of one of
  them.)* §5.4 says an entity's `data` is preserved as-is, never decoded and re-encoded. `core/wire`
  holds that line perfectly — `decode_entity` captures `data` as a raw slice, `encode_entity`
  splices it. Everywhere else in the tree it was violated, because **`entity_ecf::Value` IS
  `ciborium::Value` and cannot hold raw bytes**: the moment a site needs to inline an entity inside
  another entity's data — `{content_hash, data, type}`, which is §3.4's params shape, §3.1's
  `included` entries, and every result wrapper — the only tool available was
  `ciborium::from_reader` + `to_ecf`. Two helpers existed for exactly that purpose
  (`core/tree::raw_cbor_value`, `core/protocol::decode_entity_from_value`), which is how the pattern
  propagated: the second site copied the first. **go has no such rule to remember — its
  `Entity.Data` is `cbor.RawMessage`, so its encoder splices by construction.** A rule one
  implementation gets for free from a type is a rule the other implementation will break at every
  site, and the fix is a primitive (`entity_wire::cbor_map_set_raw`), not N call-site edits. Delete
  the lossy helpers in the same commit — a helper that exists is a helper the next site reaches for,
  and `raw_cbor_value` going dead was the signal that `core/tree` was actually clean.
  **What it cost, measured:** `to_ecf` sorts map keys, normalizes non-minimal integer and length
  encodings, folds indefinite-length items to definite and **drops tags**; ciborium's own round trip
  does all but the first and last. So a `tree:merge` of any entity this peer did not author stored it
  at a hash the source trie does not name — `200 applied:N` over bindings resolving to nothing — and
  a re-addressed *trie node* silently drops an entire subtree, because
  `trie::collect_bindings_into` skips a `Link` it cannot load.
  **Enforcement, and it is the grep plus the fixture rule.** (a) `grep -rn 'text("content_hash")'
  --include=*.rs` enumerates the inline-an-entity sites; for each, read what the `data` key is given.
  A decoded `Value` is the defect. (b) **Any test of this class needs a fixture whose BYTES our own
  codec cannot author** — the entry above already says a byte-exactness fixture needs a *field* the
  codec cannot emit; this is the same rule one level down. `{"v": 1}` with the `1` written
  non-minimally (`0xa1 0x61 0x76 0x18 0x01`) is self-consistent, valid CBOR, and unauthorable by ECF.
  Built with `to_ecf` instead, the broken and the fixed implementation are byte-identical and the
  assertion is a tautology — which is why this shipped behind a green suite and a green cross-impl
  gate.
  **And the half that is about WHERE the row lives, because a handler-side fix was dead code for the
  second time this month.** `core/tree`'s rows were green with the defect fully live on the wire:
  four more layers between the socket and the handler re-encoded independently — the outbound EXECUTE
  builder, `extract_params_entity` (every handler's `ctx.params`), the in-process sub-dispatch
  builder, and `parse_execute_response`. That last one is the sharpest: `build_execute_response_full`
  has **always** spliced raw, so the write half was right and only the read half was wrong, and **a
  round-trip test is structurally unable to see an encoder/decoder disagreement** — it is the one
  shape where two functions can disagree and still round-trip. Same conclusion as `0.8.2.24` N6:
  *an in-process row is a floor under a vector, not one.* Teeth:
  `core/peer/tests/merge_byte_fidelity_vector.rs`, two peers over a real handshake, whose **two axes
  are both load-bearing** — a non-canonical fixture AND a target peer that has never seen the entity.
  Measured: with the target sharing the source's store the pre-fix code **passed**, because merge
  binds `path → hash` from the source trie and a target that already holds that hash resolves it
  whether or not the ingest did anything. Six mutations RUN, all six reddening that row and **no**
  pre-existing row in the 133-suite set.
  **Cohort note, stated at the right evidence level:** core-go's `tree_operations.roundtrip_verify_
  entity` is the check that would catch this and misses on **both** axes (an `ecf.Encode` fixture,
  and a `tree-ops/` → `tree-ops-mirror/` round trip on one peer); its cross-peer
  `convergence.extractAndMerge` helper re-encodes the envelope in the **harness**
  (`cbor.Unmarshal` → `ecf.Encode`), so it would flatten the fixture before any peer saw it. That is
  a code read of their tree, not a drive — routed for them to confirm and to own the vector.
