# Authorization, capabilities, and the dispatch gate

> The §5.2/§6.3 checks: which authority is spent, which argument decides it, what a relocated or newly-consuming check starts reading, and how a correct predicate gets asked the wrong question.

Working memory for `entity-core-rust`, indexed from
[`INDEX.md`](INDEX.md). Entries are **findable by symptom** — the bolded lead
sentence is the shape you arrive with. Each carries its mechanism, its
enforcement point, and its provenance (the promotion ladder needs the source
commit; that is provenance, not session narration).

**An entry that could become a check SHOULD become one — and is then deleted
from here.** Memory is where a finding waits while it is still only prose.

## What a guard's own comment owes, and content-addressed keys

- **A guard's own comment is an INVENTORY of the checks it owes — read it as a checklist
  against the code beneath it, because a loop that binds a variable and uses it only in the
  error message has discarded half the invariant.** *(Candidate: bit us once, 2026-09-13, and
  it had been shipping since the guard was written. Severity: capability forgery.)*
  `verify_request` step 2b exists to close *"a forgery surface where a peer could substitute
  an entity for a known hash via envelope manipulation — downstream hash-keyed lookups like
  `included[h]` would index the substitute under h, even though h ≠ recomputed(substitute
  .bytes)"*. That sentence names **two** checks. The loop was
  `for entity in envelope.included.values() { entity.validate()?; }` and ran **one**:
  `validate()` recomputes `Hash::compute(type, data)` against the entity's **own**
  `content_hash` field — *self-consistency*, which any honestly-built entity satisfies,
  **including the attacker's**. The half about the **map key** — the address every downstream
  lookup actually uses — was thrown away by `.values()`.
  **What that bought an attacker, measured (`core/protocol/tests/included_key_binding.rs`,
  `verify_capability_chain` returned `Ok(())`):** file your own `system/peer` entity under a
  victim's identity hash, and every per-link check passes on its own terms —
  `sig.signer == cap.granter`, the resolved entity is a `system/peer`, and
  `verify_peer_data_sig` verifies **your** signature against **your** key, because that is the
  key it just looked up under the victim's hash. You need no key and no identity entity of the
  victim's, only the victim's identity *hash*, which is the public `grantee` field of any
  capability they present. So an observer of any chain could mint a leaf off it, up to the
  parent's own scope. The root link stays genuine, attenuation holds because you wrote the
  leaf, and nothing anywhere looks wrong.
  **Three transferable parts.**
  (a) **`validate()`-shaped and `is-this-the-right-one`-shaped are different questions that
  read alike.** *Self-consistent* and *correctly addressed* are one word apart in English and
  are unrelated properties; a function named `validate` answers the first and will be read as
  answering both. Same family as *one representation carrying two meanings*, at the level of a
  method name.
  (b) **In a content-addressed map the KEY is the hash of the VALUE, and that is a property of
  the TYPE, not of a code path.** Enforce it at the constructor — `decode_envelope`, which is
  where such a map is built from received bytes — and at any `pub fn` whose return value is a
  security verdict and whose callers build their maps differently
  (`verify_capability_chain`: `verify_request` builds from `envelope.included`,
  `presented_authority_authorizes` from a §7a.2a bundle merged with the parent envelope's).
  An invariant that lives in the callers is one the next caller does not inherit.
  (c) **The greps.** `grep -rn '\.values()' --include=*.rs` over any loop that validates a
  hash-keyed map, and `grep -rn 'included.get(' --include=*.rs` to enumerate what addresses it
  by key (here: `granter`, `grantee`, `parent`, `collect_authority_chain`'s resolver,
  `handle_diff`'s snapshot resolution). If a lookup keys on a hash read out of *another
  entity's data*, the key is load-bearing and something must bind it.
  **Enforcement and the measured per-site result**, because this rule is satisfiable at three
  sites and three sites is where one becomes an unmeasured claim: the decoder mutation reddens
  the decoder row, the `verify_capability_chain` mutation reddens the forgery row — **disjoint**
  — and the `verify_request` step-2b mutation reddens **nothing**, so that call is recorded at
  the code as defence in depth with the property it *would* cover (non-chain `ctx.included`
  lookups on an in-process `Envelope`) named as **unmeasured**. The control
  (`a_correctly_filed_delegation_chain_still_verifies`) is not optional: the fix is a
  comparison of two `Hash`es and getting it backwards refuses every well-formed envelope in
  the system.
  **Cohort note, and the evidence level is stated because it differs by seat.** Read at the
  line, core-go's `Envelope.ValidateAll` (`core/entity/envelope.go:57-62`) has the identical
  shape — it binds `h` in `for h, ent := range e.Included` and uses it only in the error
  string — and `grep -rn '!= ent.ContentHash' core/` finds no key comparison. That is a code
  read, **not a drive**: routed to go and py to confirm and drive in their own trees. Our own
  finding is measured; theirs is not, and the report says which is which.

## Probes, hypotheticals, and mint paths

- **A hypothetical you check MUST carry the shape you will write.** *(Ratified: bit us
  twice, in opposite directions.)* When a decision is made by probing a synthetic value
  through the real validator — `is_attenuated(&child, parent)`, an RL2 hypothetical, any
  "would this pass?" construction — build the probe with **every** field the persisted
  value will actually carry, and compute the derived ones *before* the probe, not after.
  A probe that differs from the write is a check against a value that never exists:
  - **Too permissive** → passes at issue, rejected at use. ROLE v1.7 §5.3 names this
    verbatim ("RL2 OK at issue, chain-invalid at use") — `build_hypothetical_token` +
    `effective_expires_at`, `extensions/role/src/handler.rs`.
  - **Too strict** → nothing issues at all, and the 403 looks like a scope defect. §6.2
    `request` built its probe `expires_at: None` while `is_attenuated` enforces §5.6's
    "child expiry ≤ parent's" — so **every** request from a caller whose cap expires was
    403, and the arch proposal that measured us read the symptom backwards. Fix: clamp
    first, probe with the clamped value (`clamp_mint_expiry` → `child`).
  **Enforcement:** the probe's assertion belongs in a test that fixes the derived field on
  the *parent* — `request_mint_cannot_outlive_the_caller_capability` fails (403, not a
  wrong expiry) if the probe and the mint drift apart again. Grep for `is_attenuated(&`
  and any `hypothetical`/`probe`/`would_` construction when touching a mint path.

## Ceilings: the third state, and a field that was inert

- **An `Option<T>` whose `None` must mean opposite things is the wrong type — name the
  third state.** *(Ratified with the rule above; this is the first of the two shapes,
  `7c21d04`.)* §5.2's resource dimension needed a
  ceiling for in-process sub-dispatch. Modelled as `Option<CapabilityToken>`, `None` had to
  mean **deny** for a handler holding no grant and **allow** for the peer's own SDK/engine
  entry points, which present no capability because they are the root authority. Both are
  correct readings of "absent," and either default is a shipped bug: deny breaks every
  `Peer::execute_with_options`, allow reinstates the escalation for exactly the grantless
  caller. `DispatchCeiling::{PeerRoot, Handler(Option<_>)}` makes the distinction
  unrepresentable-as-a-mistake and forces every call site to state which it is. **Reach for
  the enum the moment you catch yourself writing "`None` here means…" twice with different
  answers** — the compiler then finds the call sites for you, which is how the sweep stayed
  honest across 14 of them.
- **A check added to a path that ran none starts READING fields that were written when
  nothing read them — audit the values it will now consult, not just the call sites the
  compiler makes you touch.** *(Candidate: bit us once, `7c21d04` → found 2026-08-23.)*
  D1 gave `make_execute_fn` a §5.2 resource ceiling. The type change forced 14 call sites
  and every one got a considered answer; what nobody looked at was the **`resources` field
  of the grants the ceiling would now consult**, because until that commit no code path
  read it. §6.9's default per-handler self-grant is described as *"all resources"* and was
  written `PathScope::all()` — bare `*`, which `canonicalize` resolves to `/{local}/*`.
  Harmless as an unread field; as a ceiling it means **own namespace only**, so the peer's
  own engine could no longer write the foreign-namespace subtrees its store legitimately
  holds (V7 §1.4 Category A — a cached foreign site, a `follow` mirror at `/{them}/app/…`).
  `follow(Continuation)`'s standing leg 403'd at its `system/tree:merge` step and stayed
  red for five days. The same trap was already documented one function over: `debug_open_grants`
  carries an R-5 note saying bare `*` excludes `/{X}/…` and uses `/*/*` for exactly this
  reason — a *written* precedent that the new reader did not inherit. Fix is
  `default_handler_self_grant()` (`/*/*`), kept distinct from `wildcard_handler_grant()` so
  the own-namespace call sites that want confinement still say so.
  **Enforcement:** when a commit turns an inert field into an authorization input, grep every
  constructor of that field (`grep -rn 'resources:' --include=*.rs`) and ask what each one
  **means** versus what it **encodes** — the two are only the same once something checks. And
  pin the answer at *both* ends: `default_handler_grant_ceiling_reaches_a_foreign_namespace_path`
  (core/peer) fails against the pre-fix `wildcard_handler_grant()`, and its narrow-deputy
  control fails if the new check is neutered — verified by running both mutations, because
  "widening the default" and "putting a hole in D1" are one edit apart.

## A check that moves to a new party, or into a new scope

- **When a ruling moves a check to a NEW PARTY, audit what that party is guaranteed to hold — the
  material may have been assembled best-effort for someone else.** *(Candidate: bit us once,
  2026-09-09; the defect had been shipping invisibly since the code existed.)* 0.8.2.17's
  presented-authority arm requires the **dispatcher** to chain-verify a capability the target
  minted. Every input already existed, so it reads as a composition. It is not: §5.5 verification
  needs a detached signature per link, and `EXTENSION-CONTINUATION` §4.3 makes bundled signatures
  explicitly **best-effort** — *"B fails closed if it needed it"* — because the design had always
  assumed the **recipient** verifies. Move the check to the dispatcher and it inherits a bundle
  nobody promised would be complete.
  Underneath that was a real defect: §6.5 envelope-signature ingestion ran on **inbound EXECUTEs
  only, never on the connect response**, so this peer held a connection grant whose granter's
  signature sat live on the connection (`auth_included`) and bound at **no path** — unreachable to
  `collect_chain_bundle`, which resolves signatures only through the §3.5 invariant pointer. Every
  chain rooted at that grant was unverifiable *locally*, and nothing could see it because the far
  side verifies against its own store where its own signature **is** bound. It surfaced as
  `MissingSignature` on `follow(Continuation)`'s standing leg — a legitimate credential refused
  for want of a proof we were holding.
  **Enforcement:** for any rule that relocates a verification, name the artifact it consumes and
  find the site that PRODUCES that artifact locally; if the producer's own contract says
  *best-effort*, *silently omitted*, or *the verifier fails closed*, the relocation has a material
  gap and the fix is to close the gap, not to soften the check. In this tree the pair is
  `ingest_envelope_signatures` (producer) and `collect_chain_bundle` (consumer), and the question
  that closes it is *"which envelopes does ingestion run on?"* — the answer was one, and the code
  said so nowhere.
  **Ratified 2026-09-10, and the second bite was the SAME producer at a THIRD surface.** 0.8.2.19
  E4 generalizes §6.5 ingestion to *any received envelope carrying an `included` map*, and the one
  we still did not run it on was the **`EXECUTE_RESPONSE`** — which §6.2 names as the *deliberate*
  runtime carrier of a target-minted credential (*"the capability handler is the runtime entry
  point for in-band capability management, while §4.4 covers initial-grant delivery"*). So a peer
  that goes and **acquires** a credential in order to make a presented-authority sub-dispatch
  acquired it with its signature bound at no path: the identical `MissingSignature`, one surface
  later, and mutation-measured as `left: None` — the binding did not exist at all
  (`a_capability_minted_in_an_execute_response_lands_with_its_signature_bound`). **Two surfaces
  were each enumerated one at a time, each after a failure; the rule is the fix, not a third
  enumeration** — the enforcement question is now *"does this code path receive an envelope?"*,
  and every `yes` owes an `ingest_envelope_signatures` call. Grep `parse_execute_response(` and
  `\.included` on any receive path.
- **A ruling that says "X is IN scope" is answered by an INVENTORY, not by the one site the
  routing named — and a seam that re-roots its own dispatch to peer authority is how the scope
  rule gets emptied.** *(Candidate: bit us once, 2026-09-10; both instances found by our own
  sweep, neither named by the sibling's routing.)* 0.8.2.19's E2 decides §1.4 scope by **authority
  provenance** — *does this dispatch spend a handler's grant, or the peer's own root authority?* —
  and adds *"a peer MUST NOT exempt the class on the ground that no caller was on the stack."*
  The sibling's routing flagged one class (subscription delivery). Enumerating **every**
  `DispatchCeiling::PeerRoot` construction in the tree instead found **two** that fail the test:
  the delivery engine (`core/peer/src/lib.rs`) and `PeerLink::self_execute`
  (`core/peer/src/network_link.rs`), whose §9.2 close notification is a real outbound dispatch to
  a **caller-supplied** peer id, originated inside the `system/network` handler.
  **The transferable half is the argument, not the count.** `self_execute`'s doc comment said
  *"dispatch as the local peer identity — the same path `Peer::execute_with_options` takes"*, and
  that reads as a fact about the mechanism rather than as a claim about authority. It is a claim
  about authority: **if a handler may declare its own dispatch `PeerRoot`, the provenance rule is
  evadable by every handler and means nothing.** Prose describing a seam is not a scope argument,
  which is the same failure as a comment asserting a concurrency invariant without naming the
  construct that enforces it.
  **Enforcement:** when a ruling defines a scope, the region that closes is the **constructor of
  the thing being classified** — here `grep -rn 'DispatchCeiling::PeerRoot' --include=*.rs`, a
  closed list — and each site owes one line saying which side of the test it falls on and why.
  Sites legitimately out of scope (the SDK entry points, `Peer::execute_with_options`) say so;
  sites in scope and not yet flipped say **what blocks the flip**, because *"we know"* with no
  stated blocker is indistinguishable from an exemption. Both are pinned at the code citing
  `ROUTING-2026-09-10-a`. And note which way the cost runs: the subscription instance cannot be
  flipped from one seat — our `deliver_token` is A-rooted (conformant, §1.2) but minted as a
  **self-grant**, so its leaf `grantee` is not this engine and it relaxes nothing; flipping the
  ceiling alone refuses every cross-peer delivery. **A restrictive fix whose correctness depends
  on a credential shape three seats must mint identically is a coordination item, not a fix.**
- **A STRUCTURAL fix landed for an earlier ruling can make a later ruling's branch UNREACHABLE —
  when a new rule turns a field into a decision, enumerate every seam that TRANSFORMS that field
  before implementing it at the site the worklist names.** *(Candidate: bit us once, 2026-09-14,
  found by the wire vector after the in-tree rows were green.)* `0.8.2.24`'s `N6` splits the two
  empties of `resource`: a **genuinely absent** one takes the operation's absent-case behaviour, a
  **present** one whose effective list is empty is `400 path_required`. Landed exactly where the
  routing names it — `core/tree`'s three resource-optional ops, plus the one derivation they share
  — with 108 in-tree rows green and three mutations reddening disjoint sets. **Over a real socket
  it answered `200` anyway.** `0.8.2.20`'s structural boundary narrowing (`rt.targets =
  effective_targets(...)` in `dispatch_request`, the fix that made the subject rule *structural
  rather than an obligation re-discharged at ~20 handlers*) had already rewritten the request to
  `targets: []` — which is the absent case — so the new `SelfExcluded` arm was **dead code at the
  only door that matters**. Two rulings, one field, and the earlier one's fix silently deletes the
  later one's input.
  **Three transferable parts.**
  (a) **The tell is a PROJECTION that is lossy about its own emptiness.** Narrowing `[P]` with
  `exclude:[P]` to `[]` is not a smaller answer, it is a *different fact*. The remedy is not to
  revert the narrowing — it is a defence, and `the_dispatch_boundary_hands_the_handler_only_the_
  effective_targets` exists because a cross-impl oracle cannot attribute which of the two layers
  earned its green. It is to exempt the case that would erase the distinction: **narrow when
  narrowing leaves something, keep the pair when it would not.** The effective set is identical
  either way (`effective_targets` is idempotent and every consumer calls it), so nothing downstream
  computes a different subject.
  (b) **There were TWO seams, and the first read stopped one statement short.** The inbound wire
  path and the in-process sub-dispatch path both narrow. Reading `extract_resource_target` — which
  does hand back the raw pair — and concluding the wire seam was safe was wrong by two lines:
  `dispatch_request` narrows immediately after qualifying. A comment asserting that asymmetry was
  written, and the wire run deleted it. **Grep the field, not the function you happened to open**
  (`grep -rn 'effective_targets(' --include=*.rs` — the transform sites are the inventory), and
  keep the seams in step: a seam that narrows and one that does not is how the same request gets
  two answers depending on which door it came in.
  (c) **This is the third instance of *an in-process row is a floor under a vector, not one*, and
  the first where the floor was green while the peer was non-conformant.** The earlier two were
  about what a row *proves*; this one is about what it *cannot see* — every layer between the
  socket and the branch gets a vote, and a `HandlerContext` built by hand skips all of them.
  **Enforcement: any ruling that turns a request field into a branch owes a row that crosses a
  socket, written BEFORE the item is reported closed** — `core/peer/tests/two_empties_vector.rs`
  is the shape, and the mutation to run is *narrow unconditionally at the boundary*, which reddens
  the wire row and **nothing** in the handler's own suite.
  **Cohort note, and it is why this was routed rather than just fixed:** the boundary narrowing is
  `0.8.2.20`'s recommended structural shape, so **any seat that adopted it has this defect and a
  handler-only `N6` does not close it** — while a seat that only ever narrowed inside the handler
  is unaffected and will read the item as done. The two populations cannot tell each other apart
  from a green category.
- **A spec rule that relocates an authorization check makes you read a field that was ATTRIBUTION
  until that moment — and the propagated caller capability is the one with a comment saying so.**
  *(Ratified 2026-09-11: this is the third instance of *"a check added to a path that ran none
  starts READING fields that were written when nothing read them"*, and the first where the field's
  own doc comment told us it was not an authorization input.)* §6.3's handler-level path check is
  *"not a secondary check"* at `0.8.2.20`, so `core/tree` now authorizes the path it is about to
  touch against *"the request's capability."* Implemented as `ctx.caller_capability`, it refused
  `follow(Continuation)`'s standing mirror — and the capability arriving at `tree:put` was the
  **inbox deliver token** (`handlers:[system/inbox]`, `operations:[receive]`), four hops after the
  delivery that minted it. `make_execute_fn` says why in as many words: *"caller_capability
  propagates unchanged through sub-dispatch chains so history transitions record the original
  external caller."* It is the chain initiator, for attribution. The authority §5.2 actually checks
  for a sub-dispatch is the dispatching handler's `DispatchCeiling`, which the handler context does
  not carry.
  **So the scope of a relocated check is a question about which dispatch KIND the field means
  something for, and there are three**: inbound wire (`is_external` — the field is the verified
  caller capability, and this is the only kind where it authorizes), in-process sub-dispatch
  (attribution), and peer-root (§6.8: *"bypasses capability verification — the peer is operating as
  the tree owner"*, and the capability is *"informational, not a security assertion"*). Treating
  peer-root as checkable makes the handler-level check **stricter than the dispatch-level one for
  the same dispatch**, because `check_permission`'s resource dimension already short-circuits on
  `DispatchCeiling::PeerRoot`.
  **Enforcement:** before reading any context field as an authorization input, grep for the site
  that WRITES it and read that comment (`grep -rn '<field>' core/peer/src/connection.rs`); if the
  producer's own words are *propagates unchanged*, *for attribution*, *informational*, or *records
  the original*, it is not an authorization input and the check needs a different source or a
  narrower scope. Say the scope at the `fn` with the measurement attached
  (`TreeHandler::authorize_path`), and **pin the narrowing you caused** — gating on `is_external`
  removed a check that previously ran on every dispatch, so
  `snapshot_params_prefix_is_not_checked_on_an_internal_dispatch` asserts the reduction rather than
  leaving it to be rediscovered as a defect.
  **And the open half, stated because an unstated gap is an exemption:** a deputy's Level-2
  authority has no source in this tree. Routed, not papered over with the attribution field.

## Two authorities, and the row where they disagree

- **Two ALTERNATIVE authorities is a bypass wearing a design; the shape that is not is one gate
  with a named exemption — and the two vectors everyone writes are the two that cannot tell them
  apart.** *(Candidate: bit us once, 2026-09-10, **F67**; found by `entity-core-keystone`, not by
  us, not by go, not by py, not by arch. We wrote design prose defending it.)* 0.8.2.17 said a
  target-minted credential's *"own four dimensions authorize the sub-dispatch"* while exempting
  the handler's `peers` scope **by name**. Three independent ground-up implementations read the
  first clause as sufficient and returned *authorized* before the executing handler's grant was
  ever consulted. Because that credential arrives as a **caller-supplied parameter**, a caller
  holding a copy of any `T → P` capability could steer **any** handler on P past its own grant —
  the confused deputy, with the ceiling removed by name. 0.8.2.19 corrects it to **one gate and
  one exemption**: the handler's grant decides all four dimensions, a valid target-minted
  credential relaxes **Dimension 4 only**. *The target answers where; the handler's grant answers
  what.*
  **Three things to carry, and none of them is "read §1.4 harder."**
  1. **The reading was available and cheap.** §6.8 states the gate *positively and
     unconditionally* — *"the authorization decision for an internal sub-request is made on the
     executing handler's grant, never on the propagated caller capability"* — and that sentence
     has **two halves**. Everyone answered the second (a target-minted credential is not the
     propagated caller capability — true, and it survives) and nobody answered the first.
     `EXTENSION-CONTINUATION` §3.6b had already resolved the identical shape as *Level 1 = the
     dispatch gate, Level 2 = the caller capability*; we made a credential Level 1 for the first
     time in the corpus, on the surface where it costs most. **When a fold hands you a new
     authority, open the section that already states the gate and reconcile the two — an
     over-broad clause is a spec-issue to ROUTE, not a licence to implement from.**
  2. **The test set could not see it, and the reason generalizes past this bug.** Our two PD-2
     rows were *credential + covering grant → allow* and *no credential → refuse*. Under a bypass
     and under a compose those give the **same** answers, because in both rows the two authority
     sources **agree**. The discriminating vector is the one where they **disagree**: a valid
     credential presented to a handler whose grant does NOT cover the request → MUST refuse.
     **Whenever an outcome can be reached by more than one source of authority, the check set
     needs a row where the sources disagree — otherwise it measures their union, and a bypass and
     a composition have the same union.**
  3. **The structure is the fix; the condition is not.** Do not patch it as an `&&`. The
     credential check is now a **predicate that produces a bit**
     (`presented_credential_relaxes_peers`), never an authorizer, feeding one call to
     `check_permission_relax_peers`; the relaxation is a flag threaded into the *same* loop body
     so §5.2's all-dimensions-from-one-grant-entry rule cannot drift, and there is **no code path
     by which a credential authorizes alone**. Reinstating F67 requires adding a new early return.
     **`-> bool` meaning "authorized" and `-> bool` meaning "one dimension is relaxed" are the
     same type and opposite facts** — the function name and the doc comment are the only thing
     stopping the next reader from re-fusing them, so both say so.
  **Enforcement:** the pair is mandatory and **both mutations must be RUN, not predicted**, and
  their reddened rows must be **disjoint** — restore-the-bypass reddens the discriminator and
  leaves the relaxation control green; neuter-the-relaxation reddens the control and leaves the
  discriminator green (measured: `5P/2F` each way, `core/peer/tests/conformance_reentry_7a2a.rs`).
  A negative security test can PASS for the wrong reason — refused upstream of the gate — so
  "refused" is worth nothing until the restore mutation shows the probe *reaches* the gate. And
  note what a green cross-impl run was worth here: three seats passed both arms and the report
  read *"PD-2 both arms converged."* **Convergence on a shared reading of one spec sentence is
  cohort-consistency, not independent verification** (ADR-0012, verbatim) — and here it actively
  masked a security hole for as long as it stood.

## Carriers that go plural

- **When a carrier goes from singular to PLURAL, the empty array is a new state the old code
  could not express — and if the field selects an authorization ARM, reading presence off the
  MAP KEY instead of the array's length silently deletes the arm.** *(Candidate: bit us once,
  2026-09-10, caught by writing the row before the code.)* `GUIDE-CONFORMANCE` §7a.1's reentry
  carriers went plural at `0.8.2.19` (`reentry_granters` / `reentry_cap_signatures`) so a K-of-2
  multi-sig root could be expressed on the wire at all. The all-or-none rule then selects §1.4's
  **presented** arm from *credential + ≥1 granter + ≥1 signature*, the **ambient** arm from all
  three absent, and `400 invalid_params` from anything between. `reentry_granters: []` is the row
  that separates the two readings: key present, array empty. Our own already-ratified rule says
  absent and empty are the same fact for an optional array — so it is the **ambient** arm, and a
  peer whose presence test is `cbor_map_field_raw(...).is_some()` calls it partial and 400s it.
  That is the *exact* unmeasurability `0.8.2.17` fixed (an early refusal makes a peer look strict
  and the arm under test unreachable), reintroduced by a params change made for an unrelated
  reason. **The pluralization is where an optional-array rule stops being an encoding nicety and
  becomes an authorization branch.**
  **Enforcement:** when a scalar field becomes an array, enumerate the three states the change
  creates — absent key, present-and-empty, present-and-non-empty — and write the row for the
  middle one first; if the answer to *"is this the same as absent?"* is yes, the presence test
  must read the decoded **length**, never the key. Grep `cbor_map_field_raw` on any path whose
  result feeds a `match`/`if` that picks a code path rather than a value. Teeth:
  `all_keys_present_but_both_arrays_empty_is_the_ambient_arm` (`extensions/conformance`),
  mutation-verified as the **only** row the key-presence reading reddens — the five partial rows
  beside it stay green under it, because under that reading they are still partial.

## The authorizer's subject vs the handler's set

- **An authorization check evaluates the target it was GIVEN; a handler acts on the set that target
  DERIVES — and where those differ, the dimension does not bind however correct the check is.**
  *(Candidate: bit us once, 2026-09-10, found by recomputing arch's `CP-12a` against our tree rather
  than by the routing.)* `CP-12a` names one instance — a target the caller also excludes is *skipped*
  by `check_resource_scope` and then acted on anyway — and its fix (count the **effective** set) is
  about arity. The class is wider and the fix does not reach it: **a prefix, a wildcard, a snapshot
  root, a merge source is one string to the authorizer and a subtree to the handler.** Driven at our
  line: a grant `{include:[app/*], exclude:[app/secret]}` **authorizes** `system/tree:get` on
  `/{p}/app/` — the exclude does not match the prefix *string* — and `handle_listing` then returns
  `secret` and its hash, while the child's own path is correctly refused. The direct read is denied,
  the enumeration is not, so nothing looks wrong from either side. §5.2's own pseudocode comment
  states the property (*"Otherwise the effective target includes paths the grant forbids"*) and its
  pattern arm makes the caller's `exclude` **load-bearing for the authorization decision** — a promise
  no consumer in any tree applies.
  **The second half is ours and is the same *sibling arms* miss one layer down.** `handle_snapshot`
  carries a documented confused-deputy check for its `params.prefix` fallback; `handle_merge`
  (287 lines) and `handle_extract` (173 lines) carry **zero authorization symbols** — brace-bounded
  extraction, counting `check_permission` / `check_resource_scope` / `check_path_permission` /
  `caller_capability` / `STATUS_FORBIDDEN` / `capability_denied` / `access_denied` / `matches_scope`.
  `merge` reads no resource target at all and writes wherever `params.target_prefix` says, which is
  `EXTENSION-TREE` §11's *"MUST verify authorization before applying any writes"* and §12.1's atomic-403
  MUST, unimplemented. **core-go implements all three** (`core/tree/operations.go` — snapshot,
  per-path inside the merge loop, extract); we implement one, and one arm getting the fix is how the
  other two stayed invisible.
  **Enforcement, and the tell is a primitive rather than a rule:** when a change touches an
  authorization input that is a path, grep the handlers for the **expansion** primitives —
  `location_index.list(`, any prefix walk, any pattern match against stored paths — and for each,
  state whether the authorizer evaluated the *string* or the *set*. Where it evaluated the string, the
  handler owes either a per-entry filter against the grant (`extensions/query`'s post-filter is the
  in-tree model, and it is the one enumerating consumer that gets it right) or a refusal. A negative
  control is mandatory and it is the non-obvious half: the **child's own path must still be refused**,
  because that row passing is exactly what makes the leak read as a working guard.
  **Ratified 2026-09-13, and the third enumerating consumer is the one where the disclosure is
  DEFERRED: a path-check EXEMPTION is a claim about the exempt operation's upstream PRODUCER.**
  `listing` and `extract` disclose in their own response, so the entry above found them by asking
  what leaves the function. `snapshot` leaves a **33-byte root** and discloses nothing — the caller
  spends it one operation later at `diff`, which `EXTENSION-TREE` §11 exempts from path checks
  *entirely*. Compose them and `diff(empty, scoped_snapshot).added` returns the excluded key **and
  its content hash**, with no authorization run anywhere in the composition: `snapshot` authorized
  the prefix string, and `diff` is exempt by construction. Nothing about §11 or `handle_diff` is
  wrong; the exemption's unstated premise — *a root cannot commit to what the caller may not see* —
  is a proof obligation on `handle_snapshot`, and the entire fix is there.
  **Enforcement:** for every operation a spec exempts from a check, write down what the exemption
  assumes about its inputs and name the function that has to make it true — then test THAT function.
  The grep is the exemption, not the check: `grep -n 'exempt\|no path check\|not authorized here'`
  over the extension specs, and each hit names a producer. And the assertion cannot stop at the
  response: a snapshot body contains neither the key nor the hash under either implementation, so
  the row has to **walk the root** (`collect_all_bindings`) — which is also why no in-tree suite and
  no single-operation vector could have caught it, and why it took a cross-impl check composing two
  operations (`exclude_matrix.snapshot_diff_no_leak`).
  **The second half is about the FAST PATH, and it is the one that would have shipped a green
  suite over a live leak.** The tracked trie root (§3.4) is a *peer-level* artifact built over every
  binding with no caller in scope, so a filter placed only on the rebuild branch is skipped whenever
  a root happens to be tracked — the same request under the same cap leaking or not depending on
  whether a `system/tree/root/{prefix}` binding exists. **A fast path that returns a precomputed
  answer must be bypassed on exactly the condition that makes the filter decide something**, and the
  way to stop those two conditions drifting is to not spell them twice: `cap_filter_active(ctx)` is
  one predicate, used by the bypass and documented as tracking `authorize_path`'s early returns.
  **And the fixture lesson, which is a new shape of *a control the code path can MASK*: a control
  armed with the CANONICAL value cannot observe which branch produced it.** The first draft armed
  the tracker with `build_trie` over exactly the indexed bindings and asserted the cap-free answer
  `== tracked_root` — a **tautology**, because that is precisely what the rebuild branch also
  produces. Measured rather than reasoned: deleting the fast path outright left it GREEN and
  reddened only the pre-existing `test_handler_snapshot_uses_tracked_root_when_present`, which uses
  a fabricated root for this exact reason. The fix is a **sentinel** the other branch cannot mint (a
  key present in the tracked root with no binding in the index). **When a test asserts that an
  optimization ran, the expected value must be one only the optimization can produce** — otherwise
  it measures the answer, and both branches agree on the answer, which is the whole point of an
  optimization. Teeth: `a_snapshot_root_omits_a_binding_the_callers_grant_excludes` and
  `snapshot_under_a_scoped_cap_does_not_take_the_tracked_root_fast_path`, whose three mutations were
  RUN and redden **disjoint** rows (filter removed → both; fast path un-bypassed → only the
  fast-path row, the plain filter row **stays green**, which is what earns that row its existence;
  fast path deleted → the fast-path row and the §3.4 row).
  **⚠ And the boundary this closed does NOT reach, stated because an unstated gap is an exemption:**
  `check_path_permission` has exactly **two** production consumers in this tree (`core/tree`,
  `extensions/query` — `grep -rn 'check_path_permission(' --include=*.rs`), while
  `grep -rn 'location_index.list(' --include=*.rs extensions/` returns ~15 enumerating handlers that
  run **zero** per-entry filter (registry name listing, role assignment/derived sweeps, subscription,
  revision branch/tag listing, relay, identity, local-files). §6.3's sentence says *"the **tree
  handler** returns a listing"*, so whether it binds a **domain** listing is a spec question and not
  ours to decide — routed. Do not read the three-green tree filters as covering the class.

## Tables, matrices, and the argument that decides whose authority

- **A ruling that adds a CLASSIFICATION TABLE can contradict an unchanged MUST in the same
  document, and the fold diff is exactly the wrong place to look for it.** *(Candidate: bit us
  once, 2026-09-11, caught before implementing.)* `0.8.2.21`'s §6.8 answers *"which authority does
  the handler-level check run against?"* with a three-row table, and classes *"a listing entry"*
  and *"a merge expansion"* as handler-derived → **the executing handler's own grant**. §6.3's
  *"Listing filter"* MUST answers the same question for the same subject and says **the request's
  capability** — and it is untouched by the fold, so `git show <fold> -- specs/` (this file's own
  prescribed enforcement for a version bump) shows it to nobody. Implementing the table would
  filter a listing against the §6.9 default self-grant's `/*/*` and hand back exactly the entries
  `F71`/`CP-12a` closed. Same for merge: its expansion derives from `params.target_prefix`, a
  caller-supplied `params` path, which is **row 1 of the same table** and which §6.7 forbids the
  handler to answer with its own grant.
  **The transferable part is that a new table is a RESTATEMENT**, and this file already records
  what restatements do (`L23`: a rule promoted at one site and not swept at its restatements). A
  table is the most convincing possible restatement because it reads as the complete answer.
  **Enforcement:** when a ruling introduces a table, a list, or any enumeration that *classifies*,
  grep the spec for every **other** sentence that answers the same question for the same subject
  (here: `grep -n "check_path_permission" specs/ENTITY-CORE-PROTOCOL.md` — twelve hits, one of
  them the contradiction) and reconcile them before writing code. Where they disagree, **hold the
  narrower one, say so at the `fn` with both citations, and route** — do not pick. The cost of
  picking wrong here is silently re-opening a closed disclosure, which no oracle can see because
  both readings produce a well-formed response.
  **⭐ Ratified 2026-09-15, and the second bite makes the enforcement CHEAPER rather than harder,
  because the table CITED the section it contradicts.** `EXTENSION-TREE` v4.11 §2.2a declares, per
  operation, whether a resource-optional op's absent case is **BROAD** (refuse the self-excluded
  case `400 path_required`) or an **optional FILTER** (answer it empty) — the field `0.8.2.25` says
  three implementations were each inferring privately, and it is a genuinely good rule. Three of its
  eight rows are wrong against the same document:
  - `diff` is declared `resource` **required**, and **§4.2 — the section the row cites — says *"the
    `resource` field is optional; when omitted, handler-scope authorization (§11) suffices."***
    `diff` compares two *content-addressed snapshot roots*; it has no path subject to name.
  - `create` and `destroy` are declared **required**, and §7.2/§7.3 give them `params` of
    `system/tree/config` (a `tree_id`) and `primitive/string` (a `tree_id`) — no path — while §7.4's
    own authorization table, untouched by v4.11, reads *"Handler scope only"* for both.
  Measured before reporting rather than read: **core-go's `handleDiff` requires no resource either**
  (`core/tree/operations.go`, and their `path_required` sites are `get`/`snapshot`/`extract` only),
  so implementing the column verbatim would have made *us* the one seat refusing `diff` — including
  the `snapshot`→`diff` composition our own `exclude_matrix` leak fix depends on, and go's
  `convergence.extractAndMerge`. **The three BROAD rows are right and we already conform; it is the
  `required` column that was filled in by symmetry.**
  **So the enforcement gets a first step that is cheaper than the grep:** a classifying table's rows
  usually carry a **section reference**, and the reference is the reconciliation target — read the
  cited section *before* the rest of the document. A row whose own citation contradicts it is the
  easiest possible catch and the one most likely to be skipped, precisely because the citation reads
  as provenance rather than as a claim. Second step unchanged: the sentence elsewhere that answers
  the same question for the same subject (here §7.4's table, which v4.11 did not touch). And the
  disposition is the entry's existing one and it held: **hold the narrower reading, implement
  nothing from the disputed column, and route it** — a table with three bad rows out of eight is
  not a thing to implement selectively on your own reading of which three.
  **Corollary, and it is the larger half of this bite: an obligation stated in CORE but discharged
  in EXTENSIONS is landed in exactly one extension on the day it lands.** §3.3 now requires *every*
  resource-optional operation to declare BROAD or FILTER. `EXTENSION-TREE` §2.2a does, for its
  eight. The other **25** extension specs do not (`grep -l 'BROAD' specs/extensions/*.md` → one
  file), while 26 files in `extensions/` here read a resource target — so the field the ruling says
  must stop being inferred is still inferred everywhere but one handler. It also leaves
  `CORE-RESOURCE-TWO-EMPTIES-1` arm **(c)** — the optional-FILTER arm — with **no declared subject
  anywhere in the corpus**, so that arm is undrivable rather than merely unimplemented. **Check the
  denominator before scoping a per-operation obligation**, and report the count upward: one
  extension conforming is the start of the work, not the end of it.
- **A rule about an EXCLUDE is a rule about a matrix, and the axis nobody enumerates is the
  ARGUMENT the check is asked about.** *(Candidate: bit us once, 2026-09-12, and the finding came
  out of auditing a sibling's sweep rather than our own.)* `0.8.2.21`'s H1 is *"an unmatchable
  exclude excludes everything"*, and our four-site sweep at `9beb723` was complete **on the axes
  the ruling names** — the sites that read an exclude, × include/exclude, × concrete/pattern. go's
  `77da7ea` then closed five coordinates on axes the ruling does not name (the handlers dimension
  at both read sites, the authoring gate walking handlers as well as resources, the §5.2 pattern
  arm, and the §8.2 listing/extract filter), and go's own ratchet calls the lesson *the matrix
  blast-radius*. Re-running that matrix against **our** tree found three more, and none of them is
  an exclude-reading site at all:
  - **`extensions/query`'s step-6b filter read `resources` only, across EVERY grant.** So a path
    covered by grant B was enumerated for a query grant A authorized — `{handlers:[system/inbox],
    resources:[/{p}/secret/*]}` beside a narrow query grant enumerated the secret subtree.
    Measured: `["secret/s","users/alice"]` where one path is authorized. §5.2 answers **all
    dimensions from one grant entry**; a filter that consults one dimension across the union of
    grants is `F67`'s shape reached from a filter instead of a bypass. It also used the wrong PR-8
    frame and skipped the check entirely under the `content_store` allowance. Fix is the one
    function §5.2 step 6b names — `check_path_permission` — never a local predicate.
  - **`core/peer/src/http_live`'s content face decided membership with an open-coded literal scope
    test** (`h == "*" || h == "system/tree"`). A *patterned* handler exclude (`system/*`) and an
    *unmatchable* one (`*/tree`) were both invisible to it, `resources.exclude` was never read on
    that face at all, and there is no second layer behind it. This is go's G-3 in a file go does
    not have.
  - **`core/tree` asked §6.3 about the wrong ARGUMENT, and this is the transferable half.**
    `EXTENSION-TREE` §11's `map_operation` is closed — `get`/`snapshot`/`extract` → **`get`**,
    `put`/`merge` → **`put`** — and says whose job it is: *"performed by the handler, not by
    `check_permission` or `check_path_permission` — those functions receive the already-mapped
    permission name."* We passed `ctx.operation` through unmapped at `handle_snapshot` and
    `handle_extract`. The dispatch check asks the grant's `operations` about the **literal** name
    and the path check must then ask about **`get`**; ask it about `"extract"` and it agrees with
    the dispatch check, so a grant of `{operations:{include:["*"], exclude:["get"]}}` sails through
    both and `extract` returns an envelope of every bound entity under the prefix (`200` where the
    mapped question answers `403`, both sites mutation-measured). **The exclude was well-formed,
    the matcher was correct, the site was one of the four we had just fixed — and the check was
    asked a question whose answer does not bind.** Both siblings map (go's `checkPathPerm` takes a
    literal `"get"`/`"put"` at all seven of its sites; py's `check_caller_permission("get", …)`),
    so this was rust-only and invisible to every cross-impl row.
  **Enforcement, and it is three greps, in this order.** (a) For any rule about a *scope*, grep for
  **re-implementations** rather than for the rule's name — the tell is a literal comparison
  (`== "*"`, `.contains(`, `.iter().any(|h| h ==`) or a containment helper standing in for
  `matches_scope`/`matches_id_scope`/`check_path_permission` on a path that is *implementing a
  scope*. (b) For every authorization call, read the **arguments** against the spec's own
  parameter list: which permission, whose capability, whose frame — a correct predicate asked the
  wrong question is a fail-open with nothing wrong at the site. The enforcement point we shipped is
  the *parameter name*: `authorize_path(ctx, base_permission, path)` has no `operation` to fill
  from `ctx.operation`, and each caller names the §11 row it applies. (c) For any enumerating
  handler (`location_index.list(`, an index scan, a trie walk), ask whether its per-entry filter is
  `check_path_permission` or a local approximation; `extensions/query` was cited **in this file**
  as *"the in-tree model for an enumerating consumer"* and was the weakest of the three.
  **And the reporting half: a green cross-impl category is not evidence about any of them.**
  Measured before citing: `query` 47P/0F contains **zero** `Exclude` in any grant it delegates and
  **zero** omission assertions, so it cannot witness step 6b; `tree_operations` 62P/0F drives
  `extract` on the connection's broad cap, so it cannot witness the §11 mapping; `serving_mode`
  runs `NamespaceScope`, not `CapTokenScope`. Three surfaces, three greens, three vector asks —
  the same shape as `CORE-TREE-LISTING-1`, which we had already filed against ourselves.
- **An authorization call has a parameter that decides WHOSE AUTHORITY is being spent, it is
  tested upstream of every dimension, and a wrong one is indistinguishable from a broken
  matcher.** *(**Ratified 2026-09-13**: this is the third instance of *a correct predicate asked
  the wrong question*, and the first where the wrong argument is wrong in **both** directions at
  once.)* §6.3's `handler_pattern` is **the handler that OWNS the operation being authorized,
  never the handler running the check** (0.8.2.23). `extensions/query`'s step-6b filter passed
  `ctx.pattern` — `system/query` — while authorizing a **tree read**. Every worked example in the
  corpus and core-go's own line (`ext/query/handler.go:605`) pass the literal `"system/tree"`.
  **The two-direction part is what earns the ratification**, because a one-direction error is a
  bug and a two-direction one is an argument nobody owns: the wrong frame **refused** the
  conformant split `{system/query: find}` + `{system/tree: get}` (the tree grant is discarded
  unread — no grant naming `system/tree` survives a `handlers` test against `system/query` — and
  the surviving query grant then fails `operations` on `get`, so **every result is dropped**),
  **and admitted** a caller holding only `{handlers:[system/query], operations:[find, get]}` and
  no tree grant at all. Note the tell: the symptom of the first direction is *"the filter returns
  nothing"*, which reads as a **scope** defect and sends you to the matcher.
  **The other three frame-bearing sites here were already right, and one of them proves the rule
  is not "always pass a literal":** `core/tree` passes `ctx.pattern` and is **conformant**, because
  there owner *is* runner — which §6.3 names explicitly. A literal in query and `ctx.pattern` in
  tree are one rule. "Hard-code `system/tree` everywhere" is a different and wrong rule.
  **Enforcement.** For every `check_path_permission` / `check_permission` call, answer at the call
  site *which handler's namespace does this access land in?* — and if the answer is not the
  running handler, the frame is a **literal**, written out, with the owning handler named. Grep
  `ctx.pattern` on any path that authorizes something: the hits that are correct are the ones where
  the handler is authorizing its **own** surface. This is the same family as the §11
  `map_operation` bite (`74e2afb`) — *a correct predicate asked the wrong question is a fail-open
  with nothing wrong at the site* — with the argument being *whose authority* rather than *which
  permission*.
  **And the reporting half, which is the larger finding and was MEASURED: no vector in the cohort
  can see this.** Frame defect restored, **peer rebuilt** (`dirty=true` at HEAD, label checked),
  re-scored: `query` **48P/0F**, `security` **31P/0F**, `capability` **18P/0F**, `tree_operations`
  **64P/0F** — 161 rows, four categories, none of which reddens. The cause is the one already
  ratified here: every grant those categories delegate either names **both** `system/query` and
  `system/tree` (`query.go:679` — both frames allow) or omits `get` (`query.go:744` — both frames
  deny), so **the two frames agree on every row that exists**. *Whenever an outcome is reachable
  from more than one source of authority, a check set that never makes the sources disagree
  measures their union.* The discriminating pair is the two rows above, and they must redden in
  **opposite** directions — that is what separates a wrong frame from a merely narrow one. Teeth:
  `the_tree_read_filter_is_framed_by_the_owning_handler_not_the_running_one`, three mutations RUN.
  **Corollary on the cohort:** all three seats reported K4/K5 as conforming by **reading four call
  sites at the line**. That is honest and it is not a measurement, and neither is a green category —
  say which one you have.
  **And the half that was owed onward, landed 2026-09-13: "we have the vector built" was a
  claim about an IN-PROCESS test, and a vector is defined by the boundary it crosses.** The
  packet offered the discriminating rows to arch and keystone on the strength of
  `the_tree_read_filter_is_framed_by_the_owning_handler_not_the_running_one` — which sets
  `ctx.pattern` and `ctx.caller_capability` **by hand** on a constructed `HandlerContext`. That
  proves the filter's logic and says nothing about whether a real capability, carried on a real
  envelope through `verify_request` and the §5.2 dispatch check, **arrives** at the filter as
  the authority the rule names — which is the entire question when the artifact is a check three
  seats will be scored against. **An in-process row and a vector are different artifacts with
  the same assertions, and the word "built" hides the difference.** Landed as
  `core/peer/tests/handler_frame_vector.rs`: a peer, a handshake, a capability minted and signed
  by the server and presented on the EXECUTE, and an assertion on the decoded `matches` key.
  Both mutations were RUN against the wire rows and reproduce the in-process table exactly —
  `&ctx.pattern` reddens **both** rows in **opposite** directions (row 1 `[]`; row 2 disclosed
  the qualified path under a capability holding no tree grant), `"*"` reddens **row 1 only**
  (it fails closed at this matcher, per the prediction-was-backwards note above). Two fixture
  obligations the build earned, both of which would have made the rows lie: **put before bind**
  — `IndexingLocationIndex` reads the entity out of the content store to learn its type, so a
  bind preceding the put indexes nothing and *every* row goes trivially empty, passing row 2 for
  no reason — and **an empty 200 is not a 403**, so `drive` returns the refusal status as a
  distinct outcome rather than folding it into "disclosed nothing," which is what stops row 2
  passing because the request never reached the filter (the same unmeasurability the §7a.1
  fixture-guard entry records). **Enforcement: when offering a row to the cohort as a vector,
  state the boundary it crosses in the same sentence — and if the answer is "a `HandlerContext`
  we built," it is a floor under a vector, not one.**
