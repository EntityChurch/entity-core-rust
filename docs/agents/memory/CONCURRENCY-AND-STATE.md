# Concurrency, shared state, and residue

> Read-modify-write on state a cascade can re-enter, hot-path caching, collectors for spec'd writes, and what a previous attempt leaves behind.

Working memory for `entity-core-rust`, indexed from
[`INDEX.md`](INDEX.md). Entries are **findable by symptom** — the bolded lead
sentence is the shape you arrive with. Each carries its mechanism, its
enforcement point, and its provenance (the promotion ladder needs the source
commit; that is provenance, not session narration).

**An entry that could become a check SHOULD become one — and is then deleted
from here.** Memory is where a finding waits while it is still only prose.

## Hot paths

- **Hot paths:** `SyncTreeHook`/`on_tree_change` engines MUST cache their decoded config in
  `RwLock<...>` and refresh only on events under their own config subtree — never
  `location_index.list()` + `content_store.get()` + decode per put (that was a 100×+
  regression). Canary: `core/peer/src/lib.rs::perf_treeput_1100` (`--release`).

## Read-modify-write and the comment that claims serialization

- **A comment asserting a concurrency invariant MUST name the construct that enforces it —
  and a read-modify-write on shared state is a defect until it does.** *(Candidate: bit us
  once, `7776675`, and it cost a sibling ten days of wrong analysis.)* `auto_version_once`
  advanced the revision head with a plain `set()` under a comment reading *"SyncTreeHooks fire
  synchronously within a single cascade thread; cross-thread contention is handled by the
  NotifyingLocationIndex cascade discipline. A plain set() is conformant under that
  serialization property."* **There is no such property.** `set_impl` mutates the inner index
  and then calls `dispatch_event` holding no lock, so N writers run N cascades — and N copies
  of every hook — in parallel. The comment named a mechanism (*"the cascade discipline"*) that
  does not exist as code, and nobody checked, because prose that sounds like an invariant reads
  like one. `RootTrackerEngine::apply_event` had the same shape with no comment at all. The
  cost was not only ours: meta's cross-impl read declared rust *"structurally exempt"* from
  go's last-burst-write loss **on the strength of this comment**, so the analysis that should
  have found our bug cited it as the reason we could not have one.
  **Enforcement.** Grep the pattern, not the prose: a `get(...)` / `list(...)` followed by a
  `set(...)`/`put(...)` to the **same path** in one function is a read-modify-write, and on any
  path a `SyncTreeHook` can reach it needs CAS+retry or a lock, named at the `fn`. When you
  write a comment claiming serialization, cite the **type and the field** that provides it
  (`Mutex<_>` at `X::y`) — if you cannot, you have found the bug. And prefer CAS to a lock on
  any path whose write re-enters the cascade: a per-prefix mutex in `auto_version_once` would
  deadlock, because a universal-prefix config routes that write back through the root tracker
  into the same function for the same prefix.
  **The other half, and it is why the in-tree suite could never have caught this: an
  in-process load test is not a net for an in-process race.** An 8-writer × 40-round burst
  through the real `NotifyingLocationIndex` + tracker + revision chain **passed with the head
  advance mutated back to the broken `set()`** — the window between the read and the write is
  nanoseconds when there is no socket in the path, so the scheduler never interleaves. It was
  written, measured against the mutation, found toothless, and **deleted rather than kept as
  reassurance**. What works is a forced interleave: a `LocationIndex` decorator that fires a
  one-shot injected write on the first read of the watched path, *after* sampling the value the
  caller gets back (`InterleaveOnRead`, in both `core/tree` and `extensions/revision`). That is
  deterministic, single-threaded, and mutation-RED every time — the same conclusion core-go
  reached from the other side (*"net it with a deterministic forced-interleave test, not
  `-race` or test-starved"*). Corollary for reporting: **a concurrency fix's wire number is the
  evidence; the in-tree green is not.** Ours went 4-of-8-lost → PASS 5/5 at ~30ms, and the
  image label must read `dirty` at your HEAD or you measured a stale binary.

## A MUST-write owes a collector

- **A MUST-write owes a named collector, swept BEFORE the write.** A spec'd write with no
  reaper is a leak by construction (CONTINUATION v1.23 §3.4 A.1 — ~1,440 marker nodes/day
  against one dead peer). When adding the reaper: sweep at the top of the bind path, never
  after it — an entry whose *origination* timestamp already predates the window would
  otherwise be removed by the very call that wrote it, which reads from outside as the write
  silently failing. Wire it at **every** binder you actually run, not just the one that owns
  the sweep code (here: the continuation handler *and* the dispatcher's `rejected` markers,
  which are caller-driven and unbounded). Reference: `extensions/continuation/src/marker_collect.rs`;
  the ordering is held by `test_distinct_timestamps_yield_distinct_paths` /
  `test_path_safety_sanitization` / `test_mirror_pointer_in_body`, which fail if the sweep
  moves after the bind.

## Residue from a prior attempt

- **Residue from a PRIOR attempt is an input to the next one — failed OR completed — and a suite
  that only ever runs one attempt cannot see it.** *(**Ratified 2026-09-15**: bit us twice the
  same day, the second time through the first fix — see the end of this entry. First bite found
  by `entity-browser-rust` reading our source after a long session stopped recovering, not by
  any gate of ours.)* Two §6.5 defects, one shape. (a) The signaling bucket outlives a
  negotiation: an offerer that times out re-offers under a fresh session and its abandoned offers
  stay collectable for the TTL, oldest first, so `find_counterpart_offer`'s *first* match
  answered a dead session on every retry — the peers met at the node and never connected, and a
  browser reload changed nothing because the residue lived in the node. (b) `PeerCarrier` cached
  its node connection **outside the pool**, so none of the pool's demote-and-redial touched it and
  the first transport failure was permanent. Every negotiation test started from an empty bucket
  and every carrier test from a fresh dial, which is exactly the one state a long session never
  returns to.
  **Enforcement:** for any operation a caller retries (a negotiation, a dial, a reconnect), write
  the row as **attempt 2 after a failed attempt 1** and assert on what attempt 1 left behind; and
  for any connection/handle cached outside `RemoteState`, name its eviction at the struct (`grep
  -rn 'Mutex<Option<Arc<' --include=*.rs core/peer/src`). Teeth:
  `an_answerer_answers_the_newest_offer_not_a_stale_one_still_in_the_bucket` (signaling) and
  `a_carrier_redials_after_losing_the_node` (core/peer, `--features signaling`), whose two rows
  were RUN against each half of the fix and redden **disjointly**: no before-use `reader_ended`
  check reddens *closed by the node* only, no evict-on-error reddens *gone silent* only.
  **Second bite, and it came through the fix: a SELECTION rule is a claim about a set of two or
  more, and the residue that matters is usually a set of one.** `c3f2b76` made the answerer take
  the *newest* offer so it would skip abandoned ones. A **completed** negotiation leaves residue
  too — the counterpart's offer beside our own answer to it — and once the counterpart's channel is
  up it stops offering, so that consumed offer is the only one in the bucket, where newest and
  first are the same choice. Any later negotiation from the answerer (re-establish, teardown)
  answered it again, an answer no offerer will read (`find_answer` and go's `FindWebRTCAnswer` both
  take the first). `entity-browser-rust` measured it as K-6: answerer 8/12/16 deposits against one
  offer. **The routing's framing pointed at the wrong side**, and reading it per role is what found
  it. *"One caller 12–16, the other 4, where the old kernel gave 8 and 4"* was true, and it hid that
  the heavy side had **flipped** from offerer to answerer. The node's `offer: deposit` line also
  counts every carrier deposit, ICE candidates included, not just SDP offers. What separated a
  re-negotiation from a candidate re-trickle was the collect sequence: `included_count` 4→8→12→16,
  one collect per burst, against a destructive drain and a node that dedups identical blobs.
  **Enforcement, extended:** the attempt-2 row is owed after a **completed** attempt 1 as well as a
  failed one. For any "pick the best of the residue" rule, write the row where the residue has
  exactly **one** member and it is the wrong one. When a routed measurement is a count, break it
  out per role and per read before theorizing, since a one-sided summary can hide which side moved.
  Teeth: `an_answerer_never_re_answers_an_offer_it_already_answered`. Mutation (drop
  `!already_answered`) was RUN: row 1 reddens, and row 2 (answer the counterpart's *new* offer) is
  green, verified in a second run with row 1's assert neutered. The skip keys on the answer's
  **verified signer**, never on the session alone, so a third party cannot deposit an answer to
  suppress a live offer.
