# entity-core-rust — status

_Updated: 2026-08-14 · public: v0.8.0 (master)_

## Where it is

entity-core-rust is the Rust reference implementation of the Entity Core
Protocol (v7.9) — a clean, ground-up implementation, one of three independent
references alongside the Go (oracle) and Python peers. Downstream, the
entity-browser and Godot apps consume it via a Cargo **git dependency pinned to
a release tag**, so a lone clone builds standalone (no sibling checkouts
required).

The workspace is a strict, cycle-free crate DAG — `core/*` (ECF deterministic
CBOR → hash → entity → crypto/store/types → capability/wire/handler →
protocol/tree/peer, with `entity-core` as the facade re-export) — plus opt-in
protocol extensions (`extensions/*`), language/runtime bindings (`bindings/*`:
C FFI, Godot GDExtension, a higher-level SDK, and the wasm-worker stack), and
CLI tools (`entity`, `wire-conformance`, `fetch-published-fixture`). One
codebase serves three deployment roles: data toolkit, embedded peer, and
standalone server.

**Maturity: public research-preview, tagged v0.8.0.** Broad feature coverage —
all seven base extension handlers (inbox, continuation, subscription, clock,
revision, history, query), the identity/role/quorum/attestation trust stack,
the messaging/transport extensions (relay, route, discovery, registry),
encryption, compute, type-system, and WASM compatibility across every crate.
Crypto agility (Ed25519 + Ed448 keys, SHA-256 + SHA-384 hashes) is a
runtime/connection property negotiated in the handshake, not a build flag.
Known gaps are tracked in `docs/BACKLOG.md`; spec under-specifications found
while implementing are logged in `docs/SPEC-AMBIGUITIES.md` and routed upstream.
The protocol is **not** locked at 1.0, but the core wire format, capabilities,
and tree semantics are interop-validated against the Go and Python peers, not
just self-tested.

## Where we left off

_2026-08-14 (b) — **the admin-seeded posture is expressible on rust's wire; `--seed-policy` is the
flag core-go asked for.**_

Core-go's `2026-08-14-c` report was accurate about us: `entity-peer` had `--debug-grants` and
nothing between it and the bare §4.4 floor, so the EXTENSION-ROLE §4.7 initial-grant gating family
could not be measured against a rust peer at all — open access hides the gate, and full restriction
denies the validator its own setup. Built the third posture: `entity peer start --seed-policy
<file>` reading the **keystone canonical** schema (`{version:1, entries:[{grantee, grants}]}`), the
same document go's `--seed-policy-file` and python's `--seed-policy` take; `PeerBuilder::
with_seed_policy_from_file` closes the builder-doc deferral that was waiting on exactly that
ratification. `self` skipped, `version != 1` refused, and both pre-convergence shapes (go's old
`[{pattern,grants}]` array, python's keyed object) refused with the expected shape in the error.
Gate: `make test` **2067 / 0F** · clippy · fmt · wasm. Outgoing packet:
`ROUTING-2026-08-14-rust-wired-the-seed-policy-flag-*`.

**Three things went back with it.** `peer-manager` cannot start a rust peer in the posture yet for
two reasons that are ours to name: the seed file is written to the host's `os.TempDir()`, which is
not inside the `~/.entity`-only bind mount a containerized rust peer sees; and `startRustPeer`
appends `--debug-grants` unconditionally, which rust now **refuses** alongside `--seed-policy` at
argument parse — a misconfigured admin-seeded peer fails to start rather than coming up green and
silently non-restrictive. Third: we fail closed on `bounds`/`constraints`/`allowances` where go's
loader accepts and silently drops them (all three narrow authority, so dropping one widens the
grant); that divergence in what a peer *accepts* is routed to go + the format owners rather than
settled unilaterally. Also flagged to keystone: the canonical example carries a `_comment` inside
an entry, which its own `additionalProperties: false` schema forbids. **Not claimed:** that the
three `role_stage2_recognize_on_attest_*` rows pass against rust — they remain unmeasured until
`peer-manager` can start the peer.

_2026-08-14 — **core-go's control row caught a merge defect we had built from the pseudocode,
and four blocked rows were hiding three more.**_

Their §4 packet carried two items: one filed as a finding, one filed explicitly as *not* a bug
report because their probe could not establish it. **The one they did not file is the defect.**
Outgoing packet: `ROUTING-2026-08-14-your-observation-was-a-defect-*`.

**§4.4.4 states the oscillation check twice and the two disagree.** Invariant (3) (v3.2, A.3)
is normative and pins the comparison to the candidate's **full identity** —
`{root, sorted_parents}` — naming the consequence of getting it wrong: same-root-different-parents
is a legitimate cross-link, and treating it as oscillation *"leaves heads stuck at divergent
terminals — convergence becomes impossible."* The `detect_oscillation` pseudocode two screens
down takes no parents and compares the root alone. **We had built the pseudocode.** When every
conflicted path keeps its local side — `three-way`, `target-wins`, `manual` all do — the merged
root equals the local head's root, so the check fired on the first merge against any diverging
remote, on a fresh peer, with none of §4.4.4's four cycling preconditions present. Fixed to the
invariant; the pseudocode contradiction is logged and routed.

**Behind their control sat three more, all ours, none visible while it failed.** Per-type
merge-config was skipped for the canonical shape (our decoder demanded a `pattern` field that a
type-scoped config has no reason to carry); step 1 consulted one type instead of §5.1's
local-then-remote; and `lww` / `handler` were swept into the default arm — the exact v3.10
defect, in our tree — instead of degrading to a conflict entity. Their item 1 (the `handler`
sentinel with no companion path, now `400 invalid_strategy` at config-write) is built with its
own accepted-with-path control.

`revision` **97 P / 6 F → 103 P / 0 F**; full surface **1452 P / 18 W / 0 F / 28 S (1498)**,
zero failures anywhere. Four mutations executed, each failing exactly the rows that claim it.

**CONTINUATION v1.22 §4.3 landed in the same cycle**, and it closes the ambiguity we routed on
08-13: arch ruled the bundle MUST carry a `system/peer` for every granter **and grantee**, and a
bundler that cannot resolve one MUST fail at bundle time with `chain_unreachable` rather than
dispatch an incomplete bundle. Built both halves — grantee collection (previously picked up only
where a grantee happened also to be a granter, which is why a self-rooted cap passed and a §4.2
case-3 chain did not) and the fail-closed dispatch. Convergence is **99 P / 0 F in both
directions**, including **rust(A) → go(B)** — the pairing that drives our bundler and that no
prior run had exercised. §3.6a and §3.6b remain unbuilt.

**One finding routed outward rather than fixed:** the three `role_stage2_recognize_on_attest_*`
convergence rows are order-dependent — green on a fresh peer, red on a peer that has served one
full single-peer run — and **go's own peer reproduces it identically**. The handshake unions the
resolver's answer with the `system/capability/policy` table's `default` entry (V7 §4.4/§8, which
go implements the same way), and an earlier category leaves such an entry carrying the
validator's own wildcard grants. Same shape as the leak core-go caught in themselves this cycle.
Measured on four runs across both implementations before routing it, because our first sighting
was on a peer that had served a full run and reading it as our regression would have been wrong.

**Named, not glossed:** §5.3 delegation is unbuilt here — we degrade unconditionally, so the
degrade row passes against us for a reason weaker than it looks, and we take no position on
A-6 E1 until we have something on the wire to be wrong about. `system/substitute/http` is still
unwired (the crate has no consumer; registering it is a caller-triggered outbound-GET posture
decision, not a line). CONTINUATION v1.22 is next, starting with §4.3 bundle completeness —
which is also arch's answer to the ambiguity we routed on 08-13.

_2026-08-13 — **§6a.9.3 built the same day it was ruled, containment audited clean, and the
rexec seam is a verifier MUST the bundler cannot keep.**_

Four items came in from arch and core-go; all four are answered. Gate: `make test`
**2044 / 0F / 0S** · clippy · fmt · wasm — all green. Outgoing packet:
`ROUTING-2026-08-13-q-*`.

**`EXTENSION-REGISTRY` §6a.9 + §6a.9.3 are built.** The 08-12 carrier ruling closed our
three-way divergence — `register-request` answers in its own
`system/registry/register-result` on both branches, and the 200 was the worse half (a bare
`{binding_hash}` under `system/protocol/status`, with the ruling's discriminator absent from
the success branch and nothing measuring it). Arch then filled §6a.9.3 the next day and
**named the withheld `pending_hash` as their own defect** — *a `MUST` may not name a referent
the corpus does not define*. Holding was the right call; the referent now exists. Body,
by-request pointer, supersession, approve/deny, retention, and both new vectors
(`REG-PENDING-HANDLE-1`, `REG-PENDING-DECIDE-1`) are in.

**Building it found three unpinned things**, two of which core-go hit independently: `deny`
returns a `status` the result type does not declare (the same self-recorded defect §6a.9 was
written to fix, reproduced one section down), the decision ops have no input type, and no code
is pinned for deciding a **superseded** head — a case §6a.9.3's own supersession rule creates,
and one our first draft let through. All three in `SPEC-AMBIGUITIES`, routed.

**Path containment: clean, and clean for a different reason.** Our resolver walks every
component below the root, so the escaping-parent case never had a leaf-only defense to slip
past — that walk exists because we hit §8.3 V4a from the other direction (a trailing `/` makes
`lstat` resolve the link). Three impls, three mechanisms, and all three had a *correct helper*
— which is the argument for auditing at the handler. The audit still found two real gaps: no
`list` through an escaping **parent**, and no fixture teeth. Both closed, mutation-verified —
and the mutation taught us that a `read` leak rides a `content` handle rather than inline
bytes, so a body-byte assertion reads clean on the case that leaks hardest.

**`EXTENSION-SUBSTITUTE` is worse than unmeasured — it has no trigger.** Exhaustively: no
crate outside `extensions/storage-substitute-*` depends on either crate, `ChainConsultHook` is
constructed only in its own test, and the content handler passes `claimed_source_peer_id:
None`. Now a declared exclusion with an executed mutation.

**`rexec_delivered` — B rejects, and it is a spec seam we routed back.** Two verifier MUSTs
(step 2a per-link grantee resolution → 401; PR-8 granter canonicalization → 403) depend on
identity entities that `collect_chain_bundle` collects **best-effort** — identically in rust
and go. §4.2 case 3 puts a third-party installer in the chain, so whether B can authorize
depends on whether A's store happened to hold that installer's `system/peer` entity. A
self-rooted cap collapses granter and grantee onto peers both sides already have, which is why
go→go and go→python pass. **The mechanism is verified and pinned by two new tests; the
incident is not** — we have not run core-go's repro, and the packet names the one-run probe
that separates the two candidates.

---

_2026-08-12 — **go measured us and F-1 was ours too — structurally, not intermittently.**_
(`ROUTING-2026-08-12-your-f1-was-ours-too-and-the-audit-found-it-on-our-handshake.md`;
evidence `docs/validation/reports/2026-08-12-the-a1-eviction-orphaned-our-escalation-too.md`.)

Three commits, answering the packet's sections 1, 3 and 5. Measured against Go oracle
`c475a88`, peers built from `7aad422`:

| Pass | Result |
|---|---|
| 1 — all surfaces, closure scope | `1594 · 1580 P / 10 W / 4 F / 0 S` (29 `[self]`; peer-attributable 1565) |
| 2 — `serving_mode`, namespace scope | `55 · 55 P / 0 W / 0 F / 0 S` |
| 3 — `registry_issuer` | `19 · 19 P / 0 W / 0 F / 0 S` |

`make test` 2033/0 · clippy · fmt · wasm green. Zero skips on every pass —
`origination` and `peer_issued` are armed, not allowlisted. **The 4 F are a harness
posture artifact, proven with a control**: a *go* peer under the same
`--publish-root --serve-closure-root` posture fails the same four `serving_mode` T4 rows
with the same text, because `seed_out_of_scope` binds where only *namespace* scope makes
it out of scope. They pass 55/55 in pass 2.

- **§5.4a `[MUST]` — the §A1 eviction was killing the loop that owes the escalation**
  (`bb34557`). `liveness_escalate_after_eviction` FAILed at `21eb223` (19.161 s, terminal
  `suspect`/`transport-error`); now 5/5 over four consecutive runs. **Worse here than in
  go:** theirs read as a 1-in-4 flake because two paths raced; ours had no race, so on a
  transport-first episode the escalation was unreachable 100% of the time — the peer
  stayed `suspect` forever and §4.1 reconnect never fired. Both halves vectored; the
  negative half is in-process per §5.4a's satisfaction mode, mutation-verified, and
  declared at `docs/validation/CONFORMANCE-EXCLUSIONS.md` (a declared exclusion is not a
  pass and is counted in no number above).
- **R-7 — the extractors, not the checks** (`d19ac29`). Thirteen sites in seven files
  dropped the peer's error `code` on a non-2xx. The handshake was the bad one: hello and
  authenticate discarded `resp.result`, so every coded refusal a responder builds reached
  the dialer as a bare number — our negotiation vectors assert those codes only
  responder-side. Five surfaces audited clean and said so.
- **§6a.9's 202 carrier — holding, not converging** (`7aad422`). Logged in
  `SPEC-AMBIGUITIES` while `spec-issues/2026-08-12-c` is open. One packet number
  corrected by measurement: `registry_issuer` is 19 P / 0 W here, not 18 P / 1 W — the
  loosened check WARNs on the *error-code* carrier, which is go's shape.

<details>
<summary>2026-08-11 (b) — core-go's peer packet is through, and it led with a live
security hole in our tree</summary>

_2026-08-11 (b) — **core-go's peer packet is through, and it led with a live security
hole in our tree.**_
(`ROUTING-2026-08-11-b-the-packet-is-through-and-the-security-hole-is-closed.md`.)

Six commits, plus the nine that had been sitting unpushed. Measured against Go oracle
`76d4775`, **all three passes at zero failures and zero skips**, every pass exit 0:

| Pass | Result |
|---|---|
| 1 — all surfaces, closure scope | `1569 · 1558 P / 11 W / 0 F / 0 S` |
| 2 — `serving_mode`, namespace scope | `55 · 55 P / 0 F / 0 S` |
| 3 — `registry_issuer`, registry posture | `18 · 18 P / 0 F / 0 S` |

- **`revoke`/`renew` verified nobody** (`0caf911`) — REGISTRY §6a.9 `[RULED
  2026-08-11]`. Any peer that could reach the registry could permanently revoke any
  binding in it; revocation is monotonic, so there was no undo. All three impls
  shipped it, because §6a.9 named a proof vector for `register` and none for the other
  two — *the vector list, not the prose, is what got implemented against*. go predicted
  our `registry_issuer` would drop 16/16 → 16/18; it went to **18/18**, because the fix
  landed before the measurement. Our own two acceptance tests sent **unsigned** requests
  and passed, which is GUIDE-CONFORMANCE §2.4a's point reproduced exactly.
- **`system/peer` pinned to the floor** (`c2c1c60`) — §4.5a item 1a. We had it wrong in
  both directions (active format on the wire, home format at rest) and every test we
  had passed, because the two agree while both are the floor. Deleting the format
  *parameter* rather than defaulting it surfaced four sites. **rust independently
  derived all six values in go's v767 M3/M6 re-stamp proposal and matched its bytes
  exactly** — corroboration, not ratification; the corpus still carries the stale pins.
- **§3.3's second case** (`ba8b0bd`) — our `2ac8ed2` fixed `:announce` and left
  `:announce-stop` answering an idempotent 200 for every `profile_ref`, never asking
  the resolution question. go's packet said "verify against the two-case shape rather
  than assuming your existing fix covers both", and it was right.
- **The `notification` cut** (`d90610e`) — the open question ("may one round contain
  two strings?") is answered by the ratified banner: *one round, two strings*.
- **Containment read, not probed** (`c459905`) — rust is **not** exposed to go's §8.3
  boundary bug, by two invariants that are not boundary checks (trailing-slash prefix
  normalization; `Path::strip_prefix` being component-aware). Both now pinned.

**The delegated-cap question is answered, and our previous reasoning was wrong.**
A delegated child cap does **not** register in rust, and `403` is the spec-required
answer — §5.5a makes peer-relative cap resources **granter-local**, so a
client-granted cap reaches nothing in the responder's namespace. Nothing about
delegation decides it; the granter frame does, and our earlier "points toward yes"
was looking at the wrong dimension entirely. go withdrew the same theory after
reading the same passage. Proven with a control (`/*/*` **is** admitted) rather than
argued: `foreign_granted_peer_relative_resources_reach_nothing_locally`.

**py's `system/*` reservation hole is not ours** — go's new
`core_register_reserved_refused` and `core_register_reserved_publishes_nothing` both
PASS against a rust peer in the gate above, the negative half included.

**F-1 (go's flaky liveness check) narrowed for them:** 8/8 green against a rust peer
with go's exact envelope, spread **5.039–5.045 s** — a 6 ms band where go's peer is
bimodal 1-in-4. Rules out the validator and jitter; the ordering means go's suspected
suspect-then-demote interaction was exercised and stayed green against a second impl.
Report: `docs/validation/reports/2026-08-11-rust-delegated-cap-answer-and-f1-liveness-data.md`.

*Superseded 2026-08-12: that 8/8 was an honest pass over a surface it could not reach.
`liveness_escalate_after_eviction` did not exist yet, and the composition it probes —
an episode opened at the §A1 seam — failed here too once go pinned a vector for it.*

</details>

<details>
<summary>2026-08-10 — the cohort's four items are through, and the gate is clean for the
first time</summary>

_2026-08-10 — **the cohort's four items are through, and the gate is clean for the first
time.**_
(`ROUTING-2026-08-10-the-four-items-are-through-and-the-gate-is-clean-to-cohort.md`.)

Eight commits. Measured against Go oracle `31cd2b3`, **all three passes at zero failures
and zero skips** — the stated bar (ADR-0012: a skip counts as a failure), met on every
pass together for the first time:

| Pass | Result |
|---|---|
| 1 — all surfaces, closure scope | `1566 · 1555 P / 11 W / 0 F / 0 S` |
| 2 — `serving_mode`, namespace scope | `55 · 55 P / 0 F / 0 S` |
| 3 — `registry_issuer`, registry posture | `16 · 16 P / 0 F / 0 S` |

**Self-check labelling, now published (the item we owed the cohort).** 29 of pass 1's
1566 rows are `[self]` — they never contact the peer under test, so they are not
peer-attributable and a PASS in them says nothing about this implementation.
**1566 total → 29 self → 1537 peer-attributable.** The label is Go's (`17fc8ed`); what we
owed was reading it and publishing the split instead of a headline that reads as fully
peer-attributable. Every number above is quoted with the breakdown from here on.

- **The inbox cut landed** (`801feb1`) — `system/inbox/delivery`, EXTENSION-INBOX §2.1
  `[RATIFIED]`. One round, no dual-kind window; go cut at `927070c`, py has not. We did
  **not** cut `notification`: EXTENSION-SUBSCRIPTION §2.2 still carries an unratified
  banner, so go's question about whether "one round" contains two strings stands.
- **Four §8.4.5 width pins cleared** (`8f75835`) — go named two, the prescribed grep found
  four. The load-bearing one was the serving route, which answered `400` on a SHA-384
  `CONTENT_GET` where python answered `200` (30 of 31 SHA-384 failures sat behind that one
  sentence). REVISION's fixed-66 stays and now says why — §8.4.6 rules `prefix_hash`
  derive-to-meet, pinned to the floor, so its width follows from the pinned *format*.
- **REGISTRY §6a.9.2 built** (`99f1f31`), which made `registry_issuer` reachable against a
  rust peer **for the first time** — the category needs an armed registry and we have no
  CLI arming flag, so `set-issuer-policy` is what opened it. It found two defects shipping
  unmeasured since the handler landed (`2ed8c22`): layer-1 answered 403 where go and py
  both answer 401, and `manual` queued at 200 where both answer 202. Converged and routed;
  the spec names neither code.
- **Two containment holes in local-files** (`64f2516`). go's V4a reported 404-instead-of-403;
  reproducing it locally gave **200** and a listing of the outside directory. A trailing
  slash makes `lstat` resolve the final symlink, so `list` — which normalizes its path to
  end in `/` — inspected the target instead of the link. Fixing that exposed a second:
  the escaping component is the one a *leaf*-only check never looks at, so
  `escape-dir/secret.txt` walked straight out. Nothing reported the second; it would have
  survived a green cross-impl run.
- **A put re-derived every reference it did not author** (`9bd8633`). Same rule as the
  width work one layer up: there the code assumed a hash's *length*, here its *format*.
- **`make wasm` now holds the three worker crates** (`0580fb2`). Go's carried "S1 wasm
  probe" item does not match S1 as we recorded it (landed 2026-08-02); this is the nearest
  real gap and the naming is routed back.

**Closed by go, not by us:** `type_system_peer_published_root_match`, our single F for two
sessions, now PASSes — go added the `prefix` override at `core/types/core.go:194`. We had
declined to conform to the oracle against the spec's own text; the spec won.

`make test` 2021 passed / 0 failed · clippy · fmt · wasm green.

</details>

_2026-08-08 (fourth session) — **`published-root` carries its prefix; the last failure is
the oracle's.**_
(`ROUTING-2026-08-08-b-prefix-landed-and-your-typedef-is-the-last-failure-to-go.md`.)

One commit (`5e3894c`). `1542 total · 1532 P / 9 W / 1 F / 0 S`, pass 2 `54/54`, against
the Go `59bdfc5` surface. Arch `391c92b` landed EXTENSION-TREE §3.3a, which makes
`published-root.prefix` **REQUIRED**; Go built it plus two vectors and each sibling failed
exactly three checks on the one missing field. Two of ours now pass
(`v9_prefix_key_form`, `v10_prefix_reconstruction`).

- **We declare `/{peer_id}/`, not `"/"`.** Our keys are peer-stripped, and §3.3 now rules
  the universal prefix a **no-op trim** whose keys stay fully qualified (python's shape).
  Declaring `"/"` while keying peer-relative is exactly the divergence Go reproduced on
  demand — v8 PASSes through it, v9/v10 do not. The declaration is derived from
  `RootTrackerEngine::qualified_bare_prefix`, the same function that computes the trim
  actually applied, so it cannot drift from the keys it describes.
- **The remaining failure is Go's type registry, and we are not matching it.**
  `type_system_peer_published_root_match` reports `local: primitive/string, remote:
  system/tree/path` — `local` is Go's own registry. The spec says `system/tree/path`; Go
  reflects `Prefix string` and never added the override, though `core/types/core.go`
  carries 21 of them. **Python reached this independently** (`e60c822`) before us.
  Conforming to the oracle instead of the spec is how a cohort converges on something no
  document says; routed with the evidence.
- **Recorded, not fixed:** our config spelling `"/"` means the peer-qualified shape, not
  §3.3's universal one. The wire is correct; the config name is not. Changing it would move
  the tracked-root storage path and re-key every published trie, which is the "nobody
  re-keys a trie" the cohort ruled out.

`make test` 2005 passed / 0 failed · clippy · fmt · wasm green.

_2026-08-08 (third session) — **alignment with the oracle confirmed to the check, and the
peer-issued read seam is built.**_
(`HANDOFF-2026-08-08-c-alignment-confirmed-and-the-peer-issued-seam-is-built.md`.)

Four commits. `1540 total · 1525 P / 9 W / 0 F / 6 S`, pass 2 `54/54`, measured at both
`703bb7b` and `5c58195` against Go oracle `5eab686` — **zero regression** across the
session's changes. **This matches Go's published cohort table exactly**, verified from our
own run rather than their summary. The +8 P / −7 S on the morning's number is their
`8a25d90` peer-manager forward: the 7 `signaling` vectors we had hand-passed are now
reachable from the suite.

- **`5c58195` — the peer-issued live remote-read seam.** The 6 skips were framed as
  Go-only tooling for two handoffs; half right, because the flag is Go's but the gap
  underneath was ours. `RegistryTreeReader` (extension owns *which* paths — that is the
  trust logic) + `HttpPollRegistryReader` over a new `poll_read` module (host owns the
  transport), warming the store in the handler *before* the sync chain runs. Lazy by
  conformance, not optimization: §2.2 says a cached binding resolves **without touching
  the wire**, and a cold miss must probe even to report a negative. Revocation is a direct
  probe of the §6a.6 by-target index. `--peer-issued-registry <peer_id>@<url>` reads the
  endpoint from `hints.endpoint` and nowhere else. **The vectors stay SKIP until Go flips
  its `go|python` gate** — routed, and the seam is so far proven only against our own
  recording origin, which is same-tree evidence.
- **`144da10` — `CapTokenScope` was the third divergent copy of one convention.** §6.5.6's
  bare-`/{peer_id}` listing arm lives in three implementations of it and had drifted in all
  three directions; its includes canonicalize against `local_pid`, so it reached only the
  local peer-id. One test now asserts all three predicates at once.
- **`ac299d9` — the floor/ceiling collision is now visible**, and the node role has a CI
  guard. `system/capability/policy/{key}` is a floor on the connection path and a **ceiling**
  on the §6.2 request path; both readings are correct, nothing said so. Diagnosed, not
  fixed — the two readings still share a key.
- **`58488ec` — Go's v8 folded.** Their `published_root.v8_trie_key_convention` PASSes for
  us: the trie **algorithm** agrees byte-for-byte across all three impls, never measured
  before. The **keys** still do not, three ways — and v8 by construction *cannot* fail on
  key form, so a green v8 is not evidence our keys are cohort-correct. Written into the
  entry, because that is the exact reasoning that produced the wrong 2026-07-31 closure.

**The trap this session paid for, twice:** a test can be disarmed by its own setup and look
identical to a passing one. The first signaling guard admitted its caller with a
per-grantee policy entry, which the §6.2 lookup finds *before* the `default` fallback — so
the ceiling it existed to catch was never consulted. Found only by breaking the code and
watching the test stay green.

`make test` 2004 passed / 0 failed · clippy · fmt · wasm · `make features` green.

_2026-08-08 (second session) — **the republish landed, and it uncovered three defects a
green suite was hiding.**_
(`HANDOFF-2026-08-08-the-republish-landed-and-it-uncovered-two-defects.md`.)

Four commits. `1539 total · 1517 P / 9 W / 0 F / 13 S`, pass 2 `54/54`, rust `703bb7b`
against Go oracle `05d1fca` — **+27 P / −27 S** on the morning's number, F held at 0.

- **`8879e06` — `--publish-root` republishes on every trie-root change.** The morning
  handoff's item 00, built to its design: a tracking-config for the served prefix, and a
  hook that re-signs the hash `RootTrackerEngine` already maintains incrementally.
  128 µs/put at N=1100, 130 at N=2200 (baseline 50) — flat, guarded by a new canary.
  Two things the design didn't anticipate: **EXTENSION-TREE §3.4.1's universal prefix
  `"/"` was never implemented** (it qualified to `/{peer}//` and tracked nothing
  silently), and **the re-entry guard is not the recursion fix** — without the
  publisher's write tag you get a signed root permanently one step behind the tree, not
  a runaway, and a seq-count assertion passes right through it.
- **`aaf13bc` — ClosureScope's tree-face had no ancestor arm.** Listing routes address
  prefixes, which carry no binding, so `{prefix}.list` / `{peer_id}.list` / `peers.list`
  all 404'd under `--serve-closure-root`. Never exercised by anything: the eleven checks
  gate on `seed_republished`, and the unit test next door only fetches bound leaves. The
  first run after the republish read **11 F where there had been 27 S** — the skips were
  correct as harness behavior *and* were concealing this. Both arms of the fix already
  existed in `NamespaceScope` and in Go.
- **`0de80f7` + `703bb7b` — `peer start --signaling-node`.** The morning handoff scoped
  the node role as its own arc; it was six lines, because `entity-signaling-node` had
  already paid for the isolation boundary and the same handler drops onto any peer
  through the public seam. `signaling` measures **7/7**. `703bb7b` reverses my own
  regression from `0de80f7`: seeding `system/capability/policy/default` took
  `capability` 13/13 → 7 P / 6 F, because that entry is a **floor** for connection
  grants and a **ceiling** for §6.2 `request` — two opposite readings of one key.

**The 7 signaling passes are not yet reachable from the suite** — peer-manager forwards
`-signaling-node` only on its `--type go` branch, so they still report SKIP. Hand-passed,
pass 1 reads `1523 P / 0 F / 7 S`; that is a host-native run, cited as "what the suite
reads once Go forwards the flag," not as the suite number.

**Routed out:** two Go-side asks (forward the flag; `--publish-descriptors`' help says
"Rust pending" and we honor it), and to arch — **the published trie's key convention is
unproven cross-impl, and the 2026-07-31 closure that said otherwise was wrong.** `v5`
verifies a signature, `v7` asserts an entity type; no vector in any Go category resolves
a key from a published root. rust tracks `"/"`, Go tracks `"system/"`.

**Still open:** the 6 `peer_issued` skips are bigger than the morning's "Go-only tooling"
framing — our backend resolves against the local store only, and the live remote-read
seam is unbuilt.

Green at `make test` / `make clippy` / `make fmt` / `make wasm`.

_2026-08-08 — **the §6.5 ledger is hash-keyed, and the parity gap is two unbuilt surfaces.**_
(`HANDOFF-2026-08-08-the-ledger-is-hash-keyed-and-parity-needs-two-surfaces.md`.)

Reviewed `entity-core-go` through `05d1fca` and folded arch `c78b3dc`. Two commits.

- **`fc4fcc2` — the §6.5 minted-and-delivered ledger now resolves by CAP HASH.** arch pinned
  that as a MUST; we keyed on recipient peer-id alone, which the ruling permits only as an
  *additional* index. The wielder's peer-id equals the delivery recipient's only while the cap
  is wielded by the peer it went to — so under **delegation** a recipient-keyed-only ledger
  resolves nothing and fails **closed**: `403` on valid authority, the same wrong answer as the
  store-only revocation walk by a different route. Single-impl-invisible, which is why neither
  impl filed it; arch pinned it to Go's shape before py builds a third. The rewritten case 3 is
  the tell — it had been asserting the very semantics the ruling overturns.
- **`bd897c9` — both open ambiguities closed.** DURABILITY §5 `handle` taken as filed
  (`system/path` → `system/tree/path`; we were already there). NETWORK §12.3 ruled **(b)**, the
  reading we did *not* take: a type is owed by the surface that uses it. Our interim (a) was
  safe for the reason we gave — we implement both §6.7 ops, so we owe and publish all three
  types — but we were right about our conformance and wrong about the general rule. The
  `check-reachability 400` pushback is moot from both ends and should not be re-litigated.

**Re-measured, and it is the first crossing of the 08-07 work.** `1539 total · 1490 P / 9 W /
0 F / 40 S`, pass 2 `54/54`, rust `bd897c9` against Go oracle `05d1fca`. Go's published
baseline carries the same numbers but was pinned to `e17c2ad`+tree — which predates all five
08-07 commits. So the sender flip, `check-reachability`, the constraints, the durability
retype and the ledger change are now crossed against a live Go peer with **zero regressions**
(`origination` 5/5, `rexec_delivered` PASS). The dedicated V3 reciprocal-grant crossing from
Go's seat is still un-run and is not claimed.

**The remaining distance is skips, not failures:** 27 published-root republish + 7 SIGNALING
§4/§5 node role are ours; the 6 `peer_issued` are Go-only tooling and must not be chased.

Green at `make test` / `make clippy` / `make fmt` / `make wasm`.

_2026-08-07 — **the flag day is closed, and §6.7 is built on both halves.**_
(`ROUTING-2026-08-07-the-flag-day-is-closed-and-6.7-is-built-both-halves-to-cohort.md`.)

Five changes, answering core-go `4ecb139` (three validation reports) and browser-rust `50a2361`.

- **The sender flip — the flag day is over.** We were the last impl still inlining the reciprocal
  cap's signature + granter identity into the transported chain bundle; arch `cbe9dff` settled the
  carriage as references-only and core-go flipped at `9741eed`. A delete in three places, and the
  now-dead `originating_chain_bundle` accessor went with it. The point is not that inlining was
  broken — it worked — but that it **masks a receiver that cannot resolve from its minted ledger**,
  which is precisely how our own double-walk revocation bug (`f227df8`) survived every test we had.
  `test_s65_acceptor_originates_after_reciprocal_grant` now proves the strict path with no new test:
  the tell that the old one was measuring the lenient one. **core-py is warned** — we could not find
  a minted-grant resolver in their tree, and they will meet a bare reference the first time they
  cross with rust on acceptor-originated dispatch.
- **§6.7 `check-reachability`, responder and client.** The responder never reads `ctx.params` — the
  §6.7.2 MUST is that the dial-back targets the observed source and never a body-supplied address,
  and the alternative reading makes every dial-back peer a DDoS reflector. Rate-limited per requester
  (checked *before* the dial), capability-gated on `network-dialback` (which the §4.4 floor
  withholds), payload-free so amplification is structurally 1. The probe rides a new
  `PeerLink::probe_address` seam rather than `ensure_connected`, because the peer-shaped call would
  pool the binding and write an ephemeral address into the durable per-peer fields §6.7.1 MUST 2
  forbids it to reach. Client half in `srflx.rs` — the leg that turns a *claimed* srflx candidate
  into a *proved* one.
- **The §6.7.5 gate ran** — arch records it as never having run in any impl. Loopback half now in CI:
  a real reflect + a real dial-back over real sockets (A dials from its own listening port via
  `reuseport`, so the answer is about the endpoint the punch would use), plus the negative that pins
  `network-dialback` as genuinely restricted (bare default grants → **403**). A dial-back across a
  real NAT is still unrun by anyone.
- **Six field constraints + two type descriptors.** The `one-of`/`min-count` set core-go's differ
  surfaced once it started comparing constraints, taken verbatim from EXTENSION-TYPE v1.1, with a
  survival test asserting on the **published** descriptor rather than the builder call — that is
  where Go's own `OverrideField` bug lived. `system/network/candidate` and
  `check-reachability-result` now publish.
- **`durability/result.handle`: `primitive/string?` → `system/tree/path?`.** We were wrong and Go was
  right; the comment claiming we matched Go's declaration was stale and had never been re-checked.

**Two things routed out.** (1) To core-go: `reachability_dialback_posture` asserts "nothing else is
conformant" against a section §12.3 makes optional — *"a requester that gets a 403 or an unimplemented
response proceeds to another reflector"* — so the pre-change FAIL was misattributed. We implemented
§6.7 anyway, because we are a reference peer, but the check should be retargeted before it false-FAILs
the next impl. (2) To arch: `EXTENSION-DURABILITY` §5 declares `handle` as `system/path`, **a type
that exists nowhere in the ecosystem** (the bootstrap type is `system/tree/path`) — both impls read
through the typo and neither adopted it. Also routed: the Go/rust supplier-keying divergence (cap hash
vs recipient peer id — same verdict, different enforcement point) before py invents a third answer.

Green at `make test` / `make clippy` / `make fmt` / `make wasm`.

_2026-08-06 — **the SDK follow() primitive, the Direct WebRTC arm, and obligation 5.**_
Six commits (`f486b0f`..`e17c2ad`), driven by `entity-browser-rust` standing the first real WebRTC leg
up. No routing doc of their own; recorded here.

- **`follow()` — the subtree-mirror SDK helper**, with `FollowMode::Continuation` (a revision-free
  server-side follow chain) and `ContinuationSpec`, the typed builder for system/continuation
  entities.
- **A stale claim corrected, and it is the useful part.** The blocker was believed to be "the memory
  harness can't push notifications back." That was wrong — a **test-setup artifact**: B's engines
  were never started (the free `server::run` does not call `start_engines`; only the `Peer::run`
  method does), and a plain dial-by-address mints no §6.5 reciprocal grant, so the acceptor could
  never originate. Establish through a rendezvous seam and the memory transport pushes fine. Four
  native deterministic tests now isolate `follow()`'s own contribution — including bidirectional
  delivery over **one** symmetric channel, which retires "the A3 asymmetry is an authorization
  limit." The e2e's unconditional poll had been masking all of it.
- **`f486b0f` — the A1 Direct-arm WebRTC establisher** plus an additive SDK install seam.
- **`e17c2ad` — NETWORK §10.3 obligation 5, single-flight establishment per peer.** browser-rust
  found the cold-WebRTC path opened a channel only by brute force: ~470 concurrent pool-misses each
  spawning a fresh negotiation, piling deposits into the rendezvous bucket until two happened to
  overlap. Arch folded it as a MUST (`4c0803c`) with §11.5 gate teeth. A per-peer async gate held
  across `get_or_connect`, with a `DialGuard` that GCs the map entry so a hub does not leak gates.
  **~470 → 4 deposits/side, channel at t=1s (was ~29 s)** in browser-rust's real two-browser e2e.
  Confirmed sound from core-go's seat: the V3 crossing still completes at `reciprocal_reach_status:
  200` after it. See the 2026-08-07 routing doc §5 for where our gate boundary differs from Go's.

_2026-08-05 — **the §6.5 (b) reciprocal-grant arc, in one place.**_ Four routing docs cover it; this
is the thread, newest first. (`ROUTING-2026-08-05-direction-b-was-our-driver-and-q2-is-folded-to-go.md`,
`…-the-narrowing-is-in-and-the-discriminator-confirmed-to-arch.md`,
`…-the-6.5-narrowing-has-a-consumer-to-arch.md`,
`…-rung1-transport-is-solid-two-asks-out-of-our-court.md`.)

A rung-1 finding — an acceptor on a §6.5 (b) channel holds no authority to originate back — became a
spec gap, a proposal, four arch rulings, and a cross-impl crossing. Where it stands:

- **Mutual minting is built and narrowed.** The dialer mints the acceptor's reciprocal grant at the
  handshake; the mint fires **iff** a §3 rendezvous key was mutually brought
  (`LivePath.established_via_rendezvous_key`, local, never on the wire). Both establishers in this
  crate classify `true` — the §7 punch meets at the §3.2 `pair` key — and a dial-by-address grants
  nothing, pinned by a negative twin that differs *only* in establishment.
- **Q2 folded (arch `f8f736a`):** the reciprocal grant is the **assembled** inbound-dialer grant
  (`connection::assemble_inbound_grants`, one assembly, two callers), not the flat §4.4 floor. The
  pin test measures byte-identity between the two directions of one peer rather than a grant list
  that goes stale. Q3: the conformance floor (`RECIPROCAL_GRANT_VECTOR_FLOOR_MS`) is named apart from
  our impl-local wait. The reach-back-serving MUST was already satisfied (dialer-side §6.11(b)).
- **Cross-impl:** `entity-core-go` scored V3 direction A (Go minter → Rust acceptor) **4/4**.
  Direction B measured 0/4 and was **ours** — `cmd/signaling-punch`'s initiator dialed through the
  bare `perform_connect`, so it carried neither the dispatch stack nor the classification and minted
  nothing however symmetric the punch was. Fixed; the driver now reports `reciprocal_grant_sent` so
  the cell is scorable from its output line. **Go re-runs B.**
- **Cross-impl, second round:** core-go re-ran V3 against our push — **`8·0F @ e968ed1`**, both
  directions PASS, crossing closed. **Reach** was the open edge and is now built on both seats: their
  responder originates back (`26fd7b7`), ours does too, and our initiator lingers 2s after its pong so
  the acceptor's reach-back is not severed mid-flight (the mirror of a bug they fixed for us on
  2026-08-01, one role over). Rust↔Rust reach measures `200`. **The cross-impl reach run is theirs.**
- **Arch closed both routed gaps (`977667f`) — and both land work here.** (a) The advertisement-filter
  matching rule is ruled: four-axis `scope_subset`, entry ⊆ advertised, **drop not narrow**, governing
  the §4.4 inbound assembly identically — so it lands in the one extracted function. (b) Q1's carriage
  is a two-phase shape — deliver the cap's **content hash**, wield **as a reference** resolved at the
  dialer — which is **not** what either shipped impl did at the time. A **flag day with core-go**, not
  a unilateral fix.
  (`ROUTING-2026-08-05-reach-is-built-both-seats-and-two-new-musts-land-on-us.md`.)
  **Both shipped — see the 2026-08-07 entry.** (a) landed as `2243d65`; (b) landed in three commits
  across both impls and closed on 2026-08-07. The §7a.2a framing in the original ruling was
  subsequently **corrected** by arch `cbe9dff`: the triple gates nothing here, and wielding is an
  ordinary EXECUTE rooted at `capability` = the cap hash. No triple, no included-set chain.

_2026-08-04 (late) — **the live cross-impl sealed §6.1 punch ran; `PUNCH_TRUST` is `Require`.**_
(`docs/status/ROUTING-2026-08-04-the-live-sealed-punch-ran-and-require-is-on-to-go.md`.)

The last hold in the §6.1 flag day is discharged. Both seats are `cmd/signaling-punch` over the
CLI/JSON contract agreed with `entity-core-go`, their binary built to a scratch directory from
`6a3f1b6` (**their tree never written to, their git never run**), one Rust `--open` node, loopback,
`--mode tag`. Rust↔Go **both directions** and Rust↔Rust are `verified:true` under tolerance *and*
under `Require`, with byte-identical keys and `dialed_outbound:true` on both seats throughout.

**The tolerant pass alone would not have licensed the raise**, and that is the reasoning worth
keeping: a tolerant collector admits an *unsealed* counterpart, so a green tolerant run is
consistent with Go never having sealed anything. `Require` is the **assay**, not merely the goal —
it refuses any blob without a §6.3 container, so a green cross-impl run under it is positive proof
that Go's deposits are sealed and verify in this collector, bound to the rendezvous key. That
inverts the usual ordering: we had to flip to learn whether flipping was safe.

**And the negative control is the load-bearing half.** A Rust `signaling-punch` built from our own
pre-flip `b1eb4b5` deposits bare; Rust-on-`Require` refuses it 2/2 (`punched:false`, exit 1,
`VerificationUnavailable`, before any socket work). Without that, "green under `Require`" would not
have been distinguishable from "the policy never reached the party."

The control also found a defect **the flip itself created**: the refusal was invisible where an
operator looks — `debug!` alongside every other traversal failure, and the driver's JSON reporting
`detail: "no direct path within the deadline"`, i.e. a mixed build presenting as a NAT problem.
`punch_establisher.rs` now gives `VerificationUnavailable` its own arm and a `warn!` naming the
reading. **The outcome is unchanged** — still `None`, still relay per §7.1 step 6; only legibility
moved. The JSON contract was deliberately **not** touched: enriching `detail` would require the
§10.3 seam to return `Result` rather than `Option`, which is a joint call, and it is routed as one.

**Two asks are open and both are Go's:** their `-verify` against our vector file (`40·0F @
007e078`) — ours passes theirs at `42·0F @ 204e1d9`, so the shape is crossed in one direction only —
and a `Require`-side punch from their seat, since `cmd/signaling-punch/main.go:430` hardcodes
`VerifyTolerant` with no flag. Everything measured proves their *deposits* seal; nothing yet proves
their *collector* enforces.

**Still loopback.** Four green runs on one box say the sealed exchange completes and that `Require`
discriminates. The racing-socket tie-break remains unexercised by any substrate either impl has run,
and the cohort has still never crossed two real networks.

_2026-08-04 (late) — **the browser establisher was swallowing every error; §3.2 is closed.**_
(`docs/status/ROUTING-2026-08-04-the-establisher-was-swallowing-its-errors-to-browser-rust.md`.)

`BrowserWebRtcEstablisher::establish_live` ended in `negotiate(...).await.ok()?`, which discarded the
`WebRtcError` outright — so `VerificationUnavailable`, `IdentitySkew`, `Timeout`, and every carrier
or substrate failure collapsed into an indistinguishable `None`, in the **one** `LiveEstablish` impl
whose failures happen inside a worker where nobody can attach a debugger (`PeerPunchEstablisher` has
logged its failures all along). That gap arrived with the `Require` flip itself: the routing doc told
`entity-browser-rust` they would "see `VerificationUnavailable`" on a mixed build, and they would
not have — they built a preflight banner for a string nothing emitted. Every failure path now logs
before returning `None`; the `None` contract is unchanged (§7.3.1 pin 1 / §7.1 step 6 keep a failed
traversal as "no live path", never a dispatch error). Diagnostics only — no wire shape, no policy
change. It pairs with `entity-browser-rust`'s new worker→main `BroadcastChannel` log forwarding,
which is what makes worker-realm `tracing` lines visible at all.

**§3.2 "canonicalize the counterpart id at the §10.3 seam" is closed as not-applicable**, pinned to
symbols rather than asserted: `self_peer_id` has exactly three construction sites (all
`build_webrtc_establisher` callers in `bindings/wasm-worker-host/src/lib.rs` — Init/primary,
Init/additional, `CreatePeer`), each passing `keypair.peer_id().to_string()`, so that operand cannot
be a hash; and the target operand is refused by `EntityUri::is_peer_id` in `establish_live` **before**
`pair_key`. Landing a canonicalization there would widen a working guard from refuse to accept.
`entity-browser-rust` is right that nothing landed since `8c4a8cd` fixes their `included_count=0` —
the incorrect step is that a §3.2 seam fix would. Both sides had been holding for the other; neither
was blocked, and the rung-1 acceptance re-run is unblocked now.

_2026-08-04 — **the §6.3 container is folded into the spec, and Rust's deposit side is flipped.**_
(`docs/status/ROUTING-2026-08-04-deposit-flipped-and-the-6.1-path-is-still-bare-to-cohort.md`.)

The browser leg's missing piece landed. §6.3 named a self-contained signature and §6.2 framed the
blob with nowhere to put one, so every coordination message either impl shipped was **unsigned**.
`system/signaling/signed-blob` (`extensions/signaling/src/envelope.rs`) closes it, cross-verified
with `entity-core-go` **in both directions at both heads** — Rust `38·0F` on Go's `7384c7c`, Go
`36·0F` on Rust's `6077229`, each direction checked by the *other* implementation, which is the
§11.5.1 bar. Arch folded it at `b99304d` (their repo), carrying both of this repo's corrections as
validated behavior: the signature binds the **rendezvous key** without carrying it (a blob replayed
into another bucket fails), and a container that fails to verify is a **fourth** disposition that
MUST NOT fall back to its bare inner entity — collapsing it into "undecodable" would let one
flipped signature byte downgrade a signed offer into an accepted unsigned one.

`d70f245` flips Rust's deposit path: §6.5 now posts sealed containers, signed under the identity
the carrier authenticates to the node as, and refuses outright if the id it sorts by and the key it
signs with disagree. **The wire shapes did not move** — re-emitting the vector file differs only in
`emitter_commit` — so the crossing stands without a re-run. The one line left in the flag day is the
production policy (`AllowUnverifiedPreContainer` → `Require`), correctly still tolerant until Go's
deposit lands: `Require` refuses a bare depositor, and Go is one until it flips.

**Read the security claim precisely.** Verification is operative, not in force: half the cohort
deposits sealed, so the browser leg is not yet MITM-safe, and the reason is the migration rather
than a missing shape.

The same day turned up a second gap and closed it. The **§6.1 native punch** had no §6.3
verification code at all — it deposited bare, read bare, and could not tell a signed message from an
unsigned one, while carrying `initiator`/`responder` as forgeable wire fields. Both impls were in
that state; `entity-core-go` flipped first (`d56a690`). `b1eb4b5` landed the read side here — all
four dispositions plus §6.3 step 3, the claim comparison the browser leg has no use for — and
`007e078` seals every §6.1 deposit and derives `PunchParty`'s id **from its signing key** (Go's
shape: our §6.5 party has to refuse an id/key skew at runtime precisely because it takes two
sources, and the native establisher was the live instance of that hazard). Skip-own and the
expected-peer filter now run on the verified signer, not the claimed field.

**§6.5 is on `Require`** as of `007e078`: no SDP reaches `setRemoteDescription` on the browser leg
without a signature bound to its rendezvous bucket. It had been held off pending "Go's deposit side"
— a premise that was never true, since Go implements no §6.5 negotiation at all (their correction,
verified in their tree). A §6.5 counterpart is always another peer running this crate, and this
crate has sealed since `d70f245`, so the tolerant variant was protecting nothing and costing the
guarantee. `PUNCH_TRUST` (§6.1's policy) stays tolerant until one live cross-impl sealed punch runs:
vectors prove bytes, not that a Go peer and a Rust peer complete an exchange through a real node.

Vectors: `40·0F @ 007e078` self-verify with four §6.1 rows added, and our verifier passes Go's file
at **42·0F @ 204e1d9** including all four of theirs — the §6.1 shape crossed in one direction, with
Go's `-verify` against ours the number that would make it both.

Also settled: `BrowserWebRtcConnector` is **not** on the S5 path and will not be built — a browser
publishes no profile and has nothing to dial, so `LiveEstablish` / `BrowserWebRtcEstablisher` is the
S5 seam. S3 continues there → S4 (browser-rust) → **S5**, which is the only real evidence that the
browser leg works. rung-1 is still red for a cause upstream of the container: the node-side
rendezvous key log landed at `6a98a7f` and `entity-browser-rust` owns the re-run.

Gate: `cargo test --workspace` **2405 passed / 0 failed / 12 ignored** (`make test`, which is
`cargo test --release` over default members, **1946 / 0 / 9**), fmt clean, clippy clean, `make
features` clean, `make wasm` clean including the three worker crates.

_2026-07-31 — **the owed cross-impl backlog is clear, and Rust joined the signaling meet.**_
(`docs/validation/reports/2026-07-31-seven-categories-cleared-and-rust-joins-the-meet.md`.)

Go ran all seven owed categories against a Rust peer built from the committed tree — **clean
sweep, zero warn/fail/skip**, oracle-pinned Go `a2e2076` vs Rust `c043c7f`: `signaling` 5·0·0·0,
`authz` 11·0·0·0, `security` 30·0·0·0, `connectivity`/RT-6 24·0·0·0, `concurrency` 6·0·0·0,
`network_reconnect_anchor` 5·0·0·0, `continuation_bounds` 3·0·0·0, `published_root` 7·0·0·0.
**RT-6 now fires on the wire** — the case that was unreachable before the intercept moved
pre-verification, and the reason the whole backlog was worth clearing: it had been fixed,
shipped, and still WARNing, green on our own seat. `published_root` beat the prediction — the
trie-key convention **byte-matches Go**, so that known-open is resolved.

**The 3×3 meet is green — 27/27.** Go ran `{go,py,rust}` initiator × `{go,py,rust}` responder ×
`{tag,secret,lobby}` live through one Rust `--open` node, using Rust's driver @ `879a327`
(their `docs/validation/reports/2026-07-31-signaling-meet-3x3-cross-impl.md`). **The six
off-diagonal Rust cells are the new evidence** — Rust↔Go and Rust↔Py, both directions, had never
met live. Signaling Stage 1 is settled cross-impl; closeout and next steps in
`docs/status/HANDOFF-2026-07-31-signaling-closeout-and-next.md`.

**Both halves of the stale-image trap are closed.** Go's peer-manager keys provenance on the
sibling's git HEAD (`3c46cb3`); this repo now stamps the commit into the image
(`org.entity.git.commit` / `org.opencontainers.image.revision`, `<sha>-dirty` on a dirty tree),
so image contents are inspectable rather than merely probably fresh. Owed: confirm the stamp on
a real `make build` — the mechanism was proven on a minimal equivalent image, not the full one.

**Rust now has a client seat.** `cmd/signaling-meet` speaks the same CLI/JSON/exit contract as
Go's and Python's drivers, and its derived keys are **byte-identical to their published vectors
across all four modes** (six for six, `pair` symmetry included) — obtained read-only, no build
or git op in a sibling tree. Live Rust↔Rust meets pass at `tag`/`secret`/`lobby` through a real
`--open` node. That closes the last piece of this feature with no cross-impl evidence: every
other signaling test here is Rust↔Rust, and we were the *node* in Go's matrix, never a
participant. **Not yet run:** a live Rust↔Go / Rust↔Python meet — one command from either side
now, and the key agreement says it should be uneventful, which is exactly the claim this
exercise exists to distrust.

Gate: `cargo test --workspace` **2276 passed / 0 failed / 12 ignored**, fmt clean, clippy clean
but for the pre-existing `assertions_on_constants` in `extensions/continuation`.

_2026-07-30 — signaling Stage 1 merged to `dev`; the go/py client brief is issued_
(`docs/status/HANDOFF-2026-07-30-signaling-go-py-client-brief.md`, following
`HANDOFF-2026-07-29-signaling-merged-cross-impl-next.md`). The connection node's Stage 1 —
`extensions/signaling/` (the three verbs, the §2.2 key derivation, §3.1.1 pool selection, the
§3 coordination messages) plus `cmd/entity-signaling-node/` — is on `dev` at `7f76321`,
fast-forward, **zero edits to `core/` or `bindings/`**. Verified 2026-07-30: `cargo test
--workspace` **2260 passed / 0 failed / 12 ignored**, 72 of them signaling; `cargo fmt --check`
clean; clippy clean but for the already-logged pre-existing `assertions_on_constants` in
`extensions/continuation/`.

_2026-07-30 (same day) — the go and py clients landed, and both found the same Rust defect:_
**the shipped `entity-signaling-node` granted a connecting peer no signaling authority.** The
§4.4 floor is `system/tree:get` + `system/capability:request`, and `request` is pure
attenuation, so there was no path from the floor to `system/signaling` and no flag, config, or
file to add one — every foreign call was 403 before reaching a verb. Invisible from inside this
repo because the only Rust tests that connect to a node seed a **wildcard**, which authorizes
everything and so proves nothing about admission. The class of thing a second implementation
finds first.

Fixed: `entity_signaling::signaling_seed_grants()` (the caps in the shape
`with_seed_policy` consumes, narrow — exactly the three verbs, empty resource scope) wired to
`--open` (serve anyone; the posture the §6 gate needs) and `--grant <peer>` (serve named peers;
the private-mesh posture), which compose. **Closed stays the default** — §2.1 makes the grant
*the* admission control on the wrapped surface, and the open-to-strangers posture belongs to
the unwrapped listener whose protocol is unwritten — but the node now prints its posture at
startup instead of failing silently. New `cmd/entity-signaling-node/tests/admission.rs` (5) +
5 flag unit tests assert what the wildcard harness structurally cannot: a stranger admitted
under the narrow grant, refused without it, no spill onto other handlers, and a named grant
admitting only its peer. Suite **2270 passed / 0 failed / 12 ignored**, 82 signaling.

Go then ran its client against two live `--open` nodes: **`validate-peer -category signaling`
5/5 PASS**, PASS again on a rerun inside the TTL, and the two-instance pool discriminating
across all four modes. Go and Python also derive **byte-identical keys** for all four modes
over fixed inputs and make identical §3.1.1 selections — the highest-risk unknown, closed. The
caveat is theirs and it is the right one: both built against *this brief*, not the committed
spec, so that is **cohort-consistent agreement, not independent convergence**, and the live
go↔py meet through one node is still owed.

Their report also named a "resource-target trap", now pinned here empirically: the identical
`advertise` call is 200 without a resource target and **403 with one**, because signaling
addresses no tree resource and the seeded grant's resource scope is empty by design. Kept
narrow rather than widened to `*`; recorded as a client rule in the brief's §5.1.

One behaviour change that reached the brief: **`reflect` is a 403 against an `--open` node**,
not the 400 the wildcard harness sees — the capability check runs before dispatch, so an
enumerated grant refuses an operation it does not name. Both are correct; clients must not
treat 400 as the only signal that `reflect` is unserved. Also recorded from Python: a
responder that answers the first request in a `pair`/`lobby` bucket adopts a **stale** one on
any rerun inside the 60 s TTL, since those keys are stable by construction.

_2026-07-30 (same day) — the full `validate-peer` packet is issued to Go_
(`docs/status/HANDOFF-2026-07-30-validate-peer-packet-for-go.md`). Go's client then ran the
**live cross-impl meet** — go↔py through a Rust node, both directions, `tag`/`secret`/`lobby`,
byte-identical keys, rerun-safe on the stable `lobby` bucket. §2.2 and §3.1.1 are validated
**live across independent implementations**, not just statically — the highest-risk unknown in
this feature, and the one thing no amount of Rust-side testing could settle. `pair` is covered
statically only (needs an out-of-band peer-id exchange — harness plumbing, not a protocol
unknown).

The packet exists because signaling is not the only thing owed: **six categories are green only
on our own seat** — `authz` (F40), `security` (incl. RT-6), `concurrency` (RT-13b Part A),
`network_reconnect_anchor`, `continuation_bounds` anchor-1 (owed since 2026-07-18), and
`published_root`. RT-6 is the cautionary one and the reason to clear the rest: it was fixed,
shipped, and *still* WARNed, because the intercept sat after generic verification and the
oracle's bare-authenticate replay never reached it — green on our side, unfireable on the wire.

**Our own next build:** Rust has never been a *client* in a cross-impl meet. Every Rust live
test is Rust↔Rust; we are the node in Go's matrix, not a participant. A Rust `signaling-meet`
driver speaking the CLI+JSON contract Go and Python already share would make it a 3×3 matrix and
close the last same-impl assumption on our side.

**Rust's part is done and the next move is not ours.** Stage 1 proves mechanism, not
connectivity — it does *not* connect two NAT'd peers, which is Stage 2. And nothing in this
repo can validate the two things most likely to be wrong: every peer in every test is the
same Rust, so a wrong-but-self-consistent §2.2 derivation or §3.1.1 weight function passes
exactly as a correct one does. **go/py clients + `validate-peer -category signaling` (go as
oracle, two-instance Rust pool) are the first real evidence.** One blocker sits ahead of
that, routed and unactioned: the signaling spec corpus is uncommitted/untracked in the arch
working tree, so the packet's "build against the spec, not the Rust" is currently
unexecutable from a clone — see the brief's §1.

_2026-07-28 — STANDING-MODEL §4 O5 (sweep-all) landed — the last Rust-side §4 residual_
(`docs/status/ROUTING-2026-07-28-standing-model-4-o5-sweep-all-rust.md`; answers
`entity-core-go`'s `HANDOFF-2026-07-28-rust-py-finish-s4-residuals.md`, the one item routed
to Rust — O4 and fire-partial were already correct per the handoff's own table). Ruled by
arch (`PROPOSAL-CONTINUATION-STANDING-MODEL` §7 O5): converge on Go's sweep-all, since a
standing deadline-join that goes silent while the peer stays continuation-active was reaped
by Go but never by Rust's touched-only reap — a permanent cross-peer liveness-marker
divergence. Extended (not replaced) the existing reap-on-touch: any continuation advance
now runs a throttled (60s floor, matching Go's `joinSweepThrottle`) pass over every tracked
deadline-carrying join (`join_paths`, filled from install + touch, matching Go's
`noteJoinPath`) and reaps expired rounds via the existing `reap_join_round`. No background
timer/goroutine — driven entirely by continuation traffic, same as Go.

New test: `test_sweep_reaps_untouched_expired_join` — join A arms and expires with a slot
missing, only join B is ever advanced again, B's advance sweep reaps A anyway (one
`join_incomplete` marker, A's round reset, neither join fires).

Gate: `cargo test -p entity-continuation` 72/72 (was 71/71). `cargo build --workspace`
clean; `cargo build --target wasm32-unknown-unknown -p entity-peer` (CI feature set)
clean; `cargo fmt --check -p entity-continuation` clean; clippy clean except the
already-logged pre-existing `assertions_on_constants` failure (`docs/BACKLOG.md`).

**§4 folds once Python lands O4 (`slot` key) + fire-partial + its own O5 and the live
three-way (liveness/network/continuations/continuation_bounds) re-runs green** — nothing
further gates on Rust.

_2026-07-28 — STANDING-MODEL §4 Facet B (join completion policy) built from zero_
(`docs/status/ROUTING-2026-07-28-standing-model-4-facet-rust.md`; answers
`entity-core-go`'s `HANDOFF-2026-07-28-rust-py-convergence-standing-model-s3-s4.md` Item
2). **Scope correction found before building:** the handoff assumed Rust already had §4
mechanism 2 (deadline+abandon self-heal) and just needed the round_id addendum (§4.1) —
Rust actually had none of §4 (confirmed by exhaustive grep: no `completion_deadline`,
`on_incomplete`, `round_id`, or per-slot status tracking anywhere in
`extensions/continuation`), matching the tracker's `⬜ zero-impl`, not the handoff's
premise. Built the full facet in one pass rather than a partial addendum:

- **Mechanism 2** — `completion_deadline_ms`/`on_incomplete` ("abandon" default |
  "fire-partial") on the join entity; reaped via **lazy reap-on-touch** at the top of
  `advance_join_slot` (at the time, Rust had no background sweep subsystem to extend, unlike
  Go's `CollectExpired*` — documented as a deliberate tradeoff: a round with no further slot
  arrivals is never proactively reaped, every §6 anchor scenario is itself a touch). O5,
  landed the same day (see above), extends this to a sweep-all — the tradeoff above no
  longer holds.
- **Mechanism 1** — a non-2xx slot fills its slot and is preserved in a new
  `received_status` map; the round still fires with the error payload passed through
  untouched (matches Go's actual code, not the handoff's summary — a `join_error_slot`
  lost marker is bound alongside so the failure is observable, and it's the target's job
  to reject an error slot, not the join's).
- **§4.1** — `round_id: u64` on the join (0/omitted-on-wire unless deadline-carrying),
  optional `round_id` on the slot-advance request; a stale-round slot is dropped with a
  `join_late` marker and a 200 `{advanced:false, dropped:"stale_round", slot,
  targeted_round, current_round}` response, never accumulated.

New tests (`extensions/continuation/src/lib.rs`): `test_join_self_heals_after_deadline`
(anchor 3), `test_join_error_slot_preserved_and_marked` (anchor 4),
`test_join_straggler_bleed_caught` (anchor 5, the load-bearing one — proves the fired
round is stitched from a single generation), `test_join_untagged_advance_still_admitted`
and `test_join_round_id_stays_zero_without_deadline` (no-silent-change),
`test_join_fire_partial_dispatches_with_incomplete_marker`.

Two pin candidates beyond the handoff's four §6-R3 pins, both confirmed by reading Go's
actual source (not just the prose): the lost-marker body's `join_path`/`join_slots`
fields (present in Go's real `ChainErrorLostData`, absent from the handoff's abbreviated
list), and the drop-response's `"slot"` key alongside `advanced`/`dropped`/
`targeted_round`/`current_round`.

Gate: `cargo test -p entity-continuation -p entity-peer` 71/71 + 190/190, 0 failures;
`cargo fmt --check` clean; `cargo build --workspace` clean; `entity-peer` clippy clean;
`entity-continuation` clippy clean except the already-logged pre-existing
`assertions_on_constants` failure (`docs/BACKLOG.md`).

_2026-07-28 — STANDING-MODEL §3 authority (AT-1..AT-4) confirmed + pinned_
(`docs/status/ROUTING-2026-07-28-standing-model-authority-at1234-rust.md`; answers
`entity-core-go`'s `HANDOFF-2026-07-28-rust-py-convergence-standing-model-s3-s4.md` Item
1). Go ran all three impls live and found the substrate already three-way GREEN
(liveness 4/4, network 5/5, continuations 61/61, continuation_bounds 3/3); this closes the
one dedicated-test gap the §3 fold gates on. Rust's architecture makes the split correct
by construction — the reactive path (inbox delivery → internal `execute_fn`) never
capability-checks the caller at all, while the administrative path is gated only at the
wire dispatch seam (`connection.rs::dispatch_request`), never inside the continuation
handler. Landed:

- **AT-1** (reactive, no caller cap → advances) — already covered by pre-existing
  `test_reactive_advance_runs_under_own_authority` (`extensions/continuation/src/lib.rs`).
- **AT-2** (administrative, caller holds a cap but not `advance` → 403) and **AT-4/O1**
  (administrative, caller holds nothing relevant → 403 fail-closed) — new two-peer wire
  tests in `core/peer/src/lib.rs` (`test_standing_authority_at2_administrative_wrong_operation_denied`,
  `test_standing_authority_at4_administrative_no_capability_denied`); `Peer::execute()`
  can't exercise this gate at all (bypasses the wire seam), so both had to be full
  connect+authenticate+EXECUTE tests, not handler-level.
- **AT-3** (reactive reconnect, no advance rights) — Rust has exactly one
  `reactive_trigger` production site (inbox delivery); no separate reconnect/browser-defer
  mechanism exists, so AT-3 is the same code path as AT-1. Go's own oracle test pins it the
  same way (byte-identical `setup()` as AT-1). Added
  `test_reactive_reconnect_continuation_advances_at3` as the explicit pin rather than
  inventing a second mechanism.

Gate: `cargo test -p entity-peer -p entity-continuation` 190/190 + 65/65, 0 failures;
`cargo fmt --check` clean; `entity-peer` clippy clean. `entity-continuation` clippy was
already red pre-existing (unrelated `assertions_on_constants` lint, confirmed via
`git stash` — logged in `docs/BACKLOG.md`, not fixed here). Next: STANDING-MODEL §4.1
`round_id` join straggler guard (Item 2, genuinely new — no `round_id`/`completion_deadline`
machinery exists yet in `extensions/continuation`).

_2026-07-27 — 0.8.1 bucket-B (F40/RT-6/RT-13a/RT-13b/RT-14) landed_
(`docs/status/HANDOFF-2026-07-27-core-rust-0.8.1-bucketB-fixes-and-selfreport.md`;
answers arch's `entity-system-architecture`
`HANDOFF-2026-07-27-cohort-0.8.1-bucketB-update-packet.md`, which Rust had not yet
responded to). Two real conformance gaps fixed:

- **F40 (§5.2 id-scope literal matching).** Rust had the same bug keystone found in
  42/43 of the cohort — `operations`/`peers` routed through the §5.4 path-canonicalizing
  matcher instead of a literal string compare. Added `matches_id_scope`
  (`core/capability/src/lib.rs`) and switched `check_permission`,
  `check_permission_with_grant`, and delegation-attenuation's `scope_subset_id` to use it.
- **RT-6 (§4.6 nonce single-use).** Rust had *no* handling at all for a same-connection
  `authenticate` replay (worse than Go's pre-fix 409). Added an explicit intercept in
  `dispatch_request` (`core/peer/src/connection.rs`) returning `401 invalid_nonce`.
- **RT-13a** attested trivial/exempt (not a manual-memory substrate); **RT-13b** confirmed
  already-conformant (single-writer-task / mutex-held-writer serialization) with a new
  peer-side atomicity attestation test added; **RT-14** confirmed already-conformant
  (`Hash::to_hex()` is the only path-segment hex producer, lowercase by construction).

_2026-07-27 (same day) — RT-6 relocated after cross-impl re-validation caught it dead on the
wire._ `entity-core-go` re-validated the above on fresh peers (not the claims in the handoff)
and found F40 genuinely closed (authz 10/10) but **RT-6 still WARN**: the intercept sat *after*
`verify_request_with_ctx`, and the oracle's replay resends the bare connect-EXECUTE shape (no
`author`/`capability`, same as the original pre-Established authenticate) — which fails generic
verification first (`401 authentication_failed`) and never reaches a post-verification check.
Rust's own regression test used a different (fully-authenticated) replay shape and didn't catch
it. Fixed: moved the intercept to a pre-verification peek at `uri`/`operation` (via a newly
`pub` `entity_protocol::decode_execute_fields`, which needs only the three mandatory
`ExecuteFields` and succeeds regardless of `author`/`capability`); the unreachable
post-verification duplicate was deleted. New test
`test_rt6_bare_authenticate_replay_returns_401_invalid_nonce` reproduces the exact shape the
oracle sends. Full detail in the "Correction" section of the same handoff doc.

~~Owed: cross-impl `validate-peer` re-run to confirm RT-6 now PASSes on the wire; the F40 vector
run; the RT-13b Part-A wire probe against a live Go peer.~~ **All three CLEARED 2026-07-31** —
Go's sweep vs Rust `c043c7f`: `connectivity`/RT-6 24·0·0·0 (fires on the wire), `authz` 11·0·0·0,
`concurrency` 6·0·0·0. See `docs/validation/reports/2026-07-31-seven-categories-cleared-and-rust-joins-the-meet.md`.

_2026-07-16:_ NETWORK Amendment 12 **rung 3** landed on `dev` — the
`system/network` maintain-peer reconnect lifecycle in a new
`extensions/network` crate, composed on the rungs-1+2 §A3 liveness floor
(`docs/status/HANDOFF-2026-07-15-network-a12-rung3-rust.md`). Rust's rung-3
anchor passes at the spec-default ~100s envelope. Since then, on `dev`:
`entity peer start` gained the §2.3 `--keepalive-*-ms` overrides (Rust's half
of the cohort's Ask B — test-speed tooling, not conformance); the
wasm-worker stack gained `DisconnectPeer` connection eviction at protocol
**v10**; and the lint gate was widened — `cargo clippy --workspace` is now
`-D warnings` clean across every `bindings/*` crate for the first time
(`make clippy` only ever covered default-members, which excludes them), with
`cargo fmt --check` clean workspace-wide.

_Latest 2026-07-16 — arch rulings absorbed + a security fix_
(`docs/status/HANDOFF-2026-07-16-arch-rulings-and-injection-rust.md`). The arch
packet came back **empty — every open question across three rungs is ruled**
(`entity-system-architecture`
`docs/status/ROUTING-2026-07-16-arch-rulings-to-cohort.md`). Landed on `dev`:

- **Marker path injection — CONFIRMED and contained** (ruling 13). Go's new
  `security` probe FAILed Rust 29/30: a tree node literally named `..`, put in
  our marker tree by an **unauthorized** peer — the §3.10.3 rejected marker is
  bound *because* the cap check failed, so an attacker reaches the binding site
  by construction. Reproduced here, fixed at all three binding sites, with
  `sanitize_path_segment` converging byte-for-byte with Go's.
- **The retry loop survives** (ruling 1 — STANDING). Last session's held fix,
  unheld: **2 → 16 attempts** in 3s at min 60/max 200, stable 3/3. A peer that
  goes offline is recovered again.
- **Marker coordinates mean something** (rulings 9 + 11):
  `.../lost/chain-8a1c.../internal/...` →
  `.../lost/network-maintain-4814.../network-backoff-advance-{nanos}/...`.
  `"internal"` was `ExecuteOptions::request_id`'s default — the seam's name for
  a *category* of dispatch, shared by every handler-to-handler dispatch in the
  workspace.
- **`entity://` canonicalization — RESOLVED** (ruling 24): `canonicalize` now
  resolves `entity://{p}/x` → `/{p}/x`. Rust's longest-standing "cross-impl
  blocker" was never one; cleaning ≠ canonicalizing, and the answer was
  readable in Go's source the whole time. Does **not** close cross-peer
  delivery to a Rust subscriber (the SDK-side stack behind it is still open).

_Latest 2026-07-17 — arch round 2 absorbed + the ruled list nearly closed_
(`docs/status/HANDOFF-2026-07-17-round2-and-derived-pacing-rust.md`). Landed on
`dev` (`ae2bf31`, `32403c1`, `d7d0d79`, `de42323`):

- **Retry pacing is DERIVED, not counted** (#7/#8). `failing_since` is the one
  durable field — stamped at the transition out of `connected`, preserved
  across escalation, cleared on recovery; `attempt`/`next_attempt_at` are a
  pure function of (`failing_since`, cfg, now). The §A6.5 formula is pinned as
  a vector table ported from Go's `core/types/network_backoff_test.go` and
  reproduces its numbers value-for-value. **The table could not see the bug
  that mattered:** the status-path key was only set on a successful establish,
  so a restarted process could not *address* the stamp it was meant to
  re-derive from — restart-hammering, the ruling's headline win, would have
  silently not landed under a green table.
- **Collapse to sentinel, not hash** (round-2 ruling 1, amending 13). Rust was
  the last seat hashing. An attacker could mint unbounded path nodes — the
  pollution vector the injection fix closed, re-opened one layer up. Pinned:
  1000 distinct hostile values → exactly 1 node. The body now carries the
  originals (round-2 ruling 2), which is what makes collapsing lossless.
- **A dead peer's marker tree is EMPTY** (#3 + #2). ~1,440 nodes/day → 0.
  **#2 and #3 are not independent** despite being numbered that way: the
  `on_error` only removes the `reconnect` path's markers; the rest come from
  the backoff's own `maintain-peer` re-EXECUTE returning 502, which ruling 2's
  200-on-armed is what removes.
- **The §2.2 give-up says so** (#6): `max_attempts`/`max_elapsed_ms` decode,
  and exhaustion writes `disconnected` + `reason: retry-exhausted` (no fourth
  status value). Retry-forever remains the normative default.

Ruling 14 is **N/A for Rust** (no synthesized fallback key — `{step_index}` is
`ctx.request_id` directly; evidence in the handoff).

_Latest 2026-07-17 (later) — the ruled list is now CLOSED_ (`53d928b`, `840a2cb`;
routing docs `ROUTING-2026-07-17-marker-feasibility-and-retention-rust.md`,
`ROUTING-2026-07-17-bounds-propagation-rust-position.md`):

- **§4.7 subscription markers record who caused the substrate write** (#18, now
  MUST — `53d928b`). Every §4.7 lost-error bind — four synchronous limit/token
  sites + the async delivery worker — now uses `set_with_context` with the W6
  split: `capability`/`handler_grant` = the subscription component's own grant
  (resolved lazily; `None` degrades, never drops), `caller_capability`/`author`/
  `request_id` = the triggering caller (captured into `DeliveryWork` for the
  worker, which has no ctx). Also converged the `{reason}` sanitizer to the
  shared `sanitize_path_segment` (ruling 1 straggler — the hand-rolled copy
  wrongly rejected spaces §1.4 permits).
- **Marker handler-grant feasibility — ANSWERED** (owed to the cohort). Option
  (ii) works on Rust with no cap-check rework, for a stronger reason than Go's:
  the bind is a substrate write through `set_with_context`, and Rust enforces
  caps at the dispatch seam, not the write seam — `set_impl` reads no
  `dispatch_capability`, so the F2 trap cannot occur by construction. option (i)
  MUST-provision not needed here.
- **Retention / `RetainMarkersForever` (#19) — ROUTED, not built.** Rust has no
  marker-collection machinery (nor does the DISCOVERY pattern the proposal says
  to mirror), the landed spec still says MAY, and rulings 2+3 already took the
  dead-peer marker tree to empty — so a self-collection MUST is a heavy,
  effectively-untestable (24h) instrument for a surface that barely grows. Asked
  arch: is the MUST warranted, or does §5 stay a MAY? Logged in SPEC-AMBIGUITIES.
- **Cross-peer chain bound (`chain_depth` in `system/bounds`) — shape + O1
  confirmed, build HELD.** core-go's bounds-propagation proposal is DRAFT and
  touches wire-core; core-go itself held the cross-peer half. Rust has no
  `chain_depth` mechanism at all. Rather than lead a speculative wire-shape solo,
  Rust confirmed the field shape and the O1 causal-vs-standing signal (key on the
  presence of inherited `bounds.chain_depth`, matching Go) and will build the
  wired brake once the proposal folds or a second seat lands the field.

_Latest 2026-07-18 — both held builds UNBLOCKED and landed_
(`ROUTING-2026-07-18-bounds-and-q2-build-rust.md`; Go's
`ROUTING-2026-07-18-go-standing-model-q2-and-o1.md` landed the wired field + pinned
both O1s — the exact hold conditions Rust's 2026-07-17 note set):

- **Wired `chain_depth` brake built** (bounds-propagation, from the field up — Rust
  had no `chain_depth` at all). `chain_depth` on `Bounds` + CBOR + `system/bounds`
  type; **Delta 1 fixed** — the remote branch dropped bounds entirely (no encoder
  existed), now `build_authenticated_execute`/`send_execute` carry a bare-map
  `system/bounds` so `chain_depth`/`chain_id`/`ttl` survive the hop; inherit+`+1`
  on causal advance, root-at-0 on a fresh trigger (O1 = presence of inherited
  `bounds.chain_depth`, verbatim with Go); **§3.9 suspend** persists a resumable
  `system/continuation/suspended` entity with `reason: chain_depth_exceeded` and
  stops the chain; **§3.7 resume roots `chain_depth` at 0**. `chain_depth` is the
  independent brake regardless of ttl (Q1 §4a).
- **Standing-model §3 (Q2) — split holds by construction, marker adopted for
  convergence.** Rust has no advance-time caller-cap check (caps at the dispatch
  seam), so anchor 1 passes by construction — no Q2 defect, same shape as the
  marker-grant feasibility answer. Adopted the explicit per-dispatch
  `reactive_trigger` signal (Go's `ReactiveTrigger` analog) set by the inbox
  deliverer and threaded through `make_execute_fn` — the declared O1 signal, not
  an inference.
- **Gate green:** clippy `-D warnings` clean, 119 test-suites pass (6 new unit
  tests + a wire round-trip), fmt clean, wasm32 CI build green. ~~**Owed:** the
  cross-impl `validate-peer` / Go↔Rust anchor-1 run.~~ **CLEARED 2026-07-31** —
  `continuation_bounds` 3·0·0·0 vs Rust `c043c7f`. ttl-refill parity (§6) is still
  flagged, not built.

_Earlier 2026-07-16:_ Go's `network` category asked two questions it had never
asked before, and **both found real defects on all three seats**
(`docs/status/HANDOFF-2026-07-16-network-retry-survival-rust.md`; the cohort
report is `entity-core-go` `docs/validation/reports/`
`2026-07-16-retry-survival-cohort.md`). Yesterday's `network` 4/4 stands — it
was true; the category simply did not ask.

- **The reconnect retry loop stops after 2 attempts** — confirmed on Rust from
  our own substrate (2 attempts in 3000ms where §2.2 predicts ~20,
  reproducible 3/3), by counting §3.10 markers in-process rather than Go's
  external dial socket. §4.1's one-shot backoff continuation is re-armed by
  the very `maintain-peer` it dispatches, so the advance's post-dispatch
  consume deletes the re-arm. A peer that goes offline is never recovered.
  **Not fixed here — blocked on the §4.1 lifecycle ruling** (arch's call;
  Go's standing-continuation fix is explicitly not offered as a cohort
  answer). Pinned by `a12_retry_survives_outage`, `#[ignore]`d because it
  asserts the *current, defective* behavior.
- **`chain_id` must be a single path segment** (§3.11) — §4.1's literal
  `network/maintain/{sid}` forks the marker tree. Landed (opaque, shim-free).
- **§3.6 step 6 was unimplemented** — the advance dispatched with no bounds,
  so a chain-less trigger left every marker binder inventing a coordinate;
  Rust's fallback was the request id, which is the literal `"internal"` for
  handler-to-handler dispatch. Landed: mint the chain once, use it for both
  the marker and the dispatch bounds.

Still queued: cross-peer subscription delivery to a Rust subscriber; the
§7.2 second-half arch call and the rung-3 convergence pass (tracker #7).

The most recent substantive engineering thread before the release was
**cross-peer subscription delivery** (see Done recently / Waiting on): the
reported publisher-side bug is fixed and
the substrate completed, but the Rust-*subscriber* side of cross-peer delivery
remains a diagnosed-but-unlanded stack, bottoming out on a cross-impl
capability-canonicalization question logged in `docs/SPEC-AMBIGUITIES.md`.

## Backlog

From `docs/BACKLOG.md` (see it for full detail and fire-triggers):

- **Capability / authorization:** per-write capability selection in handlers
  (caller vs handler grant — infrastructure is in place on `HandlerContext`,
  individual handlers need domain logic); handler-specific `internal_scope()`
  declarations (currently wildcard grants); bootstrap a `system/capability`
  handler (request/delegate/revoke); `system/handler` register/unregister with
  grant creation; R-3 strict `path_required` on the remaining identity ops
  (`create`/`supersede`/`publish` attestation still accept a computed-canonical
  fallback).
- **Tree handler:** `mode:hash` hash-only reads; pagination (offset/limit) for
  large subtrees.
- **Protocol gaps:** full 6-message mutual-auth handshake (currently 3+3, one
  direction; validator does not test the mutual path yet); post-connect 409
  duplicate-connection detection.
- **Extensions:** revision Phase 2 (recursive trie diff/merge, vs today's
  flatten-and-diff); history accessed-events audit mode + config caching;
  identity §9.2 op-key confinement enforcement, a live-Op cache, a SyncTreeHook
  for the tree-write boundary, and `AttestationStore` consultation at
  `verify_request` (needs a cache-miss policy choice).
- **Bindings / SDK:** a `PeerSurface` trait to unify the SDK/WorkerProxy arms
  (gated on a second mixed-mode consumer); detached-`'static`-future rework for
  `get`/`list`/`remove`/`has`/`put_cas`; SQLite pool-split + a
  storage-concurrency posture doc; a `Batch`/`Transaction` primitive (gated on
  the cross-impl shape design).
- **Cleanup:** dedupe `error_result()`/`spawn_task()` helpers across extensions;
  remove dead `local_peer_id` fields; drop legacy snapshot-format handling and
  the deprecated `persist` feature; loom-based permutation testing for the SEC-2
  race (today covered by a multi-thread soak test).

Performance items from the per-put regression sweep are deferred (the remaining
candidates shrank to single-digit µs once the big-rock fixes landed) — pick them
up only if a future profile shows `verify_request` back on the hot path.

## Waiting on

- **Signaling — three arch-owned items, none blocking Rust's Stage 1** (merged and
  verified), all blocking what comes after it. (a) **The signaling spec corpus is
  uncommitted upstream** — `PROPOSAL-CONNECTION-NODE` is untracked and the §2.2/§3.1/§3.2/
  §3.3/§4.1 and §3.1.1 pins are uncommitted modifications, so go/py cannot build against the
  spec from a clone; verified read-only 2026-07-30 against arch HEAD `46ef024`. (b)
  **`PROPOSAL-CONNECTION-NODE` §5.1**, the public listener's wire protocol — unwritten, gates
  the unwrapped surface in all three languages. (c) **`HANDLER-OWNED-SERVICES` §6 open item
  1**, the manifest declaration's field shape — DRAFT, no cohort review, gates the
  service-owning half of Stage 2. Detail and the ask in
  `docs/status/HANDOFF-2026-07-30-signaling-go-py-client-brief.md` §1 and §9.
- **On the standing-model / network rounds, nothing is blocked on architecture.** Rounds 1
  and 2 are both absorbed.
  The `{reason}` sentinel-vs-hash divergence is **closed** — round-2 ruling 1
  ruled sentinel everywhere, which is the shape Rust already held; all three
  coordinates now use it and Go has converged. Two questions stay routed and
  block nothing: §1.4 not naming the dot tokens, and whether ruling 11's
  "keepalive carries `network-maintain-{session}`" is reachable without
  inverting the core/peer ← network layering. Both in
  `docs/SPEC-AMBIGUITIES.md`.
- **`failing_since` for a never-connected peer** — a real cross-impl gap in the
  rulings-7/8 model (the stamp is written at the transition out of `connected`;
  a peer that never connected never makes one). **Go routed it and Rust
  converged on their interim**; arch should answer Go's spec-issue, not two
  copies. Logged in `docs/SPEC-AMBIGUITIES.md` with the pointer.
- **Protocol spec (upstream):** this repo implements the landed spec and does
  not define it. Several backlog items (mutual-auth test coverage, the cross-impl
  `Batch`/`Transaction` shape) are gated on upstream design landing.
- **Cross-peer subscription delivery to a Rust subscriber** — no longer blocked
  on the `entity://` question (ruled + fixed), but still open: the SDK-side
  `deliver_token` grantee/signature/handler-scope mismatches
  (`bindings/sdk/src/subscription.rs`, `extensions/subscription/src/lib.rs`)
  are diagnosed but unlanded.
- **Cross-impl coordination on SDK-surface items** (`PeerSurface` trait, SQLite
  pool split mirroring the Go peer) waits on those consumers/decisions.

## Done recently

- **Initial public research-preview release tagged v0.8.0.** Clone-fresh gate
  green from a no-siblings checkout (`make build` → release runtime image with
  the `entity` binary; `make wasm` → wasm32 cross-compile of the canonical
  feature set; `make test`). `make` over podman is the build door (bare host
  needs only `make` + podman); `compose.yaml` is demoted to an explicit
  developer convenience. All workspace crates carry the 0.8.0 version, licensed
  **Apache-2.0**.
- **Cross-peer subscription delivery — reported bug fixed + substrate completed
  (subscriber side still open):**
  - The publisher now presents the subscriber-granted `deliver_token` (and
    bundles its delegation chain) as the delivery EXECUTE's capability for
    cross-peer delivery, instead of falling back to the connection grant — which
    on the reentry path is a publisher-authored placeholder the subscriber can't
    root (EXTENSION-SUBSCRIPTION §4.2). This unblocks the Rust-publisher →
    Go-subscriber direction.
  - Completed the dialer-side reentry receive path: a pooled outbound connection
    now dispatches inbound EXECUTE requests through the local handler stack and
    writes the response back over the same connection (previously the dialer
    reader handled only EXECUTE_RESPONSE and silently dropped reentry
    deliveries).
  - The core `entity://` canonicalization gap is **fixed** (ruling 24). The
    remaining Rust-*subscriber*-side stack is diagnosed but unlanded: SDK-level
    `deliver_token` grantee/signature/handler-scope mismatches
    (`bindings/sdk/src/subscription.rs`, `extensions/subscription/src/lib.rs`).
- **Trust stack — Role extension v1.0 → v2.0:** root-cap shape, SEC-2
  assign/exclude atomicity, and bearer-cap rejection (the new
  `unresolvable_grantee` 401).
- **Capability hardening:** granter-aware canonicalization at the dispatch
  boundary, per-link granter frame at chain-walk, grant-signature convergence,
  and a self-owner seed cap at bootstrap.
- **Transport / interop extensions:** relay v1.0 (opaque-envelope transport,
  exercised live Go↔Rust), route (routing table), discovery v1.0 (mDNS
  find-and-prompt) + registry v1.0 (petname→local-name) and the published-root
  flow with cohort absorption. Live cross-impl publish→fetch verified
  (Go-publish → Rust-consume).
- **Encryption extension v1.0:** group/self AEAD modes, key-separation, and the
  associated entity-type registrations.
- **Storage:** an IndexedDB main-thread durable backend (Phase 1) for the
  browser peer, with the SDK builder/checkpoint reach to drive it; a
  multi-tab `versionchange` deadlock guard.
- **Wire-fidelity:** on-receipt hash validation in `verify_request` (a forged
  *included* entity now fails the same as a forged root); §1.2 host-bytes-
  distrust (recompute content hashes, never trust the wire `content_hash`).
- **Performance:** per-put cost ~66.4 ms → ~0.72 ms in debug (~92×) via TCP
  NODELAY, sync-hook config caches, a dev-profile crypto/CBOR optimization
  override, and decoding chain fields once.
- **WASM:** compatibility across all crates (wasm32-unknown-unknown build check
  via `make wasm`).

## Next

> **This list was swept 2026-08-04.** Three items below had gone stale and one of
> them cost a session: 5b named §6.7.1 as unvalidated when it had been closed
> four ways on 2026-08-02, and it was picked up and recommended as "next" on that
> basis. A cold-start reference that is wrong about what is *done* is worse than
> one that is merely incomplete. The punch/WebRTC arc (2026-08-01 → 04) now leads
> the list, because that is where the work actually is.

00. **Conformance parity — what is left after 2026-08-08 (third session).** _(rewritten
    2026-08-08, third session.)_ Every item this entry carried is now **closed or routed**.
    rust reads `1540 total · 1525 P / 9 W / 0 F / 6 S` at `5c58195` against Go `5eab686`,
    pass 2 `54/54` — **matching Go's published cohort table exactly**, verified from our own
    run. Details in
    `HANDOFF-2026-08-08-c-alignment-confirmed-and-the-peer-issued-seam-is-built.md`.

    **a. The two Go-side asks landed** (their `8a25d90`). `-signaling-node` is forwarded for
    `--type rust` and the 7 `signaling` vectors converted SKIP → PASS exactly as predicted;
    `--publish-descriptors`' stale help is fixed. Nothing owed either way.

    **b. The peer-issued seam is BUILT** (`5c58195`) — `RegistryTreeReader` +
    `HttpPollRegistryReader` over the new `poll_read` module, warming the store in the
    handler before the sync chain, plus `--peer-issued-registry <peer_id>@<url>`. **The 6
    vectors still read SKIP**, and will until Go flips its `go|python` gate; that is a
    sibling-repo change, routed in
    `ROUTING-2026-08-08-the-peer-issued-read-seam-is-built-to-go.md` along with the exact
    fetch pattern we emit. Quote `1525 P / 6 S` until they do.

    **Not claimed:** the seam is proven against our own recording origin, not against Go's
    fixture bundle — same-tree evidence, which AGENTS-STANDARD warns reads stronger than it
    is. The first real measurement is theirs. One caveat is in the routing doc: if their
    fixture serves revocations only under the own-hash-keyed path, REVOKED-1 will read as
    "not revoked" against us and the finding would be the fixture's, since we probe the
    §6a.6 by-target index directly.

    **c. Both internal fixes landed.** `CapTokenScope` got its universal-tree top-level arm
    (`144da10`), with one test now pinning all three scope predicates to the convention. The
    seed-policy floor/ceiling collision is **diagnosed and visible, not fixed** (`ac299d9`):
    the lookup reports which form matched, the request path warns when a matched entry
    attenuates to nothing, and `with_seed_policy`'s doc states both meanings. The two
    readings still share a key — the real fix is separate floor and ceiling entries, and it
    is worth doing before someone else seeds a narrow `default`.

    **d. What is genuinely left here:** wait on Go's gate flip and measure honestly; decide
    whether `poll_read::list_children` (built, currently unused — the peer-issued fetch plan
    resolves everything by direct lookup) gets a consumer or gets deleted.

0. **The browser leg — S5.** S3 is built here (`worker_webrtc`, the §6.3
   container, §6.5 `Require`); S4 is `entity-browser-rust`'s and built; **S5 has
   never run** and **rung-1 is still red** — but the transport layer is now
   repeatably sound and both remaining blockers are outside this repo.

   **State as of 2026-08-05 (`d2850e5`), four consecutive rig runs from this
   tree:** data channel opens (1/peer/run), handshake completes 4/4, responder
   receives frames 4/4, zero panics, zero relay fallback, and **initiator→responder
   application payload reaches the handler 4/4**. Roles swapped in run 4 and
   behaviour followed the role, not the peer.

   **Four faults found and fixed to get there, all ours:** the unconditional
   `Drop` destroying working connections (`5e0c131`); the §7.4.1 handshake-role
   collision (`f00170c`); `verify_request` panicking on wasm32 — `std::time`
   instead of `web_time`, our own documented rule (`81ae207`); and inbound frames
   dropped between channel-open and pump-wiring (`9e65317`). Plus the acceptor
   authority refusal (`d2850e5`).

   **The two blockers are no longer ours:** (a) the rig calls `list`, which is not
   a `system/tree` operation — browser-rust's; (b) an acceptor holds no
   originating authority under §6.5 trigger (b) — a spec gap logged at `8e0eabf`
   and routed to arch, where one candidate ruling (mutual minting at handshake) is
   protocol-visible and not ours to pick
   (`ROUTING-2026-08-05-rung1-transport-is-solid-two-asks-out-of-our-court.md`).

   **Caveat:** the frame-buffering fix targets a race that reproduced ~1-in-2.
   4/4 clean is reasonable evidence, not proof, and `webrtc_session.rs` has no
   automated coverage of any kind — rig runs are the only check it gets.
   Coordination-green is not transport-works, and transport-works is not S5.

   **Their acceptance re-run has now happened (2026-08-04) and it moved the wall.**
   `included_count=0` is gone: rendezvous is sound end-to-end, both peers derive
   one key and share one bucket. The failure is now a §6.5 negotiation that ends
   in `Timeout` with a populated bucket — no `RTCDataChannel`. **That is ours**
   (`worker_webrtc.rs` + `wasm-worker-proxy/webrtc_session.rs`; browser-rust owns
   no `RTCPeerConnection`), so this item is no longer "nothing is owed to them."

   Instrumented at `40294ed` — `Timeout` carries `role` / `sdp_exchange` /
   `counterpart_msgs` / `channel wait`, plus a per-tick `trace!`. **Diagnosis, not
   a fix.** Two structural hypotheses were checked and cleared (data-channel
   create/receive symmetry; every broker arm replies), and one piece of their
   evidence was retracted: the missing main-thread "data channel did not open"
   line was never a log line, so its absence never pointed anywhere.

   **Their re-run against that HEAD discriminated in one run (3×, 2026-08-04).**
   Offerer: `role=offerer, sdp_exchange=complete, channel wait: data channel
   closed before it opened`. So it is **not** rendezvous and **not** SDP
   correlation. Load-bearing control: their bare-WebRTC falsifier on the same
   containers/bridge, `iceServers:0`, host candidates → connects, opens,
   round-trips, PASS. **§6.5 fails where bare WebRTC succeeds**, which clears the
   network and puts it on the trickle path.

   **Verdict in (2026-08-05, their run vs `3dcd484`):** `role=answerer,
   sdp_exchange=complete, candidates posted=3/fed=3, channel wait: closed before
   it opened (ice=Disconnected)`. `fed=3` **refutes both leading theories** —
   theirs (candidates not landing) and mine (`candidates_for` correlation) — by
   counter, not argument. Three lifecycle faults found and fixed at `5e0c131`:
   (1) `webrtc_call` awaited with **no timeout** while `negotiate` checks the
   deadline only at loop top, so every round trip ignored `deadline_ms` — the
   tick=2 hang; now `call_bounded` against the remaining window. (2) the
   post-answer iteration paid `wait_open` *plus* a full `sleep(poll_interval)`,
   doubling the period exactly while ICE holds a pair; now only the shortfall.
   (3) **`Drop` posted `WebRtcClose` unconditionally**, and the broker answers it
   with `pc.close()` — so on the success path every negotiation that *worked*
   would have been torn down before a byte moved. Latent only because rung-1 has
   never gone green; unexercised by any gate.

   **Reframe that matters:** `pc.close()` on any peer gives its counterpart
   exactly `ice=Disconnected` + closed channel. So the answerer's line is the
   offerer's teardown *observed* — the open question is why the offerer's window
   closed, and no round has yet quoted the offerer's terminal warn
   (`ROUTING-2026-08-05-three-lifecycle-faults-and-your-answerer-is-the-victim-to-browser-rust.md`).

   Answered at `3dcd484` with the two instruments that decided it: `wait_open`
   errors now append the `ice=`/`conn=` verdict (`Failed` = pairs tried and none
   worked; `New` = remote candidates never reached the agent; `Connected` = ICE
   fine, trickle hypothesis wrong), and `Timeout` carries
   `candidates posted=N/fed=M`. The whole trickle chain was read for the
   `67e6d96` shape first and no defect found — session adoption, blob-exact
   skip-own, `addIceCandidate` always after `setRemoteDescription`, ufrag
   absent-stays-absent, monotonic `negotiation_id` all hold. **Not found, not
   proven absent.** Next fact is their re-run; `fed=0` is mine in
   `candidates_for`, `fed>0` + `ice=Failed` is a timing/usability bug and a
   different fix
   (`ROUTING-2026-08-04-the-ice-verdict-is-now-readable-and-the-trickle-is-counted-to-browser-rust.md`).
0a. ~~**The §10.3 seam takes `Result` — ruled 2026-08-04.**~~ **LANDED `f43f0e0`
   (2026-08-05)**, after both peer repos endorsed (browser-rust: "land it,
   independent of rung-1"; Go deferred the call here). `LiveEstablishError` draws
   `NoPath` / `Refused` / `NotAttempted`. **Control flow unchanged** — every
   variant falls through to relay exactly as `None` did; only the log differs
   (`Refused` is `warn!` and names itself as policy, not connectivity).
   Two call sites stopped lying: `cmd/signaling-punch` reported "no direct path
   within the deadline" for every outcome *including* a `Require` refusal, and
   the punch round-trip test's panic said which half failed but not why.
   Original ruling follows.
   `LiveEstablish::establish_live` returns `Option<Connection>`, so a failure
   reason is destroyed inside the impl and `try_establish_live` has nothing to
   log. Go's suggestion that the reason may already be available at the call site
   does not transfer — theirs returns `(*Connection, error)`; a `None` carries
   nothing. Decided on three instances of the same patch in two days: the browser
   establisher (`485e269`), the punch establisher, and `negotiate`'s
   `if let Ok(channel) = io.wait_open(..)` (`40294ed`), which cost browser-rust a
   root-cause. ~8 sites (trait, two impls, real call site, test double, test call
   sites). **Constraint: every `Err` maps to the same relay fall-through** —
   reason for observability, never a branch for control flow; "no live path →
   relay" (§7.1 step 6 / §7.3.1 pin 1) stays deliberate. Both peer repos have
   registered and deferred the call here
   (`ROUTING-2026-08-04-the-6.1-row-now-lies-in-the-payload-and-the-seam-ruling-to-go.md`).

0b. **The §6.1 false-claim vector row — re-emitted, awaiting Go's `-verify`.**
   The row lied only in its own `claimed_peer_id` over a truthful payload, so a
   payload-driven collector (which every real §6.1 read path is) saw a consistent
   message and returned ok — it could not catch the regression it names. Go found
   it by running their verifier against our file and reported `40·1W·0F`. Fixed at
   `36fce4a`, re-emitted `40·0F @ 36fce4a` (`50b99c3`). **Our count could not
   move** — our verifier is row-driven for signed-blob rows — so this is only
   decidable from Go's seat. Until their `W` clears, the payload-lying §6.1 shape
   is crossed **one way only**. Pin adopted and seconded to arch: on a §6.1 row,
   `claimed_peer_id` MUST equal the author field inside the signed payload.

1. **Two questions routed to architecture — waiting on the model answer, not on
   Rust.** (a) Retention: is a self-collection MUST warranted, or does §5 stay a
   MAY? (`ROUTING-2026-07-17-marker-feasibility-and-retention-rust.md`).
   ~~(b) `chain_depth` — held pending fold / a second wired seat.~~ **STALE —
   built 2026-07-18** and cleared cross-impl 2026-07-31; see item 2, which
   contradicted this on the same list. The ruled list is **closed** (#18 landed,
   feasibility answered, #14 N/A).
2. **Cross-peer chain bound build — DONE (2026-07-18).** The wired `chain_depth`
   brake is built (field + CBOR, cross-peer bounds propagation, step-6
   inherit/increment, O1 signal, §3.9 suspend + §3.7 resume) plus the standing-model
   §3 (Q2) `reactive_trigger` convergence marker
   (`ROUTING-2026-07-18-bounds-and-q2-build-rust.md`). ~~**Owed:** the cross-impl
   `continuation_bounds` anchor-1 run.~~ **CLEARED 2026-07-31** — 3·0·0·0 vs Rust
   `c043c7f`. This was the oldest owed item in the tree.
3. **The cross-impl backlog is clear — nothing is owed to Go's seat.** All seven
   categories swept green 2026-07-31 (`docs/validation/reports/`
   `2026-07-31-seven-categories-cleared-and-rust-joins-the-meet.md`): `signaling`,
   `authz`/F40, `security`, `connectivity`/RT-6, `concurrency`/RT-13b,
   `network_reconnect_anchor`, `continuation_bounds`, `published_root`. Keep it that
   way — **run `validate-peer` on any wire-shape touch rather than banking a
   same-seat green**, which is precisely how RT-6 sat WARNing on top of a real fix.
4. ~~**Run the 3×3 signaling meet.**~~ **DONE 2026-07-31 — 27/27**, all six Rust
   off-diagonal cells live. Signaling Stage 1 is settled cross-impl.
5. ~~**Stamp the podman image with its git commit.**~~ **DONE 2026-07-31** — both
   halves of the stale-image trap are closed. **Owed:** confirm the stamp on a real
   `make build`; the label mechanism was proven on a minimal equivalent image, not
   the full one.
5a. ~~**Re-diff signaling against the arch corpus when it lands.**~~ **DONE
   2026-07-31** — arch `4241b96` folded the connectivity family and the re-diff ran
   against the committed text, six findings, two logged as ambiguities
   (`docs/validation/reports/2026-07-31-signaling-rediff-against-committed-v1.md`).
5b. ~~**Validate `EXTENSION-NETWORK` §6.7.1**~~ **DONE 2026-08-01/02 — the matrix is
   closed four ways.** The client half is `core/peer/src/srflx.rs`; Rust also built a
   **responder** (`NetworkHandler::handle_observe_address` + the §6.7.4 rate limit),
   and standing it up immediately found a real grant bug — Go's client got `403`
   from our responder because reflection was reachable only to a caller already
   holding a `system/network` grant, fixed in `default_connection_grants`
   (`observe-address` only; §6.7.2 `check-reachability` stays restricted, since a
   broad grant there makes every peer a DDoS reflector). Go↔Go, Go→Rust, Rust→Rust,
   Rust→Go all exercised, plus the two-NAT topology on Go's harness
   (`ROUTING-2026-08-02-rust-reflects-too-and-the-403-you-would-have-hit.md`).
5c. **The punch ladder — G0–G3 green, G4 is operator infra.** Rust and Go punch
   cross-impl through a real node; the §6.1 exchange is now **sealed on both sides
   and `Require` on ours** (2026-08-04, four live runs plus a firing negative
   control). Two things are genuinely open and both are Go's to run: their `-verify`
   against our vector file (`40·0F @ 007e078`), and a `Require`-side punch from their
   seat — their `cmd/signaling-punch` hardcodes `VerifyTolerant` with no flag.
   **Still unexercised by anybody:** the racing-socket tie-break, and everything is
   still one box — the cohort has never crossed two real networks.
6. **Cross-peer subscription delivery to a Rust subscriber** — unblocked at the
   core by ruling 24; land the SDK-side grantee/signature/handler-scope fixes.
7. Keep the green gate (`make check` = lint + test) and `make wasm` passing on
   any change.
