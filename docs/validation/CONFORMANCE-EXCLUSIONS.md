# Declared conformance exclusions — entity-core-rust

Pinned conformance vectors that are **not** exercised against this peer at the
wire, with how they are satisfied instead and the mutation that proves the
substitute has teeth.

**A declared exclusion is not a pass.** It is not counted in any gate number this
repo publishes, and an in-process result reported as a cross-impl vector pass is
a false conformance claim (`EXTENSION-NETWORK` §5.4a, `GUIDE-CONFORMANCE` §5.2b).
The point of writing them down is that the gap is *stated* rather than *absent*:
a scoreboard reading "covered" over an unreached surface is the failure mode.

Each entry states: why the vector is not drivable here · what satisfies it
instead · the mutation it was verified against, with the date it was last run ·
when the exclusion becomes void.

---

## `NET-LIVENESS-NO-ESCALATION-WITHOUT-EPISODE-1`

**Vector.** `EXTENSION-NETWORK` §5.4a — the negative half of the
escalation-survives-eviction pair. A §10.2 dispatch-fallback or RELAY
terminal-hop eviction on a `connected` peer MUST NOT produce a `disconnected`
write.

**Not drivable at the wire against this peer.** The state the vector requires —
a peer **unbound yet still `connected`** — is reachable only from the two paths
§A1's seam scope deliberately excludes from demoting (the §10.2 dispatch
fallback and the RELAY terminal-hop forward; `core/peer/src/liveness.rs` module
doc, ruling E). Both need a store-and-forward deployment, so a conformance
client cannot construct the state over the wire. The scope pin and the obstacle
have one cause. §5.4a's stated satisfaction mode for exactly this case is
in-process, with a declared exclusion naming the mutation.

*The obvious wire proxy is rejected by §5.4a and the reasoning is worth
repeating: a live idle counterpart stays **bound**, so a proxy exercises a
timer-driven escalation and never the scope-pin defect — it would read as
coverage while missing the case.*

**Satisfied by (in-process).**
`tests::a12_no_escalation_without_an_open_failure_episode`
(`core/peer/src/lib.rs`) — evicts the pooled binding directly via
`RemoteState::remove`, writing no status, with the counterpart still alive so
nothing else can demote it, then asserts the keepalive teardown leaves the peer
`connected`.

**Mutation verified against.** In `keepalive::escalate_unbound_suspect`
(`core/peer/src/keepalive.rs`), delete the `prev.status != PEER_STATUS_SUSPECT`
guard so the grace path escalates any unbound peer.
**Run 2026-08-12 at `bb34557`:** the test FAILS
(`left: "disconnected", right: "connected"`) — and the **positive** half,
`a12_escalates_to_disconnected_after_the_a1_eviction`, still PASSES under the
same mutation. That is the whole reason §5.4a makes the negative half
non-optional.

**Void when.** RELAY (or any other evict-without-demote path) is installed in
the peer under test — §5.4a requires the negative half be wire-driven there.
This is not a standing exemption.

---

## `EXTENSION-SUBSTITUTE` §3 — the chain-consult surface

**Vector.** `EXTENSION-SUBSTITUTE` §3 chain consult — a content miss on a hash
attributed to a claimed source peer walks that source's substitute chain and
fetches through it.

**Not drivable at the wire against this peer, and this is a build gap rather
than an obstacle.** Two things hold it off the wire, and only the first is
deliberate:

1. **`claimed_source_peer_id` is local dispatcher context by Ruling 4, not a
   wire field.** `system/content:get-request` carries no such field — the
   consumer's own dispatch path already knows whose tree it is walking. So the
   `system/content` handler passes `None` from its only call site
   (`extensions/content/src/handler.rs`, `let claimed_source: Option<Hash> =
   None`), and `consult` short-circuits on `ConsultMiss::NoClaimedSource`
   before touching a chain. That much is the ruling working as designed.
2. **Nothing installs the surface.** `ChainConsultHook` is never registered as a
   `MissResolver`, and `entity-storage-substitute-http`'s handler is never
   registered on a peer. Exhaustively: no crate outside
   `extensions/storage-substitute-*` depends on either crate — they are
   workspace members with no consumer. The only construction of
   `ChainConsultHook` in the tree is its own test.

**So the honest status line is: built, compiled, tested in isolation, and
unreachable from any wire request.** `entity-core-go` reached the same finding
across all three impls (`2bb028b` inventory, then the §7 behavioural checks) and
the mechanism is the same everywhere — no production caller sets the claimed
source. Recording it here because the previous framing ("built in all three,
measured by nothing") understated it: the surface is not merely unmeasured, it
has no trigger.

**Satisfied by (in-process).** `extensions/storage-substitute-sources/tests/chain_consult.rs`
(7 vectors — bare-hash short-circuit TV-SS-BARE-1, the four cap-axis denials,
resource-scope denial, chain fall-through) plus `entity-storage-substitute-http`'s
12 unit tests over the §7 URL/manifest conventions.

**Mutation verified against.** In `ChainConsultHook::consult`
(`extensions/storage-substitute-sources/src/lib.rs`), flip the fail-closed
capability arm `None => false` to `None => true`, so a caller presenting no
token is admitted before the chain is enumerated.
**Run 2026-08-13:** `missing_cap_token_denies` FAILS and the other six vectors
still pass — the suite is load-bearing on the axis that matters (chain presence
and ordering leaking to an unauthorized caller), not merely on the happy path.

**Void when.** Any caller with local source context is wired — the SDK
closure-fetch walking a known publisher's tree, or a Phase-2 dispatcher
tree-fetch — or the `storage-substitute-http` handler is registered on a peer.
At that point §3 is wire-drivable and this exclusion must be replaced by
cross-impl vectors, not renewed.
