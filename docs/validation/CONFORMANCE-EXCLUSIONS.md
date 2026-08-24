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
