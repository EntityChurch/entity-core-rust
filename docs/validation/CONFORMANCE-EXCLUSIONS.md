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

**Not drivable at the wire against this peer.** One thing holds it off the wire,
and it is deliberate and cohort-convergent:

1. **`claimed_source_peer_id` is local dispatcher context by Ruling 4, not a
   wire field.** `system/content:get-request` carries no such field — the
   consumer's own dispatch path already knows whose tree it is walking. So the
   `system/content` handler passes `None` from its only call site
   (`extensions/content/src/handler.rs`, `let claimed_source: Option<Hash> =
   None`), and `consult` short-circuits on `ConsultMiss::NoClaimedSource`
   before touching a chain. That is the ruling working as designed, and go and
   py both defer identically.

`entity-core-go` reached the same finding across all three impls (`2bb028b`
inventory, then the §7 behavioural checks) — no production caller sets the
claimed source anywhere.

> **Amended 2026-08-22 — the second ground is gone, and removing it found four
> defects.** This entry used to carry a ground 2, *"nothing installs the
> surface"*: `entity-storage-substitute-http`'s handler was registered on no
> peer, and exhaustively no crate outside `extensions/storage-substitute-*`
> depended on it. That was true, it was **not** a reason for an exclusion — it
> was an unwired surface wearing one, and it is why go's release gate scored
> this peer `substitute 0P/1S` (a skip counts as a failure) for as long as it
> did. The handler is now registered in `entity peer start`
> (`cmd/entity-peer/src/commands/peer.rs`), the §7 convention is wire-reachable,
> and the category scores **8/8 · 0F**.
>
> Registering it is what made the surface measurable, and it was immediately
> `5P/3F` — three real conformance defects that the skip had been hiding, plus
> a fourth found while fixing them. §2.3's `entry` travelled as a `bstr` where
> go and py send an entity **value**, so every cross-impl call died at the first
> field; the §7 plaintext refusal answered 400 where it is a 403 authorization
> decision; and §2.2's *"`content_url_prefix` is REQUIRED, no derivation
> default — an impl that treats it as optional-with-derivation is
> non-conformant"* was implemented as the superseded D-14 derivation, in both
> the absent and the empty-string forms. **An exclusion whose ground is "we
> never wired it" is a gap, not an exemption — this entry now rests only on
> the Ruling-4 ground, which is a property of the protocol rather than of our
> build.**
>
> **What is still not wired, stated plainly:** `ChainConsultHook` is not
> registered as a `MissResolver` on any peer. That does not change the
> exclusion's reach — ground 1 keeps the §3 chain undrivable over the wire
> regardless — but it means the §3 vectors below remain satisfied in-process
> only, and this note is the place that says so rather than leaving it implied.

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
