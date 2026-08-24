//! `signaling-punch` — **Rust's seat in the cross-impl punch (gate G2).**
//!
//! One role, one punch, one JSON line on stdout, exit 0 iff the punch was
//! *verified*. It speaks the CLI/JSON/exit contract agreed with `entity-core-go`
//! on 2026-08-01 (their routing note accepted §3.1/§3.2 without counters; both
//! notes are internal dev history — the contract itself is the flags, the JSON
//! line and the exit code documented below), so either half can be swapped for
//! Go's `cmd/signaling-punch` and the harness does not change.
//!
//! ```text
//!   signaling-punch --node 127.0.0.1:4050 --role responder --mode tag --input chess \
//!                   --local-addr 127.0.0.1:9002 &
//!   signaling-punch --node 127.0.0.1:4050 --role initiator --mode tag --input chess \
//!                   --local-addr 127.0.0.1:9001
//! ```
//!
//! # Why this is a different binary from `signaling-meet`
//!
//! `signaling-meet` proves two peers found each other *through the node*. It
//! never opens a direct path, so it cannot see anything §7.1 step 4 or §7.4.1
//! govern. This runs the whole crossing and then **uses** the result.
//!
//! # A socket is not a punch `[§3.2 of the contract]`
//!
//! `verified: true` means a HELLO handshake completed over the direct path **and
//! one operation round-tripped on it** — not that a socket formed. Three reasons
//! the weaker bar was rejected, all of them cross-impl:
//!
//! 1. A socket that cannot carry an operation is not a punch, and the failures
//!    that produce one — wrong handshake role, framing confusion on a
//!    simultaneous-open socket — are exactly what a same-impl test cannot see.
//! 2. It is the **only** cross-impl exercise of §7.4.1's handshake role. Both
//!    implementations chose initiator-as-client independently; neither has ever
//!    proven it against the other. On a punched socket nothing says who speaks
//!    first — a dial normally settles it, and a punch destroys that signal by
//!    construction.
//! 3. §10.3 obligation 1 says a punched connection is an *ordinary* transport.
//!    The cheapest proof of that claim is to run an ordinary operation over it.
//!
//! Go clears the same bar with a pong over its punched, pooled connection
//! (`TestCoordinatorEstablishThroughSeam`), so both sides mean the same thing by
//! the field.
//!
//! **The proof is the pair, and the initiator's line is the strong half** — the
//! same asymmetry `signaling-meet` has, for the same reason. The initiator's
//! `verified` means it got a 200 back over the direct path, which cannot happen
//! unless the responder served the handshake and answered; that is a positive
//! observation of the whole round trip. The responder can only report that it
//! served a handshake and then saw a clean end-of-stream — it never sees the
//! reply it sent land. A harness should therefore gate on the initiator's
//! `verified` and read the responder's as corroboration.
//!
//! # `dialed_outbound` is the field that makes G1 checkable
//!
//! §7.1 step 4 requires **both** peers to fire outbound at `fire_at`; listening
//! alone opens no NAT mapping. On loopback that requirement has no observable
//! consequence — a listen-only peer still gets a path — which is exactly how the
//! retracted shape survived review in two implementations. So each side reports
//! whether it issued a connect, and the validator compares. Without it, a partner
//! silently regressing to listen-only stays invisible until a cross-NAT run.
//!
//! **What it counts here is the `connect` syscall**, not entry to a dial seam:
//! `PeerPunchEstablisher::outbound_attempts` increments inside `dial_reuseport`
//! after the bind and after a hard failure is ruled out. A refused or timed-out
//! connect still counts — it opens the local mapping exactly as an accepted one
//! does.
//!
//! # What a green run does NOT prove
//!
//! **Not traversal.** G2 is loopback or LAN; there is no NAT, so there is no
//! mapping for a missing outbound to fail to open. A one-dials build passes this
//! gate. G2 proves the two implementations agree on the choreography, the wire,
//! and the handshake role; **G3 (emulated dual-NAT) and G4 (real) are what
//! convert that to "traverses".**

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use entity_capability::GrantEntry;
use entity_crypto::{IdentityKeypair, Keypair};
use entity_peer::live_establish::{EstablishCtx, LiveEstablish};
use entity_peer::punch_establisher::PeerPunchEstablisher;
use entity_peer::transport::{self, Connection, Connector};
use entity_peer::{remote, PeerBuilder};
use entity_signaling::{key, RendezvousKey};

#[derive(Parser)]
#[command(
    name = "signaling-punch",
    about = "Rust's participant in the cross-impl punch (G2)"
)]
struct Args {
    /// `host:port` of the connection node carrying the coordination exchange.
    #[arg(long, default_value = "")]
    node: String,
    /// `initiator` | `responder`.
    #[arg(long, default_value = "")]
    role: String,
    /// `tag` | `secret` | `lobby` | `pair`.
    #[arg(long, default_value = "")]
    mode: String,
    /// The mode's input. `pair` takes `peer-a,peer-b`; the literal `SELF` is
    /// substituted with this peer's id once the handshake reveals it.
    #[arg(long, default_value = "")]
    input: String,
    /// The shared local endpoint the punch binds with `SO_REUSEPORT` (§7.3).
    ///
    /// **The harness pins this rather than letting the OS choose**, for the same
    /// reason §6.7.3 exists: the address a peer advertises must be the socket it
    /// punches from. A driver that took an ephemeral port could not be told
    /// which endpoint to put behind a NAT.
    #[arg(long)]
    local_addr: String,
    /// Seconds to run.
    #[arg(long, default_value_t = 20.0)]
    timeout: f64,
    /// `host:port` to advertise as this side's `srflx` candidate — the public
    /// NAT mapping the counterpart dials. Empty → `--local-addr`.
    ///
    /// Behind SNAT the address a peer *binds* is private and unreachable, so a
    /// driver that could only advertise its bind address forces one side of a
    /// cross-impl run to sit public — which caps the harness at one NAT. The
    /// harness knows the topology; this is where it says so.
    ///
    /// §6.7.3's MUST still governs: whatever is advertised must be the mapping
    /// of the socket this peer punches from, which is `--local-addr`. A wrong
    /// value here describes a hole that never opens.
    #[arg(long, default_value = "")]
    srflx: String,
    /// `host:port` of a peer serving `EXTENSION-NETWORK` §6.7.1
    /// `observe-address` — **discover** the mapping instead of being told it.
    ///
    /// This is the fidelity rung above `--srflx`. With `--srflx` the harness
    /// asserts what the NAT will do; with `--reflector` the peer finds out the
    /// way a deployed peer must, by dialing a reflector **from the very socket
    /// it will punch from** (§6.7.3) and being told the source it arrived from.
    /// A harness that asserts the mapping cannot catch a peer that gathers on
    /// the wrong socket; this can.
    ///
    /// Takes precedence over `--srflx`. Failure is fatal rather than a silent
    /// fall back to the bind address: a peer that could not observe its mapping
    /// has no reflexive candidate, and advertising the private bind address
    /// behind SNAT is the lie §6.7.3 exists to forbid.
    #[arg(long, default_value = "")]
    reflector: String,
    /// **Probe mode** (`EXTENSION-SIGNALING` §11.2 SHOULD / §9.3 MUST): classify
    /// this socket's NAT mapping from several reflectors and exit. Punches
    /// nothing; needs no `--node`, `--role`, `--mode` or `--input`.
    ///
    /// This is the G4 pre-drive screen. Without it, a symmetric NAT presents as a
    /// punch failing late at the crossing — indistinguishable from a counterpart
    /// that never showed up, which is the same silent shape as the S0 rendezvous
    /// mismatch. With it, the screen is one command per side.
    #[arg(long, default_value_t = false)]
    nat_type: bool,
    /// Comma-separated `host:port` reflectors for `--nat-type`.
    ///
    /// **All of them are consulted from `--local-addr`**, because a mapping
    /// belongs to a socket (§6.7.3): two reflectors reached from two sockets make
    /// a punchable cone NAT report two ports — the exact signature of the
    /// symmetric NAT the probe looks for, with well-formed observations and a
    /// confidently wrong verdict nothing downstream can catch.
    ///
    /// §6.7.1 forbids concluding from one, so a single reachable reflector is a
    /// refusal (`ok:false`), not a verdict — even when its observation is right.
    #[arg(long, default_value = "")]
    reflectors: String,
    /// **Negative control:** never dial, listen only — the pre-G1 one-dials
    /// shape.
    ///
    /// Behind a NAT this side's hole never opens, so the counterpart's SYN
    /// reaches a closed mapping and the punch MUST fail. A dual-NAT harness
    /// whose negative control *passes* is not testing traversal, so this exists
    /// to make the harness prove itself.
    #[arg(long)]
    suppress_dial: bool,
    /// Log to stderr. The JSON line stays the only thing on stdout.
    #[arg(long)]
    debug: bool,
}

fn derive_key(mode: &str, value: &str) -> anyhow::Result<RendezvousKey> {
    Ok(match mode {
        "tag" => key::tag_key(value),
        "secret" => key::secret_key(value),
        "lobby" => key::lobby_key(value),
        "pair" => {
            let (a, b) = value.split_once(',').ok_or_else(|| {
                anyhow::anyhow!("--input for mode 'pair' must be 'peer-a,peer-b'")
            })?;
            if a.is_empty() || b.is_empty() {
                anyhow::bail!("--input for mode 'pair' must be 'peer-a,peer-b'");
            }
            key::pair_key(a, b)
        }
        other => anyhow::bail!("unknown --mode {:?}", other),
    })
}

/// The candidate set this driver advertises: exactly one `srflx`.
///
/// **One candidate, and `srflx` even on loopback** — matching Go's driver, so a
/// cross-impl run puts identical candidate sets on the wire and a divergence is
/// about the punch rather than about what each side chose to advertise. With no
/// `--srflx` the address is the bind address, which on loopback is genuinely
/// where this peer is reachable.
///
/// A `host` candidate is deliberately not added alongside: behind SNAT it is a
/// private address the counterpart cannot reach, and a candidate is a claim the
/// counterpart spends its crossing budget on.
struct Advertised(Vec<entity_signaling::coordination::Candidate>);

#[async_trait::async_trait]
impl entity_peer::punch_establisher::CandidateGatherer for Advertised {
    async fn gather(&self) -> Result<Vec<entity_signaling::coordination::Candidate>, String> {
        Ok(self.0.clone())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ---------------------------------------------------------------------------
// Proof of punch — §3.2
// ---------------------------------------------------------------------------

/// A grant admitting a stranger to `system/protocol/connect`.
///
/// The punched peer is an ephemeral identity the responder has never seen, which
/// is exactly the posture a real punch has: the two peers met through a
/// rendezvous bucket, not through a pre-shared roster. `ping` itself is answered
/// ahead of the handler-scope check (see `connection.rs`), but `authenticate`
/// still has to issue *a* capability, so the seed policy cannot be empty.
fn connect_seed() -> Vec<(String, Vec<GrantEntry>)> {
    vec![(
        "default".to_string(),
        vec![GrantEntry {
            handlers: entity_capability::PathScope::new(vec![entity_protocol::CONNECT_PATH.into()]),
            resources: entity_capability::PathScope::new(vec![]),
            operations: entity_capability::IdScope::new(vec!["ping".to_string()]),
            peers: None,
            constraints: None,
            allowances: None,
        }],
    )]
}

/// The **initiator** half of §7.4.1: run the HELLO client over the punched path,
/// then round-trip one operation on it.
///
/// §7.4.1 is a MUST and it is not a socket rule — it pins the initiator to the
/// client half *regardless of which end dialed the TCP connection*. After a punch
/// both sides dialed simultaneously, so nothing in the resulting socket pair says
/// who speaks first; two implementations that resolve it differently produce
/// either a crossed handshake or two peers both waiting, on a connection that
/// punched perfectly.
///
/// **The initiator is also the §6.5 (b) minter, so it needs a dispatch stack.**
/// A punch meets at a §3 rendezvous key, which is the symmetric establishment
/// EXTENSION-SIGNALING §6.5 (b) describes: the dialer mints the reciprocal grant
/// for the acceptor, and — the half that fails silently — must *serve* the
/// reach-back that wields it (V7 §6.11(b) dialer-side reentry). Both halves need
/// a local `PeerShared`. This driver used to call the bare `perform_connect`,
/// i.e. `reentry = None` and `established_via_rendezvous_key = false`, so it
/// minted nothing however symmetric the establishment was — which is why the
/// cross-impl V3 direction-B cell (Rust minter → Go acceptor) measured 0/4 and
/// was reported as unscorable rather than as a divergence.
///
/// The flag is read off the `LivePath` rather than hardcoded: the classification
/// belongs to the establisher that produced the path (§4.4), and a driver that
/// asserted `true` on its own would be exactly the one-sided field §7.4.1 rules
/// out.
async fn verify_as_client(
    conn: Connection,
    keypair: &IdentityKeypair,
    established_via_rendezvous_key: bool,
) -> anyhow::Result<Verified> {
    let peer = PeerBuilder::new()
        .identity_keypair(keypair.clone_identity())
        .with_seed_policy(connect_seed())
        .build()
        .map_err(|e| anyhow::anyhow!("build dialing peer: {}", e))?;
    let shared = peer.shared();
    let remote_conn = remote::perform_connect_with_dispatch(
        conn,
        keypair,
        entity_hash::HASH_ALGORITHM_SHA256,
        Some(shared),
        established_via_rendezvous_key,
    )
    .await
    .map_err(|e| anyhow::anyhow!("handshake over the punched path: {}", e))?;

    // One ordinary operation. `ping` is the §5.2 keepalive verb every peer
    // answers, which makes it the cheapest thing both implementations already
    // have — Go verifies with the same exchange.
    // The §5.2 payload shape, as `keepalive.rs` builds it.
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (
            entity_ecf::text("sequence"),
            entity_ecf::Value::Integer(1.into()),
        ),
        (
            entity_ecf::text("timestamp"),
            entity_ecf::Value::Integer(0.into()),
        ),
    ]));
    let params = entity_entity::Entity::new("system/network/ping", data)
        .map_err(|e| anyhow::anyhow!("build ping: {}", e))?;
    let uri = format!(
        "/{}/{}",
        remote_conn.remote_peer_id,
        entity_protocol::CONNECT_PATH
    );
    // The mint has already happened or not by now, and the answer must survive a
    // failing ping — a `?` here would report `grant_sent:false` for a grant that
    // was sent, which is the same conflation this field exists to remove.
    let grant_sent = remote_conn.reciprocal_grant_sent();
    let ping = remote::send_execute(
        &remote_conn,
        keypair,
        &uri,
        "ping",
        &params,
        None,
        None,
        None,
        &std::collections::HashMap::new(),
        None,
    )
    .await;

    // **Linger before dropping the connection** (`entity-core-go` ask 1). The
    // acceptor is about to originate under the grant this seat just minted it,
    // and `remote_conn`'s `Drop` aborts the reader task that would serve it — so
    // returning here severs the reach-back mid-flight. The wait happens on every
    // outcome: the mint landed at handshake time, so the counterpart's reach is
    // in flight regardless of what the ping did. See `LINGER_AFTER_VERIFY_MS`.
    tokio::time::sleep(Duration::from_millis(LINGER_AFTER_VERIFY_MS)).await;
    drop(remote_conn);

    match ping {
        Ok(resp) if resp.status == 200 => Ok(Verified {
            ok: true,
            grant_sent,
            why: None,
        }),
        Ok(resp) => Ok(Verified {
            ok: false,
            grant_sent,
            why: Some(format!(
                "ping over the punched path answered {}",
                resp.status
            )),
        }),
        Err(e) => Ok(Verified {
            ok: false,
            grant_sent,
            why: Some(format!("ping over the punched path: {}", e)),
        }),
    }
}

/// What the initiator learned on the punched path. `grant_sent` is deliberately
/// independent of `ok`: the §6.5 (b) mint happens at handshake time, so it is a
/// fact even when the ping that follows it fails.
struct Verified {
    ok: bool,
    grant_sent: bool,
    why: Option<String>,
}

/// How long the initiator holds the punched connection open after its pong —
/// the mirror of `entity-core-go`'s `lingerAfterVerify`, same 2s.
///
/// **`entity-core-go` ask 1, and the symmetric twin of a bug they fixed for us.**
/// On 2026-08-01 their responder returned the moment it observed establishment
/// and dropped the socket under an initiator still waiting on its pong; they
/// added a linger. Our initiator then did the same thing one role over — exiting
/// ~1.4 ms after its pong, under an acceptor about to exercise the very
/// authority that initiator had just granted it. Their measurement: the reach
/// dispatch started 0.2 ms after the grant landed and died on `connection
/// closed`, never a 401/403. **A symmetric establishment wants a symmetric
/// linger**, and until it exists no harness on either side can measure reach in
/// direction B.
///
/// It is a driver artifact being compensated for, not a protocol timing: a real
/// peer keeps a punched transport pooled for reuse, and a one-shot driver that
/// tears it down the instant it verifies is the thing that does not resemble a
/// peer.
const LINGER_AFTER_VERIFY_MS: u64 = 2000;

/// §6.5 (b) REACH leg — this seat is the acceptor: if the dialer minted us a
/// reciprocal grant, originate back over the connection *they* opened and report
/// what came of it. `entity-core-go` ask 2, and the mirror of the leg they built
/// in `26fd7b7`; the field names match theirs deliberately so one JSON contract
/// spans both drivers.
///
/// **Triggered on the grant landing, not on the establishment poll** — core-go's
/// ordering lesson, paid for twice on their side (first as `no transport
/// profile`, which reads like a resolution bug and is a lifetime bug, then as
/// `connection closed`). The grant landing is the moment authority exists *and*
/// the counterpart is still up; anything sequenced after the counterpart's own
/// round trip is racing its teardown.
///
/// Two facts, never folded into `ok`: `reciprocal_grant_received` says whether
/// the counterpart minted to us at all (the mirror of `reciprocal_grant_sent`),
/// and `reciprocal_reach_status` is what one dispatch under that grant returned.
/// `200` is reach; `401`/`403` is a grant that verifies and authorizes nothing —
/// the failure the whole mechanism exists to prevent, and the one invisible to
/// every test that stops at installation. Neither gates `ok`, because the punch's
/// own contract is about the punch and a counterpart that has not adopted §6.5
/// (b) must degrade to one-directional rather than fail a punch that worked.
async fn reciprocal_reach_back(
    shared: &Arc<entity_peer::PeerShared>,
    initiator_id: &str,
    keypair: &IdentityKeypair,
) -> Vec<(String, Json)> {
    // Wait the CONFORMANCE FLOOR, not our own production bound (§6.5 (b)
    // Delivery + timing, arch Q3): a vector that waits only as long as this peer
    // would is a verdict about our impatience, not about the peer under test.
    let polls = entity_peer::remote::RECIPROCAL_GRANT_VECTOR_FLOOR_MS / 25;
    let mut endpoint = None;
    for _ in 0..polls {
        if let Some(e) = shared.remote.get_inbound(initiator_id) {
            if e.originating_capability().is_some() {
                endpoint = Some(e);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let Some(endpoint) = endpoint else {
        return vec![("reciprocal_grant_received".into(), Json::Bool(false))];
    };
    let mut out = vec![("reciprocal_grant_received".into(), Json::Bool(true))];

    // The §4.4 FLOOR's own scope — `system/tree` `get` over `system/type/*`.
    // Every peer seeds its type entities, so this reaches a real entity on any
    // conformant counterpart without assuming anything the floor does not grant,
    // and it stays in scope even against a counterpart that still mints the bare
    // floor rather than the assembled set. Same target core-go's leg uses.
    //
    // `mode` is left ABSENT rather than sent as `hash`: optional fields SHOULD be
    // absent, and `mode:hash` is a known gap in this repo's own tree handler
    // (docs/BACKLOG.md) — sending a field we do not serve would make the vector
    // depend on the counterpart implementing something we do not.
    let path = format!("/{}/system/type/system/peer", initiator_id);
    let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
        entity_ecf::text("path"),
        entity_ecf::text(&path),
    )]));
    let params = match entity_entity::Entity::new("system/tree/get-params", params_data) {
        Ok(p) => p,
        Err(e) => {
            out.push((
                "reciprocal_reach_error".into(),
                Json::Str(format!("build get request: {}", e)),
            ));
            return out;
        }
    };
    let resource = entity_capability::ResourceTarget {
        targets: vec![path.clone()],
        exclude: vec![],
    };

    match remote::send_execute(
        endpoint.as_ref(),
        keypair,
        &format!("/{}/system/tree", initiator_id),
        "get",
        &params,
        Some(&resource),
        None,
        None,
        &std::collections::HashMap::new(),
        None,
    )
    .await
    {
        Ok(resp) => {
            out.push((
                "reciprocal_reach_status".into(),
                Json::Num(resp.status as usize),
            ));
            out.push(("reciprocal_reach".into(), Json::Bool(resp.status == 200)));
        }
        // A transport failure is not a verdict on the grant, so it is reported
        // as its own field rather than as a status.
        Err(e) => out.push((
            "reciprocal_reach_error".into(),
            Json::Str(format!("originate under reciprocal grant: {}", e)),
        )),
    }
    out
}

// ---------------------------------------------------------------------------
// JSON — hand-rolled, matching `signaling-meet` so the two drivers' output can
// be diffed without a parser in the way.
// ---------------------------------------------------------------------------

enum Json {
    Bool(bool),
    Str(String),
    /// Counts (`reflector_ok` / `reflector_all`) — the NAT-type contract's only
    /// numbers, and they are cardinalities, so `usize` is the whole domain.
    Num(usize),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn render_value(v: &Json) -> String {
    match v {
        Json::Bool(b) => b.to_string(),
        Json::Str(s) => format!("\"{}\"", escape(s)),
        Json::Num(n) => n.to_string(),
        Json::Arr(items) => format!(
            "[{}]",
            items.iter().map(render_value).collect::<Vec<_>>().join(",")
        ),
        Json::Obj(fields) => render(fields),
    }
}

fn render(fields: &[(String, Json)]) -> String {
    let body: Vec<String> = fields
        .iter()
        .map(|(k, v)| format!("\"{}\":{}", escape(k), render_value(v)))
        .collect();
    format!("{{{}}}", body.join(","))
}

fn emit_and_exit(fields: Vec<(String, Json)>) -> ! {
    let ok = fields
        .iter()
        .any(|(k, v)| k == "ok" && matches!(v, Json::Bool(true)));
    println!("{}", render(&fields));
    std::process::exit(if ok { 0 } else { 1 })
}

fn fail(role: &str, message: String) -> ! {
    emit_and_exit(vec![
        ("ok".into(), Json::Bool(false)),
        ("role".into(), Json::Str(role.to_string())),
        ("error".into(), Json::Str(message)),
    ])
}

// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if args.debug {
        // stderr only — stdout carries exactly the one JSON line a harness parses.
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "debug".into()),
            )
            .init();
    }

    // Probe mode is a different program sharing a binary: it punches nothing, so
    // none of the punch's required flags apply and none are validated.
    if args.nat_type {
        match run_nat_type(&args).await {
            Ok(fields) => emit_and_exit(fields),
            Err(e) => emit_and_exit(vec![
                ("probe".into(), Json::Str("nat-type".into())),
                ("ok".into(), Json::Bool(false)),
                ("error".into(), Json::Str(e.to_string())),
            ]),
        }
    }

    if args.role != "initiator" && args.role != "responder" {
        fail(&args.role, "--role must be initiator|responder".into());
    }
    if args.node.is_empty() {
        fail(&args.role, "--node is required".into());
    }
    if !matches!(args.mode.as_str(), "tag" | "secret" | "lobby" | "pair") {
        fail(&args.role, "--mode must be tag|secret|lobby|pair".into());
    }
    if args.input.is_empty() {
        fail(&args.role, "--input is required".into());
    }

    match run(&args).await {
        Ok(fields) => emit_and_exit(fields),
        Err(e) => fail(&args.role, e.to_string()),
    }
}

/// `--nat-type` — the §6.7.1 multi-reflector probe.
///
/// The output contract is Go's (`ROUTING-2026-08-02-nat-type-precheck-and-the-
/// same-socket-trap.md` §1), matched field for field so a harness runs either
/// binary unchanged.
///
/// **`ok` means a conclusion was reachable, not that the verdict was favourable.**
/// `endpoint-dependent` with `ok:true` is a *successful* probe reporting a
/// relay-only peer — the run did its job. One reachable reflector is `ok:false`,
/// because §6.7.1 forbids concluding from one.
async fn run_nat_type(args: &Args) -> anyhow::Result<Vec<(String, Json)>> {
    let local_addr: SocketAddr = args.local_addr.parse().map_err(|_| {
        anyhow::anyhow!("--local-addr must be host:port, got {:?}", args.local_addr)
    })?;

    let reflectors: Vec<String> = args
        .reflectors
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if reflectors.is_empty() {
        anyhow::bail!("--reflectors is required for --nat-type (comma-separated host:port)");
    }

    // Ephemeral identity, same as the punch path: a reflector answers strangers
    // (§6.7.4 makes network-reflect a broad default grant).
    let keypair = IdentityKeypair::Ed25519(Keypair::generate());

    let detection = entity_peer::srflx::detect_mapping(
        local_addr,
        &reflectors,
        &keypair,
        entity_hash::HASH_ALGORITHM_SHA256,
        Duration::from_secs_f64(args.timeout),
    )
    .await;

    let a = &detection.assessment;
    let conclusive = detection.conclusive();

    Ok(vec![
        ("probe".into(), Json::Str("nat-type".into())),
        ("ok".into(), Json::Bool(conclusive)),
        ("class".into(), Json::Str(a.class.as_str().to_string())),
        ("punchable".into(), Json::Bool(a.punchable())),
        (
            "mapping".into(),
            Json::Str(a.mapping.clone().unwrap_or_default()),
        ),
        ("local_addr".into(), Json::Str(local_addr.to_string())),
        (
            "observations".into(),
            Json::Arr(
                a.observations
                    .iter()
                    .map(|o| {
                        Json::Obj(vec![
                            ("reflector".into(), Json::Str(o.reflector.clone())),
                            ("observed".into(), Json::Str(o.observed.clone())),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("reflector_ok".into(), Json::Num(detection.reflector_ok)),
        ("reflector_all".into(), Json::Num(detection.reflector_all)),
        (
            "errors".into(),
            Json::Arr(
                detection
                    .errors
                    .iter()
                    .map(|e| Json::Str(e.clone()))
                    .collect(),
            ),
        ),
        ("reason".into(), Json::Str(a.reason.clone())),
    ])
}

async fn run(args: &Args) -> anyhow::Result<Vec<(String, Json)>> {
    let local_addr: SocketAddr = args.local_addr.parse().map_err(|_| {
        anyhow::anyhow!("--local-addr must be host:port, got {:?}", args.local_addr)
    })?;

    // A fresh ephemeral identity per run — what a stranger is, and what the
    // node's `--open` posture must admit.
    let keypair = IdentityKeypair::Ed25519(Keypair::generate());
    let self_id = keypair.peer_id().to_string();

    // The node's peer-id comes from a handshake, not from a flag: the carrier is
    // dialed by address (never tree-resolved — the circularity the whole punch
    // exists to escape), and the connection authenticates it.
    let probe = transport::TcpConnector
        .connect(&format!("tcp://{}", args.node))
        .await
        .map_err(|e| anyhow::anyhow!("dial node {}: {}", args.node, e))?;
    let node_peer_id = remote::perform_connect(probe, &keypair, entity_hash::HASH_ALGORITHM_SHA256)
        .await
        .map_err(|e| anyhow::anyhow!("handshake with node {}: {}", args.node, e))?
        .remote_peer_id
        .clone();

    let value = args.input.replace("SELF", &self_id);
    let k = derive_key(&args.mode, &value)?;

    // Precedence: reflector (discovered) > --srflx (asserted) > bind address.
    let (srflx_addr, srflx_source) = if !args.reflector.is_empty() {
        let gatherer = entity_peer::srflx::SrflxGatherer::new(
            &args.reflector,
            local_addr,
            keypair.clone_identity(),
            entity_hash::HASH_ALGORITHM_SHA256,
            None,
        );
        let observed = gatherer
            .observe()
            .await
            .map_err(|e| anyhow::anyhow!("srflx gather from {}: {}", args.reflector, e))?;
        (observed, "reflector")
    } else if !args.srflx.is_empty() {
        (args.srflx.clone(), "flag")
    } else {
        (local_addr.to_string(), "bind")
    };
    let advertised = Advertised(vec![entity_signaling::coordination::Candidate::new(
        entity_signaling::coordination::CANDIDATE_SRFLX,
        entity_signaling::coordination::SUBSTRATE_TCP,
        &srflx_addr,
    )]);

    let establisher = PeerPunchEstablisher::new(
        &node_peer_id,
        format!("tcp://{}", args.node),
        &self_id,
        local_addr,
        keypair.clone_identity(),
        Arc::new(transport::TcpConnector),
        entity_hash::HASH_ALGORITHM_SHA256,
    )
    // The harness supplies the out-of-band agreement the §10.3 seam lacks, so
    // every mode is reachable here, not just `pair`.
    .with_rendezvous_key(k)
    .with_gatherer(Arc::new(advertised));
    let establisher = if args.suppress_dial {
        establisher.suppress_dial()
    } else {
        establisher
    };

    let deadline =
        || EstablishCtx::dispatch(web_time::Instant::now() + Duration::from_secs_f64(args.timeout));

    let why: Option<String>;
    // §6.5 (b): initiator-only. `false` on the responder seat is a fact about
    // the role, not a failure — the acceptor does not mint.
    let mut reciprocal_grant_sent = false;
    // §6.5 (b) REACH, responder-only — `reciprocal_grant_received`,
    // `reciprocal_reach_status`, `reciprocal_reach`, `reciprocal_reach_error`,
    // matching `entity-core-go`'s field names so one JSON contract covers both
    // drivers. Absent on the initiator seat: only the acceptor can wield.
    let mut reach_fields: Vec<(String, Json)> = Vec::new();
    let (punched, remote_peer, verified) = if args.role == "initiator" {
        match establisher.establish_live(deadline(), "").await {
            Ok(path) => {
                // §4.4: the establisher classifies, the driver carries.
                let rendezvous = path.established_via_rendezvous_key;
                let conn = path.connection;
                let remote_addr = conn.remote_addr.clone();
                // **Keep the cause.** A bare `verified:false` from this side is
                // indistinguishable between a refused ping, a timed-out ping and
                // a failed handshake — which is exactly the ambiguity that made
                // the Go-reported Rust-initiator divergence un-diagnosable from
                // the JSON line alone.
                match verify_as_client(conn, &keypair, rendezvous).await {
                    Ok(v) => {
                        reciprocal_grant_sent = v.grant_sent;
                        why = v.why;
                        (true, remote_addr, v.ok)
                    }
                    Err(e) => {
                        why = Some(e.to_string());
                        (true, remote_addr, false)
                    }
                }
            }
            // **The seam's own reason, not a generic sentence.** This line used
            // to read "no direct path within the deadline" for every outcome —
            // including a §6.3 `Require` refusal, which is a policy decision
            // about a reachable counterpart and presented here as a NAT problem.
            // That is the exact mis-read the seam was changed to `Result` to fix,
            // and this is the operator-visible field where it landed.
            Err(e) => {
                why = Some(e.to_string());
                (false, String::new(), false)
            }
        }
    } else {
        match establisher.respond_once(deadline(), "").await {
            Some((conn, initiator_id)) => {
                let remote_addr = conn.remote_addr.clone();
                // §7.4.1: the responder **serves**. `handle_connection` is the
                // ordinary accept-side loop — which is the point of §10.3
                // obligation 1: a punched connection is served by exactly the
                // path a dialed one is, with no punch-aware branch.
                let peer = PeerBuilder::new()
                    .identity_keypair(keypair.clone_identity())
                    .with_seed_policy(connect_seed())
                    .build()
                    .map_err(|e| anyhow::anyhow!("build serving peer: {}", e))?;
                let shared = peer.shared();
                // Serving is spawned rather than awaited so the REACH leg below
                // can run **while the connection is still up**. Awaiting it here
                // is what made the acceptor's own authority unmeasurable from
                // this seat: by the time `handle_connection` returns, the thing
                // the grant authorizes is gone.
                let serving = shared.clone();
                let served_task = tokio::spawn(async move {
                    entity_peer::connection::handle_connection(conn, serving).await
                });

                // §6.5 (b) REACH — `entity-core-go` ask 2. This seat is the
                // ACCEPTOR, so it is the only one that can wield the reciprocal
                // grant, and a crossing that shows only the grant arriving
                // proves installation, not reach.
                reach_fields = reciprocal_reach_back(&shared, &initiator_id, &keypair).await;

                let served =
                    tokio::time::timeout(Duration::from_secs_f64(args.timeout), served_task).await;
                // **Clean end-of-stream only.** The initiator closes once its
                // ping is answered and its linger elapses, so `Ok(Ok(Ok(())))`
                // is a served handshake followed by an ordinary disconnect. A
                // `handle_connection` error is a handshake that did not
                // complete — counting it would report `verified` on the exact
                // failure this field exists to catch.
                let verified = matches!(&served, Ok(Ok(Ok(()))));
                why = match &served {
                    Ok(Ok(Ok(()))) => None,
                    Ok(Ok(Err(e))) => Some(format!("serving the punched path failed: {}", e)),
                    Ok(Err(e)) => Some(format!("the serving task did not finish: {}", e)),
                    Err(_) => Some("served path did not close within the timeout".to_string()),
                };
                (true, remote_addr, verified)
            }
            None => {
                why = Some("no direct path within the deadline".to_string());
                (false, String::new(), false)
            }
        }
    };

    let dialed_outbound = establisher.outbound_attempts() > 0;
    let mut fields = vec![
        ("ok".into(), Json::Bool(punched && verified)),
        ("role".into(), Json::Str(args.role.clone())),
        ("mode".into(), Json::Str(args.mode.clone())),
        ("input".into(), Json::Str(value)),
        ("key".into(), Json::Str(hex(k.as_bytes()))),
        ("peer_id".into(), Json::Str(self_id)),
        ("node_peer_id".into(), Json::Str(node_peer_id)),
        ("punched".into(), Json::Bool(punched)),
        ("dialed_outbound".into(), Json::Bool(dialed_outbound)),
        // §6.5 (b), initiator-only, additive to the CLI/JSON contract: whether
        // this seat minted and sent the reciprocal reentry grant. It makes the
        // cross-impl V3 direction-B cell scorable from the output line — a
        // `false` here says the *minter* declined, a `true` with no grant at the
        // acceptor says the acceptance path dropped it.
        (
            "reciprocal_grant_sent".into(),
            Json::Bool(reciprocal_grant_sent),
        ),
        ("local_addr".into(), Json::Str(local_addr.to_string())),
        ("srflx".into(), Json::Str(srflx_addr)),
        ("srflx_source".into(), Json::Str(srflx_source.to_string())),
        ("remote_addr".into(), Json::Str(remote_peer)),
        ("verified".into(), Json::Bool(verified)),
        (
            "detail".into(),
            Json::Str(why.unwrap_or_else(|| String::from("ok"))),
        ),
    ];
    // Responder-only, and appended rather than always-present: a field that is
    // absent says "this seat cannot wield" (it is the minter), which a `false`
    // would blur into "it tried and got nothing".
    fields.extend(reach_fields);
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four modes derive, and every key is 33 bytes at the SHA-256 floor —
    /// the property that catches an otherwise-correct SHA-384 impl. Same
    /// assertion `signaling-meet` makes, because a punch that derives a
    /// different key from the same `--mode/--input` never meets at all.
    #[test]
    fn every_mode_derives_a_floor_key() {
        for (mode, input) in [
            ("tag", "chess"),
            ("secret", "correct-horse-battery-staple"),
            ("lobby", "lobby:default"),
            ("pair", "alice,bob"),
        ] {
            let k = derive_key(mode, input).expect("derives");
            assert_eq!(k.as_bytes().len(), 33);
            assert_eq!(
                k.as_bytes()[0],
                0x00,
                "{} is not at the SHA-256 floor",
                mode
            );
        }
    }

    /// The punch driver must derive the *same* key as the meet driver for the
    /// same inputs — they share a node and a bucket, and a harness that runs
    /// both against one `--mode tag --input chess` expects one key.
    #[test]
    fn pair_is_order_independent_and_needs_both_ids() {
        assert_eq!(
            derive_key("pair", "alice,bob").unwrap(),
            derive_key("pair", "bob,alice").unwrap()
        );
        assert!(derive_key("pair", "alice").is_err());
        assert!(derive_key("pair", "alice,").is_err());
        assert!(derive_key("pair", ",bob").is_err());
    }

    /// The JSON line is the contract's, field for field. A harness parses this;
    /// a rename is a cross-impl break, not a cosmetic edit.
    #[test]
    fn the_json_line_carries_the_contract_fields() {
        let rendered = render(&[
            ("ok".into(), Json::Bool(true)),
            ("punched".into(), Json::Bool(true)),
            ("dialed_outbound".into(), Json::Bool(true)),
            ("verified".into(), Json::Bool(false)),
            ("local_addr".into(), Json::Str("127.0.0.1:9001".into())),
        ]);
        assert_eq!(
            rendered,
            r#"{"ok":true,"punched":true,"dialed_outbound":true,"verified":false,"local_addr":"127.0.0.1:9001"}"#
        );
    }

    #[test]
    fn escapes_the_json_string_set() {
        assert_eq!(escape(r#"a"b"#), r#"a\"b"#);
        assert_eq!(escape(r"a\b"), r"a\\b");
        assert_eq!(escape("a\nb"), "a\\nb");
        assert_eq!(escape("a\u{0}b"), "a\\u0000b");
        assert_eq!(escape("café"), "café");
    }
}
