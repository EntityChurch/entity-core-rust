//! `entity-signaling-node` — a peer that runs the connection node and nothing
//! else (`PROPOSAL-CONNECTION-NODE` §3, §4).
//!
//! **This binary is the isolation proof.** It stands up an ordinary peer and
//! installs `system/signaling` through the public
//! [`PeerBuilder::handler`](entity_core::peer::PeerBuilder::handler) seam — the
//! same seam any third-party extension would use. That seam already mints the
//! interface entity, the handler entity, the dispatch-index binding, and the
//! §6.9 capability grant for an externally-supplied handler, so **not one line
//! of `core/peer` (or any other shared core crate) changed to make this work.**
//!
//! §3 makes that the deliverable rather than a nicety: *"the isolation boundary
//! is the deliverable, not just the feature ... if the node cannot be built as a
//! clean optional extension, that is a finding worth having before a second repo
//! makes the coupling invisible."* For the dispatch half, it can.
//!
//! Deployment is deliberately minimal (§4): one public instance on a small VM,
//! zero bulk storage, transient ~1 KB per handshake. The `system/device`-backed
//! fleet/management arc is explicitly **out of this feature's path** — it stays
//! under W-FLEET, seeded by this node but not gating it.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use entity_capability::GrantEntry;
use entity_core::crypto::{IdentityKeypair, Keypair};
use entity_core::peer::transport::Listener;
use entity_core::peer::{PeerBuilder, PeerConfig};
use entity_signaling::{signaling_seed_grants, Limits, SignalingCore, SignalingHandler};

#[derive(Parser)]
#[command(
    name = "entity-signaling-node",
    about = "The system/signaling connection node — wrapped-surface rendezvous"
)]
struct Args {
    /// Address to listen on for cross-peer `execute` (the wrapped surface).
    #[arg(long, default_value = "0.0.0.0:4050")]
    listen: String,

    /// **Additionally** listen for WebSocket connections here — the browser's
    /// only way in.
    ///
    /// A browser cannot open a raw TCP socket, so without this a browser peer
    /// cannot reach the carrier **at all** and §6.5 coordination never starts —
    /// no offer is ever deposited, regardless of what WebRTC would have done
    /// afterwards. `--listen` alone serves native peers only.
    ///
    /// This is additive, not a replacement: both listeners feed the same peer
    /// through `run_multi`, so a native peer on `--listen` and a browser peer
    /// on `--ws-listen` rendezvous in the same buckets. That is the whole point
    /// — a browser and a native peer must be able to find each other.
    ///
    /// Off by default: a node that binds a second port without being asked is
    /// a deployment surprise, and the native cross-impl gates do not need it.
    #[arg(long = "ws-listen", value_name = "ADDR")]
    ws_listen: Option<String>,

    /// The endpoint this node publishes via `advertise`. Defaults to `--listen`,
    /// which is wrong behind NAT or a load balancer — set it explicitly in any
    /// real deployment, since peers dial what this says.
    #[arg(long)]
    endpoint: Option<String>,

    /// Keypair file. Generated ephemerally when absent, which is fine for a
    /// stateless introducer: §1.3 says losing a node drops in-flight handshakes
    /// and loses nothing that mattered. A stable identity matters only so peers
    /// can pin *this* node in their config or a registry pool.
    #[arg(long)]
    keypair: Option<PathBuf>,

    /// Bucket TTL in **seconds**. The default is **60 s** (§5 pin 6) and is
    /// published in `advertise` as `ttl_seconds`, so a deployment that moves it
    /// tells its peers rather than surprising them. Raising it far above the
    /// default mostly buys dead candidates: an `srflx` entry expires with the
    /// NAT binding that produced it, commonly inside 30–120 s.
    ///
    /// Seconds, not ms, because §4.5 publishes seconds — an operator flag in a
    /// unit the node cannot publish is a sub-second TTL that advertises as `0`.
    #[arg(long)]
    ttl_seconds: Option<u64>,

    /// Override the pool's `lobby` key constant (§2.2). Omit to use
    /// `lobby:default` — which every peer already assumes, so an override only
    /// makes sense for a pool that wants its own "anyone here right now" space,
    /// and it must be set identically on every node in that pool.
    #[arg(long)]
    lobby: Option<String>,

    /// Seconds between reaper passes. Purely memory reclaim — `collect` already
    /// refuses to return expired deposits, so this never changes what a peer
    /// observes.
    #[arg(long, default_value_t = 30)]
    reap_interval_secs: u64,

    /// Serve **any** peer that connects: seed the signaling grant under the
    /// `default` policy key.
    ///
    /// This is the public-introducer posture. It grants exactly
    /// `system/signaling:{offer,collect,advertise}` and nothing else — not a
    /// wildcard — but it does grant it to strangers, which is why it is opt-in
    /// rather than the default. Required to run the `PROPOSAL-CONNECTION-NODE`
    /// §6 cross-impl gate, since the go and py clients connect as unknown peers.
    #[arg(long)]
    open: bool,

    /// Serve a **named** peer: seed the signaling grant for this grantee only.
    /// Repeatable. Takes a Base58 PeerID (the pre-contact affordance) or a
    /// v7.64 hex identity-hash.
    ///
    /// This is the private-device-mesh posture (§2.1) — the case the wrapped
    /// surface exists for, where the capability grant *is* the admission
    /// control and naming your own peers is the point.
    #[arg(long = "grant", value_name = "PEER")]
    grants: Vec<String>,
}

/// Assemble the seed policy from the admission flags.
///
/// Empty means **closed**: a connecting peer receives only the §4.4 floor
/// (`system/tree:get` + `system/capability:request`) and every signaling call is
/// refused 403 before reaching a verb. That was this binary's behavior with no
/// way to change it until the go and py clients hit it — see
/// `entity_signaling::signaling_seed_grants`.
///
/// Closed is kept as the default deliberately. The wrapped surface's admission
/// control *is* the capability grant (§2.1), and the surface exists for the
/// private mesh; the open-to-strangers posture belongs to the unwrapped listener,
/// whose protocol (§5.1) is unwritten. A binary that served everyone by default
/// would quietly pre-empt that design. So the operator says which one they meant,
/// and the startup banner prints the answer back.
fn seed_policy(open: bool, grants: &[String]) -> Vec<(String, Vec<GrantEntry>)> {
    let mut entries = Vec::new();
    if open {
        entries.push(("default".to_string(), signaling_seed_grants()));
    }
    for grantee in grants {
        entries.push((grantee.clone(), signaling_seed_grants()));
    }
    entries
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    let endpoint = args.endpoint.clone().unwrap_or_else(|| args.listen.clone());

    let keypair = match args.keypair.as_deref() {
        Some(path) if path.exists() => IdentityKeypair::load_from_file(path)?,
        Some(path) => {
            let kp = IdentityKeypair::Ed25519(Keypair::generate());
            kp.save_to_file(path)?;
            tracing::info!(path = %path.display(), "generated node keypair");
            kp
        }
        None => IdentityKeypair::Ed25519(Keypair::generate()),
    };

    let limits = Limits {
        ttl_seconds: args.ttl_seconds.unwrap_or(Limits::default().ttl_seconds),
        ..Limits::default()
    };
    let mut core = SignalingCore::with_limits(&endpoint, limits.clone());
    if let Some(lobby) = args.lobby.as_deref() {
        core = core.with_lobby(lobby);
    }
    let lobby_constant = core.lobby_constant().to_string();
    let core = Arc::new(core);

    let peer_id = keypair.peer_id().to_string();
    // This node serves the three core verbs and nothing else. `reflect` is the
    // unwrapped listener's verb (`PROPOSAL-CONNECTION-NODE` §1.4) — the listener
    // owns the socket, so it owns the observation — and this binary exposes only
    // the wrapped surface, so it does not advertise or answer it.
    let handler = Arc::new(SignalingHandler::new(core.clone(), &peer_id));

    let peer = PeerBuilder::new()
        .identity_keypair(keypair)
        .config(PeerConfig {
            listen_addr: args.listen.clone(),
            ..PeerConfig::default()
        })
        .with_seed_policy(seed_policy(args.open, &args.grants))
        .handler(handler)
        .build()?;

    let listener = peer.listen().await?;
    // Bound before the banner so a bad `--ws-listen` fails at startup rather
    // than leaving a node that looks healthy and is unreachable from the one
    // client class the flag exists for.
    let ws_listener = match &args.ws_listen {
        Some(addr) => Some(
            entity_core::peer::transport::WebSocketListener::bind(addr)
                .await
                .map_err(|e| anyhow::anyhow!("--ws-listen {}: {}", addr, e))?,
        ),
        None => None,
    };

    println!("signaling node started");
    println!("  peer_id:   {}", peer.peer_id());
    println!("  tcp:       {}", listener.socket_addr());
    match &ws_listener {
        Some(ws) => println!("  websocket: {} (browsers connect here)", ws.socket_addr()),
        None => println!(
            "  websocket: not bound — NO browser peer can reach this node.\n             \
             Pass --ws-listen <addr> to serve browsers (§6.5's carrier)."
        ),
    }
    println!("  endpoint:  {}", endpoint);
    println!(
        "  limits:    ttl={}s max_blob={}B per_bucket={} keys={}",
        limits.ttl_seconds, limits.max_blob_bytes, limits.max_bucket_blobs, limits.max_keys
    );
    println!("  lobby:     {}", lobby_constant);
    println!("  surface:   wrapped (cross-peer execute) — offer/collect/advertise");
    println!("  reflect:   not served here; unwrapped listener's verb (§1.4, Stage 2)");
    // Print the admission posture, always. A node that serves nobody looks
    // identical to a working one until the first 403, and that is exactly how
    // this gap survived Stage 1 — the in-process tests seed a wildcard, so no
    // Rust-side run ever saw the closed default.
    match (args.open, args.grants.len()) {
        (true, 0) => println!("  admission: OPEN — any peer may offer/collect/advertise"),
        (true, n) => println!("  admission: OPEN + {} named grantee(s)", n),
        (false, 0) => println!(
            "  admission: CLOSED — no peer holds signaling authority; every call \
             will be refused 403.\n             Pass --open (serve anyone) or \
             --grant <peer-id> (serve named peers)."
        ),
        (false, n) => println!("  admission: {} named grantee(s) only", n),
    }

    // The reaper. Deliberately a plain task owned by this binary rather than a
    // handler-owned background service: the lifecycle contract that would let a
    // handler own it is `PROPOSAL-SDK-HANDLER-OWNED-SERVICES`, still DRAFT with
    // its §6 open item 1 — the manifest declaration's field shape — explicitly
    // "needs a call before impl". Building it as a fourth hardcoded
    // `start_engines` built-in is precisely what §3.1 says not to do.
    //
    // This loop is therefore a **data point for that open item**, not just a
    // workaround: it is the non-exposed resource class (a background loop with
    // an interval, holding no socket, reachable from nowhere). Its declaration
    // would need to say only that. The punch needs the other class — a UDP
    // listener with a bind address, outside the capability model — which is the
    // one §4's boundary rule requires the manifest to flag.
    let reaper_core = core.clone();
    let reap_interval = std::time::Duration::from_secs(args.reap_interval_secs.max(1));
    let reaper = tokio::spawn(async move {
        loop {
            tokio::time::sleep(reap_interval).await;
            let now = now_ms();
            let dropped = reaper_core.reap(now);
            if dropped > 0 {
                tracing::debug!(dropped, keys = reaper_core.key_count(), "reaped");
            }
        }
    });

    // Both listeners feed the SAME peer, so a browser and a native peer land in
    // the same rendezvous buckets and can find each other. That is the point of
    // running them together rather than standing up a separate browser node.
    let mut listeners: Vec<Box<dyn Listener>> = vec![Box::new(listener)];
    if let Some(ws) = ws_listener {
        listeners.push(Box::new(ws));
    }
    tokio::select! {
        result = peer.run_multi(listeners) => {
            if let Err(e) = result {
                tracing::error!("node stopped with error: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            println!("\nshutting down...");
        }
    }
    reaper.abort();
    Ok(())
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use entity_signaling::{OPERATIONS, PATTERN};

    /// The default is **closed**, and that has to be asserted here rather than
    /// inferred: the whole defect the go and py clients found was that this
    /// binary's admission posture was invisible from inside the repo, because
    /// nothing in Rust ever exercised the shipped construction path.
    #[test]
    fn no_flags_seeds_nothing() {
        assert!(seed_policy(false, &[]).is_empty());
    }

    #[test]
    fn open_seeds_the_default_key() {
        let policy = seed_policy(true, &[]);
        assert_eq!(policy.len(), 1);
        assert_eq!(policy[0].0, "default");
        assert_eq!(policy[0].1, signaling_seed_grants());
    }

    #[test]
    fn grants_are_keyed_per_named_peer() {
        let policy = seed_policy(false, &["peer-a".to_string(), "peer-b".to_string()]);
        let keys: Vec<&str> = policy.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["peer-a", "peer-b"]);
        assert!(policy.iter().all(|(_, g)| *g == signaling_seed_grants()));
    }

    /// `--open` and `--grant` compose rather than one overriding the other: an
    /// operator may serve strangers *and* hold a named entry for their own
    /// peers.
    #[test]
    fn open_and_named_grants_compose() {
        let policy = seed_policy(true, &["peer-a".to_string()]);
        let keys: Vec<&str> = policy.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["default", "peer-a"]);
    }

    /// The seeded grant must stay **narrow**. A wildcard here would hand every
    /// caller every handler on the node — which is what the live-test harness
    /// does, and precisely why that harness could not have caught the closed
    /// default.
    #[test]
    fn the_seeded_grant_is_signaling_only() {
        let grants = signaling_seed_grants();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].handlers.include, vec![PATTERN.to_string()]);
        assert!(!grants[0].operations.include.contains(&"*".to_string()));
        for op in OPERATIONS {
            assert!(grants[0].operations.include.contains(&(*op).to_string()));
        }
    }
}
