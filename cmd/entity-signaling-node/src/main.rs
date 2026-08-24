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
use entity_core::crypto::{IdentityKeypair, Keypair};
use entity_core::peer::transport::Listener;
use entity_core::peer::{PeerBuilder, PeerConfig};
use entity_signaling::{Limits, SignalingCore, SignalingHandler};

#[derive(Parser)]
#[command(
    name = "entity-signaling-node",
    about = "The system/signaling connection node — wrapped-surface rendezvous"
)]
struct Args {
    /// Address to listen on for cross-peer `execute` (the wrapped surface).
    #[arg(long, default_value = "0.0.0.0:4050")]
    listen: String,

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

    /// Bucket TTL in ms. The default is **60 s** (§1.1 pin 6, closing open item
    /// 3) and is published in `advertise`, so a deployment that moves it tells
    /// its peers rather than surprising them. Raising it far above the default
    /// mostly buys dead candidates: an `srflx` entry expires with the NAT
    /// binding that produced it, commonly inside 30–120 s.
    #[arg(long)]
    ttl_ms: Option<i64>,

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
        bucket_ttl_ms: args.ttl_ms.unwrap_or(Limits::default().bucket_ttl_ms),
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
        .handler(handler)
        .build()?;

    let listener = peer.listen().await?;
    println!("signaling node started");
    println!("  peer_id:   {}", peer.peer_id());
    println!("  tcp:       {}", listener.socket_addr());
    println!("  endpoint:  {}", endpoint);
    println!(
        "  limits:    ttl={}ms max_msg={}B per_key={} keys={}",
        limits.bucket_ttl_ms,
        limits.max_message_bytes,
        limits.max_messages_per_key,
        limits.max_keys
    );
    println!("  lobby:     {}", lobby_constant);
    println!("  surface:   wrapped (cross-peer execute) — offer/collect/advertise");
    println!("  reflect:   not served here; unwrapped listener's verb (§1.4, Stage 2)");

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

    let listeners: Vec<Box<dyn Listener>> = vec![Box::new(listener)];
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
