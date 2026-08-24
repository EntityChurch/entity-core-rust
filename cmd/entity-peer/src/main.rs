mod commands;
mod config;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "entity", about = "Entity Core Protocol peer")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // clap CLI enum: one value at a time, size is irrelevant
enum Commands {
    /// Manage identity keypairs
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },
    /// Manage peers
    Peer {
        /// Verbose output (debug logging)
        #[arg(short, long)]
        verbose: bool,
        /// Trace entity encode/decode and storage
        #[arg(long)]
        trace_entities: bool,
        /// Print span enter/close events with time.busy / time.idle for
        /// instrumented functions (handle_connection, dispatch_request,
        /// verify_request, read_frame, write_frame, dispatch_event,
        /// per-sync-hook). Implies a debug-level filter that includes the
        /// instrumented crates.
        #[arg(long)]
        profile: bool,
        #[command(subcommand)]
        action: PeerAction,
    },
}

#[derive(Subcommand)]
enum IdentityAction {
    /// Create a new identity keypair
    Create {
        /// Name for the identity (default: "default")
        #[arg(default_value = "default")]
        name: String,
        /// Signature key type (v7.67): ed25519 (default) or ed448
        #[arg(long, default_value = "ed25519")]
        key_type: String,
    },
    /// List all identities
    List,
    /// Show identity details
    Show {
        /// Identity name
        #[arg(default_value = "default")]
        name: String,
    },
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // clap CLI enum: one value at a time, size is irrelevant
enum PeerAction {
    /// Initialize a new peer
    Init {
        /// Peer name
        name: String,
        /// Admin identity name
        #[arg(long)]
        admin: Option<String>,
        /// Admin peer ID (external)
        #[arg(long = "admin-key")]
        admin_key: Option<String>,
        /// Signature key type (v7.67): ed25519 (default) or ed448. The
        /// minted keypair is saved with an algorithm-tagged PEM header;
        /// `peer start` auto-detects the type from that header.
        #[arg(long, default_value = "ed25519")]
        key_type: String,
    },
    /// Start a peer
    Start {
        /// Peer name
        name: String,
        /// TCP listen address (overrides config)
        #[arg(short, long)]
        listen: Option<String>,
        /// WebSocket listen address (e.g., 0.0.0.0:4041)
        #[arg(long)]
        ws_listen: Option<String>,
        /// HTTP-live listen address (e.g., 0.0.0.0:4080). Enables the
        /// `system/peer/transport/http` profile per EXTENSION-NETWORK
        /// §6.5.2c. Accepts POST EXECUTE → EXECUTE-RESPONSE per
        /// Amendment 3 (bare ECF body, Content-Length-framed). Matches
        /// Go peer's `-http-addr` flag for cross-impl interop.
        #[arg(long)]
        http_listen: Option<String>,
        /// HTTP-live URL path (default /entity). Operator choice per G1;
        /// the published profile's `endpoint.url` MUST advertise this
        /// path. Matches Go peer's `-http-path` flag.
        #[arg(long, default_value = "/entity")]
        http_path: String,
        /// HTTP-poll (serving-mode) listen address (e.g., 0.0.0.0:9201).
        /// Enables the `system/peer/transport/http-poll` profile per the
        /// serving-mode content-scope ruling
        /// (Posture 1, RECOMMENDED — isolated port for serving).
        /// Mutually exclusive with --http-poll-mount-on-live.
        /// Matches Go peer's `-http-poll-addr` flag.
        #[arg(long, conflicts_with = "http_poll_mount_on_live")]
        http_poll_addr: Option<String>,
        /// Mount the http-poll serving routes on the existing
        /// --http-listen listener (Posture 2 — same port for live +
        /// serving). Required when 80/443 must be reused. Mutually
        /// exclusive with --http-poll-addr.
        #[arg(long, conflicts_with = "http_poll_addr")]
        http_poll_mount_on_live: bool,
        /// Path prefix for poll routes when mounted on the live
        /// listener. Default `/poll`. Ignored unless
        /// --http-poll-mount-on-live is set. G4 advisory: operator
        /// MUST pick a non-colliding live --http-path.
        #[arg(long, default_value = "/poll")]
        http_poll_prefix: String,
        /// Content-namespace scope for the poll listener (RECOMMENDED
        /// default per ruling §1.2). Format: `system/content/<ns>`
        /// (e.g., `system/content/public`). The route serves H iff
        /// `/<peer_id>/<namespace>/{hex(H)}` is bound in the tree.
        /// Required when http-poll is enabled (no scope = no serving;
        /// closure-scope + whole-store opt-in land in E.3.x).
        #[arg(long)]
        serve_namespace: Option<String>,
        /// Closure-of-signed-root serving scope (NETWORK §6.5.6
        /// Amendment 10). The poll route serves the transitive trie-node
        /// closure reachable from `published-root.root_hash` (root node,
        /// interior sub-nodes, leaf-bound values, the published-root
        /// entity + its signature) — the floor that lets a consumer walk
        /// a signed root. Mutually exclusive with --serve-namespace; pair
        /// with --publish-root, which then publishes over the whole peer
        /// subtree. Matches Go peer's `--serve-closure-root`.
        #[arg(long, conflicts_with = "serve_namespace")]
        serve_closure_root: bool,
        /// Storage backend: "memory" or "sqlite" (overrides config.toml)
        #[arg(long)]
        storage: Option<String>,
        /// Issue wide-open grants on connection (debug only)
        #[arg(long)]
        debug_grants: bool,
        /// V7 §6.9a seed policy: a JSON file declaring the identity →
        /// capability entries this peer materializes at L0 and consults at
        /// §4.6 authenticate. Format is the keystone-owned cross-peer
        /// canonical schema (`shared/seed-policy/seed-policy.schema.json`) —
        /// `{"version":1,"entries":[{"grantee":"<self|default|hex|base58>",
        /// "grants":[…]}]}` — the same file go's `--seed-policy-file` and
        /// python's `--seed-policy` read.
        ///
        /// This is the operator posture *between* the two extremes: name an
        /// admin identity by its identity-hash hex and unknown peers stay
        /// gated by the initial-grant policy (EXTENSION-ROLE §4.7) while the
        /// named one can stage its own setup. Mutually exclusive with
        /// `--debug-grants`, which unions open grants onto every connection
        /// and would hide the gate the policy exists to declare.
        ///
        /// A `default` entry is read with two OPPOSITE meanings — a floor on
        /// the connection path, the attenuation CEILING on §6.2
        /// `capability:request`. Prefer a per-grantee hex/Base58 key.
        #[arg(long, conflicts_with = "debug_grants")]
        seed_policy: Option<String>,
        /// Enable history recording (format: pattern[:max_depth], e.g. "*" or "*:1000" or "project/*")
        #[arg(long)]
        history: Option<String>,
        /// Expose a filesystem directory via the local/files handler.
        /// Format: name:/fs/path:tree/prefix/ (matches Go peer's --files).
        #[arg(long)]
        files: Option<String>,
        /// Home `content_hash_format` this peer authors under and prefers
        /// in hello negotiation (V7 §4.5/§8.2): "sha256" (default, the
        /// conformance floor) or "sha384". The per-connection active format
        /// is negotiated and may differ (a sha384 peer authors sha256 on a
        /// connection to a sha256-only peer). Matches Go peer's
        /// `--hash-type` flag.
        #[arg(long, default_value = "sha256")]
        hash_type: String,
        /// Enable GUIDE-CONFORMANCE §7a test handlers (system/validate/echo +
        /// system/validate/dispatch-outbound) for validate-peer probing. OFF
        /// by default — these expose §6.13(a)/§6.13(b) for black-box wire
        /// attestation and MUST NOT be on in production (dispatch-outbound
        /// originates outbound EXECUTEs from caller params). A default peer
        /// 404s system/validate/* so the validator SKIPs honestly per §7a.4.
        #[arg(long)]
        validate: bool,
        /// Phase P: author + sign a `system/peer/published-root` over the
        /// served subtree so `MANIFEST_GET` serves a signed tree root, and
        /// **re-sign it on every trie-root change** (PROPOSAL-PEER-MANIFEST
        /// §4 P1). Requires `--serve-namespace` or `--serve-closure-root`;
        /// the latter publishes over the whole peer subtree. Under §6.5.6
        /// Amendment 10 the served closure tracks the current
        /// `published-root.root_hash`, so the republish is what keeps an
        /// entity written after startup inside the served set.
        #[arg(long)]
        publish_root: bool,
        /// EXTENSION-SIGNALING §4/§5: additionally serve the
        /// `system/signaling` rendezvous node — the punch carrier's
        /// `offer`/`collect`/`advertise` verbs — from this peer. Matches Go
        /// peer's `-signaling-node`.
        ///
        /// **Pair it with an admission posture.** The flag registers the
        /// handler; it does not grant anyone access to it. Without
        /// `--debug-grants` or an operator-installed
        /// `system/capability/policy` entry covering `system/signaling`, an
        /// unknown peer gets the §4.4 floor and every verb is 403. (Go's
        /// `-signaling-node` documents the same pairing against its
        /// `--open-access` default.)
        ///
        /// `entity-signaling-node` remains the way to run a node and nothing
        /// else; this flag is the same handler installed through the same
        /// public `PeerBuilder::handler` seam, on a peer that also does other
        /// work. `advertise` publishes the peer's `--listen` address, which is
        /// wrong behind NAT or a load balancer — use the standalone node
        /// binary's `--endpoint` for any real deployment.
        #[arg(long)]
        signaling_node: bool,
        /// EXTENSION-SIGNALING §4.5.1: publish a §9.3 STUN listener **this
        /// deployment runs** in the node's `advertise`. Repeatable; requires
        /// `--signaling-node`.
        ///
        /// RFC 7064 non-hierarchical form — `stun:host[:port]` / `stuns:…`, no
        /// `//` — validated at startup, because a browser hands the value to
        /// `RTCIceServer.urls` verbatim and a malformed one throws at
        /// `RTCPeerConnection` construction rather than degrading. Publish only
        /// a reflector you actually run; this field is never a directory of
        /// public STUN servers.
        #[arg(long = "reflection-endpoint", value_name = "STUN_URI")]
        reflection_endpoints: Vec<String>,
        /// PROPOSAL-PEER-ISSUED-REGISTRY-BACKEND: pin a remote registry as a
        /// `peer-issued` resolver-chain backend, as `<peer_id>@<url>`.
        ///
        /// Installs a §4 `ResolverChainEntry` with `backend_kind:
        /// "peer-issued"`, `backend_id` the registry's Base58 peer-id, and the
        /// endpoint in `hints.endpoint` — which is where the cohort puts it
        /// (Python's `RegistryReader` reads it from there). `system/registry:
        /// resolve` then fetches the registry's bindings over its http-poll
        /// surface on a cache miss and verifies each one against the PINNED
        /// key: a binding signed by anyone else is rejected and the chain
        /// advances, never downgraded to a pin.
        ///
        /// The peer-id is the trust root and is not negotiable from the wire —
        /// it is why this is a pin and not a lookup. Matches Go peer's
        /// `--peer-issued-registry` and Python's flag of the same name.
        ///
        /// Repeatable: pin several registries and they are tried in flag order.
        #[arg(long, value_name = "PEER_ID@URL")]
        peer_issued_registry: Vec<String>,
        /// Enable EXTENSION-CONTENT v3.5 §5.3 descriptor publication on
        /// `--files` roots (DOMAIN-LOCAL-FILES §2.5). With this set, a
        /// `read` of a file with a known media-type publishes a
        /// `system/content/descriptor` at the canonical
        /// `/{peer}/system/content/descriptor/{B_hex}/{D_hex}` path.
        /// Sets `RootConfigData.publish_descriptors` on the configured
        /// root. Matches Go peer's `--publish-descriptors`.
        #[arg(long)]
        publish_descriptors: bool,
        /// EXTENSION-NETWORK §2.3 keepalive `interval_ms` for the §5.4
        /// outbound ping loops (0 = spec default 30000). Short values
        /// (e.g. 1500) make the suspect→disconnected escalation observable
        /// in seconds — pair with `validate-peer -keepalive-envelope-ms`
        /// for the liveness harness. Matches Go peer's
        /// `-keepalive-interval-ms` and Python's `--keepalive-interval-ms`.
        #[arg(long, default_value_t = 0)]
        keepalive_interval_ms: u64,
        /// EXTENSION-NETWORK §2.3 keepalive `timeout_ms` per ping
        /// (0 = spec default 10000). Matches Go peer's
        /// `-keepalive-timeout-ms`.
        #[arg(long, default_value_t = 0)]
        keepalive_timeout_ms: u64,
        /// EXTENSION-NETWORK §2.3 consecutive misses before the
        /// disconnected/keepalive-miss demotion (0 = spec default 3).
        /// Matches Go peer's `-keepalive-max-missed`.
        #[arg(long, default_value_t = 0)]
        keepalive_max_missed: u32,
    },
    /// List all peers
    List,
    /// Show peer details
    Show {
        /// Peer name
        name: String,
    },
    /// Issue a curated peer-issued registry binding (operator tool, holds the
    /// registry key = this peer's identity). Signs a `name → target_peer_id`
    /// binding with the peer's key and publishes the body + signature + by-name
    /// pointer into the peer's tree, ready to be served as a coral-reef
    /// (PROPOSAL-PEER-ISSUED-REGISTRY-BACKEND §3.2). Resolvers that pin this
    /// peer's key resolve the name through the `peer-issued` backend.
    IssueBinding {
        /// Registry peer name (its identity is the signing key K_registry)
        name: String,
        /// The name to bind (e.g. billslab.com; NFC, no '/', no control chars)
        bind_name: String,
        /// Target peer-id the name resolves to (Base58, V7 §1.5)
        target_peer_id: String,
        /// Content-hash (hex) of a published `system/peer/transport/*` entity
        /// (repeatable). REGISTRY §3 `transports` is `[system/hash]`, not URLs.
        #[arg(long = "transport")]
        transports: Vec<String>,
        /// Time-to-live in milliseconds (omit for no expiry)
        #[arg(long)]
        ttl_ms: Option<u64>,
        /// Storage backend: "memory" or "sqlite" (overrides config.toml).
        /// Use "sqlite" so the binding persists for `peer start` to serve.
        #[arg(long)]
        storage: Option<String>,
        /// Home content_hash_format ("sha256" default or "sha384") — MUST match
        /// what `peer start` serves this registry under.
        #[arg(long, default_value = "sha256")]
        hash_type: String,
    },
}

fn init_tracing(verbose: bool, trace_entities: bool, profile: bool) {
    // Default filter. --profile enables span events on the instrumented crates
    // at debug, which is what surfaces time.busy / time.idle on each span close.
    let default_filter = if trace_entities {
        "trace".to_string()
    } else if profile {
        // Quiet at info, but the instrumented crates at debug so spans fire.
        "info,entity_peer=debug,entity_protocol=debug,entity_wire=debug,entity_store=debug"
            .to_string()
    } else if verbose {
        "debug".to_string()
    } else {
        "info".to_string()
    };

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| default_filter.into());

    let builder = tracing_subscriber::fmt().with_env_filter(env_filter);

    if profile {
        // FmtSpan::CLOSE prints "<span>: close time.busy=<x> time.idle=<y>"
        // when each instrumented span ends. CPU time vs await time, no extra
        // deps, viewable in any tail-able log.
        builder
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .init();
    } else {
        builder.init();
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Identity { action } => {
            init_tracing(false, false, false);
            match action {
                IdentityAction::Create { name, key_type } => {
                    commands::identity::create(&name, &key_type)?
                }
                IdentityAction::List => commands::identity::list()?,
                IdentityAction::Show { name } => commands::identity::show(&name)?,
            }
        }
        Commands::Peer {
            verbose,
            trace_entities,
            profile,
            action,
        } => {
            init_tracing(verbose, trace_entities, profile);
            match action {
                PeerAction::Init {
                    name,
                    admin,
                    admin_key,
                    key_type,
                } => {
                    commands::peer::init(&name, admin.as_deref(), admin_key.as_deref(), &key_type)?
                }
                PeerAction::Start {
                    name,
                    listen,
                    ws_listen,
                    http_listen,
                    http_path,
                    http_poll_addr,
                    http_poll_mount_on_live,
                    http_poll_prefix,
                    serve_namespace,
                    serve_closure_root,
                    storage,
                    debug_grants,
                    seed_policy,
                    history,
                    files,
                    hash_type,
                    validate,
                    publish_root,
                    signaling_node,
                    reflection_endpoints,
                    peer_issued_registry,
                    publish_descriptors,
                    keepalive_interval_ms,
                    keepalive_timeout_ms,
                    keepalive_max_missed,
                } => {
                    commands::peer::start(
                        &name,
                        listen.as_deref(),
                        ws_listen.as_deref(),
                        http_listen.as_deref(),
                        &http_path,
                        http_poll_addr.as_deref(),
                        http_poll_mount_on_live,
                        &http_poll_prefix,
                        serve_namespace.as_deref(),
                        serve_closure_root,
                        storage.as_deref(),
                        debug_grants,
                        seed_policy.as_deref(),
                        history.as_deref(),
                        files.as_deref(),
                        &hash_type,
                        validate,
                        publish_root,
                        signaling_node,
                        &reflection_endpoints,
                        &peer_issued_registry,
                        publish_descriptors,
                        commands::peer::KeepaliveOverrides {
                            interval_ms: keepalive_interval_ms,
                            timeout_ms: keepalive_timeout_ms,
                            max_missed: keepalive_max_missed,
                        },
                    )
                    .await?
                }
                PeerAction::List => commands::peer::list_peers()?,
                PeerAction::Show { name } => commands::peer::show(&name)?,
                PeerAction::IssueBinding {
                    name,
                    bind_name,
                    target_peer_id,
                    transports,
                    ttl_ms,
                    storage,
                    hash_type,
                } => commands::peer::issue_binding(
                    &name,
                    &bind_name,
                    &target_peer_id,
                    &transports,
                    ttl_ms,
                    storage.as_deref(),
                    &hash_type,
                )?,
            }
        }
    }

    Ok(())
}
