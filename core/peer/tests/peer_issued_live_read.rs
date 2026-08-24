//! PROPOSAL-PEER-ISSUED-REGISTRY-BACKEND §2.1/§2.2 over a real wire.
//!
//! The extension's own tests drive `resolve_one` against a pre-seeded local
//! store — the offline half — and prove the trust logic. What they cannot see
//! is whether the peer ever *goes to the registry*, because a pre-seeded store
//! and a live-fetched one are indistinguishable once the fetch is done. That is
//! precisely the distinction the cohort's six wire vectors exist to draw: over
//! the wire four of them collapse to the same observable status, so the
//! evidence is the FETCH PATTERN, not the verdict.
//!
//! So the origin here records every request path, exactly like Go's fixture,
//! and each test asserts what the peer did or did not fetch. A test that only
//! asserted the resolve result would pass against a peer that never dialed.
#![cfg(all(
    feature = "http-live",
    feature = "registry",
    not(target_arch = "wasm32")
))]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use entity_crypto::Keypair;
use entity_entity::Entity;
use entity_hash::Hash;
use entity_registry::data::BindingData;
use entity_registry::{
    by_name_pointer_path, resolver_config_path, revocation_by_target_path, signature_pointer_path,
    ResolverChainEntry, ResolverConfigData, BACKEND_KIND_PEER_ISSUED,
};

use entity_peer::poll_read::HttpPollRegistryReader;

// ---------------------------------------------------------------------------
// A recording http-poll origin: the registry's served surface
// ---------------------------------------------------------------------------

/// Serves the Amendment 5 poll routes off two maps, and logs every path asked
/// for. Hand-rolled rather than an `HttpLiveListener` on purpose: the point of
/// these tests is what the CONSUMER fetched, so the origin must be a plain
/// witness, not another copy of our own serving logic that could agree with the
/// client for the wrong reason.
struct RecordingRegistry {
    paths: Mutex<HashMap<String, Hash>>,
    content: Mutex<HashMap<Hash, Vec<u8>>>,
    log: Mutex<Vec<String>>,
}

impl RecordingRegistry {
    fn new() -> Self {
        Self {
            paths: Mutex::new(HashMap::new()),
            content: Mutex::new(HashMap::new()),
            log: Mutex::new(Vec::new()),
        }
    }

    fn put_entity(&self, entity: Entity) -> Hash {
        let h = entity.content_hash;
        self.content
            .lock()
            .unwrap()
            .insert(h, entity_wire::encode_entity(&entity));
        h
    }

    fn bind(&self, path: &str, hash: Hash) {
        self.paths.lock().unwrap().insert(path.to_string(), hash);
    }

    fn requests(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    fn saw(&self, want: &str) -> bool {
        self.requests().iter().any(|p| p == want)
    }

    /// Answer one request. `uri` is the raw path.
    fn answer(&self, uri: &str) -> Option<Vec<u8>> {
        self.log.lock().unwrap().push(uri.to_string());

        if let Some(hex) = uri.strip_prefix("/content/") {
            let bytes = hex_to_bytes(hex)?;
            let h = Hash::from_bytes(&bytes).ok()?;
            return self.content.lock().unwrap().get(&h).cloned();
        }
        // A `.bin` leaf: reply with the 2-key bare pointer the publisher serves.
        let path = uri.strip_suffix(".bin")?;
        let h = *self.paths.lock().unwrap().get(path)?;
        Some(entity_ecf::ecf_for_hash_value(
            "system/hash",
            &entity_ecf::Value::Bytes(h.to_bytes().to_vec()),
        ))
    }
}

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Serve `registry` on a fresh port until the returned handle is dropped.
async fn serve(registry: Arc<RecordingRegistry>) -> (String, tokio::task::JoinHandle<()>) {
    use http_body_util::Full;
    use hyper::body::Bytes;
    use hyper::{Request, Response, StatusCode};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind origin");
    let addr = listener.local_addr().expect("addr");
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let registry = registry.clone();
            tokio::spawn(async move {
                let service =
                    hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                        let registry = registry.clone();
                        async move {
                            let uri = req.uri().path().to_string();
                            Ok::<_, std::convert::Infallible>(match registry.answer(&uri) {
                                Some(body) => Response::builder()
                                    .status(StatusCode::OK)
                                    .body(Full::new(Bytes::from(body)))
                                    .unwrap(),
                                None => Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap(),
                            })
                        }
                    });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (format!("http://{}", addr), handle)
}

// ---------------------------------------------------------------------------
// Building the registry's served content
// ---------------------------------------------------------------------------

/// Publish a peer-issued binding onto the registry's SERVED surface: body,
/// by-name pointer, and the §5.2 invariant-pointer signature by `signer`.
/// Mirrors the extension tests' `publish_binding`, but into the origin rather
/// than into a local store — that difference is the whole subject here.
/// A comfortably-live TTL. D3 makes a non-null `ttl` mandatory for
/// `kind: "peer-issued"`, so fixtures testing something else (the pin,
/// revocation, the precede path) must carry a real one — otherwise they would
/// pass for the wrong reason, refused by D3 rather than by the thing under test.
const LIVE_TTL_MS: u64 = 86_400_000;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn publish_binding(
    reg: &RecordingRegistry,
    registry_id: &str,
    signer: &Keypair,
    name: &str,
    target: &str,
    ttl: Option<u64>,
) -> Hash {
    publish_binding_at(reg, registry_id, signer, name, target, now_ms(), ttl)
}

#[allow(clippy::too_many_arguments)]
fn publish_binding_at(
    reg: &RecordingRegistry,
    registry_id: &str,
    signer: &Keypair,
    name: &str,
    target: &str,
    issued_at: u64,
    ttl: Option<u64>,
) -> Hash {
    let binding = BindingData {
        name: name.into(),
        kind: "peer-issued".into(),
        target_peer_id: target.into(),
        transports: vec![entity_ecf::Value::Text("tcp://billslab.com:9000".into())],
        issued_at,
        ttl,
        supersedes: None,
        issuer_attestation: None,
        metadata: None,
    };
    let binding_hash = reg.put_entity(binding.to_entity().expect("binding entity"));
    reg.bind(&by_name_pointer_path(registry_id, name), binding_hash);
    sign_onto(reg, registry_id, signer, &binding_hash);
    binding_hash
}

/// Bind a signature over `target` at the registry's invariant pointer, and
/// serve the signer's identity entity — the resolver derives the signer's
/// public key from it to apply the pin, so a signature without it verifies
/// nothing.
fn sign_onto(reg: &RecordingRegistry, registry_id: &str, signer: &Keypair, target: &Hash) {
    reg.put_entity(signer.peer_entity().expect("peer entity"));
    let sig = entity_types::SignatureData {
        target: *target,
        signer: signer.peer_identity_hash(),
        algorithm: "ed25519".into(),
        signature: signer.sign(&target.to_bytes()).to_vec(),
    };
    let sig_hash = reg.put_entity(sig.to_entity().expect("signature entity"));
    reg.bind(&signature_pointer_path(registry_id, target), sig_hash);
}

/// A consumer peer pinning `registry_id` at `endpoint`, plus the pieces needed
/// to drive one `system/registry:resolve` against it.
struct Consumer {
    peer: entity_peer::Peer,
}

impl Consumer {
    fn pinning(seed: u8, registry_id: &str, endpoint: &str) -> Self {
        let peer = entity_peer::PeerBuilder::new()
            .keypair(Keypair::from_seed([seed; 32]))
            .build()
            .expect("consumer builds");
        let config = ResolverConfigData {
            resolver_chain: vec![ResolverChainEntry {
                backend_kind: BACKEND_KIND_PEER_ISSUED.to_string(),
                backend_id: registry_id.to_string(),
                priority: 0,
                accepted_trust_anchors: Vec::new(),
                hints: Some(entity_ecf::Value::Map(vec![(
                    entity_ecf::text("endpoint"),
                    entity_ecf::text(endpoint),
                )])),
            }],
            ..Default::default()
        };
        let hash = peer
            .content_store()
            .put(config.to_entity().expect("config entity"))
            .expect("put config");
        peer.location_index()
            .set(&resolver_config_path(&peer.peer_id().to_string()), hash);
        Self { peer }
    }

    /// Run `system/registry:resolve` and return the result's `status` and
    /// `peer_id` fields.
    async fn resolve(&self, name: &str) -> (String, Option<String>) {
        let cs = self.peer.content_store().clone();
        let li = self.peer.location_index().clone();
        let pid = self.peer.peer_id().to_string();
        let log = Arc::new(entity_registry::log::ResolutionLog::new(
            cs.clone(),
            li.clone(),
            pid.clone(),
            1024,
        ));
        let handler = entity_registry::RegistryHandler::new(cs, li, pid, log)
            .with_reader(Arc::new(HttpPollRegistryReader::new()));

        let params = Entity::new(
            entity_types::TYPE_PROTOCOL_STATUS,
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                entity_ecf::text("name"),
                entity_ecf::text(name),
            )])),
        )
        .expect("params");
        let execute = Entity::new(
            entity_types::TYPE_EXECUTE,
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![])),
        )
        .expect("execute");
        let ctx = entity_handler::HandlerContext::builder(execute, params)
            .operation("resolve".to_string())
            .build();
        let result = entity_handler::Handler::handle(&handler, &ctx)
            .await
            .expect("resolve dispatches");

        let value: ciborium::Value =
            ciborium::de::from_reader(result.result.data.as_slice()).expect("result decodes");
        let map = value.as_map().expect("result is a map").clone();
        let field = |k: &str| -> Option<String> {
            map.iter()
                .find(|(key, _)| key.as_text() == Some(k))
                .and_then(|(_, v)| v.as_text().map(|s| s.to_string()))
        };
        (field("status").unwrap_or_default(), field("peer_id"))
    }
}

// ---------------------------------------------------------------------------
// The vectors
// ---------------------------------------------------------------------------

/// RESOLVE-1 — cold cache: the peer fetches the by-name pointer from the pinned
/// registry, verifies against the pinned key, and surfaces the binding.
///
/// The fetch assertion is the load-bearing half. Without it a peer that
/// resolved from a warm store — or from nothing at all — reads identically.
#[tokio::test]
async fn cold_resolve_goes_to_the_pinned_registry_and_verifies() {
    let reg = Arc::new(RecordingRegistry::new());
    let registry_kp = Keypair::generate();
    let rid = registry_kp.peer_id().as_str().to_string();
    let target = Keypair::generate().peer_id().as_str().to_string();
    publish_binding(
        &reg,
        &rid,
        &registry_kp,
        "billslab.com",
        &target,
        Some(LIVE_TTL_MS),
    );

    let (endpoint, handle) = serve(reg.clone()).await;
    let consumer = Consumer::pinning(60, &rid, &endpoint);

    let (status, peer_id) = consumer.resolve("billslab.com").await;

    assert!(
        reg.saw(&format!(
            "{}.bin",
            by_name_pointer_path(&rid, "billslab.com")
        )),
        "the peer resolved WITHOUT fetching the by-name pointer from the \
         pinned registry — origin saw {:?}. A result without a fetch is a \
         stale cache or a coincidence, not a peer-issued resolve",
        reg.requests()
    );
    assert_eq!(status, "resolved", "origin saw {:?}", reg.requests());
    assert_eq!(peer_id.as_deref(), Some(target.as_str()));

    handle.abort();
}

/// VERIFY-FAIL-1 (§2.1 step 3 MUST) — a binding signed by a key that is not the
/// pinned registry's is rejected and the chain advances. Never accepted, and
/// never downgraded to a pin.
///
/// The peer must still have gone to the wire: "rejected it correctly" and
/// "never looked" are the same status here, which is the whole reason the
/// fetch log exists.
#[tokio::test]
async fn a_binding_signed_by_a_non_pinned_key_is_rejected_after_a_real_fetch() {
    let reg = Arc::new(RecordingRegistry::new());
    let registry_kp = Keypair::generate();
    let attacker = Keypair::generate();
    let rid = registry_kp.peer_id().as_str().to_string();
    let target = Keypair::generate().peer_id().as_str().to_string();
    // Served by the pinned registry's namespace, but signed by someone else.
    publish_binding(
        &reg,
        &rid,
        &attacker,
        "billslab.com",
        &target,
        Some(LIVE_TTL_MS),
    );

    let (endpoint, handle) = serve(reg.clone()).await;
    let consumer = Consumer::pinning(61, &rid, &endpoint);

    let (status, _) = consumer.resolve("billslab.com").await;

    assert!(
        reg.saw(&format!(
            "{}.bin",
            by_name_pointer_path(&rid, "billslab.com")
        )),
        "origin saw {:?} — the backend was never consulted, so the rejection \
         proves nothing",
        reg.requests()
    );
    assert_eq!(
        status, "chain_exhausted",
        "a binding signed by a non-pinned key MUST NOT resolve"
    );

    handle.abort();
}

/// REVOKED-1 (§2.1 step 4 MUST) — a verifying revocation at the §6a.6 by-target
/// index excludes the binding.
///
/// Asserts the index is *probed by direct lookup*, not found by listing the
/// revocation subtree: the index exists so a resolver need not walk every
/// revocation a registry ever issued. This is also the exact check Go found
/// Python skipping — the binding is valid in every other respect, so an
/// impl that never probes serves a revoked name.
#[tokio::test]
async fn a_revoked_binding_is_excluded_via_the_by_target_index() {
    let reg = Arc::new(RecordingRegistry::new());
    let registry_kp = Keypair::generate();
    let rid = registry_kp.peer_id().as_str().to_string();
    let target = Keypair::generate().peer_id().as_str().to_string();
    let binding_hash = publish_binding(
        &reg,
        &rid,
        &registry_kp,
        "billslab.com",
        &target,
        Some(LIVE_TTL_MS),
    );

    // A registry-signed revocation, reachable only through the by-target index.
    let revocation = entity_registry::data::RevocationData {
        revokes: binding_hash,
        reason: Some("key rotation".into()),
        revoked_at: 2_000,
    };
    let rev_hash = reg.put_entity(revocation.to_entity().expect("revocation entity"));
    reg.bind(&revocation_by_target_path(&rid, &binding_hash), rev_hash);
    sign_onto(&reg, &rid, &registry_kp, &rev_hash);

    let (endpoint, handle) = serve(reg.clone()).await;
    let consumer = Consumer::pinning(62, &rid, &endpoint);

    let (status, _) = consumer.resolve("billslab.com").await;

    assert!(
        reg.saw(&format!(
            "{}.bin",
            revocation_by_target_path(&rid, &binding_hash)
        )),
        "the peer never probed the by-target revocation index — origin saw \
         {:?}. The binding verifies and is unexpired, so skipping this lookup \
         serves a REVOKED name",
        reg.requests()
    );
    assert_eq!(
        status, "chain_exhausted",
        "a binding with a verifying revocation MUST NOT resolve"
    );

    handle.abort();
}

/// EXPIRED-1 (§2.1 step 5 MUST) — `issued_at + ttl <= now` excludes the binding.
#[tokio::test]
async fn an_expired_binding_is_excluded() {
    let reg = Arc::new(RecordingRegistry::new());
    let registry_kp = Keypair::generate();
    let rid = registry_kp.peer_id().as_str().to_string();
    let target = Keypair::generate().peer_id().as_str().to_string();
    // issued_at 1000 + ttl 1 is long past.
    publish_binding_at(
        &reg,
        &rid,
        &registry_kp,
        "billslab.com",
        &target,
        1_000,
        Some(1),
    );

    let (endpoint, handle) = serve(reg.clone()).await;
    let consumer = Consumer::pinning(63, &rid, &endpoint);

    let (status, _) = consumer.resolve("billslab.com").await;
    assert_eq!(status, "chain_exhausted");
    assert!(reg.saw(&format!(
        "{}.bin",
        by_name_pointer_path(&rid, "billslab.com")
    )));

    handle.abort();
}

/// PRECEDE-1 (§2.2) — a locally-cached binding resolves identically to
/// live-fetch, **without touching the wire**.
///
/// The negative is the assertion. A warm cache that re-fetched anyway would
/// still produce `resolved`, and would still be wrong: §2.2 is what makes an
/// offline / shipped-coral-reef deployment work at all.
#[tokio::test]
async fn a_preceded_binding_resolves_without_touching_the_wire() {
    let reg = Arc::new(RecordingRegistry::new());
    let registry_kp = Keypair::generate();
    let rid = registry_kp.peer_id().as_str().to_string();
    let target = Keypair::generate().peer_id().as_str().to_string();
    publish_binding(
        &reg,
        &rid,
        &registry_kp,
        "billslab.com",
        &target,
        Some(LIVE_TTL_MS),
    );

    let (endpoint, handle) = serve(reg.clone()).await;
    let consumer = Consumer::pinning(64, &rid, &endpoint);

    // First resolve: cold, goes to the wire, and warms the local store.
    let (first, _) = consumer.resolve("billslab.com").await;
    assert_eq!(first, "resolved");
    let after_cold = reg.requests().len();
    assert!(after_cold > 0, "the cold resolve should have fetched");

    // Second resolve: the store is now the precede path.
    let (second, second_peer) = consumer.resolve("billslab.com").await;
    assert_eq!(
        second, "resolved",
        "a preceded binding MUST resolve identically to live-fetch"
    );
    assert_eq!(second_peer.as_deref(), Some(target.as_str()));
    assert_eq!(
        reg.requests().len(),
        after_cold,
        "the second resolve touched the wire — §2.2 says a cached binding \
         resolves WITHOUT it. Requests: {:?}",
        reg.requests()
    );

    handle.abort();
}

/// OFFLINE-NOTFOUND-1 (§2.1 step 1) — a name absent from the registry's by-name
/// index yields the backend's negative result, **and the backend is consulted**.
///
/// The probe is the point: a peer that answered "not found" from a local shrug
/// produces the same status without ever having asked.
#[tokio::test]
async fn an_absent_name_is_probed_on_the_wire_before_reporting_not_found() {
    let reg = Arc::new(RecordingRegistry::new());
    let registry_kp = Keypair::generate();
    let rid = registry_kp.peer_id().as_str().to_string();
    // Deliberately publish nothing: the name MUST 404 for this to mean anything.

    let (endpoint, handle) = serve(reg.clone()).await;
    let consumer = Consumer::pinning(65, &rid, &endpoint);

    let (status, _) = consumer.resolve("absent.example").await;

    assert!(
        reg.saw(&format!(
            "{}.bin",
            by_name_pointer_path(&rid, "absent.example")
        )),
        "the peer reported a negative without probing the registry — origin \
         saw {:?}",
        reg.requests()
    );
    assert_ne!(
        status, "resolved",
        "an absent name MUST NOT resolve; got {status}"
    );

    handle.abort();
}

/// The seam must not fire for a chain entry that carries no endpoint hint.
///
/// A bare `(kind, backend_id)` entry is the shape Go's harness shipped, and it
/// arms only an impl that gets the endpoint from somewhere else. Ours reads the
/// hint and nowhere else, so the correct behaviour is a silent no-op on the
/// wire — not a dial to a guessed host.
#[tokio::test]
async fn a_chain_entry_without_an_endpoint_hint_does_not_dial() {
    let reg = Arc::new(RecordingRegistry::new());
    let registry_kp = Keypair::generate();
    let rid = registry_kp.peer_id().as_str().to_string();
    let target = Keypair::generate().peer_id().as_str().to_string();
    publish_binding(
        &reg,
        &rid,
        &registry_kp,
        "billslab.com",
        &target,
        Some(LIVE_TTL_MS),
    );

    let (_endpoint, handle) = serve(reg.clone()).await;

    // Same pin, hints omitted.
    let peer = entity_peer::PeerBuilder::new()
        .keypair(Keypair::from_seed([66u8; 32]))
        .build()
        .expect("peer builds");
    let config = ResolverConfigData {
        resolver_chain: vec![ResolverChainEntry {
            backend_kind: BACKEND_KIND_PEER_ISSUED.to_string(),
            backend_id: rid.clone(),
            priority: 0,
            accepted_trust_anchors: Vec::new(),
            hints: None,
        }],
        ..Default::default()
    };
    let hash = peer
        .content_store()
        .put(config.to_entity().expect("config entity"))
        .expect("put config");
    peer.location_index()
        .set(&resolver_config_path(&peer.peer_id().to_string()), hash);
    let consumer = Consumer { peer };

    let (status, _) = consumer.resolve("billslab.com").await;

    assert!(
        reg.requests().is_empty(),
        "an entry with no endpoint hint dialed anyway: {:?}",
        reg.requests()
    );
    assert_eq!(
        status, "chain_exhausted",
        "with nothing cached and nowhere to fetch from, the chain is exhausted"
    );

    handle.abort();
}
