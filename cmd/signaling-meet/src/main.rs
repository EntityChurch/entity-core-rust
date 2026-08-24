//! `signaling-meet` — **Rust's seat in the cross-impl meet.**
//!
//! One role, one exchange, one JSON line on stdout, exit 0 iff met. It speaks
//! the identical CLI/JSON/exit contract as `entity-core-go`'s
//! `cmd/signaling-meet` and `entity-core-py`'s `signaling_meet.py`, so any two
//! of the three can be swapped for each other in a meet and the harness does
//! not change.
//!
//! # Why this exists
//!
//! Every other signaling test in this repo is **Rust↔Rust**. That is the trap
//! `AGENTS.md` names: a wrong-but-self-consistent §2.2 derivation passes a
//! same-impl suite exactly as a correct one does, because encoder and decoder
//! agree with themselves. Go and Python have met each other live through a Rust
//! node — but Rust has only ever been the *node*, never a participant, so
//! **Rust's client half was the last piece of this feature with no cross-impl
//! evidence at all.** This closes that.
//!
//! ```text
//!   signaling-meet --node 127.0.0.1:4050 --role responder --mode tag --input chess &
//!   signaling-meet --node 127.0.0.1:4050 --role initiator --mode tag --input chess
//! ```
//!
//! Point either half at a Go or Python binary instead and the meet is
//! cross-impl. The node must be running with `--open` (or `--grant` for this
//! peer): each run connects as a **fresh ephemeral peer**, which is exactly what
//! a stranger is.
//!
//! # The asymmetry in the exit codes is deliberate
//!
//! The **initiator** exits 0 only when it was actually answered — its nonce came
//! back in a `connect-response` from someone else. That is a real meet and it is
//! the strong signal.
//!
//! The **responder** serves for the whole `--timeout` and exits 0 if it answered
//! at least one request. Weaker on purpose: it cannot know whether the peer it
//! answered was the one the harness cared about. Two consequences that are easy
//! to get wrong, and both are MUSTs of §3.2 rather than style:
//!
//! - It must **not exit at its first answer.** `pair` and `lobby` keys are
//!   stable by construction, so their buckets still hold earlier exchanges until
//!   the 60 s TTL. A responder that answers one stale request and leaves has
//!   abandoned the peer actually waiting on it — while reporting success.
//! - It must **skip nonces it already answered**, or it re-answers the same
//!   request every poll and fills the bucket against the 32-message bound.
//!
//! **The proof of a meet is therefore the pair, not either line alone:** the
//! initiator exited 0 *and* its nonce appears in the responder's `answered`.
//! `key` is in the output for the same reason — two impls that fail to meet
//! compare that field first, and a mismatch localizes the fault to §2.2 before
//! anyone reads a packet capture.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use clap::Parser;
use entity_core::crypto::{IdentityKeypair, Keypair};
use entity_core::peer::transport::Connector;
use entity_core::peer::{remote, transport};
use entity_entity::Entity;
use entity_signaling::coordination::{
    self, Candidate, CollectedMessage, ConnectRequest, ConnectResponse, Nonce, CANDIDATE_HOST,
    CANDIDATE_SRFLX, SUBSTRATE_TCP,
};
use entity_signaling::data::CollectResult;
use entity_signaling::{key, CollectRequest, OfferRequest, RendezvousKey};

/// Matches Go's and Python's 0.2 s. The node is a plain store with no
/// notification, so both roles poll — which is what §4 step 2 assumes.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Parser)]
#[command(
    name = "signaling-meet",
    about = "Rust's participant in the cross-impl signaling meet"
)]
struct Args {
    /// `host:port` of the connection node.
    #[arg(long)]
    node: String,
    /// `initiator` | `responder`.
    #[arg(long)]
    role: String,
    /// `tag` | `secret` | `lobby` | `pair`.
    #[arg(long)]
    mode: String,
    /// The mode's input. `pair` takes `peer-a,peer-b`; the literal `SELF` is
    /// substituted with this peer's id once the handshake reveals it.
    #[arg(long)]
    input: String,
    /// Seconds to run.
    #[arg(long, default_value_t = 15.0)]
    timeout: f64,
}

// ---------------------------------------------------------------------------
// Candidate payloads — byte-for-byte with Go's and Python's so a diff of the
// three impls' output lines up. Opaque to the node and to the entity layer.
// ---------------------------------------------------------------------------

fn initiator_candidates() -> Vec<Candidate> {
    vec![
        Candidate::new(CANDIDATE_HOST, SUBSTRATE_TCP, "192.168.1.10:9000"),
        Candidate::new(CANDIDATE_SRFLX, SUBSTRATE_TCP, "203.0.113.7:41234"),
    ]
}

fn responder_candidates() -> Vec<Candidate> {
    vec![Candidate::new(
        CANDIDATE_HOST,
        SUBSTRATE_TCP,
        "192.168.1.11:9000",
    )]
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ---------------------------------------------------------------------------
// The two verbs over a live connection
// ---------------------------------------------------------------------------

struct Meet<'a> {
    conn: &'a remote::RemoteConnection,
    keypair: &'a IdentityKeypair,
    uri: String,
}

impl Meet<'_> {
    async fn offer_message(&self, k: RendezvousKey, entity: &Entity) -> anyhow::Result<u32> {
        let params = OfferRequest {
            rendezvous_key: k,
            message: coordination::to_blob(entity),
        }
        .to_entity()?;
        Ok(self.execute("offer", &params).await?.0)
    }

    async fn collect_messages(&self, k: &RendezvousKey) -> anyhow::Result<Vec<CollectedMessage>> {
        let params = CollectRequest { rendezvous_key: *k }.to_entity()?;
        let (status, result) = self.execute("collect", &params).await?;
        if status != 200 {
            anyhow::bail!("collect: status {}", status);
        }
        Ok(CollectResult::from_params(&result.data)?
            .messages
            .iter()
            .map(|blob| coordination::classify_blob(blob))
            .collect())
    }

    /// No resource target — signaling addresses no tree resource, and the
    /// node's seeded grant has an empty resource scope, so attaching one is a
    /// 403 that reads exactly like "not granted". (Go's report named this the
    /// resource-target trap; `admission.rs` pins it.)
    async fn execute(&self, operation: &str, params: &Entity) -> anyhow::Result<(u32, Entity)> {
        let resp = remote::send_execute(
            self.conn,
            self.keypair,
            &self.uri,
            operation,
            params,
            None,
            None,
            None,
            &HashMap::new(),
            None,
        )
        .await
        .map_err(|e| anyhow::anyhow!("{} dispatch: {}", operation, e))?;
        Ok((resp.status, resp.result))
    }
}

/// Offer a `connect-request` and wait for the response echoing our nonce,
/// returning the moment it lands.
async fn run_initiator(
    meet: &Meet<'_>,
    k: RendezvousKey,
    peer_id: &str,
    deadline: Instant,
) -> Vec<(String, Json)> {
    let nonce = Nonce::generate();
    let nonce_hex = hex(nonce.as_bytes());

    let request = ConnectRequest {
        initiator: peer_id.to_string(),
        candidates: initiator_candidates(),
        nonce: nonce.clone(),
    };
    let entity = match request.to_entity() {
        Ok(e) => e,
        Err(e) => return fail_with(&nonce_hex, format!("build connect-request: {}", e)),
    };
    match meet.offer_message(k, &entity).await {
        Ok(200) => {}
        Ok(status) => {
            return fail_with(
                &nonce_hex,
                format!("offer connect-request: status {}", status),
            )
        }
        Err(e) => return fail_with(&nonce_hex, format!("offer connect-request: {}", e)),
    }

    while Instant::now() < deadline {
        if let Ok(messages) = meet.collect_messages(&k).await {
            if let Some(resp) = coordination::find_response(&messages, &nonce, peer_id) {
                return vec![
                    ("ok".into(), Json::Bool(true)),
                    ("nonce".into(), Json::Str(nonce_hex)),
                    ("responder".into(), Json::Str(resp.responder)),
                    (
                        "candidates".into(),
                        Json::Arr(resp.candidates.iter().map(|c| c.address.clone()).collect()),
                    ),
                ];
            }
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    fail_with(
        &nonce_hex,
        "no response echoing our nonce before the deadline".to_string(),
    )
}

fn fail_with(nonce_hex: &str, error: String) -> Vec<(String, Json)> {
    vec![
        ("ok".into(), Json::Bool(false)),
        ("nonce".into(), Json::Str(nonce_hex.to_string())),
        ("error".into(), Json::Str(error)),
    ]
}

/// Answer every non-own request in the bucket, for the **whole** deadline,
/// skipping nonces already answered. See the module doc for why both halves of
/// that sentence are load-bearing.
async fn run_responder(
    meet: &Meet<'_>,
    k: RendezvousKey,
    peer_id: &str,
    deadline: Instant,
) -> Vec<(String, Json)> {
    let mut answered: Vec<String> = Vec::new();
    let mut initiators: Vec<String> = Vec::new();
    let mut candidates: Vec<String> = Vec::new();
    let mut seen: HashSet<Vec<u8>> = HashSet::new();

    while Instant::now() < deadline {
        if let Ok(messages) = meet.collect_messages(&k).await {
            for m in &messages {
                let CollectedMessage::Request(req) = m else {
                    continue;
                };
                // §3.2: skip your own messages — `collect` is non-destructive,
                // so we always re-read what we wrote, and a peer that answered
                // itself would "succeed" at meeting nobody.
                if req.initiator == peer_id || !seen.insert(req.nonce.as_bytes().to_vec()) {
                    continue;
                }
                let response = ConnectResponse {
                    responder: peer_id.to_string(),
                    candidates: responder_candidates(),
                    nonce: req.nonce.clone(),
                };
                let entity = match response.to_entity() {
                    Ok(e) => e,
                    Err(e) => {
                        return responder_error(
                            answered,
                            initiators,
                            format!("build connect-response: {}", e),
                        )
                    }
                };
                match meet.offer_message(k, &entity).await {
                    Ok(200) => {}
                    Ok(status) => {
                        return responder_error(
                            answered,
                            initiators,
                            format!("offer connect-response: status {}", status),
                        )
                    }
                    Err(e) => {
                        return responder_error(
                            answered,
                            initiators,
                            format!("offer connect-response: {}", e),
                        )
                    }
                }
                answered.push(hex(req.nonce.as_bytes()));
                initiators.push(req.initiator.clone());
                candidates.extend(req.candidates.iter().map(|c| c.address.clone()));
            }
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    if answered.is_empty() {
        return vec![
            ("ok".into(), Json::Bool(false)),
            ("answered".into(), Json::Arr(vec![])),
            ("initiators".into(), Json::Arr(vec![])),
            (
                "error".into(),
                Json::Str("no request to answer before the deadline".into()),
            ),
        ];
    }
    vec![
        ("ok".into(), Json::Bool(true)),
        ("answered".into(), Json::Arr(answered)),
        ("initiators".into(), Json::Arr(initiators)),
        ("candidates".into(), Json::Arr(candidates)),
    ]
}

fn responder_error(
    answered: Vec<String>,
    initiators: Vec<String>,
    error: String,
) -> Vec<(String, Json)> {
    vec![
        ("ok".into(), Json::Bool(false)),
        ("answered".into(), Json::Arr(answered)),
        ("initiators".into(), Json::Arr(initiators)),
        ("error".into(), Json::Str(error)),
    ]
}

// ---------------------------------------------------------------------------
// Minimal JSON emitter
// ---------------------------------------------------------------------------
//
// Hand-rolled rather than pulling `serde_json` in for one flat object of eight
// fields: the ecosystem's dependency posture is deliberately conservative, and
// the wire here is CBOR — this JSON exists only so a shell harness can read the
// result. The escaper is the only part with any risk (`--input` and error text
// are arbitrary), so it is unit-tested below rather than eyeballed.

enum Json {
    Bool(bool),
    Str(String),
    Arr(Vec<String>),
}

/// Escape per RFC 8259 §7: the two mandatory escapes, the five short forms, and
/// `\u00XX` for everything else below 0x20. Non-ASCII passes through as UTF-8,
/// which is valid JSON.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
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

fn render(fields: &[(String, Json)]) -> String {
    let body: Vec<String> = fields
        .iter()
        .map(|(k, v)| {
            let rendered = match v {
                Json::Bool(b) => b.to_string(),
                Json::Str(s) => format!("\"{}\"", escape(s)),
                Json::Arr(items) => {
                    let inner: Vec<String> =
                        items.iter().map(|i| format!("\"{}\"", escape(i))).collect();
                    format!("[{}]", inner.join(","))
                }
            };
            format!("\"{}\":{}", escape(k), rendered)
        })
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

    if args.role != "initiator" && args.role != "responder" {
        fail(&args.role, "--role must be initiator|responder".into());
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

async fn run(args: &Args) -> anyhow::Result<Vec<(String, Json)>> {
    // A fresh ephemeral identity per run — which is precisely what a stranger
    // is, and what the node's `--open` posture must admit.
    let keypair = IdentityKeypair::Ed25519(Keypair::generate());
    let stream = transport::TcpConnector
        .connect(&format!("tcp://{}", args.node))
        .await
        .map_err(|e| anyhow::anyhow!("dial {}: {}", args.node, e))?;
    let conn = remote::perform_connect(stream, &keypair, entity_hash::HASH_ALGORITHM_SHA256)
        .await
        .map_err(|e| anyhow::anyhow!("handshake with {}: {}", args.node, e))?;

    let peer_id = keypair.peer_id().to_string();
    let node_peer_id = conn.remote_peer_id.clone();

    // `pair` needs both peer-ids and ours is only known once connected, so a
    // driver passes "…,SELF" and we substitute here — exactly as Go and Python
    // do, so the same harness line works against any of the three.
    let value = args.input.replace("SELF", &peer_id);
    let k = derive_key(&args.mode, &value)?;

    let meet = Meet {
        conn: &conn,
        keypair: &keypair,
        uri: format!("/{}/system/signaling", node_peer_id),
    };
    let deadline = Instant::now() + Duration::from_secs_f64(args.timeout);

    let outcome = if args.role == "initiator" {
        run_initiator(&meet, k, &peer_id, deadline).await
    } else {
        run_responder(&meet, k, &peer_id, deadline).await
    };

    let mut fields: Vec<(String, Json)> = vec![
        ("role".into(), Json::Str(args.role.clone())),
        ("peer_id".into(), Json::Str(peer_id)),
        ("node_peer_id".into(), Json::Str(node_peer_id)),
        ("mode".into(), Json::Str(args.mode.clone())),
        ("input".into(), Json::Str(value)),
        ("key".into(), Json::Str(hex(k.as_bytes()))),
    ];
    fields.extend(outcome);
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_the_json_string_set() {
        assert_eq!(escape(r#"a"b"#), r#"a\"b"#);
        assert_eq!(escape(r"a\b"), r"a\\b");
        assert_eq!(escape("a\nb"), "a\\nb");
        assert_eq!(escape("a\tb"), "a\\tb");
        assert_eq!(escape("a\u{0}b"), "a\\u0000b");
        // Non-ASCII is valid JSON as UTF-8 and must not be mangled — the §2.2
        // inputs are byte-exact, so an escaper that "normalized" here would
        // misreport the very thing the `key` field exists to diagnose.
        assert_eq!(escape("café"), "café");
    }

    #[test]
    fn renders_a_flat_object() {
        let fields = vec![
            ("ok".to_string(), Json::Bool(true)),
            ("role".to_string(), Json::Str("initiator".into())),
            (
                "answered".to_string(),
                Json::Arr(vec!["ab".into(), "cd".into()]),
            ),
        ];
        assert_eq!(
            render(&fields),
            r#"{"ok":true,"role":"initiator","answered":["ab","cd"]}"#
        );
    }

    /// The four modes must all derive, and every key is 33 bytes at the SHA-256
    /// floor — the property that catches an otherwise-correct SHA-384 impl.
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

    #[test]
    fn pair_requires_two_peer_ids() {
        assert!(derive_key("pair", "alice").is_err());
        assert!(derive_key("pair", "alice,").is_err());
        assert!(derive_key("pair", ",bob").is_err());
    }

    /// `pair` is order-independent, so the harness may pass the two ids either
    /// way round — the property that lets both peers derive first.
    #[test]
    fn pair_is_order_independent_through_the_cli_shape() {
        assert_eq!(
            derive_key("pair", "alice,bob").unwrap(),
            derive_key("pair", "bob,alice").unwrap()
        );
    }
}
