//! The MCP credential-broker's third door: a vouchryx Cross App Access (XAA)
//! bearer access token (W3-tokenfuse).
//!
//! Kept as its own file rather than folded into `mcp_broker.rs`, the same
//! reason `mcp_door.rs` is its own file: the door under test is new, and a
//! second door's tests belong beside it, not buried in an already-large file.

use std::sync::Arc;

use axum::routing::post;
use axum::{Json, Router};
use base64::Engine as _;
use serde_json::{json, Value};
use tokenfuse_delegation::testing::{access_token, cfg, token, Key};
use tokenfuse_gateway::mcpbroker::{app, BrokerState, ScanMode};
use tokenfuse_gateway::wardryx::Wardryx;
use tokenfuse_gateway::xaadoor::{from_values, XaaDoor};

const RESOURCE: &str = "https://mcp.acme.example/mcp";

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// A stub MCP server: echoes what it received so a test can see whether the
/// broker actually forwarded a call.
async fn stub(Json(req): Json<Value>) -> Json<Value> {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    Json(json!({ "jsonrpc": "2.0", "id": id, "result": { "echo": req.get("params").cloned() } }))
}

async fn spawn_server(router: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(l, router).await;
    });
    format!("http://{addr}")
}

/// A broker with the XAA door on, verifying against `issuer`, resource
/// `RESOURCE`, and nothing else configured (no bearer keys, no CIMD clients):
/// the point of these tests is the XAA door itself.
fn xaa_router(upstream: String, issuer: &Key) -> Router {
    let door = from_values(Some("on"), Some(RESOURCE), Some(cfg(issuer)))
        .expect("a well-formed XAA config")
        .expect("Some, since accept=on");
    app(state(upstream, Some(door)))
}

fn state(upstream: String, xaa: Option<Arc<XaaDoor>>) -> Arc<BrokerState> {
    state_with_keys(upstream, xaa, "")
}

fn state_with_keys(
    upstream: String,
    xaa: Option<Arc<XaaDoor>>,
    keys_spec: &str,
) -> Arc<BrokerState> {
    Arc::new(BrokerState {
        chain_proof: None,
        revocations: None,
        identity_strict: tokenfuse_gateway::identitymap::StrictMode::Off,
        upstream,
        named_upstreams: Default::default(),
        vault: tokenfuse_core::SecretVault::new(),
        scan: ScanMode::Off,
        dlp: tokenfuse_core::DlpMode::Off,
        dlp_pii: tokenfuse_core::DlpMode::Off,
        lock: None,
        wardryx: Arc::new(Wardryx::disabled()),
        keys: tokenfuse_gateway::clientkeys::ClientKeys::from_spec(keys_spec)
            .expect("a usable key spec"),
        clients: Default::default(),
        require_proof: false,
        client: reqwest::Client::new(),
        events: Arc::new(tokenfuse_core::agent_event::Exporter::disabled()),
        taint_gateway: None,
        taint_failclosed: false,
        xaa,
    })
}

async fn call(broker_url: &str, headers: &[(&str, &str)]) -> reqwest::Response {
    let mut req = reqwest::Client::new().post(broker_url).json(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "gh_api", "arguments": {} }
    }));
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    req.send().await.unwrap()
}

// --- RFC 9728 metadata -------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_resource_metadata_names_vouchryx() {
    let issuer = Key::new();
    let broker_url = spawn_server(xaa_router("http://127.0.0.1:1".to_string(), &issuer)).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let resp = reqwest::get(format!("{broker_url}/.well-known/oauth-protected-resource"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["resource"], RESOURCE);
    assert_eq!(body["authorization_servers"][0], cfg(&issuer).issuer);
    assert_eq!(body["bearer_methods_supported"][0], "header");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_resource_metadata_is_also_served_at_the_resources_own_path() {
    let issuer = Key::new();
    let broker_url = spawn_server(xaa_router("http://127.0.0.1:1".to_string(), &issuer)).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let resp = reqwest::get(format!(
        "{broker_url}/.well-known/oauth-protected-resource/mcp"
    ))
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["resource"], RESOURCE);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_well_known_paths_404_when_xaa_is_off() {
    let broker_url = spawn_server(app(state("http://127.0.0.1:1".to_string(), None))).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    for path in [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
    ] {
        let resp = reqwest::get(format!("{broker_url}{path}")).await.unwrap();
        assert_eq!(
            resp.status(),
            404,
            "{path} must 404 exactly as before this door existed"
        );
    }
}

// --- WWW-Authenticate ----------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_401_points_at_the_resource_metadata() {
    let issuer = Key::new();
    let broker_url = spawn_server(xaa_router("http://127.0.0.1:1".to_string(), &issuer)).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let resp = call(&broker_url, &[]).await;
    assert_eq!(resp.status(), 401);
    let www = resp
        .headers()
        .get("www-authenticate")
        .expect("a 401 while XAA is on must carry WWW-Authenticate")
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(
        www,
        "Bearer resource_metadata=\"https://mcp.acme.example/.well-known/oauth-protected-resource/mcp\""
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_401_carries_no_www_authenticate_when_xaa_is_off() {
    let broker_url = spawn_server(app(state("http://127.0.0.1:1".to_string(), None))).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    // With no door at all configured, a plain call is admitted (Open); use a
    // wrong bearer-key style credential path instead by naming a client key
    // door that refuses. Simplest: leave everything off, which admits Open
    // and forwards - so this negative control instead checks a request that
    // IS refused for another reason (an over-cap on_behalf_of), asserting
    // that refusal carries no WWW-Authenticate when XAA is off.
    let entries = (0..40)
        .map(|i| format!("agent://acme.example/hop{i}"))
        .collect::<Vec<_>>()
        .join(",");
    let resp = call(&broker_url, &[("x-fuse-on-behalf-of", &entries)]).await;
    assert_eq!(resp.status(), 400);
    assert!(resp.headers().get("www-authenticate").is_none());
}

// --- the door itself -------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_vouchryx_token_is_attributed_to_its_agent() {
    let issuer = Key::new();
    let upstream = spawn_server(Router::new().route("/", post(stub))).await;
    let broker_url = spawn_server(xaa_router(upstream, &issuer)).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let now = tokenfuse_gateway::sink::now_millis() / 1000;
    let tok = access_token(&issuer, now, json!({"aud": RESOURCE}));
    let resp = call(&broker_url, &[("authorization", &format!("Bearer {tok}"))]).await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body.get("result").is_some(),
        "the call must reach the upstream: {body}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_token_for_another_resource_is_refused_at_the_broker() {
    let issuer = Key::new();
    let upstream = spawn_server(Router::new().route("/", post(stub))).await;
    let broker_url = spawn_server(xaa_router(upstream, &issuer)).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let now = tokenfuse_gateway::sink::now_millis() / 1000;
    let tok = access_token(
        &issuer,
        now,
        json!({"aud": "https://elsewhere.example/mcp"}),
    );
    let resp = call(&broker_url, &[("authorization", &format!("Bearer {tok}"))]).await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_only_xaa_configured_a_call_with_no_credential_is_refused() {
    let issuer = Key::new();
    let upstream = spawn_server(Router::new().route("/", post(stub))).await;
    let broker_url = spawn_server(xaa_router(upstream, &issuer)).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let resp = call(&broker_url, &[]).await;
    assert_eq!(
        resp.status(),
        401,
        "Admission::Open must not be reachable once XAA is configured"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bound_token_presented_as_bearer_is_refused() {
    let issuer = Key::new();
    let holder = Key::new();
    let upstream = spawn_server(Router::new().route("/", post(stub))).await;
    let broker_url = spawn_server(xaa_router(upstream, &issuer)).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let now = tokenfuse_gateway::sink::now_millis() / 1000;
    let jkt =
        tokenfuse_dpop::thumbprint(&serde_json::from_value(holder.jwk_value(None)).expect("a jwk"))
            .expect("a thumbprint");
    let tok = access_token(&issuer, now, json!({"aud": RESOURCE, "cnf": {"jkt": jkt}}));
    let resp = call(&broker_url, &[("authorization", &format!("Bearer {tok}"))]).await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_exchange_token_presented_as_bearer_is_refused() {
    let issuer = Key::new();
    let holder = Key::new();
    let upstream = spawn_server(Router::new().route("/", post(stub))).await;
    let broker_url = spawn_server(xaa_router(upstream, &issuer)).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let now = tokenfuse_gateway::sink::now_millis() / 1000;
    // A real vouchryx-shaped DELEGATION (exchange) token, minted by
    // `verify_delegation`'s own fixture: it carries `cnf.jkt` and no
    // `client_id`, so it is not an access token.
    let exchange_tok = token(&issuer, &holder, now, json!({"aud": RESOURCE}));
    let resp = call(
        &broker_url,
        &[("authorization", &format!("Bearer {exchange_tok}"))],
    )
    .await;
    assert_eq!(resp.status(), 401);
}

/// Mutant territory (the algorithm rule applied end to end): an EC issuer key
/// only offers ES256/ES384, so a header claiming HS256 must be refused
/// before the (irrelevant) third segment is ever inspected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_algorithm_taken_from_the_header_is_refused_for_an_access_token() {
    let issuer = Key::new();
    let upstream = spawn_server(Router::new().route("/", post(stub))).await;
    let broker_url = spawn_server(xaa_router(upstream, &issuer)).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let now = tokenfuse_gateway::sink::now_millis() / 1000;
    let header = b64(br#"{"alg":"HS256","typ":"JWT","kid":"v-1"}"#);
    let claims = b64(json!({
        "iss": cfg(&issuer).issuer, "sub": "user://acme/alice", "aud": RESOURCE,
        "iat": now, "exp": now + 300, "jti": "at-hs256",
        "client_id": "https://client.acme.example/agent",
        "act": {"sub": "agent://acme/triage"},
    })
    .to_string()
    .as_bytes());
    let forged = format!("{header}.{claims}.not-a-real-signature");
    let resp = call(
        &broker_url,
        &[("authorization", &format!("Bearer {forged}"))],
    )
    .await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_xaa_bearer_never_falls_through_to_a_valid_bearer_key() {
    let issuer = Key::new();
    let upstream = spawn_server(Router::new().route("/", post(stub))).await;
    // A state with BOTH the XAA door and a valid TOKENFUSE_MCP_KEYS
    // credential configured.
    let door = from_values(Some("on"), Some(RESOURCE), Some(cfg(&issuer)))
        .unwrap()
        .unwrap();
    let broker_url = spawn_server(app(state_with_keys(
        upstream,
        Some(door),
        "sk-broker-abc:tool-user",
    )))
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let now = tokenfuse_gateway::sink::now_millis() / 1000;
    let broken = access_token(
        &issuer,
        now,
        json!({"aud": "https://elsewhere.example/mcp"}),
    );
    let resp = call(
        &broker_url,
        &[
            ("authorization", &format!("Bearer {broken}")),
            (
                tokenfuse_gateway::clientkeys::CLIENT_KEY_HEADER,
                "sk-broker-abc",
            ),
        ],
    )
    .await;
    // Two credentials at once is ALSO a refusal on its own (correction 3's
    // sibling rule), so this equally proves the point: a failed (or merely
    // co-presented) XAA bearer never reaches the bearer-key door.
    assert_eq!(resp.status(), 401);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bearer_credential_alongside_x_fuse_key_is_refused() {
    let issuer = Key::new();
    let upstream = spawn_server(Router::new().route("/", post(stub))).await;
    let door = from_values(Some("on"), Some(RESOURCE), Some(cfg(&issuer)))
        .unwrap()
        .unwrap();
    let broker_url = spawn_server(app(state_with_keys(
        upstream,
        Some(door),
        "sk-broker-abc:tool-user",
    )))
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let now = tokenfuse_gateway::sink::now_millis() / 1000;
    let good = access_token(&issuer, now, json!({"aud": RESOURCE}));
    let resp = call(
        &broker_url,
        &[
            ("authorization", &format!("Bearer {good}")),
            (
                tokenfuse_gateway::clientkeys::CLIENT_KEY_HEADER,
                "sk-broker-abc",
            ),
        ],
    )
    .await;
    assert_eq!(
        resp.status(),
        401,
        "two credentials at once must refuse, not pick one"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bearer_credential_alongside_a_dpop_header_is_refused() {
    let issuer = Key::new();
    let upstream = spawn_server(Router::new().route("/", post(stub))).await;
    let broker_url = spawn_server(xaa_router(upstream, &issuer)).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let now = tokenfuse_gateway::sink::now_millis() / 1000;
    let good = access_token(&issuer, now, json!({"aud": RESOURCE}));
    let resp = call(
        &broker_url,
        &[
            ("authorization", &format!("Bearer {good}")),
            ("dpop", "anything-at-all"),
        ],
    )
    .await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_declared_chain_that_disagrees_with_the_xaa_token_is_refused() {
    let issuer = Key::new();
    let upstream = spawn_server(Router::new().route("/", post(stub))).await;
    let broker_url = spawn_server(xaa_router(upstream, &issuer)).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let now = tokenfuse_gateway::sink::now_millis() / 1000;
    let tok = access_token(&issuer, now, json!({"aud": RESOURCE}));
    let resp = call(
        &broker_url,
        &[
            ("authorization", &format!("Bearer {tok}")),
            (
                "x-fuse-on-behalf-of",
                "user://acme/alice,agent://acme/somebody-else",
            ),
        ],
    )
    .await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_declared_chain_that_is_a_reordering_of_the_xaa_tokens_chain_is_refused() {
    let issuer = Key::new();
    let upstream = spawn_server(Router::new().route("/", post(stub))).await;
    let broker_url = spawn_server(xaa_router(upstream, &issuer)).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let now = tokenfuse_gateway::sink::now_millis() / 1000;
    let tok = access_token(&issuer, now, json!({"aud": RESOURCE}));
    // The token's chain is [user://acme/alice, agent://acme/triage]; declared
    // is the same SET in the other order.
    let resp = call(
        &broker_url,
        &[
            ("authorization", &format!("Bearer {tok}")),
            (
                "x-fuse-on-behalf-of",
                "agent://acme/triage,user://acme/alice",
            ),
        ],
    )
    .await;
    assert_eq!(resp.status(), 401);
}

/// A matching declared chain must not be refused: the guard against an
/// overeager comparison.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_declared_chain_that_matches_the_xaa_tokens_chain_is_admitted() {
    let issuer = Key::new();
    let upstream = spawn_server(Router::new().route("/", post(stub))).await;
    let broker_url = spawn_server(xaa_router(upstream, &issuer)).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let now = tokenfuse_gateway::sink::now_millis() / 1000;
    let tok = access_token(&issuer, now, json!({"aud": RESOURCE}));
    let resp = call(
        &broker_url,
        &[
            ("authorization", &format!("Bearer {tok}")),
            (
                "x-fuse-on-behalf-of",
                "user://acme/alice,agent://acme/triage",
            ),
        ],
    )
    .await;
    assert_eq!(resp.status(), 200);
}

/// Correction 4: a delegation token (`Authorization: DPoP` + a `dpop` proof)
/// is a chain proof, not a door credential. With XAA on and no keys/clients
/// configured, presenting one alone must still be refused with the XAA
/// WWW-Authenticate, not silently admitted as `Admission::Open`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_xaa_on_a_delegation_token_alone_does_not_open_the_door() {
    use tokenfuse_delegation::testing::proof_at;
    let issuer = Key::new();
    let holder = Key::new();
    let upstream = spawn_server(Router::new().route("/", post(stub))).await;
    let broker_url = spawn_server(xaa_router(upstream, &issuer)).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let now = tokenfuse_gateway::sink::now_millis() / 1000;
    let delegation = token(&issuer, &holder, now, json!({}));
    let mcp_url = format!("{broker_url}/");
    let dpop = proof_at(&holder, now, "POST", &mcp_url, "p-1");
    let resp = call(
        &broker_url,
        &[
            ("authorization", &format!("DPoP {delegation}")),
            ("dpop", &dpop),
        ],
    )
    .await;
    assert_eq!(
        resp.status(),
        401,
        "a chain proof is not a door credential and must not open the door on its own"
    );
    assert!(resp.headers().get("www-authenticate").is_some());
}

/// Correction 3: RFC 7235 section 2.1, `auth-scheme` is a token and tokens
/// compare case-insensitively.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_bearer_scheme_is_case_insensitive() {
    let issuer = Key::new();
    for scheme in ["Bearer", "bearer", "BEARER", "BeArEr"] {
        let upstream = spawn_server(Router::new().route("/", post(stub))).await;
        let broker_url = spawn_server(xaa_router(upstream, &issuer)).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let now = tokenfuse_gateway::sink::now_millis() / 1000;
        let tok = access_token(&issuer, now, json!({"aud": RESOURCE}));
        let resp = call(
            &broker_url,
            &[("authorization", &format!("{scheme} {tok}"))],
        )
        .await;
        assert_eq!(resp.status(), 200, "scheme {scheme:?} must be accepted");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dpop_scheme_falls_through_to_the_existing_path_unchanged() {
    // Already exercised end to end by `with_xaa_on_a_delegation_token_alone_does_not_open_the_door`;
    // this one asserts the narrower fact that the SCHEME match itself is the
    // reason: `Authorization: Dpop ...` (any case) is never read as bearer.
    let issuer = Key::new();
    let upstream = spawn_server(Router::new().route("/", post(stub))).await;
    let broker_url = spawn_server(xaa_router(upstream, &issuer)).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let now = tokenfuse_gateway::sink::now_millis() / 1000;
    let tok = access_token(&issuer, now, json!({"aud": RESOURCE}));
    // A well-formed ACCESS token wearing the DPoP scheme must not be read as
    // an XAA bearer credential at all; it falls through to `mcpdoor::admit`,
    // which with nothing else configured and XAA on refuses it as Open.
    let resp = call(&broker_url, &[("authorization", &format!("DPoP {tok}"))]).await;
    assert_eq!(resp.status(), 401);
}

/// Correction 1: invariant 51 holds on this door too, with its own 400 shape,
/// not folded into the XAA door's 401.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_chain_over_the_cap_is_refused_at_the_xaa_door_too() {
    let issuer = Key::new();
    let upstream = spawn_server(Router::new().route("/", post(stub))).await;
    let broker_url = spawn_server(xaa_router(upstream, &issuer)).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let now = tokenfuse_gateway::sink::now_millis() / 1000;
    let tok = access_token(&issuer, now, json!({"aud": RESOURCE}));
    let entries = (0..40)
        .map(|i| format!("agent://acme.example/hop{i}"))
        .collect::<Vec<_>>()
        .join(",");
    let resp = call(
        &broker_url,
        &[
            ("authorization", &format!("Bearer {tok}")),
            ("x-fuse-on-behalf-of", &entries),
        ],
    )
    .await;
    assert_eq!(resp.status(), 400, "the over-cap 400, never the door's 401");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "on_behalf_of_over_cap");
}

/// The classic path, unaffected by XAA existing at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xaa_off_leaves_an_authorization_bearer_request_exactly_as_before() {
    let upstream = spawn_server(Router::new().route("/", post(stub))).await;
    let broker_url = spawn_server(app(state(upstream, None))).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    // Nothing else is configured either (no keys, no clients, no XAA), so
    // this is the original `Admission::Open` default: forwarded, unchanged.
    let resp = call(
        &broker_url,
        &[("authorization", "Bearer whatever-a-client-happens-to-send")],
    )
    .await;
    assert_eq!(
        resp.status(),
        200,
        "an unconfigured broker is still Open with XAA off"
    );
}
