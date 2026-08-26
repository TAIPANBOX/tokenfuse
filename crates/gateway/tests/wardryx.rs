//! Integration test for the Wardryx enforcement hook (a PEP) wired into
//! `proxy::messages`.
//!
//! `crates/gateway/src/wardryx.rs` has unit tests for the decision cache and
//! the fail-open/closed fallback in isolation. This file proves the HTTP
//! wiring end to end: a tiny stub Wardryx server stands in for the PDP, and
//! a real (offline) gateway request is driven through `tokenfuse_gateway::app`
//! against the in-process `StubProvider` upstream, mirroring the pattern
//! `tests/router.rs` and `tests/mcp_broker.rs` already use.

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokenfuse_core::{Ledger, Mode, ModelPrice, Policy, PriceBook};
use tokenfuse_gateway::provider::StubProvider;
use tokenfuse_gateway::state::AppState;
use tokenfuse_gateway::wardryx::{FailMode, Wardryx, WardryxMode};
use tower::ServiceExt;

/// A stub Wardryx PDP: always answers with whatever `response` it was
/// configured with, and records every request body and call count so tests
/// can assert on what the gateway actually sent (and how often).
#[derive(Clone)]
struct WardryxStub {
    response: Arc<Mutex<Value>>,
    last_request: Arc<Mutex<Option<Value>>>,
    calls: Arc<AtomicUsize>,
}

impl WardryxStub {
    fn new(response: Value) -> Self {
        WardryxStub {
            response: Arc::new(Mutex::new(response)),
            last_request: Arc::new(Mutex::new(None)),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

async fn decide(State(stub): State<WardryxStub>, Json(body): Json<Value>) -> Json<Value> {
    stub.calls.fetch_add(1, Ordering::SeqCst);
    *stub.last_request.lock().unwrap() = Some(body);
    Json(stub.response.lock().unwrap().clone())
}

fn wardryx_router(stub: WardryxStub) -> Router {
    Router::new()
        .route("/v1/decide", post(decide))
        .with_state(stub)
}

async fn spawn_server(router: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(l, router).await;
    });
    format!("http://{addr}")
}

/// `AppState` wired to an offline (in-process) `StubProvider` upstream, so
/// the "allow" path never makes a real network call either, and the given
/// `Wardryx` hook.
fn state(wardryx: Wardryx) -> AppState {
    let prices = PriceBook::new().with(
        "test-model",
        ModelPrice::per_mtok_usd(3.0, 15.0, 0.30, 3.75),
    );
    AppState::new(
        Arc::new(Ledger::new()),
        Arc::new(prices),
        Arc::new(Policy {
            mode: Mode::Enforce,
            ..Default::default()
        }),
        Arc::new(StubProvider::default()),
        "wardryx-test-policy",
    )
    .with_wardryx(Arc::new(wardryx))
}

/// The same state, but keeping the caller's own handle on the hook so a test
/// can read what the PDP answered afterwards (`Wardryx::verdicts`).
fn state_sharing(wardryx: Arc<Wardryx>) -> AppState {
    let prices = PriceBook::new().with(
        "test-model",
        ModelPrice::per_mtok_usd(3.0, 15.0, 0.30, 3.75),
    );
    AppState::new(
        Arc::new(Ledger::new()),
        Arc::new(prices),
        Arc::new(Policy {
            mode: Mode::Enforce,
            ..Default::default()
        }),
        Arc::new(StubProvider::default()),
        "wardryx-test-policy",
    )
    .with_wardryx(wardryx)
}

fn body() -> String {
    r#"{"model":"test-model","max_tokens":100,"messages":[{"role":"user","content":"hi"}]}"#
        .to_string()
}

fn request_with_headers(body: &str, extra: &[(&str, &str)]) -> Request<Body> {
    let mut builder = Request::post("/v1/messages")
        .header("x-fuse-run-id", "wardryx-test-run")
        // Enforce mode requires an agent identity before it will ask the PDP
        // anything, so every test below that is about PDP WIRING has to send
        // one. The absence of this header is its own case, and it has its own
        // two tests at the bottom of this file rather than being smuggled into
        // ten tests that are asking a different question.
        .header("x-fuse-agent-id", "agent://wardryx-test/caller")
        .header("x-fuse-budget-usd", "5.0");
    for (k, v) in extra {
        builder = builder.header(*k, *v);
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

fn request(body: &str) -> Request<Body> {
    request_with_headers(body, &[])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enforce_blocks_on_deny() {
    let stub = WardryxStub::new(json!({
        "decision": "deny",
        "reason": "policy says no",
        "policy_version": "v1"
    }));
    let url = spawn_server(wardryx_router(stub.clone())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let wardryx = Wardryx::new(
        WardryxMode::Enforce,
        FailMode::Open,
        url,
        None,
        Duration::from_millis(500),
        Duration::from_secs(2),
    );
    let app = tokenfuse_gateway::app(state(wardryx));

    let resp = app.oneshot(request(&body())).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(resp.headers().get("x-fuse-wardryx").unwrap(), "deny");
    assert_eq!(stub.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enforce_hold_returns_403_with_approval_id() {
    let stub = WardryxStub::new(json!({
        "decision": "hold",
        "approval_id": "appr-42",
        "reason": "needs a human"
    }));
    let url = spawn_server(wardryx_router(stub.clone())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let wardryx = Wardryx::new(
        WardryxMode::Enforce,
        FailMode::Open,
        url,
        None,
        Duration::from_millis(500),
        Duration::from_secs(2),
    );
    let app = tokenfuse_gateway::app(state(wardryx));

    let resp = app.oneshot(request(&body())).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(resp.headers().get("x-fuse-wardryx").unwrap(), "hold");
    assert_eq!(resp.headers().get("x-fuse-approval-id").unwrap(), "appr-42");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shadow_mode_never_blocks() {
    // The PDP says deny, but shadow mode must never act on it.
    let stub = WardryxStub::new(json!({ "decision": "deny", "reason": "would deny" }));
    let url = spawn_server(wardryx_router(stub.clone())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let wardryx = Wardryx::new(
        WardryxMode::Shadow,
        FailMode::Open,
        url,
        None,
        Duration::from_millis(500),
        Duration::from_secs(2),
    );
    let app = tokenfuse_gateway::app(state(wardryx));

    let resp = app.oneshot(request(&body())).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("x-fuse-wardryx").unwrap(), "would-deny");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn off_mode_makes_no_decide_call() {
    let stub = WardryxStub::new(json!({ "decision": "deny" }));
    let url = spawn_server(wardryx_router(stub.clone())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    // A real, reachable URL is configured, so a stray call would succeed
    // (and be counted) if the `Off` gate in `proxy::messages` were broken.
    let wardryx = Wardryx::new(
        WardryxMode::Off,
        FailMode::Open,
        url,
        None,
        Duration::from_millis(500),
        Duration::from_secs(2),
    );
    let app = tokenfuse_gateway::app(state(wardryx));

    let resp = app.oneshot(request(&body())).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get("x-fuse-wardryx").is_none());
    assert_eq!(stub.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failmode_open_allows_when_pdp_unreachable() {
    // Nothing listens on this address: connections fail fast (refused), no
    // real server needed to prove the fail-open fallback.
    let wardryx = Wardryx::new(
        WardryxMode::Enforce,
        FailMode::Open,
        "http://127.0.0.1:1",
        None,
        Duration::from_millis(300),
        Duration::from_secs(2),
    );
    let app = tokenfuse_gateway::app(state(wardryx));

    let resp = app.oneshot(request(&body())).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("x-fuse-wardryx").unwrap(), "allow");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failmode_closed_denies_when_pdp_unreachable() {
    let wardryx = Wardryx::new(
        WardryxMode::Enforce,
        FailMode::Closed,
        "http://127.0.0.1:1",
        None,
        Duration::from_millis(300),
        Duration::from_secs(2),
    );
    let app = tokenfuse_gateway::app(state(wardryx));

    let resp = app.oneshot(request(&body())).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(resp.headers().get("x-fuse-wardryx").unwrap(), "deny");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approval_token_header_is_forwarded_to_decide_call() {
    let stub = WardryxStub::new(json!({ "decision": "allow" }));
    let url = spawn_server(wardryx_router(stub.clone())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let wardryx = Wardryx::new(
        WardryxMode::Enforce,
        FailMode::Open,
        url,
        None,
        Duration::from_millis(500),
        Duration::from_secs(2),
    );
    let app = tokenfuse_gateway::app(state(wardryx));
    let req = request_with_headers(&body(), &[("x-fuse-approval-token", "tok-abc123")]);

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("x-fuse-wardryx").unwrap(), "allow");

    let sent = stub
        .last_request
        .lock()
        .unwrap()
        .clone()
        .expect("the decide endpoint was called");
    assert_eq!(sent["approval_token"], json!("tok-abc123"));
}

/// A request whose `tools` array declares one URL-bearing tool, so
/// `referenced_domains` has something to extract.
fn body_with_tool_url() -> String {
    r#"{"model":"test-model","max_tokens":100,"messages":[{"role":"user","content":"hi"}],
        "tools":[{"name":"fetch","description":"fetch a resource","server_url":"https://api.acme.example/v1/data"}]}"#
        .to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn steps_and_domains_are_sent_to_decide_call() {
    let stub = WardryxStub::new(json!({ "decision": "allow" }));
    let url = spawn_server(wardryx_router(stub.clone())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let wardryx = Wardryx::new(
        WardryxMode::Enforce,
        FailMode::Open,
        url,
        None,
        Duration::from_millis(500),
        // Zero TTL: both calls below share the same (agent_id, tool_names)
        // cache key, and a real cache hit on the second call would serve
        // the cached decision without ever reaching the stub again -- which
        // would hide the very thing this test exists to prove (that the
        // second call's "steps" reflects the first call's completed
        // reservation). Keep caching out of the way entirely.
        Duration::from_millis(0),
    );
    let app = tokenfuse_gateway::app(state(wardryx));
    let tool_body = body_with_tool_url();

    // First call on a fresh run: no prior action has been reserved yet, so
    // the run's accumulated step count is zero.
    let resp1 = app.clone().oneshot(request(&tool_body)).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);
    let sent1 = stub
        .last_request
        .lock()
        .unwrap()
        .clone()
        .expect("first decide call was made");
    assert_eq!(sent1["steps"], json!(0));
    assert_eq!(sent1["domains"], json!(["api.acme.example"]));

    // Second call, same run: the first call's reserve() already bumped the
    // ledger's step count by one, so this call's "steps" must reflect it.
    let resp2 = app.oneshot(request(&tool_body)).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let sent2 = stub
        .last_request
        .lock()
        .unwrap()
        .clone()
        .expect("second decide call was made");
    assert_eq!(sent2["steps"], json!(1));
    assert_eq!(sent2["domains"], json!(["api.acme.example"]));

    assert_eq!(stub.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deny_from_a_step_or_domain_rule_still_maps_to_403() {
    // Wardryx's own max_steps/allow_domains rules are exercised by the
    // wardryx repo's decision-table test; this only proves the gateway's
    // enforcement mapping doesn't need to know or care *why* Wardryx
    // denied. A deny is a deny -- whether it came from a step-budget rule,
    // a domain rule, deny_tool, or anything else -- and it maps to the same
    // 403 path `enforce_blocks_on_deny` already covers generically. This
    // uses a step/domain-flavored `reason` to make that connection explicit
    // for this feature, and doubles as one more check that the request this
    // hook actually sends carries the "steps"/"domains" a real PDP would
    // have decided against.
    let stub = WardryxStub::new(json!({
        "decision": "deny",
        "reason": "policy \"finance-guardrail\" step budget exhausted: 5 >= max_steps 5",
        "policy_version": "v1"
    }));
    let url = spawn_server(wardryx_router(stub.clone())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let wardryx = Wardryx::new(
        WardryxMode::Enforce,
        FailMode::Open,
        url,
        None,
        Duration::from_millis(500),
        Duration::from_secs(2),
    );
    let app = tokenfuse_gateway::app(state(wardryx));

    let resp = app.oneshot(request(&body_with_tool_url())).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(resp.headers().get("x-fuse-wardryx").unwrap(), "deny");

    let sent = stub
        .last_request
        .lock()
        .unwrap()
        .clone()
        .expect("the decide endpoint was called");
    assert_eq!(sent["domains"], json!(["api.acme.example"]));
    assert_eq!(sent["steps"], json!(0));
}

/// Proves the actual bug this feature closes: a decision cache keyed only
/// on `(agent_id, tool_set_hash)` used to reuse a cached `allow` across
/// calls whose `steps`/`domains`/`est_cost_usd` had since changed the
/// answer Wardryx would give. `cacheable: false` on the wire is how Wardryx
/// now tells the gateway a decision depends on exactly that kind of
/// per-request state -- so it must reach the PDP on every call, never
/// served from cache, even well inside the TTL and even for the identical
/// (agent_id, tool_names) pair every call below uses.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cacheable_false_is_never_reused_from_cache() {
    let stub = WardryxStub::new(json!({
        "decision": "allow",
        "policy_version": "v1",
        "cacheable": false
    }));
    let url = spawn_server(wardryx_router(stub.clone())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let wardryx = Wardryx::new(
        WardryxMode::Enforce,
        FailMode::Open,
        url,
        None,
        Duration::from_millis(500),
        // Generous TTL: every call below falls inside the same window, so
        // a wrongly-cached decision would be served instead of reaching
        // the stub -- exactly the bug this test exists to catch.
        Duration::from_secs(30),
    );
    let app = tokenfuse_gateway::app(state(wardryx));

    const REQUESTS: usize = 3;
    for _ in 0..REQUESTS {
        let resp = app.clone().oneshot(request(&body())).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("x-fuse-wardryx").unwrap(), "allow");
    }

    assert_eq!(
        stub.calls.load(Ordering::SeqCst),
        REQUESTS,
        "cacheable: false must reach Wardryx on every request; the decision cache must never reuse it"
    );
}

/// The mirror image of `cacheable_false_is_never_reused_from_cache`: when
/// Wardryx marks a decision `cacheable: true` (no matched policy is
/// request-specific), the gateway's existing repeat-call cache still
/// applies -- only the first call within the TTL reaches the stub, the
/// rest are served from cache.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cacheable_true_is_served_from_cache_within_ttl() {
    let stub = WardryxStub::new(json!({
        "decision": "allow",
        "policy_version": "v1",
        "cacheable": true
    }));
    let url = spawn_server(wardryx_router(stub.clone())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let wardryx = Wardryx::new(
        WardryxMode::Enforce,
        FailMode::Open,
        url,
        None,
        Duration::from_millis(500),
        Duration::from_secs(30),
    );
    let app = tokenfuse_gateway::app(state(wardryx));

    const REQUESTS: usize = 3;
    for _ in 0..REQUESTS {
        let resp = app.clone().oneshot(request(&body())).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("x-fuse-wardryx").unwrap(), "allow");
    }

    assert_eq!(
        stub.calls.load(Ordering::SeqCst),
        1,
        "cacheable: true should be cached after the first call: only one upstream hit for {REQUESTS} requests"
    );
}

/// Regression: a request that only DECLARES a tool (Anthropic `tools[]`, no
/// `tool_use` block yet) must still surface that tool name to the PDP, so a
/// `deny_tool` policy fires before the model is ever given the chance to invoke
/// it. Previously the PEP consulted only *invoked* tools, so `tool_names` here
/// was empty and a first-turn `deny_tool` could be bypassed by declaring the
/// forbidden tool without calling it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn declared_tool_is_forwarded_to_pdp() {
    let stub = WardryxStub::new(json!({ "decision": "allow" }));
    let url = spawn_server(wardryx_router(stub.clone())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let wardryx = Wardryx::new(
        WardryxMode::Enforce,
        FailMode::Open,
        url,
        None,
        Duration::from_millis(500),
        Duration::from_secs(2),
    );
    let app = tokenfuse_gateway::app(state(wardryx));

    let body = r#"{"model":"test-model","max_tokens":100,"messages":[{"role":"user","content":"refund by wire"}],"tools":[{"name":"wire_transfer","description":"move money","input_schema":{"type":"object"}}]}"#;
    let resp = app.oneshot(request(body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK); // the stub allows; we assert on what was sent

    let sent = stub
        .last_request
        .lock()
        .unwrap()
        .clone()
        .expect("PDP received a decide request");
    let tools = sent
        .get("tool_names")
        .and_then(|t| t.as_array())
        .expect("decide request carries tool_names");
    assert!(
        tools.iter().any(|t| t.as_str() == Some("wire_transfer")),
        "a declared-but-not-invoked tool must be forwarded to the PDP, got {tools:?}"
    );
}

/// The same request as everything above, minus the one header that says who
/// is calling.
fn request_without_an_agent_id(body: &str) -> Request<Body> {
    Request::post("/v1/messages")
        .header("x-fuse-run-id", "wardryx-test-run")
        .header("x-fuse-budget-usd", "5.0")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// Enforce mode with no agent identity is refused here, and the PDP is never
/// asked.
///
/// This is a regression test for a wrong ADDRESS rather than a wrong answer.
/// The gateway used to read `x-fuse-agent-id` with `unwrap_or_default()` and
/// send the empty string on as an identity; Wardryx answered 400, which the
/// gateway reported as `wardryx unreachable (response was not valid JSON)`,
/// and under `failmode=closed` that is a 403 that sends somebody to debug a
/// machine that was healthy the whole time.
///
/// So the status alone is not the assertion that matters. The two that matter
/// are that the PDP was never called, and that the body does not mention it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enforce_without_an_agent_id_is_refused_without_asking_the_pdp() {
    let stub = WardryxStub::new(json!({ "decision": "allow" }));
    let url = spawn_server(wardryx_router(stub.clone())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let wardryx = Wardryx::new(
        WardryxMode::Enforce,
        // Fail-open, so a test that passes cannot be passing because the
        // fallback happened to deny: with this setting an unreachable or
        // unasked PDP would let the call THROUGH.
        FailMode::Open,
        url,
        None,
        Duration::from_millis(500),
        Duration::from_secs(2),
    );
    let app = tokenfuse_gateway::app(state(wardryx));

    let resp = app
        .oneshot(request_without_an_agent_id(&body()))
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "a policy question with no subject is the caller's error, not a 403 and not a pass"
    );

    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let error: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(error["error"]["type"], "identity_required");
    let reason = error["error"]["reason"].as_str().unwrap();
    assert!(
        reason.contains("x-fuse-agent-id"),
        "the refusal has to name the header that is missing, got {reason:?}"
    );
    assert!(
        !reason.to_lowercase().contains("wardryx"),
        "the policy plane is healthy and must not be named in this error, got {reason:?}"
    );

    assert_eq!(
        stub.calls.load(Ordering::SeqCst),
        0,
        "the PDP must not be asked a question with no subject in it"
    );
}

/// The mirror image: shadow mode blocks nothing by definition, so a missing
/// agent identity must not become a refusal there.
///
/// Without this test, "shadow mode is untouched" is a sentence in a commit
/// message. The observation still has to happen, with whatever attribution it
/// was given, which is why the decide call is counted rather than ignored.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shadow_without_an_agent_id_still_observes_and_never_blocks() {
    let stub = WardryxStub::new(json!({ "decision": "deny", "reason": "would deny" }));
    let url = spawn_server(wardryx_router(stub.clone())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let wardryx = Wardryx::new(
        WardryxMode::Shadow,
        FailMode::Open,
        url,
        None,
        Duration::from_millis(500),
        Duration::from_secs(2),
    );
    let app = tokenfuse_gateway::app(state(wardryx));

    let resp = app
        .oneshot(request_without_an_agent_id(&body()))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("x-fuse-wardryx").unwrap(), "would-deny");
    assert_eq!(
        stub.calls.load(Ordering::SeqCst),
        1,
        "shadow mode observes; refusing here would make it act, which is the one thing it must not do"
    );
}

// -- what the PDP actually answered (GET /v1/policy-plane) -------------------
//
// `src/policyplane.rs` decides what a set of verdicts MEANS, and its unit tests
// cover that. These two cover the wiring underneath it, which no unit test can
// see: that a decision off the wire is recorded, and that a failmode fallback
// is not. Without them `decide` could stop counting altogether and every other
// test in this repository would still pass, which is precisely the shape of
// fault the endpoint exists to catch.

/// A real deny from a real PDP is the evidence a deployment check needs, and
/// it has to arrive by itself: an allow this gateway never received must not
/// appear beside it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_verdict_off_the_wire_is_recorded_as_one() {
    let stub = WardryxStub::new(json!({ "decision": "deny", "reason": "policy says no" }));
    let url = spawn_server(wardryx_router(stub.clone())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let hook = Arc::new(Wardryx::new(
        WardryxMode::Enforce,
        FailMode::Open,
        url,
        None,
        Duration::from_millis(500),
        // No cache: a second call must reach the PDP, not a stored copy.
        Duration::from_millis(0),
    ));
    let app = tokenfuse_gateway::app(state_sharing(hook.clone()));

    let resp = app.oneshot(request(&body())).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let v = hook.verdicts();
    assert_eq!(v.deny, 1, "the deny the PDP returned");
    assert_eq!(v.allow, 0, "and nothing else");
    assert_eq!(v.unreachable_fallbacks, 0);
    assert!(
        v.last_deny_millis > 0,
        "a verdict with no timestamp cannot answer a question about a window"
    );
}

/// The fault this endpoint exists for, end to end: `failmode=open` turns an
/// unreachable PDP into an allow, the call proceeds, and the deployment looks
/// exactly like a governed one. It must not COUNT as a verdict.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreachable_pdp_never_counts_as_an_allow() {
    let hook = Arc::new(Wardryx::new(
        WardryxMode::Enforce,
        FailMode::Open,
        // Port 1: nothing is listening, so every decide call fails transport.
        "http://127.0.0.1:1",
        None,
        Duration::from_millis(50),
        Duration::from_millis(0),
    ));
    let app = tokenfuse_gateway::app(state_sharing(hook.clone()));

    let resp = app.oneshot(request(&body())).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "fail-open is the configured behaviour and is unchanged by this test"
    );

    let v = hook.verdicts();
    assert_eq!(v.allow, 0, "the gateway allowed it; the PDP did not");
    assert_eq!(v.deny, 0);
    assert_eq!(v.unreachable_fallbacks, 1);
}

// ---------------------------------------------------------------------------
// The policy plane as a DEPENDENCY of this box, rather than as its judge.
//
// Everything above this line asks what the PDP decided. These four ask what
// happens when it decides nothing because nobody could reach it, which until
// now was the quietest failure in the gateway: `Verdicts` counted it, a
// `tracing::warn!` mentioned it, and the shared event bus said nothing at all,
// so a call that no policy had governed was indistinguishable on the trail
// from one that a policy had allowed.
// ---------------------------------------------------------------------------

/// An exporter on a private file, plus the path to read back.
fn recording_exporter(
    tag: &str,
) -> (
    Arc<tokenfuse_core::agent_event::Exporter>,
    std::path::PathBuf,
) {
    let dir = std::env::temp_dir().join(format!("tf-pdp-depfail-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a temp dir");
    let path = dir.join("events.ndjson");
    let exp =
        tokenfuse_core::agent_event::Exporter::open(path.to_str().expect("a utf-8 temp path"))
            .expect("an exporter on a fresh file");
    (Arc::new(exp), path)
}

fn dependency_failures_at(path: &std::path::Path) -> Vec<Value> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<Value>(l).expect("one JSON object per line"))
        .filter(|e| e["type"] == "dependency_failed")
        .collect()
}

/// A port nothing is listening on, so `decide` fails at connect rather than
/// hanging until the timeout. The same precondition mockryx's game-day drill
/// creates for the provider, one plane over.
const DEAD_PDP: &str = "http://127.0.0.1:1";

#[tokio::test]
async fn an_unreachable_policy_plane_is_recorded_when_it_fails_open() {
    let (events, path) = recording_exporter("open");
    let hook = Wardryx::new(
        WardryxMode::Enforce,
        FailMode::Open,
        DEAD_PDP,
        None,
        Duration::from_millis(200),
        Duration::from_secs(0),
    );
    let st = state(hook).with_events(events);

    let resp = tokenfuse_gateway::app(st)
        .oneshot(request(&body()))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "fail-open means the call proceeds, and this test does not change that"
    );

    let found = dependency_failures_at(&path);
    assert_eq!(found.len(), 1, "exactly one event, got {found:?}");
    let e = &found[0];
    assert_eq!(e["severity"], "high");
    assert_eq!(e["data"]["dependency"], "policy_plane");
    assert_eq!(e["data"]["stage"], "decide");
    assert_eq!(
        e["data"]["effect"], "allowed_ungoverned",
        "the member that stops a reader filing this as an ordinary outage: \
         nothing governed this call"
    );
}

#[tokio::test]
async fn an_unreachable_policy_plane_is_recorded_when_it_fails_closed() {
    let (events, path) = recording_exporter("closed");
    let hook = Wardryx::new(
        WardryxMode::Enforce,
        FailMode::Closed,
        DEAD_PDP,
        None,
        Duration::from_millis(200),
        Duration::from_secs(0),
    );
    let st = state(hook).with_events(events);

    let resp = tokenfuse_gateway::app(st)
        .oneshot(request(&body()))
        .await
        .unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "fail-closed refuses the call"
    );

    let found = dependency_failures_at(&path);
    assert_eq!(found.len(), 1, "exactly one event, got {found:?}");
    assert_eq!(found[0]["data"]["dependency"], "policy_plane");
    assert_eq!(
        found[0]["data"]["effect"], "denied_unasked",
        "\"a policy denied this\" and \"nobody could be asked\" are different \
         facts, and only one of them is true here"
    );
}

// Shadow mode reaches the same code and blocks nothing whatever the failmode
// says, so the effect is read from the decision that was applied and not from
// the configuration. Without this case a reader of the trail would be told a
// shadow deployment had refused a call it forwarded.
#[tokio::test]
async fn an_unreachable_policy_plane_in_shadow_mode_reports_what_actually_happened() {
    let (events, path) = recording_exporter("shadow");
    let hook = Wardryx::new(
        WardryxMode::Shadow,
        FailMode::Closed,
        DEAD_PDP,
        None,
        Duration::from_millis(200),
        Duration::from_secs(0),
    );
    let st = state(hook).with_events(events);

    let resp = tokenfuse_gateway::app(st)
        .oneshot(request(&body()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "shadow never blocks");

    let found = dependency_failures_at(&path);
    assert_eq!(found.len(), 1, "exactly one event, got {found:?}");
    assert_eq!(
        found[0]["data"]["effect"], "allowed_ungoverned",
        "the failmode says closed and the call went through; the event reports \
         the call, not the setting"
    );
}

// The non-fault case, and the one that decides whether the flag means
// anything: a PDP that answered must never be reported as a PDP that died,
// including when what it answered was no.
#[tokio::test]
async fn a_policy_plane_that_answered_is_not_reported_as_unreachable() {
    let (events, path) = recording_exporter("answered");
    let stub = WardryxStub::new(json!({"decision": "deny", "reason": "tool not allowed"}));
    let url = spawn_server(wardryx_router(stub)).await;
    let hook = Wardryx::new(
        WardryxMode::Enforce,
        FailMode::Open,
        url,
        None,
        Duration::from_secs(2),
        Duration::from_secs(0),
    );
    let st = state(hook).with_events(events);

    let resp = tokenfuse_gateway::app(st)
        .oneshot(request(&body()))
        .await
        .unwrap();
    assert_ne!(resp.status(), StatusCode::OK, "the PDP said no");

    assert!(
        dependency_failures_at(&path).is_empty(),
        "a plane that answered was reported as a plane that failed: {:?}",
        dependency_failures_at(&path)
    );
}

// ---------------------------------------------------------------------------
// The chain this proxy asks the PDP about must be one somebody PROVED.
//
// This is the same gap the MCP broker had and the bigger of the two, because
// this is the path the agents' own traffic takes. `on_behalf_of` came from a
// header, so `max_chain_depth` capped a number the caller chose.

/// A PDP-backed gate in enforce mode, for the two chain tests below.
fn enforcing(url: String) -> Wardryx {
    Wardryx::new(
        WardryxMode::Enforce,
        FailMode::Open,
        url,
        None,
        Duration::from_millis(500),
        Duration::from_secs(2),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_chain_nobody_proved_reaches_the_pdp_marked_unproven() {
    let stub = WardryxStub::new(json!({"decision": "allow", "policy_version": "v1"}));
    let url = spawn_server(wardryx_router(stub.clone())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    let st = state(enforcing(url));

    let resp = tokenfuse_gateway::app(st)
        .oneshot(request_with_headers(
            &body(),
            &[(
                "x-fuse-on-behalf-of",
                "user://acme.example/ceo,agent://acme.example/a,agent://acme.example/b",
            )],
        ))
        .await
        .unwrap();
    assert!(resp.status().is_success(), "status {}", resp.status());

    let asked = stub
        .last_request
        .lock()
        .unwrap()
        .clone()
        .expect("the PDP was not asked");
    assert_eq!(
        asked["chain_proven"],
        json!(false),
        "the proxy asked the PDP about a caller-declared chain without saying \
         nobody proved it. asked: {asked}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_proven_chain_reaches_the_pdp_from_the_token() {
    use tokenfuse_delegation::testing::{cfg, proof_at, token, Key, URL};

    let stub = WardryxStub::new(json!({"decision": "allow", "policy_version": "v1"}));
    let url = spawn_server(wardryx_router(stub.clone())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    let mut st = state(enforcing(url));

    let issuer = Key::new();
    let holder = Key::new();
    st.chain_proof = Some(Arc::new(tokenfuse_gateway::chainproof::Proving {
        cfg: cfg(&issuer),
        // The origin the fixture's own URL names, so the two agree by
        // construction rather than by a string retyped in two places.
        origin: URL.trim_end_matches("/v1/messages").to_string(),
    }));

    let now = tokenfuse_gateway::sink::now_millis() / 1000;
    let tok = token(
        &issuer,
        &holder,
        now,
        json!({
            "sub": "user://acme.example/alice",
            "act": { "sub": "agent://acme.example/orchestrator" }
        }),
    );
    let pf = proof_at(&holder, now, "POST", URL, "p-proxy");

    let resp = tokenfuse_gateway::app(st)
        .oneshot(request_with_headers(
            &body(),
            &[
                ("authorization", &format!("DPoP {tok}")),
                (tokenfuse_gateway::mcpdoor::PROOF_HEADER, &pf),
            ],
        ))
        .await
        .unwrap();
    assert!(resp.status().is_success(), "status {}", resp.status());

    let asked = stub
        .last_request
        .lock()
        .unwrap()
        .clone()
        .expect("the PDP was not asked");
    assert_eq!(asked["chain_proven"], json!(true), "asked: {asked}");
    assert_eq!(
        asked["on_behalf_of"],
        json!([
            "user://acme.example/alice",
            "agent://acme.example/orchestrator"
        ]),
        "asked: {asked}"
    );
}
