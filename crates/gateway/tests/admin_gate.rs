//! Integration tests for the admin gate on the gateway's observability and
//! kill routes: `GET /v1/runs`, `POST /v1/runs/{id}/kill`, `GET /v1/keys`,
//! `GET /v1/policy-plane`, `GET /v1/agent-ids`.
//!
//! Until this gate existed those five routes had no authentication at all.
//! The comment beside them said the gateway binds loopback by default, which
//! is true and was not the whole picture: the shipped `Dockerfile` sets
//! `TOKENFUSE_ADDR=0.0.0.0:4100`, and a deployment that publishes that port
//! hands anyone who can reach it every run's budget and spend, every key id,
//! every agent identity, and a kill switch for any run. These tests hit the
//! real router `tokenfuse_gateway::app` builds, the same way
//! `tests/keys_endpoint.rs` and `tests/policy_plane.rs` do, rather than
//! calling `adminkeys` functions directly, because the HTTP wiring (which
//! routes are covered, which are not, the exact response bodies) is what a
//! caller on the wire actually sees.

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use std::sync::Arc;
use tokenfuse_core::{Ledger, Mode, ModelPrice, Policy, PriceBook};
use tokenfuse_gateway::adminkeys::{self, AdminGate, AdminKeys};
use tokenfuse_gateway::provider::StubProvider;
use tokenfuse_gateway::state::AppState;
use tower::ServiceExt;

/// A plain gateway state with a given admin gate. `require_run_id` is off so
/// `/v1/messages` succeeds with no `x-fuse-run-id` header, which keeps the
/// one test that touches it (`healthz_and_messages_are_never_behind_the_admin_gate`)
/// about the gate and not about metering preconditions unrelated to it.
fn state(gate: AdminGate) -> AppState {
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
        "admin-gate-test-policy",
    )
    .with_require_run_id(false)
    .with_admin_gate(gate)
}

fn get(path: &str) -> Request<Body> {
    Request::get(path).body(Body::empty()).unwrap()
}

fn get_with_bearer(path: &str, token: &str) -> Request<Body> {
    Request::get(path)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

async fn error_field(resp: axum::response::Response) -> String {
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["error"].as_str().unwrap_or_default().to_string()
}

/// The dangerous middle case invariant 20 already named for the MCP broker,
/// one door over: nothing configured, and the bind is not loopback. Every one
/// of the five routes refuses rather than answering.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_open_bind_with_no_admin_keys_refuses_kill_and_runs() {
    let gate = AdminGate::resolve(AdminKeys::default(), false, false);

    let app = tokenfuse_gateway::app(state(gate.clone()));
    let resp = app.oneshot(get("/v1/runs")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(error_field(resp).await, "admin_keys_required");

    let app = tokenfuse_gateway::app(state(gate));
    let req = Request::post("/v1/runs/some-run/kill")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(error_field(resp).await, "admin_keys_required");
}

/// Today's behaviour, unchanged: nothing configured on the default loopback
/// bind means the five routes answer exactly as before this gate existed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_loopback_bind_with_no_admin_keys_keeps_the_routes_open() {
    let gate = AdminGate::resolve(AdminKeys::default(), true, false);

    for path in ["/v1/runs", "/v1/keys", "/v1/policy-plane", "/v1/agent-ids"] {
        let app = tokenfuse_gateway::app(state(gate.clone()));
        let resp = app.oneshot(get(path)).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "{path} must stay open on loopback"
        );
    }
}

/// The credential itself: a configured key opens every route, a wrong one
/// does not, and no header at all is the same refusal as a wrong one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_configured_admin_key_opens_the_routes_and_a_wrong_one_does_not() {
    let keys = AdminKeys::from_spec("sk-admin-correct").unwrap();
    // Configured keys are required regardless of the bind (invariant of
    // `AdminGate::resolve`), so this exercises that on a loopback bind, which
    // is the case an operator is most likely to be surprised by.
    let gate = AdminGate::resolve(keys, true, false);

    let app = tokenfuse_gateway::app(state(gate.clone()));
    let resp = app
        .oneshot(get_with_bearer("/v1/keys", "sk-admin-correct"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the right key must open the door"
    );

    let app = tokenfuse_gateway::app(state(gate.clone()));
    let resp = app
        .oneshot(get_with_bearer("/v1/keys", "sk-admin-wrong"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(error_field(resp).await, "unauthorized");

    let app = tokenfuse_gateway::app(state(gate));
    let resp = app.oneshot(get("/v1/keys")).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "no header at all is the same refusal as the wrong key"
    );
    assert_eq!(error_field(resp).await, "unauthorized");
}

/// `TOKENFUSE_ALLOW_OPEN_OBS=1` restores the old open behaviour on a wide
/// bind with nothing configured, exactly like `TOKENFUSE_MCP_ALLOW_OPEN_BIND`
/// does for the MCP broker's door, and the opt-out does not silence the
/// startup warning that names the safer fix.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_allow_open_obs_opt_out_is_honoured_and_logged() {
    let gate = AdminGate::resolve(AdminKeys::default(), false, true);
    let app = tokenfuse_gateway::app(state(gate));
    let resp = app.oneshot(get("/v1/keys")).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the opt-out must be honoured: no refusal on a wide-open bind"
    );

    let warning = adminkeys::open_obs_warning("0.0.0.0:4100", false, true)
        .expect("the opt-out does not silence the warning");
    assert!(warning.contains("TOKENFUSE_ADMIN_KEYS"));
    assert!(warning.contains("TOKENFUSE_ALLOW_OPEN_OBS"));
}

/// `/healthz` and `/v1/messages` are outside this gate entirely: a Breaker
/// deployment that never configures `TOKENFUSE_ADMIN_KEYS` must still serve
/// traffic even while the observability/kill routes refuse every request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn healthz_and_messages_are_never_behind_the_admin_gate() {
    let gate = AdminGate::resolve(AdminKeys::default(), false, false);
    assert!(
        matches!(gate, AdminGate::Forbidden),
        "the fixture must actually be in the refusing state, or this test proves nothing"
    );

    let app = tokenfuse_gateway::app(state(gate.clone()));
    let resp = app.oneshot(get("/healthz")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body =
        r#"{"model":"test-model","max_tokens":100,"messages":[{"role":"user","content":"hi"}]}"#;
    let req = Request::post("/v1/messages")
        .body(Body::from(body))
        .unwrap();
    let app = tokenfuse_gateway::app(state(gate));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the LLM proxy must be unaffected by the observability gate being closed"
    );
}
