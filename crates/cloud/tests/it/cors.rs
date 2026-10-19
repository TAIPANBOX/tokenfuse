//! Which browser origins the control plane answers (CLAUDE.md invariant 131).
//!
//! Before this invariant every response carried `Access-Control-Allow-Origin: *`,
//! so any web page a signed-in operator visited could call the control plane
//! from the browser. These tests drive the real router with an `Origin` header
//! and read what comes back. The unset default is loopback only, which keeps the
//! local dashboard working; a configured list replaces it.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::response::Response;
use tower::ServiceExt;

use tokenfuse_cloud::cors::CorsPolicy;
use tokenfuse_cloud::keys::digest;
use tokenfuse_cloud::{app, AppState, Principal, Store};

fn state() -> AppState {
    let mut keys = HashMap::new();
    keys.insert(
        digest("adm"),
        Principal {
            org: "acme".into(),
            role: "admin".into(),
            site: None,
        },
    );
    AppState::new(Arc::new(Store::new()), Arc::new(keys), 0.8)
}

/// One request from `origin` to `path`. An OPTIONS request is a preflight, so
/// it carries the method the browser would ask about.
async fn from_origin(state: &AppState, method: Method, path: &str, origin: &str) -> Response {
    let preflight = method == Method::OPTIONS;
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header(header::ORIGIN, origin);
    if preflight {
        req = req.header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET");
    }
    app(state.clone())
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

fn allow_origin(resp: &Response) -> Option<String> {
    resp.headers()
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .map(|v| v.to_str().unwrap().to_string())
}

fn vary_names_origin(resp: &Response) -> bool {
    resp.headers()
        .get_all(header::VARY)
        .iter()
        .any(|v| v.to_str().unwrap().to_ascii_lowercase().contains("origin"))
}

#[tokio::test]
async fn an_origin_nobody_named_gets_no_allow_origin_header() {
    let resp = from_origin(&state(), Method::GET, "/healthz", "https://evil.example").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        allow_origin(&resp),
        None,
        "a page on evil.example must not be told it may read this response"
    );
}

#[tokio::test]
async fn a_refused_origin_is_marked_vary_too() {
    // A cache must not hand a refusal to a dashboard that was allowed, or an
    // allowed answer to a stranger, so the refusal varies on Origin as well.
    let resp = from_origin(&state(), Method::GET, "/healthz", "https://evil.example").await;
    assert!(
        vary_names_origin(&resp),
        "a refusal must vary on Origin too"
    );
}

#[tokio::test]
async fn a_loopback_origin_is_reflected_exactly_and_marked_vary() {
    let resp = from_origin(&state(), Method::GET, "/healthz", "http://localhost:3000").await;
    assert_eq!(
        allow_origin(&resp).as_deref(),
        Some("http://localhost:3000")
    );
    assert!(vary_names_origin(&resp), "a cache must key on Origin");
}

#[tokio::test]
async fn every_loopback_host_and_any_port_is_allowed_by_default() {
    for origin in [
        "http://127.0.0.1:5173",
        "http://localhost:8080",
        "http://[::1]:9000",
    ] {
        let resp = from_origin(&state(), Method::GET, "/healthz", origin).await;
        assert_eq!(
            allow_origin(&resp).as_deref(),
            Some(origin),
            "the local dashboard at {origin} must keep working"
        );
    }
}

#[tokio::test]
async fn a_preflight_from_an_origin_nobody_named_is_204_without_allow_origin() {
    let resp = from_origin(
        &state(),
        Method::OPTIONS,
        "/v1/runs",
        "https://evil.example",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(allow_origin(&resp), None);
}

#[tokio::test]
async fn a_preflight_from_a_loopback_origin_is_allowed() {
    let resp = from_origin(
        &state(),
        Method::OPTIONS,
        "/v1/runs",
        "http://localhost:3000",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        allow_origin(&resp).as_deref(),
        Some("http://localhost:3000")
    );
}

#[tokio::test]
async fn a_configured_list_replaces_the_loopback_default() {
    let policy = CorsPolicy::from_spec(Some("https://dash.example.com")).unwrap();
    let st = state().with_cors(policy);

    let named = from_origin(&st, Method::GET, "/healthz", "https://dash.example.com").await;
    assert_eq!(
        allow_origin(&named).as_deref(),
        Some("https://dash.example.com"),
        "an origin on the configured list is answered"
    );

    let loopback = from_origin(&st, Method::GET, "/healthz", "http://localhost:3000").await;
    assert_eq!(
        allow_origin(&loopback),
        None,
        "once a list is set, loopback is no longer implicitly allowed"
    );
}

#[tokio::test]
async fn a_request_with_no_origin_gets_no_cors_header() {
    // A server-to-server caller (a gateway, curl) sends no Origin and needs no
    // CORS answer; the header is for browsers only.
    let resp = app(state())
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(allow_origin(&resp), None);
}
