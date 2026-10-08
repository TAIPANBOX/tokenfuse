//! End-to-end test of the ingest path: a JSON batch shaped exactly like a
//! gateway `CloudSink` POST (`{"records":[…]}`) flows through `/v1/ingest`,
//! authorizes by bearer key, and lands in the store's per-org aggregates.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use tokenfuse_cloud::{app, AppState, Principal, Store};

fn state_with(store: Arc<Store>) -> AppState {
    let mut keys = HashMap::new();
    keys.insert(
        "k".to_string(),
        Principal {
            org: "acme".into(),
            role: "admin".into(),
            site: None,
        },
    );
    // A read-only credential for the SAME org. Every other test here uses the
    // admin key; this one exists so the ingest route can be pinned against the
    // role that must not reach it.
    keys.insert(
        "viewerkey".to_string(),
        Principal {
            org: "acme".into(),
            role: "viewer".into(),
            site: None,
        },
    );
    // A site-scoped ingest key (invariant 65): the least privilege a remote
    // gateway needs. Bound to "site-a", so a push made with it is attributed
    // there without the body naming anything.
    keys.insert(
        "ingestkey".to_string(),
        Principal {
            org: "acme".into(),
            role: "ingest".into(),
            site: Some("site-a".into()),
        },
    );
    AppState::new(store, Arc::new(keys), 0.8)
}

#[tokio::test]
async fn ingest_authorized_aggregates_into_store() {
    let store = Arc::new(Store::new());
    let router = app(state_with(Arc::clone(&store)));

    // Exactly the shape crates/gateway/src/cloudsink.rs POSTs (`unit` is the
    // docs/20-identity-map.md section 4 addition - additive, so it rides
    // along on the same batch as every other field).
    let payload = r#"{"records":[
        {"ts_millis":100,"run_id":"r1","model":"claude","decision":"allow","input_tokens":10,"output_tokens":5,"cost_microusd":1000,"step":1,"unit":"treasury"},
        {"ts_millis":200,"run_id":"r1","model":"claude","decision":"cache_hit","input_tokens":0,"output_tokens":0,"cost_microusd":0,"step":2,"unit":"treasury"}
    ]}"#;

    let resp = router
        .oneshot(
            Request::post("/v1/ingest")
                .header("authorization", "Bearer k")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["accepted"], 2);

    let runs = store.runs("acme");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].spent_microusd, 1000);
    assert_eq!(runs[0].calls, 2);
    assert_eq!(runs[0].cache_hits, 1);
    assert_eq!(runs[0].steps, 2);
    assert_eq!(runs[0].unit, "treasury");
}

/// A gateway that predates docs/20-identity-map.md simply omits `unit` -
/// additive means the batch still ingests, and the run's `unit` stays empty
/// (folded into the "unassigned" bucket by `Store::units`, never a hard error).
#[tokio::test]
async fn ingest_without_unit_is_additive() {
    let store = Arc::new(Store::new());
    let router = app(state_with(Arc::clone(&store)));

    let payload = r#"{"records":[
        {"ts_millis":100,"run_id":"r1","model":"claude","decision":"allow","cost_microusd":1000,"step":1}
    ]}"#;

    let resp = router
        .oneshot(
            Request::post("/v1/ingest")
                .header("authorization", "Bearer k")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let runs = store.runs("acme");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].unit, "");
    let units = store.units("acme");
    assert_eq!(units.len(), 1);
    assert_eq!(units[0].unit, "unassigned");
}

/// I1 (docs/21-tool-runs.md): `tool_calls` on the wire (exactly what a
/// NEW gateway's `CloudSink` would POST) rolls up into the run and the
/// org-wide summary total.
#[tokio::test]
async fn ingest_with_tool_calls_rolls_up_into_runs_and_summary() {
    let store = Arc::new(Store::new());
    let router = app(state_with(Arc::clone(&store)));

    let payload = r#"{"records":[
        {"ts_millis":100,"run_id":"r1","model":"claude","decision":"allow","cost_microusd":1000,"step":1,"tool_calls":2},
        {"ts_millis":200,"run_id":"r1","model":"claude","decision":"allow","cost_microusd":1000,"step":2,"tool_calls":0}
    ]}"#;

    let resp = router
        .oneshot(
            Request::post("/v1/ingest")
                .header("authorization", "Bearer k")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let runs = store.runs("acme");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].tool_calls, 2);
    let summary = store.summary("acme");
    assert_eq!(summary.tool_calls, 2);
}

/// A gateway that predates I1 simply omits `tool_calls` - additive means the
/// batch still ingests, and the run's `tool_calls` stays at 0 (an unknown
/// observation contributes nothing, never a hard error).
#[tokio::test]
async fn ingest_without_tool_calls_is_additive() {
    let store = Arc::new(Store::new());
    let router = app(state_with(Arc::clone(&store)));

    let payload = r#"{"records":[
        {"ts_millis":100,"run_id":"r1","model":"claude","decision":"allow","cost_microusd":1000,"step":1}
    ]}"#;

    let resp = router
        .oneshot(
            Request::post("/v1/ingest")
                .header("authorization", "Bearer k")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let runs = store.runs("acme");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].tool_calls, 0);
}

#[tokio::test]
async fn ingest_without_a_key_is_unauthorized() {
    let router = app(state_with(Arc::new(Store::new())));
    let resp = router
        .oneshot(
            Request::post("/v1/ingest")
                .body(Body::from(r#"{"records":[]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// A read-only credential may not write telemetry.
///
/// Ingest is a WRITE, and it was authorized as a read: `org_for` resolves any
/// principal that maps to an org, so a viewer key, a paired device token of
/// any role, and a viewer-scoped OIDC token all reached it. The role exists to
/// say what a credential may change, and everything this route accepts becomes
/// state the org is then graded on.
#[tokio::test]
async fn a_viewer_key_cannot_ingest() {
    let store = Arc::new(Store::new());
    let router = app(state_with(Arc::clone(&store)));

    let payload = r#"{"records":[
        {"ts_millis":100,"run_id":"r1","model":"claude","decision":"allow","cost_microusd":1000,"step":1}
    ]}"#;

    let resp = router
        .oneshot(
            Request::post("/v1/ingest")
                .header("authorization", "Bearer viewerkey")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a read-only key must be refused at the ingest route, not merely resolved to an org"
    );
    assert!(
        store.runs("acme").is_empty(),
        "nothing the refused caller sent may reach the store"
    );
}

/// The reason the role matters, end to end.
///
/// Ingested records are not inert evidence: three of them, with a decision
/// this plane recognizes and a `run_id` the caller picked, raise a High
/// `budget_exhausted` incident (`Store::ingest_at`, `budget_blocks` = 3 by
/// default). That incident is exported as a Critical agent-event into the
/// shared NDJSON log and mailed to a human by heraldyx, and the same records
/// feed the `decision_counts` that `/v1/compliance` grades an org's controls
/// from. So a read-only credential could wake somebody at three in the morning
/// about a budget that was never touched, and manufacture regulator-facing
/// evidence that a control fired.
///
/// The admin arm is not decoration: it proves the payload really does trip the
/// detector, so the viewer arm is refused authorization rather than merely
/// failing to reach a threshold.
#[tokio::test]
async fn a_viewer_cannot_manufacture_a_budget_exhausted_incident() {
    const BLOCKS: &str = r#"{"records":[
        {"run_id":"forged","model":"claude","decision":"budget_exceeded","cost_microusd":0,"step":1,"agent_id":"agent://bank.example/treasury/recon"},
        {"run_id":"forged","model":"claude","decision":"budget_exceeded","cost_microusd":0,"step":2,"agent_id":"agent://bank.example/treasury/recon"},
        {"run_id":"forged","model":"claude","decision":"budget_exceeded","cost_microusd":0,"step":3,"agent_id":"agent://bank.example/treasury/recon"}
    ]}"#;

    let store = Arc::new(Store::new());
    let state = state_with(Arc::clone(&store));

    let resp = app(state.clone())
        .oneshot(
            Request::post("/v1/ingest")
                .header("authorization", "Bearer viewerkey")
                .header("content-type", "application/json")
                .body(Body::from(BLOCKS))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(
        store.incidents("acme").is_empty(),
        "a read-only credential must not be able to raise an incident that pages a human \
         and grades a compliance control"
    );

    // The same batch from an admin credential still does everything it always
    // did: the route is gated, not broken.
    let resp = app(state)
        .oneshot(
            Request::post("/v1/ingest")
                .header("authorization", "Bearer k")
                .header("content-type", "application/json")
                .body(Body::from(BLOCKS))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let incidents = store.incidents("acme");
    assert_eq!(
        incidents.len(),
        1,
        "the payload really does trip a detector"
    );
    assert_eq!(incidents[0].kind, "budget_exhausted");
    assert_eq!(
        store.decision_counts("acme").get("budget_exceeded"),
        Some(&3),
        "and really does land in the counts /v1/compliance grades controls from"
    );
}

// -- invariant 65: the ingest role, and the site it names ------------------

/// The narrow credential this whole invariant exists for: a site-scoped
/// `ingest` key may push telemetry, and every record in the push lands
/// attributed to its bound site.
#[tokio::test]
async fn an_ingest_key_may_push_telemetry() {
    let store = Arc::new(Store::new());
    let router = app(state_with(Arc::clone(&store)));

    let payload = r#"{"records":[
        {"ts_millis":100,"run_id":"r1","model":"claude","decision":"allow","cost_microusd":1000,"step":1}
    ]}"#;

    let resp = router
        .oneshot(
            Request::post("/v1/ingest")
                .header("authorization", "Bearer ingestkey")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let gws = store.gateways("acme");
    assert_eq!(gws.len(), 1, "{gws:?}");
    assert_eq!(gws[0].site, "site-a");
    assert_eq!(gws[0].spent_microusd, 1000);
}

/// A read-only credential still cannot ingest once the `ingest` role exists
/// beside it - the new role narrows `admin`, it does not widen `viewer`.
#[tokio::test]
async fn a_viewer_key_still_cannot_ingest() {
    let store = Arc::new(Store::new());
    let router = app(state_with(Arc::clone(&store)));

    let resp = router
        .oneshot(
            Request::post("/v1/ingest")
                .header("authorization", "Bearer viewerkey")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"records":[]}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// The body cannot choose a site: `CallRecord` has no `site`/`gateway` field
/// to read one from, so an attempt to spoof one is just an extra, ignored
/// JSON key (this crate derives no `deny_unknown_fields` anywhere). Only the
/// pushing key's OWN bound site (`site-a`, invariant 65) ever appears.
#[tokio::test]
async fn a_record_cannot_choose_its_site() {
    let store = Arc::new(Store::new());
    let router = app(state_with(Arc::clone(&store)));

    let payload = r#"{"records":[
        {"ts_millis":100,"run_id":"r1","model":"claude","decision":"allow","cost_microusd":1000,"step":1,"site":"spoofed","gateway":"spoofed"}
    ]}"#;

    let resp = router
        .oneshot(
            Request::post("/v1/ingest")
                .header("authorization", "Bearer ingestkey")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let gws = store.gateways("acme");
    assert_eq!(gws.len(), 1, "{gws:?}");
    assert_eq!(
        gws[0].site, "site-a",
        "only the credential's own site appears"
    );
    assert!(
        !gws.iter().any(|g| g.site == "spoofed"),
        "a field in the body must never name a site: {gws:?}"
    );
}

#[tokio::test]
async fn healthz_is_ok() {
    let router = app(state_with(Arc::new(Store::new())));
    let resp = router
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// GET a read route with the admin key, through the same router a gateway
/// pushes to.
async fn read(state: &AppState, path: &str) -> serde_json::Value {
    let resp = app(state.clone())
        .oneshot(
            Request::get(path)
                .header("authorization", "Bearer k")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "{path}");
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// Invariant 84, end to end: a gateway's `CloudSink` puts the trace's
/// `key_id` beside every record it pushes, and a call it refused for identity
/// lands in `/v1/spend` and `/v1/agents` under that credential, never under
/// the agent id the caller claimed. The record below is the R6 refusal of
/// 2026-10-07 in the exact wire shape (every trace field, flattened, plus
/// `owner`).
#[tokio::test]
async fn an_identity_refusal_pushed_by_a_gateway_is_filed_under_its_key() {
    let store = Arc::new(Store::new());
    let state = state_with(Arc::clone(&store));
    // The real clock: `/v1/spend` prunes days past retention against it.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let claimed = "agent://taipanbox.dev/routers/flint";
    let payload = serde_json::json!({"records": [
        {"ts_millis": now, "run_id": "imp", "model": "claude-sonnet-5",
         "decision": "identity_mismatch", "input_tokens": 0, "output_tokens": 0,
         "cost_microusd": 0, "step": 1, "agent_id": claimed, "saved_microusd": 0,
         "parent_run_id": "", "on_behalf_of": "", "outcome": "",
         "key_id": "forge-imposter", "unit": "", "tool_calls": null,
         "tools_offered": null, "tools_would_prune": null,
         "pruned_schema_tokens_est": null, "owner": ""},
        {"ts_millis": now, "run_id": "imp", "model": "claude-sonnet-5",
         "decision": "identity_mismatch", "input_tokens": 0, "output_tokens": 0,
         "cost_microusd": 0, "step": 1, "agent_id": claimed, "saved_microusd": 0,
         "parent_run_id": "", "on_behalf_of": "", "outcome": "",
         "key_id": "forge-imposter", "unit": "", "tool_calls": null,
         "tools_offered": null, "tools_would_prune": null,
         "pruned_schema_tokens_est": null, "owner": ""}
    ]});
    let resp = app(state.clone())
        .oneshot(
            Request::post("/v1/ingest")
                .header("authorization", "Bearer k")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let spend = read(&state, "/v1/spend?days=1").await;
    let agents = spend["agents"].as_array().expect("agents");
    assert!(
        agents.iter().all(|a| a["agent_id"] != claimed),
        "the claimed agent made none of these calls: {spend}"
    );
    let key = agents
        .iter()
        .find(|a| a["agent_id"] == "key:forge-imposter")
        .unwrap_or_else(|| panic!("filed under the credential: {spend}"));
    assert_eq!(key["blocked"], 2);
    assert_eq!(key["calls"], 2);
    assert_eq!(key["spent_microusd"], 0);

    let fleet = read(&state, "/v1/agents").await;
    let rows = fleet.as_array().expect("an array of agents");
    assert!(
        rows.iter().all(|a| a["agent_id"] != claimed),
        "the claimed agent ran nothing: {fleet}"
    );
    assert!(
        rows.iter().any(|a| a["agent_id"] == "key:forge-imposter"),
        "the run is the credential's: {fleet}"
    );
}

/// Invariant 86, end to end: the gateway names the basis each admitted call
/// was charged at (`price_basis`, wire-only, beside `owner`), and a run whose
/// calls were refused says so. `/v1/runs` and `/v1/summary` serve both, which
/// is what the dashboard's Runs table and fleet tile read.
#[tokio::test]
async fn refusals_and_fallback_prices_reach_the_runs_and_summary_reads() {
    let store = Arc::new(Store::new());
    let state = state_with(Arc::clone(&store));
    let payload = r#"{"records":[
        {"ts_millis":100,"run_id":"r1","model":"claude-sonnet-6","decision":"allow","cost_microusd":52500,"step":1,"agent_id":"agent://acme/a","key_id":"k1","owner":"","price_basis":"fallback"},
        {"ts_millis":200,"run_id":"r1","model":"claude-sonnet-6","decision":"identity_mismatch","cost_microusd":0,"step":2,"agent_id":"agent://acme/b","key_id":"k1","owner":""}
    ]}"#;
    let resp = app(state.clone())
        .oneshot(
            Request::post("/v1/ingest")
                .header("authorization", "Bearer k")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let runs = read(&state, "/v1/runs").await;
    let r1 = runs
        .as_array()
        .and_then(|a| a.iter().find(|r| r["run_id"] == "r1"))
        .unwrap_or_else(|| panic!("r1 in /v1/runs: {runs}"));
    assert_eq!(r1["blocked"], 1, "{r1}");
    assert_eq!(r1["last_decision"], "identity_mismatch", "{r1}");
    assert_eq!(r1["fallback_calls"], 1, "{r1}");

    let sum = read(&state, "/v1/summary").await;
    assert_eq!(sum["fallback_calls"], 1, "{sum}");
    assert_eq!(
        sum["fallback_models"],
        serde_json::json!([{"model": "claude-sonnet-6", "calls": 1}]),
        "{sum}"
    );
}

/// Invariant 87, end to end: a call forwarded under
/// `TOKENFUSE_IDENTITY_STRICT=warn` arrives with its `identity_reason`, and
/// `/v1/runs` and `/v1/summary` say the identity check would have refused it.
#[tokio::test]
async fn a_warn_mode_identity_mismatch_reaches_the_runs_and_summary_reads() {
    let store = Arc::new(Store::new());
    let state = state_with(Arc::clone(&store));
    let payload = r#"{"records":[
        {"ts_millis":100,"run_id":"w1","model":"claude-sonnet-5","decision":"allow","cost_microusd":7000,"step":1,"agent_id":"agent://acme/victim","key_id":"k1","owner":"","price_basis":"known","identity_reason":"agent_id_not_allowed"}
    ]}"#;
    let resp = app(state.clone())
        .oneshot(
            Request::post("/v1/ingest")
                .header("authorization", "Bearer k")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let runs = read(&state, "/v1/runs").await;
    let w1 = runs
        .as_array()
        .and_then(|a| a.iter().find(|r| r["run_id"] == "w1"))
        .unwrap_or_else(|| panic!("w1 in /v1/runs: {runs}"));
    assert_eq!(w1["identity_warned"], 1, "{w1}");
    assert_eq!(w1["last_identity_reason"], "agent_id_not_allowed", "{w1}");
    let sum = read(&state, "/v1/summary").await;
    assert_eq!(sum["identity_warned_calls"], 1, "{sum}");
}
