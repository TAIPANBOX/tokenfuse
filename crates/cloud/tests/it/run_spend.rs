//! `GET /v1/run-spend` (invariant 75): the one read a remote site's gateway
//! needs to seed its run ledger at startup, answered only to a site-bound
//! key and only about that site's own runs, three fields per run.
//!
//! Measured 2026-10-05 (forge -> GCP hub migration): a site gateway reached
//! the hub through its public entry, which answers `/v1/runs` 404 by design
//! because `/v1/runs` lists the whole org. The seed failed, and a run with
//! 2566 uUSD at the hub and a 4500 budget admitted a ~2550 call it should
//! have refused. These tests hold the read that replaces it for a site.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use tokenfuse_cloud::{app, AppState, CallRecord, Principal, Store, RUNS_WINDOW_HEADER};

fn key(org: &str, role: &str, site: Option<&str>) -> Principal {
    Principal {
        org: org.into(),
        role: role.into(),
        site: site.map(str::to_string),
    }
}

fn test_state() -> (AppState, Arc<Store>) {
    let store = Arc::new(Store::new());
    let mut keys = HashMap::new();
    keys.insert("flint".into(), key("acme", "ingest", Some("flint")));
    keys.insert("brume".into(), key("acme", "ingest", Some("brume")));
    keys.insert("admin".into(), key("acme", "admin", None));
    keys.insert("viewer".into(), key("acme", "viewer", None));
    keys.insert("unbound-ingest".into(), key("acme", "ingest", None));
    keys.insert("admin-at-flint".into(), key("acme", "admin", Some("flint")));
    keys.insert("beta-flint".into(), key("beta", "ingest", Some("flint")));
    (
        AppState::new(Arc::clone(&store), Arc::new(keys), 0.8),
        store,
    )
}

fn rec(run: &str, cost: i64, ts: i64) -> CallRecord {
    CallRecord {
        run_id: run.into(),
        agent_id: "agent://acme.example/secret-agent".into(),
        decision: "allow".into(),
        cost_microusd: cost,
        ts_millis: ts,
        step: 1,
        ..Default::default()
    }
}

async fn get(
    state: &AppState,
    path: &str,
    bearer: Option<&str>,
) -> (StatusCode, axum::http::HeaderMap, serde_json::Value) {
    let mut req = Request::get(path);
    if let Some(k) = bearer {
        req = req.header("authorization", format!("Bearer {k}"));
    }
    let resp = app(state.clone())
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, headers, v)
}

fn by_run(v: &serde_json::Value) -> Vec<(String, i64, bool)> {
    let mut out: Vec<(String, i64, bool)> = v
        .as_array()
        .expect("an array")
        .iter()
        .map(|r| {
            (
                r["run_id"].as_str().unwrap().to_string(),
                r["spent_microusd"].as_i64().unwrap(),
                r["killed"].as_bool().unwrap(),
            )
        })
        .collect();
    out.sort();
    out
}

/// The 2026-10-05 numbers: the run the site pushed is answered with its
/// whole Cloud-known spend, and another site's run is not answered at all.
#[tokio::test]
async fn a_site_key_reads_the_spend_of_its_own_sites_runs_only() {
    let (state, store) = test_state();
    store.ingest_from("acme", Some("flint"), &[rec("mig-flint", 1288, 10)]);
    store.ingest_from("acme", Some("flint"), &[rec("mig-flint", 1278, 20)]);
    store.ingest_from("acme", Some("brume"), &[rec("mig-brume", 1278, 30)]);
    store.ingest("acme", &[rec("in-cluster", 500, 40)]);

    let (status, _, v) = get(&state, "/v1/run-spend", Some("flint")).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(by_run(&v), vec![("mig-flint".to_string(), 2566, false)]);

    let (status, _, v) = get(&state, "/v1/run-spend", Some("brume")).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(by_run(&v), vec![("mig-brume".to_string(), 1278, false)]);
}

/// Three fields and nothing else: agent ids, owners, units and the site
/// names of the rest of the fleet stay inside the hub.
#[tokio::test]
async fn a_row_carries_exactly_run_id_spend_and_killed() {
    let (state, store) = test_state();
    store.ingest_from("acme", Some("flint"), &[rec("mig-flint", 100, 10)]);
    let (_, _, v) = get(&state, "/v1/run-spend", Some("flint")).await;
    let row = v.as_array().unwrap()[0].as_object().unwrap();
    let mut fields: Vec<&str> = row.keys().map(String::as_str).collect();
    fields.sort();
    assert_eq!(fields, vec!["killed", "run_id", "spent_microusd"]);
}

/// A key bound to no site cannot be told which runs are its own, so the
/// route refuses it rather than answering for the whole org: that is the
/// widening the hub entry exists to prevent, and an admin key that leaks to
/// a site must not undo it.
#[tokio::test]
async fn a_key_bound_to_no_site_is_refused_whatever_its_role() {
    let (state, store) = test_state();
    store.ingest_from("acme", Some("flint"), &[rec("mig-flint", 100, 10)]);
    store.ingest("acme", &[rec("in-cluster", 500, 40)]);
    for k in ["admin", "viewer", "unbound-ingest"] {
        let (status, _, v) = get(&state, "/v1/run-spend", Some(k)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{k}: {v}");
        assert!(v.as_array().is_none(), "{k} got rows: {v}");
    }
}

#[tokio::test]
async fn no_key_or_an_unknown_key_is_unauthorized() {
    let (state, _) = test_state();
    let (status, _, _) = get(&state, "/v1/run-spend", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _, _) = get(&state, "/v1/run-spend", Some("nope")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// The site comes from the key, the role does not widen it: an admin key
/// bound to flint reads flint's runs, not the org's.
#[tokio::test]
async fn a_site_bound_key_of_any_role_is_scoped_to_its_site() {
    let (state, store) = test_state();
    store.ingest_from("acme", Some("flint"), &[rec("mig-flint", 100, 10)]);
    store.ingest_from("acme", Some("brume"), &[rec("mig-brume", 200, 20)]);
    let (status, _, v) = get(&state, "/v1/run-spend", Some("admin-at-flint")).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(by_run(&v), vec![("mig-flint".to_string(), 100, false)]);
}

/// Two orgs may name a site the same; the org still comes from the key.
#[tokio::test]
async fn the_same_site_name_in_another_org_reads_nothing_of_this_one() {
    let (state, store) = test_state();
    store.ingest_from("acme", Some("flint"), &[rec("mig-flint", 100, 10)]);
    let (status, _, v) = get(&state, "/v1/run-spend", Some("beta-flint")).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v.as_array().unwrap().is_empty(), "{v}");
}

#[tokio::test]
async fn a_killed_run_says_so() {
    let (state, store) = test_state();
    store.ingest_from("acme", Some("flint"), &[rec("mig-flint", 100, 10)]);
    store.kill("acme", "mig-flint");
    let (_, _, v) = get(&state, "/v1/run-spend", Some("flint")).await;
    assert_eq!(by_run(&v), vec![("mig-flint".to_string(), 100, true)]);
}

/// The same window `/v1/runs` applies (runs last seen at or after the
/// cutoff, each with its lifetime spend), named in the same header.
#[tokio::test]
async fn since_millis_selects_runs_and_the_window_header_names_it() {
    let (state, store) = test_state();
    store.ingest_from("acme", Some("flint"), &[rec("old", 100, 10)]);
    store.ingest_from("acme", Some("flint"), &[rec("new", 200, 1_000)]);
    let (status, h, v) = get(&state, "/v1/run-spend?since_millis=500", Some("flint")).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(by_run(&v), vec![("new".to_string(), 200, false)]);
    assert_eq!(h[RUNS_WINDOW_HEADER], "500");

    let (_, h, v) = get(&state, "/v1/run-spend", Some("flint")).await;
    assert_eq!(by_run(&v).len(), 2);
    assert_eq!(h[RUNS_WINDOW_HEADER], "none");
}

/// Named limit: a run's site is "last non-empty wins" (invariant 65), so a
/// run another site pushed after this one is that site's now, and this site
/// is not told its spend.
#[tokio::test]
async fn a_run_last_pushed_by_another_site_belongs_to_that_site() {
    let (state, store) = test_state();
    store.ingest_from("acme", Some("flint"), &[rec("shared", 100, 10)]);
    store.ingest_from("acme", Some("brume"), &[rec("shared", 50, 20)]);
    let (_, _, v) = get(&state, "/v1/run-spend", Some("flint")).await;
    assert!(v.as_array().unwrap().is_empty(), "{v}");
    let (_, _, v) = get(&state, "/v1/run-spend", Some("brume")).await;
    assert_eq!(by_run(&v), vec![("shared".to_string(), 150, false)]);
}
