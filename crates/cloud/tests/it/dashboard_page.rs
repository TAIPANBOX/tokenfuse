//! The page the control plane serves at `GET /` (CLAUDE.md invariant 102).
//!
//! A run id and a model name are chosen by whoever calls a gateway and the
//! Cloud stores them as sent, so the page has to put them into the document as
//! text. These read the page through the route that serves it, so returning to
//! a template string assigned as markup goes red in `cargo test` as well as in
//! `scripts/no-html-from-data.sh`. No JavaScript runs here: what they hold is
//! the shape of the code, and the gate's teeth cases hold the gate.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use tokenfuse_cloud::{app, AppState, Store};

async fn served_page() -> String {
    let state = AppState::new(Arc::new(Store::new()), Arc::new(HashMap::new()), 0.8);
    let resp = app(state)
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .expect("the page has a content type")
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        content_type.starts_with("text/html"),
        "GET / answered {content_type}"
    );
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn the_served_page_never_parses_a_run_field_as_markup() {
    let page = served_page().await;
    // Whitespace removed, so `innerHTML =` and `innerHTML=` read the same.
    let code: String = page.split_whitespace().collect();
    for sink in [
        "innerHTML=",
        "innerHTML+=",
        "outerHTML=",
        "outerHTML+=",
        "insertAdjacentHTML(",
        "document.write(",
        "document.writeln(",
        "createContextualFragment(",
        "setHTMLUnsafe(",
        "srcdoc=",
    ] {
        assert!(
            !code.contains(sink),
            "the page served at / uses `{sink}`: a run id or a model name chosen by a \
             caller would be parsed as markup in the operator's browser"
        );
    }
    for as_text in ["run.textContent = r.run_id;", "model.textContent = r.model"] {
        assert!(
            page.contains(as_text),
            "the page served at / no longer sets `{as_text}`: the run id and the model \
             reach the table as text, or this test and scripts/no-html-from-data.sh \
             are updated together"
        );
    }
}

#[tokio::test]
async fn the_served_page_names_no_removed_key_and_calls_its_savings_all_time() {
    let page = served_page().await;
    assert!(
        !page.contains("devkey"),
        "the page offers `devkey` as an example key; that fallback was removed in v1.9.0"
    );
    // `SavingsAcc` has no month boundary: `/v1/savings` totals everything the
    // plane has ingested, as the Next.js dashboard already says.
    assert!(
        !page.contains("this month"),
        "the page labels the all-time savings total as this month's"
    );
    assert!(
        page.contains("\"all time · blocked \""),
        "the savings breakdown no longer says the figure is all time"
    );
}
