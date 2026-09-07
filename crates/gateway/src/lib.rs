//! TokenFuse gateway library: the budget-enforcing proxy assembled as an axum
//! `Router`. The binary (`main.rs`) wires real config around `app()`; tests
//! drive `app()` directly.

pub mod adminkeys;
pub mod agentids;
pub mod backtestcli;
pub mod chainproof;
pub mod clientkeys;
pub mod cloudsink;
pub mod compliancecli;
pub mod constants;
pub mod declassify;
pub mod defaults;
pub mod embedder;
pub mod estimate;
pub mod events;
pub mod firewall;
pub mod firewallcli;
pub mod focusexport;
pub mod identitymap;
pub mod keysreport;
pub mod keystats;
pub mod ledger_backend;
pub mod mcpbroker;
pub mod mcpcli;
pub mod mcpclient;
pub mod mcpdoor;
pub mod mcpexposure_probe;
pub mod obs;
pub mod otel;
pub mod outcomescli;
pub mod policyplane;
pub mod pricebook;
pub mod provider;
pub mod proxy;
#[cfg(feature = "cluster")]
pub mod raft_ledger;
pub mod revocations;
pub mod router;
pub mod savingscli;
pub mod settle;
pub mod sink;
pub mod sqlq;
pub mod state;
pub mod toolcheck;
pub mod tui;
pub mod unitledger;
pub mod wardryx;
pub mod wasmpolicy;
pub mod wire;

use axum::extract::DefaultBodyLimit;
use axum::middleware::from_fn_with_state;
use axum::routing::{get, post};
use axum::Router;
use state::AppState;

/// Default maximum request-body size (bytes). Bounds memory a single client can
/// force the gateway to buffer. Generous enough for large prompts; override with
/// `TOKENFUSE_MAX_BODY_BYTES`.
const DEFAULT_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Build the gateway router from shared state.
pub fn app(state: AppState) -> Router {
    let max_body = std::env::var("TOKENFUSE_MAX_BODY_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_BODY_BYTES);
    // The five observability/kill routes (CLAUDE.md invariant, see
    // `adminkeys`): everything an operator needs to list every run's budget
    // and spend, list key ids, enumerate agent identities, or kill a run.
    // Gated by `state.admin_gate`, never by anything the caller can choose.
    // `route_layer` (not `layer`) so the gate applies to exactly these five
    // routes and never to `/healthz`, `/v1/messages`, or `/v1/fuse/*`.
    let admin = Router::new()
        .route("/v1/runs", get(obs::list_runs))
        .route("/v1/runs/{id}/kill", post(obs::kill_run))
        .route("/v1/keys", get(keysreport::list_keys))
        .route("/v1/policy-plane", get(policyplane::policy_plane))
        .route("/v1/agent-ids", get(agentids::agent_ids))
        .route_layer(from_fn_with_state(state.clone(), adminkeys::admin_gate));
    Router::new()
        .route("/healthz", get(proxy::healthz))
        .route("/v1/messages", post(proxy::messages))
        .merge(admin)
        // docs/07 B.7 level 2: an executor asks BEFORE it runs a tool.
        .route("/v1/fuse/check-tool-call", post(toolcheck::check_tool_call))
        // docs/07 B.4 gate 1: a human reviewed it, so the label comes off.
        .route("/v1/fuse/declassify", post(declassify::declassify))
        .layer(DefaultBodyLimit::max(max_body))
        .with_state(state)
}
