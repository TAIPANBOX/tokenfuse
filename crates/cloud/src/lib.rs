//! TokenFuse Cloud control plane: aggregates the call telemetry many gateways
//! push in into a single per-organization fleet view. The Rust successor to the
//! original Go control plane (see docs/02-architecture.md, ADR-7).

#[cfg(feature = "apns")]
pub mod apns;
pub mod audit_sign;
// Delegation verification moved to its own crate so the GATEWAY can use it:
// the gateway must not depend on this one, which would put the control-plane
// API surface inside the data-plane binary. Same reasoning, and the same
// re-export, as `oidc::algorithms_for_key` after `tokenfuse-dpop` was cut.
pub use tokenfuse_delegation as delegation;
pub mod devices;
pub mod http;
pub mod keys;
pub mod oidc;
pub mod push;
pub mod replay;
pub mod store;

pub use audit_sign::{signing_key_from_env as audit_signing_key_from_env, AuditManifest};
pub use http::{app, openapi_spec, AppState, RUNS_WINDOW_HEADER};
pub use keys::{parse_keys, Principal};
pub use oidc::{verify_id_token, OidcConfig};
pub use push::{NullSender, PushPipeline, PushSender};
pub use replay::{read_run_events, ReplayEvent};
pub use store::{CallRecord, FindingInput, Incident, IncidentConfig, Store};
