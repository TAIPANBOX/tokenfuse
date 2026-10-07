//! The one integration-test binary of this crate (CLAUDE.md invariant 78).
//!
//! Every file under `tests/` used to be its own binary, each linking the whole
//! dependency graph with its own copy of the debug info, so one `cargo test`
//! after a change relinked all of them. They are modules of this binary now
//! and share one link. Run one of them with `cargo test --test it <module>::`.
//!
//! Sharing one process is the price, and it was audited when the files were
//! merged: no module changes the environment or the working directory, no two
//! modules bind the same fixed port or write the same scratch path, and none
//! installs a process-wide `tracing` subscriber (`shadow_tool_pruning` did, and
//! now scopes its capture to its own requests). A module that needs any of
//! those has to serialise on something in this binary or stay a binary of its
//! own, named in `scripts/one-test-binary-per-crate.sh`'s allow-list.

mod common;

mod admin_gate;
mod cache_default_startup;
mod codex_money_review;
mod delegation_htu_matches_wire;
mod image_user_group;
mod keys_endpoint;
mod manifest;
mod mcp_broker;
mod mcp_client_redirect;
mod mcp_door;
mod mcp_scan_body_cap;
mod mcp_scan_exit_code;
mod mcp_scan_exposure;
mod mcp_scan_live;
mod mcp_scan_report;
mod mcp_xaa;
mod no_usage_stream_settles_on_the_estimate;
mod policy_plane;
mod price_book_startup;
mod require_run_id;
mod router;
mod run_budget_ceiling_startup;
mod send_failure_retention;
mod shadow_tool_pruning;
mod stub_wire_mismatch;
mod the_estimate_never_goes_negative;
mod version_and_help;
mod wardryx;
mod wire_door;
mod xaa_startup;
