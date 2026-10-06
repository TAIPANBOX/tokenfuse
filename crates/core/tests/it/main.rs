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
//! installs a process-wide `tracing` subscriber. A module that needs any of
//! those has to serialise on something in this binary or stay a binary of its
//! own, named in `scripts/one-test-binary-per-crate.sh`'s allow-list.

mod codex_money_review;
mod fable_missed;
