//! `tokenfuse mcp-scan` — scan an MCP server's `tools/list` for poisoning and
//! for drift against a pinned lockfile (rug-pull detection).
//!
//! Two ways to get the `tools/list` payload: a saved JSON file ([`run`]) or a
//! live Streamable HTTP fetch against a running MCP server ([`run_live`]).
//! Both share the same scan/diff/print logic once the JSON value is in hand.

use std::fs;
use tokenfuse_core::mcp::{diff, parse_tools, scan_injection, Drift, Lock};

use crate::mcpclient::{fetch_tools_list, McpClientConfig};

/// Scan `tools_path` (a saved `tools/list` JSON). Optionally diff against
/// `lock_path`, and optionally (over)write the lock. Findings are printed;
/// they are not yet reflected in the exit code (that lands with `--fail-on`).
pub fn run(tools_path: &str, lock_path: Option<&str>, write_lock: bool) -> Result<(), String> {
    let raw = fs::read_to_string(tools_path).map_err(|e| format!("read {tools_path}: {e}"))?;
    let value: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("parse {tools_path}: {e}"))?;
    let tools = parse_tools(&value);
    println!("MCP scan — {} tool(s) in {tools_path}", tools.len());
    scan_and_report(&tools, lock_path, write_lock)
}

/// Scan a live MCP server at `url` over Streamable HTTP. Twin of [`run`]: same
/// injection scan / lock-diff / print logic, fed by a live `tools/list` fetch
/// instead of a file on disk.
pub async fn run_live(url: &str, lock_path: Option<&str>, write_lock: bool) -> Result<(), String> {
    let cfg = McpClientConfig::new(url);
    let value = fetch_tools_list(&cfg).await.map_err(|e| e.to_string())?;
    let tools = parse_tools(&value);
    println!("MCP scan — {} tool(s) live from {url}", tools.len());
    scan_and_report(&tools, lock_path, write_lock)
}

/// Shared post-parse logic for [`run`] and [`run_live`]: injection scan, plus
/// optional lock write/diff.
fn scan_and_report(
    tools: &[tokenfuse_core::mcp::McpTool],
    lock_path: Option<&str>,
    write_lock: bool,
) -> Result<(), String> {
    let findings = scan_injection(tools);
    if findings.is_empty() {
        println!("  injection scan: clean");
    } else {
        println!("  injection scan: {} issue(s)", findings.len());
        for f in &findings {
            println!("    ⚠ {}: {}", f.tool, f.issue);
        }
    }

    if let Some(lock_path) = lock_path {
        if write_lock {
            let lock = Lock::from_tools(tools);
            let json = serde_json::to_string_pretty(&lock).map_err(|e| e.to_string())?;
            fs::write(lock_path, json).map_err(|e| format!("write {lock_path}: {e}"))?;
            println!(
                "  lock: wrote {} tool fingerprints to {lock_path}",
                tools.len()
            );
        } else {
            let lock_raw =
                fs::read_to_string(lock_path).map_err(|e| format!("read {lock_path}: {e}"))?;
            let lock: Lock =
                serde_json::from_str(&lock_raw).map_err(|e| format!("parse {lock_path}: {e}"))?;
            let drifts = diff(tools, &lock);
            if drifts.is_empty() {
                println!("  lock: no drift — matches {lock_path}");
            } else {
                println!("  lock: {} change(s) vs {lock_path}", drifts.len());
                for d in &drifts {
                    match d {
                        Drift::Changed(n) => {
                            println!("    ⛔ RUG PULL: tool '{n}' description/schema changed")
                        }
                        Drift::Added(n) => println!("    + new tool '{n}' (not in lock)"),
                        Drift::Removed(n) => println!("    - tool '{n}' removed"),
                    }
                }
            }
        }
    }
    Ok(())
}
