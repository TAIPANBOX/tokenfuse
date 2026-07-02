//! `tokenfuse mcp-scan` — scan an MCP server's `tools/list` for poisoning and
//! for drift against a pinned lockfile (rug-pull detection).

use std::fs;
use tokenfuse_core::mcp::{diff, parse_tools, scan_injection, Drift, Lock};

/// Scan `tools_path` (a saved `tools/list` JSON). Optionally diff against
/// `lock_path`, and optionally (over)write the lock. Returns process-style exit
/// code semantics via `Ok(problems_found)`.
pub fn run(tools_path: &str, lock_path: Option<&str>, write_lock: bool) -> Result<(), String> {
    let raw = fs::read_to_string(tools_path).map_err(|e| format!("read {tools_path}: {e}"))?;
    let value: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("parse {tools_path}: {e}"))?;
    let tools = parse_tools(&value);
    println!("MCP scan — {} tool(s) in {tools_path}", tools.len());

    let findings = scan_injection(&tools);
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
            let lock = Lock::from_tools(&tools);
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
            let drifts = diff(&tools, &lock);
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
