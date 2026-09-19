#!/usr/bin/env bash
# @codex 2026-09-19: execute the real HTTP regression suite; no silent empty suite.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
suite=crates/gateway/tests/send_failure_retention.rs
if [[ ! -s "$suite" ]]; then
    echo "measured nothing: D9 HTTP regression suite missing" >&2
    exit 1
fi
output=$(cargo test -p tokenfuse-gateway --test send_failure_retention -- --nocapture 2>&1) || { printf '%s\n' "$output"; exit 1; }
printf '%s\n' "$output"
grep -Eq 'test result: ok\. [1-9][0-9]* passed; 0 failed' <<<"$output" || { echo "measured nothing: no passing D9 tests" >&2; exit 1; }
