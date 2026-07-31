#!/usr/bin/env bash
# Enforces invariant 1 of CLAUDE.md: tokenfuse-core stays dependency-minimal.
#
# Core is money, pricing, ledger and policy. It has to stay provable and
# portable, which means nothing web-shaped, nothing utoipa-shaped and nothing
# p256-shaped leaks into it. Those belong in crates/gateway or crates/cloud,
# which sit on the I/O boundary.
#
# The allowed list below is the same one CLAUDE.md states in prose. Keeping both
# is a deliberate exception to the one-copy rule, because the prose has to
# explain why and the script has to enforce what: if you change one, change the
# other in the same commit.
#
# Reads the manifest with `cargo metadata` rather than parsing TOML, so
# `thiserror.workspace = true` resolves the same way cargo sees it.
#
# This file is the ONE copy of this check. The local hook and CI both call it.

set -euo pipefail

cd "$(dirname "$0")/.."

python3 - <<'PY'
import json
import subprocess
import sys

ALLOWED = {"thiserror", "serde", "serde_json", "regex", "sha2"}

meta = json.loads(
    subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
)

pkg = next((p for p in meta["packages"] if p["name"] == "tokenfuse-core"), None)
if pkg is None:
    print("FAIL: package 'tokenfuse-core' not found in cargo metadata")
    sys.exit(1)

# Normal dependencies only. dev-dependencies are test-time and do not ship in
# the crate a consumer builds, so they are not what this invariant is about.
actual = {d["name"] for d in pkg["dependencies"] if d["kind"] is None}

extra = sorted(actual - ALLOWED)
missing = sorted(ALLOWED - actual)

fail = False

for name in extra:
    print(f"FAIL: tokenfuse-core depends on '{name}', which is not on the allowed list")
    fail = True

for name in missing:
    print(f"FAIL: allowed dependency '{name}' is gone from tokenfuse-core")
    print("      Either it was removed on purpose, in which case update this")
    print("      script AND CLAUDE.md invariant 1 in the same commit, or it was")
    print("      removed by accident.")
    fail = True

if fail:
    print()
    print("Core is money, pricing, ledger and policy. It stays provable and")
    print("portable. Put the new dependency in crates/gateway or crates/cloud,")
    print("which already sit on the I/O boundary. See CLAUDE.md invariant 1.")
    sys.exit(1)

print(f"OK: tokenfuse-core depends on exactly {len(ALLOWED)} allowed crates.")
PY
