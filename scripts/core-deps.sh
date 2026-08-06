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
#
# WHAT A BROKEN READ LOOKS LIKE HERE, and why it needed its own path
#
# The other gates in `scripts/` can pass while measuring nothing, so each says
# so out loud. This one cannot pass: an empty read makes every allowed crate
# look missing, and it exits 1. That is not the same as being safe. It fails
# with five lines saying serde, sha2 and the rest were removed from a manifest
# that still lists them, plus advice about putting new dependencies in the
# gateway, and sends the reader to a file where nothing is wrong. A check that
# misdiagnoses is a check that gets relaxed by whoever is trying to unblock CI.
#
# Verified 2026-08-06 by changing the `kind` filter to something cargo does not
# emit, which is how a metadata-format change would arrive: it printed exactly
# those five lines. It now says the read failed instead.

set -euo pipefail

cd "$(dirname "$0")/.."

python3 - <<'PY'
import json
import subprocess
import sys

ALLOWED = {"thiserror", "serde", "serde_json", "regex", "sha2"}

def measured_nothing(what):
    """Exit on a read that established nothing, distinctly from a real finding.

    Both exit 1. The difference is where they send the reader: a finding is
    about the manifest, this is about this script."""
    print("FAIL: this check measured nothing, so invariant 1 is UNVERIFIED here.")
    print(f"      {what}")
    print("      Fix this script (or the environment) before trusting a green run.")
    sys.exit(1)


try:
    proc = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        capture_output=True,
        text=True,
        check=True,
    )
except FileNotFoundError:
    measured_nothing("`cargo` is not on PATH, so the manifest was never read.")
except subprocess.CalledProcessError as e:
    measured_nothing(
        "`cargo metadata` failed, so the manifest was never read: "
        + (e.stderr or "").strip().splitlines()[-1:][0]
        if (e.stderr or "").strip()
        else "`cargo metadata` failed, so the manifest was never read."
    )

meta = json.loads(proc.stdout)

pkg = next((p for p in meta["packages"] if p["name"] == "tokenfuse-core"), None)
if pkg is None:
    print("FAIL: package 'tokenfuse-core' not found in cargo metadata")
    sys.exit(1)

# Normal dependencies only. dev-dependencies are test-time and do not ship in
# the crate a consumer builds, so they are not what this invariant is about.
declared = pkg["dependencies"]
if not declared:
    measured_nothing(
        "cargo metadata reports no dependencies at all for tokenfuse-core, which "
        "is not what its manifest says."
    )

actual = {d["name"] for d in declared if d["kind"] is None}
if not actual:
    measured_nothing(
        f"tokenfuse-core declares {len(declared)} dependencies and none of them "
        "came back with kind=None, which is how cargo reports a normal "
        "(non-dev, non-build) dependency. That is this filter, not the manifest: "
        "the metadata format has most likely changed."
    )

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
