#!/usr/bin/env bash
# Runs cargo-audit over both lockfiles, and re-establishes the reason behind
# every ignored advisory before it lets one through.
#
# WHY THIS IS A SCRIPT AND NOT TWO CI LINES.
#
# `crates/cluster` is its own workspace with its own Cargo.lock, so it needs its
# own audit run. cargo-audit reads `.cargo/audit.toml` from the CURRENT
# directory and does not walk upwards, so the obvious fix is a second copy of
# the ignore list in `crates/cluster/.cargo/audit.toml`. That is the shape this
# estate has already been bitten by twice: a check living in two copies, one of
# them updated, and the pair disagreeing at the worst possible moment. There is
# one list, at `.cargo/audit.toml`, and this script hands it to both runs.
#
# WHY AN IGNORE NEEDS A CHECK OF ITS OWN.
#
# An ignore is a claim that an advisory cannot reach us. The claim is usually
# true when it is written and there is nothing that notices when it stops being
# true, so it silently turns into protection against nothing. Today's entry
# (rkyv, RUSTSEC-2026-0235) rests on a specific fact: the crate is recorded in
# Cargo.lock behind an optional feature nothing enables, so it is never
# compiled. That fact is checkable, so it is checked here on every run, with the
# cluster feature explicitly on because that is the only graph the crate can
# enter through.
#
# This file is the ONE copy of this check. CI calls it; run it by hand the same
# way.

set -euo pipefail

cd "$(dirname "$0")/.."

# The tools first, by name, because without them this script does not measure
# a weaker version of the same thing: it dies inside a python subprocess call
# with a FileNotFoundError, several screens from the cause. An advisory check
# that cannot run has to say so.
for tool in cargo cargo-audit; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "FAIL: $tool is not on PATH, so this check measured nothing."
    echo "      An ignore is a claim that an advisory cannot reach us, and that"
    echo "      claim is worth nothing unless something re-establishes it."
    echo "      Install it with: cargo install cargo-audit --locked"
    exit 1
  }
done

config=".cargo/audit.toml"
[ -f "$config" ] || {
  echo "FAIL: $config is missing, so the ignore list has no single source"
  exit 1
}

# The ids, from the one file that carries them and their reasons.
ids=$(grep -oE 'RUSTSEC-[0-9]{4}-[0-9]{4}' "$config" | sort -u)

args=()
for id in $ids; do
  args+=(--ignore "$id")
done

echo "ignored advisories, from $config:"
if [ -z "$ids" ]; then
  echo "  (none)"
else
  printf '  %s\n' $ids
fi
echo

# Every ignored crate must be absent from the BUILT graph. cargo-audit reads the
# lockfile, which is the right thing for it to do; this asserts the narrower
# claim the ignore actually rests on.
#
# `--all-features --target all` is deliberately the widest possible reading: if
# the crate cannot get in under every feature of every target, it cannot get in.
echo "checking that each ignored advisory's crate stays out of the build graph"
python3 - "$ids" <<'PY'
import re
import subprocess
import sys

# Crate per advisory. An ignore with no entry here is refused rather than
# trusted: the point of the file is that a reason exists and is checked.
REACHABILITY = {
    "RUSTSEC-2026-0235": "rkyv",
}

ids = [i for i in sys.argv[1].split() if i]
fail = False

for advisory in ids:
    crate = REACHABILITY.get(advisory)
    if crate is None:
        print(f"FAIL: {advisory} is ignored but this script has no reason recorded for it.")
        print("      Add the crate it concerns to REACHABILITY, or stop ignoring it.")
        fail = True
        continue

    found = False
    for manifest in ["Cargo.toml", "crates/cluster/Cargo.toml"]:
        out = subprocess.run(
            [
                "cargo", "tree",
                "--manifest-path", manifest,
                "-i", crate,
                "--all-features",
                "--target", "all",
            ],
            capture_output=True,
            text=True,
        )
        # A crate outside the graph makes `cargo tree -i` say so on stderr and
        # print nothing; a crate inside it prints the dependents.
        if out.returncode == 0 and re.search(rf"^{re.escape(crate)} v", out.stdout, re.M):
            print(f"FAIL: {advisory} is ignored because '{crate}' is never built, "
                  f"but it IS in the build graph of {manifest}:")
            print(out.stdout.strip()[:800])
            found = True

    if found:
        fail = True
    else:
        print(f"  ok  {advisory}: '{crate}' is in no build graph, only in the lockfile")

if fail:
    print()
    print("An ignore whose reason has stopped holding is worse than no ignore:")
    print("it reports zero for a vulnerability that now reaches production code.")
    sys.exit(1)
PY

echo
echo "auditing the workspace"
cargo audit "${args[@]}"

echo
echo "auditing crates/cluster"
(cd crates/cluster && cargo audit "${args[@]}")
