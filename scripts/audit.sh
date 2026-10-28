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
# true, so it silently turns into protection against nothing. There are two
# kinds of reason here, and each is a checkable fact, so each is checked on
# every run:
#
#   * "the crate is never built". rkyv (RUSTSEC-2026-0235) is recorded in
#     Cargo.lock behind an optional feature nothing enables, so it is never
#     compiled. Checked with the cluster feature explicitly on, because that is
#     the only graph the crate can enter through.
#
#   * "the crate is built, but only through callers the advisory does not touch,
#     and only until a named release". zstd and zstd-safe (RUSTSEC-2026-0391 and
#     RUSTSEC-2026-0403) are built through parquet and arrow-ipc 59, which call
#     only zstd::bulk. The fixed versions need parquet and arrow-ipc 60, which
#     no DataFusion release takes yet. Checked against the lockfiles as text: the
#     crate stays inside the version range the reason was argued for, nothing
#     but the named callers depends on it, and the ignore EXPIRES the day
#     parquet or arrow-ipc 60 is in a lockfile.
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

# THE ADVISORY DATABASE MUST BE CLEAN, AND THIS IS NOT PEDANTRY.
#
# `cargo audit` fetches by pulling into ~/.cargo/advisory-db, and `git pull`
# never removes an UNTRACKED file. It then reads the DIRECTORY rather than git
# HEAD, so any stale file that ever landed there is loaded as an advisory
# forever while every subsequent fetch reports success.
#
# On 2026-08-09 that cost hours. Upstream renamed an advisory between two
# crate directories; the old path survived locally as untracked, cargo-audit
# saw the id twice, and refused to load the ENTIRE database with
#
#   error loading advisory database: parse error: duplicate advisory ID
#
# Every audit in the estate was red, `--ignore` did not help (the failure is at
# database LOAD, before any ignore is evaluated), and the finding was written up
# as an upstream outage. It was not: `git grep -l <id> HEAD -- crates/` returned
# exactly one path throughout. `git clean -fd` fixed it in one command.
#
# The diagnosis is one line and nobody runs it, so it runs here. Naming the
# files is the whole value: the cargo-audit error names an advisory id, which
# sends a reader to the wrong repository.
# ASKING ANOTHER REPOSITORY A QUESTION NEEDS THE ENVIRONMENT CLEARED.
#
# git runs a hook with GIT_DIR set to the repository being pushed. `git -C
# <elsewhere>` changes the DIRECTORY and keeps that variable, so the command
# below would read the advisory database's working tree against TOKENFUSE's
# index: every one of the database's entries comes back untracked, this check
# refuses, and the failure is invisible from a terminal because GIT_DIR is only
# set inside a hook.
#
# Found in trailryx on 2026-08-26, where it cost three push attempts before
# anybody looked at the environment rather than at the disk, and found here by
# estate-gates C9, which exists because of it. This repository installs no hook
# today, so the fault was latent rather than live. That is a fact about this
# repository on this date and not about this script.
#
# The half worth naming is the remediation printed below. `git clean -fd` in a
# terminal tidies nothing, because nothing is untracked there. In the
# environment where that message would actually appear, it deletes the advisory
# database.
dbgit() { env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE git "$@"; }

db="${CARGO_HOME:-$HOME/.cargo}/advisory-db"
if [ -d "$db/.git" ]; then
  dirty="$(dbgit -C "$db" status --porcelain 2>/dev/null || true)"
  if [ -n "$dirty" ]; then
    echo "FAIL: the advisory database at $db has files git does not track."
    echo
    printf '%s\n' "$dirty" | sed 's/^/      /'
    echo
    echo "      cargo-audit reads that DIRECTORY, not git HEAD, and \`git pull\`"
    echo "      never removes an untracked file, so these are loaded as advisories"
    echo "      on every run and no upstream fix will ever clear them. A duplicate"
    echo "      id among them makes cargo-audit refuse the whole database, which"
    echo "      looks exactly like an upstream outage and is not one."
    echo
    echo "      Fix it with:  git -C $db clean -fd"
    echo "      (from a terminal. NOT from inside a hook, where GIT_DIR points"
    echo "       at the repository being pushed and this would delete the"
    echo "       database rather than tidy it.)"
    exit 1
  fi
else
  # Not a failure and not a pass. A machine that has never run cargo-audit has
  # no database yet, so there is nothing here to be clean or dirty, and a check
  # that reported nothing would read as agreement.
  echo "note: no advisory database at $db yet, so its cleanliness was not checked."
fi

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

# What each ignore rests on is re-established here, in this order, and an ignore
# that fits neither table is refused rather than trusted.
#
# 1. Every ignored advisory has a recorded reason of one of the two kinds.
# 2. The bounded ones are judged from the lockfiles AS TEXT, before cargo is
#    asked anything: a lockfile edited by hand, or by a bump that has not yet
#    been built, is a thing `cargo tree` would try to resolve again, and the
#    expiry has to be reported as the expiry rather than as a resolver error.
# 3. A "never built" crate must be absent from the BUILT graph. cargo-audit reads
#    the lockfile, which is the right thing for it to do; this asserts the
#    narrower claim the ignore actually rests on. `--all-features --target all`
#    is deliberately the widest possible reading: if the crate cannot get in
#    under every feature of every target, it cannot get in.
echo "checking that each ignored advisory's reason still holds"
python3 - "$ids" <<'PY'
import re
import subprocess
import sys

# "Never built": the crate this advisory concerns must be in no build graph.
# An ignore with no entry in either table is refused rather than trusted: the
# point of the file is that a reason exists and is checked.
REACHABILITY = {
    "RUSTSEC-2026-0235": "rkyv",
}

# "Built, but only through callers the advisory does not touch, until a named
# release". Per advisory: the crate, the half-open version range [low, high) the
# reason was argued for, and the only crates allowed to depend on it.
#
# zstd-safe stays below 8 AND is not to be moved within 7.x: 7.2.2 and later are
# inside the affected range of a further advisory that 7.2.1 sits outside of, so
# a plain `cargo update` would trade two ignored findings for a new live one.
# cargo-audit reports that on its own; the range is the half this table owns.
BOUNDED = {
    "RUSTSEC-2026-0391": ("zstd", (0, 13, 0), (0, 14, 0), {"arrow-ipc", "parquet"}),
    "RUSTSEC-2026-0403": ("zstd-safe", (7, 0, 0), (8, 0, 0), {"zstd"}),
}

# The release that retires the BOUNDED ignores: parquet or arrow-ipc at this
# major or later means the fixed zstd is reachable, and the ignore has expired.
EXPIRES_AT = {"parquet": 60, "arrow-ipc": 60}

LOCKS = ["Cargo.lock", "crates/cluster/Cargo.lock", "crates/radar/Cargo.lock"]

ids = [i for i in sys.argv[1].split() if i]
fail = False


def version_tuple(version):
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", version)
    return tuple(int(x) for x in m.groups()) if m else None


def read_lock(path):
    """[(name, version, [dependency names])] from a Cargo.lock, read as text."""
    out = []
    for block in re.split(r"(?m)^\[\[package\]\]\s*$", open(path).read())[1:]:
        name = re.search(r'(?m)^name = "([^"]+)"', block)
        version = re.search(r'(?m)^version = "([^"]+)"', block)
        if not (name and version):
            continue
        # Entries of `dependencies = [ ... ]`: ` "zstd",` or ` "zstd 0.13.3",`.
        deps = [d.split(" ")[0] for d in re.findall(r'(?m)^ "([^"]+)",?$', block)]
        out.append((name.group(1), version.group(1), deps))
    return out


# 1. a recorded reason, of one kind or the other
for advisory in ids:
    if advisory not in REACHABILITY and advisory not in BOUNDED:
        print(f"FAIL: {advisory} is ignored but this script has no reason recorded for it.")
        print("      Add the crate it concerns to REACHABILITY or BOUNDED, or stop ignoring it.")
        fail = True

# 2. the bounded reasons, from the lockfiles as text
bounded = [a for a in ids if a in BOUNDED]
if bounded and not fail:
    locks = {}
    for path in LOCKS:
        try:
            locks[path] = read_lock(path)
        except FileNotFoundError:
            # crates/radar is audited below and fails there if its lockfile is gone;
            # the root one is the subject here, and without it nothing was measured.
            if path == "Cargo.lock":
                print("FAIL: Cargo.lock is missing, so the bounded ignores measured nothing.")
                fail = True

    expired = sorted(
        (path, name, version)
        for path, pkgs in locks.items()
        for name, version, _ in pkgs
        if name in EXPIRES_AT
        and (version_tuple(version) or (0,))[0] >= EXPIRES_AT[name]
    )
    for path, name, version in expired:
        print(f"FAIL: {', '.join(bounded)} {'is' if len(bounded) == 1 else 'are'} ignored only until "
              f"{name} {EXPIRES_AT[name]}, and {path} has {name} {version}: the ignore has expired.")
        print("      The fixed zstd is reachable now. Remove the ignore from .cargo/audit.toml and the")
        print("      entry from BOUNDED in this script, and let cargo-audit judge what is left.")
        fail = True

    for advisory in bounded:
        crate, low, high, callers = BOUNDED[advisory]
        seen = [(path, version) for path, pkgs in locks.items()
                for name, version, _ in pkgs if name == crate]
        if not seen:
            print(f"FAIL: {advisory} is ignored for '{crate}', but '{crate}' is in no lockfile: "
                  "the ignore matches nothing.")
            print("      Remove it from .cargo/audit.toml and from BOUNDED in this script.")
            fail = True
            continue
        ok = True
        for path, version in seen:
            v = version_tuple(version)
            if v is None or not (low <= v < high):
                print(f"FAIL: {advisory} is ignored for {crate} "
                      f"{'.'.join(map(str, low))} up to (not including) {'.'.join(map(str, high))}, "
                      f"but {path} has {crate} {version}, outside the range the reason was argued for.")
                print("      Argue it again, or remove the ignore if this version is the fix.")
                fail = True
                ok = False
        for path, pkgs in locks.items():
            for name, version, deps in pkgs:
                if crate in deps and name not in callers:
                    print(f"FAIL: {advisory} is ignored on the reasoning that '{crate}' is used only "
                          f"through {', '.join(sorted(callers))}, but {name} {version} in {path} depends on it too.")
                    print("      The reason covers the callers it names; read what this one calls.")
                    fail = True
                    ok = False
        if ok and not expired:
            versions = ", ".join(sorted({v for _, v in seen}))
            print(f"  ok  {advisory}: '{crate}' {versions} is inside its range, "
                  f"its only dependents are {', '.join(sorted(callers))}, and no ignored-until release is in a lockfile")

# 3. the "never built" reasons
if not fail:
    for advisory in ids:
        crate = REACHABILITY.get(advisory)
        if crate is None:
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

# The third nested workspace, and until 2026-09-09 it had no lockfile at all, so
# nothing here audited it and nothing pinned it. That is the crate whose output
# is loaded into the kernel: aya, aya-ebpf and their trees were the one part of
# this repository's dependency graph no advisory had ever been compared against.
# Clean on the first run, 65 crates.
#
# Its lockfile going missing fails this step rather than skipping it: cargo audit
# has nothing to scan and says so, which is the "measured nothing" answer the
# other two subjects already give.
echo
echo "auditing crates/radar"
(cd crates/radar && cargo audit "${args[@]}")
