#!/usr/bin/env python3
"""Writes scripts/teeth-shards.tsv: which CI shard of gates-have-teeth.sh runs which case.

    python3 scripts/teeth-rebalance.py LOG [LOG ...] > scripts/teeth-shards.tsv

LOG is the log of a teeth job from CI (all eight shards of a run make the best input;
several runs are fine, the median of a case's runs is taken). The harness prints, for
every case it judged, `ok  <case> (fail|pass)  <seconds>s`, and for every baseline the
baseline pass took, `baseline  <case>  <seconds>s`; a case's weight is the two added.
Cases are dealt out longest first, each to the lightest shard so far, and the file keeps
the harness's own order of cases (the harness looks up the entry after the one it found
last before it searches).

A case that appears in no log is given the median weight and named on stderr, so a new
case is never a reason for a bad balance and never a reason for a failure.

Cases that share a cost are kept in one shard, because the cost is paid once per shard
that has one of them: `stated-numbers:` cases are handed the output of one run of the
whole suite by the harness, and the first of them in a shard pays for it. Spread over
eight shards they would pay for it eight times. `--together PREFIX` names such a group.

The shard count is read from the workflow; `--shards N` overrides it for a trial.
"""

import argparse
import re
import statistics
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ANSI = re.compile(r"\x1b\[[0-9;]*m")
STAMP = re.compile(r"^﻿?\d{4}-\d\d-\d\dT[\d:.]+Z ")
OK = re.compile(r"^ok\s+(.*?)\s+\((?:pass|fail)\)\s+(\d+)s\s*$")
BASE = re.compile(r"^baseline\s+(.*?)\s+(\d+)s\s*$")


def read_weights(logs):
    runs = defaultdict(list)  # case -> [seconds, per log]
    for log in logs:
        own = defaultdict(float)
        for raw in Path(log).read_text(errors="replace").splitlines():
            line = ANSI.sub("", STAMP.sub("", raw)).rstrip()
            m = OK.match(line) or BASE.match(line)
            if m:
                own[m.group(1).strip()] += int(m.group(2))
        for case, secs in own.items():
            runs[case].append(secs)
    return {case: statistics.median(v) for case, v in runs.items()}


def harness_cases(root):
    out = subprocess.run(
        ["bash", "scripts/gates-have-teeth.sh"],
        cwd=root,
        env={"TEETH_LIST": "1", "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"},
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [line for line in out.splitlines() if line]


def shard_count(root):
    text = (root / ".github/workflows/ci.yml").read_text()
    m = re.search(r"^\s+TEETH_SHARD: \$\{\{ matrix\.shard \}\}/(\d+)\s*$", text, re.M)
    if not m:
        sys.exit("no TEETH_SHARD divisor in .github/workflows/ci.yml")
    return int(m.group(1))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logs", nargs="+")
    ap.add_argument("--shards", type=int)
    ap.add_argument("--together", action="append", default=["stated-numbers:"], metavar="PREFIX")
    args = ap.parse_args()

    root = Path(__file__).resolve().parent.parent
    n = args.shards or shard_count(root)
    cases = harness_cases(root)
    weights = read_weights(args.logs)
    known = [weights[c] for c in cases if c in weights]
    if not known:
        sys.exit("none of the harness's cases appears in the logs given: wrong files?")
    fill = statistics.median(known)
    unseen = [c for c in cases if c not in weights]
    for c in unseen:
        print(f"no timing in the logs for {c!r}; using the median, {fill:.0f}s", file=sys.stderr)
    weight = {c: weights.get(c, fill) for c in cases}

    # Items to deal: one per case, one per together-group.
    items = []  # (weight, [cases])
    grouped = set()
    for prefix in args.together:
        members = [c for c in cases if c.startswith(prefix)]
        if members:
            items.append((sum(weight[c] for c in members), members))
            grouped.update(members)
    items += [(weight[c], [c]) for c in cases if c not in grouped]
    items.sort(key=lambda it: -it[0])

    load = [0.0] * n
    shard_of = {}
    for w, members in items:
        i = min(range(n), key=lambda k: (load[k], k))
        load[i] += w
        for c in members:
            shard_of[c] = i + 1

    print("# Which CI shard of scripts/gates-have-teeth.sh runs which case.")
    print("# Columns, tab separated: shard, seconds, case name. Lines starting with # are comments.")
    print("# The seconds are what the case (and the baseline it needed) took in CI; the shards were")
    print("# filled longest case first so each carries about the same. Regenerate from the logs of a")
    print("# CI run with: python3 scripts/teeth-rebalance.py LOG... > scripts/teeth-shards.tsv")
    print("# A case this file does not name runs in the shard its position gives it, so adding a")
    print("# case needs no edit here; scripts/teeth-shards-cover-every-case.sh checks the result.")
    for c in cases:
        print(f"{shard_of[c]}\t{round(weight[c])}\t{c}")

    print(
        "shards, seconds each: " + " ".join(f"{x:.0f}" for x in load)
        + f"  (longest {max(load):.0f}s, shortest {min(load):.0f}s, even split {sum(load) / n:.0f}s)",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
