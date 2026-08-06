#!/usr/bin/env bash
# Enforces invariant 5 of CLAUDE.md: a new dimension in the replicated ledger is
# a raft and schema-identity decision, not a routine edit.
#
# WHAT THIS PINS
#
# The four types in `crates/cluster/src/types.rs` that ARE the replicated
# schema: `Request` (the log entry every node applies), `Response`, `RunState`
# (per-run accounting held in the state machine) and `LedgerState` (the whole
# machine). Their field and variant names are recorded below. Change one and
# this check fails, naming what moved.
#
# WHY A COMMENT WAS NOT ENOUGH, which is what this invariant used to have
#
# Adding a field to `RunState` compiles cleanly. Every test passes. Nothing in
# the workspace notices, because the workspace builds a fresh state machine in
# every test.
#
# A deployed node does not. `LedgerState` is written to redb through
# `serde_json` (`redbstore.rs`), and none of these types carries
# `#[serde(default)]`. So a node that has a durable store, which is the whole
# point of `serve --dir`, cannot read back state written by the previous shape:
# it comes up having lost every budget and every reservation, silently, and the
# first thing anybody notices is that the breaker stopped breaking.
#
# That is not a hypothesis about this repository's habits. `build_durable` sat
# behind a test-only caller for months while the shipped binary had no durable
# mode at all (#162), which is exactly the kind of gap nobody sees without a
# check.
#
# WHAT THIS IS NOT
#
# It is not a claim that adding a field is wrong. It often is not. It is a claim
# that adding one is a DECISION: the migration, the `#[serde(default)]`, the
# raft snapshot compatibility and the version story all have to be chosen, and
# the recorded shape below is updated in the same commit that chooses them.
#
# The trait in `crates/gateway/src/ledger_backend.rs` is deliberately NOT pinned
# here: a method added to it fails to compile until both backends implement it,
# so the compiler already makes that loud. This script covers the half the
# compiler cannot see.

set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 1

python3 - "$@" <<'PY'
import re
import sys
from pathlib import Path

TYPES = Path("crates/cluster/src/types.rs")

# ---------------------------------------------------------------------------
# The recorded shape. Update it in the same commit as the change it describes,
# and say in that commit what happens to a node holding the old shape on disk.
# ---------------------------------------------------------------------------
EXPECTED = {
    "Request::Open": ["run", "budget_micros", "parent"],
    "Request::Reserve": ["run", "micros"],
    "Request::Settle": ["run", "reserved_micros", "actual_micros"],
    "Response": [
        "accepted",
        "spent_micros",
        "reserved_micros",
        "budget_micros",
        "step",
        "blocked_run",
        "reason",
    ],
    "RunState": [
        "budget_micros",
        "reserved_micros",
        "spent_micros",
        "steps",
        "parent",
    ],
    "LedgerState": ["runs"],
}

problems = []


def note(msg):
    problems.append(msg)
    print(msg)


text = TYPES.read_text()


def strip_comments(s):
    # Comments first, always: a doc comment here contains commas, and splitting
    # before stripping loses every field after one. That bug parsed `Response`
    # as five fields of seven while looking perfectly healthy.
    return re.sub(r"//[^\n]*", "", s)


def block(name, kind):
    m = re.search(r"pub %s %s\s*\{" % (kind, re.escape(name)), text)
    if not m:
        return None
    depth, i = 0, m.end() - 1
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    return strip_comments(text[m.end() : i])


def split_top(body):
    out, depth, cur = [], 0, ""
    for ch in body:
        if ch in "<([{":
            depth += 1
        elif ch in ">)]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return out


def fields(body):
    names = []
    for piece in split_top(body):
        piece = re.sub(r"#\[[^\]]*\]", "", piece)
        m = re.match(r"\s*(?:pub\s+)?([a-z_][a-z0-9_]*)\s*:", piece)
        if m:
            names.append(m.group(1))
    return names


actual = {}

for name in ("Response", "RunState", "LedgerState"):
    body = block(name, "struct")
    if body is None:
        note(f"`{name}` is no longer a `pub struct` in {TYPES}, so its shape cannot be checked")
        continue
    got = fields(body)
    if not got:
        note(f"`{name}` parsed to no fields at all, which means this check measured nothing")
        continue
    actual[name] = got

req = block("Request", "enum")
if req is None:
    note(f"`Request` is no longer a `pub enum` in {TYPES}, so the log entry shape cannot be checked")
else:
    found = False
    for v in re.finditer(r"([A-Z][A-Za-z0-9_]*)\s*\{([^}]*)\}", req):
        found = True
        actual[f"Request::{v.group(1)}"] = fields(v.group(2))
    if not found:
        note("`Request` parsed to no variants at all, which means this check measured nothing")

for key in sorted(set(EXPECTED) | set(actual)):
    want, got = EXPECTED.get(key), actual.get(key)
    if want == got:
        continue
    if want is None:
        note(f"`{key}` is new in the replicated schema: {got}")
    elif got is None:
        note(f"`{key}` has gone from the replicated schema (recorded as {want})")
    else:
        added = [f for f in got if f not in want]
        removed = [f for f in want if f not in got]
        note(
            f"`{key}` changed shape. Added: {added or 'none'}. Removed: {removed or 'none'}. "
            f"Recorded: {want}. Found: {got}"
        )

if problems:
    print(
        "\nThe replicated ledger's schema moved (CLAUDE.md invariant 5).\n"
        "\n"
        "This is not a claim that the change is wrong. It is a claim that it is a\n"
        "DECISION, and the decision is about the nodes that already exist:\n"
        "`LedgerState` is written to redb as serde_json and nothing here carries\n"
        "`#[serde(default)]`, so a node with a durable store cannot read back what\n"
        "it wrote under the old shape. It restarts having lost every budget and\n"
        "every reservation, with no error, and the first symptom is a breaker that\n"
        "stopped breaking.\n"
        "\n"
        "Choose the migration, the defaults and the snapshot compatibility, then\n"
        "update EXPECTED in this script in the same commit, and say in that commit\n"
        "what happens to a node holding the old shape on disk."
    )
    sys.exit(1)

print(
    f"the replicated ledger's schema matches its recorded shape "
    f"({len(EXPECTED)} types/variants pinned)."
)
PY
