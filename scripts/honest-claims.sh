#!/usr/bin/env bash
# Holds the two halves of invariant 4 ("honesty is a feature") that have a
# mechanical form, and deliberately does not pretend to hold the third.
#
# WHAT CANNOT BE CHECKED, established before writing this rather than assumed
#
# Whether a NEW sentence over-claims is judgment. The obvious script is a banned
# word list: "guarantees", "ensures", "fully compliant". It was tested against
# this repository on 2026-08-06 and it is unusable. `guarantee` appears five
# times in README.md, and the ones it would flag hardest are the honest ones:
#
#   "...reconciled against real usage, not a hard real-time guarantee"
#   "...not a guarantee that not one extra cent can ever be spent"
#
# The honest sentence and the dishonest one share a vocabulary and differ in
# polarity, which is the part a regex cannot read. A gate that fires on the
# sentences an invariant exists to protect gets deleted, correctly.
#
# WHAT CAN BE CHECKED, and both are real regression modes
#
# 1. THE CATALOG'S GRADES. `tokenfuse_core::compliance::CATALOG` grades every
#    control `Enforced`, `Partial` or `Documented`, and that grade is a claim
#    made to a regulator through `/v1/compliance` and `tokenfuse compliance`.
#    Moving one UP is over-claiming coverage in the most literal sense the
#    invariant has, it is a one-word edit, and nothing else in this repository
#    would notice. The grades are recorded below.
#
# 2. THE DISCLOSURES. The invariant names two limitations the docs must state
#    plainly: budgets are estimate-then-settle, and the system fails open by
#    default. Deleting a sentence is how "state it plainly, not buried" fails,
#    and a missing sentence is exactly as checkable as a present one.
#
# Scope is README.md, the front door, not every file under docs/. Requiring
# these sentences in documents that are not about budgets would make the check
# noise, and noise is how a check stops being read.

set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 1

python3 - "$@" <<'PY'
import re
import sys
from pathlib import Path

CATALOG = Path("crates/core/src/compliance.rs")
README = Path("README.md")

# --- 1: the recorded grades ------------------------------------------------
#
# Update in the same commit as the change, and say in that commit what evidence
# supports the new grade. An upgrade is a claim somebody may act on.
GRADES = {
    "TF.BUDGET": "Enforced",
    "TF.LOOP": "Enforced",
    "TF.KILL": "Enforced",
    "TF.DLP": "Enforced",
    "TF.TAINT": "Enforced",
    "TF.MCP.POISON": "Enforced",
    "TF.MCP.RUGPULL": "Enforced",
    "TF.MCP.EXPOSURE": "Enforced",
    "TF.WASM": "Partial",
    "TF.AUDIT": "Partial",
    "TF.ACCESS": "Partial",
}

RANK = {"Documented": 0, "Partial": 1, "Enforced": 2}

# --- 2: the disclosures README must carry ----------------------------------
#
# Several phrasings each, so ordinary copy-editing does not fail this. Reword
# past all of them and it fails, which is the intended contract: the sentence is
# load-bearing, so its rewrite is a decision, not a typo fix.
DISCLOSURES = [
    (
        "budgets are estimate-then-settle, not exact",
        [
            r"estimate[-\s]then[-\s]settle",
            r"estimates cost.{0,160}settles",
            r"not a guarantee that not one extra cent",
            r"not a hard real[-\s]time guarantee",
        ],
    ),
    (
        "the system fails open by default",
        [
            r"fail[-\s]open by default",
            r"fail[-\s]open.{0,80}default",
            r"default.{0,80}fail[-\s]open",
        ],
    ),
]

problems = []


def note(msg):
    problems.append(msg)
    print(msg)


def measured_nothing(what):
    print("FAIL: this check measured nothing, so invariant 4 is UNVERIFIED here.")
    print(f"      {what}")
    print("      Fix this script before trusting a green run.")
    sys.exit(1)


# --- the catalog -----------------------------------------------------------

text = CATALOG.read_text()
found = {}
for m in re.finditer(
    r'control_id:\s*"([^"]+)"(.{0,800}?)enforcement:\s*Enforcement::(\w+)', text, re.S
):
    found[m.group(1)] = m.group(3)

if not found:
    measured_nothing(
        f"no control_id/enforcement pair parsed out of {CATALOG}. The catalog's "
        "shape has changed and this script is reading nothing."
    )

for cid in sorted(set(GRADES) | set(found)):
    want, got = GRADES.get(cid), found.get(cid)
    if want == got:
        continue
    if want is None:
        note(
            f"{cid} is a new control graded {got}, which is a new claim about what this "
            "product enforces. Record it in this script in the same commit, with the "
            "evidence for the grade in the commit message."
        )
    elif got is None:
        note(f"{cid} is recorded here as {want} and is gone from the catalog.")
    elif RANK[got] > RANK[want]:
        note(
            f"{cid} was UPGRADED from {want} to {got}. That is a stronger claim about "
            "coverage, made to whoever reads /v1/compliance or `tokenfuse compliance`. "
            "If the evidence supports it, record it here and say so in the commit; "
            "invariant 4 is about not over-claiming, and this is the literal case."
        )
    else:
        note(
            f"{cid} was downgraded from {want} to {got}, which is honest but leaves this "
            "script's record stale. Update it in the same commit."
        )

# --- the disclosures -------------------------------------------------------

readme = re.sub(r"\s+", " ", README.read_text())

for what, patterns in DISCLOSURES:
    if not any(re.search(p, readme, re.I) for p in patterns):
        note(
            f"README.md no longer states that {what}. Invariant 4 requires these "
            "limitations plainly in the docs, not buried: an honest product that stops "
            "saying what it cannot do has over-claimed by omission. If the wording moved, "
            "add the new phrasing to DISCLOSURES in this script."
        )

# --- verdict ---------------------------------------------------------------

if problems:
    print(
        f"\n{len(problems)} honesty claim(s) moved without being recorded "
        "(CLAUDE.md invariant 4)."
    )
    sys.exit(1)

print(
    f"{len(GRADES)} control grades unchanged and {len(DISCLOSURES)} stated limitations "
    "still stated."
)
PY
