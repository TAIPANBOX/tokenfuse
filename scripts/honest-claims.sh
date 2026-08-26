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
# 3. THE TWO FRAMEWORK LISTS AND THE LINE BETWEEN THEM. `FRAMEWORK_VERSIONS` is
#    what the code ENFORCES; `RELEVANT_FRAMEWORKS` is what this product is
#    relevant to and enforces no part of. The Rust tests hold the properties
#    that can be read off one compilation: the two id sets are disjoint, no
#    control cites a merely-relevant id, and every such row states its own
#    limit. What no test in the crate can hold is MOVEMENT: promoting
#    ISO-23894 out of the second list and into the first is a green edit, and it
#    is the same over-claim as upgrading a control's grade, one level up where
#    `Enforcement` cannot see it. So the membership of both lists is recorded
#    here for the same reason the grades are, and moving a framework between
#    them is a decision that gets written down in the commit that makes it.
#
#    It lives in this script rather than a twelfth one because it is the same
#    invariant and the same file, and this estate has been bitten twice by a
#    check living in two copies.
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

# --- 3: which framework is in which list -----------------------------------
#
# ENFORCED_FRAMEWORKS is `FRAMEWORK_VERSIONS`, the list every reporting surface
# renders as "the frameworks this product enforces". RELEVANT_ONLY is
# `RELEVANT_FRAMEWORKS`, the list that says the opposite in the same breath as
# claiming relevance.
#
# A move from RELEVANT_ONLY to ENFORCED_FRAMEWORKS is the over-claim this
# invariant is about, and it needs the same thing a grade upgrade needs: the
# evidence, in the commit that makes the move. A move the other way is honest
# and still gets recorded, because a stale record here is what makes the next
# real move invisible.
ENFORCED_FRAMEWORKS = {
    "OWASP-ASI-2026",
    "MITRE-ATLAS",
    "NIST-800-53r5",
    "SOC2",
    "EU-AI-ACT",
    "DORA",
    "NIS2",
}

RELEVANT_ONLY = {
    "ISO-23894",
}

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

# --- which framework is in which list --------------------------------------


def const_block(name):
    """The body of a `pub const NAME ... = &[ ... ];`, or None.

    The slice runs from the `[` of the VALUE, found by anchoring on `= &[`, to
    its matching `]`, counting brackets and skipping string literals.

    Both halves of that are corrections a mutant forced, and both are the exact
    failure this repository names about text gates: the check stops reading what
    it thinks it reads and says nothing.

    The end was `text.find("\\n];")` first, which is how the tuple list ends and
    is NOT how the struct list ends (`}];`), so the slice ran past
    RELEVANT_FRAMEWORKS and swallowed the whole CATALOG, and still printed the
    right answer by luck. Then the start was the first `[` after the name, which
    is the one in the TYPE (`&[(&str, &str, &str)]`), so the slice was the type
    annotation and no id parsed at all. `@measured` by mutants 3 and 4 and by
    the negative control, 2026-08-26.
    """
    at = text.find(f"pub const {name}")
    if at == -1:
        return None
    eq = text.find("= &[", at)
    if eq == -1:
        return None
    open_at = eq + 3
    depth, i, n = 0, open_at, len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
        elif ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                return text[open_at : i + 1]
        i += 1
    return None


enforced_block = const_block("FRAMEWORK_VERSIONS")
relevant_block = const_block("RELEVANT_FRAMEWORKS")

if enforced_block is None or relevant_block is None:
    missing = "FRAMEWORK_VERSIONS" if enforced_block is None else "RELEVANT_FRAMEWORKS"
    measured_nothing(
        f"{missing} is not a `pub const ... = &[ ... ]` in {CATALOG} any more, so "
        "this script cannot tell which frameworks this product claims to enforce "
        "and which it only relates to."
    )

# Neither slice may contain the other's marker, which is what a runaway slice
# looks like. Cheap, and it is the exact defect the bracket scan replaced.
if "framework_id:" in enforced_block or "control_id:" in relevant_block:
    measured_nothing(
        "one framework list's slice reaches into the other, or into CATALOG, so "
        "the ids counted below are not the ids of the list they are attributed to."
    )

# The enforced list is `(id, name, version)` triples; the relevant list is
# structs with a named field. Two different shapes on purpose: see the module
# doc. Both are parsed here, and an empty parse from either is a failure.
enforced_found = set(re.findall(r'\(\s*"([^"]+)"', enforced_block))
relevant_found = set(re.findall(r'framework_id:\s*"([^"]+)"', relevant_block))

if not enforced_found:
    measured_nothing(
        "no framework id parsed out of FRAMEWORK_VERSIONS. Its row shape has "
        "changed and this script is reading nothing."
    )
if not relevant_found:
    measured_nothing(
        "no framework_id parsed out of RELEVANT_FRAMEWORKS. Either the row shape "
        "has changed, or the category has been emptied, and an empty category is "
        "not a clean run: it is a list nothing is left in and nothing objects to."
    )

for fid in sorted(RELEVANT_ONLY & enforced_found):
    note(
        f"{fid} is recorded as a framework this product does NOT enforce and is now "
        "in the enforced framework list, which every reporting surface renders as "
        "the frameworks this product enforces. That is the same over-claim as "
        "upgrading a control's grade, one level up. If a control really does "
        "enforce part of it, record the move here and put the evidence in the "
        "commit message."
    )

for fid in sorted(ENFORCED_FRAMEWORKS & relevant_found):
    note(
        f"{fid} is recorded as enforced and now also appears in RELEVANT_FRAMEWORKS. "
        "A framework is one or the other: a framework with any enforced row stays in "
        "the enforced list, and its unclaimed parts are gap notes."
    )

for fid in sorted(enforced_found - ENFORCED_FRAMEWORKS - RELEVANT_ONLY):
    note(
        f"{fid} is a new framework in the enforced list, which is a new claim that "
        "this product enforces part of it. Record it in this script in the same "
        "commit, with the control that carries the evidence."
    )

for fid in sorted(relevant_found - RELEVANT_ONLY - ENFORCED_FRAMEWORKS):
    note(
        f"{fid} is a new framework this product claims to be relevant to. That is a "
        "smaller claim than enforcement and it is still a claim made to an auditor. "
        "Record it in this script in the same commit."
    )

for fid in sorted(ENFORCED_FRAMEWORKS - enforced_found - relevant_found):
    note(f"{fid} is recorded here as enforced and is gone from the catalog entirely.")

for fid in sorted(RELEVANT_ONLY - relevant_found - enforced_found):
    note(
        f"{fid} is recorded here as relevant-not-enforced and is gone from the "
        "catalog entirely. Dropping it is a decision; leaving this record behind "
        "makes the next real move invisible."
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
    f"{len(GRADES)} control grades unchanged, {len(ENFORCED_FRAMEWORKS)} frameworks still "
    f"enforced and {len(RELEVANT_ONLY)} still only relevant, and {len(DISCLOSURES)} stated "
    "limitations still stated."
)
PY
