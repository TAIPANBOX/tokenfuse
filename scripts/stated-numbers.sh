#!/usr/bin/env bash
# Every number this repository's front matter states about this repository,
# checked against the repository. Two files state one today: README.md's tests
# badge and PROGRESS.md's Test status section.
#
# WHY THIS EXISTS
#
# A number in a document is a claim with no owner. It is right the day it is
# written, and nothing tells anybody when it stops being right, because the
# suite grows in commits that never open the document.
#
# Not hypothetical, and this repository has now supplied both halves of the
# lesson. On 2026-08-05 the it-rat.com service pages were audited against the
# repositories they describe and four of seven figures were stale. **TokenFuse
# was the largest: the page said 513 tests where the workspace ran 709**, and
# nobody knows how long it had said that. The badge got a gate that day. What
# the gate did NOT cover was the same figure written in prose one file over:
# PROGRESS.md said **100 passing (core: 60, gateway: 40)** while the workspace
# ran 747, a sevenfold error, found by reading rather than by any check. That is
# the argument for gating a figure wherever it is stated rather than wherever it
# is prettiest. None of these was wrong when written.
#
# WHAT IS COUNTED, because a number needs a definition more than it needs a
# badge
#
# Every `test result:` line `cargo test --all` prints, summed. That is the whole
# workspace: unit tests, integration tests and doc-tests, exactly what a
# contributor sees at the end of a run, so the figure is one somebody can
# reproduce in one command rather than a number only this script knows how to
# get.
#
# It runs the suite, unlike its Go siblings, because cargo has no cheap
# enumeration equivalent to `go test -list`. So a red suite fails this check
# too. That is a side effect and not the point: `cargo test --all` in CI is what
# says they pass.
#
# The cluster crate is deliberately NOT included. It is its own workspace behind
# the `cluster` feature with its own CI job, and folding it in would make this
# number irreproducible with the plain command the badge implies.
#
# WHAT THE PER-CRATE CHECK PROVES, AND WHAT IT DOES NOT
#
# PROGRESS.md also breaks the total down per crate. This script checks that the
# parts SUM to the measured total. It does not check that core's share is
# really core's, because that would mean running `cargo test -p` four more times
# for a decoration, while the total is the load-bearing figure.
#
# So: a breakdown that drifts out of step with the total fails here, and a
# breakdown with two compensating errors passes. A deliberate limit, stated
# rather than left for somebody to discover (invariant 4).
#
# The crate names are written out rather than matched generically, and that is
# the same speed bump the note above the pattern describes: adding a workspace
# member has to touch this line, so nobody adds one whose tests are counted in
# the total and missing from the breakdown. `dpop` joined on 2026-08-26, and
# `delegation` the same day, when the RFC 8693 verifier was cut out of `cloud`
# so the GATEWAY could use it without depending on the control plane.

set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 1

readme="README.md"
progress="PROGRESS.md"
problems=0

note() {
	printf '%s\n' "$1"
	problems=$((problems + 1))
}

actual=$(cargo test --all --quiet 2>/dev/null |
	grep -E '^test result' | awk '{s += $4} END {print s + 0}')

if [ "${actual:-0}" -eq 0 ]; then
	note "the suite reported no tests at all, which means this check measured nothing"
	exit 1
fi

# --- README.md: the badge ------------------------------------------------

stated=$(grep -o 'badge/tests-[0-9]*-' "$readme" | grep -o '[0-9]*' | head -1)
if [ -z "$stated" ]; then
	note "the README carries no tests badge, so this check has nothing to compare against"
	note "add: ![tests](https://img.shields.io/badge/tests-${actual}-brightgreen)"
	exit 1
fi

[ "$stated" = "$actual" ] ||
	note "the badge says $stated tests and \`cargo test --all\` runs $actual"

# --- PROGRESS.md: the same figure, in prose ------------------------------
#
# PROGRESS.md wraps its paragraphs, so the breakdown straddles a newline.
# Normalise the whitespace before matching, rather than writing a pattern that
# depends on where a paragraph happens to wrap today.

# Scoped to the Test status section, not the whole file. The figure lives there,
# and the rest of PROGRESS.md is prose that may legitimately quote an older
# count while explaining how it drifted. Reading the whole file made exactly
# that happen: a paragraph recording that this file once said "100 passing"
# where the workspace ran 747 was picked up as the current claim, and the gate
# failed on its own history lesson. A check that a true sentence can break is a
# check somebody eventually deletes.
progress_text=$(awk '/^## Test status/{f=1; next} /^## /{f=0} f' "$progress" | tr '\n' ' ')

stated_progress=$(printf '%s' "$progress_text" |
	grep -oE '\*\*[0-9]+ passing\*\*' | grep -oE '[0-9]+' | head -1)

if [ -z "$stated_progress" ]; then
	note "PROGRESS.md states no workspace test count: expected \`**<N> passing**\` in its Test status section"
	note "  if you reworded that line, update this script in the same commit: a gate a rewrite can silently drop is not a gate"
else
	[ "$stated_progress" = "$actual" ] ||
		note "PROGRESS.md says $stated_progress passing and \`cargo test --all\` runs $actual"
fi

breakdown=$(printf '%s' "$progress_text" |
	grep -oE 'core [0-9]+, dpop [0-9]+, delegation [0-9]+, gateway [0-9]+, cloud [0-9]+, umbrella [0-9]+' | head -1)

if [ -z "$breakdown" ]; then
	note "PROGRESS.md carries no per-crate breakdown: expected \`core <N>, dpop <N>, delegation <N>, gateway <N>, cloud <N>, umbrella <N>\`"
	note "  same rule as above: reword it and update this script together, or drop both"
else
	sum=$(printf '%s' "$breakdown" | grep -oE '[0-9]+' | awk '{s += $1} END {print s + 0}')
	[ "$sum" = "$actual" ] ||
		note "PROGRESS.md's breakdown ($breakdown) sums to $sum and the suite runs $actual"
fi

# --- verdict --------------------------------------------------------------

if [ "$problems" -gt 0 ]; then
	printf '\n%d number(s) this repository states about itself that it does not support.\n' "$problems"
	printf 'Update them in the same commit as the tests. That is the point: the suite\n'
	printf 'changes in commits that never open README.md or PROGRESS.md, and this is\n'
	printf 'what makes that impossible.\n'
	exit 1
fi

printf '%s tests across the workspace; the README badge and PROGRESS.md both say so.\n' "$actual"
