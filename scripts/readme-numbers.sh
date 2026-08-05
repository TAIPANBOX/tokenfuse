#!/usr/bin/env bash
# Every number this README states about this repository, checked against the
# repository.
#
# WHY THIS EXISTS
#
# A number on a README is a claim with no owner. It is right the day it is
# written, and nothing tells anybody when it stops being right, because the
# suite grows in commits that never open the README.
#
# Not hypothetical, and this repository is the worst case of it. On 2026-08-05
# the it-rat.com service pages were audited against the repositories they
# describe and four of seven figures were stale. **TokenFuse was the largest:
# the page said 513 tests where the workspace runs 709**, and nobody knows how
# long it had said that. None of the four was wrong when written.
#
# WHAT IS COUNTED, because a number needs a definition more than it needs a
# badge
#
# Every `test result:` line `cargo test --all` prints, summed. That is the whole
# workspace: unit tests, integration tests and doc-tests, exactly what a
# contributor sees at the end of a run, so the badge is a figure somebody can
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

set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 1

readme="README.md"
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

stated=$(grep -o 'badge/tests-[0-9]*-' "$readme" | grep -o '[0-9]*' | head -1)
if [ -z "$stated" ]; then
	note "the README carries no tests badge, so this check has nothing to compare against"
	note "add: ![tests](https://img.shields.io/badge/tests-${actual}-brightgreen)"
	exit 1
fi

[ "$stated" = "$actual" ] ||
	note "the badge says $stated tests and \`cargo test --all\` runs $actual"

if [ "$problems" -gt 0 ]; then
	printf '\n%d number(s) the README states that this repository does not support.\n' "$problems"
	printf 'Update the badge in the same commit as the tests. That is the point: the\n'
	printf 'suite changes in a commit that never opens the README, and this is what\n'
	printf 'makes that impossible.\n'
	exit 1
fi

printf '%s tests across the workspace, and the badge says so.\n' "$actual"
