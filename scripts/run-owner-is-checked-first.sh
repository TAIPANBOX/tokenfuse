#!/usr/bin/env bash
# A run's owner is settled before anything reads or writes the run on behalf
# of the caller (CLAUDE.md invariant 120).
#
# WHY THIS EXISTS
#
# A run belongs to the principal whose metered call first named it, and a call
# naming a run another principal opened is refused having learnt nothing about
# that run and changed nothing in it. "Nothing" holds only while the claim is
# the FIRST thing the metered door does with the run id: a line that records
# the request's tool blocks, opens the ledger entry, reads the taint or the
# Cloud budget above the claim compiles, passes every test that does not look
# at that one effect, and lets another caller write into or read from a run it
# does not own. Equally, a declared parent is judged before the ledger can
# adopt it or the parent can be opened on first sight; judged only after, a
# refused parent has already been linked.
#
# WHAT IT CHECKS
#
# In `async fn handle_call(` (crates/gateway/src/proxy.rs), with comments
# masked: `run_owners.claim(` is present, and its first line comes before the
# first line of every call that touches the run (`.note_blocks(`,
# `.pending_reason(`, `.open_run(`, `.snapshot(`, `accumulate_taint(`,
# `note_taint_parent(`, `inherited_taint(`, `cloud_budget(`); and the first
# `foreign_parent_refusal(` comes before the first `.open_run(`. In
# `fn answer(` (crates/gateway/src/toolcheck.rs), the owner is read
# (`run_owner(`) before the run's taint is (`accumulate_taint(`,
# `inherited_taint(`).
#
# WHAT IT REFUSES TO PASS ON
#
# Either function gone, renamed, or no longer containing the call that anchors
# it (`.open_run(`, `accumulate_taint(`): the scan measured nothing. Exit 1 and
# say so.
#
# WHAT IT DOES NOT CHECK
#
# That the claim's answer is acted on, that the principal is the right one, or
# that the parent check is given the right parent: the tests in
# tests/it/run_belongs_to_its_principal.rs hold those, and the product mutants
# in scripts/gates-have-teeth.sh plant each fault. A call that touches the run
# under a name this list does not carry is not seen; the list is the set of
# run-state calls the function made when this gate was written.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

proxy="crates/gateway/src/proxy.rs"
check="crates/gateway/src/toolcheck.rs"
fail=0

# The body of a top-level function: from the line that starts with $2 to the
# first line that is exactly "}", each line prefixed with its number and with
# any `//` comment cut off.
body() {
	awk -v sig="$2" '
		index($0, sig) == 1 { f = 1 }
		f { line = $0; sub(/\/\/.*$/, "", line); print NR "\t" line }
		f && /^}$/ { exit }
	' "$1"
}

# The line number of the first line of $1 (a body) containing $2, or empty.
first() {
	printf '%s\n' "$1" | grep -F -- "$2" | head -1 | cut -f1
}

for f in "$proxy" "$check"; do
	if [ ! -f "$f" ]; then
		printf 'FAIL: %s is not there, so this gate measured nothing.\n' "$f"
		exit 1
	fi
done

handle=$(body "$proxy" "async fn handle_call(")
if [ -z "$handle" ] || [ -z "$(first "$handle" ".open_run(")" ]; then
	printf 'FAIL: %s has no `async fn handle_call(` that opens a run, so this gate measured nothing.\n' "$proxy"
	exit 1
fi
answer=$(body "$check" "fn answer(")
if [ -z "$answer" ] || [ -z "$(first "$answer" "accumulate_taint(")" ]; then
	printf 'FAIL: %s has no `fn answer(` that reads a run'"'"'s taint, so this gate measured nothing.\n' "$check"
	exit 1
fi

claim=$(first "$handle" "run_owners.claim(")
if [ -z "$claim" ]; then
	printf 'NEVER CLAIMS  %s: handle_call opens runs and never calls run_owners.claim(\n' "$proxy"
	fail=$((fail + 1))
else
	for needle in ".note_blocks(" ".pending_reason(" ".open_run(" ".snapshot(" \
		"accumulate_taint(" "note_taint_parent(" "inherited_taint(" "cloud_budget("; do
		at=$(first "$handle" "$needle")
		if [ -n "$at" ] && [ "$at" -lt "$claim" ]; then
			printf 'TOUCHES THE RUN BEFORE ITS OWNER  %s:%s calls %s before the claim at line %s\n' \
				"$proxy" "$at" "$needle" "$claim"
			fail=$((fail + 1))
		fi
	done
fi

open=$(first "$handle" ".open_run(")
parent=$(first "$handle" "foreign_parent_refusal(")
if [ -z "$parent" ] || [ "$parent" -gt "$open" ]; then
	printf 'PARENT JUDGED ONLY AFTER IT IS OPENED  %s: the first foreign_parent_refusal( (line %s) does not come before the first .open_run( (line %s)\n' \
		"$proxy" "${parent:-none}" "$open"
	fail=$((fail + 1))
fi

owner=$(first "$answer" "run_owner(")
if [ -z "$owner" ]; then
	printf 'NEVER CLAIMS  %s: the tool-call check never reads the run'"'"'s owner\n' "$check"
	fail=$((fail + 1))
else
	for needle in "accumulate_taint(" "inherited_taint("; do
		at=$(first "$answer" "$needle")
		if [ -n "$at" ] && [ "$at" -lt "$owner" ]; then
			printf 'TOUCHES THE RUN BEFORE ITS OWNER  %s:%s calls %s before the owner is read at line %s\n' \
				"$check" "$at" "$needle" "$owner"
			fail=$((fail + 1))
		fi
	done
fi

if [ "$fail" -gt 0 ]; then
	printf '\n%d place(s) where a run is touched before its owner is settled (invariant 120).\n' "$fail"
	exit 1
fi
printf 'OK: the metered door claims the run (line %s) and judges a declared parent (line %s) before it opens anything (line %s); the tool-call check reads the owner first.\n' \
	"$claim" "$parent" "$open"
