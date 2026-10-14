#!/usr/bin/env bash
# Checks that the four CI shards of scripts/gates-have-teeth.sh run every case
# exactly once: no case name is listed twice, no shard is empty, and the shards
# together are the full list, with nothing dropped and nothing run in two shards.
#
# WHY THIS EXISTS
#
# The harness took 30 to 60 minutes as one job, so ci.yml runs it as four shards
# (TEETH_SHARD=i/4). A filter that drops a case from every shard, or lets two
# shards both run it, turns the harness green while a gate goes untested: each
# shard passes on the cases it does run, so nothing else would show the gap.
#
# HOW IT CHECKS WITHOUT RUNNING A CASE
#
# TEETH_LIST=1 makes the harness print the names its run would run, through the
# same filter, and stop. It mutates nothing, so this needs no cargo and no clean
# tree.
#
# The optional argument is the harness to check. It defaults to the real one; the
# planted-fault cases in gates-have-teeth.sh pass a copy with a broken filter.

set -uo pipefail

cd "$(dirname "$0")/.."

harness="${1:-scripts/gates-have-teeth.sh}"
shards=4
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if [ ! -f "$harness" ]; then
	printf 'FAIL: %s does not exist, so the shards measured nothing.\n' "$harness"
	exit 1
fi

# The full list is taken with TEETH_SHARD unset: when this gate runs inside a teeth
# shard, the shard's own setting is in the environment and would filter the list.
if ! env -u TEETH_SHARD TEETH_LIST=1 bash "$harness" >"$work/all" 2>"$work/all.err"; then
	printf 'FAIL: %s did not list its cases:\n' "$harness"
	cat "$work/all.err"
	exit 1
fi

full="$(grep -c . "$work/all")"
if [ "$full" -eq 0 ]; then
	printf 'FAIL: %s lists no cases, so the shards measured nothing.\n' "$harness"
	exit 1
fi

fail=0

dups="$(sort "$work/all" | uniq -d)"
if [ -n "$dups" ]; then
	printf 'FAIL: a case name is listed twice, so shards cannot be compared by name:\n%s\n' "$dups"
	fail=1
fi

sizes=""
: >"$work/union"
for i in $(seq 1 "$shards"); do
	if ! TEETH_LIST=1 TEETH_SHARD="$i/$shards" bash "$harness" >"$work/shard$i" 2>"$work/shard$i.err"; then
		printf 'FAIL: shard %s/%s did not list its cases:\n' "$i" "$shards"
		cat "$work/shard$i.err"
		fail=1
	fi
	n="$(grep -c . "$work/shard$i")"
	if [ "$n" -eq 0 ]; then
		printf 'FAIL: shard %s/%s lists no case, so it measured nothing.\n' "$i" "$shards"
		fail=1
	fi
	sizes="$sizes $n"
	cat "$work/shard$i" >>"$work/union"
done

sort "$work/all" >"$work/all.sorted"
sort "$work/union" >"$work/union.sorted"
if ! cmp -s "$work/all.sorted" "$work/union.sorted"; then
	union_n="$(grep -c . "$work/union")"
	printf 'FAIL: the shards are not a partition of the case list: %s cases in the full list, %s across the shards.\n' "$full" "$union_n"
	printf 'Lines marked < are in the full list more often than the shards run them; lines marked > are run more often than listed.\n'
	diff "$work/all.sorted" "$work/union.sorted" | head -40
	fail=1
fi

if [ "$fail" -ne 0 ]; then
	exit 1
fi

printf 'ok: %s cases, %s shards with%s cases, each run by exactly one shard\n' "$full" "$shards" "$sizes"
