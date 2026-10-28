#!/usr/bin/env bash
# Checks that the CI shards of scripts/gates-have-teeth.sh run every case exactly
# once: no case name is listed twice, no shard is empty, and the shards together
# are the full list, with nothing dropped and nothing run in two shards. The shard
# count is read from the workflow, where the teeth job's matrix, the divisor each
# shard filters by and the job's name all state it, and the three must agree.
#
# WHY THIS EXISTS
#
# The harness took 30 to 60 minutes as one job, so ci.yml runs it as shards
# (TEETH_SHARD=i/N). A filter that drops a case from every shard, or lets two
# shards both run it, turns the harness green while a gate goes untested: each
# shard passes on the cases it does run, so nothing else would show the gap.
#
# The count was written twice until 2026-10-26, as the matrix and as `shards=4`
# here, and nothing checked that they agreed: a matrix of eight with a gate of four
# would have proved a partition nobody ran. It is now written in the workflow only.
#
# HOW IT CHECKS WITHOUT RUNNING A CASE
#
# TEETH_LIST=1 makes the harness print the names its run would run, through the
# same filter, and stop. It mutates nothing, so this needs no cargo and no clean
# tree.
#
# THE SHARD MAP
#
# Which shard runs which case is not the case's position any more: scripts/
# teeth-shards.tsv names a shard for each case, balanced by the seconds each took in
# CI (scripts/teeth-rebalance.py writes it from the logs). A case the map does not
# name is placed by its position and still runs once, so the partition below holds
# with or without an entry. What the map can get wrong that the partition does not
# show is checked here: an entry for a case that no longer exists (renamed away,
# so its weight now balances nothing), a shard that does not exist, a case named
# twice, and a map that is gone.
#
# The optional arguments are the harness and the workflow to check. They default
# to the real ones; the planted-fault cases in gates-have-teeth.sh pass a copy of
# the harness with a broken filter, and edit the workflow itself.

set -uo pipefail

cd "$(dirname "$0")/.."

harness="${1:-scripts/gates-have-teeth.sh}"
workflow="${2:-.github/workflows/ci.yml}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if [ ! -f "$workflow" ]; then
	printf 'FAIL: %s does not exist, so the shard count measured nothing.\n' "$workflow"
	exit 1
fi

# The one value a pattern captures in the workflow, or nothing when it matches no
# line or more than one.
one() {
	local got
	got="$(sed -nE "s#$1#\\1#p" "$workflow")"
	[ "$(printf '%s' "$got" | grep -c .)" -eq 1 ] && printf '%s' "$got"
}
matrix="$(one '^[[:space:]]+shard: \[([0-9, ]+)\][[:space:]]*$' | tr -d ' ')"
shards="$(one '^[[:space:]]+TEETH_SHARD: \$\{\{ matrix\.shard \}\}/([0-9]+)[[:space:]]*$')"
named="$(one '^[[:space:]]+name: teeth \(shard \$\{\{ matrix\.shard \}\} of ([0-9]+)\)[[:space:]]*$')"
if [ -z "$matrix" ] || [ -z "$shards" ] || [ -z "$named" ]; then
	printf 'FAIL: %s has no single teeth matrix, TEETH_SHARD divisor and shard name, so the shard count measured nothing.\n' "$workflow"
	exit 1
fi
expected=""
for i in $(seq 1 "$shards"); do expected="${expected:+$expected,}$i"; done
if [ "$matrix" != "$expected" ] || [ "$named" != "$shards" ]; then
	printf 'FAIL: the shard count in %s disagrees with itself: matrix [%s], TEETH_SHARD divisor %s, job name "of %s".\n' \
		"$workflow" "$matrix" "$shards" "$named"
	exit 1
fi

if [ ! -f "$harness" ]; then
	printf 'FAIL: %s does not exist, so the shards measured nothing.\n' "$harness"
	exit 1
fi

map="scripts/teeth-shards.tsv"
if [ ! -f "$map" ]; then
	printf 'FAIL: %s does not exist, so the balance of the shards measured nothing.\n' "$map"
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

# The map: every entry names a shard that exists, a case the harness has, and
# names it once. Entries are `shard<TAB>seconds<TAB>case`; lines starting with # are
# comments.
awk -F'\t' -v n="$shards" '
	$0 ~ /^#/ || $0 == "" { next }
	NF < 3 || $3 == "" { printf "FAIL: %s line %d does not have shard, seconds and a case name.\n", FILENAME, NR; bad = 1; next }
	$1 !~ /^[0-9]+$/ || $1 + 0 < 1 || $1 + 0 > n { printf "FAIL: %s line %d: \"%s\" is not a shard (the shards are 1 to %d).\n", FILENAME, NR, $1, n; bad = 1 }
	$2 !~ /^[0-9]+(\.[0-9]+)?$/ { printf "FAIL: %s line %d: \"%s\" is not a number of seconds.\n", FILENAME, NR, $2; bad = 1 }
	END { exit bad }
' "$map" || fail=1
awk -F'\t' '$0 !~ /^#/ && NF >= 3 && $3 != "" { print $3 }' "$map" | sort >"$work/map.names"
mapdups="$(uniq -d "$work/map.names")"
if [ -n "$mapdups" ]; then
	printf 'FAIL: %s names a case more than once, so its weight is counted twice:\n%s\n' "$map" "$mapdups"
	fail=1
fi
sort "$work/all" >"$work/all.sorted"
stale="$(comm -13 "$work/all.sorted" <(uniq "$work/map.names"))"
if [ -n "$stale" ]; then
	printf 'FAIL: %s names no case the harness has (renamed or removed since the map was made):\n%s\n' "$map" "$stale"
	fail=1
fi

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

# What the map says each shard weighs, in seconds: a figure to read, not a limit.
weights=""
for i in $(seq 1 "$shards"); do
	w="$(awk -F'\t' 'NR == FNR { if ($0 !~ /^#/ && NF >= 3) t[$3] = $2; next } ($0 in t) { s += t[$0] } END { printf "%d", s + 0 }' "$map" "$work/shard$i")"
	weights="$weights $w"
done

printf 'ok: %s cases, %s shards (from %s) with%s cases, each run by exactly one shard\n' "$full" "$shards" "$workflow" "$sizes"
printf 'the map (%s) weighs them, in seconds:%s\n' "$map" "$weights"
