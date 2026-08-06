#!/usr/bin/env bash
# The constants this repository publishes to the rest of the stack stay equal to
# the Rust they are generated from.
#
# WHY THIS EXISTS
#
# Every other repository in the estate that needs TokenFuse's wire vocabulary
# has taken it BY VALUE: somebody read the Rust and retyped the strings in
# another language. Reported 2026-08-06, verdryx's blocked-decision mirror held
# seven wire strings while BreakerReason had held nine since 2026-07-23, so for
# eleven days avoided estimates were counted as real spend. The copy was not
# wrong when it was written; nothing was watching it. That is invariant 12's
# shape one level up.
#
# `contracts/tokenfuse-constants.json` replaces the retyping. It is GENERATED,
# never hand-maintained, because a hand-written constants file is the original
# defect with an extra step: a file that can disagree with the constants it
# names. This script is what makes "generated" true after the commit that
# generated it.
#
# WHY IT BUILDS INSTEAD OF READING THE SOURCE AS TEXT
#
# The four text gates beside it parse Rust with regular expressions, and
# CLAUDE.md records what that costs: three of the four stopped matching while
# being written and reported success. There is no regex that can tell you what
# `EventType::severity` returns. So this one runs the real code and compares its
# output, which cannot half-match. The price is a build, and it is the right
# price for the one check whose whole job is that a value is what the code says
# it is.
#
# USAGE
#
#   ./scripts/constants.sh            check (what CI runs)
#   ./scripts/constants.sh --write    regenerate the committed artifact

set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 1

artifact="contracts/tokenfuse-constants.json"

work=$(mktemp -d) || exit 1
trap 'rm -rf "$work"' EXIT

# A read that established nothing exits distinctly from a real finding, for
# core-deps.sh's reason: both exit 1, and the difference is where they send the
# reader. "The artifact is stale" points at the artifact; this points here.
measured_nothing() {
	printf 'FAIL: this check measured nothing, so the artifact is UNVERIFIED here.\n'
	printf '      %s\n' "$1"
	printf '      Fix this script (or the environment) before trusting a green run.\n'
	exit 1
}

if ! command -v cargo >/dev/null 2>&1; then
	measured_nothing "\`cargo\` is not on PATH, so the constants were never generated."
fi

if ! cargo run --quiet -p tokenfuse-gateway --bin tokenfuse -- constants \
	>"$work/generated.json" 2>"$work/stderr"; then
	measured_nothing "\`tokenfuse constants\` did not run: $(tail -3 "$work/stderr" | tr '\n' ' ')"
fi

if [ ! -s "$work/generated.json" ]; then
	measured_nothing "\`tokenfuse constants\` printed nothing, so there was nothing to compare."
fi

if ! grep -q '"schema_version"' "$work/generated.json"; then
	measured_nothing "the generated document carries no schema_version, so this is not the artifact."
fi

if [ "${1:-}" = "--write" ]; then
	mkdir -p "$(dirname "$artifact")"
	cp "$work/generated.json" "$artifact"
	printf 'wrote %s from the Rust source.\n' "$artifact"
	exit 0
fi

if [ ! -f "$artifact" ]; then
	printf 'FAIL: %s does not exist.\n' "$artifact"
	printf '      Other repositories read that path. Generate it with:\n'
	printf '        ./scripts/constants.sh --write\n'
	exit 1
fi

if diff -u "$artifact" "$work/generated.json" >"$work/diff"; then
	entries=$(grep -c '"wire"' "$artifact")
	printf 'OK: %s matches the Rust source (%s breaker reasons published).\n' "$artifact" "$entries"
	exit 0
fi

printf 'FAIL: %s disagrees with the Rust it is generated from.\n\n' "$artifact"
sed 's/^/  /' "$work/diff"
printf '\nRegenerate it in the SAME commit as the change that moved it:\n'
printf '  ./scripts/constants.sh --write\n\n'
printf 'This file is what other repositories read instead of retyping these\n'
printf 'values. A stale copy here is the fault it exists to prevent, published.\n'
exit 1
