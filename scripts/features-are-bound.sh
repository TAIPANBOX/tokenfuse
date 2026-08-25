#!/usr/bin/env bash
# Every scenario in features/ names a test that exists, and every scenario
# names one at all.
#
# WHY BOTH DIRECTIONS
#
# A scenario with no binding is a paragraph describing what somebody wanted,
# and it proves nothing about what the code does. A binding pointing at a test
# that has been renamed or deleted is worse than none: it reads as held, and a
# reader has no way to tell without grepping.
#
# WHY NOT A BDD RUNNER
#
# cucumber-rs here, godog in the Go repos, pytest-bdd in the Python ones: three
# runners and three step-definition styles across an estate that would gain, in
# exchange, the readability it already gets from the binding. The value asked
# for is that the Given/When/Then can be read INSTEAD of the diff. This
# delivers that at a fraction of the surface. `@claude`, and a deviation from a
# literal reading of the ask; overruling it means wiring a real runner.
#
# WHAT THIS DOES NOT DO
#
# It does not check that the test ASSERTS what the scenario says, and nothing
# mechanical can: the steps are prose and the binding is a pointer. What it
# catches is the pointer breaking, which is the failure that happens on its
# own while nobody is looking.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

if [ ! -d features ]; then
	echo "no features/ directory: nothing to check, and that is not a pass." >&2
	exit 1
fi

fail=0
scenarios=0
bindings=0

while IFS= read -r file; do
	pending=""
	lineno=0
	while IFS= read -r line; do
		lineno=$((lineno + 1))
		case "$line" in
		*@test:*)
			t="${line##*@test:}"
			t="${t%% *}"
			pending="$pending $t"
			bindings=$((bindings + 1))
			# `fn name(` covers both the in-module `#[test]`/`#[tokio::test]`
			# functions and the ones in crates/*/tests/. `async fn` matches
			# too, because the needle is the `fn name(` substring.
			if ! grep -rq --include='*.rs' "fn ${t}(" crates/ 2>/dev/null; then
				printf 'DANGLING  %s:%s\n          @test:%s names no test\n' \
					"$file" "$lineno" "$t"
				fail=$((fail + 1))
			fi
			;;
		*Scenario:*)
			scenarios=$((scenarios + 1))
			if [ -z "$pending" ]; then
				printf 'UNBOUND   %s:%s\n          %s\n          no @test: above it, so it proves nothing\n' \
					"$file" "$lineno" "$(printf '%s' "$line" | sed 's/^ *//')"
				fail=$((fail + 1))
			fi
			pending=""
			;;
		esac
	done <"$file"
done < <(find features -name '*.feature' | sort)

# The other direction that matters: a feature file with no scenarios at all is
# one somebody started and left, and it would pass everything above.
for f in features/*.feature; do
	if ! grep -q "Scenario:" "$f"; then
		printf 'EMPTY     %s\n          a feature file with no scenarios\n' "$f"
		fail=$((fail + 1))
	fi
done

echo
if [ "$scenarios" -eq 0 ]; then
	echo "measured nothing: no scenarios found, which is a failure of this" >&2
	echo "script and not a clean bill of health." >&2
	exit 1
fi
printf 'features: %d scenarios, %d bindings, %d broken\n' "$scenarios" "$bindings" "$fail"
[ "$fail" -eq 0 ]
