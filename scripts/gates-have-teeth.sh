#!/usr/bin/env bash
# Checks that the gates in `scripts/` still FAIL on the faults they exist to
# catch, and still PASS on the things they must not catch.
#
# WHY
#
# Four gates hold four invariants, and every one of them parses text with
# regular expressions. That kind of parser does not break loudly: it stops
# matching and reports success. Three of the four broke exactly that way while
# being written, and each time the only reason anybody noticed was that a mutant
# was supposed to fail and did not.
#
# So the mutants existed as prose in commit messages and in the `*(gate: ...)*`
# markers in CLAUDE.md, which is a record of what was true once. Nothing ran
# them again. A gate that has quietly stopped catching anything looks exactly
# like a gate with nothing to catch, and it stays that way until the fault it
# was written for ships.
#
# HOW IT MUTATES WITHOUT LEAVING A MESS
#
# It edits tracked files in place, so it refuses to start unless the tree is
# clean, restores with `git checkout` after every case, restores again from a
# trap on any exit path including a kill, and asserts the tree is clean before
# reporting success. If this script ever leaves residue, its own last check
# fails and says so.
#
# A MUTATION THAT DID NOT APPLY PROVES NOTHING
#
# Every edit below asserts it changed the file, and a case whose edit applied
# nothing is a failure rather than a pass. That is not hypothetical either: an
# early mutant here edited zero bytes because the string it looked for was not
# in the manifest in the form assumed, and reported a clean run.

set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 1

if [ -n "$(git status --porcelain)" ]; then
	printf 'this script mutates tracked files, so it needs a clean tree.\n'
	printf 'commit or stash first; it restores with `git checkout` and cannot\n'
	printf 'tell your edits from its own.\n'
	exit 1
fi

restore() { git checkout -- . 2>/dev/null; }
trap restore EXIT INT TERM

failures=0
cases=0

# run_case <name> <expect: fail|pass> <gate> <python edit> [required output]
#
# The optional last argument is what separates "it failed" from "it failed for
# the reason this case is about". Without it, a case that expects a failure is
# satisfied by any failure at all, including one caused by the harness itself.
run_case() {
	local name="$1" expect="$2" gate="$3" edit="$4" needle="${5:-}"
	cases=$((cases + 1))

	if ! python3 -c "$edit"; then
		printf 'BROKEN  %s\n        its mutation did not apply, so this case proved nothing\n' "$name"
		failures=$((failures + 1))
		restore
		return
	fi

	# shellcheck disable=SC2086
	local out
	out=$(eval "$gate" 2>&1)
	local rc=$?
	restore

	# Exit code first. A needle checked before the expectation turns "it did not
	# fail at all" into "it failed for the wrong reason", which is a worse
	# diagnosis than the fault: it sends the reader looking at wording when the
	# gate is toothless. This harness reported exactly that on its own new cases.
	if [ "$expect" = fail ] && [ "$rc" -ne 0 ] && [ -n "$needle" ] &&
		! printf '%s' "$out" | grep -qF -- "$needle"; then
		printf 'WRONG REASON  %s\n              it failed, but not saying %s\n' "$name" "$needle"
		failures=$((failures + 1))
		return
	fi

	if [ "$expect" = fail ] && [ "$rc" -eq 0 ]; then
		printf 'TOOTHLESS  %s\n           the gate passed on a fault it exists to catch\n' "$name"
		failures=$((failures + 1))
	elif [ "$expect" = pass ] && [ "$rc" -ne 0 ]; then
		printf 'OVEREAGER  %s\n           the gate failed on something it must not catch\n' "$name"
		failures=$((failures + 1))
	else
		printf 'ok  %-58s (%s)\n' "$name" "$expect"
	fi
}

# A tiny helper for the edits: replace once, and prove it happened.
py() { printf 'import sys\ndef edit(p, a, b):\n    s = open(p).read()\n    assert a in s, "pattern not found in " + p\n    open(p, "w").write(s.replace(a, b, 1))\ndef edit_all(p, a, b):\n    s = open(p).read()\n    assert a in s, "pattern not found in " + p\n    open(p, "w").write(s.replace(a, b))\n%s\n' "$1"; }

# --- invariant 1: core stays dependency-minimal ----------------------------

run_case "core-deps: a dependency core is not allowed" fail \
	"./scripts/core-deps.sh" \
	"$(py 'edit("crates/core/Cargo.toml", "sha2 = \"0.10\"", "sha2 = \"0.10\"\nutoipa = \"5\"")')"

run_case "core-deps: an allowed dependency removed" fail \
	"./scripts/core-deps.sh" \
	"$(py 'edit("crates/core/Cargo.toml", "regex = \"1\"", "")')"

# No mutation: the fault is the environment, so the edit is a no-op that still
# has to be a real statement for the harness to accept it.
run_case "core-deps: cargo missing, so it measured nothing" fail \
	"env PATH=/usr/bin:/bin ./scripts/core-deps.sh" \
	"pass" \
	"measured nothing"

# --- invariant 3: core types stay behind the Cloud DTO boundary ------------

run_case "dto-boundary: a core type on a DTO through value_type" fail \
	"./scripts/dto-boundary.sh" \
	"$(py 'edit("crates/cloud/src/http.rs", "struct BudgetBody {\n    budget_usd: f64,", "struct BudgetBody {\n    budget_usd: f64,\n    #[schema(value_type = String)]\n    entry: tokenfuse_core::audit::AuditEntry,")')"

run_case "dto-boundary: an exception whose reason stopped holding" fail \
	"./scripts/dto-boundary.sh" \
	"$(py 'edit("crates/core/src/mcpreport.rs", "pub enum Severity {", "pub enum Severity {\n    Custom(String),")')" \
	"has stopped being true"

# --- invariant 5: the replicated ledger keeps its recorded shape -----------

run_case "replicated-shape: a field added to the replicated state" fail \
	"./scripts/replicated-shape.sh" \
	"$(py 'edit("crates/cluster/src/types.rs", "    pub steps: u32,", "    pub steps: u32,\n    pub tenant: String,")')"

run_case "replicated-shape: a type renamed, so it measured nothing" fail \
	"./scripts/replicated-shape.sh" \
	"$(py 'edit("crates/cluster/src/types.rs", "pub struct RunState {", "pub struct RunAccounting {")')" \
	"cannot be checked"

# --- invariant 12: stated numbers match the repository ---------------------

# The mutant reads the badge and adds one, rather than naming today's figure.
# It used to name it, and that made this case break every time the suite grew:
# the count moved to 757, the pattern stopped matching, and the harness reported
# BROKEN on a gate that was working. A case that has to be edited whenever the
# thing it watches changes is a case somebody deletes.
badge_now=$(grep -o 'badge/tests-[0-9]*-' README.md | head -1)
badge_next="badge/tests-$(($(printf '%s' "$badge_now" | tr -dc '0-9') + 1))-"

run_case "stated-numbers: the badge disagrees with the suite" fail \
	"./scripts/stated-numbers.sh" \
	"$(py "edit(\"README.md\", \"$badge_now\", \"$badge_next\")")"

# The one case that must NOT fail. PROGRESS.md is prose that will keep quoting
# older counts while explaining how they drifted, and reading the whole file
# once made this gate fail on a paragraph recording its own history lesson.
run_case "stated-numbers: an old count quoted in prose elsewhere" pass \
	"./scripts/stated-numbers.sh" \
	"$(py 'edit("PROGRESS.md", "## Current stage", "Once **512 passing**, now more.\n\n## Current stage")')"

# --- invariant 4: claims about coverage stay recorded ----------------------

run_case "honest-claims: a control upgraded, which is over-claiming" fail \
	"./scripts/honest-claims.sh" \
	"$(py 'edit("crates/core/src/compliance.rs", "enforcement: Enforcement::Partial", "enforcement: Enforcement::Enforced")')" \
	"UPGRADED"

run_case "honest-claims: README stops stating a limitation" fail \
	"./scripts/honest-claims.sh" \
	"$(py 'edit_all("README.md", "fail-open", "resilient-mode"); edit_all("README.md", "Fail-open", "Resilient-mode")')" \
	"no longer states"

run_case "honest-claims: the catalog parse broke, so it measured nothing" fail \
	"./scripts/honest-claims.sh" \
	"$(py 'edit_all("crates/core/src/compliance.rs", "control_id:", "control_ident:")')" \
	"measured nothing"

# --- invariant 16: a documented command can start a gateway ----------------

run_case "runnable-quickstart: the headline command loses its flag" fail \
	"./scripts/runnable-quickstart.sh" \
	"$(py 'edit("README.md", "docker run -p 4100:4100 -e TOKENFUSE_ALLOW_STUB=1 ghcr.io/taipanbox/tokenfuse", "docker run -p 4100:4100 ghcr.io/taipanbox/tokenfuse")')" \
	"cannot start a gateway"

# The compose stack is the case that would have failed on somebody else's
# machine rather than in a document, so it gets its own case.
run_case "runnable-quickstart: the compose gateway loses its flag" fail \
	"./scripts/runnable-quickstart.sh" \
	"$(py 'edit("cloud/docker-compose.yml", "      TOKENFUSE_ALLOW_STUB: \"1\"", "")')" \
	"crash-loops"

# The one that must NOT fire, carrying both exclusions. `tokenfuse mcp-scan`,
# `tokenfuse top` and `tokenfuse constants` share the binary with the gateway
# and need no provider; and a line with an ellipsis is prose ABOUT a command,
# which this repository writes a great deal of, since the fault the gate exists
# for has to be explained somewhere. A gate that flags either is deleted by
# whoever is unblocking CI.
run_case "runnable-quickstart: a subcommand and a prose ellipsis" pass \
	"./scripts/runnable-quickstart.sh" \
	"$(py 'edit("README.md", "## 📜 License", "```bash\ndocker run ghcr.io/taipanbox/tokenfuse mcp-scan --url https://mcp.example.com/rpc\n```\n\nRunning `docker run ... ghcr.io/taipanbox/tokenfuse` with no provider exits 2.\n\n## 📜 License")')"

run_case "runnable-quickstart: the compose image renamed, so it measured nothing" fail \
	"./scripts/runnable-quickstart.sh" \
	"$(py 'edit("cloud/docker-compose.yml", "image: ghcr.io/taipanbox/tokenfuse:latest", "image: ghcr.io/taipanbox/tokenfuse-gw:latest")')" \
	"measured nothing"

# --- the published stack constants match the Rust --------------------------
#
# The odd one out among the gates: it BUILDS instead of parsing text, so this
# case costs a recompile of core and the gateway. That is the right price for
# the one check whose whole job is that a published value is what the code says
# it is, and no regex can ask `EventType::severity` what it returns.
#
# The mutation is the fault this exists for, in the form it actually arrives:
# somebody edits a wire string and does not regenerate the file other
# repositories read. The needle keeps a failed BUILD from passing as a caught
# fault, which would be the toothless case wearing the right exit code.

run_case "constants: a wire string changed without regenerating" fail \
	"./scripts/constants.sh" \
	"$(py 'edit("crates/core/src/breaker.rs", "BreakerReason::LoopDetected => \"loop_detected\",", "BreakerReason::LoopDetected => \"loop_detected_v2\",")')" \
	"disagrees with the Rust"

# --- the harness cleans up after itself ------------------------------------

restore
if [ -n "$(git status --porcelain)" ]; then
	printf '\nthis script left the tree dirty, which means a case restored badly:\n'
	git status --porcelain
	failures=$((failures + 1))
fi

if [ "$failures" -gt 0 ]; then
	printf '\n%d of %d cases did not behave. A gate that stopped catching its fault\n' "$failures" "$cases"
	printf 'looks exactly like a gate with nothing to catch, which is why this runs.\n'
	exit 1
fi

printf '\n%d cases: every gate still fails on its fault and passes on what it must not catch.\n' "$cases"
