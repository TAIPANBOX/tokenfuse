#!/usr/bin/env bash
# A label an enforcement point reports comes from the act it saw and never from a
# name (CLAUDE.md invariant 143).
#
# WHY THIS EXISTS
#
# A run's history is the conversation the caller sends, so the source map's labels
# answer "has this run touched an untrusted source" from a string the agent wrote.
# The observed act is the one path where the answer does not depend on that string:
# the broker knows which server answered because it made the connection. That holds
# only while no name reaches the path, and a change that lets one in compiles, keeps
# every test that does not rename a tool, and hands the agent back the rename. The
# same goes for the broker reporting after the answer has already left, and for a
# classification looked up by the name a request chose rather than the server it
# reached, which a default route then walks around.
#
# WHAT IT CHECKS
#
# In crates/gateway/src/observedact.rs, comments and tests masked: `ObservedAct` is
# closed (`deny_unknown_fields`) and its members are exactly run_id, labels and
# source, and nothing reads the name map (`labels_for_tools`, `firewall.sources`).
# In crates/gateway/src/mcpbroker.rs: `report_observed_act(` takes no tool and reads
# none; `fn classified(` looks the upstream up through `upstream_key(` and reads no
# request context; in `async fn process_into(`, the report comes after the upstream
# answered (`upstream_reply(`) and before the first thing that can return the answer
# (the tool-listing checks), and the refusal of a call that names no run comes before
# the taint gate and the forward.
#
# WHAT IT REFUSES TO PASS ON
#
# Either file gone, or an anchor gone: the scan measured nothing. Exit 1 and say so.
#
# WHAT IT DOES NOT CHECK
#
# That the labels reach the run, that a refusal is acted on, or that the gateway
# judges on them: tests/it/observed_act.rs holds those over the real broker and the
# real router. Which server an operator classified is configuration.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

act="crates/gateway/src/observedact.rs"
broker="crates/gateway/src/mcpbroker.rs"
fail=0

for f in "$act" "$broker"; do
	if [ ! -f "$f" ]; then
		printf 'FAIL: %s is not there, so this gate measured nothing.\n' "$f"
		exit 1
	fi
done

# Everything before the test module, each line prefixed with its number and with
# any `//` comment cut off.
production() {
	awk '
		/^#\[cfg\(test\)\]/ { exit }
		{ line = $0; sub(/\/\/.*$/, "", line); print NR "\t" line }
	' "$1"
}

# The body of a top-level item: from the line that starts with $2 to the first line
# that is exactly "}".
body() {
	production "$1" | awk -F'\t' -v sig="$2" '
		index($2, sig) == 1 { f = 1 }
		f { print }
		f && $2 == "}" { exit }
	'
}

first() {
	printf '%s\n' "$1" | grep -F -- "$2" | head -1 | cut -f1
}

dto=$(body "$act" "pub struct ObservedAct")
if [ -z "$dto" ]; then
	printf 'FAIL: %s has no `pub struct ObservedAct`, so this gate measured nothing.\n' "$act"
	exit 1
fi
members=$(printf '%s\n' "$dto" | sed -n 's/^[0-9]*[[:space:]]*pub \([a-z_]*\):.*/\1/p' | sort | tr '\n' ' ')
if [ "$members" != "labels run_id source " ]; then
	printf 'FAIL: ObservedAct carries [%s], and it carries run_id, labels and source and nothing else.\n' "$members"
	printf '      A member here is something a caller can write: a name that arrives at this route is the defect.\n'
	fail=1
fi
if ! production "$act" | grep -qF "deny_unknown_fields"; then
	printf 'FAIL: ObservedAct is not closed, so a tool name sent here would be dropped and look read.\n'
	fail=1
fi
if production "$act" | grep -qE 'labels_for_tools|firewall\.sources'; then
	printf 'FAIL: %s reads a name: the name map has no part in an observed act.\n' "$act"
	fail=1
fi

report=$(body "$broker" "async fn report_observed_act(")
if [ -z "$report" ]; then
	printf 'FAIL: %s has no `async fn report_observed_act(`, so this gate measured nothing.\n' "$broker"
	exit 1
fi
if printf '%s\n' "$report" | grep -qE '\btool\b'; then
	printf 'FAIL: report_observed_act takes the tool, and the label must not be able to depend on it.\n'
	fail=1
fi

classified=$(body "$broker" "fn classified<")
if [ -z "$classified" ]; then
	printf 'FAIL: %s has no `fn classified<`, so this gate measured nothing.\n' "$broker"
	exit 1
fi
if ! printf '%s\n' "$classified" | grep -qF "upstream_key(" || printf '%s\n' "$classified" | grep -qF "ctx"; then
	printf 'FAIL: a classification is looked up by the server a call reaches, not by the route it named.\n'
	fail=1
fi

process=$(body "$broker" "async fn process_into(")
answered=$(first "$process" "upstream_reply(")
listing=$(first "$process" 'if method == "tools/list" && st.scan')
gate=$(first "$process" "taint_gate(st, ctx")
if [ -z "$process" ] || [ -z "$answered" ] || [ -z "$listing" ] || [ -z "$gate" ]; then
	printf 'FAIL: %s has no `async fn process_into(` with its anchors, so this gate measured nothing.\n' "$broker"
	exit 1
fi
reported=$(first "$process" "report_observed_act(st, ctx")
if [ -z "$reported" ]; then
	printf 'FAIL: process_into never reports what a classified upstream answered.\n'
	fail=1
elif [ "$reported" -lt "$answered" ] || [ "$reported" -gt "$listing" ]; then
	printf 'FAIL: the report is at line %s and belongs between the answer (%s) and the listing checks (%s).\n' \
		"$reported" "$answered" "$listing"
	fail=1
fi
no_run=$(first "$process" "observed.is_some() && record_run_id(ctx).is_none()")
if [ -z "$no_run" ] || [ "$no_run" -gt "$gate" ]; then
	printf 'FAIL: a call to a classified upstream that NAMES NO RUN is refused before the taint gate.\n'
	fail=1
fi

if [ "$fail" -ne 0 ]; then
	exit 1
fi
printf 'OK: the label an enforcement point reports comes from the server that answered, before the answer leaves.\n'
