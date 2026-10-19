#!/usr/bin/env bash
# The standalone dashboard connects with an org key read from the URL. A query
# parameter is sent to the server, lands in access logs and in Referer headers;
# a URL fragment is not sent at all (CLAUDE.md invariant 133). This gate holds
# the connect page to three things:
#
#   1. the fragment is read, and it is read BEFORE the query, so a fragment key
#      is the one that wins;
#   2. the query is still read, for links made before the fragment existed;
#   3. the key is stripped from the address bar once read (history.replaceState),
#      so it does not sit in the browser history or get pasted into a ticket.
#
# It is textual: the page has no test harness and the steps are a shape, not a
# behaviour. The Rust test in crates/cloud/tests/it/dashboard_page.rs reads the
# same file; this script is the one a reviewer runs without cargo.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

page="cloud/dashboard/app/page.tsx"

if [ ! -f "$page" ]; then
	echo "FAIL: $page is missing, so the gate measured nothing." >&2
	exit 1
fi

fail=0

frag_line=$(grep -n 'location\.hash' "$page" | head -1 | cut -d: -f1)
query_line=$(grep -n 'location\.search' "$page" | head -1 | cut -d: -f1)

if [ -z "$frag_line" ]; then
	echo "FAIL: $page never reads location.hash, so a key in the fragment is ignored" >&2
	fail=1
fi
if [ -z "$query_line" ]; then
	echo "FAIL: $page no longer reads location.search, so old ?key= links break" >&2
	fail=1
fi
if [ -n "$frag_line" ] && [ -n "$query_line" ] && [ "$frag_line" -ge "$query_line" ]; then
	echo "FAIL: $page reads the query (line $query_line) before the fragment (line $frag_line)" >&2
	fail=1
fi
if ! grep -q 'history\.replaceState' "$page"; then
	echo "FAIL: $page never strips the key from the address bar (history.replaceState)" >&2
	fail=1
fi

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "ok: $page reads the key from the fragment first, the query second, and strips it"
