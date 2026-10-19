#!/usr/bin/env bash
# The control plane holds its credentials by digest, never by the secret
# (CLAUDE.md invariant 133 for org keys, invariant 132 for device tokens).
#
# A map keyed by the raw secret makes every copy of the process state a list
# of live credentials, and a lookup keyed by the presented bearer is the
# natural place to add a second, raw, comparison later. This gate checks the
# shape where the mistake happens:
#
#   1. the digest function exists (if it is gone, the gate measured nothing);
#   2. every lookup into the org-key map (`keys.get(`) takes a `digest(`;
#   3. every access to the device map (`devices.get(`, `devices.insert(`)
#      takes a `digest(`;
#   4. parse_keys inserts by digest.
#
# It is textual. The behaviour (a raw token is not in a written snapshot, a
# migrated device still authenticates) is held by cargo test; this is the check
# a reviewer can run without building the crate. Comment lines are skipped.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

src="crates/cloud/src"
keys_rs="$src/keys.rs"

if [ ! -f "$keys_rs" ] || ! grep -q 'pub fn digest(' "$keys_rs"; then
	echo "FAIL: $keys_rs defines no digest function, so the gate measured nothing." >&2
	exit 1
fi

fail=0
seen=0

check_sites() {
	local pattern="$1" what="$2"
	local lines
	lines=$(grep -rn --include='*.rs' -E "$pattern" "$src" | grep -vE ':[0-9]+:[[:space:]]*//' || true)
	[ -z "$lines" ] && return 0
	while IFS= read -r line; do
		seen=$((seen + 1))
		if ! printf '%s\n' "$line" | grep -q 'digest('; then
			echo "FAIL: $what is looked up or stored by something other than a digest: $line" >&2
			fail=1
		fi
	done <<< "$lines"
}

check_sites 'keys\.get\(' "the org-key map"
check_sites 'devices\.(get|insert)\(' "the device map"

# parse_keys must key the map by digest. Its insert spans lines, so the first
# argument is the line after the `keys.insert(` opener.
inserts=$(grep -n 'keys\.insert(' "$keys_rs" | grep -vE '^[0-9]+:[[:space:]]*//' || true)
if [ -z "$inserts" ]; then
	echo "FAIL: $keys_rs no longer inserts org keys, so the gate measured nothing." >&2
	exit 1
fi
while IFS=: read -r lineno _; do
	seen=$((seen + 1))
	first_arg=$(sed -n "$((lineno + 1))p" "$keys_rs")
	if ! printf '%s\n' "$first_arg" | grep -q 'digest('; then
		echo "FAIL: parse_keys keys the map by something other than a digest, at $keys_rs:$lineno" >&2
		fail=1
	fi
done <<< "$inserts"

if [ "$seen" -eq 0 ]; then
	echo "FAIL: found no credential lookups or inserts, so the gate measured nothing." >&2
	exit 1
fi
if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "ok: $seen credential lookups and inserts in $src are by digest"
