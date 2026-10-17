#!/usr/bin/env bash
# The attestation method the policy plane is told is derived from the door,
# never read from the caller's header (CLAUDE.md invariant 116).
#
# WHY THIS EXISTS
#
# Until 2026-10-17 both doors copied `x-fuse-attestation-method` from the
# request into the question put to wardryx, so a `deny_if_unattested` policy
# admitted any caller that wrote `spiffe-svid` (agent-security review, F-005).
# The fix is one module, `crates/gateway/src/attestation.rs`, which derives the
# method from what the door verified and reads the header only to say, once,
# that it is ignored. The regression this gate exists for is somebody reading
# the header again at a call site, which compiles, passes every test that does
# not send the header, and reopens the hole.
#
# WHAT IT CHECKS
#
# In every Rust file under crates/gateway/src other than attestation.rs, no
# line outside a comment names the header, either as the string literal or as
# `attestation::CLIENT_HEADER`. Either is a way to read it.
#
# WHAT IT REFUSES TO PASS ON
#
# attestation.rs missing, or no longer carrying the literal: the module that
# owns the header is gone or renamed, so a clean scan of the rest measured
# nothing. Exit 1 and say so.
#
# WHAT IT DOES NOT CHECK
#
# That `from_door` is given the right fact at each call site: the integration
# tests hold that (`a_client_attestation_header_never_reaches_the_pdp`,
# `the_broker_never_tells_the_pdp_an_attestation_the_caller_wrote` and the two
# dpop-key tests). A header read through a name built at runtime is not seen.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

owner="crates/gateway/src/attestation.rs"
literal='"x-fuse-attestation-method"'

if [ ! -f "$owner" ]; then
	printf 'FAIL: %s is not there, so this gate measured nothing.\n' "$owner"
	exit 1
fi
if ! grep -qF -- "$literal" "$owner"; then
	printf 'FAIL: %s no longer names %s, so this gate measured nothing.\n' "$owner" "$literal"
	exit 1
fi

found=0
scanned=0
while IFS= read -r f; do
	[ "$f" = "$owner" ] && continue
	scanned=$((scanned + 1))
	hits=$(grep -nE -- "\"x-fuse-attestation-method\"|attestation::CLIENT_HEADER" "$f" |
		grep -vE '^[0-9]+:[[:space:]]*//' || true)
	if [ -n "$hits" ]; then
		while IFS= read -r h; do
			printf 'READS THE HEADER  %s:%s\n' "$f" "$h"
		done <<<"$hits"
		found=$((found + 1))
	fi
done < <(git ls-files 'crates/gateway/src/*.rs')

if [ "$scanned" -eq 0 ]; then
	printf 'FAIL: no Rust file under crates/gateway/src to scan, so this gate measured nothing.\n'
	exit 1
fi

if [ "$found" -gt 0 ]; then
	printf '\n%d file(s) read x-fuse-attestation-method outside %s.\n' "$found" "$owner"
	printf 'The attestation the policy plane is told comes from the door (invariant 116):\n'
	printf 'use crate::attestation::from_door, never the caller'"'"'s header.\n'
	exit 1
fi

printf 'OK: %d file(s) scanned; only %s names x-fuse-attestation-method.\n' "$scanned" "$owner"
