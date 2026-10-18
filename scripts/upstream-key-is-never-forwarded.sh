#!/usr/bin/env bash
# A brokered gateway never forwards the caller's own provider credential
# (CLAUDE.md invariant 122, finding F-002 of the 2026-10-17 agent-security review).
#
# WHY THIS EXISTS
#
# Until invariant 122 the gateway forwarded the caller's `authorization` and
# `x-api-key` upstream unchanged, so an agent that held the provider key called
# the provider directly and nothing metered that call. The fix is one copy loop
# in `HttpProvider::send`: when the gateway holds the provider key it skips the
# two credential headers in `PROVIDER_CREDENTIAL_HEADERS` and sends its own key
# instead. The regression this gate exists for is that loop being edited so the
# skip no longer happens when the key is held, which compiles, passes every
# test that does not send a provider key, and reopens the bypass.
#
# WHAT IT CHECKS
#
# In crates/gateway/src/provider.rs, three literal facts:
#   1. the list of credential headers is exactly authorization and x-api-key;
#   2. inside `async fn send`, the copy loop skips a credential header only when
#      the gateway holds the key (`self.upstream_key.is_some()`), so an
#      unbrokered gateway forwards exactly as it did before;
#   3. the gateway's own key is sent upstream from `self.upstream_key`.
#
# WHAT IT REFUSES TO PASS ON
#
# provider.rs missing, or any of the three literals absent: the copy loop it
# guards is gone or renamed, so a clean read measured nothing. Exit 1 and say so.
#
# WHAT IT DOES NOT CHECK
#
# That the caller's credential is refused before it reaches `send` (the
# integration tests `a_caller_supplied_x_api_key_is_refused_when_brokered` and
# `a_caller_supplied_provider_key_never_reaches_the_upstream` hold that), or that
# the skip covers a header another future line adds to the forward list. The
# structural check reads the literal text only.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

owner="crates/gateway/src/provider.rs"

if [ ! -f "$owner" ]; then
	printf 'FAIL: %s is not there, so this gate measured nothing.\n' "$owner"
	exit 1
fi

fail=0

if ! grep -qF -- 'const PROVIDER_CREDENTIAL_HEADERS: &[&str] = &["authorization", "x-api-key"];' "$owner"; then
	printf 'FAIL: %s no longer declares PROVIDER_CREDENTIAL_HEADERS as authorization and x-api-key, so this gate measured nothing.\n' "$owner"
	exit 1
fi

# The body of `async fn send` in `impl Provider for HttpProvider` (the trait
# declares one too), from its signature to the first line that closes a
# four-space-indented block after it. The guard must be inside it.
send_body=$(awk '
	/^impl Provider for HttpProvider \{/ { in_impl = 1 }
	in_impl && /^    async fn send\(/ { inside = 1 }
	inside { print }
	inside && /^    }$/ { exit }
' "$owner")

if [ -z "$send_body" ]; then
	printf 'FAIL: %s has no `async fn send`, so this gate measured nothing.\n' "$owner"
	exit 1
fi

guard='if self.upstream_key.is_some() && PROVIDER_CREDENTIAL_HEADERS.contains(name) {'
if ! printf '%s\n' "$send_body" | grep -qF -- "$guard"; then
	printf 'FAIL: the copy loop in HttpProvider::send no longer skips the caller'\''s provider credential when the gateway holds the key.\n'
	printf '      expected, inside send: %s\n' "$guard"
	fail=1
fi

if ! printf '%s\n' "$send_body" | grep -qF -- 'if let Some(key) = &self.upstream_key {'; then
	printf 'FAIL: HttpProvider::send no longer sends the gateway'\''s own key from self.upstream_key.\n'
	fail=1
fi

if ! printf '%s\n' "$send_body" | grep -qF -- 'let (name, value) = key.header();'; then
	printf 'FAIL: HttpProvider::send no longer takes the upstream header from key.header().\n'
	fail=1
fi

if [ "$fail" -ne 0 ]; then
	printf '\nThe caller'\''s provider credential must never leave a brokered gateway (invariant 122).\n'
	exit 1
fi

printf 'OK: %s skips the caller'\''s provider credential only when the gateway holds the key, and sends the key from the gateway.\n' "$owner"
