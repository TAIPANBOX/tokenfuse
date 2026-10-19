#!/usr/bin/env bash
# The gateway's client keys are looked up by a digest, and the declassify key is
# compared in constant time (CLAUDE.md invariant 134, finding F-023 of the
# 2026-10-17 agent-security review).
#
# WHY THIS EXISTS
#
# `ClientKeys` was a `HashMap<String, String>` keyed by the configured secret,
# and the declassify key was compared with `==`. Neither is a secret the gateway
# should hold or compare in the clear. The fix keys the map by SHA-256 of each
# secret and compares secrets with `subtle::ConstantTimeEq`. The regression this
# gate exists for is the map being keyed by the raw secret again, or the
# declassify comparison being written as `==`: both compile, both pass every
# behavioural test that sends a correct key, and neither is visible in a run.
#
# WHAT IT CHECKS
#
# Literal facts in the code of two files. Line comments are stripped first, so a
# comment that names the old shape does not count either way.
#   1. crates/gateway/src/clientkeys.rs, the code before its test module, declares
#      the lookup map as `by_digest: HashMap<[u8; 32], String>`;
#   2. that same code contains no `HashMap<String` (no map keyed by text);
#   3. the digest is SHA-256 of the secret's bytes;
#   4. crates/gateway/src/declassify.rs compares the presented key with
#      `clientkeys::secret_eq` and not with `==`.
#
# WHAT IT REFUSES TO PASS ON
#
# Either file missing, or the literal facts absent: a clean read measured nothing,
# and it says so with exit 1 rather than reporting success.
#
# WHAT IT DOES NOT CHECK
#
# That every other comparison of a presented secret in the gateway is constant
# time: the closure token and the MCP session tag are verified with the hmac
# crate, and `crate::adminkeys::AdminKeys::matches` compares each key in constant
# time but stops at the first key that matches. A new map keyed by a raw secret
# in some other file is not seen. The gate reads two files' literal text.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

keys="crates/gateway/src/clientkeys.rs"
declassify="crates/gateway/src/declassify.rs"

for f in "$keys" "$declassify"; do
	if [ ! -f "$f" ]; then
		printf 'FAIL: %s is not there, so this gate measured nothing.\n' "$f"
		exit 1
	fi
done

# The code of clientkeys.rs before its test module, with line comments removed.
code=$(awk '/^#\[cfg\(test\)\]/ { exit } { print }' "$keys" | sed 's://.*$::')

fail=0

if ! grep -qF -- 'by_digest: HashMap<[u8; 32], String>,' <<<"$code"; then
	printf 'FAIL: %s no longer declares its lookup map as by_digest: HashMap<[u8; 32], String>, so this gate measured nothing.\n' "$keys"
	exit 1
fi

if grep -qF -- 'HashMap<String' <<<"$code"; then
	printf 'FAIL: %s has a map keyed by text, which is a map keyed by the raw secret. Key it by the SHA-256 digest of the secret.\n' "$keys"
	fail=1
fi

if ! grep -qF -- 'Sha256::digest(secret.as_bytes())' <<<"$code"; then
	printf 'FAIL: %s does not compute the lookup key as SHA-256 of the secret, so the digest is not what the map holds.\n' "$keys"
	fail=1
fi

decl=$(sed 's://.*$::' "$declassify")
if ! grep -qF -- 'crate::clientkeys::secret_eq(want, got)' <<<"$decl"; then
	printf 'FAIL: %s does not compare the declassify key with clientkeys::secret_eq, so the comparison is not in constant time.\n' "$declassify"
	fail=1
fi

if grep -qF -- 'want == got' <<<"$decl"; then
	printf 'FAIL: %s compares the declassify key with ==, which is not in constant time.\n' "$declassify"
	fail=1
fi

if [ "$fail" -ne 0 ]; then
	exit 1
fi

printf 'ok: client keys are looked up by digest, and the declassify key is compared in constant time.\n'
