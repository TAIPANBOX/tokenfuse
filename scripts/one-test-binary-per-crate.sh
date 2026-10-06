#!/usr/bin/env bash
# Enforces invariant 78 of CLAUDE.md: a crate has ONE integration-test binary.
#
# WHY
#
# Cargo builds every file directly under a crate's `tests/` as a binary of its
# own, and each links the whole dependency graph. In the gateway that was about
# 28 binaries of 200 MB or more each, all of DataFusion inside every one, so a
# single `cargo test` after a one-line change relinked every one of them and
# wrote gigabytes to disk. Measured on a laptop: about 3.9 TB written by Rust
# builds of this estate in under seven days.
#
# So the integration tests of a crate live in `tests/it/`, as modules of
# `tests/it/main.rs`, and link once. This script fails as soon as a second
# binary appears, because nothing else would: a new `tests/foo.rs` compiles,
# passes, and quietly adds another full link to every test run.
#
# WHAT COUNTS AS A BINARY
#
# The two shapes cargo discovers on its own: a file `tests/<name>.rs`, and a
# directory `tests/<name>/main.rs`. Files deeper down (`tests/it/foo.rs`,
# `tests/it/common/mod.rs`) are modules, not binaries. A `[[test]]` entry whose
# `path` points anywhere else is not read; nothing in this repository has one,
# and a gate that parsed TOML with a regular expression to find one would be a
# second thing to keep true.
#
# The crates are DISCOVERED, every Cargo.toml under crates/ with a [package]
# section, including the nested workspaces (crates/cluster, crates/radar). A
# list of crates kept here would go stale at exactly the moment a crate is
# added, which is invariant 34's lesson.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# A binary that is deliberately its own. Each entry says why, here, because the
# exception has to travel with the rule rather than live in somebody's memory.
ALLOW=(
	# The raft-backed ledger test. `#![cfg(feature = "cluster")]`, declared as
	# a `[[test]]` with `required-features = ["cluster"]`, and run by its own
	# CI step (`cargo test -p tokenfuse-gateway --features cluster --test
	# cluster_backend`). Folding it into tests/it would rebuild the whole
	# shared binary with the cluster feature for that one step, and it binds
	# fixed ports (5599-5625) that nothing else in the gateway should share a
	# process with.
	"crates/gateway/tests/cluster_backend.rs"
)

fail=0
packages=0
binaries=0

for entry in "${ALLOW[@]}"; do
	if [ ! -f "$entry" ]; then
		printf 'STALE  %s\n       is allowed as a binary of its own and does not exist; drop it from the list\n' "$entry"
		fail=$((fail + 1))
	fi
done

allowed() {
	local e
	for e in "${ALLOW[@]}"; do [ "$e" = "$1" ] && return 0; done
	return 1
}

while IFS= read -r manifest; do
	grep -q '^\[package\]' "$manifest" || continue
	packages=$((packages + 1))
	dir="$(dirname "$manifest")"
	[ -d "$dir/tests" ] || continue
	found=()
	for f in "$dir"/tests/*.rs "$dir"/tests/*/main.rs; do
		[ -f "$f" ] || continue
		binaries=$((binaries + 1))
		allowed "$f" && continue
		found+=("$f")
	done
	if [ "${#found[@]}" -gt 1 ]; then
		printf '%s has %d integration-test binaries, and one is the rule:\n' "$dir" "${#found[@]}"
		printf '       %s\n' "${found[@]}"
		printf '       move each file into tests/it/ as a module of tests/it/main.rs,\n'
		printf '       or allow it here with the reason it has to be its own binary\n'
		fail=$((fail + 1))
	fi
done < <(find crates -name Cargo.toml -not -path '*/target/*' | sort)

if [ "$packages" -eq 0 ] || [ "$binaries" -eq 0 ]; then
	printf 'measured nothing: %d crates and %d integration-test binaries found under\n' "$packages" "$binaries" >&2
	printf 'crates/, which is a failure of this script and not a clean bill of health.\n' >&2
	exit 1
fi

printf 'one-test-binary-per-crate: %d crates, %d integration-test binaries (%d allowed apart), %d broken\n' \
	"$packages" "$binaries" "${#ALLOW[@]}" "$fail"
[ "$fail" -eq 0 ]
