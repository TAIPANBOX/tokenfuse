#!/usr/bin/env bash
# One binary, two processes: `tokenfuse` (the LLM proxy, `serve`) and
# `tokenfuse mcp-broker` (the MCP door, `mcp_broker`). Each reads its own
# environment at its own startup, and each builds its own state struct.
#
# WHAT THIS CATCHES, and it is not hypothetical
#
# Measured 2026-08-26: `chainproof::from_env()` was called in `mcp_broker` and
# nowhere else. The proxy's `AppState.chain_proof` was set to `None` by
# `AppState::new` and by nothing after it, so `chainproof::resolve` at
# proxy.rs ran on every request against a `None` config and returned
# `Chain::Claimed` every time. The delegation door existed at both call sites,
# had tests at both, and was switched on at one. Nothing said so: the code
# reads identically at the two doors, and the difference lives a thousand lines
# away in a function the diff never touched.
#
# That is the shape here. A door added to one process and forgotten in the
# other is invisible in review, because what is missing is a line nobody wrote.
#
# HOW THE SUBJECTS ARE FOUND, which is the point
#
# By DISCOVERY, never from a list in this file. A gate carrying its own list of
# what to check is itself unchecked: the list is what goes stale, and it goes
# stale silently the moment somebody adds the thing it was supposed to notice.
# So every `<module>::from_env(` call in main.rs is found, and which of the two
# process functions it sits in comes from the line numbers.
#
# THE EXCEPTION, and where it has to live
#
# Some doors are legitimately one-sided: the broker has no model router and no
# prompt firewall, because it never sees a prompt. Rather than list those here,
# the reason is required AT THE CALL SITE, as a `process-local:` comment within
# six lines above it. The exception then travels with the code that needs it and
# is read by whoever changes that code, instead of sitting in a script they have
# no reason to open.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PY'
import re, sys

SRC = "crates/gateway/src/main.rs"
PROCESSES = ("serve", "mcp_broker")

lines = open(SRC).read().split("\n")
fn_at = {}
current = None
for i, line in enumerate(lines, 1):
    m = re.match(r"^(?:pub )?(?:async )?fn ([a-z_][a-z0-9_]*)", line)
    if m:
        current = m.group(1)
    fn_at[i] = current

found = {}
for i, line in enumerate(lines, 1):
    if line.lstrip().startswith("//"):
        continue
    for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)::from_env\(", line):
        if fn_at[i] in PROCESSES:
            found.setdefault(m.group(1), {}).setdefault(fn_at[i], i)

if not found:
    print(f"no `<module>::from_env(` call was found in {SRC} at all, so this")
    print("gate measured nothing. Either the startup wiring moved or this")
    print("script's discovery broke; both need a person, and neither is a pass.")
    sys.exit(1)

def reason_above(line_no):
    for j in range(max(1, line_no - 6), line_no):
        m = re.search(r"process-local:\s*(\S.*)", lines[j - 1])
        if m and m.group(1).strip():
            return m.group(1).strip()
    return None

bad = []
for module in sorted(found):
    where = found[module]
    missing = [p for p in PROCESSES if p not in where]
    if not missing:
        continue
    line_no = next(iter(where.values()))
    reason = reason_above(line_no)
    if reason:
        print(f"  {module:12} {'/'.join(sorted(where))} only, on purpose: {reason}")
    else:
        bad.append((module, sorted(where)[0], missing[0], line_no))

for module, has, lacks, line_no in bad:
    print(f"{SRC}:{line_no}: `{module}::from_env()` is called in `{has}` and not in `{lacks}`.")
    print(f"  So one of the two processes runs with `{module}` unconfigured while the")
    print("  code at its door reads exactly like the code at the other one. Either")
    print(f"  configure it in `{lacks}` too, or put a `process-local: <reason>` comment")
    print("  within six lines above the call saying why that process does not need it.")

n = len(found)
if bad:
    print()
    print(f"{len(bad)} door(s) of {n} configured in one process and unexplained in the other.")
    sys.exit(1)
print(f"{n} startup door(s): each is configured in both processes, or says at the call site why not.")
PY
