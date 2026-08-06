#!/usr/bin/env bash
# Every command this repository tells a reader to run against the gateway can
# actually start one.
#
# WHY THIS EXISTS
#
# On 2026-08-05 the gateway learned to refuse to start with neither
# `TOKENFUSE_UPSTREAM` nor `TOKENFUSE_ALLOW_STUB` set, because without a
# provider it answers from a stub and meters a fixed 1000/500 tokens as real
# spend, and a live cluster had been doing exactly that with nobody warned. The
# refusal is right. Nothing that advertised the old behaviour moved with it: the
# README's headline "try it in one command", its own get-started step, the
# Dockerfile's comment, the crates.io crate's doc, the Show HN draft, and the
# `docker compose` stack, which would have crash-looped the moment its image was
# rebuilt. `grep -r ALLOW_STUB docs/` returned nothing at all.
#
# That is a specific and very common failure: **the code got a new precondition
# and the documented command did not.** It is invisible to every other check
# here, because a document does not compile, and it is exactly the class a
# regular expression CAN hold, so it gets one.
#
# WHAT IT CHECKS
#
# Two shapes, because those are the two ways this repository tells somebody to
# start a gateway:
#
#   1. `docker run ... ghcr.io/taipanbox/tokenfuse[:tag]`, in any tracked text
#      file, continuation lines joined;
#   2. `cargo run -p tokenfuse-gateway`, excluding `--example` runs, which build
#      a benchmark rather than the server.
#
# plus the gateway service in `cloud/docker-compose.yml`, which is the same
# claim in a different syntax and was the one place that would have failed
# silently on somebody else's machine.
#
# Each must carry `TOKENFUSE_UPSTREAM` or `TOKENFUSE_ALLOW_STUB`.
#
# WHAT IT DOES NOT CHECK
#
# That the command is otherwise correct, that the image exists, or that prose
# ABOUT the image is right. It holds one precondition, the one the binary
# enforces at startup, and says so rather than implying more.
#
# Two exclusions are deliberate and both are load-bearing. A SUBCOMMAND
# invocation (`... -- constants`, `tokenfuse top`) shares the binary with the
# gateway and needs no provider. An ELLIPSIS means the line is prose about a
# command rather than a command, and this document is full of prose about the
# very invocation that fails. Either would make the gate fire on something
# correct, and a gate that cries wolf gets deleted by whoever is unblocking CI.

set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 1

python3 - "$@" <<'PY'
import re
import subprocess
import sys
from pathlib import Path

# The gateway image, and only it: `-control-plane` and `-dashboard` are
# different programs with different preconditions, so the boundary is explicit.
IMAGE = re.compile(r"ghcr\.io/taipanbox/tokenfuse(:[A-Za-z0-9._-]+)?(?![\w./-])")
CARGO = re.compile(r"cargo run\b[^\n]*-p tokenfuse-gateway")
REQUIRED = ("TOKENFUSE_UPSTREAM", "TOKENFUSE_ALLOW_STUB")

TEXT_SUFFIXES = {".md", ".yml", ".yaml", ".rs", ".sh", ".toml"}
EXTRA_FILES = {"Dockerfile"}

problems = []
checked = 0


def note(msg):
    problems.append(msg)
    print(msg)


def measured_nothing(what):
    print("FAIL: this check measured nothing, so it proves nothing.")
    print(f"      {what}")
    print("      Fix this script before trusting a green run.")
    sys.exit(1)


def tracked_files():
    out = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, check=True
    ).stdout.split()
    for f in out:
        p = Path(f)
        if p.suffix in TEXT_SUFFIXES or p.name in EXTRA_FILES:
            yield p


def commands(text):
    """Yield whole commands, with backslash continuations joined."""
    joined, buf = [], ""
    for line in text.splitlines():
        stripped = line.rstrip()
        # A markdown code fence, a comment marker or a doc-comment prefix does
        # not change what the command IS, and a command in a `//!` doc comment
        # is one a reader will copy.
        cleaned = re.sub(r"^\s*(//!|///|#|>|\*)\s?", "", stripped)
        if cleaned.endswith("\\"):
            buf += cleaned[:-1] + " "
            continue
        joined.append(buf + cleaned)
        buf = ""
    if buf:
        joined.append(buf)
    return joined


for path in tracked_files():
    # This script names the variables it looks for, so it would match itself.
    if path.name == "runnable-quickstart.sh":
        continue
    try:
        text = path.read_text()
    except (UnicodeDecodeError, OSError):
        continue
    for cmd in commands(text):
        # An ellipsis means prose, not a command. A document explaining that
        # `docker run ... ghcr.io/taipanbox/tokenfuse` exits 2 is describing the
        # fault this gate exists for, and failing on it would make the gate
        # break on a true sentence, which is how `stated-numbers.sh` learned the
        # same lesson one file over. Nothing with an ellipsis in it is
        # copy-pasteable anyway.
        if "..." in cmd or "…" in cmd:
            continue
        # A SUBCOMMAND is not the server. `tokenfuse constants`, `tokenfuse
        # top`, `tokenfuse mcp-scan` and friends share one binary with the
        # gateway and need no provider, so a command that names one is not
        # making the claim this script holds. `scripts/constants.sh` is exactly
        # that case, and flagging it would teach whoever unblocks CI that this
        # gate cries wolf.
        docker_m = IMAGE.search(cmd) if "docker run" in cmd else None
        docker = bool(docker_m) and not re.match(
            r"\s+[A-Za-z]", cmd[docker_m.end() :] if docker_m else ""
        )
        cargo_m = CARGO.search(cmd)
        cargo = (
            bool(cargo_m)
            and "--example" not in cmd
            and not re.search(r"--\s+[A-Za-z]", cmd)
        )
        if not (docker or cargo):
            continue
        checked += 1
        if not any(v in cmd for v in REQUIRED):
            note(
                f"{path}: this command cannot start a gateway:\n"
                f"    {cmd.strip()}\n"
                "  With neither TOKENFUSE_UPSTREAM nor TOKENFUSE_ALLOW_STUB the process\n"
                "  exits 2 rather than metering invented usage as spend. Add the provider,\n"
                "  or add TOKENFUSE_ALLOW_STUB=1 and say in the surrounding text that the\n"
                "  numbers are then fictional."
            )

# --- the compose stack, which is the same claim in another syntax ------------

compose = Path("cloud/docker-compose.yml")
if not compose.exists():
    measured_nothing(f"{compose} is gone; this script still expects to check it.")

blocks = re.split(r"\n(?=  \w[\w-]*:\n)", compose.read_text())
gateway_blocks = [b for b in blocks if IMAGE.search(b) and "image:" in b]
if not gateway_blocks:
    measured_nothing(
        f"no service in {compose} names the gateway image, so the stack this "
        "repository tells people to run was not checked at all."
    )
for b in gateway_blocks:
    checked += 1
    # Comments are stripped first, and that is the whole difference between
    # this check working and looking like it works: this file keeps
    # `# TOKENFUSE_UPSTREAM: ...` commented out beside the live setting as the
    # instruction for going real, and a substring search reads that as
    # configured. The first version of this gate did exactly that and reported
    # a clean run on a service that could not start.
    live = "\n".join(line.split("#", 1)[0] for line in b.splitlines())
    if not any(v in live for v in REQUIRED):
        name = b.strip().split(":", 1)[0]
        note(
            f"{compose}: service `{name}` runs the gateway image with neither "
            "TOKENFUSE_UPSTREAM nor TOKENFUSE_ALLOW_STUB, so the container exits 2 and "
            "the stack crash-loops."
        )

if checked == 0:
    measured_nothing(
        "no gateway invocation was found in any tracked file, which means the "
        "patterns above stopped matching rather than that the documents are clean."
    )

if problems:
    print(
        f"\n{len(problems)} documented command(s) that cannot start a gateway, "
        f"out of {checked} checked."
    )
    sys.exit(1)

print(f"{checked} documented gateway invocations, every one of which can start.")
PY
