#!/usr/bin/env bash
# Every tool this project's CI installs by name is installed at a named
# version. An unpinned install is a dependency with no lockfile: it resolves to
# whatever is newest at the moment the job runs, so the build that passes today
# and the build that fails tomorrow are the same commit.
#
# WHY THIS EXISTS, AND IT IS NOT HYPOTHETICAL
#
# The radar job ran `cargo install bpf-linker` with no version and no
# `--locked`. bpf-linker 0.11.0 was published on 2026-08-12, the day after that
# job last went green, and it links system LLVM dynamically, which `System
# deps` does not install. main went red on 2026-08-20 with nothing in this
# repository having changed, and the first pull request opened afterwards
# arrived with a red check that looked like its own fault. That is the
# expensive part: not the build minutes, but a failure attributed to the wrong
# change.
#
# WHAT IS CHECKED
#
#   cargo install    a version AND --locked. The version alone still lets the
#                    crate's own dependencies float, which is the same failure
#                    one level down.
#   pip install      `==`, or `-r <file>`, which moves the pin into the file.
#   pipx / uv tool   same as pip.
#   npm install -g   `name@version`.
#   go install       `path@version`, and `@latest` is not a version.
#
#   apt-get install  a snapshot (--snapshot YYYYMMDDTHHMMSSZ), or an explicit
#                    pkg=version. Added 2026-08-20 on Yurii's instruction,
#                    after this header argued for leaving apt alone.
#   runs-on          a released image label, never a `-latest` one.
#
# WHY APT IS IN SCOPE AFTER ALL, since this header used to argue the opposite
#
# The argument against was that pinning apt on a hosted runner pins to versions
# that exist only in the image the runner happens to boot, so the pin breaks on
# the next image roll and the gate demanding it gets deleted by whoever is
# unblocking CI. That argument was right about `pkg=version` and wrong about
# apt, because it assumed a version number is the only way to pin.
#
# The Ubuntu snapshot service serves the archive as it stood at a timestamp,
# for any date after 1 March 2023, and apt in 24.04 speaks it natively. A
# snapshot does not break when the image rolls, because it does not describe
# the image; it describes the archive. That is the pin the earlier argument
# said did not exist.
#
# It only holds with the runner image pinned too, which is why `runs-on` is
# checked here rather than somewhere else. `ubuntu-latest` is a rolling label:
# it is 24.04 today, 26.04 is already in public preview, and GitHub migrates
# the label over one to two months during which any workflow using it may see
# the OS change underneath. A snapshot pin on a rolling image is half a pin.
#
# WHAT IS STILL NOT CHECKED
#
# That the snapshot timestamp is recent, or that it is the same one everywhere.
# Both are judgement: an old snapshot is a deliberate choice as often as it is
# neglect, and a job may legitimately need a different one.
#
# `rustup toolchain install` is not a tool install, it is a channel, and
# `npm ci` is driven by a lockfile that is committed. Both must NOT fail this,
# and both have cases in gates-have-teeth.sh saying so.
#
# COMMENTS ARE STRIPPED, and that is load-bearing rather than tidy. The comment
# above the pinned bpf-linker step quotes the old unpinned command verbatim, to
# explain what went wrong. A scanner that reads comments fails on the very
# sentence that records the fix, which is how a gate teaches people to stop
# writing down why.
#
# The known limit of stripping `#` by text: a `#` inside a quoted string is
# treated as a comment. No workflow here has one, and the alternative is a YAML
# parser this repository would have to install. Stated rather than hidden.

set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 1

python3 - "$@" <<'PY'
import glob
import re
import sys

WORKFLOWS = sorted(glob.glob(".github/workflows/*.yml") + glob.glob(".github/workflows/*.yaml"))

problems = []
checked = 0


def note(*lines):
    problems.append(lines[0])
    for line in lines:
        print(line)


def measured_nothing(what):
    print("FAIL: this check measured nothing, so no claim about pinning is verified.")
    print(f"      {what}")
    print("      Fix this script before trusting a green run.")
    sys.exit(1)


def strip_comment(line):
    """Drop a YAML/shell comment. A '#' only starts one at the beginning of the
    line or after whitespace, so `foo#bar` and a URL fragment survive."""
    out = re.split(r"(?:^|\s)#", line, maxsplit=1)[0]
    return out


# (verb pattern, human name, predicate deciding whether the rest is pinned)
def cargo_pinned(rest):
    missing = []
    if not re.search(r"--version[= ]\S+", rest) and not re.search(r"^\s*\S+@\S+", rest):
        missing.append("a version (--version X.Y.Z)")
    if "--locked" not in rest:
        missing.append("--locked")
    return missing


def pip_pinned(rest):
    if re.search(r"(^|\s)-r(\s|=)", rest):
        return []
    if "==" in rest:
        return []
    return ["a version (pkg==X.Y.Z), or -r a requirements file"]


def npm_pinned(rest):
    # the package sits after the -g flag; a pin is name@version
    if re.search(r"[\w@/.-]+@[\w.-]+", rest.replace("-g", " ")):
        return []
    return ["a version (pkg@X.Y.Z)"]


def apt_pinned(rest):
    if re.search(r"--snapshot[= ]\S+", rest):
        return []
    # An explicit pkg=version is accepted, but it is the weaker form: it holds
    # only until the archive publishes a new build inside the same release.
    if re.search(r"[\w.+-]+=[\w.:+~-]+", rest):
        return []
    return ["a snapshot (--snapshot YYYYMMDDTHHMMSSZ), or an explicit pkg=version"]


def go_pinned(rest):
    m = re.search(r"\S+@(\S+)", rest)
    if m and m.group(1) != "latest":
        return []
    return ["a version (path@vX.Y.Z); @latest is not a version"]


VERBS = [
    (re.compile(r"(?<!rustup )\bcargo install\b(?P<rest>.*)"), "cargo install", cargo_pinned),
    (re.compile(r"\bpip3?\s+install\b(?P<rest>.*)"), "pip install", pip_pinned),
    (re.compile(r"\bpipx\s+install\b(?P<rest>.*)"), "pipx install", pip_pinned),
    (re.compile(r"\buv\s+tool\s+install\b(?P<rest>.*)"), "uv tool install", pip_pinned),
    (re.compile(r"\bnpm\s+(?:install|i)\s+(?:-g|--global)\b(?P<rest>.*)"), "npm install -g", npm_pinned),
    (re.compile(r"\bgo\s+install\b(?P<rest>.*)"), "go install", go_pinned),
    (re.compile(r"\bapt(?:-get)?\s+install\b(?P<rest>.*)"), "apt-get install", apt_pinned),
]

# `rustup toolchain install stable` contains the word install and is a channel,
# not a crate. `npm ci` is lockfile-driven. Neither is a finding.
IGNORE = re.compile(r"\brustup\s+toolchain\s+install\b|\bnpm\s+ci\b")

if not WORKFLOWS:
    measured_nothing(
        "no workflow files matched .github/workflows/*.yml, so nothing was scanned. "
        "Either the directory moved or this glob is wrong."
    )

for path in WORKFLOWS:
    for lineno, raw in enumerate(open(path).read().split("\n"), 1):
        line = strip_comment(raw)
        if not line.strip() or IGNORE.search(line):
            continue
        for pattern, verb, predicate in VERBS:
            m = pattern.search(line)
            if not m:
                continue
            checked += 1
            missing = predicate(m.group("rest"))
            if missing:
                note(
                    f"{path}:{lineno} floats: {line.strip()}",
                    f"    this {verb} needs {' and '.join(missing)}.",
                    "    Unpinned, this resolves to whatever is newest when the job runs, so",
                    "    the commit that passes today is the commit that fails tomorrow.",
                )
            break

# --- the runner image ------------------------------------------------------
#
# A rolling image label is the same fault one layer out, and it is the layer a
# snapshot pin above depends on. `ubuntu-latest` is 24.04 today, 26.04 is in
# public preview, and the migration takes one to two months during which a
# workflow using the label may see the OS change underneath it.
runners = 0
for path in WORKFLOWS:
    for lineno, raw in enumerate(open(path).read().split("\n"), 1):
        line = strip_comment(raw)
        m = re.search(r"runs-on:\s*(?P<label>[\w.-]+)", line)
        if not m:
            continue
        runners += 1
        label = m.group("label")
        if label.endswith("-latest"):
            note(
                f"{path}:{lineno} floats: runs-on: {label}",
                "    a -latest label rolls to the next OS release on GitHub's schedule,",
                "    over one to two months, and a workflow using it sees the change",
                "    underneath. Name the release the job is tested against.",
            )

if runners == 0:
    measured_nothing(
        f"{len(WORKFLOWS)} workflow file(s) were read and not one `runs-on:` was found. "
        "Either these are not workflow files or this pattern no longer matches."
    )

if checked == 0:
    measured_nothing(
        f"{len(WORKFLOWS)} workflow file(s) were read and not one install command was "
        "recognised. Either CI stopped installing tools by name, or these patterns no "
        "longer match the way it does."
    )

if problems:
    print(f"\n{len(problems)} unpinned install(s) across {len(WORKFLOWS)} workflow file(s).")
    sys.exit(1)

print(
    f"{checked} tool install(s) and {runners} runner label(s) across "
    f"{len(WORKFLOWS)} workflow file(s), every one pinned."
)
PY
