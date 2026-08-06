#!/usr/bin/env bash
# Enforces invariant 3 of CLAUDE.md: core types reach the Cloud OpenAPI only via
# cloud-local `*Schema` DTOs.
#
# WHAT THE COMPILER ALREADY DOES, because a gate that duplicates it is worse
# than no gate: it costs a run and teaches the reader nothing
#
# Invariant 1 keeps `utoipa` out of `tokenfuse-core`, so no core type can ever
# implement `ToSchema`. That single fact closes most of invariant 3 by
# construction, and it was measured rather than assumed (2026-08-06):
#
#   - a core type named in `components(schemas(..))` fails to compile:
#     "the trait bound `AuditEntry: ToSchema` is not satisfied";
#   - a core type as a field of a `ToSchema` DTO fails the same way;
#   - `impl ToSchema for <core type>` inside crates/cloud is refused by the
#     orphan rule, both trait and type being foreign to that crate.
#
# WHAT IT DOES NOT DO, which is the whole reason this script exists
#
# `#[schema(value_type = ..)]` tells utoipa to describe a field as some other
# type and never asks the real one for a schema. A core type annotated that way
# compiles cleanly and lands on the public API surface. Measured the same day:
# the same field that fails to compile bare, compiles with the annotation.
#
# One field still sits in it deliberately, recorded below with the fact that
# makes it safe, which this script re-establishes on every run rather than
# trusting a comment (invariant 11's rule, applied here).
#
# THE SECOND ROAD, which the first version of this script did not look down
#
# A schema type can also reach the OpenAPI document through `body = <name>` on a
# `#[utoipa::path]` while the handler returns the core type. Nothing is a field
# of anything, so the scan above never sees it. Two such mirrors remain, both on
# the compliance endpoints, and this script compares each to its original by
# field NAME, since names are what a JSON body shows.
#
# WHY A MIRROR IS THE WEAK FORM, and what replaced it once
#
# `ReplayResponse.audit` and `/v1/audit` used to serialise
# `Vec<tokenfuse_core::audit::AuditEntry>` while publishing `AuditEntrySchema`.
# They agreed only while somebody kept them agreeing by hand. Proven rather than
# feared: a field added to the core struct made `/v1/audit` answer a key the
# published schema never declared.
#
# That one is fixed rather than watched. The DTO is serialised now, so core may
# grow a field without touching the API and a field added to the DTO fails to
# compile until `From` fills it: the compiler holds it and there is no mirror
# left to keep. The two below are still watched, which is strictly weaker, and
# the note in the MIRRORS table says what fixing them would look like.

set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 1

python3 - "$@" <<'PY'
import re
import sys
from pathlib import Path

CLOUD = Path("crates/cloud/src")
CORE = Path("crates/core/src")

# ---------------------------------------------------------------------------
# The recorded exceptions. A core type on the schema surface is allowed only if
# it appears here, and only while its `check` still holds. Adding an entry is a
# DTO-boundary decision, which CLAUDE.md's escalation list says is the user's,
# not a routine edit.
# ---------------------------------------------------------------------------
ALLOWED = {
    ("store.rs", "severity"): dict(
        why="Declared to the schema as a plain String, which every variant of "
        "core's Severity serialises to. A new variant keeps the schema "
        "truthful; a Severity that stopped being a plain enum would not.",
        check="severity_is_a_unit_enum",
    ),
}

# ---------------------------------------------------------------------------
# The remaining documentation mirrors.
#
# These never appear as a field of a DTO, so the scan above cannot see them:
# they reach the OpenAPI document through `body = <name>` on a `#[utoipa::path]`
# while the handler returns the core type. Same drift, different road, and the
# first version of this script did not look down it.
#
# `AuditEntrySchema` used to be one of these and is not any more: it is
# serialised now, so the compiler holds it and no entry is needed here. These
# two still describe a core type they do not carry. Field NAMES are what a JSON
# body shows, so names are what this compares; the types differ by
# representation on purpose (`&'static str` against `String`, an enum against
# the string it serialises to).
# ---------------------------------------------------------------------------
MIRRORS = {
    "ControlEvidenceSchema": ("ControlEvidence", "compliance.rs"),
    "ComplianceReportSchema": ("ComplianceReport", "compliance.rs"),
}

problems = []


def note(msg):
    problems.append(msg)
    print(msg)


def core_names_imported(text):
    """Type names this file pulled in from tokenfuse_core, so a bare `AuditEntry`
    is recognised as core rather than only a fully qualified path."""
    names = set()
    for use in re.findall(r"use\s+tokenfuse_core::([^;]+);", text, re.S):
        for part in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", use):
            if part[:1].isupper():
                names.add(part)
        for alias in re.findall(r"as\s+([A-Za-z_][A-Za-z0-9_]*)", use):
            names.add(alias)
    return names


def schema_items(text):
    """(item name, body) for every struct/enum in this file deriving ToSchema."""
    out = []
    for m in re.finditer(r"#\[derive\(([^)]*)\)\]", text):
        if "ToSchema" not in m.group(1):
            continue
        rest = text[m.end() :]
        head = re.search(r"\b(?:struct|enum)\s+([A-Za-z_][A-Za-z0-9_]*)", rest)
        if not head:
            continue
        brace = rest.find("{", head.end())
        if brace == -1:
            continue
        depth, i = 0, brace
        while i < len(rest):
            if rest[i] == "{":
                depth += 1
            elif rest[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        out.append((head.group(1), rest[brace : i + 1]))
    return out


def fields(body):
    """(field name, type text) pairs, ignoring comments and attributes."""
    out = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith(("//", "#[", "/*", "*")):
            continue
        m = re.match(r"(?:pub\s+)?([a-z_][a-z0-9_]*)\s*:\s*(.+?),?$", line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def struct_fields(path, name):
    text = path.read_text()
    m = re.search(r"\b(?:struct|enum)\s+" + re.escape(name) + r"\s*\{", text)
    if not m:
        return None
    depth, i = 0, m.end() - 1
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    return fields(text[m.end() - 1 : i + 1])


# --- the exceptions' own justifications, re-established every run -----------


def severity_is_a_unit_enum():
    for path in CORE.rglob("*.rs"):
        text = path.read_text()
        m = re.search(r"pub enum Severity\s*\{([^}]*)\}", text)
        if not m:
            continue
        for variant in re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*([({])?", m.group(1)):
            if variant[1]:
                return (
                    f"core's Severity variant `{variant[0]}` carries data, so the "
                    "schema's `value_type = String` is no longer true"
                )
        return None
    return "core declares no `pub enum Severity`, so the recorded reason cannot be checked"


CHECKS = {
    "severity_is_a_unit_enum": severity_is_a_unit_enum,
}

# --- 1: no core type on the schema surface except the recorded ones ---------

seen = set()
for path in sorted(CLOUD.rglob("*.rs")):
    text = path.read_text()
    core_names = core_names_imported(text)
    for item, body in schema_items(text):
        for fname, ftype in fields(body):
            is_core = "tokenfuse_core::" in ftype or any(
                re.search(r"\b" + re.escape(n) + r"\b", ftype) for n in core_names
            )
            if not is_core:
                continue
            key = (path.name, fname)
            seen.add(key)
            if key not in ALLOWED:
                note(
                    f"{path}: `{item}.{fname}: {ftype}` puts a tokenfuse-core type on the "
                    "Cloud OpenAPI surface. Core types reach it only through a cloud-local "
                    "*Schema DTO (invariant 3). If this one genuinely must, record it in "
                    "ALLOWED in this script with a reason this script can re-establish."
                )

# --- 2: every recorded exception still deserves to be recorded -------------

for key, entry in ALLOWED.items():
    if key not in seen:
        note(
            f"{key[0]}: the exception for field `{key[1]}` matches nothing any more. "
            "Delete it: an exception nobody needs is one nobody re-reads, and it will be "
            "trusted the next time something does match it."
        )
        continue
    failure = CHECKS[entry["check"]]()
    if failure:
        note(f"{key[0]}: `{key[1]}` was allowed because: {entry['why']}\n  That has stopped being true: {failure}")

# --- 3: every documentation mirror still mirrors -----------------------------

for dto_name, (core_name, core_file) in MIRRORS.items():
    dto = struct_fields(CLOUD / "http.rs", dto_name)
    core = struct_fields(CORE / core_file, core_name)
    if dto is None or core is None:
        note(
            f"{dto_name}: could not read it or its original `{core_name}`, so the mirror "
            "cannot be compared. If one of them was renamed or removed, update MIRRORS."
        )
        continue
    dto_names = [f[0] for f in dto]
    core_names = [f[0] for f in core]
    if dto_names != core_names:
        only_core = [n for n in core_names if n not in dto_names]
        only_dto = [n for n in dto_names if n not in core_names]
        note(
            f"{dto_name} has stopped mirroring tokenfuse_core's {core_name}, so the OpenAPI "
            "document now describes a response body that is not the one sent. In core only: "
            f"{only_core or 'none'}. In the mirror only: {only_dto or 'none'}. The durable fix "
            "is the one applied to AuditEntrySchema: serialise the DTO instead of describing "
            "the core type, and the compiler holds it with no mirror to keep."
        )

# --- verdict ---------------------------------------------------------------

if problems:
    print(f"\n{len(problems)} problem(s) on the Cloud DTO boundary (CLAUDE.md invariant 3).")
    sys.exit(1)

print(
    f"the Cloud OpenAPI surface exposes no tokenfuse-core type beyond "
    f"{len(ALLOWED)} recorded exception(s), and each one's reason still holds."
)
PY
