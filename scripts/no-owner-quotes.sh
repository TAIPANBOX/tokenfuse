#!/usr/bin/env bash
# Enforces invariant 101 of CLAUDE.md: no tracked file quotes the owner or
# attributes a decision to him by name.
#
# WHY
#
# This repository is public. A decision the owner made is still recorded,
# because a later reader has to know it is a decision and not something to
# re-derive: it is written as `@decided YYYY-MM-DD` followed by a paraphrase in
# this repository's own words, and never edited afterwards. What is not written
# is his own wording, or his name as the one who said, asked or decided
# something. Before this check existed, marker lines, quotations and prose in a
# non-Latin language about the owner sat in tracked files, and nothing would
# have stopped the next one.
#
# FOUR SHAPES ARE REFUSED, each on the line it occurs on:
#
#   1. the old provenance marker, an at-sign followed by his first name, in
#      any case;
#   2. a guillemet on a line that also carries Cyrillic, the shape his quotes
#      took;
#   3. Cyrillic in prose: anywhere in a non-code file, and outside a string
#      literal in a code file (.rs .ts .tsx .js .mjs .cjs). A string literal may
#      carry Cyrillic, because hostile-input tests need non-Latin text; so may
#      a file under a testdata/ directory;
#   4. his first name capitalised as a word, outside an authorship line (one
#      that says copyright, author or maintainer): the shape of "he found",
#      "his call", "he read the demo", which a list of verbs would never
#      finish. The owner as copyright holder or author is not a quote and
#      passes.
#
# URLs are blanked before 1, 2 and 4 run: the name inside somebody's address
# is an address, not an attribution.
#
# WHAT IT DOES NOT CATCH
#
# An English quote of his words in ordinary quotation marks, an attribution
# that does not use his name ("the owner said"), and a paraphrase that is in
# fact a translation: those are prose a reader judges, and nothing mechanical
# can. In a code file a line that opens as a comment is prose whole; on a
# line that opens as code, a string literal is found per line, so a quoted
# Ukrainian phrase in a comment trailing code on the same line passes, and
# Cyrillic in a string spanning several lines is refused, the safe way to be
# wrong. It reads only what git tracks.
#
# The other public repositories of the estate hold the same four shapes.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

git ls-files -z | python3 -c '
import re, sys

# Assembled rather than written, so this file can describe the rule without
# being one of the files the rule refuses.
FIRST = "Y" + "urii"

marker = re.compile("@" + FIRST.lower() + r"\b", re.I)
name = re.compile(r"\b" + FIRST + r"\b")
authorship = re.compile(r"copyright|\(c\)|\bauthors?\b|\bmaintainers?\b|\bmaintained by\b|" + chr(0xA9), re.I)
guillemet = re.compile("[" + chr(0xAB) + chr(0xBB) + "]")
cyrillic = re.compile("[" + chr(0x400) + "-" + chr(0x4FF) + "]")
url = re.compile(r"[a-z][a-z0-9+.-]*://[^\s)\]>\"]+", re.I)
# One-line string literals: double-quoted, single-quoted, template, each with
# escapes. A Rust lifetime (`'"'"'a`) is not matched, since it has no closing
# quote right after its one character.
literal = re.compile(r"\"(?:[^\"\\]|\\.)*\"|'"'"'(?:[^'"'"'\\]|\\.)*'"'"'|`(?:[^`\\]|\\.)*`")
CODE = (".rs", ".ts", ".tsx", ".js", ".mjs", ".cjs")

paths = [p for p in sys.stdin.buffer.read().decode("utf-8", "replace").split("\0") if p]
scanned = 0
findings = []
for path in paths:
    try:
        raw = open(path, "rb").read()
    except OSError:
        continue
    if b"\0" in raw[:8000]:
        continue  # binary, by git'"'"'s own heuristic
    text = raw.decode("utf-8", "replace")
    scanned += 1
    testdata = "testdata/" in path
    code = path.endswith(CODE)
    for i, line in enumerate(text.split("\n"), 1):
        plain = url.sub(" ", line)
        at = "%s:%d" % (path, i)
        if marker.search(plain):
            findings.append(at + ": the old provenance marker carrying the owner'"'"'s name; write @decided and a paraphrase")
        if guillemet.search(plain) and cyrillic.search(plain):
            findings.append(at + ": a quotation in guillemets, in the owner'"'"'s own language")
        if name.search(plain) and not authorship.search(plain):
            findings.append(at + ": the owner named as the one who said, asked, decided or found something")
        if testdata or not cyrillic.search(line):
            continue
        # A comment line is prose whole, quotes and all: a quoted phrase in a
        # comment is exactly how a quote of his was written.
        comment = line.lstrip().startswith(("//", "*", "/*"))
        rest = literal.sub("\"\"", line) if code and not comment else line
        if cyrillic.search(rest):
            findings.append(at + ": Ukrainian prose; a decision is paraphrased in English")

if scanned == 0:
    print("no tracked text file was read, so this check measured nothing.")
    sys.exit(1)
for f in findings:
    print("FAIL  " + f)
if findings:
    print("\n%d line(s) quote or name the owner in a public repository." % len(findings))
    print("Record a decision as @decided YYYY-MM-DD and a paraphrase in English.")
    sys.exit(1)
print("OK: %d tracked text file(s), no quote of the owner and no attribution by name." % scanned)
'
