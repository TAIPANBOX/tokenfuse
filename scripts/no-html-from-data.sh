#!/usr/bin/env bash
# Enforces invariant 102 of CLAUDE.md: a page this repository serves builds no
# markup out of the data it shows.
#
# WHY
#
# The control plane's own page (crates/cloud/index.html, served at `GET /`)
# rendered the runs table by interpolating each run's fields into a template
# string and assigning the result to `innerHTML`. A run id and a model name are
# chosen by whoever calls a gateway, and the Cloud stores them as sent, so the
# page parsed caller-chosen text as markup in the operator's browser, on the
# page that also keeps the org key in localStorage. The fix built the rows with
# createElement and textContent; this keeps the template string from coming
# back, since it renders identically for every honest run id and nothing else
# would notice.
#
# WHAT IS READ
#
# 1. Every file a crate embeds with include_str! or include_bytes! whose name
#    ends in .html, .htm, .js or .mjs: that is what a binary of this repository
#    serves. The list is discovered from the Rust sources, never typed here, so
#    a second embedded page is read without anybody remembering to add it. For
#    an HTML file, the inline <script> elements are read.
#
#    In that code, each HTML sink is found (an assignment to innerHTML,
#    outerHTML or srcdoc; a call to insertAdjacentHTML, document.write,
#    document.writeln, createContextualFragment, setHTMLUnsafe or
#    parseHTMLUnsafe) and the value it is given is classified. A value that is
#    anything but one constant string (a template literal with ${...}, a
#    concatenation, a variable, a call) is refused outright: this check cannot
#    know where a variable came from, so it does not guess. A constant string is
#    allowed only when the ALLOW list below names it with the reason it is safe.
#
# 2. The Next.js dashboard's sources (cloud/dashboard, its own image). React
#    escapes what it renders, so the only ways in are the sinks themselves:
#    any code line there naming dangerouslySetInnerHTML or one of the sinks
#    above is refused. That half has no allow-list, because no part of that
#    dashboard needs one; a change that does needs this script changed too.
#
# MEASURED NOTHING
#
# No embedded page at all, an embedded page that is not in the tree, an HTML
# page with no inline script, a script this reader cannot follow to its end,
# and a dashboard with no source file each fail as "measured nothing" rather
# than passing on an empty read.
#
# WHAT IT DOES NOT CATCH
#
# A sink reached through a computed property (el[name] = ...), an inline event
# handler attribute, a javascript: URL put into href or src, or markup built
# somewhere this script does not read. A regular-expression literal is not
# parsed: one containing a quote makes the reader stop, which fails as measured
# nothing, the loud way to be wrong. A statement with no semicolon runs on into
# the next line and is then read as built from data, the safe way to be wrong.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

python3 - <<'PY'
import os
import re
import subprocess
import sys

# Each permitted sink: (path, the constant expression exactly as written, why it
# is safe). Only a constant string can be listed, and every entry must match a
# sink, so this list cannot outlive the code it excuses.
ALLOW = [
]

ASSIGN = re.compile(r"\.\s*(innerHTML|outerHTML|srcdoc)\s*\+?=(?!=)")
# The argument that carries the markup: None means every argument.
CALLS = {
    "insertAdjacentHTML": 1,
    "write": None,
    "writeln": None,
    "createContextualFragment": 0,
    "setHTMLUnsafe": 0,
    "parseHTMLUnsafe": 0,
}
CALL = re.compile(
    r"(?:\.\s*(insertAdjacentHTML|createContextualFragment|setHTMLUnsafe|parseHTMLUnsafe)"
    r"|\bdocument\s*\.\s*(writeln|write))\s*\("
)
CONSTANT = re.compile(r'"[_\n]*"|\'[_\n]*\'|`[_\n]*`')
EMBED = re.compile(r'include_(?:str|bytes)!\s*\(\s*"([^"]+\.(?:html?|m?js))"\s*\)')
SCRIPT = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.S | re.I)
DASHBOARD_WORDS = re.compile(
    r"dangerouslySetInnerHTML|innerHTML|outerHTML|insertAdjacentHTML|document\s*\.\s*write"
    r"|createContextualFragment|setHTMLUnsafe|parseHTMLUnsafe|srcdoc"
)


def tracked(prefix):
    out = subprocess.run(["git", "ls-files", "-z", "--", prefix], capture_output=True, check=True)
    return [p for p in out.stdout.decode().split("\0") if p]


def mask(src):
    """The code of a script with every comment blanked and the inside of every
    string replaced by '_', newlines kept, the same length as the source; the
    code inside a template literal's ${...} stays code. None when the reader
    cannot follow the script to its end."""
    out = list(src)
    n = len(src)

    def blank(a, b, ch):
        for k in range(a, b):
            if out[k] != "\n":
                out[k] = ch

    def template_text(j):
        start = j
        while j < n:
            if src[j] == "\\":
                j += 2
                continue
            if src[j] == "`":
                blank(start, j, "_")
                return j + 1, False
            if src.startswith("${", j):
                blank(start, j, "_")
                return j + 2, True
            j += 1
        return None, None

    i = 0
    depth = 0
    reopen = []  # the brace depth at which each open ${ returns to template text
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            blank(i, j, " ")
            i = j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            if j < 0:
                return None
            blank(i, j + 2, " ")
            i = j + 2
        elif c in "'\"":
            j = i + 1
            while j < n and src[j] != c:
                if src[j] == "\\":
                    j += 1
                elif src[j] == "\n":
                    return None
                j += 1
            if j >= n:
                return None
            blank(i + 1, j, "_")
            i = j + 1
        elif c == "`" or (c == "}" and reopen and reopen[-1] == depth - 1):
            if c == "}":
                depth -= 1
                reopen.pop()
            j, opened = template_text(i + 1)
            if j is None:
                return None
            if opened:
                reopen.append(depth)
                depth += 1
            i = j
        else:
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            i += 1
    if reopen:
        return None
    return "".join(out)


def expression_end(code, j):
    depth = 0
    while j < len(code):
        ch = code[j]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return j
            depth -= 1
        elif ch in ";," and depth == 0:
            return j
        j += 1
    return j


def arguments(code, paren):
    depth = 0
    spans = []
    start = paren + 1
    for j in range(paren, len(code)):
        ch = code[j]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                spans.append((start, j))
                return spans
        elif ch == "," and depth == 1:
            spans.append((start, j))
            start = j + 1
    return None


def trimmed(text, code, a, b):
    while a < b and code[a].isspace():
        a += 1
    while b > a and code[b - 1].isspace():
        b -= 1
    return text[a:b], code[a:b]


findings = []
nothing = []
allow_used = set()
sinks = 0
scripts = 0

for entry in ALLOW:
    path, expr, reason = entry
    probe = mask(expr)
    if not reason.strip() or probe is None or not CONSTANT.fullmatch(probe.strip()):
        findings.append("ALLOW entry %r for %s is unusable: it needs a reason, and only a constant string can be listed" % (expr, path))

embedded = []
for rs in [p for p in tracked("crates") if p.endswith(".rs")]:
    try:
        text = open(rs, encoding="utf-8").read()
    except OSError:
        continue
    for m in EMBED.finditer(text):
        page = os.path.normpath(os.path.join(os.path.dirname(rs), m.group(1)))
        if page not in [e[0] for e in embedded]:
            embedded.append((page, rs))

if not embedded:
    nothing.append("no Rust source under crates/ embeds an HTML or script file, so nothing a binary serves was read")

for page, rs in embedded:
    try:
        text = open(page, encoding="utf-8").read()
    except OSError:
        nothing.append("%s is embedded by %s and is not in the tree, so nothing was read of it" % (page, rs))
        continue
    if page.endswith((".html", ".htm")):
        bodies = [(m.start(2), m.group(2)) for m in SCRIPT.finditer(text) if "src=" not in m.group(1).lower()]
        if not bodies:
            nothing.append("%s has no inline <script>, so nothing was read of it" % page)
            continue
    else:
        bodies = [(0, text)]
    for offset, body in bodies:
        code = mask(body)
        if code is None:
            line = text.count("\n", 0, offset) + 1
            nothing.append("%s: the script starting on line %d could not be read to its end (an unclosed string, comment or template, or a regular expression this reader does not parse)" % (page, line))
            continue
        scripts += 1
        given = []
        for m in ASSIGN.finditer(code):
            end = expression_end(code, m.end())
            given.append((m.start(), m.group(1), [(m.end(), end)]))
        for m in CALL.finditer(code):
            name = m.group(1) or m.group(2)
            spans = arguments(code, m.end() - 1)
            if spans is None:
                given.append((m.start(), name, [(m.end(), len(code))]))
                continue
            index = CALLS[name]
            if index is not None:
                spans = spans[index:index + 1] or [(m.end(), m.end())]
            given.append((m.start(), name, spans))
        for at, sink, spans in sorted(given):
            sinks += 1
            line = text.count("\n", 0, offset + at) + 1
            for a, b in spans:
                source, masked = trimmed(body, code, a, b)
                shown = " ".join(source.split())
                shown = shown if len(shown) <= 80 else shown[:77] + "..."
                if not CONSTANT.fullmatch(masked):
                    findings.append("%s:%d: %s is given %s, which is built from data; build the node with createElement and set the data with textContent" % (page, line, sink, shown or "(nothing this reader could find)"))
                    continue
                listed = [k for k, e in enumerate(ALLOW) if e[0] == page and e[1] == source]
                if not listed:
                    findings.append("%s:%d: %s is given the constant %s, which no ALLOW entry names; add one with the reason it is safe, or use textContent" % (page, line, sink, shown))
                allow_used.update(listed)

for k, (path, expr, _) in enumerate(ALLOW):
    if k not in allow_used:
        findings.append("ALLOW entry %r for %s matches no sink; remove it" % (expr, path))

dashboard = []
for path in tracked("cloud/dashboard"):
    if not path.endswith((".tsx", ".ts", ".jsx", ".js", ".mjs")):
        continue
    try:
        dashboard.append((path, open(path, encoding="utf-8").read()))
    except OSError:
        continue
if not dashboard:
    nothing.append("cloud/dashboard has no source file to read, so nothing of the dashboard was read")
for path, source in dashboard:
    for i, line in enumerate(source.split("\n"), 1):
        if line.lstrip().startswith(("//", "*", "/*", "{/*")):
            continue
        m = DASHBOARD_WORDS.search(line)
        if m:
            findings.append("%s:%d: %s in the dashboard; render the value as a React child or attribute, which escapes it" % (path, i, m.group(0)))

for f in findings:
    print("FAIL  " + f)
if nothing:
    for f in nothing:
        print("NOTHING  " + f)
    print("\nthis check measured nothing about what it names above, which is not a pass.")
    sys.exit(1)
if findings:
    print("\n%d place(s) where a page this repository serves can build markup out of data." % len(findings))
    sys.exit(1)
print("OK: %d embedded page(s) (%s), %d script(s), %d HTML sink(s), each an allowed constant; %d dashboard source file(s) with none." % (
    len(embedded), ", ".join(p for p, _ in embedded), scripts, sinks, len(dashboard)))
PY
