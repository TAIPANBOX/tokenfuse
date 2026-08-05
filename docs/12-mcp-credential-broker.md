# 12 · MCP credential-broker

> Status: **implemented** — `tokenfuse mcp-broker` (gateway) + the pure core in
> `tokenfuse-core::secretbroker`.

## Why

Agents call tools through **MCP** servers, and those calls often need secrets —
a GitHub token, a database password, an API key. The dangerous default is to put
the secret *in the agent's context*: it ends up in the LLM prompt, the trace, the
model's memory, and any logs. A single prompt-injection or a poisoned tool
description can then exfiltrate it.

The broker removes the secret from the agent entirely. The agent holds only a
**handle** — `{{secret:github_token}}` — which is safe to appear anywhere. The
broker swaps the handle for the real value **at the boundary**, in the last hop
before the MCP server. The secret is never in the prompt, the trace, or the
agent's memory.

## Shape

```
  agent ──JSON-RPC──▶  ┌──────────────────────────────┐ ──▶  real MCP server
  (holds handles)      │      mcp-broker (proxy)       │      (gets real secret)
                       │  tools/call → inject secrets  │
  agent ◀──────────────│  tools/list → poisoning scan  │ ◀──
                       └──────────────────────────────┘
```

It's a JSON-RPC proxy the agent points its MCP client at (`TOKENFUSE_MCP_ADDR`,
default `127.0.0.1:4200`), forwarding to `TOKENFUSE_MCP_UPSTREAM`:

- **`tools/call`** → `secretbroker::inject_secrets` replaces every
  `{{secret:NAME}}` handle in the params with the vault's value just before
  forwarding. Unknown handles are left verbatim and logged (never silently
  emptied). Secret *values* are never logged — only counts.
- **`tools/list`** → the existing scanner (`tokenfuse_core::mcp`) checks a
  tool's description **and every documented parameter in its `inputSchema`**
  for injection phrases / hidden characters. `TOKENFUSE_MCP_SCAN`:
  `off` · `warn` (log + annotate the response, default) · `block` (refuse the
  list with a JSON-RPC error).
- everything else is passed through unchanged.

## The vault

`TOKENFUSE_MCP_SECRETS="github_token=ghp_…,db=…"` (`name=value` pairs). The pure
`SecretVault` / `inject_secrets` in `tokenfuse-core::secretbroker` have no I/O and
are unit-tested (nested objects/arrays, missing handles, plain values untouched);
a richer vault (files, a secrets manager) plugs in behind the same type.

## Run it

```bash
TOKENFUSE_MCP_UPSTREAM=https://mcp.example.com/rpc \
TOKENFUSE_MCP_SECRETS="github_token=ghp_REAL" \
TOKENFUSE_MCP_SCAN=block \
  tokenfuse mcp-broker            # listens on 127.0.0.1:4200
```

Point the agent's MCP client at `http://127.0.0.1:4200`, and have it pass
`{{secret:github_token}}` wherever the token would go.

## Tested

- `secretbroker` unit tests: nested handle injection, missing-handle reporting,
  plain values untouched.
- `tests/mcp_broker.rs`: a `tools/call` with `{{secret:gh}}` reaches a stub
  upstream as the **real** secret (the agent only ever sent the handle); a
  poisoned `tools/list` is **blocked**.

## Also enforced

- **DLP on outgoing args** (`TOKENFUSE_MCP_DLP=off｜warn｜block`) — catches raw
  secrets an agent pasted directly into tool arguments (not via a handle), before
  injection, reusing `tokenfuse-core::dlp`.
- **PII masks (optional)** (`TOKENFUSE_MCP_DLP_PII=off｜shadow｜mask｜block`), a
  separate, opt-in extension of the same scan (email/card/phone, regex-only,
  off unless set) - see [13](13-security-hardening.md) for the full writeup.
- **Rug-pull lockfile** (`TOKENFUSE_MCP_LOCK=<file>`) — pins tool fingerprints;
  a changed tool definition on `tools/list` is flagged/blocked (`mcp::diff`).

### What the poisoning scan reads, and what it chooses to ignore

It used to read a tool's top-level `description` and nothing else. An agent
reads parameter documentation too, to decide how to fill a call, so text in an
`inputSchema` property description reaches the model the same way, and hiding
a payload there is a known and repeatedly demonstrated MCP vector. A
schema-borne payload was therefore invisible on the first scan; it could only
ever be caught later, as a rug pull, and then only if the operator happened to
pin the tool while it was still benign. `parse_tools` had already been folding
the whole schema into the fingerprint, so the text was right there.

The scan now walks `properties` and `items` (depth- and count-capped, because
a schema is attacker-controlled) and names the site in every finding:
`suspicious phrase in parameter "filters.tag" description: "do not mention"`,
against `suspicious phrase in description: …` for the tool's own text.

**Widening it meant tightening it.** Three markers, `secret`, `api_key` and
`system prompt`, were matched as bare substrings on lowercased text, which
makes "The API key to authenticate with" a High-severity finding. That is the
vocabulary of every honest tool that handles a credential, and parameter
descriptions are where that vocabulary actually lives, so widening alone would
have multiplied the false positives on the noisiest markers in the list. Those
three now need two things: a **word boundary** (so "secretary" and
"legacy_api_keyring" do not count) and an **instruction-shaped context** in the
same text, meaning a phrase addressed to the reader ("you must", "do not",
"before using") or an external destination (an `http://` / `https://` URL).

The cost, stated plainly: a payload that names a credential and gives no
instruction around it is no longer a finding on its own. That was never much of
a signal, and a poisoned tool carries an instruction by construction, because
the instruction is the attack. Everything in the instruction-shaped list is
matched exactly as before.

### The fingerprint, and what a lock says about itself

A fingerprint is `hex(sha256(domain || len-framed name, description, input
schema))`, and the lockfile names both the algorithm and its format version:

```json
{ "algorithm": "sha256", "version": 1, "tools": { "search": "6dbab326…" } }
```

It used to be `DefaultHasher` truncated to a `u64`, in a lockfile that was a
bare `{name: number}` map. Two problems, both fixed here (2026-08-05).

It was not a tamper-evidence primitive: `DefaultHasher` is SipHash with a fixed
zero key, so there is no MAC property, and 64 bits is well under what a control
marketed as catching a deliberate post-approval change should carry. The audit
chain in `crate::audit` had already reached SHA-256 for the same reason.

It was also not stable. Rust's standard library does not guarantee
`DefaultHasher`'s output across releases; `rust-toolchain.toml` here is an
unpinned `stable`, and `action.yml` builds the scanner from source with
`dtolnay/rust-toolchain@stable` on every run. One Rust release changing the
default hasher would have flipped every pinned tool to `Drift::Changed`, which
this product surfaces as **RUG PULL** at Critical, and `--fail-on high` would
have turned that into a red check for every consumer at once. The recovery it
invites (re-pin the lock) is exactly the action that masks a real rug pull.

**An existing lockfile does not read as a rug pull.** A lock whose
`(algorithm, version)` this build does not know is `Drift::LockNotComparable`,
reported as finding kind `stale_lock` at **Medium**, with the message that
rug-pull detection is off until it is re-pinned. Medium sits under the default
`--fail-on high`, so an old lock does not fail your build, and `mcp-scan --lock
<file> --write-lock` restores detection. `Added`/`Removed` are still reported
against such a lock, since those compare names, which every format agreed on.

## The broker's own door

The broker resolves handles against the **whole** vault and forwards to any
configured upstream, so whatever can reach the port can spend the credentials.
Two things guard that, and until 2026-08-05 only the first existed:

1. **The loopback default.** `TOKENFUSE_MCP_ADDR` defaults to
   `127.0.0.1:4200`. Widening it used to be silent; a non-loopback bind now
   logs a startup warning naming what is exposed, in the same voice as the
   Cloud's own (`crates/cloud/src/main.rs`). The condition is a pure function,
   `mcpbroker::bind_exposure_warning`, so it is testable without a listener.
2. **Optional client credentials.** `TOKENFUSE_MCP_KEYS="secret:key_id,…"`,
   the same form, the same header (`x-fuse-key`) and the same resolver
   (`clientkeys.rs`) the gateway uses for `TOKENFUSE_CLIENT_KEYS`, because a
   second authentication scheme is a second thing to get wrong. That includes
   inheriting its documented decision to resolve a secret through a plain
   `HashMap`: moving to a constant-time comparison is a posture change for
   every plane at once, not something to smuggle into one crate.

   **Unset means the broker authenticates nobody, exactly as before**, so no
   loopback deployment breaks on upgrade. Set, and every JSON-RPC call must
   present a known credential or get `401` with the gateway's own body.
   Set-but-unusable (a typo, an empty interpolated variable) refuses to start
   rather than reading as "off". `/healthz` stays open: it carries no vault,
   reaches no upstream, and is what a container runtime probes before it has
   any credential to present.

   The stdio transport has no header channel and no port; its access control is
   the operating system's, since the client is the parent process.

**Still open, and deliberately not decided here.** A non-loopback bind with no
credentials configured currently *warns*. Whether it should REFUSE to start,
matching this repo's own precedent (commit 4b4b3fd, "gateway: refuse to start
rather than invent usage"), is a deployment-breaking change and is the
operator's call, not the fix's.

## Response redaction + stdio (implemented)

- **Response redaction** — with `TOKENFUSE_MCP_DLP` on, secrets in a tool's
  *response* are redacted (`[REDACTED:kind]`) before reaching the agent, so a
  tool result can't leak a credential into the model's context.
- **stdio transport** — `tokenfuse mcp-broker --stdio` (or `TOKENFUSE_MCP_STDIO`)
  speaks newline-delimited JSON-RPC on stdin/stdout for MCP clients that launch a
  server as a subprocess; logs go to stderr. Both transports share `process()`.

## Related: `mcp-scan --url` exposure checks

`tokenfuse mcp-scan --url <endpoint>` (separate from the broker above) adds
server-exposure checks on top of the poisoning/rug-pull scan: unauthenticated
`tools/list`/`tools/call` reachability, plaintext transport, wildcard CORS,
and SSRF-capable tool detection (`tokenfuse-core::mcpexposure`). **This
scanner is CLI-first** — built to run against a server you own, from your own
machine. If a hosted "paste a URL, we'll scan it" service is ever built on
top of it, the scanner becomes an SSRF oracle and MUST add resolve-then-pin
IP validation (deny-list loopback/RFC1918/link-local/cloud-metadata
addresses), no cross-boundary redirect following, and per-tenant egress
sandboxing — none of which is implemented today because CLI self-scan has no
SSRF elevation. See the doc comment at the top of
`crates/core/src/mcpexposure.rs` for the full writeup.

### CI: scan your MCP server on every PR

The repo root ships a composite GitHub Action (`action.yml`) that runs
`tokenfuse mcp-scan --url <endpoint>` in CI and fails the build when a
finding meets or exceeds `--fail-on` (default `high`). It always uploads the
`ScanReport` JSON as a build artifact, even when the scan fails, so a poisoned
tool or a rug-pull diff is easy to inspect from the failed run.

On `pull_request` runs it also posts (and, on re-runs, updates in place — no
comment spam) a markdown summary comment on the PR: severity counts, a table
of findings (kind/severity/tool/message, capped to ~20 rows), and the
`--fail-on` threshold + pass/fail outcome. That step is best-effort
(`continue-on-error: true`): it needs `pull-requests: write` on the *calling*
workflow (not just this action), and if that permission is missing or the
GitHub API hiccups, it silently no-ops rather than failing the job — the
scan's own exit code is always the real pass/fail signal.

```yaml
permissions:
  contents: read
  pull-requests: write   # needed for the PR-comment summary step

steps:
  - uses: TAIPANBOX/tokenfuse@main   # pin to a tag/SHA in production
    with:
      url: https://mcp.example.com/rpc
      fail-on: high                  # critical|high|medium|low|none
      # lock-path: .mcp-scan.lock.json   # rug-pull baseline, if you keep one
      # attempt-call: "true"             # only for a server you own
      # github-token: ${{ secrets.GITHUB_TOKEN }}   # defaults to github.token
```

`attempt-call` makes the scanner issue a live `tools/call`, not just
`tools/list` — only set it against a server you own, for the same reason the
CLI itself is self-scan-only (see above). See
`.github/workflows/mcp-scan-example.yml` in this repo for a full,
copy-pasteable `workflow_dispatch` template (it also shows the
`pull-requests: write` permission for the PR-comment step).

## Demo: see a rug pull caught live

[docs/17 · Rug-pull demo](17-rugpull-demo.md) — `cargo run --example
rugpull_demo -p tokenfuse-gateway` runs the pin-then-diff rug-pull check
above against a self-contained in-process stub server, end to end, printing
the `⛔ RUG PULL` / `Critical` output described in this doc.

## Not yet (follow-ups)

- Spawning a **child stdio MCP server** (today the broker forwards to an HTTP
  upstream from either transport).
