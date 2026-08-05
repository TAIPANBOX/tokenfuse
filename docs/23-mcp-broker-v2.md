# 23 - mcp-broker v2: named upstreams, a policy gate, and tool-call audit

Status: v2, shipped as `feat/mcp-broker-v2`. Three additions to the existing
MCP credential-broker, each additive and off by default so a broker with no
new config behaves exactly as before.

The framing is unchanged and deliberate (see `docs/09-product-strategy.md`
and CLAUDE.md): the broker is one capability pack, not a product, and this is
not an "MCP security scanner". It is a second Policy Enforcement Point for an
operator governing their OWN agents' MCP tool use.

## 1. Named upstreams

The broker forwarded to one `TOKENFUSE_MCP_UPSTREAM`. It can now hold several:

```
TOKENFUSE_MCP_UPSTREAMS="github=https://mcp.github.example, files=http://127.0.0.1:9001"
```

A request selects one with the `X-Fuse-Mcp-Upstream` header; with no header it
goes to the default `TOKENFUSE_MCP_UPSTREAM` (or, if only named upstreams are
configured, the first of them). An unknown name is **refused** with JSON-RPC
error `-32005`, never silently re-routed: forwarding a request, and the
secrets the broker is about to inject, to a server the operator did not name
is exactly the mistake the refusal prevents. The stdio transport has no
per-message header channel, so it always uses the default upstream.

## 2. The second PEP: Wardryx on `tools/call`

Every `tools/call` is now put to the same Wardryx PDP the LLM path uses
(`proxy::messages` -> `Wardryx::decide`), so a `deny_tool` policy (or
`deny_if_unattested`, or an approval `hold`) enforces at the MCP layer, not
only on the model-call path. The gate runs **before** secret injection and
forwarding, so a denied tool never receives a real secret and never reaches
the upstream.

Config is the shared `TOKENFUSE_WARDRYX_*` (mode, URL, key, failmode, timeout,
cache): configure Wardryx once and both the gateway and the broker enforce.
The gate is off unless `TOKENFUSE_WARDRYX_MODE` is `shadow`/`enforce` and
`TOKENFUSE_WARDRYX_URL` is set.

Decisions:

- **enforce + allow**: the call proceeds (secrets injected, forwarded).
- **enforce + deny**: JSON-RPC error `-32004`, naming the tool and the PDP's
  reason. The tool never runs.
- **enforce + hold**: JSON-RPC error `-32004` stating approval is required
  (with the approval id when the PDP gave one). The broker cannot run the
  interactive approval ceremony, so a hold is a refusal-with-reason here; the
  approval row Wardryx created can be granted and the call retried with
  `x-fuse-approval-token`, which the broker forwards to the PDP.
- **shadow**: never blocks; the response is annotated
  `{"_tokenfuse": {"wardryx": "would-<decision>"}}` so a rollout can see what
  enforce would do.

The `DecideContext` for a `tools/call` sends `agent_id` (from
`X-Fuse-Agent-Id`), `tool_names = [the called tool]`, `on_behalf_of` and
`attestation_method` from their headers, and a stable per-agent `run_id`
(`mcp:<agent>`). The broker has no run/budget/step/model state, so `steps`,
`domains`, `model`, and `est_cost_usd` are sent empty; Wardryx reads an empty
value as "nothing to restrict", never as a denial, so tool and attestation
rules still apply and the cost/step rules simply do not fire here.

**No identity, no call (enforce mode).** Without an `X-Fuse-Agent-Id` (every
stdio call, and any HTTP call that omits it) an enforcing gate **refuses** the
`tools/call`. It does not fabricate an id, and it no longer skips.

This is a correction, made 2026-08-05. The gate used to skip, on the stated
reasoning that "an empty agent id would match no policy anyway (an allow), so
skipping yields the same result made explicit". That is an assumption about
another service's behaviour, and it is false for exactly the policy this gate
was added to enforce: a tool-scoped `deny_tool` denies the TOOL, whoever calls
it, so dropping one header the caller writes turned the deny into an allow.
Secret injection then ran anyway, four lines below a comment promising it would
not.

The refusal matches the LLM path byte for byte, because it is the LLM path's
own function (`proxy::identity_required`): HTTP `400`, body
`{"error":{"type":"identity_required","reason":"... send one in
`x-fuse-agent-id`","retryable":false}}`. Enforce only, also mirroring the LLM
path: shadow mode blocks nothing by definition and keeps observing with
whatever attribution it was given, and a broker with no Wardryx configured is
untouched.

Consequences worth naming rather than burying:

- **stdio + enforce is now a refusal on every `tools/call`.** The transport has
  no per-message header channel, so it can never carry the subject the policy
  keys on. The JSON-RPC form of the same decision is error `-32007`, since
  stdio has no status line. An operator who wants both must use the HTTP
  transport with `X-Fuse-Agent-Id`, or run the gate in shadow.
- **`tools/list` is unaffected.** The gate only covers `tools/call`, so the
  poisoning and rug-pull scan still answers an unidentified caller: refusing it
  would remove a control that works in the name of adding one.
- A header that is present but blank names nobody, and is read as absent
  everywhere here, including for the `agent_id` on an emitted event.

The broker holds no signer and mutates no plane: it can refuse a call, never
perform one.

## 3. `tool_call` audit events

Each Wardryx-gated `tools/call` emits one `tool_call` agent-event (a new
`EventType`, agent-passport SPEC.md §6 envelope) carrying
`data: {tool, upstream, decision}`, where `decision` is `allow|deny|hold` (or
`would-<decision>` in shadow). Severity is `low`: this is a per-action audit
signal, not an alert, so an allowed call never pages like an incident; the
verdict lives in `data.decision`. Like every event here it is skipped (not
fabricated) when `agent_id` is absent, and it is zero-cost when the exporter
(`TOKENFUSE_EVENTS_PATH`) is unset.

This is the MCP-layer tool-invocation signal. It is distinct from the I1
`tool_calls` Parquet column (docs/21), which counts the tool-use blocks a
MODEL emits in an LLM response and inspects no MCP traffic. Both are "tool
call" signals; they measure different things and neither replaces the other.

## Wire error codes (broker JSON-RPC)

- `-32001` poisoned tool description (existing)
- `-32002` raw secret in tool arguments (existing)
- `-32003` rug-pull: tool definition changed (existing)
- `-32004` Wardryx denied or held the tool call (new)
- `-32005` unknown named upstream (new)
- `-32006` pii in tool arguments or response (`TOKENFUSE_MCP_DLP_PII=block`)
- `-32007` the call named no agent, so an enforcing gate could not judge it.
  Distinct from `-32004` on purpose: a refusal because the gate could not RUN
  is a different fact from one the gate decided, and a client that retries on
  the second should not retry on the first. The HTTP transport answers this
  case with `400 identity_required` instead, matching the LLM path.

## Out of scope for v2 (named, not hidden)

- Tool-namespacing federation (merging several upstreams' `tools/list` under
  name prefixes) is not done; v2 selects one upstream per request by header.
- The broker still forwards to an HTTP upstream from either transport; it does
  not yet spawn a child stdio MCP server (the `docs/12` follow-up stands).
- No budget/step accounting exists in the broker, so the Wardryx cost and
  step rules do not apply to `tools/call` (only tool, domain, attestation, and
  approval rules do).
