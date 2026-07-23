# 21 - Tool runs: counting the tool calls a model emits per LLM call

Status: v1, shipped as `feat/tool-calls-metric`. An observed metric only:
this doc describes what gets counted and how it flows through the
pipeline, not a budget or a policy. There is no enforcement on tool calls
in this release.

## What counts as a tool run

One "tool run" is one tool call the MODEL emits in a single proxied
response - not a tool the request offered, not a tool the client later
executed and reported back. The count is derived purely from the response
body/stream TokenFuse already parses for token usage
(`crates/gateway/src/provider.rs`); no new request is made and no MCP
traffic is inspected.

Counting rules, per provider and per streaming mode:

| Provider | Non-streaming | Streaming (SSE) |
|---|---|---|
| Anthropic | Number of `content[]` blocks with `"type":"tool_use"` in the response body. | Number of `content_block_start` events whose `content_block.type == "tool_use"`. |
| OpenAI | `choices[0].message.tool_calls` array length, summed across choices if the request asked for more than one. | Number of DISTINCT `index` values seen across `choices[].delta.tool_calls[]`. |

The OpenAI streaming rule matters: a tool call's `arguments` stream in
across several deltas that all repeat the same `index`, so counting delta
EVENTS would overcount; only the count of unique indexes is the number of
tool calls.

TokenFuse is a provider-agnostic reverse proxy (one endpoint, `/v1/messages`,
forwards whatever body it's given), so the counter inspects the JSON shape
rather than the endpoint path - the same approach `merge_usage`'s existing
Anthropic/OpenAI usage parsing already uses. See
`crates/gateway/src/provider.rs`'s `ToolCallCounter` for the implementation
and its unit tests for worked examples of each rule above.

## No tool calls vs. unparseable: `Option<u32>`, never a guess

The field is `tool_calls: Option<u32>` everywhere it appears (Parquet trace,
Cloud ingest/aggregates, FOCUS export), and the two "empty" states mean
different things:

- `Some(0)`: the response body parsed and genuinely contained no tool
  calls. This is the common case for an ordinary text response.
- `None`: the body never parsed as JSON at all - a call that was blocked
  before it reached the provider (no response exists to inspect), an
  upstream error, or a truly garbled/empty body.

Nothing ever guesses a count from an ambiguous shape. One exception is
worth calling out because it looks like a guess but isn't: a semantic-cache
hit (`crates/gateway/src/proxy.rs`) records `Some(0)`, not `None`, because
the cache only ever serves a request that declared no `tools` at all
(`cache_eligible`) - the model backing that cached response structurally
could not have emitted a tool call, so `0` is a fact, not an assumption.

Every call that was blocked before reaching the provider (budget, policy,
loop, WASM policy, Wardryx deny/hold, unit budget, identity mismatch)
records `None`: there is no response to have counted anything from. A
post-hoc block on an already-completed call (the agent firewall's
`taint_blocked` verdict) also records `None` on its own row - the real
observation already landed on the sibling `allow` row for that same call,
and duplicating it would double-count.

## Where it lives

- **Parquet trace** (`crates/gateway/src/sink.rs`): `CallRecord.tool_calls`
  is the newest column, appended at the end following the same
  nullable-evolution pattern as every prior addition (`agent_id`,
  `parent_run_id`, `outcome`, `key_id`, `unit`, ...). Unlike those string
  columns (which default a missing value to `""` and are only nullable in
  the *read* schema), `tool_calls` is a genuinely nullable `UInt32` column
  in BOTH the write and read schema, because `None` and `Some(0)` are
  different facts worth preserving as a real Parquet NULL vs. a real zero.
  `tokenfuse sql` reads a directory mixing pre-I1 files (no `tool_calls`
  column at all) with new files transparently - see
  `crates/gateway/src/sqlq.rs`'s
  `mixed_pre_tool_calls_and_tool_calls_schema_files_read_with_defaults`.
- **FOCUS export** (`crates/gateway/src/focusexport.rs`): a new
  `x_tool_calls` column, following the `x_unit` precedent. Blank (not
  `"0"`) for a `None` value.
- **Cloud ingest + aggregates** (`crates/cloud/src/store.rs`): the
  ingest `CallRecord` DTO carries the field additively
  (`#[serde(default)]`). `RunAgg`, `AgentAgg`, and `UnitAgg` each get a
  `tool_calls: u64` SUM across their calls, gated by the same
  `is_blocked` exclusion real spend uses (a blocked row's tool_calls -
  which a well-behaved gateway never sets anyway - can't inflate the
  total). `Summary.tool_calls` is the org-wide running total. The
  burn-rate series (`SeriesBucket.tool_calls`) sums UNCONDITIONALLY,
  mirroring `cost_microusd`: it's an activity signal, not a trusted
  accounting total.
- **Dashboard** (`cloud/dashboard/app/page.tsx`): a "Tool runs" column on
  the Runs table, and a "Tool runs today" summary tile.

## Serde compatibility, both directions

Nothing in this repo sets `#[serde(deny_unknown_fields)]` on any ingest or
trace-adjacent type, so the field is additive in both directions with zero
extra code:

- An OLD gateway (pre-I1) omits `tool_calls` from its `/v1/ingest` POST;
  `#[serde(default)]` on the Cloud-side DTO defaults it to `None`.
- A NEW gateway sends `tool_calls` to an OLD control plane that predates
  this field: serde's default behavior silently drops unrecognized JSON
  keys, so the batch still ingests cleanly - the old plane just never
  aggregates a dimension it doesn't know about yet.

## Explicitly out of scope for v1

This is an OBSERVED metric only:

- No budget, cap, or per-tool-call price. `ModelPrice::cost` deliberately
  does not read `Usage::tool_calls`.
- No policy or enforcement decision reads this field. The agent firewall's
  taint/capability checks are unrelated and unchanged (they classify WHICH
  tools were named, not how many calls were made).
- No new event type and no ledger/raft change - `tool_calls` never reaches
  `LedgerBackend` or `crates/cluster`.

If a future increment wants budgets on tool-call volume, that's a
deliberate follow-up decision, not an implicit consequence of this one.
