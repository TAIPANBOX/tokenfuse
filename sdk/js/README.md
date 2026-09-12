# tokenfuse (JS/TS SDK)

Thin, dependency-free client helpers for [TokenFuse](https://github.com/TAIPANBOX/tokenfuse),
runtime cost control for AI agents.

TokenFuse is a drop-in proxy: you don't rewrite your agent, you point your
provider client at the gateway and attach a few `X-Fuse-*` headers. This package
builds those headers and URLs.

## Install

```bash
npm install tokenfuse
```

## Use

```js
const tf = require("tokenfuse");
const Anthropic = require("@anthropic-ai/sdk");

const client = new Anthropic({
  baseURL: tf.gatewayUrl(),                          // http://127.0.0.1:4100
  defaultHeaders: tf.runHeaders("run-42", { budgetUsd: 5.0 }),
});
```

When a run exceeds its budget (or trips a policy/loop/kill), the gateway returns
`402` with a stable JSON error contract (`budget_exceeded`, `loop_detected`,
`policy_violation`, `killed`, `wasm_policy`, …): inspect the response status/body.
Two additional block types return `403` instead of `402`: `dlp_blocked` (a
secret was found in the outgoing prompt) and `taint_blocked` (the model asked
for a capability denied under the run's taint).

### The OpenAI door

A gateway started with an OpenAI-shaped upstream (`TOKENFUSE_UPSTREAM` ending in
`/v1/chat/completions`, or `TOKENFUSE_WIRE=openai`) serves OpenAI-shaped clients.
One process, one wire shape; the same headers, the same 402 contract:

```js
const OpenAI = require("openai");

const client = new OpenAI({
  baseURL: tf.openaiBaseUrl(),                       // http://127.0.0.1:4100/v1
  defaultHeaders: tf.runHeaders("run-42", { budgetUsd: 5.0 }),
});
```

## API

- `gatewayUrl(gateway?)`: base URL for an Anthropic-shaped client.
- `messagesUrl(gateway?)`: the Anthropic-style messages endpoint.
- `openaiBaseUrl(gateway?)`: `baseURL` for an OpenAI-shaped client (the gateway root plus `/v1`).
- `chatCompletionsUrl(gateway?)`: the OpenAI-style chat completions endpoint.
- `runHeaders(runId, { budgetUsd, taskType, parentRunId, tags })`: the `X-Fuse-*` headers.

Versions: from 0.5.0 this package versions with the gateway.

Ships with TypeScript types. Licensed under Apache-2.0.
