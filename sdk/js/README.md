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
- `createAgentFetch({ issuer, key, clientId, clientSecret, workloadToken, audience, fetch, now })`: a `fetch` that signs each request for an agent (see below).
- `AgentTokenError`: thrown when vouchryx refuses the token request.

### Agent tokens

`createAgentFetch` returns a `fetch`-compatible function that holds an agent's ES256
key, asks vouchryx for a short-lived token, and signs each request to a TokenFuse door:

```js
const { createAgentFetch } = require("tokenfuse");

const agentFetch = createAgentFetch({
  issuer: "https://vouchryx.example.com",
  key: pemKey,                      // the agent's ES256 (P-256) private key, PEM
  clientId: "agent://acme/triage",
  clientSecret: enrolmentKey,       // or workloadToken: () => readProjectedToken()
});
const res = await agentFetch("https://tokenfuse.example.com/v1/messages", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body,
});
```

The token is asked for again at 80 percent of its life, every request carries a fresh
proof, and a DPoP nonce challenge is answered by one retry. The module uses `node:crypto`
only. It needs `fetch`: Node 18 or later, or an `options.fetch` of your own.

Versions: from 0.5.0 this package versions with the gateway.

Ships with TypeScript types. Licensed under Apache-2.0.
