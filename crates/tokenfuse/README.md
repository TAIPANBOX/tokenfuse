# tokenfuse

**Runtime cost control & security for AI agents.**

TokenFuse is a drop-in proxy between your agent and its LLM/tool providers. It
enforces per-run budgets, detects runaway loops, provides a kill-switch, and
keeps secrets out of the model's context, without rewriting your agent.

TokenFuse runs as a **service**, not a library dependency. This crate is the
project's umbrella / name anchor; the gateway ships as the `tokenfuse` binary and
as Docker images:

```bash
docker run -p 4100:4100 -e TOKENFUSE_MODE=enforce \
  -e TOKENFUSE_UPSTREAM=https://api.anthropic.com/v1/messages \
  ghcr.io/taipanbox/tokenfuse
```

Then point your provider client at `http://127.0.0.1:4100` and attach a few
`X-Fuse-*` headers. `x-fuse-run-id` is required: a call the gateway cannot
account for is refused rather than forwarded unmetered. To try it with no
provider at all, add `-e TOKENFUSE_ALLOW_STUB=1`, which makes the gateway
answer from a built-in stub and meter invented usage; it is opt-in for exactly
that reason, and without either variable the process refuses to start.

- **Source & docs:** https://github.com/TAIPANBOX/tokenfuse
- **Python SDK:** `pip install tokenfuse-sdk` (imports as `tokenfuse`)
- **JS/TS helpers:** `npm install tokenfuse`

Licensed under Apache-2.0.
