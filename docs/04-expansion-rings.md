# Tokenfuse — Platform expansion map ("rings")

> Selection principle — 4 filters: (1) reuses our existing assets (interception point, ledger, traces, policies+MCP), (2) pain point confirmed by research, (3) same buyer, (4) doesn't pull in a new operational dependency.

## Ring 1 — Efficiency (same traffic)

### 1.1 Semantic cache ⭐ (top pick)
Caches LLM responses by embedding similarity + exact-match for deterministic tool results. Agentic workloads are wildly repetitive. A cache hit = $0 and ~5 ms.
- Reuse: interception point + ledger (auto savings report).
- Business: "Saved this month: $1,847"; a "% of savings" pricing model.
- Staleness risk → governed by policies (TTL, scope per task-type, tag-based invalidation, off for side-effect tools).
- Local embedding: an ONNX model in the binary, no external calls.
- **Phase 2.5.**

### 1.2 Model cost routing
"Task-type → Haiku, escalate to Opus on retry", fallback on outage, canaries. The mature form of the downgrade action. Differentiation from LiteLLM: routing as a consequence of budget policy and burn trend, not static config. **Phase 3.**

### 1.3 Context compression (opt-in)
LLMLingua-style. Explicit opt-in only + an A/B quality report on golden traces. **Phase 4+, low priority.**

## Ring 2 — RAG and data

Rationale: 72% run RAG in production; pain points — freshness, tenant isolation, ~90% wasted embedding compute, context stuffing. The agentic stack = LLM API + vector DB API; we're already in the first one.

### 2.1 Embedding ledger ⭐
Accounting for `/v1/embeddings`: content-hash → "this text has already been embedded 47 times", a "full rebuild $X vs incremental $X/10" report. Almost zero new architecture. **Phase 3.**

### 2.2 Context auditor
Waste index: how many retrieved tokens actually influenced the response (citation heuristics + a sampled LLM-judge on a cheap model). "Reads 38k, uses 2.1k → $410/mo overspend; recommend top_k 20→6 + reranker." Requires an opt-in content mode. **Phase 3.**

### 2.3 Vector proxy
A gateway pattern for Qdrant/pgvector (start with two): hit-rate, chunk age in results (freshness), **detection of tenant isolation breaches** (tenant A received tenant B's chunks → block/alert). ~80% reuse. Caution: N adapters = maintenance burden. **Phase 4.**

## Ring 3 — Agent security (the biggest strategic prize)

### 3.1 Taint policies for tool calls ⭐ ("agent firewall")
Context that touched an untrusted source (web, external email, an unknown MCP tool) → tainted → high-privilege actions (writing to prod, email, exec) are blocked pending human approval. Defense against prompt injection at the level of ACTIONS, not words.
- Reuse: tool-call history in traces + block mechanics + the approve flow from W3.
- Market: OWASP ASI01, 65% of organizations report incidents.
- **Phase 4, but the `source_taint` field in the trace ships from Phase 1** (otherwise it's a painful migration).

### 3.2 DLP: secrets in prompts
Scan traffic in both directions (regex + entropy, local) → masking/block. We're the point where "traditional DLP can't see agentic traffic." Low-to-medium complexity, high value. **Phase 3.**

### 3.3 MCP gateway
Proxy MCP connections: a registry of allowed servers, scanning of tools/prompts/resources, **rug-pull detection** (a tool's description changed between sessions), audit + per-tool cost attribution. The emptiest market found in research (>10k servers, the first full scanner only appeared in early 2026). **Phase 4.**

## Ring 4 — Governance (enterprise)

- **Agent inventory / AI-BOM:** Radar → a registry of "which agents, models, tools, data." Pain point: 82% shadow agents.
- **Compliance reports:** EU AI Act — audit log + ledger → a report at the click of a button.
- **Golden traces / regressions:** replay harness as a feature: "after the prompt change, cost +40%, steps 12→31." Boundary with evals: we stick to cost/behavior metrics.

## What we deliberately do NOT build

| Temptation | Why not |
|---|---|
| Standalone eval product | Research shows: ops-heavy margins, capped revenue, the feature gets absorbed by platforms |
| Full observability | Red ocean (Langfuse/Braintrust/Arize); we integrate via OTel instead |
| Our own agent framework | A different product; we need to work with all of them |
| RAG builder / chunking | A different buyer; our role is accounting, audit, guard |

## Strategic arc

```
Phase 1-2   core                     "cost control"
Phase 2.5   semantic cache           "we pay for ourselves"
Phase 3     ledger+auditor+DLP       "spend + data + first security teeth"
Phase 4     taint+MCP gateway+Radar  → category: AGENT RUNTIME FIREWALL
Phase 5     AI-BOM+compliance        "enterprise checkbox"
```

Narrative: "stop burning money" → "stop burning money and data" → "runtime control over everything agents do."

## Bake into the architecture from day 1 (even if the code comes later)

1. Semantic cache — the "serve from cache" decision as a policy-engine action.
2. Taint — a source field on every message in the trace.
3. Gateway protocol abstraction: LLM API today → MCP tomorrow → vector DB the day after.
