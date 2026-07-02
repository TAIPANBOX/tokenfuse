# TokenGuard

> Runtime control for AI agents: budgets, runaway-behavior detection, kill-switch.
> **Observability shows you the fire — we bring the automatic fire extinguisher.**

**Status:** planning (architecture v0.2, no code written yet). Created 2026-07-02 based on research into DevOps/Cloud/AI engineers' pain points.

## In one sentence

A proxy gateway between the agent and the LLM provider that doesn't just *track* spend (everyone does that), but *forcibly stops* runaway agents: per-run budget, loop detection, `max_tokens` clamp, burn forecast, kill-switch.

## Why this is worth building (from the research)

- Agents burn tokens 10-100x faster than chat; documented cases of 2,000 → 120,000 tokens per task.
- Standard APM is blind: a looping agent still returns `200 OK`.
- Competitors (Langfuse, Helicone, Braintrust) are a rearview mirror: they show you how much you've already spent. LiteLLM/Portkey have per-key/per-user budgets, but no run semantics, no loop detection, no step-by-step enforcement.

## Documentation

| File | Contents |
|---|---|
| [docs/01-research.md](docs/01-research.md) | Research: engineers' pain points, figures, sources, tooling gaps, alternative ideas |
| [docs/02-architecture.md](docs/02-architecture.md) | Architecture v0.2: Rust core, ADRs, components, data model, policy DSL |
| [docs/03-roadmap.md](docs/03-roadmap.md) | Phases 0-5, "90 seconds to wow" demo scenario, success metrics |
| [docs/04-expansion-rings.md](docs/04-expansion-rings.md) | Platform map: 4 expansion rings (cache, RAG, security, governance) |
| [docs/05-open-questions.md](docs/05-open-questions.md) | Open questions to resolve before starting on code |
| [docs/06-semantic-cache.md](docs/06-semantic-cache.md) | Detailed design of the semantic cache (partitions, thresholds, ONNX, invalidation) |
| [docs/07-taint-model.md](docs/07-taint-model.md) | Taint model specification (labels, propagation, policies, enforcement) |
| [docs/08-security-extensions.md](docs/08-security-extensions.md) | Security extensions: agent identity, MCP credential broker, RAG ingestion scanning (S1-S8) |
| [docs/09-product-strategy.md](docs/09-product-strategy.md) | One product vs. separate: verdict is "core + capability packs" |

## Key theses

1. **Enforcement, not observation** — the product sits in the request path.
2. **Rust data plane** (a single static binary, p99 < 3 ms), Go for the Cloud control plane, Next.js for the dashboard.
3. **OSS core (Apache-2.0) + Cloud** — the Langfuse/LiteLLM model.
4. **Rollout path:** shadow → warn → enforce (removes the fear of "yet another proxy in prod").
5. **Strategic arc:** cost control → data control → agent runtime firewall.
