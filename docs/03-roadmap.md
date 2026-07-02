# TokenGuard — Roadmap

> Estimates: solo developer, full-time. Each phase = a separate public launch (a series of waves, not a single release).

## Phases

| Phase | Duration | Content | "Wow" on delivery |
|---|---|---|---|
| **0 — spikes** | 1.5 wk | Rust SSE passthrough for both providers; p99 measurement; header propagation through Claude Agent SDK / LangGraph; Parquet-writer prototype | "< 3 ms overhead" benchmark — the first tweet |
| **1 — MVP** | 5 wk | Gateway (Anthropic+OpenAI) + in-proc reserve/settle + per-run budget + max_tokens clamp + 402 contract + shadow mode + trace recording + Slack kill-button (W10) + **TUI `tokenguard top` (W2)** + Python SDK + `docker run` onboarding | The "90 seconds" demo, almost complete |
| **2 — intelligence** | 6 wk | Loop detectors (3 heuristics) + **burn forecast (W4)** + **MCP self-aware + approve flow (W3)** + **Parquet/DataFusion (W8)** + OTel (W9) + policy DSL + action chain + TS SDK + replay harness | **OSS launch: Show HN** |
| **2.5 — cache** | 2–3 wk | Semantic cache (local ONNX embedding, TTL/scope policies) | "Saved this month: $1,847" — the product pays for itself |
| **3 — platform** | 6–8 wk | **WASM policies (W5)** + **backtesting (W6)** + hierarchical budgets + embedding ledger + context auditor + secrets DLP + Cloud (multi-tenancy, billing) | "Policies as code + a time machine" |
| **4 — flagship** | 8+ wk | **Radar/eBPF (W1)** + **raft cluster (W7)** + taint policies + MCP gateway + vector proxy + virtual keys | "Agent runtime firewall"; "it finds shadow agents on its own" |
| **5 — enterprise** | — | AI-BOM inventory + compliance reports (EU AI Act) | Enterprise checkbox |

**To Show HN: ~12.5 weeks.** To first paying customer: ~4–5 months.

## Phase 0 gate

All three spikes green (SSE passthrough works, token estimation within ±15%, headers propagate through frameworks) — otherwise revisit ADR-1/ADR-6.

## MVP definition of done

A stranger goes from README to their first blocked runaway run in 15 minutes.

## "90 seconds to wow" demo (Show HN scenario)

```
00:00  docker run tokenguard                    ← one line
00:10  export ANTHROPIC_BASE_URL=http://localhost:4100
       the regular agent runs as before
00:20  tokenguard top                           ← live runs, $/min sparklines
00:35  launch a "broken" agent (demo repo with a deliberate loop)
00:45  TUI: the run turns red — "loop detected: same tool signature 3x /
       forecast: budget blowout at step ~34"
00:55  Slack: an alert with a [Kill run] button
01:00  the agent receives 402 budget_exceeded, shuts down gracefully
01:10  tokenguard sql "select task_type, sum(cost)... group by 1"
01:25  finale: "Rust, a single binary, your data in Parquet. github.com/..."
```

**Prioritization rule:** a feature enters an early phase only if it's in this demo or ≥3 real users have requested it.

> **Content note:** this demo scenario is a draft for an English-language YouTube Short / TikTok (strategy: short video pitches for all projects). Write every new "wow" moment so it also reads as a video script. Production tools: HeyGen, Higgsfield/Creative Claw, ElevenLabs.

## Success metrics

- time-to-first-blocked-run < 15 min
- p95 overhead < 10 ms (target p99 < 3 ms)
- ≥1 runaway prevented per active team/week (retention mechanic: every block = a "you saved $X" email)

## Monetization

- OSS self-host — free (Apache-2.0)
- Cloud: Free (1 project, 7-day retention) / Team ~$49–99/mo / Scale — % of spend under management
- Semantic cache unlocks a "% of savings" pricing model
- Enterprise self-host license — later

## GTM

- Launch waves: benchmark → MVP+TUI → MCP self-aware → backtesting → Radar (5 news hooks)
- Channels: Show HN, r/LLMDevs, r/LocalLLaMA (if Ollama support ships)
- Every integration (Claude Agent SDK, LangGraph, CrewAI, OpenAI Agents SDK) = a guide + example in the repo = content marketing
- TokenGuard can sit BEHIND LiteLLM (an enforcement layer, not a routing competitor)

## Risks

| Risk | Mitigation |
|---|---|
| Rust slows things down (~25–30% in the first months) | A Next.js dashboard without heroics; complex pieces (raft, eBPF) pushed to later phases |
| eBPF is Linux-only, brittle across kernels | Radar = opt-in module; CO-RE + aya; the product is fully functional without it |
| openraft — a complex distributed system | Phase 4; until then in-proc (80% of users) + a Redis option |
| WASM — over-engineering for MVP | CEL/YAML covers 90% of cases from Phase 2; WASM — Phase 3 |
| "Wow" eats the core focus | The demo-script rule (see above) |
| LiteLLM/Portkey copy the budgets | Speed + run semantics + behavioral detectors as the whole product, not feature #47; the OSS community as distribution |
| Providers change their APIs | A thin per-provider adapter; nightly contract tests against live APIs |
