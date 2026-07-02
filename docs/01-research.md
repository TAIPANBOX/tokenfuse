# Research: DevOps / Cloud / AI engineers' pain points (as of mid-2026)

> Conducted 2026-07-02 (deep research: 6 search tracks, 26 sources, 127 extracted claims).
> ⚠️ Verification status: search and fact extraction from real sources are complete; the final adversarial cross-check was not finished (session limit). Figures are attributed to sources but have not passed independent verification — treat as "according to X."

## 1. Cloud security

- **Secrets:** GitGuardian 2026 — 28.65 million new hardcoded secrets in public GitHub commits in 2025 (+34% YoY). AI service keys +81% (1,275,105). LLM infrastructure keys (orchestration, RAG, vector storage) leak 5x faster than model keys.
- **AI coding makes it worse:** Claude Code commits — 3.2% secret-leak rate vs. 1.5% baseline; MCP configs exposed 24,008 secrets (2,117 valid).
- **Remediation is the main gap:** 64% of valid secrets leaked in 2022 are still active (January 2026). Detection exists — remediation doesn't.
- **Automation is detection-only:** 37% of organizations — automation only alerts; only 11% have autonomous remediation (Cloud Security Report 2026, n=1,163).
- **Tool sprawl:** 69% — the main barrier. IAM (77%) and misconfiguration (70%) are the top-2 risks.
- **NHI:** ~100 machine identities per human.
- **CNCF:** lack of expertise (58%), DevOps×security complexity (51%).

## 2. AI/LLM and agent security

- 65% of organizations had an AI agent security incident in the past year, all with business impact (CSA/Token Security "Autonomous but Not Controlled").
- 82% found shadow AI agents; meanwhile 68% claim "high visibility" (self-deception).
- >80% of Fortune 500 run low-code/no-code agents; only ~10% have a governance strategy (Microsoft Cyber Pulse 2026).
- MCP: >10,000 active public servers. Attacks: tool poisoning, variable poisoning, prompt injection, rug pull, server impersonation (peer-reviewed, ACM). The first full scanner (tools+prompts+resources) only appeared in early 2026. DLP/CASB don't see MCP traffic.
- OWASP: LLM Top 10 v2 (prompt injection #1, agentic focus) + new Top 10 for Agentic Applications 2026 (ASI01 = Agent Behavior Hijacking).

## 3. AI agent operations (LLMOps)

- Tokens: agents burn tokens 10-100x faster than chat (context re-sent on every step; >30x at 50 steps, >100x at 200). Case: a code-review agent went from 2,000 to 120,000 tokens after a self-improvement loop.
- APM is blind: a looping/hallucinating agent returns 200 OK at normal latency.
- Reddit (Apr-Jun 2026): inference cost is a direct blocker; a shift toward local models.

## 4. Data and databases for AI (RAG)

- 72% of organizations have RAG in production (Q1 2026).
- Three root causes of unreliability: stale data, cross-tenant leakage, query-complexity explosion — all stemming from splitting the operational DB from a separate vector DB (arXiv). Unifying on Postgres+pgvector+HNSW: -92% latency (date-filtered), -74% (tenant-scoped).
- Document parsing (broken tables) is the root cause of "plausible but wrong" answers.
- Reranking +10-30% precision; semantic chunking +9% recall.
- Incremental embedding pipelines (content-hash) save ~90% compute — but teams keep rebuilding from scratch.

## 5. Cross-cutting (trust in AI)

- DORA 2025 (n≈5,000): 90% use AI, 30% have low/no trust in AI-generated code; AI adoption correlates negatively with delivery stability.
- Stack Overflow 2025: 66% — frustration with "almost right, but not quite"; 45% — debugging AI code takes longer; distrust (46%) > trust (33%).
- DevOps engineers spend ~30% of their time on routine work (DuploCloud, n=135).

## 6. Tooling gaps (where the market is weak)

| # | Gap |
|---|---|
| G1 | Secret remediation (not detection) |
| G2 | Visibility/governance for MCP and agents |
| G3 | FinOps for agents (token cost enforcement) ← **chosen: Tokenfuse** |
| G4 | Agent observability (200 OK ≠ success) |
| G5 | Guardrails against prompt injection in tool-calling |
| G6 | RAG data freshness/quality |
| G7 | CSPM alert triage |

## 7. Tool ideas (prioritization at the time of research)

1. **Agent Token-Budget Guard** ← chosen (Tokenfuse)
2. MCP Security Scanner / Gateway (the emptiest market; folded into Tokenfuse as Ring 3)
3. Secret Remediation Bot (a strong alternative; multi-provider auto-rotation)
4. RAG Data-Freshness & Quality Linter (partially folded in as Ring 2)
5. Agent Observability (red ocean — do not pursue)
- ⚠️ Standalone eval startup — do NOT build: thin ops margins, capped revenue, the feature gets absorbed by platforms (Thomas Liao, "Why are there so few independent eval startups").

## Key sources

- https://dora.dev/dora-report-2025/
- https://survey.stackoverflow.co/2025
- https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026/
- https://www.cybersecurity-insiders.com/2026-cloud-security-report-closing-the-cloud-complexity-gap/
- https://cloudsecurityalliance.org/blog/2026/04/28/the-shadow-ai-agent-problem-in-enterprise-environments
- https://cloudsecurityalliance.org/blog/2026/03/13/the-state-of-cloud-and-ai-security-in-2026
- https://dl.acm.org/doi/10.1145/3786160.3788471 (MCP threat landscape / MCP-Scanner)
- https://arxiv.org/pdf/2605.03275 (RAG unified Postgres)
- https://repello.ai/blog/owasp-llm-top-10-2026
- https://www.practical-devsecops.com/owasp-top-10-agentic-applications/
- https://thomasliao.com/eval-startups
- https://accuknox.com/blog/cncf-cloud-native-security-survey
- Reddit digests of agentic threads (dev.to, Apr-Jun 2026), HN item 48637868
