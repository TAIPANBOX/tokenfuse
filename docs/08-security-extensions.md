# Tokenfuse — Agent / MCP / RAG Security Extensions

> Advisory note, locked in 2026-07-02. No code written yet. The throughline idea is a UNIFIED TAINT DOMAIN: a single "untrusted" label flows through web → RAG ingestion → memory → tool call. The uniqueness lies in having all interception points within a single product.

## 1. Security of the Agents Themselves

### S1. Agent Identity / "IAM for NHI" ⭐⭐⭐
Each agent is a separate identity with scoped permissions (models, tools, budgets), short-lived tokens (TTL of minutes, auto-rotation), and one-click revoke. Agents never see the real provider keys. This addresses the "100:1 NHI sprawl" problem and the fact that "64% of leaked secrets stay active for years" (a short-lived token has nothing left to rotate). An extension of virtual keys. Phase 4.

### S2. Memory Poisoning Protection ⭐⭐
Taint labels survive being written into agent memory: content from a web context → the memory write carries the label → when read back N sessions later, the context is tainted again. Propagation rule P5 (to be added to doc 07) + interception of memory tools. OWASP Agentic explicitly covers memory poisoning; almost nobody enforces it. Phase 4.

### S3. Behavioral Baselines / Drift ⭐
A normal-behavior profile per task type (tool sequences, step distribution) → alert on deviation (a compromised agent behaves differently before performing forbidden actions). A later-stage feature (requires a volume of traces) — this is our data flywheel, and competitors don't have the traces. 

### S4. Tamper-Evident Audit ⭐⭐
A hash chain (each record includes the hash of the previous one) + periodic signing. Forensics after an incident + EU AI Act compliance almost for free (we already write every decision anyway). A cheap extension of decisions_audit. Phase 3.

## 2. MCP Security (on top of the already-planned gateway)

### S5. MCP Credential Broker ⭐⭐⭐ (top pick overall)
MCP server credentials live in our broker; the agent connects to servers through a gateway that injects short-lived credentials on the fly. Zero secrets in developer configs. Straight from the research: MCP configs leaked 24,008 secrets (2,117 valid) because keys sit in plaintext in mcp.json. Architecturally trivial (we're already a proxy). The best bridge from FinOps to secrets security. This is where the MCP gateway should START, not with a scanner. Phase 4.

### S6. MCP Lockfile ⭐⭐
Like package-lock.json for MCP: we pin hashes of the descriptions of all tools/prompts/resources in mcp.lock. A description change (rug pull) → blocked until re-approved, with a diff. Makes rug-pull detection declarative and version-controlled in git. A "viral" idea for launching the MCP gateway. Phase 4.

## 3. RAG Security

### S7. Ingestion Scan — "Antivirus for the Corpus" ⭐⭐⭐
The most dangerous RAG attack vector is indirect injection in documents (white text in a PDF, HTML comments, zero-width characters, ASCII smuggling). Scan the corpus ON INGESTION: intercept the embedding calls (we already sit there for the embedding ledger) → run an injection-pattern scanner → quarantine poisoned chunks before indexing, tagging them with a provenance label. A real attack vector, almost no existing tools cover it, and it's pure synergy with the cost-savings feature. Phase 3.

### S8. Retrieval Taint — Closing the Loop ⭐⭐
Chunks from the vector DB carry provenance labels from ingestion (S7); when pulled into context, taint activates → the full policy engine kicks in (doc 07). RAG stops being a blind spot for poisoned content. This unifies the vector proxy (2.3) + embedding ledger (2.1) + taint model (07) into a single organism.

## Prioritization

| Pick | Feature | Pain | Complexity | When |
|---|---|---|---|---|
| 🥇 | S5 MCP Credential Broker | 24k secrets in MCP configs | low | at MCP gateway launch, P4 |
| 🥇 | S7 RAG Ingestion Scan | indirect injection in documents | medium | alongside embedding ledger, P3 |
| 🥈 | S1 Agent Identity/NHI | 100:1 NHI sprawl | medium-high | alongside virtual keys, P4 |
| 🥈 | S6 MCP Lockfile | rug pull | low | alongside MCP gateway, P4 |
| 🥈 | S2 Memory Poisoning | OWASP Agentic | low (rule P5) | alongside taint, P4 |
| 🥉 | S4 Tamper-Evident Audit | forensics, EU AI Act | low | P3 |
| 🥉 | S8 Retrieval Taint | RAG as an injection channel | medium | after S7+taint |
| 🥉 | S3 Behavioral Baselines | compromised agent | high | later stage, flywheel |

## Key Takeaway

S5 and S7 are not just "add-ons" — they UNIFY what's already planned: S5 makes the MCP gateway the place where all credentials live (rather than just another scanner); S7 makes the embedding hook do double duty (cost savings + security). The throughline uniqueness is a unified taint domain across all interception points — something nobody else has.
