# TokenGuard — Open questions (resolve before starting the code)

## Resolved

| Question | Decision | Date |
|---|---|---|
| Data plane language | Rust (tokio/hyper); Go — for the Cloud control plane; Next.js — dashboard | 2026-07-02 |
| Positioning | Start from the FinOps pain point, architecturally build toward an agent runtime firewall | 2026-07-02 |
| Distribution model | OSS core (Apache-2.0) + Cloud | 2026-07-02 (license to be finally confirmed — see below) |
| Telemetry storage | Parquet + DataFusion, no separate analytical DBMS | 2026-07-02 |

## Open

1. **Name and brand.** Working name — TokenGuard. Naming research done 2026-07-02:
   - "TokenGuard" is **crowded**: free on crates.io/npm/Docker Hub, but **taken** on PyPI (an adjacent Claude Code tool) and all good domains (.com/.dev/.ai/.io) are registered. GitHub has 12+ repos named tokenguard, including `LoveFishoO/TokenGuard` — "Zero-config proxy that stops runaway LLM agents from burning your API" (near-identical name + concept), plus several other LLM cost/budget repos. Poor discoverability and category-ownership risk.
   - Best free alternatives checked: **`tokenfuse`** (free on crates.io/npm/PyPI, `.dev` domain free, near-empty GitHub namespace; "fuse/circuit-breaker" metaphor fits the positioning) — **recommended**; `fuseguard` (fully free, slightly generic); `burnstop` — avoid (already used by direct competitors: `phuryn/burnstop` 8★ + a "pre-flight budget gate for AI agent runaways" repo).
   - **Decision pending:** keep TokenGuard (accept crowding; SDK on PyPI must use a different name) vs rename to `tokenfuse`. Renaming later = find/replace in docs + `gh repo rename`.
2. **License, final call:** Apache-2.0 (maximum adoption) vs AGPL (protection from cloud clones). Leaning toward Apache-2.0.
3. **First integration for launch:** Claude Agent SDK or LangGraph? (The Claude Code audience is already burning on this pain point — likely the answer.)
4. **Ollama/vLLM from Phase 1?** Local models: GPU-time/tokens instead of $. Cheap to add, expands the r/LocalLLaMA audience. Leaning toward "yes, as accounting without enforcement."
5. **`downgrade_model` in Phase 2 or later?** Quality risk → sneaky bugs for customers. Possibly warn+suggest only in Phase 2, auto-downgrade later.
6. **Cache pricing model:** fixed tiers vs % of savings (requires customer trust in our savings numbers).
7. **Content mode for the Context auditor:** how to communicate the departure from metadata-only (a separate opt-in track? an on-prem-only feature?).

## Next concrete steps (once execution starts)

1. Naming research (domain, crates.io, collisions).
2. Phase 0: break the 3 spikes into tickets with acceptance criteria:
   - SSE passthrough for Anthropic+OpenAI on hyper, p99 measured under 500 concurrent streams;
   - accuracy of local token estimation vs actual usage (target ±15%);
   - propagation of X-Guard headers through the Claude Agent SDK and LangGraph.
3. `git init` + first commit of these docs.
4. Repo skeleton: `crates/gateway`, `crates/policy`, `crates/ledger`, `crates/tui`, `dashboard/`.
