# TokenFuse — Product Strategy: One Product or Separate Ones

> Decision locked in 2026-07-02. VERDICT: one product, one core, modular capability packs under a single brand. NOT separate products.

## Why NOT Separate Products

1. The single unbreakable advantage is the shared interception point. All of the uniqueness (a unified taint domain spanning web→RAG→memory→tool-call, a cache that feeds security, a ledger that sees everything) only exists as a single process sitting in the traffic path. Split it up, and each piece becomes "just another player" in a niche with existing competitors.
2. One buyer, one budget — a team buys one thing into its stack. 3 products = 3 sales cycles/integrations/invoices = friction that kills adoption.
3. Solo founder × 3 products = 0 products (3 READMEs, 3 CI setups, 3 communities, 3 brands).
4. Data flows in a loop — traces feed the cache, baselines, backtesting, and security. Separate products don't share the flywheel.

## Why NOT a Shapeless "Multi-Tool" Either

The opposite mistake. The cure is a clear "core + packs" model.

## Model: Core + Capability Packs

```
One brand, one binary, one installation

  FinOps pack    Cache pack    Security pack    Data pack
  (budgets,      (semantic     (taint, MCP,     (RAG ingest,
   kill, forecast) cache)      DLP)             ledger)
       │             │              │               │
       └─────────────┴──────┬───────┴───────────────┘
                            ▼
              Shared core (Rust):
    interception · ledger+traces · policy engine · taint domain
              Parquet+DataFusion · OTel
```

- One installation, one binary, one brand. Packs are enabled via config/license key, not separate downloads.
- The core is always free (OSS Apache-2.0): interception, ledger, basic budgets. The adoption engine.
- Pack monetization:
  - FinOps + Cache → Team tier (the cache pays for itself).
  - Security (taint, MCP broker, DLP) → Enterprise tier (bought by security teams with a different budget).
  - Data/RAG → a separate upsell.
- The roadmap doesn't change — the rings just get commercial packaging: Ring 1 = Cache, Ring 3 = Security, Ring 2 = Data.

## Technical Form

Cargo workspace: `crates/core` (interception, ledger, policies, traits) + `crates/pack-finops`, `pack-cache`, `pack-security`, `pack-data`. The packs implement the core's traits (PolicyHook, RequestInterceptor) and compile into a single binary using feature flags. One process, one release, code physically separated — fast development plus clean boundaries.

## When It's OK to Spin Off a Separate Product

The one scenario: if the MCP Credential Broker (S5) takes off enough that people want it WITHOUT the rest — then a separate, free OSS utility as a top-of-funnel entry point into the platform. A data-driven decision, a year out, not decided in advance.

## In One Sentence

Build a platform whose parts don't make sense apart — their inseparability IS the moat. Split it into separate products now, and you lose the one thing competitors can't copy.
