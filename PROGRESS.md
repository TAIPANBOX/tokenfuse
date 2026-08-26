# TokenFuse — build progress

A living log of *where the code is*, so anyone (or a future session) can pick up
mid-stream. Planning docs live in [`docs/`](docs/); this file tracks implementation.

**Last updated:** 2026-08-06, covering the 2026-08-04 cloud range's first four
items. One theme: a guarantee nobody switched on, a command nobody could run,
and a severity nobody could sort by are all the same failure, which is that the
thing we say is true was never the thing anybody checked.

**The documented command could not start a gateway** (this branch). Since the
gateway learned to refuse to start rather than meter invented usage as spend,
`docker run ... ghcr.io/taipanbox/tokenfuse` exits 2, and every place that
advertised the old behaviour still advertised it: the README headline and its
get-started step, the Dockerfile comment, the crates.io crate's doc, the Show HN
draft, and `cloud/docker-compose.yml`, whose gateway service would crash-loop
the moment its image was rebuilt. `grep -r ALLOW_STUB docs/` returned nothing.
All fixed, and held by `scripts/runnable-quickstart.sh` (invariant 16), because
a document does not compile and this is the one thing about it that can be
checked mechanically.

**The safe defaults are the defaults** (same branch, invariant 17). `TOKENFUSE_DLP`
unset meant `off` and a call with no `x-fuse-run-id` reached the provider
recorded nowhere, so a deployment could pass every check it had and be governed
on paper. Both now point the other way, both are one explicit variable from the
old behaviour, and the consequence on upgrade is stated in the README rather
than discovered.

**A detector's severity comes from its magnitude** (same branch, invariant 18).
Measured on 999 agents: 3000 alerts, trip counts from 1 to 73, median 2, and one
severity on all of them. The detector scaled as computation and not as an alert.

**A check that cannot fail** (same branch, invariant 19). `GET /v1/policy-plane`
reports what the PDP has ANSWERED, counting a fail-open fallback as what it is
rather than as an allow, so "the policy plane is on the data path" stops being a
statement about environment variables;
earlier 2026-08-06, covering #178-#180. Three commits about the
checks themselves, and the shape they share is that a check can fail without
having established anything.

**Two gates were wrong in ways that read as findings** (#178, #179).
`stated-numbers.sh` matched its pattern across the whole of this file and took
the first hit, so a new paragraph recording that PROGRESS.md once said "100
passing" was read as the current claim, and the gate failed on its own history
lesson. Scoped to the Test status section, where the claim lives, because a
check a true sentence can break is a check somebody eventually deletes.
`core-deps.sh` could not pass an empty read, which sounded safe and was not: it
failed with five lines saying serde, sha2 and the rest had been removed from a
manifest that still lists all five, plus advice about putting new dependencies
in the gateway. Every word pointed at `Cargo.toml`, where nothing was wrong. An
unreadable manifest now has its own exit path, distinct from a finding, and the
distinction it draws is where it sends the reader.

**The mutants stopped being prose** (#180). Four gates hold four invariants and
every one parses text with regular expressions, which does not break loudly: it
stops matching and reports success. Three of the four broke exactly that way
while being written, each caught only because a mutant was supposed to fail and
did not. Those mutants lived in commit messages and in CLAUDE.md's
`*(gate: ...)*` markers, a record of what was true once, and nothing ran them
again. `scripts/gates-have-teeth.sh` now runs nine of them in CI: eight require
a gate to fail on the fault it exists to catch, one requires a gate NOT to fail
on what it must not catch, and three require the failure to say the right thing,
since "it failed" and "it failed for this reason" are different claims. It was
checked against itself, because a checker of checkers can also be toothless;
earlier 2026-08-06, covering #171-#177. One theme, and it is the same
one #134-#170 ended on: statements that were true when written and had quietly
stopped being, plus the mechanisms that now hold them instead of attention.

**This file, made current and then gated** (#171-#173). The header and the
Status-by-component table were brought up to #170; the remaining-work list was
re-verified against #111-#170, with the one-command check for each item recorded
beside it, because the old line said "re-checked against #91-#110" and had no
clock. The test count then moved from a badge-only gate to one covering every
file that states it (`scripts/stated-numbers.sh`), after this file was found
saying **100 passing** where the workspace ran 747, a sevenfold error sitting
next to an already-gated badge. A number is not gated because it is prominent,
it is gated because it is stated.

**The Cloud DTO boundary, gated and then made largely unnecessary** (#174-#176).
Invariant 3 got `scripts/dto-boundary.sh`, and writing the mutants first showed
the debt note's plan was wrong twice over: the compiler already refuses every
shape that note described (invariant 1 keeps `utoipa` out of core, so no core
type can implement `ToSchema`), while the one shape it does not refuse,
`#[schema(value_type = ..)]`, was already in use and unmentioned. Three
documentation mirrors were then retired: `/v1/audit`, `ReplayResponse.audit` and
`/v1/compliance` had published hand-written `*Schema` types while serialising
the core types those merely described, so each pair agreed only while somebody
kept it agreeing by hand. Proven twice with a field added to core, which made
each endpoint answer a key its published schema never declared. All three now
serialise the DTO, so the compiler holds both directions and the script's
mirror table is empty.

**The replicated ledger's shape, pinned** (#177). Invariant 5's note said the
rule could not be scripted and asked for a comment. The replicated schema is
four types in one file, so it pins as mechanically as invariant 1's dependency
list. What the comment could not have carried is the consequence: adding a field
to `RunState` compiles and every test passes, because every test builds a fresh
state machine, while a node with a durable store cannot read back what it wrote
under the old shape and restarts having lost every budget, silently.
`scripts/replicated-shape.sh` makes that a decision rather than an accident; the
comment went in beside it, at the top of `ledger_backend.rs`.

Worth recording once rather than twice: **two debt notes in a row underestimated
what was checkable**, and both times the cost of finding out was half an hour
reading the code the note described. That lesson is in CLAUDE.md, next to the
entries it came from;
earlier 2026-08-05, covering #134-#170. Four tracks, and none of them
a new capability: this stretch was spent making the capabilities already listed
below actually true.

**Correctness on the money path** (#141, #162, #163, #167-#170). The gateway now
refuses to start rather than answer from `StubProvider` and meter its canned
1000/500 tokens as real spend; `TOKENFUSE_ALLOW_STUB=1` keeps the offline loop
and says in the log that every figure after it is fictional. Found on a live
five-node Kubernetes cluster whose manifest had simply not set
`TOKENFUSE_UPSTREAM`: every call returned 200, each was billed $0.0035, and
nothing warned (#141). The cluster binary gained a durable mode it never had:
`build_durable` had existed since the redb store landed with a test as its only
caller, so `serve` always built an in-memory node and a restart of a real server
lost every budget and every reservation, silently. `--dir <path>` wires it, and
`VALIDATION.md`'s durability rows now say which of them were quorum results
rather than single-node ones (#162, #163). A call the provider REFUSED settled
the pre-flight estimate as spend, first on the buffered path (#167) and then on
the streaming one (#168, which also stopped `POST /v1/ingest` accepting a
read-only key). Four defects on the MCP surface: a policy gate switched off by
omitting one header, an open broker bind, a fingerprint std does not promise,
and a scan that read half the tool (#169). A telemetry push the control plane
refused was reported nowhere, so a gateway with a wrong cloud key looked healthy
from both ends (#170, invariant 13).

**The incident layer says what it means** (#152-#158, CLAUDE.md invariants
7-10). `budget_threshold` and `run_killed` reach the shared bus (#152);
`budget_exhausted` fires on a budget block rather than on any spend-avoiding
block, which had it telling a human at 3am that a run with no budget had run out
of it (#153); a working breaker stopped being a critical event (#154); the two
refusals with no event of their own got one (#155); `spend_spike` and
`fanout_explosion` now measure a CHANGE against the subject's own history
instead of a fixed level, so a busy org stopped tripping on every batch and a
genuine tenfold jump under the old line stopped being invisible (#156, #158);
and an org-scoped incident that structurally cannot reach a notifier is recorded
as a boundary rather than given a fabricated `agent_id` to make it travel
(#157).

**Gates that actually run** (#146-#151, #164). CI runs the gates it claimed to
(#149); the `core-deps` gate had been committed non-executable, so it could not
run for anyone who cloned (#148); the agent-event exporter's two promises got
tests, and the latent env-var race between them got a mutex (#150); first-party
actions moved off the Node 20 runtime (#151); the README's test count is now
computed and gated (#164, invariant 12); CLAUDE.md dropped its status section in
favour of enforcement markers (#146); and wasmtime 43 -> 47.0.3 closed
RUSTSEC-2026-0222 in the off-by-default wasm sandbox (#147).

**The written record stops describing what does not exist** (#142-#145,
#159-#161, #165, #166): a paid-plan upgrade prompt this free product cannot
honour, an OpenAI endpoint the gateway does not serve, a phone app, a Slack
kill-switch, a Cloud dashboard screenshot, and several stack-diagram edges that
were missing, one-way, or naming seven services and no console.

Also landed in this range and not previously recorded here: the key lifecycle
report at `GET /v1/keys` (#134), mcp-broker v2 with named upstreams, a Wardryx
policy gate and a `tool_call` audit (#135), and the complete GenAI semconv
attribute set on the OTel LLM-call span (#137);
earlier 2026-07-24 (**opt-in PII masks in DLP**, #138: `TOKENFUSE_DLP_PII` / `TOKENFUSE_MCP_DLP_PII`, `off\|shadow\|mask\|block` switched independently of the secret scanners, default `off` so behavior is byte-identical until opted in; `pii_email`, Luhn-gated `pii_card`, intl-only `pii_phone`, secrets win on overlap, one merged redact pass. Same day, **the SPEC 6.5 `prev_hash` event chain**, #139: every agent-event NDJSON line is hash-chained over RFC 8785 canonical JSON (hand-rolled JCS in `core/src/jcs.rs`, core's dep list stays closed), one file = one chain resumed across restarts by the Exporter inside its existing lock, fail-open; verify with `agent-conform -chain`. Earlier 2026-07-23: **month-to-date unit spend**, #132 - the units-card member of the time-window honesty class: `/v1/units` rows gain `month`/`month_spent_microusd`/`month_calls` - a persisted, ingest-time UTC-month fold mirroring the gateway `unitledger` window - and the dashboard's Business units card now compares the MONTHLY caps against month-to-date spend instead of all-time, falling back to an explicitly-labeled all-time figure on older planes. Same day, Tool runs metric, #130: model-emitted tool calls counted per call through the whole accounting pipeline (gateway -> traces/Cloud -> dashboard tile + per-run column), docs/21; plus a follow-up sync of the Tool runs tile comment after the #130 x #131 cross-merge. Same day, dashboard time-window honesty, #131: "Spent today" / "Saved this month" / "Spend by run · today" relabeled to the all-time / run-lifetime figures they actually render (Store::summary / SavingsAcc have no day- or month-boundary reset); an honest daily number needs a plane-side day-windowed rollup first, see the comment at the tiles. Same day, identity map: key<->agent<->unit binding, strict mode, monthly unit budgets, Cloud unit aggregation + central unit-cap overrides, docs/20);
earlier 2026-07-12 (P3 enterprise/compliance track: machine-readable control catalog, `tokenfuse compliance` CLI + SARIF export, Cloud `/v1/compliance`, minimal OIDC bearer auth, #91; tamper-evident audit trail + ES256-signed manifest + dashboard savings tile, #92; FinOps reporting: `tokenfuse focus-export` #97, the agent-event NDJSON exporter + `x-fuse-on-behalf-of` + `parent_run_id` #98, outcome tags + `tokenfuse outcomes` #99; post-launch fixes for the Anthropic auth header, a raft-follower snapshot panic, and 2026 model pricing, #100-#102; the **Wave-2 governance plane** (model router, the Wardryx PEP/PDP policy hook, Cloud incident replay + regulator evidence pack, per-instance Parquet trace segments), landed and hardened across #103, #104, #106, #110, see [docs/19](docs/19-wave2-governance.md). "None of this is in a tagged release yet" was true the day it was written and stopped being true on 2026-07-15: all of it is inside v0.4.0, verified by `git merge-base --is-ancestor` on those merges)

**Earlier:** 2026-07-03 (the web dashboard restyled to the fuse identity; the bolt emblem unified across README, dashboard and showcase as an amber→ember tile with a black-keyline bolt; README visuals refreshed)

## Current stage

**Phases 1–4 implemented; v0.4.0 released** (tagged 2026-07-15; this line said
v0.1.0 until 2026-08-05, three releases after the fact). The full request path (budget
enforcement with `TOKENFUSE_MODE=shadow|warn|enforce`, real SSE forwarding at
~0.4 µs p99 in-process / ~1–2 ms on the wire, loop detection, hierarchical
sub-agent budgets), the intelligence/ops layer (semantic cache, WASM policies,
backtesting, Parquet + `tokenfuse sql`, OTel, `tokenfuse top`, Python SDK), the
security packs (agent firewall/taint, DLP, MCP scanner), eBPF Radar, the
**HA raft cluster** (in-process + HTTP transport, hierarchical + durable redb
storage, runtime membership changes), and the **hosted Cloud** (a **Rust**
control plane, `crates/cloud`, plus the Next.js dashboard, gateway telemetry and
the fleet-wide kill-switch). This line said "Go control plane" until 2026-08-06,
which had been wrong since the ADR-7 cutover: the Go plane was deleted, its CI
job with it, and nothing in this repository has been Go since.

Shipped as container images on GHCR: `tokenfuse`, `tokenfuse:cluster`,
`tokenfuse-control-plane`, `tokenfuse-dashboard` — runs anywhere, no dedicated
server. The optional-hardening backlog is now also cleared: **cloud RBAC +
budget alerts**, **cluster mutual TLS**, and a **security-hardening pass**
(request-body limits, upstream connect timeout, a `cargo audit` CI gate, and a
documented threat model in [docs/13](docs/13-security-hardening.md)). What's left
is genuinely optional scale/ops work (a SQL/columnar Cloud store; automated cert
rotation) and a formal third-party audit — none of it a blocker.

**Budgets above the run: slice 2, the identity map, landed in #128**
(docs/20). Slice 1 (#119) established the server-resolved
`key_id`; this slice binds it: a declarative JSON map
(`TOKENFUSE_IDENTITY_MAP`) links `key_id -> business unit -> allowed
`agent://` ids, `TOKENFUSE_IDENTITY_STRICT=off|warn|enforce` gates the
key<->agent binding (403 `identity_mismatch` in enforce, a
`x-fuse-identity: would-block` header in warn), and a unit with
`budget_usd_month` gets the first budget above the run: a UTC-calendar-month
cap, reserve-then-settle like run budgets, tripping `402
unit_budget_exceeded` under `TOKENFUSE_MODE=enforce`. The trace gains a
server-resolved `unit` column (nullable-evolution), `focus-export` gains
`x_unit`, breaker events gain `data.unit`, and the Cloud gains `GET
/v1/units` (per-unit aggregation, unmapped spend visible as `unassigned`),
`POST /v1/units/{id}/budget` (audited central override) and `GET
/v1/unit-budgets` (polled by every gateway, replace-all). Honest limits,
stated in docs/20 and the README: unit counters are per-gateway-process
(restart resets them; the raft ledger deliberately does not grow this
dimension), and with client keys off the strict check has nothing
authenticated to gate. Still next, re-checked 2026-08-05: per-key budgets
(nothing in `crates/` keys a budget on `key_id`; #134's `GET /v1/keys` is a
lifecycle report, not a cap), threshold alerts per unit (#152 put a threshold on
the bus for RUNS only), and fleet-consistent unit caps. Dashboard grouping by
unit is done: the Business units card landed in #129 and gained month-to-date
comparison in #132.

## Status by component

| Component | State | Notes |
|---|---|---|
| Workspace + tooling | ✅ done | Cargo workspace, `rust-toolchain.toml`, rustfmt, GitHub Actions CI. Nine jobs, not the three this row used to name: `fmt · clippy · test`, `python sdk`, `js sdk`, `openapi spec`, `dashboard (Next.js)`, `cluster (raft HA)`, `security (cargo audit)`, `radar (eBPF build)`, `cloud apns (feature build)`. The first of those also runs the five script gates listed in the row below. |
| `crates/core` — money | ✅ done | Integer microdollar type, tested |
| `crates/core` — pricing | ✅ done | Per-Mtok prices, cache priced separately, overflow-safe, fallback for unknown models |
| `crates/core` — ledger | ✅ done | Reserve → settle, atomic under concurrency (test proves no oversubscription) |
| `crates/core` — policy | ✅ done | shadow/warn/enforce modes; per-step + max-steps rules; records "would block" in shadow |
| `crates/gateway` — HTTP skeleton | ✅ done | axum server, `/healthz` + `/v1/messages`, estimate → enforce → forward → settle, 402 budget contract, shadow/warn/enforce, `x-fuse-*` response headers. The unmanaged pass-through (no `x-fuse-run-id`) is opt-in since 2026-08-06: unset, a call the gateway cannot account for is refused with `400 metering_required`, and `TOKENFUSE_REQUIRE_RUN_ID=0` restores it |
| Gateway — real forwarding + SSE passthrough | ✅ done | `HttpProvider` (reqwest/rustls) streams chunks through; `UsageParser` extracts usage from Anthropic + OpenAI SSE and non-stream JSON; settle at end-of-stream. `TOKENFUSE_UPSTREAM` selects the real provider; the stub needs `TOKENFUSE_ALLOW_STUB=1` and the process refuses to start with neither (#141). Verified live. |
| Latency benchmark (p99 < 3 ms) | ✅ done | `examples/bench.rs`; decision path **p99 0.38 µs**, full in-process request **p99 4.67 µs** — ~3 orders under target. See BENCHMARKS.md |
| Client-cancel settle guard | ✅ done | `SettleGuard` settles on Drop — client cancel or upstream error mid-stream never leaks a reservation |
| Loop detection | ✅ done | `crates/core/loops.rs`: identical-tool-call + ping-pong (from the request's own message history) + context-growth (per-run tracker). Wired in: enforce → `402 loop_detected`, shadow/warn → `x-fuse-would-block` header. Verified live. |
| Observability API | ✅ done | `GET /v1/runs` (list runs, spend, %, killed) + `POST /v1/runs/{id}/kill` (hard stop, any mode). Backs the TUI and any caller of the kill endpoint |
| `tokenfuse top` TUI | ✅ done | ratatui / crossterm live view: runs table, spend/budget bars, %, steps, select + kill (`k`), refresh, quit. `tokenfuse top` subcommand; polls `/v1/runs` |
| Python SDK | ✅ done | `sdk/python` — dependency-free helpers: `run_headers`, `gateway_url`, and typed exceptions (`BudgetExceeded`/`LoopDetected`/`PolicyViolation`/`Killed`) via `raise_for_fuse`/`check_response`. Own CI job (pytest, 9 tests) |
| Parquet trace sink (`tokenfuse sql`) | ✅ done | `sink.rs`: settled calls → rotating Parquet segments (opt-in via `TOKENFUSE_DATA_DIR`; `NullSink` default). `sqlq.rs` + `tokenfuse sql "…"` query the trace with DataFusion. Verified live end-to-end. **Per-instance segment names** (Wave-2 hardening, #104): segments are `calls-<instance>-<seq:08>.parquet`, where `<instance>` is a per-process pid+start-nanos token: before this, `seq` started at 0 in every process, so two gateways sharing one `TOKENFUSE_DATA_DIR` (an HA cluster's nodes, or a restarted process) both wrote `calls-00000000.parquet` and clobbered each other's trace. Readers enumerate by the `.parquet` extension, not by parsing `seq`, so the wider filename is transparent to `focus-export`/`outcomes`/`sql`. |
| Semantic cache (Ring 1.1) | ✅ done | `crates/core/cache.rs`: hard-partition + cosine similarity, entity-guard, length-ratio guard, TTL, FIFO eviction; pluggable `Embedder`. Wired for non-streaming tool-free calls; `TOKENFUSE_CACHE=off\|shadow\|on`. On-hit serves `$0` with `x-fuse-saved-usd`. Verified live. |
| Cache ONNX embedder | ✅ done | Optional `onnx` cargo feature: real multilingual-e5-small embeddings via `fastembed`/ort (`TOKENFUSE_CACHE_EMBEDDER=onnx`). Default stays `HashEmbedder` (dep-free); CI builds default only. Compiles + clippy-clean with the feature. |
| Agent firewall / taint (Ring 3.1) | ✅ done | `crates/core/taint.rs`: tools → labels/capabilities, monotonic per-run taint, rule eval. Gateway accumulates taint from `X-Fuse-Taint` + tool history; a model tool call needing a capability denied under the run's taint → `403 taint_blocked` (enforce) or `x-fuse-taint` note (shadow). `TOKENFUSE_FIREWALL=off\|shadow\|enforce`. SDK gains `TaintBlocked`. |
| DLP secret scanning (Ring 3.2) | ✅ done | `crates/core/dlp.rs`: pattern detectors (AWS/OpenAI/Anthropic/Google/GitHub/Slack keys, JWT, private key, Bearer) with overlap-dedup + redaction. Gateway scans the outgoing prompt; `TOKENFUSE_DLP=off\|shadow\|mask\|block` → `403 dlp_blocked`, masks to `[REDACTED:kind]`, or flags via `x-fuse-dlp`. **`block` when unset since 2026-08-06** (`off` restores the old default). Pattern-based, so it catches carelessness and not intent: a secret with no distinctive prefix, or one split across the text, passes, which is measured in VALIDATION.md and said in the README. SDK gains `DlpBlocked`. Opt-in PII masks (`TOKENFUSE_DLP_PII=off\|shadow\|mask\|block`, default `off`, switched independently of `TOKENFUSE_DLP`): `pii_email`, Luhn-gated `pii_card`, intl-only `pii_phone`. Verified live. |
| OTel export (W9) | ✅ done | `gateway/otel.rs`: one OTLP/JSON span per call over HTTP (`gen_ai.*` + `tokenfuse.*` attrs; one trace per run) to `TOKENFUSE_OTLP_ENDPOINT`. `TeeSink` composes it with the Parquet trace. No heavy OTel deps; default off. Verified live against a mock collector. |
| WASM policies (W5) | ✅ done | Optional `wasm` cargo feature: custom policy modules run in a `wasmtime` sandbox with a fuel limit. Scalar ABI `evaluate(est,spent,budget,step,taint_bits)->0/1/2`; block → `402 wasm_policy`. `TOKENFUSE_WASM_POLICY=<path>` (.wasm/.wat). Fail-open. Default build excludes it; compiled/tested/clippy-clean + verified live with a `.wat` policy. |
| MCP credential-broker | ✅ done | `tokenfuse mcp-broker` — a JSON-RPC proxy the agent's MCP client points at. On `tools/call` it injects `{{secret:NAME}}` handles from a vault with real secrets **at the boundary** (secret never in the LLM prompt/trace/agent memory); on `tools/list` it runs the poisoning scanner (`off\|warn\|block`). Pure core in `tokenfuse-core::secretbroker` (`SecretVault` + `inject_secrets`, unit-tested); gateway `mcpbroker.rs` + `tests/mcp_broker.rs` (handle→real secret reaches a stub upstream; poisoned list blocked). Config: `TOKENFUSE_MCP_{UPSTREAM,SECRETS,SCAN,ADDR}`. |
| MCP broker — DLP + redaction + stdio | ✅ done | DLP on outgoing args + **redaction of secrets in responses** (`TOKENFUSE_MCP_DLP`), rug-pull lockfile (`TOKENFUSE_MCP_LOCK`), and a **stdio** transport (`mcp-broker --stdio`, newline-delimited JSON-RPC, logs to stderr) sharing `process()` with HTTP. Opt-in PII masks (`TOKENFUSE_MCP_DLP_PII=off\|shadow\|mask\|block`, default `off`): `pii_email`, Luhn-gated `pii_card`, intl-only `pii_phone`. Tests: dlp-block, rug-pull-block, response-redaction. |
| MCP scanner + lockfile (Ring 3.3 / S6) | ✅ done | `crates/core/mcp.rs`: parse `tools/list`, fingerprint tools, scan descriptions for poisoning (injection phrases, zero-width chars), and diff vs a lockfile → **rug-pull** detection. `tokenfuse mcp-scan <tools.json> [--lock f] [--write-lock]`. Verified live. (Live credential-broker proxy = follow-up, needs MCP transport.) |
| eBPF Radar (W1) | ✅ done | `crates/radar` (+ nested `radar-ebpf`, aya): eBPF on `sys_enter_connect` reports every outbound TCP connection (pid/comm/ip:port) and flags LLM providers + local Ollama/vLLM — **zero app config**. Linux-only; excluded from default workspace, own CI job. **Built & run live on a Hetzner Ubuntu 24.04 VPS (kernel 7.0)** — flagged real Anthropic/OpenAI + Ollama traffic, ignored non-LLM. |
| Backtesting (W6) | ✅ done | `crates/core/backtest.rs`: replay a candidate policy (per-run/per-step budget, max-steps) over the Parquet trace → runs/calls blocked + `$ saved`. `tokenfuse backtest --budget … --max-steps …`. Verified live (saved 50% on a demo trace). |
| Hierarchical sub-agent budgets | ✅ done | `X-Fuse-Parent-Run-Id` links a run to its parent; `reserve`/`settle` roll a sub-agent's spend up the ancestor chain and check every level (all-or-nothing). A child that fits its own budget is still blocked by a tighter parent → `402 budget_exceeded` naming the parent. |
| HA cluster / raft (W7) | ✅ done | `crates/cluster` (openraft, storage-v2): the budget ledger replicated across N nodes. `Reserve`/`Settle` are raft log entries, so the affordability check is **linearized** — no cross-node double-spend — and budgets survive a node crash (quorum commit). Reference in-memory storage. `cargo run -p tokenfuse-cluster` demos a 3-node cluster: over-budget reserve denied by consensus, spend read back from a **follower**. Excluded from default workspace; own CI job. |
| Cluster — HTTP transport | ✅ done | `net_http.rs` (HTTP `RaftNetwork`, JSON-over-HTTP via openraft `serde`) + `server.rs` (axum per-node server: `/raft/*` peer RPCs, `/mgmt/init`, `/mgmt/metrics`, `/api/write`, `/api/read/{run}`) → clusters form **across processes/machines**. `tokenfuse-cluster serve --id N --http … --peers …` runs one node; `demo-http` spins 3 over real sockets. 2 HTTP integration tests (form over `:0`, deny over-budget by consensus, follower read; leader-forward). |
| Gateway↔cluster integration | ✅ done | Async `LedgerBackend` trait (`ledger_backend.rs`): `LocalLedger` (default, wraps in-process `Ledger` — no behavior change) or `RaftLedger` (`raft_ledger.rs`, feature `cluster`) which co-locates a raft node so budgets are enforced by consensus across gateways. Hot path refactored sync→async (`open`/`reserve`/`snapshot` await; `settle` stays sync fire-and-forget so `SettleGuard::drop` is unchanged). Configured via `TOKENFUSE_CLUSTER_*`; fails open on consensus outage. Gated tests (`tests/cluster_backend.rs`): enforce/deny/settle + parent-budget. Default gateway 35 tests still green. |
| Cluster — auth + TLS | ✅ done | **Auth:** `TOKENFUSE_CLUSTER_TOKEN` shared secret — all endpoints except `/healthz` require `Authorization: Bearer <token>` (axum middleware), threaded through peer RPCs, admin/app `Client`, leader-forwarded writes, and the gateway. **TLS:** native HTTPS via rustls/axum-server (`TOKENFUSE_CLUSTER_TLS_CERT`/`_KEY` or `serve --tls-cert/--tls-key`); rustls client with optional self-signed CA trust (`TOKENFUSE_CLUSTER_CA`). Both off by default (dev). Tests `cluster_token_secures_endpoints` + `serves_over_https_with_token`. |
| Cluster — membership changes | ✅ done | Nodes join/leave a running cluster: `/mgmt/init-single`, `/mgmt/add-learner {id,addr}`, `/mgmt/change-membership [ids]` (+ `HttpNode` + `Client` methods). A runtime-added node's address travels in the replicated membership (`BasicNode.addr`), so the HTTP network reaches it (falls back to the bootstrap peer map). Test `membership_grow_add_learner_then_promote` (single voter → add learner over HTTP → promote → write replicates to the new node). |
| Cluster — durable storage (redb) | ✅ done | `crates/cluster/src/redbstore.rs`: `RedbLogStore` + `RedbStateMachineStore` implement the openraft storage-v2 traits over [redb](https://docs.rs/redb) (embedded, pure-Rust, ACID; one file per node, no C deps). Writes commit before returning, so budgets survive a **process restart**, not just a node crash. `HttpNode::build_durable(id, peers, dir)`; gateway env `TOKENFUSE_CLUSTER_DATA_DIR`. Read side shared via a `LedgerReader` trait (in-memory or redb). Test `budgets_survive_a_restart` (write → drop → reopen same dir → still there). In-memory backend remains the default. |
| Cluster — hierarchical budgets + steps | ✅ done | The replicated SM models `parent` chains and per-run `steps`, mirroring `tokenfuse-core::Ledger`: `Reserve` fits the run **and every ancestor** (all-or-nothing), rolls up the chain, and names the `blocked_run` on denial; `Settle` rolls up too. So sub-agent budgets (`X-Fuse-Parent-Run-Id`) are enforced in cluster mode, not just locally. In-process test `subagent_reserve_rolls_up_and_parent_budget_blocks` + gateway `raft_backend_enforces_parent_budget`. |
| Container image + GHCR | ✅ done | Multi-stage `Dockerfile` (rust build → debian-slim runtime, non-root, CA roots) + `.github/workflows/release.yml` publishes to `ghcr.io/taipanbox/tokenfuse` on tags / manual dispatch via the built-in `GITHUB_TOKEN`. `docker run -p 4100:4100 -e TOKENFUSE_UPSTREAM=<provider> ghcr.io/taipanbox/tokenfuse` runs anywhere, **no dedicated server** (`TOKENFUSE_ALLOW_STUB=1` instead of the provider for an offline try; with neither, the process refuses to start rather than meter invented usage). Dockerfile takes `--build-arg FEATURES=…`; the release matrix also publishes **`tokenfuse:cluster`** (built with `--features cluster` — raft HA + durable redb baked in) and `tokenfuse-control-plane`. |
| Portable benchmark harness | ✅ done | `bench/` (mock upstream, wrk scripts, `run.sh`, README) reproduces the networked latency benchmark on any Linux box; `.github/workflows/bench.yml` runs it in GitHub Actions (manual). Rescued the ad-hoc VPS files into the repo. Radar's live output preserved at `crates/radar/sample-output.txt`. |
| `TOKENFUSE_MODE` enforcement toggle | ✅ done | Binary reads `TOKENFUSE_MODE=shadow\|warn\|enforce` at startup (default shadow). The Docker image can now actually block (402), not just observe. Verified live on a VPS: enforce → 402 over budget. |
| Hosted Cloud v1 (control plane + dashboard) | ✅ done | `crates/cloud` (Rust/axum, single static binary — **ported from Go**, ADR-7, PR A1–A5): ingests gateway telemetry (`POST /v1/ingest`, Bearer org-key), serves per-org aggregates (`/v1/runs`, `/v1/summary`), mutations (`kill`/`budget` admin-only) + poll endpoints (`/v1/kills`, `/v1/budgets`), `/v1/alerts`, and an embedded live dashboard (`/`). RBAC (`key:org[:role]`, admin/viewer→403), durable JSON snapshot + autosave (`TOKENFUSE_CLOUD_DATA`), CORS. Covered by `cargo test --all` (21 tests when this row was written; the current figure is in Test status and is the only one gated); image `tokenfuse-control-plane` from `crates/cloud/Dockerfile`. The Go plane was deleted in the cutover. |
| Cloud Next.js dashboard | ✅ done | `cloud/dashboard` (Next.js App Router, TS, static export): connect form (base URL + org key), summary cards, spend-by-run chart, runs table with **Kill** + **Budget** actions, 3 s auto-refresh. Talks to the control plane from the browser; control plane sends CORS headers. Built to static files, served by nginx → `ghcr.io/taipanbox/tokenfuse-dashboard`, in `docker compose` on `:3000`. Own CI job `dashboard` (npm ci + next build). The embedded vanilla-JS dashboard remains for a zero-deploy quick look. |
| Cloud durable store | ✅ done | Control-plane state (org→run aggregates, kills, budgets) persists across restarts: `TOKENFUSE_CLOUD_DATA=<path>` loads a JSON snapshot on startup and autosaves every 2 s (atomic tmp+rename), zero external deps. Distroless image ships a non-root-owned `/data`; compose mounts a `cloud-data` volume. Test `persistence_round_trip` (it was `TestPersistenceRoundTrip` here until 2026-08-06, a Go name for a test that has been Rust since the cutover). SQL/columnar (Postgres/ClickHouse) for scale is a drop-in behind the same `Store`. |
| Cloud central budgets | ✅ done | Control plane: `POST /v1/runs/{run}/budget {budget_usd}` + `GET /v1/budgets`; dashboard **Budget** button per run. Gateway: `cloudsink::spawn_budget_poller` fetches `/v1/budgets` every 3 s → `AppState.cloud_budgets`; `proxy` `open_run` uses the cloud budget over the `x-fuse-budget-usd` header. Verified e2e: header `$999999` + cloud `$0.0001` → 402. Lets an operator tighten a runaway cap centrally. |
| Cloud kill-switch (kill from cloud) | ✅ done | Control plane: `POST /v1/runs/{run}/kill` + `GET /v1/kills` (per-org), `RunAgg.killed`; dashboard gains a per-run **Kill** button. Gateway: `cloudsink::spawn_kill_poller` fetches `/v1/kills` every 3 s and applies each id to the local kill set → the run is hard-stopped (`402 killed`) across the whole org fleet. `TOKENFUSE_CLOUD_URL` is now a base URL. Verified e2e: kill in cloud → gateway returns 402 `killed`. |
| Gateway → Cloud telemetry (`CloudSink`) | ✅ done | `crates/gateway/src/cloudsink.rs`: batches settled `CallRecord`s and POSTs them async (fire-and-forget, periodic flush) to the control plane; `TOKENFUSE_CLOUD_URL` + `TOKENFUSE_CLOUD_KEY`, composed via `TeeSink`. `CallRecord` gained `Serialize`. Verified end-to-end: 3 calls → Cloud shows 3 runs / $0.0315. `cloud/docker-compose.yml` runs the whole stack (`docker compose up`). |
| Cloud RBAC + budget alerts | ✅ done | Control plane keys are now `key:org[:role]` with roles `admin` (default) / `viewer`; reads + ingest work for any valid key, **mutations** (kill, set-budget) require `admin` → `403` for a viewer, `401` for an unknown key. `GET /v1/alerts` flags runs that spent ≥ a fraction of their central budget (`TOKENFUSE_CLOUD_ALERT_PCT`, default 0.8, or `?pct=`); the embedded dashboard shows an alert count + ⚠ on near-budget rows. Tests, in Rust since the ADR-7 cutover and named here so the row can be checked: `viewer_can_read_but_not_mutate`, `parses_org_and_role`, `alerts_only_fire_over_threshold`. (#51) |
| Cluster mutual TLS | ✅ done | On top of server TLS + bearer token: `TOKENFUSE_CLUSTER_MTLS_CA` makes a node **require** a CA-signed client cert from every peer (rustls `WebPkiClientVerifier`, `server::serve_mtls`); each node presents its own cert via `TOKENFUSE_CLUSTER_CLIENT_CERT/_KEY` (reqwest `Identity`). Cryptographic peer auth — an unauthenticated TCP client can't complete the handshake. Also `serve --mtls-ca …`. Test `serves_over_mutual_tls`. (#52) |
| Security-hardening pass | ✅ done | Request-body size limit on the gateway + MCP-broker routers (`DefaultBodyLimit`, `TOKENFUSE_MAX_BODY_BYTES`, default 16 MiB); upstream **connect** timeout (`TOKENFUSE_UPSTREAM_CONNECT_TIMEOUT_SECS`, no whole-request timeout so SSE streams aren't cut); a `cargo audit` CI job (workspace + cluster); optional **wasmtime 27→43** clearing 15 advisories (2 critical, `wasm` feature is off by default). Threat model + trust boundaries + the deliberate fail-open rationale documented in [docs/13](docs/13-security-hardening.md). (#53) |
| Published to package registries | ✅ done | The `tokenfuse` name is claimed and **published** on all three registries (v0.3.0): **npm** `npm install tokenfuse` (`sdk/js`), **crates.io** `cargo add tokenfuse` (umbrella crate `crates/tokenfuse`), **PyPI** `pip install tokenfuse-sdk` (`sdk/python`; the plain `tokenfuse` name is blocked on PyPI by the unrelated existing `token-fuse`, so the distribution is `tokenfuse-sdk` while the import stays `import tokenfuse`). Publish tokens were revoked after use. Domain `tokenfuse.dev` is the only remaining name to claim (owner action). |
| Cloud: OpenAPI, live stream, signed device mutations | ✅ done | The control-plane work that finished `crates/cloud` after the Go→Rust port (A1–A5, recorded above). **A6**: OpenAPI 3.1 via `utoipa`: `GET /openapi.json` + an `--openapi` dump, with a CI `openapi` job that regenerates and validates the spec. **A7**: live data, SSE `/v1/stream` and the burn-rate series at `/v1/series`. **A8**: a hardware-backed mutation path. A paired device registers a public key and signs `kill` / `budget` over a canonical string (ES256), verified server-side, and its device id is what lands in the audit trail as the actor. This is a *second* accepted path: an admin org key with no signature is the one the dashboard and the CLI use. **A9**: the alert pipeline. Store change events become alerts through a swappable `PushSender`, deduplicated per `(org, run, reason)` on a 10-minute window; the default sender is a no-op, so the pipeline costs nothing until one is configured. 42 tests. |
| Enterprise / compliance track (P3) | ✅ done | `crates/core/src/compliance.rs`: a machine-readable, honesty-first control catalog (`CATALOG`, 11 controls: `TF.BUDGET`, `TF.LOOP`, `TF.KILL`, `TF.DLP`, `TF.TAINT`, `TF.MCP.POISON`, `TF.MCP.RUGPULL`, `TF.MCP.EXPOSURE`, `TF.WASM`, `TF.AUDIT`, `TF.ACCESS`) mapped to external frameworks, each control graded `Enforced`/`Partial`/`Documented` rather than just claimed in prose (CLAUDE.md invariant #4: never over-claim). `compute_compliance` projects the catalog against the Parquet trace (+ optional `mcp-scan --json-out` findings) into a `ComplianceReport`; `tokenfuse compliance [--since/--until] [--json\|--markdown] [--scan-report f]` (`compliancecli.rs`) prints it, reusing the `tokenfuse sql`/savings trace loader. `mcp-scan` itself gains `--sarif` (`mcpreport::to_sarif` → minimal valid SARIF 2.1.0, severity→level) so findings ride the existing GitHub Action / code-scanning. Cloud: `GET /v1/compliance` projects the same catalog against the org's live decision + incident counts (`compute_compliance_from_counts`), readable by any role. **Was** `Feature::Compliance`-gated when this row was written; #125 removed plan entitlements from the product, so there is no gate on it now. Minimal OIDC bearer auth for the Cloud plane (`crates/cloud/src/oidc.rs`, `TOKENFUSE_CLOUD_OIDC_{ISSUER,AUDIENCE,JWKS,ORG_CLAIM,ROLES_CLAIM,ADMIN_ROLE}`): validates signature + `iss` + `aud` against a JWKS, `from_env()` returns `None` (feature off) unless issuer, audience, and JWKS are all configured. 19 tests in `compliance.rs`, 15 in `cloud/tests/oidc.rs`. (#91) |
| Compliance polish: signed audit manifest, dashboard tile, Breaker facade | ✅ done | `crates/core/src/audit.rs`: a hash-chained `AuditEntry` log (`append`/`verify_chain`, SHA-256 over `seq/ts/actor/action/subject/detail/prev_hash`) recording every control-plane mutation (kill, set-budget, incident-ack): tamper-evident, detects a broken link or a removed entry. `crates/cloud/src/audit_sign.rs` adds **external custody**: `GET /v1/audit/manifest` returns an ES256-signed (`p256`, server key from the `AUDIT_SIGNING_KEY_ENV`-configured signing key) manifest over the chain tip (`org`, `tip_seq`, `tip_hash`, `entry_count`, timestamp) a regulator can verify independently without trusting the store; absent a signing key the endpoint 404s (not 500). The Next.js dashboard (`cloud/dashboard/app/page.tsx`) gains a **"Saved this month"** tile fed by `GET /v1/savings` (blocked $ · cache $ · N budget breaks), mirroring the embedded dashboard; an absent response is swallowed so the rest of the page still refreshes. That was written as "402/gated on a free plan" and stopped being true when plan entitlements were removed (#123, #125): there are no plans, so the only case left is a plane older than the endpoint. `proxy.rs`'s real 402 path is rewired onto the `breaker_error_response` facade (invariant #2, the byte-for-byte golden regression test). 10 tests in `audit.rs`, 6 in `cloud/tests/audit_manifest.rs`. (#92) |
| `tokenfuse focus-export` (FinOps FOCUS export) | ✅ done | `crates/gateway/src/focusexport.rs`: `tokenfuse focus-export --traces <dir-or-glob> --out <file.csv> [--from/--to RFC3339]` reads the Parquet trace via the same DataFusion path as `tokenfuse sql` and emits a FOCUS 1.2-style CSV (FinOps Open Cost & Usage Specification, one row per call) so a FinOps team can load agent spend into the tooling they already use for cloud spend. Every column is sourced from the actual `calls` schema: nothing synthesized; columns with no matching field yet (`x_parent_run_id`, `x_outcome`) are emitted empty via the same `COALESCE`-for-schema-evolution pattern the rest of the trace reader uses, so a pre-P3/P4 trace file without those columns still reads. Blocked calls are included as `$0` rows. Read-only: never touches the enforcement hot path. (#97) |
| Agent-event exporter + delegation chain + `parent_run_id` | ✅ done | `crates/core/src/agent_event.rs`: the NDJSON envelope, severity mapping, and fail-open file writer for the shared **agent-passport** `taipanbox.dev/agent-event/v0.1` schema, used by both the gateway (per-request: `breaker_tripped`/`dlp_block`/`taint_block`) and the Cloud plane (the P2 fleet-aggregate incidents). Gateway side in `crates/gateway/src/events.rs`, opt-in via `TOKENFUSE_EVENTS_PATH`, zero-cost when unset, fail-open (logs a warning, never crashes the gateway) when set, and never fabricates an `agent_id` (skips the event instead, per CLAUDE.md invariant #6). `x-fuse-on-behalf-of` captures a delegation chain per call, and `X-Fuse-Parent-Run-Id` is now threaded all the way into the Parquet trace as `parent_run_id` (nullable-read schema evolution), both later consumed by `focus-export`'s `x_parent_run_id` column. Each NDJSON line now also carries the SPEC 6.5 `prev_hash` chain: one file is one chain, resumed across restarts; verify with `agent-conform -chain`. (#98) |
| Outcome tags + `tokenfuse outcomes` | ✅ done | `crates/core/src/outcomes.rs`: a per-call `X-Fuse-Outcome` header captured verbatim into the trace (`sink::CallRecord.outcome`) with **no run-level state built on the hot path**: `compute_outcomes` is a pure post-processing pass over loaded trace rows that resolves a run's outcome as the **last non-empty tag in step order** (`step`, not `ts_millis`: a fast local run can share a millisecond but never a step), so a later re-tag (`escalated` → `case_resolved`) wins over an earlier one. `tokenfuse outcomes --traces <dir> [--from/--to] [--json]` (`outcomescli.rs`) reports per outcome tag: runs, total settled cost, mean cost/run, calls, blocked calls, plus an `(untagged)` row for runs that never sent the header. Answers "what does one resolved case cost" for FinOps. Read-only, reuses the `tokenfuse sql`/`focus-export` DataFusion loader. (#99) |
| Post-v0.3.0 fixes: auth header, cluster panic, price book | ✅ done | Three independent one-file fixes. **(1)** `crates/gateway/src/provider.rs` now forwards `x-api-key` (Anthropic's native auth header) in `FORWARD_HEADERS` alongside `authorization`; without it every real Anthropic call 401'd (#100). **(2)** `crates/gateway/src/proxy.rs`: the pre-reserve budget `snapshot()` no longer `.expect()`s a just-opened run: `RaftLedger::snapshot` is a local, eventually-consistent read (`sm.read_run`) that can legitimately race the just-committed `open_run` write on a follower node under burst load, so a `None` now falls back to the true zero/fresh `RunSnapshot` instead of panicking the request task; enforcement itself is unaffected since the real check (`ledger.reserve`) still goes through raft consensus. Reproduced live with a concurrent fresh-run burst fired at a follower in `tests/cluster_backend.rs` (#101). **(3)** `crates/gateway/src/pricebook.rs`: exact price-book entries (input/output/cache read/cache write per Mtok) for `claude-haiku-4-5`, `claude-sonnet-4-5`, `claude-opus-4-5`, `gpt-4o`, `gpt-4o-mini`, `o1`: these were falling through to the conservative generic fallback (`x-fuse-price: fallback`), mis-sizing the pre-call reserve estimate; pulled out of `main.rs` into its own unit-tested module so a units mistake (the classic 1e6 error) is caught by a sane-range assertion rather than shipped (#102). |
| Model router (Wave-2 governance) | ✅ done | `crates/gateway/src/router.rs`: picks the cheapest model that still meets a task's declared quality tier before the request is priced/reserved/forwarded (`proxy::messages`, wired between `parse_request` and `estimate_cost`), an optimization, not a guardrail, so the savings must be attributable on their own. `TOKENFUSE_ROUTER=off\|shadow\|on` (default off); rules from `TOKENFUSE_ROUTER_RULES` (a JSON task-class table) or the built-in defaults, with an unreadable/malformed table failing open to the defaults plus a warning (never a hard error). "Never routes up" is an oversimplification: the precise rule is the cheapest candidate that clears the class's required tier, so a caller explicitly requesting *below* the required tier is still routed to a pricier-but-sufficient model (tested end-to-end). Response header `x-fuse-router`: `<model>=kept`, `<from>-><to>` on an applied rewrite, or `would-<from>-><to>` in shadow mode. Router savings are booked as their own dimension in `compute_savings`, split from cache savings so a FinOps report doesn't conflate the two. Hardened to never panic building the header on a malformed model string (#106). Design + invariants in [docs/19](docs/19-wave2-governance.md). |
| Wardryx policy hook (PEP/PDP, Wave-2 governance) | ✅ done | `crates/gateway/src/wardryx.rs` + `proxy.rs`: TokenFuse is the PEP (Policy Enforcement Point): on the request path, after the WASM policy check and before `reserve()`, it calls an external [Wardryx](https://github.com/TAIPANBOX/wardryx) PDP's `/v1/decide` with a decision context (agent id, on-behalf-of chain, tool set, declared domains, step count, estimated cost, approval token) and acts on the verdict: `allow` proceeds, `deny` → `403` + `x-fuse-wardryx: deny`, `hold` → `403` + `x-fuse-wardryx: hold` + `x-fuse-approval-id` (stateless: the caller resubmits with `x-fuse-approval-token` once approved out of band; TokenFuse never parks the connection). `TOKENFUSE_WARDRYX_MODE=off\|shadow\|enforce` (default off, forced off without `TOKENFUSE_WARDRYX_URL`); `TOKENFUSE_WARDRYX_FAILMODE=open\|closed` (default open) covers PDP timeouts/outages. Gates on tools the request **declares** (`tools[]`, via `taint::declared_tool_names_in`), not only invoked ones, so a `deny_tool` fires before the model can emit the forbidding call (#103). A short-TTL decision cache (`TOKENFUSE_WARDRYX_CACHE_TTL_MS`, default 3000) only ever stores a verdict the PDP itself marked `cacheable`; request-specific policies (`max_steps`/`allow_domains`/`require_human_above_usd`) come back `cacheable:false` and a `hold` is never cached, keyed on `(agent_id, sorted tool-set hash, attestation_method)`; attestation is part of the key so a cacheable `deny_if_unattested` verdict can never leak across attestation states within the TTL (#110). 14 tests in `tests/wardryx.rs`. Design + invariants in [docs/19](docs/19-wave2-governance.md). |
| Cloud incident replay + regulator evidence pack (Wave-2 governance) | ✅ done | `crates/cloud/src/replay.rs` + `http.rs`: `GET /v1/replay/{run}` reconstructs one run's ordered timeline by reading (never writing) the agent-event NDJSON file at `TOKENFUSE_CLOUD_REPLAY_EVENTS`, joined with the run's incidents and any audit-chain entries naming it as `subject`; unset, missing, or a corrupt line is tolerated (`configured:false` or a malformed-line count, never a panic), and a run belonging to a different org 404s exactly like an unknown one (never leaks existence across orgs). `GET /v1/compliance/evidence` grades every catalog control against **this org's live decision + incident + audit evidence** (`EvidenceStatus::Enforced\|Partial\|Documented`, decided per-org, not a static catalog claim) across three regulator-facing sections (EU AI Act, US Federal Reserve SR 11-7 model-risk management, and SOC 2), plus whether the org's own audit chain currently verifies end-to-end. Both endpoints are read-only and additive (no enforcement or stored-state change), and never expose `tokenfuse-core` types directly (invariant #3, cloud-local `*Schema` DTOs only). 4 tests in `cloud/tests/replay.rs`, 3 in `cloud/tests/compliance_evidence.rs`. Hardened + documented in [docs/19](docs/19-wave2-governance.md) (#104). |
| Post-v0.4.0 correctness: devkey admin, cache partition, dead budget bypass | ✅ done | Three unrelated fixes with one shape: each was silent in production. **#114**: `crates/cloud/src/keys.rs::parse_keys()` inserted a hardcoded `devkey -> org=default, role=admin` credential whenever the key config parsed to nothing, so a plane started with an empty or malformed `TOKENFUSE_CLOUD_KEYS` accepted `Bearer devkey` as an **admin** and said nothing. **#115**: the semantic cache's hard-partition key dropped the system-prompt dimension for Anthropic's array-shaped `system` field (`system_text()` in `proxy.rs` handled only the string form), so two requests with different system prompts could share a partition. **#116**: `Mode::Enforce`'s budget gate carried an `Err(BudgetError::UnknownRun) => reserve_unchecked(..)` arm, an unconditional bypass. Traced dead on both backends rather than assumed dead, and changed to fail **closed** through the same `breaker_error_response` path as the sibling `Exceeded` arm, since `BudgetError`'s two variants must stay exhaustively matched. |
| Client credential identity (`key_id`) | ✅ done | `crates/gateway/src/clientkeys.rs`: the gateway resolves the `x-fuse-key` header to a stable, **server-side** `key_id` recorded on every `CallRecord`. Identity and nothing else: no budget is enforced against it in this slice. The distinction is the point and is load-bearing for everything above the run: `agent_id` is a header the caller writes, so it is sound for attribution a cooperating fleet reports about itself and unsound as a budget key, which a caller could move off simply by sending a different one. `""` when client keys are not configured, which is every deployment that has not opted in (#119). |
| Findings from other planes (`POST /v1/findings`) | ✅ done | `crates/cloud`: the control plane accepts a detection **another service** made and files it as an incident, carrying two optional fields that record who detected it and how, so a fleet view can hold evidence this plane did not produce without pretending it did (#120). |
| Free and open source: plan gating removed | ✅ done | The product shape settled, and the record has to show the reversal rather than only the destination. #122 built an observe-only free tier (`Plan::Free` served fleet reads, everything acting or advanced stayed paid, plus `/v1/me`, inert dashboard buttons and an upgrade banner). **#123 reverted it**: TokenFuse is free and open source, and the paid, secured control room over the whole stack is a separate product. #125 then removed the P2 plan-entitlements machinery outright, #127 and #142 cleared the remaining paid-Cloud wording and the upgrade prompt the gateway still printed. Nothing named `entitlements`, `Plan::` or `Feature::` survives in `crates/cloud/src/` (checked 2026-08-05). Same PR hardened the money plane: the control plane binds `127.0.0.1` by **default** (`TOKENFUSE_CLOUD_HOST`), and a non-loopback bind logs that it is now reachable from the network rather than doing it quietly (#123). A static sample-data dashboard preview landed alongside (#124). |
| Identity map: key ↔ agent ↔ unit, monthly unit budgets | ✅ done | `crates/gateway/src/identitymap.rs` + Cloud: a declarative JSON map (`TOKENFUSE_IDENTITY_MAP`) binds `key_id -> business unit -> allowed agent:// ids`; `TOKENFUSE_IDENTITY_STRICT=off\|warn\|enforce` gates the key↔agent binding (403 `identity_mismatch` in enforce, an `x-fuse-identity: would-block` header in warn); a unit with `budget_usd_month` gets the first budget **above the run**, a UTC-calendar-month cap that reserves and settles like a run budget and trips `402 unit_budget_exceeded` under `TOKENFUSE_MODE=enforce`. The trace gains a server-resolved `unit` column, `focus-export` an `x_unit`, breaker events a `data.unit`. Cloud gains `GET /v1/units` (unmapped spend visible as `unassigned`), `POST /v1/units/{id}/budget` (audited central override) and `GET /v1/unit-budgets` (polled by every gateway, replace-all). Honest limits, stated here and in docs/20: unit counters are **per-gateway-process** so a restart resets them, the raft ledger deliberately does not grow this dimension, and with client keys off the strict check has nothing authenticated to gate (#128, docs/20). |
| Dashboard: Business units card | ✅ done | `cloud/dashboard/app/page.tsx`: per-unit rows with their monthly caps, `unassigned` shown as itself rather than hidden (#129). The card compares the **monthly** caps against month-to-date spend, not all-time: `/v1/units` rows carry `month`/`month_spent_microusd`/`month_calls` from a persisted ingest-time UTC-month fold mirroring the gateway's `unitledger` window, falling back to an explicitly labelled all-time figure against an older plane (#132). |
| Tool runs metric | ✅ done | Model-emitted tool calls counted per call through the whole accounting pipeline: `tokenfuse_core::pricing::Usage::tool_calls` at settle time, `CallRecord.tool_calls` (nullable-evolution, `None` when the response body never parsed, never a guess), Cloud aggregation, and a dashboard tile plus a per-run column. Observed-only by design: v1 enforces nothing on tool calls (#130, docs/21; tile comment resynced after the #130 × #131 cross-merge in #133). |
| Dashboard time-window honesty | ✅ done | "Spent today", "Saved this month" and "Spend by run · today" were relabelled to the all-time and run-lifetime figures they actually render, because `Store::summary` and `SavingsAcc` have no day or month boundary reset. An honest daily number needs a plane-side day-windowed rollup first, and the comment at the tiles says so rather than the label implying it already exists (#131). |
| Key lifecycle report (`GET /v1/keys`) | ✅ done | `crates/gateway/src/keysreport.rs`: a read-only report correlating the three places a `key_id`'s identity lives, so an operator or the console can tell a live key from a stale, unbound, dangling or long-removed one without grepping the trace by hand. Read-only: it reports, it revokes nothing (#134, I15). |
| MCP broker v2 + surface hardening | ✅ done | Three additive changes, each **off by default** so a broker with no new config behaves exactly as before: named upstreams (`TOKENFUSE_MCP_UPSTREAMS="name=url,.."`, selected per request by `X-Fuse-Mcp-Upstream`, no header meaning the default), a Wardryx policy gate on `tools/call`, and a `tool_call` audit record (#135, docs/23). Four defects on that surface were then fixed (#169): the policy gate could be switched **off by omitting one header**; the broker had no authentication of its own and widened its bind silently; rug-pull detection rested on `DefaultHasher`, whose values std does not promise to keep stable across releases, so a lockfile written by one build could stop comparing against another (legacy locks now report `Drift::LockNotComparable` rather than a false clean); and the poisoning scan read a tool's summary and none of its parameters. |
| OTel GenAI semantic conventions | ✅ done | `crates/gateway/src/otel.rs`: the LLM-call span now carries the current GenAI semconv set (`gen_ai.operation.name`, `gen_ai.system`, `gen_ai.request.model`, `gen_ai.response.model`, `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`), so a semconv-aware backend recognises it as an LLM call instead of an anonymous HTTP span (#137). |
| The gateway refuses to invent usage | ✅ done | With no `TOKENFUSE_UPSTREAM` the gateway answered every request from `StubProvider` (canned body, fixed 1000 input / 500 output tokens) and the ledger metered that as real spend: fabricated answers and fabricated money, both plausible, both riding the same audit trail as the real thing. Found on a live five-node Kubernetes cluster whose manifest had simply not set the variable, where every call returned `200`, each was billed `$0.0035`, and nothing warned. The stub is now opt-**in**: `TOKENFUSE_ALLOW_STUB=1` keeps the offline dev loop and logs that every figure from then on is fictional; without it and without an upstream the process exits 2 and prints both ways forward (#141). |
| Incidents that mean what they say | ✅ done | `budget_threshold` and `run_killed` reach the shared agent-event bus (#152). Then the detectors were audited against their own names, which is where CLAUDE.md invariants 7 to 10 come from: `budget_exhausted` fires on a budget block rather than on any spend-avoiding block, after a live cluster raised a High incident saying a run with no budget had exhausted it (#153); a working breaker stopped being a critical event (#154); the two refusals with no event of their own (a unit's monthly cap, a local policy or wasm deny) got `unit_cap_exceeded` and `policy_deny`, which is what made lowering the generic event honest rather than merely quieter (#155); and `spend_spike` and `fanout_explosion` now measure a **change** against the subject's own recent history instead of a fixed level, so an org whose ordinary day sat above the line stopped spiking on every batch and a genuine tenfold jump below it stopped being invisible (#156, #158). An org-scoped incident that structurally cannot reach a notifier is recorded as a boundary in heraldyx's README rather than given a fabricated `agent_id` to make it travel (#157). |
| Cluster: a single node that survives on its own | ✅ done | `build_durable` had existed since the redb store landed with a **test as its only caller**: `serve` always built an in-memory node, so restarting a real server lost every budget and every reservation, with no error and no warning. "Budgets survive a node crash" had been true only in the sense that a quorum of others still held them. `--dir <path>` wires the binary to the durable store, and the in-memory case now says so at startup in words rather than by the absence of a flag (#162). `VALIDATION.md` was corrected in the same breath: every durability row there had been a **quorum** result and had not said so (#163). |
| A refused call settles as zero | ✅ done | When a response reports no usage it can price, settlement charges `reservation.amount`, the pre-flight estimate. On a 2xx that is the conservative fallback it was written to be. On a 4xx or 5xx there is no completion at all, so the estimate was a number this gateway invented and then wrote into the run's budget, the unit's monthly cap, the Parquet trace, the FOCUS export and the Cloud aggregates as money somebody was billed; a provider that 429s a run repeatedly would exhaust that run's budget on calls that cost nothing. Fixed on the buffered path (#167) and then on the streaming one (#168). Not a blanket zero: usage a provider **does** report on a refusal is still settled as itself, because a provider that generated part of a response and then failed over it bills for what it generated. |
| Ingest requires an admin credential | ✅ done | `POST /v1/ingest` accepted any valid org principal, including a read-only key, so a viewer credential could write the evidence that pages a human. Narrowed to an admin credential (#168). All three deployment repos already hand the gateway an admin key (stack-k8s `cloud_admin`, stack-single `CLOUD_ADMIN`, stack-up dev-mode `devkey`), so nothing known broke; a deployment outside those three that used a viewer key now gets a 403, which is why #170 exists. |
| `CloudSink` reports a refused push | ✅ done | `ship` matched only the transport error `reqwest` returns when a request never gets an answer, and `reqwest` returns `Ok(Response)` for every status it does get, so a 401, 403 or 500 from `/v1/ingest` left no log line, no counter and no metric. A gateway whose cloud key was wrong, rotated or short of the role the endpoint requires was byte for byte a healthy one from both ends while the org's spend never reached the control plane. A refusal now warns **once per distinct status per sink**, repeats drop to debug, and an unreachable control plane deliberately stays at debug because that fault clears itself. Five tests, each checked against a mutant (#170, CLAUDE.md invariant 13). |
| The repo's own gates | ✅ done | Five scripts, each run by CI's `fmt · clippy · test` job and each verified against mutants rather than written green. **`core-deps.sh`** (invariant 1) holds core's dependency list; it had been committed **non-executable**, so it failed with permission denied for everyone who cloned (#148), and an unreadable manifest used to fail as five lines claiming serde and sha2 had vanished from a file that still lists them, so an empty read now has its own exit path (#179). **`stated-numbers.sh`** (invariant 12) checks every number this repo states about itself, in every file that states it: it began as a badge-only check (#164), widened after the same figure in prose one file over said 100 where the workspace ran 747 (#173), and was scoped to the Test status section after it failed on a paragraph recording that very drift (#178). **`dto-boundary.sh`** (invariant 3) keeps `tokenfuse-core` types off the Cloud OpenAPI surface, covering the one road the compiler leaves open, `#[schema(value_type = ..)]`, since invariant 1 closes the rest by construction (#174). **`replicated-shape.sh`** (invariant 5) pins the replicated ledger's schema, because a field added there compiles and passes every test while a node with a durable store silently loses its ledger (#177). **`gates-have-teeth.sh`** breaks the other four on purpose and requires the failure, since a regex parser stops matching and reports success rather than breaking loudly, and three of the four did exactly that while being written (#180). It mutates tracked files, so it refuses a dirty tree, restores from a trap, and asserts the tree is clean before reporting success. CI also runs the gates it had only claimed to (#149), first-party actions moved off the Node 20 runtime (#151), and `cargo audit` runs through `audit.sh` so its one ignore re-establishes its own reason every run (invariant 11). |
| Safe defaults, after the 2026-08-04 cloud range | ✅ done | Two settings whose default was a security decision made by omission, parsed together in `crates/gateway/src/defaults.rs`. `TOKENFUSE_DLP` unset meant `off`, so the scanner this product advertises scanned nothing until an operator set a variable, and the range had to enable it by hand before it could test it at all. A call with no `x-fuse-run-id` reached the provider and was recorded in no ledger, trace or event stream. Separately each is defensible; together a deployment could pass every check it had and be governed **on paper**. Both defaults now point the other way, and the old behaviour is one explicit variable away in each case (`TOKENFUSE_DLP=off`, `TOKENFUSE_REQUIRE_RUN_ID=0`), which is the difference between a default and a prohibition. The upgrade consequence is real and is stated in the README's "Safe by default" section rather than left to be discovered. PII masks (`TOKENFUSE_DLP_PII`) deliberately did NOT move: their false positives are prose rather than credentials and the range established nothing about them. |
| `GET /v1/policy-plane`: a check that CAN fail | ✅ done | `crates/gateway/src/policyplane.rs` + `wardryx::Verdicts`. Every check for "the policy plane is on the data path" read environment variables and never asked whether a verdict had come back, so a plane that answered nothing passed, and the range hit that by accident: a missing identity header made a healthy PDP answer nothing and the gateway reported `wardryx unreachable`. The endpoint reports what the PDP ANSWERED: real allow/deny/hold counts with timestamps, plus the failmode fallbacks kept separate, because fail-open turns an outage into an allow and counting it would rebuild the fault inside the check. `on_data_path` is any real verdict in the window; `allow_and_deny_seen` needs both, so it stays false until a deployment drill proves the refusal works. This is trailryx's invariant in another form: a check that cannot fail reports zero forever. |
| A detector's severity is its magnitude | ✅ done | `store::severity_from_magnitude`. Measured 2026-08-04 on 999 agents: 3000 alerts, every agent tripping all three detectors that had anything to say, trip counts from 1 to 73 with a median of 2, and **one severity on all of them**. The number was already computed and already printed in the summary line; only the field an operator sorts by ignored it. Severity now steps up at four times a detector's own threshold and again at sixteen, so the ladder moves with whatever the operator configured instead of being a second fixed threshold, and it rises with a later trip but never falls, because two of these detectors count inside a window and an open incident must not walk down a triage list while the run is still going. The general form: a detector that scales as computation does not automatically scale as an alert, and the two failures look nothing alike from inside the code. |
| The documented command runs | ✅ done | `scripts/runnable-quickstart.sh` (invariant 16). The gateway gained a precondition (#141) and every command that advertised the old behaviour kept advertising it, including a `docker compose` stack that would crash-loop on the next image build. The gate joins continuation lines, finds every `docker run … ghcr.io/taipanbox/tokenfuse` and `cargo run -p tokenfuse-gateway` in a tracked file plus the compose gateway service, and requires each to carry `TOKENFUSE_UPSTREAM` or `TOKENFUSE_ALLOW_STUB`. It deliberately ignores subcommand invocations (`… -- constants`, `tokenfuse top`), which share the binary and need no provider, since a gate that cries wolf is a gate somebody deletes. |

## Test status

**Counts re-measured 2026-08-25**, each by the command named, because the set
here once said 100 where the workspace ran 747 and nothing had been watching:
`cargo test --all` runs **930 passing** (core 265, gateway 465, cloud 199,
umbrella 1, by `cargo test -p <crate>`), which is the figure the README badge
states and `scripts/stated-numbers.sh` gates (invariant 12). Python SDK: 11
passing (from the `python sdk` CI job). JS SDK: a smoke check, no count.
**`tokenfuse-cluster`: 13 integration tests** on live raft clusters (in-process
+ over HTTP sockets, incl. token-auth, HTTPS, **mTLS**, membership, linearizable
reads, redb durability; excluded crate, own CI job). `cargo clippy
--all-targets --all-features` clean with `-D warnings` across the workspace,
radar, and cluster. **`cargo audit` via `scripts/audit.sh`: 0 vulnerabilities**
across both manifests, unmaintained-crate warnings only (`number_prefix`,
`paste`, `rustls-pemfile`), plus one recorded ignore (rkyv, RUSTSEC-2026-0235)
whose justification the script re-establishes on every run (invariant 11).

The live-verification claims below were NOT re-checked in that pass and are
kept as written, with their original scope: **eBPF Radar built + run live on a
Linux VPS** (flags real LLM traffic). **Networked benchmark (release, 2-vCPU VPS):** the gateway adds **+0.82 ms p50 / +2.0 ms p99** over a direct socket to the upstream (see BENCHMARKS.md). Verified live: mcp-scan poisoning/rug-pull; OTLP export; DLP block; WASM policy block; enforce 402; durable-HA restart persistence; full Cloud stack.

## How to run

```bash
cargo test --all        # run the suite
TOKENFUSE_ALLOW_STUB=1 cargo run -p tokenfuse-gateway   # gateway, offline, invented numbers
```

## How to run against a real provider

```bash
TOKENFUSE_UPSTREAM=https://api.anthropic.com/v1/messages cargo run -p tokenfuse-gateway
# then point your agent at http://127.0.0.1:4100 and pass your provider key through
```

## Next steps

The roadmap (phases 1–4) is implemented and shipped in **v0.4.0** (tagged
2026-07-15; this line said v0.2.0 until 2026-08-06, two releases behind), and the
optional-hardening backlog that followed it is now cleared too:

- ✅ **mTLS / client-cert** auth between nodes (#52)
- ✅ **Durable Cloud store** — JSON snapshot + autosave (#49); a SQL/columnar
  backend for scale is a drop-in behind the same `Store` (see below)
- ✅ **Dashboard RBAC + alerting** (#51)
- ✅ **MCP broker** response redaction + stdio transport (#50)
- ✅ **Security-hardening pass** — body limits, connect timeout, `cargo audit`
  gate, threat model (#53)
- ✅ **Published to npm / crates.io / PyPI** — the `tokenfuse` name is claimed on
  all three (PyPI as `tokenfuse-sdk`); publish tokens revoked afterwards.

Since v0.3.0, two more tracks landed on `main` (and shipped: both are inside the
v0.4.0 tag of 2026-07-15, verified by `git merge-base --is-ancestor` on the #91,
#104 and #110 merges, though this list claimed otherwise until 2026-08-05;
see the Status-by-component rows above for the source-file detail):

- ✅ **P3: enterprise / compliance track**: the machine-readable control
  catalog, `tokenfuse compliance` CLI + SARIF export, Cloud `/v1/compliance`,
  minimal OIDC bearer auth (#91), the tamper-evident audit trail + ES256-signed
  manifest + dashboard savings tile (#92)
- ✅ **FinOps reporting**: `tokenfuse focus-export` (#97), the agent-event
  NDJSON exporter + `x-fuse-on-behalf-of` delegation chain + `parent_run_id`
  + the SPEC 6.5 `prev_hash` integrity chain (#98), outcome tags +
  `tokenfuse outcomes` (#99)
- ✅ **Post-launch fixes**: Anthropic auth-header forwarding, a raft-follower
  ledger-snapshot panic, 2026 model price-book entries (#100-#102)
- ✅ **Wave-2 governance plane**: the model router, the Wardryx PEP/PDP policy
  hook, Cloud incident replay + the regulator evidence pack, and per-instance
  Parquet trace segment naming, all off-by-default and fail-safe; landed and
  hardened across #103, #104, #106, #110; design + invariants in
  [docs/19](docs/19-wave2-governance.md)

What genuinely remains is deferred scale/ops work, not a blocker for a young
project.

**Re-checked `@claude 2026-08-05` against #111-#170** (the previous check
covered #91-#110 and was 60 PRs behind). All four items below still stand:
nothing merged in that range closed any of them. Checked by reading the code
rather than the PR titles, and each check is one command, so the next re-check
can repeat it instead of trusting this paragraph:

- **1**: no `postgres`/`clickhouse`/`sqlx` dependency in
  `crates/cloud/Cargo.toml`, and `crates/cloud/src/store.rs` still persists by
  JSON snapshot plus autosave.
- **2**: no `spiffe`, `svid`, rotation, reload or file watcher anywhere in
  `crates/cluster/src/`; every certificate still arrives as a static PEM path
  in an env var (`TOKENFUSE_CLUSTER_TLS_CERT/_KEY`, `_MTLS_CA`,
  `_CLIENT_CERT/_KEY`).
- **3**: `docs/13-security-hardening.md` still opens by stating it is an
  engineering hardening pass and not an independent third-party audit.
- **4**: the Wardryx decision cache still evicts on
  `cached_at.elapsed() >= self.ttl` and on nothing else
  (`crates/gateway/src/wardryx.rs`). Worth recording as a change since the last
  check even though the item is unmoved: `policy_version` is now carried on
  each cache entry and returned on a hit, so the raw material a version-aware
  invalidation would need is already in place. Nothing acts on it yet.

1. **SQL/columnar Cloud store** (Postgres/ClickHouse) for scale + long retention,
   behind the existing `Store` interface.
2. **Automated cert rotation / SPIFFE-style identity** for the cluster mesh
   (today: static PEM files; mTLS itself is done).
3. An **independent third-party security audit** before any "GA" claim: the
   in-house hardening pass ([docs/13](docs/13-security-hardening.md)) is explicit
   that it is *not* a substitute for one, and neither is the P3 compliance
   catalog or the internal adversarial-review rounds that preceded it.
4. **Policy-version-aware Wardryx cache invalidation**: today's decision cache
   is purely time-based (`TOKENFUSE_WARDRYX_CACHE_TTL_MS`); a poller that
   proactively drops cache entries the moment Wardryx's `policy_version`
   changes is a documented future enhancement (`wardryx.rs`), not required for
   Wave 2, and would tighten the window between a policy edit and it taking
   effect below the TTL.
