# Live infrastructure validation

TokenFuse was exercised on real Linux infrastructure with a real Anthropic key before any public
launch - three things that never show up on a macOS dev machine or CI fixtures: a real multi-node raft
cluster, real cross-cloud network conditions, and real LLM cost accounting. All infrastructure was
disposable (ephemeral Hetzner VPS boxes, torn down after each run; short-lived cloud instances for the
AWS/GCP leg) and reachable only over `127.0.0.1` / SSH tunnel - nothing was ever exposed publicly.

## Raft HA cluster - from loopback to a real cross-datacenter network

The cluster (`crates/cluster`, raft-replicated budget ledger) was proven correct at three levels of
increasing realism:

| Test | Loopback (3 nodes, one box) | Cross-machine (4 nodes, one DC) | Cross-DC (4 nodes, two DCs) |
|---|---|---|---|
| No double-spend | 30 concurrent reserves vs a 5-unit budget → exactly 5 admitted, byte-identical state | same → 5/25, byte-identical on all 4 nodes | same → 5/25, byte-identical |
| Leader-crash re-election | `kill -9` leader → ~526ms | ~583ms over a real inter-host network | ~568ms |
| Network partition | not testable on one box | isolated leader could not commit (no quorum); majority kept serving; **no split-brain**; healed node caught up on the missed write | same, confirmed cross-DC |

The 4-node cross-machine and cross-DC runs used the product's actual intended shape - one gateway
process per host, TLS between nodes off a shared CA, a shared bearer token - not a bespoke test rig.

**A single node surviving on its own, added 2026-08-04, because until that date it did not.**
Every row above is a QUORUM result: the killed node came back to a consistent state because the
other two still held it, and that is a different claim from "the ledger is durable". It had to be,
because the shipped binary had no durable mode at all: `build_durable` existed and its only caller
was a test, so `serve` always built an in-memory node and a restart of a real server lost every
budget and every reservation, silently. Restarting the whole cluster would have lost everything.

`--dir <path>` now wires the binary to the redb-backed store, and the in-memory case says so at
startup in words rather than by the absence of a flag. The test is
`a_budget_survives_a_process_that_was_killed_rather_than_stopped`
(`crates/cluster/tests/kill_durability.rs`): it spawns the real binary, `SIGKILL`s it so nothing
gets a chance to flush or tidy up, and starts it again on the same directory. The budget and the
reservation are both there afterwards.

Two things that run measured rather than assumed. `/api/write` answers **HTTP 200 with an error
body** while raft has no leader yet, and `/healthz` answers before `--init` runs, so a client that
reads the status line believes a write succeeded that stored nothing; the first version of this test
did exactly that, then blamed the disk. And the readiness worry turned out not to exist: state was
readable **0 ms** after `/healthz` first answered.

Still not measured here: power loss, where the disk's own cache is allowed to forget what it
acknowledged. `SIGKILL` leaves the kernel and its page cache alive, so this proves recovery from a
dead process, not from a dead machine.

## Enforcement under real load

**A representative real run** (the fleet-summary dashboard referenced from the README): 6 agents, 24
runs, 51 real Claude calls - 34 served (200), 17 blocked (402) - **$0.0115 spend, $0.0247 saved**
(breaker $0.02136 + semantic cache $0.00176 + model router $0.00154), 3 budget breaks. The Breaker
tripped live mid-run: 4 calls admitted against a $0.006 budget, the 5th would have exceeded it, so calls
5-8 were held at 402 - enforced by the raft ledger, in seconds, not on next month's invoice. Three
incidents were auto-detected in the same run: `budget_exhausted` (a scraper agent, 3 runaway runs),
and `fanout_explosion` (an orchestrator with 7 children, and a support agent mid-burst).

**A separate, larger enriched multi-agent campaign** (later run, real Claude `claude-haiku-4-5` through
the fully-featured gateway - enforce + router + cache + DLP + firewall + Wardryx PEP + Cloud sink):

- **176 real allowed calls / 65 runs / $0.0206 total spend.**
- All three savings levers fired for real: breaker (blocked spend) **$0.03066** + semantic cache
  **$0.00430** + model router **$0.00154** = **$0.0365 saved**, 12 budget breaks.
- The model router downgraded `claude-sonnet-4-5 → claude-haiku-4-5` on cheap tasks; the semantic
  cache served real repeat prompts - both savings are measured, not theoretical.

This is the same campaign the 34-agent concurrency test below was run against.

**Concurrency, 34 requests fired at once** (different agents, credentials, budgets, policies): good
agents **6/6 served (200)**, money-oversteppers **10/10 blocked (402)**, permission-oversteppers
**6/6 denied (403)**. A shared-budget race - 10 agents against one **$0.0010** cap - admitted **exactly
3, blocked 7**, parent spend stayed under the cap: the raft ledger held a shared budget correctly under
true concurrency, not just sequential load.

**Scale test** (stub provider, to isolate the governance hot path from LLM latency): 100 concurrent
reserves against a 20-unit budget admitted **exactly 20**; 500 concurrent against a 50-unit budget
admitted **exactly 50** - zero over-admission at either scale. Full-gateway throughput: 216 req/s at
c=100, 397 req/s at c=500, 8,000/8,000 requests served, none dropped.

## Cross-cloud cost accounting (AWS + GCP)

A separate question from the Hetzner runs above: does the gateway's cost-enforcement mechanism itself
hold up on the two clouds most of our audience actually runs on? A matched-protocol campaign (176 real
allowed calls, 12 budget-block attempts, same model, same `enforce` mode) was run on AWS (`t3.medium`,
`eu-central-1`) and GCP (`e2-medium`, `europe-west3`):

| metric | Hetzner | AWS | GCP |
|---|---|---|---|
| real calls / budget blocks | 176 / 12 | 176 / 12 | 176 / 12 |
| total LLM spend | $0.0206 | $0.050971 | $0.051214 |
| cost per allowed call | $0.000117 | $0.000290 | $0.000291 |
| p50 / p99 latency | - | 1.227s / 3.795s | 1.227s / 5.006s |

**Honest scope note:** AWS and GCP are scale-matched to Hetzner by call count and validate the gateway
and its cost accounting with real Anthropic traffic - they are not a repeat of the full raft/router/cache/
multi-agent evidence above, which remains Hetzner-only for now. The cost-per-call gap (~2.5x) is not
apples-to-apples either: the Hetzner number includes router downgrades and cache hits that were
deliberately left off on AWS/GCP so those two would isolate pure gateway + real-model cost.

**The breaker fired identically on all three: 12 of 12 deliberate budget overruns blocked, no
exceptions.** That is the portability claim worth carrying out of this run. What differs between the
clouds is the price of the machine, not the behaviour of the control.

## What the control plane itself costs, at cluster scale

The runs above answer "does the breaker work here". They are one small machine per cloud and under an
hour, so they say nothing about the cost of running the governance itself. Between 25 and 27 July 2026
the whole stack came up as a five-node k3s cluster on each of the three clouds, six clusters in all, to
answer exactly that. Command output is public in
[stack-k8s](https://github.com/TAIPANBOX/stack-k8s) under `cloud/*/evidence/`; the full sheet is that
repository's `PORTABILITY.md`. Do not merge these numbers with the 176-call campaign above: different
experiment, different scale.

| | Hetzner (5 x CPX42) | AWS (5 x `c6a.2xlarge`) | GCP (5 x `c2d-highcpu-8`) |
|---|---|---|---|
| cluster burn while running | EUR 0.20/hour | USD 1.836/hour | USD 2.04/hour |
| five nodes, published monthly rate | EUR 137 | USD 1,487 | USD 1,291 |
| RWX volume for the shared event log | EUR 0 (Longhorn) | USD 1.80/month (EFS) | USD 194.56/month (Filestore, 1 TiB minimum) |
| cost per million governed decisions | EUR 0.024 | USD 0.208 | USD 0.229 |

Three FinOps findings, none of which we expected going in:

1. **RWX is where the clouds differ by two orders of magnitude**, not compute. A 5 GiB shared event log
   costs USD 1.80/month on EFS and USD 194.56/month on Filestore, because Filestore bills a whole TiB.
   Compute was within 15%; storage was 108x.
2. **The newest CPU generation is the cheapest per unit of work, not the dearest.** AWS `c7a` (Genoa)
   costs 37% more per hour than `c6a` (Milan) and returns 64% more throughput, so it is 16% cheaper per
   governed decision. "Take a smaller instance" quietly raises unit cost on a CPU-bound workload, and a
   quota that blocks the newest family is therefore a price increase wearing a paperwork costume.
3. **Metering is cheap in CPU and expensive in gigabytes.** Every governed decision writes about 426
   bytes of hash-linked audit, and every decision is audited rather than a sample: 614 MB a day at a
   thousand calls a minute. Retention is a design parameter from day one, and it is the one line of an
   agent programme that can be forecast exactly, from one number.

## Real bugs live testing found (and fixed)

All three were invisible on fixtures, the stub provider, and macOS - only real Linux + real traffic
surfaced them. All fixed and merged before the runs above were taken as final.

1. **`x-api-key` not forwarded** (`provider.rs`) - the upstream header allowlist had OpenAI's
   `authorization` but not Anthropic's native `x-api-key`, so the gateway could not authenticate to
   Anthropic's own API. Fixed.
2. **Raft-ledger snapshot panic** (`proxy.rs:360`) - `.expect("run just opened")` panicked a worker
   when a follower's local snapshot lagged a just-opened run under burst load; 1/26 requests silently
   dropped. Fixed with a zero-snapshot fallback (enforcement itself was never at risk - the real gate is
   the raft-linearized `reserve()`).
3. **Price book missing current models** - `claude-haiku-4-5` wasn't in the price book, so reserve
   estimates fell back to a conservative default and mis-sized headroom. Fixed; the price book now
   covers 9 models.

A later concurrency run also caught and fixed a real Wardryx enforcement gap (its PEP decision cache
missed `attestation_method` in its key); see Wardryx's own validation notes for that one, since it lives
in Wardryx's code even though TokenFuse's gateway is what exposed it under load.

## The breaker against a real provider, and what the scanner beside it does not catch

2026-08-04, on a three-node k3s cluster in AWS `eu-central-1`, gateway pointed at
`https://api.anthropic.com/v1/messages` with a real key. Every earlier guardrail run in this
repository used a stub provider, which is free and deterministic and cannot answer the one
question a buyer asks first: does the breaker hold when there is real money on the other side.

**It holds.** A `claude-opus-4-1` request for 2000 tokens against a budget of `0.000001` USD came
back **HTTP 402**, `type: budget_exceeded`, `spent_usd: 0.0`, and the response body carried **no
`request_id`**: the provider never saw the request. A managed call with a workable budget went
through and was metered at `0.000049` USD with `x-fuse-price: known` and a real `allow` from the
policy plane.

**Under a fleet, the accounting stayed exact.** 100 agents x 3 calls: 18 blocked, and 18 was
precisely the number the fixture should produce (5 agents priced below one call, x3, plus one
planted runaway x3). 250 agents x 4 calls: 56 blocked, again exact. No over-permit and no
over-refuse under contention.

**Throughput, ours versus the provider's.** The same fleet with every budget set below one call
price never leaves the cluster, so it measures the gateway, the PDP and the ledger alone:
**1,119 decisions/s** at 250-way concurrency, against **81 calls/s** for the identical fleet with
the provider in the path. Gateway resident memory 39 MiB, Wardryx 6 MiB. The governance layer is
not the bottleneck and is not close to being it.

**Where our half breaks, and in which direction.** At 1000-way concurrency, 6 of 2000 calls came
back `wardryx_denied` rather than `budget_exceeded`: connections to the PDP began failing and
`failmode=closed` denied them. 0.3% false refusals, and the alternative under `failmode=open`
would have been 0.3% of calls passing unexamined while the run still looked clean.

**DLP: what it stops and what it does not.** With `TOKENFUSE_DLP=block`, a whole
`AKIAIOSFODNN7EXAMPLE` in a prompt was refused with `x-fuse-dlp: blocked: 1 secret(s):
aws_access_key`, and the provider never saw it. Two things did get through, both stated here
because a buyer will find them in five minutes:

- the 40-character AWS **secret** key on its own (no distinctive prefix to match on), and
- the same access key **split across the text** (`"part one is AKIAIOSF and part two is
  ODNN7EXAMPLE"`).

The scanner reads contiguous text. It catches carelessness, an agent that dropped a config into a
prompt. It does not stop somebody hiding a secret on purpose, and nothing in this repository
should be worded as though it did.

**Two faults this run found, both since fixed.** A call with no `x-fuse-run-id` reached the
provider and was recorded in no ledger, trace or event stream (all three NDJSON files at 0 bytes
after a successful call) - refused by default since 2026-08-06 with `400 metering_required`, and
`TOKENFUSE_REQUIRE_RUN_ID=0` restores the pass-through for a deployment that wants it. Secret
scanning moved the same way in the same change: this run had to enable `TOKENFUSE_DLP` by hand
because unset meant `off`, and unset now means `block`. And a missing `x-fuse-agent-id` was passed to the
PDP as an empty identity, whose rejection the gateway reported as `wardryx unreachable`, sending
an operator to debug a healthy machine - now a local `identity_required` naming the header.

## One gateway behind a home router, two clouds at once, and sixteen ways to break it (2026-09-17)

2026-09-17: gateway `tokenfuse:v1.0.1` and control plane `tokenfuse-control-plane:v1.0.1`, as
pinned by stack-single v1.1.3, ran on a Debian 13 mini PC behind a home router on carrier-grade
NAT. The gateway was published on the box's tailnet address only, never on the LAN.
`TOKENFUSE_CLIENT_KEYS` carried one key per cloud; the identity map bound the AWS key to
`agent://customer.example/aws/*` and the GCP key to `agent://customer.example/gcp/*` (units
`aws` and `gcp`). The launcher set `TOKENFUSE_WARDRYX_MODE=enforce` and
`TOKENFUSE_WARDRYX_FAILMODE=closed`; the binary's own default is `mode=off, failmode=open`.
Full detail: the run's evidence and
[estate-gates/PROVEN.md](https://github.com/TAIPANBOX/estate-gates/blob/main/PROVEN.md), the
rows dated 2026-09-17.

**Two customer agents called through the box at once, on two clouds, against the real
provider.** Direct WireGuard paths measured 23 ms and 29 ms. From 11:46:22Z to 11:47:15Z both
loops ran 17 x `200` at `0.000033` USD each with `x-fuse-wardryx: allow`, then `402
budget_exceeded` from call 18, the wire body identical on both. Six `breaker_tripped` lines
landed on one bus, interleaved by timestamp and chained by `prev_hash`. `GET /v1/runs` showed
`pct_used: 93.5` on both runs afterward.

**The box told the two clouds apart by key and by id.** No key: `401`. The AWS key presenting
the GCP agent id: `403 identity_mismatch`, one `high` event on the bus. A wrong key: `401`.

**The box froze one cloud's agents while the other kept working.** `PUT
/v1/policies/freeze-gcp` (`deny_above_usd 0.000001`) made every GCP call `403 wardryx=deny`
starting at call 1, while AWS ran its 17 calls in the same minute, unaffected. Three
`policy_deny` events reached the bus; `DELETE` on the policy, and GCP calls answered `200`
again.

**A FinOps crew ran on the box through its own gateway door, and a monthly cap stopped it.** A
second gateway in the same compose project served unit `finops`, matched by prefix, with a
central cap set through the control plane's `POST /v1/units/finops/budget`. One real
`claude-sonnet-5` call settled at `0.05811` USD, then the next answered `402 unit 'finops'
monthly budget exceeded`; `unit_cap_exceeded` (high) and `breaker_tripped` landed on the crew
door's own events file. The published price book carries no `claude-sonnet-5` row, so that call
priced at the fallback rate (15/75 USD per Mtok, `x-fuse-price: fallback`), about five times the
model's list price (tokenfuse#305, open).

**The FinOps reporting surface ran end to end.** `x-fuse-outcome` tags priced by `tokenfuse
outcomes`; `tokenfuse focus-export` wrote 272 rows for the customer door and 5 for the crew
door; `tokenfuse savings` totalled `0.002498` USD across 17 budget breaks; `tokenfuse sql` read
`calls` by unit and decision; `tokenfuse compliance --markdown` ran. On the control plane,
`/v1/spend`, `/v1/owners`, `/v1/summary`, `/v1/savings`, `/v1/series`, `/v1/units`,
`/v1/incidents` and `/v1/audit/verify` all answered, the last `ok`. Units read aws 1122, gcp
627, finops 58110 microUSD; four `budget_exhausted` incidents were open; a central override on
a unit refused the next call with `402 unit_budget_exceeded`.

**The failure matrix covered sixteen cases; these are the gateway's and the control plane's
own.** The policy plane stopped: every call answered `403 wardryx unreachable,
failmode=closed` in 0.3 s, one `dependency_failed` (`dependency=policy_plane`) per call, and
recovery was instant. Provider egress rejected: `502` in 53 ms plus `dependency_failed` at
stage `send`. A retired model id: `404` plus `dependency_failed` at stage `response`. A revoked
key: `401` passed through with no event, by design (invariant 47). Three identical `tool_use`
blocks among the last ten: `402 loop_detected` before the provider ever saw the call; forty
identical plain calls are not a loop by that definition, and were stopped by the budget alone.
`docker compose down`/`up` and two reboots: the run ledger went from 26 runs to 0 and the unit
ledger's month reset, while the control plane still held `0.002145` USD, so a central cap was
enforced afterward against a tally that had forgotten the month. Control plane stopped: three
calls' telemetry was lost outright, not queued. A customer node killed mid-run, and a path cut
for 40 s: no plane said anything at 5 s or at 60 s. The control plane could not create its own
events file (uid 10001 with gid 999 against a `2775 root:10001` directory) and said nothing,
so no control-plane incident reached the bus until the file was pre-created. Owner attribution
read `unassigned` for every run. A 40-entry `x-fuse-on-behalf-of` chain was accepted with no
event while delegation verification was off.

**What followed, as of this writing.** tokenfuse#292 and #297 are fixed by #303 (`f6c2ca2`);
#293, #294 and #295 by #310 (`3787ccd`, invariants 52 to 54); #296 by #307 (`169a83e`, the
`run_stalled` detector, invariant 60); #305 above is still open. None of it is in a tagged
release: the launchers pin v1.0.2, whose gateway carries none of these fixes.

**What this run did not prove.** Managed agent runtimes (Bedrock Agents, Vertex Agent Engine)
were not exercised, nor were managed clusters, arm64, or more than one node or agent per
cloud. Volume stayed low: about half a call per second across two agents. The raft build was
not part of this run. Only the tailnet-bound gateway was rebooted; its reboot survival on the
default loopback bind is untested here.

## Method

Disposable Hetzner VPS boxes (deleted after each run) and short-lived cloud instances; code delivered as
a `git archive` tarball (no secrets, no `.git`, no token) rather than a token-bearing clone; the Anthropic
key was written to a root-only file, never logged, and revoked after use; every service bound to
`127.0.0.1` only, reached exclusively via SSH tunnel. Nothing from these runs was ever exposed publicly,
and no infrastructure or secret from the campaign persists today.

