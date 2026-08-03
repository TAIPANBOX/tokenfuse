# CLAUDE.md - working instructions for tokenfuse

These instructions apply to any model working in this repo. They encode the
process and patterns the project was built with so work stays consistent
regardless of which model is active. Read this before starting a task.

## What tokenfuse is

A drop-in reverse proxy between AI agents and LLM providers. It enforces
per-run hierarchical budgets in real time - an over-budget call gets a hard
`402 Payment Required` ("Breaker"), not a warning after the fact - detects
loops, runs an agent firewall (taint tracking + DLP), scans and brokers
credentials for MCP tools, writes zero-DB Parquet analytics, replicates the
budget ledger across a raft HA cluster, and ships a hosted Cloud whose
privileged mutations can additionally require a hardware-backed ES256
signature from a separately paired device.

Positioning is FinOps-first: **"enforcement, not observability."** This was a
deliberate pivot (`docs/09-product-strategy.md`, decided 2026-07-02; reframed
2026-07-07 - see the P0 Breaker-reframe commits). Never market tokenfuse as an
MCP security scanner - the MCP scanner/broker is one capability pack inside a
single core, not the product.

## Where the code actually is

**`PROGRESS.md`.** This file is process and invariants; it carries no status,
deliberately. A status section inside an instruction file is the half that goes
stale first, and the reader trusts the whole document on the strength of the
half that is still correct. This one used to say "v0.3.0 released" and "none of
this has shipped in a tagged release yet" while the v0.4.0 tag had been standing
since 2026-07-15.

Note a known gap while you are in there: `PROGRESS.md`'s header is current, but
its "What genuinely remains" section still says it was re-checked against
#91-#110. PRs have since reached #145. Those four remaining items may well still
stand, but nothing has re-verified them, so do not quote them as current without
checking.

## The working loop (this repo uses PR flow - unlike idryx/qryx, which push to main)

1. Branch per phase/feature off `main`.
2. Implement one logical increment.
3. Run the gates (below) - all must pass.
4. If working as a subagent for the architect: leave changes **uncommitted**
   for review before committing.
5. Commit with Conventional Commits, message ending in:
   `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`
6. Push the branch, open a PR with `gh`.
7. Wait for **all** CI checks to go green. Fix forward if red.
8. **Ask the user** before merging.
9. Merge with a merge commit (`--merge`), matching PRs #94-#99. Don't
   squash or rebase-merge.

**Parallel work in this repo MUST use `git worktree add`** - the main
checkout is frequently shared across sessions/agents.

## Gates (must pass before calling anything done)

```sh
cargo fmt --all -- --check
cargo clippy --all-targets          # CI additionally runs --all-features
cargo test --all
cargo test -p tokenfuse-gateway --features cluster --test cluster_backend
./scripts/core-deps.sh
```

The last one is the raft-backed ledger test gated behind the `cluster`
feature - copy this exact invocation, it's what `.github/workflows/ci.yml`
runs. CI also runs separate jobs for the Python SDK (`sdk/python`), the JS SDK
(`sdk/js`), the OpenAPI spec, the Next.js dashboard, the `crates/cluster`
workspace (own fmt/clippy/test), `cargo audit` (workspace + cluster), the
`crates/radar` eBPF build (Linux-only), and a `--features apns` clippy build
for `tokenfuse-cloud`. Job names, if you need to reference one:
`fmt · clippy · test`, `python sdk`, `js sdk`, `openapi spec`, `dashboard
(Next.js)`, `cluster (raft HA)`, `security (cargo audit)`, `radar (eBPF
build)`, `cloud apns (feature build)`.

## Hard invariants

1. **`tokenfuse-core` stays dependency-minimal.** Its full allowed dependency
   list, verbatim from `crates/core/Cargo.toml`, is: `thiserror`, `serde`,
   `serde_json`, `regex`, `sha2` (for the hash-chained audit trail in
   `audit.rs`). Nothing web-, `utoipa`-, or `p256`-shaped leaks in here - those
   belong in `crates/gateway` or `crates/cloud`, which sit on the I/O
   boundary. Core is money, pricing, ledger, policy - it has to stay provable
   and portable.
   *(gate: `scripts/core-deps.sh`)*
2. **Enforcement hot path: byte-identical output across refactors.** The
   golden regression test is
   `breaker_error_response_matches_budget_error_byte_for_byte` in
   `crates/gateway/src/proxy.rs`. It asserts the Breaker-facade-backed
   `breaker_error_response` produces the same status, body bytes, and headers
   as the old `budget_error` builder, across all five 402 budget-family
   reasons (PR #92 wired the facade into the real 402 path - don't let it
   drift back apart).
   *(test: `breaker_error_response_matches_budget_error_byte_for_byte`)*
3. **Core types reach the Cloud OpenAPI only via cloud-local `*Schema` DTOs.**
   Never derive/expose `tokenfuse-core` types directly on the Cloud API
   surface - the DTO boundary is what lets core evolve without breaking the
   public schema.
   *(not enforced)*
4. **"Honesty is a feature."** Never over-claim compliance coverage or
   hard-guarantee semantics. Budgets are estimate-then-settle, and the system
   fails open by default - docs and READMEs must state these limitations
   plainly, not bury them.
   *(not enforced)*
5. **Don't thread new dimensions through `LedgerBackend`/raft casually.** The
   ledger's replicated state (`crates/gateway/src/ledger_backend.rs`,
   `crates/cluster`) is the thing that has to stay linearizable across nodes;
   a new field there is a raft/schema-identity decision, not a routine edit.
   *(not enforced)*
6. **Telemetry evolves append-only.** Parquet schema changes follow the
   nullable-evolution pattern set by P2/P3/P4 (see the comments in
   `crates/gateway/src/sink.rs` around `read_schema()` and the mixed-schema
   test in `crates/gateway/src/sqlq.rs`): new columns are nullable in the
   *read* schema so old trace files keep reading, even though the *write*
   schema declares them non-nullable for what we produce going forward. The
   agent-event exporter (`crates/gateway/src/events.rs`) must stay zero-cost
   when `TOKENFUSE_EVENTS_PATH` is unset and fail-open when it's set (log a
   warning, don't crash the gateway) - and it must never fabricate an
   `agent_id`; skip the event if the request doesn't carry one.

   *(partly gated: the mixed-schema test in `crates/gateway/src/sqlq.rs` covers
   the Parquet read path; the exporter's two promises are now held by
   `a_disabled_exporter_does_no_work_at_all`,
   `an_unopenable_path_falls_back_to_disabled_rather_than_failing`,
   `a_directory_as_the_events_path_is_also_fail_open`,
   `an_empty_path_is_treated_as_unset` and
   `a_missing_agent_id_is_skipped_and_counted_never_invented`)*
7. **A level-triggered detector is edge-converted at the source.** Four of the
   cloud's detectors fire on discrete trips (a block, a loop repeat, a burst),
   so one trip is one event. `budget_threshold` is not like them: once
   `spent/budget` is over the line it stays over, because spend never goes
   down. A condition of that shape must emit on the TRANSITION only, or every
   later call in the run writes another line into the shared event log, which
   is the resource that saturates first in this stack (about 0.4 KB per
   decision, so a busy run fills a volume that CPU never touches). The edge
   marker is the incident's own existence, which rides in the snapshot, so a
   restart does not re-notify either. `set_budget` clears it, because a new
   budget is a new line to cross.
   *(test: `budget_threshold_is_exported_once_per_crossing`, plus
   `raising_a_budget_lets_the_threshold_fire_again` for the reset)*

   The same shape check is owed to `spend_spike`, which is also level-triggered
   (an org's burn rate stays high for as long as it stays high) and does
   re-emit per ingest batch today. Not changed here: it has shipped that way,
   and altering when an existing incident reaches the console's stream is a
   behaviour change that needs its own decision, not a drive-by.

8. **An incident's name is a claim, and its trigger has to support that
   claim.** `budget_exhausted` fires on `budget_exceeded` and on nothing else.
   It used to fire on the whole `is_budget_protection` set, which also holds
   `loop_detected`, `policy_violation`, `wasm_policy` and `killed`. That set is
   correct where it comes from: all five avoid spend, so all five belong in the
   savings report. As a trigger for an incident with this name it states
   something untrue about a run that may have no budget at all, and the stack
   mails that sentence to a human at three in the morning.

   Measured on a live cluster 2026-08-02: a run blocked three times by the loop
   detector, no budget ever set, raised a High incident saying its budget was
   gone, and the notifier delivered exactly that. The two thresholds are both 3
   by default, so a real `sustained_loop` could not be raised WITHOUT a false
   `budget_exhausted` beside it, and the fiction outranked the truth on
   severity. Narrowed by the user's decision the same day.

   The general form, which is the part worth keeping: a set that answers "did
   this save money" is not a set that answers "did this run out of money", and
   sharing one predicate between a report and an alert is how the second
   question quietly inherits the first one's answer.
   *(test: `budget_exhausted_needs_a_budget_block_not_any_saving_block`, which
   also asserts the savings figure is unchanged, and
   `a_looping_run_raises_the_loop_and_nothing_about_money`; both verified by
   restoring the old predicate, which fails them)*

## Decisions that have no gate yet

This list is debt, and it is here to stay visible rather than to be tidy.

**Held by this file alone: invariants 3, 4 and 5.** Invariant 6 is only partly
held, and invariant 2 is held by one golden test that must never be deleted.

- **Invariant 3** (core types reach the Cloud OpenAPI only via cloud-local
  `*Schema` DTOs) is mechanically checkable: fail if any `utoipa` derive in
  `crates/cloud` names a `tokenfuse-core` type. That is the exact regression
  mode, and it is perhaps forty lines.
- **Invariant 5** (do not thread new dimensions through `LedgerBackend`/raft
  casually) cannot be scripted, but it can be made loud: a comment block at the
  top of `ledger_backend.rs` saying a field added here is a raft and
  schema-identity decision would put the warning where the edit happens rather
  than in a file somebody may not have opened.
- **Invariant 6**'s exporter half is now five tests. Both promises stop being
  true quietly, which is why they needed tests rather than comments: nothing
  crashes when a disabled exporter starts doing work, it just gets slower, in
  production, per request; and nothing warns when a broken path stops being
  fail-open, the gateway simply refuses to start on somebody else's machine
  because an optional audit export could not open a file.

  Verified by breaking both: making `emit` build an event before checking
  whether it is disabled fails three of them, and turning the open error into a
  panic fails two. The Parquet read path is still the tested part of this
  invariant, and the write-schema evolution is still not.

  Writing them turned up a latent race worth recording. Every test here mutates
  one process-wide environment variable, and cargo runs a binary's tests on
  parallel threads. The two original tests had that race and passed on luck;
  four more would have made it bite. They now serialise on a mutex, which is
  std-only, because adding a dev-dependency to this repo is an escalation and a
  flaky test is worse than no test.
- **Invariant 4** ("honesty is a feature") is judgement, and stays judgement. It
  is also the one most worth re-reading before writing a README.
- **Invariant 8 has a sibling nobody has checked.** The narrowing was found by
  running one detector and reading its trigger. The other kinds were not
  re-read against their own names in the same pass: `spend_spike`,
  `fanout_explosion`, `mcp_drift` and the taint/DLP kinds each assert something
  specific, and each is triggered by a predicate that was written for its own
  reasons. One was wrong. That is not evidence the rest are right, and there is
  no test that would say.

## Standing rule

An approved architecture decision is **not finished** until it is two things: a
numbered invariant in this file, and a gate in a script or a test if it can be
checked structurally. Until then it is a document, and documents do not stop
code.

When the user approves a decision, add it here in the same session. Do not defer
it, because later is where the drift lives.

## Known pitfalls

- **CI runner disk.** The `fmt · clippy · test` job builds three full profiles
  (clippy `--all-features`, debug tests, the `cluster`-feature test graph); a
  warm cache on the 14 GB runner disk has run dry mid-link before (`ld` dies
  with SIGBUS). The job frees ~25 GB of preinstalled bundles it doesn't need
  (`android`, `dotnet`, `ghc`, `boost`, CodeQL) before building. If SIGBUS
  link failures recur, bump the `Swatinem/rust-cache` `prefix-key` (currently
  `v1`, bumped 2026-07-09 after a poisoned-cache SIGBUS) to force a fresh
  cache namespace.
- `core.fileMode` is already set to `false` in this repo's git config, don't
  re-set it or chase phantom mode-only diffs. **The other half of that: a
  NEW executable file does not get its bit recorded either.** `chmod +x`
  succeeds on disk, git ignores it, and the file lands as `100644`, so
  `./scripts/whatever.sh` fails with permission denied for everyone who
  clones. Add executables with `git update-index --chmod=+x <path>`. This
  bit `scripts/core-deps.sh` on the commit that introduced it.
- **Docs are numbered 01-20** (`docs/`); new design docs continue the
  sequence (next is 21). `docs/09-product-strategy.md` is the one to read
  before touching product framing or positioning.

## Model escalation - tell the user, don't just push through

No model can switch itself. When a task hits the criteria below, stop and
say so, then wait for the user before proceeding:

- A real **architectural fork** with expensive rollback - ledger/raft
  changes, Cloud schema-identity decisions, anything that touches how core
  types cross the DTO boundary.
- Anything **irreversible or outward-facing** - cutting a release, publishing
  a package (npm/crates.io/PyPI/GHCR), or any other public action. Note the
  standing decision: **no publicity push** (HN posts, launch announcements,
  etc.) until the user says the stack is ready - don't raise the topic
  unprompted.
- **Subtle correctness on the enforcement path** - anything touching the 402
  Breaker response, budget reservation/settlement, or the loop/taint/DLP
  block decisions, where a missed case ships a wrong allow/deny.

Routine increments are fine on a cheaper model: a new report CLI (like
`focus-export`/`outcomes`), connector-pattern extensions, tests, docs.

## Memory

Session learnings live under
`~/.claude/projects/-Users-factory-Development-tokenfuse/memory/` if present.
Check it for prior lessons before repeating a class of mistake.

## Conventions

- **No long dashes** anywhere: not in code comments, docs, commit messages, or
  PR bodies. Use a comma, a colon, parentheses, or a short hyphen.
- Nothing paid or metered gets enabled without telling the user first and
  getting agreement.
- Do not delete or revoke keys, tokens, or certificates on your own initiative.
