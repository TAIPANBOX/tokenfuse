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

   `spend_spike` was the same shape and was left alone here, then rewritten on
   2026-08-03 (invariant 10): it is now edge-triggered too, on the transition
   into a spike, with the marker in memory beside the other trackers rather
   than on the incident. A restart mid-spike therefore costs one extra report,
   which is the price of not deleting the incident to re-arm it.

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

9. **A refusal that can wake somebody has a type of its own.** This is what
   makes `breaker_tripped = medium` honest rather than merely quieter. Every
   reason the breaker can give either emits its own event where it is decided
   (DLP, taint, identity) or is raised by the control plane from the settled
   record (budget exhaustion, loops, kills). The two that had neither, a unit's
   monthly cap and a refusal by this gateway's own policy or wasm evaluator,
   now emit `unit_cap_exceeded` and `policy_deny` beside the generic record.

   The rule generalises past these two: lowering the severity of a generic
   event is only safe when every case it covers is also reported specifically.
   Otherwise it is not a reduction in noise, it is a hole.
   *(test: `the_two_refusals_with_no_other_event_get_their_own` and
   `a_reason_that_already_has_an_event_is_not_reported_twice` in
   `gateway::proxy`, which also pins that the six reasons with their own events
   do NOT get a second one, since double-reporting would make every count of
   them wrong; plus `both_new_events_outrank_the_generic_one`)*

10. **A name that promises a change is measured as a change.** Two detectors
   carry one now, and both used to measure a size instead.

   `spend_spike`
   compares an org's last minute against ITS OWN recent normal: the burn over
   the preceding half hour, per minute, times a configured multiple, with the
   old fixed rate kept as a floor beneath which no multiple counts.

   It used to be the rate alone, which measured a HEIGHT while the name
   promised a CHANGE. An org whose ordinary working day sat above the line
   raised a spike on every ingest batch for as long as it kept working, and an
   org whose spend genuinely jumped tenfold under the line raised nothing. This
   is invariant 8's shape again, found by the audit invariant 8 asked for.

   Three conditions, each earning its place: the floor, because without one a
   jump from a rounding error to twice a rounding error is an infinite
   multiple; the multiple, which is what makes the word true; and some history,
   because an org whose first ever minute is expensive has not spiked, it has
   arrived. A baseline of zero is deliberately allowed to trip, since idle to
   hot is the runaway case this exists for, and the floor is what keeps that
   honest.
   `fanout_explosion` is the same shape and was rewritten the same day: an
   agent's distinct runs this window against its OWN habit, the average of its
   completed windows, with `fanout_runs` kept as the floor. An agent whose
   ordinary job is twenty concurrent runs tripped it every window, and one that
   normally drives two and suddenly drove nineteen tripped nothing.

   Its history is a count per fixed bucket, NOT a longer run-id deque, and that
   is load-bearing: the deque is capped at `INCIDENT_TRACKER_CAP` distinct runs,
   so a busy agent stretching it to cover a baseline would evict its own history
   and then read as an explosion forever. The fault would have come back in the
   fix for it, at the exact scale where it matters most.

   Both are edge-triggered for invariant 7's reason, and both allow a baseline
   of zero to trip, because idle-to-hot is the runaway case these exist for and
   the floor is what keeps that honest.
   *(test, spike: `a_steady_burn_above_the_line_stops_being_a_spike`,
   `a_jump_over_its_own_normal_is_a_spike`, `a_jump_below_the_floor_is_not_a_spike`,
   `an_org_with_no_history_has_not_spiked`,
   `a_quiet_org_that_suddenly_spends_is_a_spike`,
   `a_spike_is_reported_once_per_crossing`. Fan-out:
   `a_steady_fan_out_is_not_an_explosion`,
   `a_jump_over_its_own_habit_is_an_explosion`,
   `a_jump_below_the_floor_is_not_an_explosion`,
   `an_agent_with_no_habit_yet_has_not_exploded`,
   `an_explosion_is_reported_once_per_crossing`. In each set the steady case,
   the no-history case and the once-per-crossing case fail on the old
   predicate, which is how they were checked)*

11. **A silenced advisory carries a reason, and the reason is re-established on
   every run.** `cargo audit` reads the lockfile, which is correct and is why
   it can flag a crate cargo records but never compiles. Silencing that is
   sometimes right; silencing it with a sentence in a comment is not, because
   the sentence stops being true without saying so and the entry then protects
   nothing while looking like a decision.

   Today's single entry is rkyv (RUSTSEC-2026-0235), which reaches the
   lockfile through openraft, byte-unit and rust_decimal, sits behind an
   optional rust_decimal feature nothing enables, and is therefore never built.
   That is a checkable fact rather than a judgement, so `scripts/audit.sh`
   asserts it: the crate must be absent from the build graph of both manifests
   under `--all-features --target all`, and an ignore with no recorded crate is
   refused outright rather than trusted.

   The same script is also the one caller of both audits, because the ignore
   list would otherwise need a second copy inside `crates/cluster`:
   cargo-audit reads `.cargo/audit.toml` from the current directory and does
   not walk up. This estate has been bitten twice by a check living in two
   copies.
   *(gate: `scripts/audit.sh`; verified by pointing the recorded crate at one
   that IS built, which fails it, and by adding an ignore with no recorded
   reason, which also fails it)*

12. **A number this README states about the repository is checked against the
   repository.** A figure on a page has no owner and no clock: it is right the
   day it is written and the suite grows in commits that never open the README.
   Measured 2026-08-05, this repository was the worst case in the estate: the
   it-rat.com page for TokenFuse said **513 tests where the workspace runs 709**,
   and nobody knows for how long. It was not wrong when written; nothing was
   watching it. The badge counts every `test result:` line `cargo test --all`
   prints, which is the whole workspace and exactly what a contributor sees at
   the end of a run, so it is reproducible in one command. `crates/cluster` is
   deliberately excluded: it is its own workspace behind a feature with its own
   CI job, and folding it in would make the figure irreproducible with the plain
   command the badge implies.
   *(gate: `scripts/readme-numbers.sh`; verified by moving the badge one test,
   which fails it and names both figures)*

13. **A failure nobody else reports is made visible, once per distinct kind.**
   `CloudSink::ship` matched only the transport error `reqwest` returns when a
   request never gets an answer at all. `reqwest` answers `Ok(Response)` for
   every status it DOES get, so a 401, 403 or 500 from `/v1/ingest` went past
   that arm and left nothing behind: no log line, no counter, no metric. The
   gateway went on metering locally and answering every call exactly as before,
   so a gateway whose cloud key is wrong, rotated, or short of the role the
   endpoint requires was byte for byte a healthy one from both ends while the
   org's spend never reached the control plane at all. Two deployment repos had
   already written the symptom into comments (stack-k8s: "the money plane is
   deaf"; stack-single: "it looks exactly like a working deployment from the
   outside"), which is what a fault with no signal looks like. It was known well
   enough to be folklore in two other repositories because the code said
   nothing.

   A refusal now warns once per distinct status per sink, and the repeats drop
   to debug. Both halves are the rule and neither survives alone. Raising the
   level without the gate is invariant 7's failure in another costume: the same
   wrong key refuses EVERY batch for as long as the process runs, so a
   per-batch warning writes one configuration fault into the log several times
   a second and buries the enforcement decisions sharing it. Keeping the gate
   without the level leaves the fault exactly where it was.

   The boundary is deliberate and is the other half of the claim: a control
   plane that cannot be REACHED stays at debug, because that fault is usually
   transient, it clears without anybody editing configuration, and it was
   logged before. What earns a warning is not "something failed". It is
   "something failed, it will not clear itself, and no other part of the estate
   will ever mention it".

   Adopted `@yurii 2026-08-05` ("merge it and add the invariant"); the wording
   and the general form above are `@claude`.
   *(test: `a_refused_push_is_visible_to_the_operator`,
   `a_control_plane_that_refuses_every_batch_is_reported_once`,
   `a_second_distinct_status_is_reported_again`,
   `an_accepted_batch_is_never_reported` and
   `a_control_plane_that_cannot_be_reached_is_not_a_refusal` in
   `gateway::cloudsink`. Each was checked against a mutant rather than written
   green: restoring the old `send()` call fails four of the five, a
   warn-per-batch version fails the once-per-status one, a version that reports
   successes fails the accepted-batch one, and escalating transport errors
   fails the unreachable one)*

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
- **Invariant 8's siblings were audited on 2026-08-03, and two are still
  open.** Every incident kind and every event type was read against its
  producing code. `mcp_drift`, `dlp_block`, `identity_mismatch`,
  `sustained_loop`, `budget_threshold` and `quality_drift` say what they do.
  Two do not:

  - ~~**`spend_spike` is not a spike.**~~ Fixed 2026-08-03, invariant 10.
  - ~~**`spend_spike` can never reach a notifier.**~~ Still true, no longer
    debt: accepted as a BOUNDARY by the user on 2026-08-03 and documented for
    operators in heraldyx's README, where somebody choosing what to rely on
    will read it.

    It is org-scoped with no `agent_id`, and the exporter refuses to invent one
    (invariant 6, correctly), so a `high` incident is visible in the console and
    structurally invisible to any consumer of the event log. Measured on a live
    cluster 2026-08-02: `agent-event skipped: incident has no attributed
    agent_id, event=spend_spike, skipped_total=6`.

    What this forecloses is the tempting fix. Do not give the incident a
    fallback subject, a "various" agent, or the org id in the `agent_id` field
    to make it travel: each makes every downstream count wrong and puts a name
    on a subject line that did not do the thing. Mailing org-wide facts means
    the envelope grows a subject kind and every product moves together, which
    is a change to agent-passport, not to this crate.

  `fanout_explosion` was a third case of the same shape and was fixed the same
  day; see invariant 10.

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
