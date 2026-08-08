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

**All of it was brought current on 2026-08-05, through #170**: the header, the
Status-by-component table, the re-verified remaining-work list, and the test
counts, which had said 100 where the workspace runs 747. Three separate warnings
used to live in this paragraph, each naming a different stale half, and each was
overtaken while the previous one was being written.

So the warning that replaces them is about the shape, not the half: **that file
has no gate.** It is true on a date and starts drifting with the next merge, and
the only number in it anything holds is the test count, via
`scripts/stated-numbers.sh` (invariant 12). What it does carry now is dates and
checks: claims say when they were established and, where a command establishes
them, which command. Trust a claim in proportion to the date beside it, and when
you find one with no date, treat that as the oldest thing in the file rather
than the safest.

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
./scripts/stated-numbers.sh
./scripts/dto-boundary.sh
./scripts/replicated-shape.sh
./scripts/honest-claims.sh
./scripts/runnable-quickstart.sh
./scripts/constants.sh          # builds, unlike the five above; see invariant 14
./scripts/gates-have-teeth.sh   # needs a clean tree; see below
```

`gates-have-teeth.sh` is the odd one out and is listed last on purpose. The
five gates above it all parse text with regular expressions, and that kind of
parser does not break loudly: it stops matching and reports success. Three of
them broke exactly that way while being written, each time caught only
because a mutant was supposed to fail and did not. So the mutants stopped being
prose in commit messages and became a harness: it breaks each gate on purpose,
requires the failure, and for the diagnosis cases requires the failure to SAY
the right thing, since "it failed" and "it failed for this reason" are different
claims. It also asserts one gate must NOT fire, because an overeager check gets
deleted as fast as a toothless one.

It mutates tracked files and restores them with `git checkout`, so it refuses to
start on a dirty tree and cannot tell your edits from its own. That makes it the
gate you run after committing rather than before, and CI is its real home.

The `--features cluster` line is the raft-backed ledger test; copy that exact
invocation, it is what `.github/workflows/ci.yml` runs. It is named here rather
than pointed at as "the last one", which is what this sentence used to say: the
list has grown twice since, and a positional reference into a list that grows is
wrong the moment it does.

CI also runs separate jobs for the Python SDK (`sdk/python`), the JS SDK
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
   *(gate: `scripts/core-deps.sh`; verified against four mutants: a dependency
   added, a dependency removed, and two that establish nothing rather than
   finding something, `cargo` absent from PATH and a metadata format this script
   can no longer read. The last pair has its own exit path because an empty read
   used to fail as five lines claiming serde and sha2 had vanished from a
   manifest that still lists them, which sends the reader to the wrong file and
   gets a check relaxed by whoever is unblocking CI)*
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

   **Most of this is held by the compiler, as a consequence of invariant 1**,
   and that was measured on 2026-08-06 rather than assumed. Core cannot depend
   on `utoipa`, so no core type can implement `ToSchema`: naming one in
   `components(schemas(..))` fails to compile, so does using one as a field of a
   `ToSchema` DTO, and `impl ToSchema for` a core type inside `crates/cloud` is
   refused by the orphan rule. The debt note this replaces proposed grepping for
   exactly those three, which would have spent a CI run re-proving what `cargo
   check` already refuses.

   **Two holes are left, and they are why the script exists.**
   `#[schema(value_type = ..)]` describes a field as some other type and never
   asks the real one for a schema, so an annotated core type compiles cleanly
   onto the public surface. One field sits there deliberately,
   `store.rs::severity`, declared `String` because every variant of core's
   `Severity` serialises to one; the script fails if a variant ever carries
   data. The second road is `body = <name>` on a `#[utoipa::path]`, where the
   handler returns the core type and the named schema is a hand-written mirror
   of it. Nothing is a field of anything there, so a field scan cannot see it.

   **A mirror is the weak form, and all three this repository had are now
   gone.** `/v1/audit`, `ReplayResponse.audit` and `/v1/compliance` published
   `AuditEntrySchema`, `ControlEvidenceSchema` and `ComplianceReportSchema`
   while serialising the core types those merely described, so each pair agreed
   only while somebody kept it agreeing by hand. Proven rather than feared,
   twice on 2026-08-06: a field added to core's `AuditEntry` made `/v1/audit`
   answer a key its schema never declared, and a field added to core's
   `ControlEvidence` did the same to `/v1/compliance`.

   All three now serialise the DTO, so core may grow a field without touching
   this API, and a field added to a DTO fails to compile until `From` fills it.
   The compiler holds both directions, and the script's `MIRRORS` table is empty
   with a note saying to keep it that way. Two details there are load-bearing
   and easy to undo by accident: the count maps are `BTreeMap`, not `HashMap`,
   because core produced sorted keys and the body should not start varying; and
   `Enforcement` is converted by an exhaustive `match`, not by formatting, so a
   variant added to core fails to compile here and somebody decides what this
   API calls it.
   *(gate: `scripts/dto-boundary.sh`; verified against three mutants, each of
   which fails it: a new core type on a DTO through `value_type`, core's
   `Severity` gaining a data-carrying variant, and an exception that no longer
   matches anything. The two retired mirrors are held by tests instead:
   `the_audit_response_carries_exactly_the_fields_the_schema_declares` and
   `the_compliance_response_carries_exactly_the_fields_the_schema_declares`,
   each of which fails against its old handler with a field added to core and
   passes against the converted one)*
4. **"Honesty is a feature."** Never over-claim compliance coverage or
   hard-guarantee semantics. Budgets are estimate-then-settle, and the system
   fails open by default - docs and READMEs must state these limitations
   plainly, not bury them.

   **Two thirds of this has a mechanical form, found by testing the premise
   rather than repeating that it is judgment.** First, every control in
   `CATALOG` carries a grade, and that grade is a claim made to whoever reads
   `/v1/compliance` or runs `tokenfuse compliance`. Moving one up is
   over-claiming coverage in the most literal sense this invariant has, it is a
   one-word edit, and nothing else here would notice. The grades are recorded in
   the script; an upgrade, a downgrade and a new control each fail differently,
   because they need different answers. Second, a limitation the docs must state
   plainly can be checked for presence: a sentence that stops being said is how
   "not buried" fails, and a missing sentence is exactly as checkable as a
   present one.

   **The remaining third stays judgment, and this was established rather than
   assumed.** Whether a NEW sentence over-claims cannot be checked by a word
   list, and the obvious list was tried against this repository on 2026-08-06:
   `guarantee` appears five times in README.md, and the uses it would flag
   hardest are the honest ones, "not a hard real-time guarantee" and "not a
   guarantee that not one extra cent can ever be spent". The honest sentence and
   the dishonest one share a vocabulary and differ in polarity, which is the part
   a regex cannot read. A gate that fires on the sentences an invariant exists to
   protect gets deleted, correctly.
   *(gate: `scripts/honest-claims.sh`; verified against six mutants: a control
   upgraded, a control downgraded, a control added, each of the two required
   disclosures removed from the README, and a catalog whose shape this script can
   no longer parse, which fails as unverified rather than passing)*
5. **Don't thread new dimensions through `LedgerBackend`/raft casually.** The
   ledger's replicated state (`crates/gateway/src/ledger_backend.rs`,
   `crates/cluster`) is the thing that has to stay linearizable across nodes;
   a new field there is a raft/schema-identity decision, not a routine edit.

   **Why a comment was not enough, which is what this had until 2026-08-06.**
   Adding a field to `RunState` compiles, and every test in the workspace
   passes, because every test builds a fresh state machine. A deployed node does
   not: `LedgerState` goes to redb as `serde_json` and nothing in
   `crates/cluster/src/types.rs` carries `#[serde(default)]`, so a node with a
   durable store cannot read back what it wrote under the old shape. It restarts
   having lost every budget and every reservation, silently, and the first
   symptom is a breaker that stopped breaking. That is not a hypothesis about
   this estate's habits: `build_durable` sat behind a test-only caller for
   months while the shipped binary had no durable mode at all (#162).

   The gate does not refuse the change, and saying so matters, because a check
   that reads as a prohibition gets worked around. It refuses the change being
   made SILENTLY: the migration, the defaults and the snapshot compatibility get
   chosen, the recorded shape is updated in the same commit, and that commit
   says what happens to a node holding the old shape on disk. The warning also
   sits at the top of `ledger_backend.rs`, where the edit happens, rather than
   only in this file.

   The trait's own methods are deliberately NOT pinned: a method added there
   fails to compile until both backends implement it, so the compiler already
   holds that half.
   *(gate: `scripts/replicated-shape.sh`, pinning `Request`'s variants,
   `Response`, `RunState` and `LedgerState`; verified against five mutants, each
   of which fails it: a field added to `RunState`, a field added to
   `Request::Reserve`, a new `Request` variant, a field removed from `Response`,
   and a type renamed, which fails as "cannot be checked" rather than passing
   quietly)*
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

12. **A number this repository states about itself is checked against itself,
   in every file that states it.** A figure on a page has no owner and no clock:
   it is right the day it is written and the suite grows in commits that never
   open the page.
   Measured 2026-08-05, this repository was the worst case in the estate: the
   it-rat.com page for TokenFuse said **513 tests where the workspace runs 709**,
   and nobody knows for how long. It was not wrong when written; nothing was
   watching it. The badge counts every `test result:` line `cargo test --all`
   prints, which is the whole workspace and exactly what a contributor sees at
   the end of a run, so it is reproducible in one command. `crates/cluster` is
   deliberately excluded: it is its own workspace behind a feature with its own
   CI job, and folding it in would make the figure irreproducible with the plain
   command the badge implies.

   **The "in every file" half was added 2026-08-05, and it is the half this
   estate had to learn twice.** Gating the badge alone left the same figure
   written in prose one file over: PROGRESS.md said **100 passing (core: 60,
   gateway: 40)** while the workspace ran 747, a sevenfold error, and it was
   found by somebody reading rather than by the gate that existed precisely for
   this. A number is not gated because it is prominent; it is gated because it
   is stated. PROGRESS.md also breaks the total down per crate, and the check on
   that is deliberately weaker: the parts must SUM to the measured total, which
   catches a breakdown drifting out of step and not two compensating errors. The
   limit is written in the script rather than left to be discovered.

   The PROGRESS.md half reads only the **Test status** section, not the whole
   file, and that is not tidiness. The rest of that file is prose which
   legitimately quotes older counts while explaining how they drifted, and
   reading everything made this gate fail on a paragraph recording its own
   history lesson. A check that a true sentence can break is a check somebody
   eventually deletes.
   *(gate: `scripts/stated-numbers.sh`, which covers README.md and PROGRESS.md;
   verified against five mutants: the badge off by one, the PROGRESS total off
   by one, a breakdown that no longer sums, and either figure reworded out of
   the file, each of which fails it and names both figures. The fifth pins the
   scoping in the other direction: an old count quoted in prose outside the Test
   status section must NOT fail it)*

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

14. **A value another repository has to agree with is published, not retyped.**
   The estate consumes this repository's wire vocabulary by value: somebody
   reads the Rust and types the strings into their own language. Reported
   2026-08-06, verdryx's blocked-decision mirror carried seven wire strings
   while `BreakerReason` had carried nine since 2026-07-23, so for eleven days
   avoided estimates were counted as real spend. It carries two more
   hand-copies (the price book, the Parquet column names), and genaryx copies
   verdryx's SQLite schema into a Rust doc comment. This repository cannot check
   any of those and does not try to; what it can stop being is the reason the
   next copy is wrong.

   `contracts/tokenfuse-constants.json` is the published form: Breaker reasons
   with statuses, the blocked-decision set, agent-event types with their fixed
   severities, both Parquet schemas, and the default price book. **It is
   generated, and that is the load-bearing half.** A hand-maintained constants
   file is the original defect with an extra step, a file that can disagree with
   the constants it names, which is why the gate compares the committed copy
   against freshly generated bytes rather than reading the file's word for it.

   **This gate BUILDS, unlike the four text gates above it, and the difference
   is deliberate.** No regular expression can ask `EventType::severity` what it
   returns, and CLAUDE.md already records what regex gates cost: three of four
   stopped matching while being written and reported success. The price is a
   recompile in CI, paid by the one check whose entire job is that a published
   value is what the code says it is.

   Two smaller things here are load-bearing and easy to undo by accident. The
   artifact path carries NO version, because a versioned filename is how a
   consumer keeps reading the old file forever after a bump; `schema_version`
   inside it is the signal instead. And `PriceBook::entries` sorts, because the
   book is a `HashMap` and an unsorted projection makes the committed file
   disagree with itself run to run, which turns the gate into noise.
   *(gate: `scripts/constants.sh`, plus eight tests in `gateway::constants`,
   every one of which was checked against its own mutant on 2026-08-06. Two of
   them failed that check first and had to be rewritten: they took their
   expected COUNT from the same array the artifact is generated from, so
   deleting a variant from it passed. The expectation is now written out
   independently. A test whose expectation comes from the thing under test
   cannot fail, and it looks exactly like a test that has nothing to catch)*

15. **Under strict, identity comes from the credential and never from a
   header.** `crates/gateway/src/clientkeys.rs` exists because anything a
   caller can choose, a caller can change: a cap keyed on `x-fuse-agent-id` is
   bypassed by sending a different one, and somebody else's can be burned on
   purpose. `IdentityMap::resolve` then ran the binding check only for a
   `key_id` with an explicit `keys[]` entry, and every OTHER authenticated
   caller fell through to prefix matching on exactly that header.

   So a real credential the map did not bind had two ways past a unit's
   monthly cap, and `TOKENFUSE_IDENTITY_STRICT` closed neither, because it
   governs the binding check and this path never reached one. An agent id
   matching no prefix resolved to no unit, which makes `unit_reservation`
   `None` in the proxy and skips the cap entirely. One matching a different
   unit's prefix charged that unit. Both were silent: startup warned about the
   opposite mismatch (a map `key_id` with no client key) and not this one, and
   the docs described the prefixes as the fallback "for unkeyed traffic",
   which was true of the case they had in mind and not of this one.

   Strict now refuses both, and refusing the SECOND is the decision worth
   recording. Attributing it would have been defensible (a unit did resolve),
   and it is wrong for this invariant's reason: the only thing connecting that
   caller to that unit is a string it wrote. A credential the map DOES bind is
   unaffected in both directions, because the prefixes are never consulted for
   it.

   Two boundaries keep this from breaking deployments, and both are
   load-bearing. `off`, the default, is byte-identical: the resolved unit is
   unchanged in every case and `off` never consults the mismatch, so the only
   mode that behaves differently is one an operator asked for. And a map that
   is not configured reports nothing, because `main.rs` parses
   `TOKENFUSE_IDENTITY_STRICT` and `TOKENFUSE_IDENTITY_MAP` independently:
   strict without a map is a live configuration, it has always been a no-op,
   and without that guard enforce would answer 403 to every authenticated
   call on upgrade.
   *(test: `the_monthly_cap_cannot_be_skipped_by_choosing_an_agent_id`,
   `strict_refuses_an_authenticated_key_the_map_does_not_bind`,
   `strict_refuses_an_unbound_key_that_points_at_another_units_prefix`,
   `strict_still_allows_a_bound_key_and_bills_its_own_unit`,
   `an_unmapped_key_is_unchanged_when_strict_is_off` and
   `warn_reports_an_unbound_key_without_refusing_it` in `gateway::proxy`, plus
   four in `gateway::identitymap` including
   `a_bound_key_is_never_diverted_by_a_prefix_for_another_unit` and the
   disabled-map guard inside
   `the_default_map_is_disabled_and_resolves_nothing`. Each of the six failing
   ones was run against the unfixed code first. Two OLD tests asserted the
   defect as expected behaviour and were changed, which is recorded in their
   bodies rather than left to be noticed in a diff)*

16. **A command this repository tells somebody to run can run.** The gateway
   gained a precondition on 2026-08-05 (no `TOKENFUSE_UPSTREAM` and no
   `TOKENFUSE_ALLOW_STUB` means it exits 2 rather than metering invented usage
   as spend, #141). Nothing that advertised the old behaviour moved with it:
   the README's headline "try it in one command" and its own get-started step,
   the Dockerfile comment, the crates.io crate's doc, the Show HN draft, and
   `cloud/docker-compose.yml`, whose gateway service would have crash-looped on
   the next image build. `grep -r ALLOW_STUB docs/` returned nothing at all.

   The general form is the reason this is an invariant rather than a fix: **code
   acquires a precondition in a commit that never opens a document.** It is the
   same shape as invariant 12's stated numbers, and it fails the same way, on
   somebody else's machine, at the worst possible moment, which for a quickstart
   is the first thirty seconds a stranger spends on this project.

   What the gate holds is exactly one precondition, the one the binary enforces
   at startup. It deliberately ignores subcommand invocations (`… -- constants`,
   `tokenfuse top`), which share the binary and need no provider, because a gate
   that fires on a correct command gets deleted by whoever is unblocking CI.
   *(gate: `scripts/runnable-quickstart.sh`; verified against four mutants: the
   flag removed from the README quickstart, the flag removed from the compose
   gateway service, a subcommand invocation which must NOT fail it, and the
   compose image renamed, which fails as "measured nothing" rather than passing
   because it found nothing to check)*

17. **A guarantee that is off until somebody sets a variable is not a
   guarantee.** Established on a live cloud range 2026-08-04, where three
   separately defensible defaults combined into a deployment that could pass
   every check it had and be governed on paper: `TOKENFUSE_DLP` unset meant
   `off`, so the scanner this product advertises scanned nothing; a call with no
   `x-fuse-run-id` reached the provider and was recorded in no ledger, trace or
   event stream; and the check that would have caught either read environment
   variables (invariant 19).

   Both defaults now point the other way, and BOTH halves of that are the rule.
   A default that cannot be turned off is a prohibition, and an operator with a
   real reason (a prompt corpus full of things that look like keys, a gateway in
   front of a client that cannot add a header yet) needs one variable, not a
   fork: `TOKENFUSE_DLP=off` and `TOKENFUSE_REQUIRE_RUN_ID=0`. The upgrade
   consequence is a `403` and a `400` on paths that used to succeed, which is
   stated in the README rather than discovered.

   The boundary is deliberate: `TOKENFUSE_DLP_PII` did NOT move. Its false
   positives are ordinary prose rather than credentials, and the range
   established nothing about it. Turning something on by default is a claim that
   its true positives outweigh its false ones, and that claim needs evidence per
   scanner, not per repository.
   *(test: `secret_scanning_is_on_by_default`,
   `a_call_with_no_run_id_is_refused_by_default` and
   `metering_is_required_by_default` in `gateway::proxy`, each run against the
   unfixed code first; plus six in `gateway::defaults` pinning the vocabulary,
   including `a_misspelt_dlp_value_never_reads_as_disabled` and
   `pii_masks_stay_off_when_nothing_is_configured`. One OLD test asserted the
   pass-through default as correct and was flipped, with the reason in its body)*

18. **A detector that scales as computation does not automatically scale as an
   alert.** Measured 2026-08-04: 999 agents produced 3000 alerts, every agent
   tripping all three detectors that had anything to say about it, with trip
   counts inside the largest running from 1 to 73, median 2, and the planted
   runaway at 45. Every one of those alerts carried the same severity. The
   signal was in the data and printed in the summary line; the field an operator
   SORTS by was identical on all thousand rows.

   So severity comes from the magnitude a detector measured, not from the name
   of the detector. Three details are load-bearing. It escalates on a MULTIPLE
   of the detector's own threshold (four, then sixteen), not on a second fixed
   threshold, which would measure a size again one level up and put a busy agent
   permanently at critical: this is invariant 10's lesson applied to severity
   rather than to triggers. It never falls, because two of these detectors count
   inside a window, and an incident that downgraded itself would move down a
   triage list while the run that earned it is still open. And the base severity
   is the floor, so an incident at the line reads exactly as it did before.
   *(test: `a_run_blocked_far_past_the_threshold_outranks_one_that_just_crossed`,
   `a_loop_that_keeps_going_climbs_the_scale`,
   `severity_records_the_worst_it_reached_and_never_walks_back`,
   `the_ladder_is_a_multiple_of_the_threshold_not_a_second_threshold` and the
   overeager guard `a_loop_that_only_just_crossed_keeps_its_base_severity`, in
   `cloud::store`. Verified against four mutants: severity ignoring the
   magnitude, escalating on the threshold itself (which fails the guard AND four
   older tests), and a later trip walking the severity back down. The last one
   passed the first version of its test, because the magnitude had fallen so far
   that the detector no longer fired at all, so the test now ages the window out
   and re-trips at a magnitude that is genuinely lower)*

19. **A check that reads configuration proves nothing about behaviour.** The
   deployment check for "the policy plane is on the data path" read environment
   variables, so a plane that had never returned a verdict passed it. The range
   walked into it: a missing identity header made a healthy PDP answer nothing,
   the gateway reported `wardryx unreachable`, and an operator would have gone
   to repair a machine that was fine.

   `GET /v1/policy-plane` reports what the PDP ANSWERED. Two parts of that are
   the invariant rather than the implementation. A failmode fallback is counted
   as a fallback and never as a verdict, because fail-open turns an outage into
   an `allow`, which is the exact state the check exists to distinguish. And the
   evidence expires: the facts are scoped to a window, so a plane that answered
   once last March does not report as live.

   `allow_and_deny_seen` is deliberately hard to satisfy, and that is the point.
   It stays false until a real deny comes back, which normally means a
   deployment drill that sends one call the policy must refuse. This is the
   invariant trailryx already carries in another form: **a check that cannot
   fail reports zero forever**, and it looks exactly like a check with nothing
   to report.
   *(test: six in `gateway::policyplane` including
   `a_failmode_fallback_is_never_evidence_of_a_verdict`,
   `allows_alone_do_not_prove_the_plane_can_refuse` and
   `a_zero_timestamp_is_never_read_as_recent`; three in `tests/policy_plane.rs`
   for the endpoint; and two in `tests/wardryx.rs` for the wiring underneath,
   which no unit test can see: `a_verdict_off_the_wire_is_recorded_as_one` and
   `an_unreachable_pdp_never_counts_as_an_allow`. Every one was checked against
   its own mutant)*

20. **A door with nothing behind it does not open onto the network.** The MCP
   credential-broker resolves `{{secret:NAME}}` handles against the whole
   vault and forwards to any configured upstream, so anything that reaches
   its port can spend every credential in it. Until 2026-08-05 the only guard
   was the loopback default; #169 then added optional client credentials and
   a startup warning on a wider bind, but deliberately stopped short of
   refusing to start, because that breaks a running deployment at boot and is
   a decision, not a fix (docs/12's "still open" note).

   That decision is now made. A non-loopback bind with no `TOKENFUSE_MCP_KEYS`
   configured refuses to start (`mcpbroker::refuse_open_bind`), naming the
   address, the missing configuration, and the opt-out in the same error: an
   operator who has deliberately decided to run the broker open sets
   `TOKENFUSE_MCP_ALLOW_OPEN_BIND=1`, parsed exactly like `TOKENFUSE_ALLOW_STUB`
   (only `1` or `true` count, not any other non-empty string). Two cases are
   unaffected either way, on purpose: a wide bind WITH credentials configured,
   which is a posture this repository already lets an operator choose and
   keeps only warning (`bind_exposure_warning`, unchanged); and the loopback
   default itself, which must not get harder for the common local case.

   Loopback for the refusal is asked of the standard library
   (`IpAddr::is_loopback`), not matched as a string. `bind_exposure_warning`
   deliberately keeps a narrower, Cloud-matching string set, because there a
   false warning on `127.0.0.2` costs one extra line an operator reads past;
   here the same gap would either refuse to start a deployment that was never
   exposed, or start one that is, and both cost more than a warning does.
   *(test: `an_open_bind_with_no_keys_refuses_to_start`,
   `a_loopback_bind_is_never_refused`,
   `configured_auth_avoids_the_refusal_leaving_only_the_warning`,
   `the_operator_can_opt_out_of_the_refusal`,
   `opting_out_of_the_refusal_does_not_silence_the_warning` and
   `loopback_is_the_standard_librarys_answer_not_a_string_match`, all in
   `gateway::mcpbroker`. The first five were run against the unfixed code
   first: `refuse_open_bind` did not exist, so the suite failed to compile)*

21. **Radar reports what it sees; it is not where the sensor grows.** The
   estate has two implementations of one eBPF sensor: `crates/radar` here, and
   idryx's `internal/ebpfcapture`, a Go port of this one. Every capability the
   sensor gains from now on is built in idryx, and radar's job narrows to
   emitting what it observes into the shared agent-event stream instead of
   printing a table to a terminal.
   *(@yurii 2026-08-08, "Idryx основний, radar зводимо до відправника подій")*

   **Three defects found on 2026-08-08 are why the direction is that way and
   not the other** (@claude, read off both trees). `radar-ebpf` reads the
   syscall argument at a hard-coded `ctx.read_at::<u64>(24)`, commented "offset
   24 on x86_64", so it is not CO-RE and reads the wrong bytes anywhere else;
   the port uses the BTF-typed `trace_event_raw_sys_enter` and is portable.
   `main.rs`'s loopback filter admits ports 11434 and 8000 but not 8001, while
   its own `is_llm` lists 8001 as a vLLM port, so that branch is unreachable
   and a local vLLM on 8001 is never reported. And it drops its own traffic by
   comparing `comm`, which any process can rename with `prctl`; the port
   compares PID.

   The structural half matters as much: this file holds twenty invariants and
   none of them is about radar, the crate has no tests at all, and its CI job
   runs `cargo build` and stops. The most fragile code in the repository had
   the least holding it.

   **This does not deprecate radar and does not forbid fixing it.** The three
   defects above are worth repairing precisely because it ships and runs. The
   line is between correcting what exists and adding observation that does not.
   *(not enforced yet, deliberately. It becomes checkable the moment radar
   emits agent-event NDJSON, when a gate can require the shared envelope and
   refuse a return to the terminal table. Until then this is prose, which is
   the weakest form, and the failure mode is quiet: a capability added here
   compiles, passes CI, and reads as progress)*

## Decisions that have no gate yet

This list is debt, and it is here to stay visible rather than to be tidy.

**Held by this file alone: invariants 4 and 21.** Invariant 6 is only partly
held, and invariant 2 is held by one golden test that must never be deleted.

- **Invariant 21** has a known end date as prose: it stops being judgement the
  moment radar emits the shared envelope, because a shape is checkable and a
  terminal table is distinguishable from NDJSON by any script. It is recorded
  here rather than left implicit, because a rule about WHERE work happens
  breaks silently. Nothing goes red when the next sensor capability lands in
  this crate instead of idryx: it compiles, its job stays green, and the
  duplicate work is only visible to somebody who reads both repositories.

- **Invariant 3 came off this list on 2026-08-06**, and how it came off is worth
  keeping. The note here said it was "mechanically checkable: fail if any
  `utoipa` derive names a `tokenfuse-core` type. That is the exact regression
  mode." It was not the exact regression mode. Writing the mutants first showed
  the compiler already refuses all three shapes that note described, and that
  the one shape it does NOT refuse, `#[schema(value_type = ..)]`, was already
  in use on two fields and unmentioned. A gate built from the note would have
  passed forever while the real hole stayed open. The lesson generalises past
  this entry: **a debt note is a guess about a regression, and the guess is
  worth testing before it is worth implementing.**
- **Invariant 5 came off this list on 2026-08-06, and the note here was wrong
  in the same way invariant 3's was.** It said the rule "cannot be scripted" and
  proposed a comment. The replicated schema is four types in one file, so it
  pins exactly as mechanically as invariant 1's dependency list does, and the
  comment went in beside the gate rather than instead of it. Twice now, a debt
  note has underestimated what was checkable; both times the cost of finding out
  was half an hour of reading the code the note described.
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
