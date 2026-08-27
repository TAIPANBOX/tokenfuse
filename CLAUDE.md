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
5. Commit with Conventional Commits, message ending in a `Co-Authored-By:`
   trailer naming **the model that actually did the work**:
   `Co-Authored-By: Claude <model> <noreply@anthropic.com>`, for example
   `Claude Opus 5` or `Claude Fable 5`.

   This line named `Claude Fable 5` outright until 2026-08-11, and by then it
   was wrong twice over. Measured on that date, the last forty commits on
   `main` carry 14 `Opus 5` trailers and 11 `Fable 5`: the repository had
   already stopped following it, correctly, because a trailer exists to record
   authorship and a fixed string records whatever was true when somebody typed
   it. A session that obeyed the line signed Fable 5 for work Opus 5 did, which
   is the one thing this trailer must not do.

   Do not rewrite published history to correct a trailer. Fix the next one.
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
./scripts/features-are-bound.sh
./scripts/runnable-quickstart.sh
./scripts/pinned-installs.sh
./scripts/audit.sh              # invariant 11; needs cargo-audit
./scripts/constants.sh          # builds, unlike the text gates; see invariant 14
./scripts/gates-have-teeth.sh   # needs a clean tree; see below
```

`audit.sh` was missing from this list until 2026-08-09 while CI ran it, which
is this repository's own recurring fault: a list that covers part of something
inherits trust for the whole. Somebody following these instructions ran seven
gates and believed they had run all of them.

`gates-have-teeth.sh` is the odd one out and is listed last on purpose. The
text gates above it all parse with regular expressions, and that kind of parser
does not break loudly: it stops matching and reports success. Three of them
broke exactly that way while being written, each time caught only because a
mutant was supposed to fail and did not. So the mutants stopped being prose in
commit messages and became a harness: it breaks each gate on purpose, requires
the failure, and for the diagnosis cases requires the failure to SAY the right
thing, since "it failed" and "it failed for this reason" are different claims.
Eight of its cases assert a gate must NOT fire, because an overeager check gets
deleted as fast as a toothless one.

**It asserts a third property, on ten of its 43 cases: a gate whose subject
has been taken away must say it measured nothing rather than report OK.** A
check that cannot tell "did not fail" from "did not run" is the most expensive
mistake this estate makes in its tooling, and it is made in tooling rather than
in product code because tooling is where a silent pass looks like a result.

Both numbers in that sentence were stale before they were corrected on
2026-08-25: it said seven of 22 while the harness ran 30, because the count was
written once and the cases kept arriving. It moved again the next day with the
hook-environment case, and again on 2026-08-26 with the four cases holding the
relevant-not-enforced framework list (invariant 33), one of which takes that
list away. It had drifted again by 2026-08-27, reading 39 and "two gates must
NOT fire" while the harness ran 43 with eight of those. That is the point rather
than an annoyance: the number moves whenever somebody looks, and looking is the
only thing that moves it. @measured 2026-08-27, all three figures from one run:
`./scripts/gates-have-teeth.sh | grep -c '^ok '` for the total,
`| grep -c '(pass)'` for the must-not-fire cases, and reading each case's label
for the ten that take a subject away. That is invariant 12's own failure
inside the file that records invariant 12, and it is left written down rather
than quietly fixed, because the fix that would actually hold is a gate and
there is not one. Nothing checks this sentence. Counting cases is easy
(`./scripts/gates-have-teeth.sh | grep -c '^ok '`); deciding which of them
assert the taken-away property is a reading of each case's intent, and a
regular expression over the labels would be a fourth thing to keep true.
`@claude` 2026-08-25.

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
   no longer parse, which fails as unverified rather than passing. The same
   script grew a third half on 2026-08-26, recording which of the two framework
   lists each framework sits in, with five mutants of its own; that is invariant
   33 and the reason it lives here rather than in a twelfth script is that it is
   the same invariant over the same file)*
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

   **Carrying one is not the same as sending the header, and the difference was
   costing records.** Measured 2026-08-26 on a running gateway: a request whose
   DPoP-bound, issuer-signed chain named `agent://acme/triage` raised two
   `taint_raised` events in enforce mode and both were dropped, because
   `x-fuse-agent-id` was absent. An injection was detected on the request with
   the strongest identity this gateway ever sees, and the record was empty.

   So a PROVEN chain's agent leaf now fills the record's subject when the header
   is absent. That is not fabrication: the identity was in the request, inside a
   credential this gateway verified. A CLAIMED chain never does, because a
   caller who can write the header can write the chain, and reading one because
   the other is missing is the same free-form weakness with extra steps. Nor
   does a leaf that is not an `agent://` URI: a token with no `act` names a
   person, and a person is not an agent id.

   **Records only.** `agent_id` still governs the identity map, the unit a call
   is billed to, the strict-mode binding check, and what the PDP is told. None
   of those read the derived value, and moving them is a separate decision with
   money and enforcement attached.
   *(rule: `chainproof::proven_actor`, four unit tests including
   `a_claimed_chain_names_nobody`, which is the one that goes red if the
   fallback is ever widened. Handler tests
   `a_proven_chain_files_the_record_when_no_header_names_an_agent`, verified red
   against the header-only rule with verbatim "the injection was detected and
   nothing reached the record", and `a_claimed_chain_does_not_file_the_record`)*

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

   **The same script refuses to audit against a dirty advisory database, and
   that is a different failure worth naming.** `cargo audit` fetches by pulling
   into `~/.cargo/advisory-db`, and `git pull` never removes an untracked file.
   It then reads the DIRECTORY rather than git `HEAD`, so a stale file that once
   landed there is loaded as an advisory forever while every fetch reports
   success. On 2026-08-09 an upstream rename left the old path behind locally,
   cargo-audit saw one id twice and refused to load the whole database, and the
   condition was written up as an upstream outage for hours. It was not:
   `git grep -l <id> HEAD` returned one path throughout, and `git clean -fd`
   fixed it in one command. `--ignore` does not help, because the failure is at
   database LOAD, before any ignore is evaluated.
   *(gate: `scripts/audit.sh` refuses and NAMES the untracked files before
   cargo-audit runs, because cargo-audit's own error names an advisory id and
   sends a reader to the wrong repository. Verified by planting the exact file
   that caused it.)*

   The same script is also the one caller of both audits, because the ignore
   list would otherwise need a second copy inside `crates/cluster`:
   cargo-audit reads `.cargo/audit.toml` from the current directory and does
   not walk up. This estate has been bitten twice by a check living in two
   copies.
   *(gate: `scripts/audit.sh`; verified by pointing the recorded crate at one
   that IS built, which fails it, and by adding an ignore with no recorded
   reason, which also fails it. Both of those were done by hand once, in the
   session that wrote the script, and nothing re-ran them for three days; they
   are now cases in `gates-have-teeth.sh`, together with a third the sentence
   above never claimed, the ignore list deleted entirely, which must fail as a
   missing single source rather than pass with nothing to check. None of the
   three reaches `cargo audit`, so they cost no advisory-db fetch.)*

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

22. **A tool CI installs by name is installed at a named version.** An unpinned
   install is a dependency with no lockfile: it resolves to whatever is newest
   at the moment the job runs, so the commit that passes today and the commit
   that fails tomorrow are the same commit.

   Measured rather than feared. The radar job ran `cargo install bpf-linker`
   with no version and no `--locked`. bpf-linker 0.11.0 was published on
   2026-08-12, the day after that job last went green, and it links system LLVM
   dynamically, which `System deps` does not install. main went red on
   2026-08-20 with nothing in this repository having changed, and #203, a
   two-file markdown change opened afterwards, arrived wearing the red check.

   That last part is the reason this is an invariant and not a fix. The cost of
   an unpinned install is not the build minutes, it is a failure attributed to
   the wrong change, which is the same class as invariant 12's stated numbers
   and invariant 16's quickstart: the repository was correct, and something
   outside a commit made it look otherwise.

   `--locked` is required alongside the version for `cargo install`, because a
   version alone still lets the crate's own dependencies float, which is this
   same failure one level down.

   **apt is in scope, and this reverses what stood here for one afternoon.**
   `@yurii 2026-08-20`: «запінь apt теж». The argument recorded here against it
   was that pinning apt on a hosted runner pins to versions that exist only in
   the image the runner happens to boot, so the pin breaks on the next image
   roll and the gate demanding it gets deleted by whoever is unblocking CI.

   That argument was right about `pkg=version` and wrong about apt, because it
   assumed a version number is the only way to pin. `@claude`: the Ubuntu
   snapshot service serves the archive as it stood at a timestamp, for any date
   after 1 March 2023, and apt in 24.04 speaks it natively. **A snapshot does
   not break when the image rolls, because it does not describe the image, it
   describes the archive.** One `APT_SNAPSHOT` per workflow file, bumped
   deliberately in a commit that says what moved, the way a lockfile is bumped.

   Two things had to move with it. The runner's own sources point at the azure
   mirror, which does not serve snapshots and has a long public record of
   missing content, so each apt step repoints them at `archive.ubuntu.com`
   first. And **the runner image is pinned**, `ubuntu-24.04` rather than
   `ubuntu-latest`, because a snapshot pin on a rolling image is half a pin:
   the label is 24.04 today, 26.04 is in public preview, and GitHub migrates it
   over one to two months during which a workflow may see the OS change
   underneath. `runs-on` is therefore checked by the same gate.

   `@measured` radar job on PR #206, 2026-08-20: `apt-get` does accept
   `--snapshot`, and the snapshot service answers once the runner's sources are
   repointed off the azure mirror. That was the one thing holding the approach
   up and it is not checkable on a developer's macOS, so it was written here as
   an open residual until the run existed. The measurement is of that run and
   that image: an apt-get that stopped taking the flag would be a fix to the
   verb, not to the approach.
   *(gate: `scripts/pinned-installs.sh`; verified against eight mutants: a
   `cargo install` losing its version, one losing `--locked`, a `pip install`
   losing its `==`, an `apt-get install` losing its snapshot, a `runs-on` back
   to a `-latest` label, and two that must NOT fire, `rustup toolchain install`
   and the comment above the radar step which quotes the old unpinned command
   verbatim. The eighth takes the subject away: with no install command left it
   must say it measured nothing rather than report OK)*

23. **A door with something behind it still has to check who is knocking.**
   Invariant 20 closed who may reach the broker's port; this closes a
   different question the door does not answer: once inside, which secret a
   caller may pull. `SecretVault::get` took only a name, so `{{secret:NAME}}`
   resolved against the whole vault for any authenticated caller, as any
   agent, calling any tool. `mcpbroker::process` had both `agent_id` (already
   read two lines earlier for the Wardryx gate) and the tool name in hand at
   the injection call site and used neither. Verified 2026-08-25.

   Resolution is now identity-aware: `SecretVault::resolve(name, agent_id,
   tool)` is the read path `inject_secrets` goes through, and a secret may
   carry an optional `ScopeRule` naming allowed agent ids and/or allowed tool
   names, `TOKENFUSE_MCP_SECRET_SCOPES`, configured SEPARATELY from
   `TOKENFUSE_MCP_SECRETS` so an existing deployment that never sets it is
   byte-for-byte unchanged: a secret named in no rule is unscoped, resolvable
   by any agent, any tool, exactly as before this existed. The handle syntax,
   `{{secret:NAME}}`, did not change.

   Unlike `ClientKeys::from_spec`, which skips one malformed entry and keeps
   the rest of a spec usable, ONE malformed `TOKENFUSE_MCP_SECRET_SCOPES`
   entry refuses the whole spec and the process does not start. The two
   failures are not the same shape: a dropped key entry only makes one fewer
   credential valid; a dropped scope entry would silently unscope the secret
   it was meant to protect, which is the exact failure this invariant closes.

   A refused resolution refuses the WHOLE `tools/call` (JSON-RPC `-32008`),
   the same posture as the Wardryx deny beside it in `process`, rather than
   forwarding the call with the handle left as an unsubstituted placeholder.
   Leaving the placeholder and forwarding anyway would still reach the
   upstream MCP server and could still trigger whatever side effect that tool
   has, with a syntactically broken credential standing in for a real one; an
   agent with no authorization for a secret has no business causing that tool
   to run at all. Never logs the secret value, only its name, the agent, and
   the tool.

   Because unscoped means anyone, and that must never be silent: the broker
   logs at startup how many configured secrets carry no rule
   (`mcpbroker::unscoped_secrets_warning`), and an opt-in
   `TOKENFUSE_MCP_REQUIRE_SECRET_SCOPES=1` (parsed like
   `TOKENFUSE_MCP_ALLOW_OPEN_BIND`) turns that into a refusal to start
   (`mcpbroker::refuse_unscoped_secrets`), naming the unscoped secrets and how
   to fix it. Off by default, so nothing changes until an operator asks.
   *(test: sixteen in `core::secretbroker` covering `ScopeRule::allows`,
   `SecretVault::resolve` and `parse_scope_spec`, including
   `an_unscoped_secret_resolves_for_any_agent_any_tool` (the back-compat
   guarantee), `an_agent_scoped_secret_refuses_an_absent_identity` (a call
   with no agent id is never a wildcard) and
   `a_malformed_entry_fails_the_whole_spec`; seven in `gateway::mcpbroker`
   covering `unscoped_secrets_warning` and `refuse_unscoped_secrets`,
   including `require_scopes_refuses_to_start_when_a_secret_is_unscoped` and
   `require_scopes_off_never_refuses_even_with_unscoped_secrets`; and six in
   `tests/mcp_broker.rs` over the live HTTP path, asserting on what actually
   reached the upstream the way
   `a_tool_call_with_no_agent_id_is_refused_and_no_secret_is_resolved` already
   does:
   `a_scoped_secret_resolves_for_its_allowed_agent_and_reaches_the_upstream`,
   `a_scoped_secret_is_refused_for_a_different_agent_and_nothing_is_forwarded`,
   `a_tool_scoped_secret_resolves_for_its_allowed_tool`,
   `a_tool_scoped_secret_is_refused_for_a_different_tool`,
   `an_unscoped_secret_still_resolves_for_any_agent_unchanged` and
   `the_allowed_pairing_proves_the_scope_refusal_above_is_not_vacuous`, the
   negative control: the SAME rule, both halves, so the refusal cannot be
   mistaken for a broker that refuses every call. All twenty-nine were run
   against the unfixed code first: `ScopeRule`, `resolve` and
   `parse_scope_spec` did not exist, and `inject_secrets` took two arguments,
   not four, so the suite failed to compile)*

24. **A dependency THIS BOX needs, failing, is an event on the shared bus and
   not only a line in this process's log.** Every one of the fourteen event
   types that preceded this one was about the agent: it misbehaved, or this
   gateway refused it. Nothing was about the gateway's own supply failing, so
   the loudest thing that can happen to a fleet, its model provider going away,
   left the ledger, the trace, the Parquet export and the event bus all exactly
   as they were on a quiet afternoon. Measured 2026-08-25 against a gateway
   with `TOKENFUSE_UPSTREAM` pointed at a dead port: 502, no hang, no invented
   answer, reservation released at zero, and no record anywhere that it had
   happened.

   The policy plane is the same fault one plane over and the worse half of it.
   An unreachable PDP under the DEFAULT `failmode=open` synthesizes an `allow`,
   `Verdicts::unreachable_fallbacks` counts it, a `tracing::warn!` mentions it,
   and wardryx writes no `policy_allow` of its own because wardryx is the thing
   that is down. So the response carries `x-fuse-wardryx: allow`, which is true
   about what this gateway did and false about what any policy decided, and the
   trail cannot tell a governed call from an ungoverned one.

   **Why it is one type and not one per dependency.** `data.dependency` names
   which; `data.effect` names what this gateway then did, and that member is
   the one a consumer must not skip, because `allowed_ungoverned` is a
   governance gap wearing an outage's clothes. Splitting the type would split
   the fixed severity with it, and severity is fixed per type in this crate
   precisely so no call site can choose one. It is the shape agent-passport
   SPEC.md §6.2 already argues for on idryx's `identity_finding`: one name a
   consumer routes on, the detail in `data`, rather than a registry row and a
   render-catalogue entry per case.

   **Where it deliberately says nothing.** The unmanaged pass-through reaches
   the provider before `run_id` or `agent_id` has been resolved, so a failure
   there has no subject; SPEC.md §6.1 forbids inventing one and
   `Exporter::emit` counts the skip. That path has also been off by default
   since 2026-08-06 (`require_run_id`), so it is reachable only where an
   operator asked for it back. And a provider that ANSWERS 5xx or 529 is not
   this event at all: it is `Ok(ProviderResponse)` with a status, forwarded
   with its settlement, which mockryx's game-day drill spends a paragraph
   distinguishing and which this invariant does not claim to cover.
   *(test: `a_provider_that_cannot_be_reached_is_recorded`,
   `a_stream_that_dies_mid_answer_is_recorded` and
   `a_response_body_that_cannot_be_read_is_recorded` in `gateway::proxy`, each
   verified red against the unfixed code, verbatim `exactly one event, got []`;
   `an_unreachable_policy_plane_is_recorded_when_it_fails_open`,
   `..._when_it_fails_closed` and
   `an_unreachable_policy_plane_in_shadow_mode_reports_what_actually_happened`
   in `tests/wardryx.rs`, verified red by removing the emit block, same
   verbatim failure. The two that must NOT fire carry the rule's other half and
   were verified against their own mutants: `a_healthy_call_reports_no_...` and
   `a_call_with_no_identity_reports_no_...` in `gateway::proxy`, and
   `a_policy_plane_that_answered_is_not_reported_as_unreachable`, which goes
   red when the decode path claims `unreachable: true`. The fixed band is
   pinned by `the_dependency_failed_event_carries_the_high_band`, and the
   published artifact by `scripts/constants.sh`, which builds.)*

25. **A filter that refuses something says so on the bus, and a filter that
   DECLINES to refuse says so too.** The agent firewall could refuse from the
   day Ring 3.1 shipped and, until 2026-08-26, could not tell anyone afterwards
   what it had refused, to whom, or under which rule. Its shadow mode was
   worse than quiet: a would-block set the `x-fuse-taint` RESPONSE header and
   emitted nothing at all, so the only party ever informed was the agent that
   had just been talked into the action. docs/07 B.9 makes shadow the
   documented on-ramp, and a week of it produced no material to decide with.

   Three types now, and the split is the invariant. `taint_raised` (`low`)
   records a run acquiring a label, which is the beginning of a story whose end
   `taint_block` (`high`) was already recording: taint accumulates monotonically
   across a whole run, so without the acquisition an operator reads "blocked,
   context was [web, file]" with no way at all to learn where the web came
   from. `taint_shadow` (`medium`) is the would-block, and its band is the
   judgement: not `low`, because in shadow the dangerous action is PERMITTED
   and the client executes it, so this is a thing that happened rather than a
   refusal that worked; not `high`, because a shadow week paging at
   `taint_block`'s band pages an operator during precisely the week they were
   told to watch quietly, and an operator who mutes the sender in week one
   never reaches week two.

   **The record has to be countable, not only readable.** A block used to carry
   one prose sentence, so two refusals under different rules were
   indistinguishable strings. Rules now have names, `evaluate` returns a
   `TaintVerdict`, and every verdict event carries `stage`, `mode`, `rule`,
   `labels`, `requested`, `denied` and `tools`. `denied` says a category was
   refused; `tools` says which door was tried, and that is the member that
   makes a row actionable.

   **The floor a config file cannot remove.** docs/07 B.9 locks anti-exfiltration
   on in enforce mode, and a policy file is exactly how somebody would take it
   away, by accident far more often than on purpose: a file REPLACES the
   built-in policy, so writing one to add a rule of your own silently drops the
   other two. `from_json` and `from_env` both put it back, first in the order,
   and only in enforce: shadow is the mode an operator runs to learn what THEIR
   policy does, and a rule they did not write would make that week's numbers
   describe somebody else's.

   **A policy that cannot be read stops the box.** A gateway running the
   starter policy while its operator believes their own rules are live is worse
   than one that is plainly off, so a named `TOKENFUSE_FIREWALL_CONFIG` that is
   missing, malformed, or has a misspelled key exits 2 with the field named.
   *(test: `a_shadow_would_block_is_recorded`,
   `the_record_says_which_rule_fired_at_which_stage_and_over_what` and
   `becoming_tainted_is_recorded_not_only_being_blocked` in `gateway::proxy`,
   each verified red against the unfixed code, verbatim `left: 0 right: 1` for
   the first and third and `left: Null right: "model_tool_call"` for the
   second; `anti_exfiltration_cannot_be_dropped_in_enforce_mode` and
   `shadow_mode_does_not_get_the_floor_forced_on_it` in `gateway::firewall`;
   `a_config_that_cannot_be_read_stops_the_box_rather_than_falling_back` and
   `the_error_says_what_to_fix` for the abort, whose exit code was also
   measured live (`@measured` three bad configs against the release binary,
   2026-08-26, `EXIT=2` each with the field named). The bands are pinned by
   `scripts/constants.sh`, which builds the published artifact from the Rust
   source.)*

   **Where it says nothing.** Nothing here looks at the TEXT of a prompt: the
   model is label-based by design, and B.10 is unamended. Levels 2 and 3 and
   the sub-run bypass were open when this invariant was first written and are
   closed by invariant 26.

26. **A firewall you can walk around is a firewall you do not have, and it must
   be on to be walked around at all.** Invariant 25 gave the taint filter a
   voice. This gives it reach, and the first of the four was not a missing
   feature but a bypass.

   **A sub-run laundered its parent's taint.** docs/07 B.3 P3 has said since
   2026-07-02 that a subagent inherits its parent by default, and the taint map
   was keyed on `run_id` alone, so the entire firewall was one
   `x-fuse-parent-run-id` header away from off: taint the parent, spawn a
   child, do the dangerous thing in the child. Measured against the unfixed
   tree, the child got HTTP 200 and the shell went through. The chain is now
   resolved on EVERY request rather than seeded when a child opens, because
   seeding once would have made "spawn the child first" the same bypass in a
   different order. The chain comes off a request header, so a cycle is one
   line of curl: the visited set and the depth cap are not defensive
   programming, they are what keeps a caller from spinning the gateway inside a
   lock on the request path.

   **Every enforcement claim this product made was advisory.** B.7 level 1 is
   the gateway seeing `tool_use` in the model's answer; the CLIENT executes the
   tool, so a caller that ignores the 403 runs it anyway, and B.10 listed that
   as a limitation for seven weeks. `POST /v1/fuse/check-tool-call` is the
   other order of operations: an executor asks BEFORE it runs, and acts on the
   answer because acting on it is why it asked. It judges and does not
   accumulate, since a tool's OUTPUT is what carries taint and the tool has not
   run. It answers HTTP 200 always, with the decision in the body: a 403 here
   is indistinguishable from an auth failure or a proxy in the way, and a
   client that cannot tell those apart must choose between failing closed on a
   network blip and failing open on a refusal.

   **Its answer distinguishes three things, not two**, and this is the member a
   consumer must not skip: `allow` because nothing objected, `allow` because
   the firewall is OFF (`governed: false`), and `allow` because it is in shadow
   and a rule DID object (`would_block` present). Folding them reports "the
   gateway permitted this" for a box where nothing was asked, which is
   `dependency_failed`'s `allowed_ungoverned` mistake one plane over.

   **Level 3 is a client of level 2, not a second judge.** `tokenfuse
   mcp-broker` is a separate process invocation with its own state, so a taint
   map of its own would be a second answer about one run, and an operator
   reading a refusal at one door and a permission at the other has no way to
   tell which was right. It asks over HTTP, before secret injection and before
   the upstream, and passes `via: "mcp"` so the record says which door without
   the door being able to change the DECISION by naming itself differently. It
   needs `x-fuse-run-id`, because taint is per run and MCP carries no run
   identity of its own; a gateway it cannot reach is recorded as
   `dependency_failed` naming the policy plane, the same fact through a second
   door.

   **The default was `off`, which contradicted the specification it came
   from.** B.9 names shadow as the on-ramp, so out of the box this subsystem
   protected nothing and, worse, measured nothing, and every argument for
   turning it on had to be made without a number from the fleet it was about.
   It is `shadow` now: shadow refuses nothing, so no request that worked
   yesterday fails today, which is what makes it a default rather than a
   breaking change. It only became worth defaulting to on the day it started
   writing, one invariant ago; before that it would have been a cost with no
   output. `TOKENFUSE_FIREWALL=off` restores the old silence exactly.

   **And both taint families carry `data.prompt_hash`**, `sha384:<hex>` over
   the newest user message that carries TEXT, absent when a conversation has
   none. The newest instruction and not the history, because hashing the
   conversation changes every turn and groups nothing; what this answers is
   whether four incidents came from ONE instruction. And not the newest MESSAGE
   either: Anthropic carries a `tool_result` in a message whose role is `user`,
   so reading it literally left the field null across every tool loop, which is
   the `tool_result` stage and the place the question is most worth asking
   (measured 2026-08-26 on a live tool-use request, fixed the same day). It
   walks back only until it finds text, so a changed instruction stays visible
   at the turn it changed, and a conversation with no instruction anywhere is
   still absent rather than hashed. On the acquisition as well as the verdict, because the turn a
   run became untrusted and the turn it tried something are usually not the
   same turn. A hash and only a hash, so there is nothing here to erase, and it
   deliberately does NOT reach trailryx's `basis.prompt_hash`: that field is
   unerasable typed metadata, this value arrives in `data`, and trailryx's
   mapper is forbidden from promoting a producer's free-form member into a
   typed field. It lands in the payload plane, behind the key whose destruction
   erases it, which is where a pseudonymous identifier of possibly-personal
   content belongs.
   *(test: `a_sub_run_cannot_launder_its_parents_taint`, verified red against
   the unfixed tree, verbatim `left: 200 right: 403`;
   `a_run_that_declares_itself_its_own_ancestor_does_not_hang_the_box` for the
   cycle; the seven in `gateway::toolcheck`, of which
   `the_two_doors_answer_the_same_way_about_one_run` is the one that makes
   level 2 worth having and `a_firewall_that_is_off_says_allow_and_ungoverned_not_just_allow`
   the one that keeps its answer honest; five in `tests/mcp_broker.rs` for
   level 3, including
   `a_gateway_that_cannot_be_reached_does_not_silently_become_permission`;
   `the_default_is_shadow_so_a_box_that_asked_for_nothing_still_measures`,
   which also asserts the off switch still means off; nine in
   `core::agent_event::prompt_hash_tests` and two in `gateway::proxy` for the
   instruction hash, of which `it_is_a_hash_and_carries_no_word_of_the_prompt`
   is the whole safety argument. `@measured` end to end against the release
   binary, 2026-08-26: started with NO firewall variable and logged
   `mode=Shadow`; a child run with a spotless history refused with `tainted
   context [unclassified, web]` inherited from `p1`; the record carried
   `stage: parent_run`, `from_tools: ["p1"]`; the MCP door forwarded under
   shadow and refused under enforce with `stage: mcp_tool_call`; and
   `tokenfuse firewall --events` showed all four stages.)*

   **Where it still says nothing.** None of docs/07 B.4's three sanitization
   gates is built, so a label acquired is carried for the life of the run and
   the only release valve is a new run. Source matching is on tool NAME only:
   B.2's `mcp_server` and `args.path` globs are not built. Level 1 is still
   advisory and always will be; what changed is that it is no longer the only
   door. And nothing here looks at the text of a prompt.

27. **A detector that reads the attacker's text may not decide anything.** The
   agent firewall is label-based by design and only ever as good as the
   operator's source map, and a source map is a statement about the PIPE while
   injections arrive in the WATER. `crates/core/src/injection.rs` closes that:
   it reads tool results and, where a document is written like an instruction
   to the model, adds one label, `suspected_injection`. The capability gate
   refuses. That is the whole design.

   **It may not decide, and the reason is not caution.** The attacker writes
   the text, so anything that reads the text and then chooses `allow` or `deny`
   has handed the attacker a vote in its own verdict. As a taint SOURCE it has
   no such vote: taint is monotonic, so its findings can only make the gate
   stricter and never looser, and defeating the detector returns you to the
   coarse model rather than getting you past it. A false positive costs one
   refused dangerous action; a false negative costs nothing that was not
   already being lost. That asymmetry is why a regex-only, publicly readable,
   defeatable detector is an acceptable thing to ship, and it would not be if
   it decided.

   **What it adds over the labels already there.** A run that called
   `web_search` is already untrusted. This earns its place in one case and it
   is the common one: a source the operator classified as TRUSTED carrying
   something the world put in it, an internal ticket system or a wiki or a
   support inbox. Second, it says WHY: before it, an operator read "blocked,
   context was [web]" and could not tell whether anything had actually tried.

   **Signals are names, never text.** A signal name is a fact about the SHAPE
   of a document and carries none of its content, which is what lets it travel
   on a bus that holds no content, into the record and into an alert.

   **It scans tool results and not the user's own message**, and that blind
   spot is deliberate: a security engineer typing "check whether it will ignore
   all previous instructions" must not taint their own run for doing their job.
   The cost is named rather than hidden: pasting an untrusted document into
   your own message is not covered.

   **Silence about a label that did not exist is not consent.** In enforce
   mode, a policy that mentions the label nowhere gets
   `no-action-after-an-injection-signal` added, because a file written before
   the detector existed could not have mentioned it, and reading its silence as
   agreement would hand every such operator a detector producing a label
   nothing acts on: the exact case it exists for. `@claude`, and NOT the same
   basis as anti-exfiltration's floor, which docs/07 B.9 locks. A rule of their
   own naming the label wins; `"detect_injection": false` turns the scan off
   entirely, because a floor with no exit is one somebody escapes by turning
   the whole firewall off. Anti-exfiltration still judges first, being the one
   B.9 locks and the one an auditor comes looking for.
   *(test: `an_injection_in_a_trusted_source_is_still_an_injection` in
   `gateway::proxy`, verified red against the unfixed tree, verbatim
   `left: 200 right: 403`; `an_ordinary_tool_result_raises_nothing` beside it,
   which passed BEFORE the change and had to keep passing after, since a
   detector that fires on ordinary text gets switched off and takes the coarse
   model with it. Twelve in `core::injection`, of which `ordinary_documents_stay_quiet`
   carries ten real documents each containing a word a naive pattern would fire
   on, and `the_users_own_words_are_not_scanned` records the blind spot as a
   decision. Four in `gateway::firewall` for the floor, the operator's own
   rule, the off switch, and shadow not getting the floor forced on it.
   `@measured` against the release binary, 2026-08-26, with a policy trusting
   an internal ticket system: an ordinary ticket answered 200 with
   `signals: []`; the same source carrying an override, an exfiltration ask and
   a tool directive answered 403 with `tainted context [internal,
   suspected_injection]`, three signals on the event, and `grep` over the whole
   NDJSON found ZERO words of the ticket; `detect_injection: false` answered
   200.)*

   **Where it says nothing.** Regex only, English only, and its patterns are
   shapes rather than meanings. It is defeatable by anybody who reads the file,
   which is public, and that is acceptable only because of the asymmetry above.
   docs/07 B.4's three sanitization gates are still unbuilt, so a run that
   picks this label up carries it to the end.

28. **A control with no way back gets switched off, so the way back is part of
   the control.** docs/07 B.10 has always named conservativeness as the price of
   a monotonic label model and B.4 as the valve. The valve was never built, so
   a label lasted the life of a run, and once inheritance shipped on the same
   morning one long-lived parent made every child untrusted forever. An
   operator whose fleet is refused all day turns the firewall off, and that
   costs them the coarse model that WAS working.

   `POST /v1/fuse/declassify`. A human reviewed the content and says so; the
   labels come off that run. **Four things keep it from being the bypass, and
   none is obscurity.** `actor` must be a `user://` principal, so an agent
   clearing its own taint is refused outright. `reason` is required, because a
   human lifting a control without saying why is the audit hole rather than the
   control. `secrets` can never be cleared, since B.9 locks anti-exfiltration
   on and clearing that label makes the rule unreachable for a run. And a
   clearance is SPENT by the next arrival of that label: they reviewed what was
   there, not what comes next, and a clearance that survived would mean one
   review buys an agent a permanent exemption.

   **`agent_id` is required and it is not a formality.** `Exporter::emit` skips
   an event with no subject and counts the skip, because SPEC 6.1 forbids
   inventing one, so an optional field there would have meant clearances
   applied and never recorded: a control lifted with no trace, the worst
   outcome this endpoint has. Found by the test, not by reading.

   Recorded at `high`, the band a block takes, because an estate that pages
   when a rule fires and stays quiet when somebody switches it off has its
   weights backwards. `data.authenticated` says whether the caller presented
   `TOKENFUSE_DECLASSIFY_KEY`; unset, this endpoint sits behind network
   placement exactly as `/v1/runs/{id}/kill` does, and an auditor has to be
   able to tell those apart. Making the key mandatory was considered and
   rejected: `kill` sits open beside it on the same router, so a bespoke
   credential on one endpoint is a false comfort rather than a boundary.

   **A clearance is about the BLOCKS a person read, and for its first day it
   was not.** The fourth point above was true as written and useless in
   practice. Taint is re-derived from the whole `messages[]` array on every
   request and an agent loop resends the whole conversation, so "the next
   arrival of that label" was the very block a human had just reviewed, coming
   back on the next turn: the clearance was spent before the run's next action
   was judged, and the valve released for exactly one request shape, a
   follow-up carrying no tool history, which nothing sends. The test that
   proved it worked sent that shape. It passed against the defect.

   Both wire shapes carry an id per tool call, so a review is recorded against
   ids. The same block arriving again is not an arrival; one that was not there
   when somebody read the conversation is. `@yurii 2026-08-26` chose this over
   the cheaper option of remembering how far the history reached.

   Four decisions inside it, each of which could have gone the other way. **A
   block with no id is never reviewed**, because the other fallback is a bypass
   one omitted field wide, and the cost, a valve that still spends every turn
   for a producer that sends no ids, is reported as `reviewed_blocks: 0` rather
   than discovered on the next call. **`reviewed_blocks` is inferred when
   absent**, meaning every block this gateway has seen on the run, which is what
   was on the operator's screen; requiring the ids would put the question of
   what a human read into the agent framework's hands, which is the party this
   endpoint exists to overrule, and an id the run never carried refuses the
   WHOLE clearance because a forward-dated review is a permanent exemption
   bought in advance. **The set is capped at 256 blocks per run and overflow
   drops the oldest**, so their labels return: an unbounded set is a leak, and
   fail-closed is the direction to fail in. **`suspected_injection` follows the
   same rule**, being the same shape one field over: it is re-derived by
   scanning tool RESULTS each turn, so a block somebody signed for takes its
   result with it, while a result whose call has scrolled out of the window is
   attributed to no tool and is still scanned.

   The blocks are recorded before ANY refusal can return, not beside the
   firewall's own accumulation, and that placement is load-bearing rather than
   tidy: a refusal is what somebody is looking at when they clear a run, and the
   wasm hook refuses on the taint bitset and returns long before the firewall
   block. Found by a test, after a mutant showed the wasm plane's own bitset was
   re-derived from the unsplit history and no test in the workspace noticed.
   *(test: `a_clearance_survives_the_history_the_next_turn_resends`, verified red
   against the unfixed tree, verbatim `left: 403 right: 200`;
   `a_page_read_after_the_review_is_not_covered_by_it`,
   `a_block_carrying_no_id_is_never_read_as_reviewed`,
   `signing_for_a_block_the_run_never_carried_is_refused`,
   `an_injection_a_human_reviewed_does_not_come_back_every_turn` and
   `the_wasm_plane_sees_the_clearance_the_firewall_saw` in `gateway::proxy`;
   seven in `gateway::state::block_ledger_tests` for the ledger, its cap and its
   cull; three in `core::taint` for the ids on both wire shapes. Ten mutants
   planted in the PRODUCT code 2026-08-26 and all ten caught, of which two
   survived a first pass and are why two of those tests exist: the eviction cull
   deleted, which the bound test could not catch because it signed for blocks
   AFTER the overflow; and the wasm plane's bitset restored to the unsplit
   history, which nothing covered at all. Scenarios:
   `features/agent-firewall.feature`, seven, each bound to a named test.
   `@measured` against the release binary in enforce mode with a real upstream,
   2026-08-26: read the board -> 403 `[web]`; a person cleared it ->
   `{"cleared":["web"],"reviewed_blocks":1}`; the SAME conversation resent ->
   200, with no `taint_raised` at all; the same conversation plus one unreviewed
   page -> 403. Ten events off that run pass `agent-conform -chain`, hash chain
   included.)*

   **B.4's other two gates are not built here and cannot be.** Both declassify
   a VALUE, and B.3 refuses per-value tracking in as many words, for the reason
   it gives: intractable at the proxy level, and false precision. Their
   run-level expression is B.3 P4's quarantined sub-run: read the dirty
   document in a child, hand the caller only what came out. That works because
   **taint flows down a chain and never up it**, and nothing asserted that
   until now. A change making inheritance symmetric would have turned the
   estate's one sanctioned way of handling dirty data into a way of spreading
   it, and every quarantine already written would have started poisoning its
   caller.
   *(test: `a_human_who_reviewed_the_context_can_let_a_label_go`, verified red
   against the unfixed tree; `a_clearance_is_spent_by_the_next_arrival_of_that_label`,
   `clearing_a_child_says_the_parent_still_carries_it`,
   `secrets_cannot_be_let_go_at_all`,
   `a_clearance_with_no_human_and_no_reason_is_not_a_clearance` and
   `taint_flows_down_a_chain_and_never_up_it` in `gateway::proxy`; three in
   `gateway::declassify` for the key, the reason cap and the authenticated
   flag. `@measured` against the release binary, 2026-08-26: reads the web ->
   403, still 403, a human clears it -> 200, reads the web again -> 403. The
   bus carried `taint_cleared` at `high` with the actor, the reason and
   `authenticated: true`; an agent trying to clear its own taint was refused by
   name, and so was a call with no key on a gateway that had one configured.)*

   **Where it says nothing.** Nothing stops a caller declaring a quarantine as
   the PARENT of a clean run, which flows the taint the wrong way round on
   purpose; that is the caller's shape to get right and the honest limit of a
   proxy-level model. And the key is only as good as a deployment that keeps it
   away from the agent, which is true of every operator control here.

   Three more, added with the block model. A label the caller declares in the
   `x-fuse-taint` REQUEST header is re-supplied every turn it is sent and spends
   the clearance, which is correct, because the caller chooses to keep sending
   it and can stop. The answer an allowed turn produces is a new action nobody
   reviewed, so a model tool call this gateway has just permitted is accumulated
   on the run at that moment (B.3 P2) and judged on the next turn; measured
   live. And the `taint_cleared` event does not say WHICH blocks a clearance
   covered, only how many the HTTP answer reports, because that would be a new
   member on `taint_cleared_data` in `tokenfuse-core`.

29. **Every verifier in this workspace shares one copy of the algorithm rule.**
   `oidc.rs` has closed the RS256-to-HS256 downgrade since it was written: the
   permitted algorithms come from the KEY TYPE and never from the token header,
   which is written by whoever presents the token. When `delegation.rs` arrived
   on 2026-08-26 needing the same rule, the agent-identity plan's word was that
   the defence "must be preserved verbatim". It is not preserved verbatim; it is
   shared, because verbatim is two things that agree today and a shared function
   is two things that cannot disagree tomorrow.

   **The one copy is `tokenfuse_dpop::algorithms_for_key`**, and it moved there
   the same day, when the MCP broker's door (invariant 30) became a third caller
   in the OTHER crate. `oidc` re-exports it under its old name, so
   `oidc::algorithms_for_key` still resolves and `delegation` still calls that
   path. Its address is the only thing that changed; a crate was the only place
   left that all three could reach, because the gateway must not depend on the
   Cloud and `tokenfuse-core` must not grow a JWS library (invariant 1).

   **On the PROOF path this rule is defence in depth, not the only barrier, and
   that is measured rather than assumed.** `@measured` 2026-08-26, by planting
   the mutant and by a throwaway probe against `tokenfuse-dpop`: replacing
   `algorithms_for_key` with `header.alg` inside `verify_proof` changed no test
   in the workspace, because every route through it is already closed. A
   symmetric key is refused earlier, by the private-member check, since an `oct`
   JWK carries `k`. An RSA or EC key presented with an HMAC algorithm is refused
   by `jsonwebtoken` 9 itself, whose own key-family check answers
   `InvalidAlgorithm`. And `thumbprint` refuses anything that is neither RSA nor
   EC at the end.

   It stays, for two reasons that are not "it might help". It does not depend on
   a library's internal check, which is a thing a dependency bump can change
   without saying so. And on the TOKEN paths it IS the barrier: there the key
   comes from a configured JWKS by `kid`, `thumbprint` is never consulted, and
   nothing else refuses an `oct` entry in an operator's own key set, which is
   also what closes `none`. `the_algorithm_still_comes_from_the_key_on_this_path`
   and `the_algorithm_comes_from_the_key_and_never_from_the_header` are what
   hold it, and neither can go red for the proof path, which is the honest
   limit.

   **A delegation is verified with what the process already holds.** No client,
   no URL, no timeout: the key set is local, the clock is passed in, and
   revocation is a closure the caller owns. wardryx decides at a 3.2 ms p50 and
   audits every decision, so putting signature verification behind a round trip
   taxes every decision in the estate and makes the token service a hard
   dependency of every enforcement point at once, which is the shape
   `dependency_failed` was cut to record.

   **A token carrying `cnf.jkt` and presented with no proof is REFUSED**, never
   accepted with the binding skipped. An enforcement point that simply forgot to
   pass a proof would otherwise report success while honouring a stolen token,
   and that failure looks exactly like it is working. A token with NO `cnf.jkt`
   is refused too: vouchryx binds everything it mints, so an unbound one came
   from somewhere else or from a version that stopped binding.

   **The chain is READ and not verified.** `agent-stack-go`'s invariant 5
   applies here: root-first ordering is a property of how a chain was BUILT and
   cannot be checked from a finished list. And the two specifications keep
   different lists, which is the part that catches people: RFC 8693 keeps the
   subject OUT of `act` while agent-passport puts the root INTO the chain, so
   the mapping is `[sub] + reverse(act)` rather than a reversal. A verifier that
   handed the actors straight to a record would write a delegation with the
   human missing from it, and every token would still verify.

   **And the cap on that chain counts ENTRIES, which is why it is not the cap on
   the actors.** agent-passport SPEC 5.1 reads "Maximum chain depth is 32
   entries" and SPEC section 5 calls the members of `on_behalf_of` entries, so
   the bound belongs to the assembled list. `chain_of` prepends the subject and
   `verify_delegation` refuses an empty `sub`, so every chain this crate builds
   spends one entry on the root: `MAX_CHAIN_ENTRIES` is the SPEC's number and
   `MAX_ACTORS_WITH_SUBJECT` is derived from it rather than retyped. Measured
   2026-08-27 with agent-conform against a real emitted line: the bound was on
   the actors, so a token carrying 32 of them verified here and produced a
   33-entry chain that agent-conform, both envelope schemas and agent-stack-go's
   `chain.Validate` all refuse with `maxItems: got 33, want 32`. The door
   reported success and the audit trail it was supposed to leave did not exist.

   That is the same shape as invariant 34 one repository over: one rule, two
   places, nothing comparing them. The comparison cannot live here, because this
   repository may not read agent-passport or agent-stack-go, so it lives in
   `estate-gates`.
   *(test: fourteen in `cloud::delegation`, of which
   `a_token_presented_by_the_wrong_holder_is_refused` and
   `a_bound_token_checked_with_no_proof_is_refused_rather_than_downgraded` are
   the two the binding exists for, `a_delegation_verifies_and_the_chain_keeps_its_root`
   holds the mapping, and `the_algorithm_still_comes_from_the_key_on_this_path`
   holds the shared rule from the new side. The Go half is
   `agent-stack-go/delegation`, TAIPANBOX/agent-stack-go#31.)*

   **Where it says nothing.** Nothing in this repository CALLS it yet: no
   gateway path checks a delegation token, so this is a verifier with no
   consumer, exactly as vouchryx was a producer with no verifier this morning.
   Wiring it into `/v1/messages` is a separate decision with a wire contract of
   its own. There is no replay cache on this side either, so a captured proof
   works as often as it is presented inside its sixty-second window; the Go half
   has one and this does not, and that asymmetry is a gap rather than a design.

30. **A door worth guarding is not guarded by a password.** Invariant 20 closed
   who may reach the broker's port. Invariant 23 closed which secret they may
   pull once inside. The credential ON the door stayed `TOKENFUSE_MCP_KEYS`, a
   shared secret in a header, which sits in a deployment manifest, an
   environment variable, a shell history, a CI log, and in every request on the
   wire, and which is the whole of the identity for whoever captures it.

   `TOKENFUSE_MCP_CLIENT_IDS` is the other door: CIMD client metadata documents
   (`draft-ietf-oauth-client-id-metadata-document`), each published by a client
   at its own https `client_id` URL and naming that client's public keys, plus
   an RFC 9449 proof of possession on every call. Off unless configured, so a
   deployment that sets none of it is byte for byte unchanged.

   **The identity comes from the key that signed the proof, never from anything
   the caller asserts.** That is invariant 15's rule one door over, and it also
   makes "claims client A, signs with client B's key" unrepresentable rather
   than merely checked. Two clients publishing one key is refused at
   configuration time, where it is one error message, rather than at request
   time, where it would be a coin toss.

   **This broker never dereferences a `client_id`, and that is the decision
   rather than an omission.** On the request path a fetch would make this door's
   availability somebody else's website, per call, to a host chosen by the party
   being authenticated; invariant 29 already refused the same shape one plane
   over for the same reason. At startup it would buy one deploy step, cost a
   boot-time dependency on a third party, and still need a restart to see a
   rotated key. So the fetch is a `curl` in the operator's deploy. The cost is
   named rather than hidden: this process cannot enforce CIMD's self-consistency
   rule that a document was served from the URL it claims, because it did not do
   the retrieving.

   **Single use is not optional HERE, whatever it is elsewhere.** `htm` and
   `htu` pin a proof to one method and one URL, which is most of DPoP's
   per-request value on an API with many endpoints and nearly none on this one:
   every JSON-RPC method arrives as a POST to the same path. Without a replay
   cache a proof captured from a harmless `tools/list` is a valid credential for
   `tools/call` for the rest of the window. The cache keeps two generations of
   two windows each, because `iat` is accepted a window either side of now and
   so the longest interval over which one proof can be presented twice and be
   fresh both times is two windows; rotating every window would leave a
   shortfall that is a replay that works. At its cap it REFUSES rather than
   forgetting, and only a caller whose proof already verified against a
   configured key ever reaches it, so filling it is something an admitted client
   can do and a stranger cannot.

   **`htu` is compared against `TOKENFUSE_MCP_PROOF_URL` plus the path this
   server routed, never a `Host` header.** A caller who supplies the host can
   make `htu` agree with anything, which turns the check into decoration. The
   variable is therefore required whenever clients are configured.

   **The composition of the two doors is the part with teeth.** A caller that
   presents a proof is judged BY it: a broken proof is a refusal and never a
   fall-back, even when the same call carries a good bearer credential, or an
   attacker with a stolen `x-fuse-key` strips the header and is back in the old
   world. A caller that presents NO proof falls through to the bearer door while
   one is configured, which is what makes this an addition rather than a
   breaking change, and that migration state is announced at startup
   (`bearer_door_still_open_warning`) with the variable that ends it
   (`TOKENFUSE_MCP_REQUIRE_PROOF`). Requiring a proof with no clients configured
   refuses to start, being a door nothing can open.

   Set-but-unusable refuses to start rather than reading as "off", the same
   conclusion `TOKENFUSE_MCP_KEYS` and `TOKENFUSE_MCP_SECRET_SCOPES` both
   reached. And "is there anything on the door" is now one named question
   (`something_on_the_door`), asked once, so the refusal and the warning cannot
   answer it differently and an operator who configured only the STRONGER
   credential is not refused for want of the weaker one.
   *(scenarios: `features/mcp-proof-door.feature`, thirteen, each bound to a
   named test. Test: twenty in `tests/mcp_door.rs`, of which
   `a_replayed_proof_is_refused_though_it_verifies_perfectly` is the one this is
   worth having for on a single-URL endpoint,
   `a_broken_proof_is_never_downgraded_to_the_bearer_door` holds the composition
   rule, and `two_proofs_from_one_client_are_both_admitted` is its negative
   control, since a door that refused every second call would pass the replay
   test. Six in `gateway::mcpbroker` for the startup conditions. Three in
   `tests/mcp_broker.rs` over the live HTTP path asserting on what reached the
   upstream, including
   `a_captured_proof_replayed_at_the_live_door_reaches_nothing_the_second_time`.
   Sixteen in `tokenfuse-dpop` for the verifier and the cache. All were run
   against the unfixed tree first: `mcpdoor` did not exist, so the suite failed
   to compile, verbatim ``could not find `mcpdoor` in `tokenfuse_gateway` ``.

   Ten mutants were planted in the PRODUCT code on 2026-08-26, nine caught and
   one not, each named with the test that caught it: the key that signed a proof
   never looked up (`a_proof_from_a_key_no_client_published_is_refused`); the
   replay answer computed and discarded
   (`a_replayed_proof_is_refused_though_it_verifies_perfectly` and the live
   one); `require_proof` ignored
   (`require_proof_closes_the_bearer_door_without_removing_the_keys`); a broken
   proof falling back to the bearer door
   (`a_broken_proof_is_never_downgraded_to_the_bearer_door`, plus three more);
   `htu` not compared (`a_proof_for_another_path_or_another_moment_is_refused`,
   and the same-named tests in `tokenfuse-dpop` and `cloud::delegation`); an
   `http` client id accepted
   (`an_http_client_id_is_refused_rather_than_quietly_accepted`); the cache
   forgetting at its cap rather than refusing
   (`a_full_cache_refuses_rather_than_forgetting_something_it_promised`); the
   private-member check dropped
   (`a_client_leaking_its_private_key_is_refused_rather_than_helped`, both
   crates); and `something_on_the_door` back to keys alone
   (`a_proof_door_counts_as_something_on_the_door`).

   **The tenth survived, and it is recorded rather than quietly fixed**: taking
   the algorithm from the proof header instead of the key type changed no test
   in the workspace. It is an equivalent mutant on this path and that was
   established by measurement, not by argument. See invariant 29.)*

   **Where it says nothing.** It does not authenticate the agent to the upstream
   MCP server: the broker forwards with whatever the vault injects and the
   upstream sees the broker, with nothing signed on the outbound leg. It is not
   a delegation check and says nothing about whom the caller acts for; that is
   invariant 29's verifier, which no request path here calls yet. It does not
   narrow which secret may be pulled, which is invariant 23. It does nothing
   against a compromised client, since a private key an attacker holds is as
   good as a bearer token they hold; what it removes is the value of anything
   captured in flight or found at rest. The replay cache is per PROCESS, so two
   brokers behind a load balancer each remember their own. stdio is untouched,
   having no header channel. There is no agent-event for a refusal at this door,
   matching the bearer door exactly. And the shared `401` body names
   `x-fuse-key` even on a deployment that configures only the proof door,
   because it is the gateway's own `unauthorized_response` and sharing it is
   what keeps the two planes from drifting.

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
- **`cargo audit` at the repo root is a false green.** There are TWO
  lockfiles, the workspace root and `crates/cluster`, and CI names it in the
  step it fails on: "Audit both lockfiles". A bare `cargo audit` scans one and
  says nothing about the other, so it PASSES while CI goes red, which is the
  dangerous direction for a check to be wrong in. It also does not know about
  the allowances `scripts/audit.sh` carries (currently RUSTSEC-2026-0235,
  rkyv, "is in no build graph, only in the lockfile"), so it reports a failure
  the gate has already judged. Run `./scripts/audit.sh`. This cost a red CI on
  2026-08-20, when the h2 fix for RUSTSEC-2026-0258 landed in the root
  lockfile and left `crates/cluster` on the vulnerable version.

- **An unpinned `cargo install` in CI is a dependency with no lockfile.** The
  radar job ran `cargo install bpf-linker` with no version and no `--locked`,
  so it resolved to whatever was newest when the job started. bpf-linker 0.11.0
  landed on 2026-08-12, the day after this job last went green, and it links
  system LLVM dynamically, which the `System deps` step does not install. Main
  went red on 2026-08-20 with nothing in this repository having changed, and
  the first PR to notice looked like the cause. Pinned to 0.10.4 `--locked`.
  Two `pip install` steps (pytest, openapi-spec-validator) are still unpinned
  and can fail the same way; `cargo install cargo-audit --locked` carries no
  version either, so it floats a major.

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

Session learnings live under this checkout's own Claude Code project directory,
`~/.claude/projects/<this checkout's absolute path, slashes as hyphens>/memory/`,
if present. Check it for prior lessons before repeating a class of mistake.

The literal path was written out here until 2026-08-20 and named a home
directory that does not exist on the machine this repository is developed on, so
for months the one line telling a reader where the prior lessons are sent them
to nothing, silently, which is the failure mode this whole file is about. It is
written as a derivation now for two reasons: the directory is per-machine by
construction, so any literal is right on exactly one clone; and this repository
is public, so a literal publishes somebody's username to everyone who reads it.

## Conventions

- **No long dashes** anywhere: not in code comments, docs, commit messages, or
  PR bodies. Use a comma, a colon, parentheses, or a short hyphen.
- Nothing paid or metered gets enabled without telling the user first and
  getting agreement.
- Do not delete or revoke keys, tokens, or certificates on your own initiative.

31. **A chain the PDP is asked about carries whether anybody PROVED it, and the
    answer is never the caller's to give.** wardryx gained
    `deny_if_chain_unproven`, `max_chain_depth` and `require_root_principal`
    on 2026-08-26, and this gateway sent it `on_behalf_of` taken from the
    `x-fuse-on-behalf-of` header. So a depth cap of three capped a number the
    CALLER chose, and `deny_if_chain_unproven` denied on the strength of a
    claim. vouchryx issues a token that settles the question and two languages
    could verify one; no request path called either.

    `chain_proven` is set by `chainproof::resolve` and by nothing else. No
    header sets it, because a caller able to assert it would be asserting the
    very thing the field exists to establish. False is the honest default and
    means "nobody proved this", which is a different statement from saying
    nothing, and it is what every deployment that configures no issuer sends.

    **Both doors, not one.** The MCP broker and the LLM proxy both build a
    `DecideContext` and both took the chain from that header. The proxy is the
    larger of the two: it is the path the agents' own traffic takes. Fixing one
    and leaving the other would have been the failure that looks exactly like
    it is working, so the rule lives in one module and both call it.

    **A token and a header that disagree are refused**, not silently
    reconciled. A caller sending both is either confused or probing which one
    this code believes, and answering that quietly is how a downgrade hides.
    Compared as an ordered list AND as a set, because a reordering has the same
    set and an extra name has the same prefix.

    It is also part of the decision cache key, for the reason
    `attestation_method` already is: a proven and an unproven request for the
    same (agent, tool-set) must not share an entry, or whichever landed first
    answers for the other.
    *(test: `a_chain_nobody_proved_is_asked_about_as_unproven`,
    `a_proven_chain_comes_from_the_token_and_not_from_the_header`,
    `a_token_and_a_header_that_disagree_are_refused_rather_than_reconciled`
    in `tests/mcp_broker.rs`; `a_chain_nobody_proved_reaches_the_pdp_marked_unproven`
    and `a_proven_chain_reaches_the_pdp_from_the_token` in `tests/wardryx.rs`.
    Not a script gate: nothing STOPS a third `DecideContext` being built
    somewhere without going through `chainproof`, and the compiler naming both
    existing sites when the field was added is what found them this time.)*

32. **A list somebody can be told about is a list something reads, and its AGE
    is a decision rather than an accident.** vouchryx has served
    `GET /v1/revocations` since the day it was written, with an `as_of` cursor
    put there so a poller could tell an empty list from a failed fetch. Measured
    2026-08-26: nothing polled it. Both doors here passed
    `revoked: |_, _, _| false`, no Go enforcement point set `Options.Revoked`,
    and four documents in two repositories said in the present tense that every
    enforcement point consults it. The four are corrected in the same wave, and
    that half is not optional: this repository's rule is to change the text
    rather than to narrate the change.

    `tokenfuse_delegation::revocations` is the local cache the `revoked` closure
    is filled from. Still no client in that crate, which is invariant 29 intact:
    the FETCH is out of band and the CHECK is local, so `Revocations::check`
    takes a clock, returns an `Answer`, and has nowhere to send a request.

    **Age is the third state, and it decides what a MISS means rather than what
    a HIT means.** The estate has answered "a dependency is unreachable" twice,
    both times with an operator-chosen fail mode defaulting to open
    (`wardryx::FailMode`, `TOKENFUSE_MCP_TAINT_FAILMODE`). `FailMode` here is
    the same word and DELIBERATELY the opposite default, and the difference is
    stated rather than hidden: an unreachable PDP says nothing, so opening
    decides a question no answer was coming for, while an unreachable revocation
    list says one narrow thing, which is that this authority can no longer be
    confirmed. Open there is also an attack primitive, because it makes revoking
    conditional on one service being reachable and does so silently. What a
    revocation list adds on top is that a stale list is still mostly right: one
    from four minutes ago holds every revocation older than four minutes. So a hit
    stands at any age, because nothing un-revokes a token and discarding a
    revocation we hold would call a token we know is dead a live one. A miss is
    an inference from the list being COMPLETE, completeness is what expires, and
    past `DEFAULT_MAX_AGE_SECS` the fail mode answers a miss instead.

    **Sixty seconds is the number, and it is the window in which a revoked token
    still works.** It comes from the token rather than from taste: vouchryx
    mints at a five-minute default TTL and caps at an hour, so a list allowed to
    outlive a token would let one minted after the last poll be revoked and go
    on working for its whole life, which makes the control decorative for a
    whole generation of tokens rather than merely late.

    **Never fetched is not stale, and an older answer never replaces a newer
    one.** `Basis::Never` and `Basis::Stale` both defer to the fail mode and are
    different faults: a poller nobody wired does not clear itself and nothing
    else in the estate will mention it, which is invariant 13's boundary. A
    snapshot whose `as_of` moved backwards is refused and counted, because
    installing it would reset the age and a view that had stopped moving would
    start reading as fresh, which turns every other rule here off. Equal cursors
    ARE accepted: `as_of` is a Unix second and refusing that would break any
    poller faster than 1 Hz.
    *(scenarios: `features/revocation.feature`, eighteen, each bound to a named
    test. Test: eighteen in `delegation::revocations`, every one run against a
    `check` stubbed to `|_, _, _| false`, which is what the doors do today;
    fourteen went red there, verbatim among them `left: Never right: Stale {
    age_secs: 61 }` and `tok-1 was answered from the list: Answer { revoked:
    false, basis: Never }`. One stayed red past the stub and found a real
    defect: a derived `Deserialize` reads `[]` positionally into an empty
    snapshot, so `Snapshot::from_json` now refuses a body that is not a JSON
    object. Eight mutants planted in the product code on
    2026-08-26, all eight caught, each named with the test that caught it in the
    pull request. The two worth naming here are the ones the design turns on:
    the age never consulted, so a stale list serves for ever
    (`a_miss_on_a_stale_list_falls_back_to_the_fail_mode`), and the age
    governing a HIT as well as a MISS
    (`a_stale_list_still_refuses_what_it_names`). Not a script gate: nothing
    STOPS a door going on passing `|_, _, _| false`, and wiring the two doors is
    a separate wave with a wire contract of its own.)*

    **Where it says nothing.** No door in this repository calls it yet, so this
    is still a library with no consumer, which is what invariant 29 already says
    about the verifier it plugs into. It holds no store, so a restart starts
    from `Basis::Never` and the fail mode governs until the first poll lands.
    And it cannot tell a vouchryx that restarted and forgot its whole list from
    one whose entries legitimately expired: both answer an empty list with a
    current cursor, and vouchryx's own README names the in-memory store under
    NOT PROVEN for exactly that reason.

33. **A framework row is a claim about what the code ENFORCES, and what this
    product is merely relevant to is a different list with a different type.**
    `crates/core/src/compliance.rs` has refused to mis-cite a standard since it
    was written, and that refusal left it with nowhere honest to put ISO/IEC
    23894: it is guidance on an AI risk-management PROCESS built on ISO 31000,
    enforcing a process is not a thing code does, so a catalog row for it is the
    over-claim `Enforcement` exists to prevent. Leaving it out entirely dropped
    the true half with the false one, which is that a customer under 23894 can
    put this product's enforcement decisions in their risk file as evidence.

    `RELEVANT_FRAMEWORKS` is that third category. `@yurii 2026-08-26`, "3a (c)",
    which confirmed the two standing refusals (ISO 23894 and OWASP ASI07) and
    asked for this list beside them. The argument for each refusal is `@claude`,
    dated 2026-08-26, and stands unedited in the module doc.

    **Three shape decisions, and each is what keeps the two from being one.** A
    separate type rather than a flag on `ControlMapping`, because a boolean on
    the existing rows is one edit away from a row that carries the flag and stays
    in the enforced list anyway. Disjoint id sets, asserted, which is what makes
    the separation true of every SURFACE without reading any of them: every
    reporting path renders the enforced list by iterating `framework_versions`,
    so a framework that can never appear there can never be shown as enforced.
    And three required prose fields, because relevance stated with no limit
    beside it is a coverage claim in a quieter voice.

    **The category is per FRAMEWORK, not per obligation.** The EU AI Act has
    articles nothing here enforces (Art. 10, the bias obligations) and stays an
    enforced framework, because Art. 15 has real controls behind it. Only a
    framework this product enforces NO part of belongs in the third list; a
    framework's unclaimed parts stay in the module's gap notes.

    **ASI07 is deliberately NOT in it**, and that is the boundary worth
    recording, because the two confirmed refusals have two different reasons and
    only one of them is what this category answers. 23894 is a process standard
    this product is genuinely relevant to and enforces no clause of. ASI07 names
    a control this product does not have at all, since the agents here do not
    talk to each other across a trust boundary, so there is no channel being
    inspected and nothing to be relevant about. Filing it here would soften a
    decision rather than record one.

    **Where it is published and where it is not.** `relevant_frameworks` is a
    field of `ComplianceReport`, so `tokenfuse compliance --json` carries it;
    `@measured` against the release binary 2026-08-26, six top-level keys with
    `relevant_frameworks` beside `framework_versions` and `ISO-23894` absent from
    the enforced list. The human and Markdown renderings of that CLI and the
    Cloud's `/v1/compliance` DTO do not carry it yet. Neither can show a
    merely-relevant framework as enforced, by the disjointness above, and neither
    shows it at all; both were measured, not read off the source, and both are
    one small change in files this pass did not touch.
    *(gate: `scripts/honest-claims.sh`, which now records the membership of BOTH
    lists for the reason it already records every control's grade: a promotion
    out of the relevant list into the enforced one is the same over-claim one
    level up, where `Enforcement` cannot see it. Verified against five mutants,
    each of which fails it: 23894 promoted into the enforced list, a new
    relevance claim nobody recorded, an enforced framework appearing in the
    relevant list, the const removed, and the category emptied to `&[]`, the last
    two as "measured nothing" rather than a clean run. Four are cases in
    `gates-have-teeth.sh`, with a fifth that must NOT fire when a relevance row's
    prose is reworded. Tests: six in `core::compliance`, of which
    `a_framework_is_enforced_or_merely_relevant_and_never_both` is the one the
    surface claim rests on and
    `asi07_is_still_absent_and_did_not_come_back_as_a_relevant_framework` is what
    stops the softer road back. Scenarios: `features/relevant-not-enforced.feature`,
    six, each bound.

    Writing the gate reproduced this file's own lesson about text gates twice in
    ten minutes, and both were found by the mutants rather than by reading. Its
    first const slicer looked for the terminator `\n];`, which is how the tuple
    list ends and is not how the struct list ends, so it ran past its subject and
    swallowed the whole catalog while printing the right answer by luck. Its
    second started the bracket scan at the first `[` after the name, which is the
    one in the TYPE, so it read the type annotation and parsed no id at all, and
    the NEGATIVE control is what caught that one.)*

34. **One binary runs two processes, and a door added to one of them is not a
    door.** `serve` (the LLM proxy) and `mcp_broker` (the MCP door) are separate
    process invocations that read their own environment and build their own
    state. Their enforcement call sites read identically, which is exactly why
    the difference is invisible: what is missing is a line nobody wrote, a
    thousand lines from the code it silently disables.

    Measured 2026-08-26: `chainproof::from_env()` was called in `mcp_broker` and
    nowhere else. `AppState::new` set `chain_proof: None` and nothing after it
    assigned one, so `chainproof::resolve` at proxy.rs ran against `None` on
    every request and returned `Chain::Claimed` every time. The delegation door
    shipped that morning with tests at both call sites and was switched on at
    one. The same wave then wired `revocations` into the broker only, which is
    the same defect committed twice in one day.

    **The subjects are DISCOVERED, never listed.** Every `<name>::from_env(`
    call in `main.rs` is found by reading the source, and which process it sits
    in comes from the line numbers. A gate carrying its own list of what to
    check is itself unchecked, and it goes stale silently at the exact moment
    somebody adds the thing it existed to notice. This is the fourth defect of
    that shape found on 2026-08-26 and the rule now has a name of its own.

    **A one-sided door is allowed and has to say why, at the call site.** The
    broker has no prompt firewall and no model router, because it never sees a
    prompt and picks no model. Those carry a `process-local:` reason within six
    lines above the call, so the exception travels with the code that needs it
    rather than sitting in a script nobody opens. A marker with nothing after
    it, or written in a form the gate does not read, is not an exception.
    *(gate: `scripts/both-processes-configure-the-same-doors.sh`, four cases in
    `gates-have-teeth.sh`: the one-sided door, an exception written in a form
    nothing reads, the discovery finding nothing at all, and a legitimate
    one-sided door it must not fire on. Scenarios:
    `features/the-delegation-door.feature`, seven, each bound to a named test.
    Doc: `docs/25-the-delegation-door.md`)*

    **And the harness that holds the gates now holds itself.** `gates-have-teeth.sh`
    was a hand-written list of cases with nothing checking that every gate on
    disk had one, which is the same shape one level up: a new gate with no case
    looks exactly like a gate with nothing to catch. Every `scripts/*.sh` must
    now be named by at least one case.

35. **A door that hands out a chain the RECORD refuses has verified a token
    whose trail cannot be written.** `agent-conform` runs `chain.Validate` on
    every `on_behalf_of` it reads, and the v0.2 envelope pins
    `pattern: ^(agent|user)://` on every item and `maxItems: 32` on the list. A
    chain this door produces that fails either is a token that verified and
    whose events are quarantined, which is the worst shape of all: green at the
    door, green in the log, and refused by the one thing that keeps the record.

    Measured 2026-08-27, three rules, all three found the same afternoon. The
    DEPTH cap counted actors where the record counts entries, so a subject plus
    32 actors made 33. The CYCLE rule was enforced only at the record, so a
    token whose `sub` also appeared in its `act` verified here. The ENTRY SCHEME
    was enforced only at the record, so `mailto:alice@acme.example` was accepted
    as a principal.

    **The duplication is structural and permanent.** The record's rules live in
    Go (`agent-stack-go/chain`), this door is Rust, and there is no seam between
    them. Nothing can share the code, so what stops the two drifting is a gate.
    agent-stack-go reached the same answer for its own pair, where
    `deps-layering.sh` forbids the import:
    `scripts/door-and-record-agree.sh` there discovers the record's rules from
    the errors `Validate` can return.

    **The scheme only, deliberately.** A stricter pattern here would refuse
    chains the record accepts, which is this same rule failing in the other
    direction, and one test passes before AND after to hold that line.
    *(tests: four in `crates/delegation`, three red against the unfixed
    assembler with the chain it handed out quoted verbatim, one green on both
    sides as the overshoot guard. Scenarios: `features/the-delegation-cap.feature`)*
36. **Whether a policy JUDGED an action is a separate fact from whether the
    action OCCURRED, and a door that keeps only the first keeps nothing for the
    deployment that configured no policy.** `emit_tool_call` sat inside
    `if st.wardryx.mode != WardryxMode::Off` in the MCP broker, so the whole
    per-action audit trail of that door was a side effect of having a PDP. The
    default deployment has none.

    Measured 2026-08-27 on the release binary, both directions, with
    `TOKENFUSE_WARDRYX_*` unset and a stub upstream over plain HTTP: a live
    `tools/call` that was brokered successfully wrote ZERO lines to
    `TOKENFUSE_EVENTS_PATH` against `main`, and one line against this branch,
    `{"type":"tool_call", ..., "data":{"decision":"allowed-ungoverned","tool":"gh_api", ...}}`.
    The call itself was served identically in both, which is what made the
    absence invisible.

    **The word is `allowed-ungoverned` and it is deliberately not `allow`.**
    The dependency plane already uses it for an outage that was let through
    (invariant 24), and `/v1/fuse/check-tool-call` answers `governed: false` for
    the same distinction (invariant 26). A third spelling would have made three
    consumers of one fact read three vocabularies, and writing `allow` would
    record a governance gap as a permission.

    **Exactly one record per brokered call, and only for one that was
    brokered.** Those are two halves and each fails differently. Two records say
    the agent called the tool twice, which makes every count of that tool wrong.
    A record written for a call that was refused before the upstream was
    contacted (the DLP block, the taint gate, the identity refusals, an unknown
    named upstream, a scope-denied secret) sends an auditor after an action
    nobody took. The gate's own deny and hold are the one refusal that keeps its
    record, because there a policy did judge, and a refusal is the row worth
    having.

    **A call attributable to nobody is counted, not passed over.** SPEC.md §6.1
    forbids inventing an `agent_id`, so the event is skipped; the emit is
    attempted anyway, so `Exporter::skipped_count` moves and `log_outcome` warns.
    Guarding the call site instead would make the same gap a branch that never
    runs, and an operator can read a counter where they cannot read an unentered
    `if let`.
    *(test: five in `tests/mcp_broker.rs`, of which
    `a_brokered_tool_call_is_recorded_when_no_policy_gate_is_configured` and
    `a_brokered_call_that_names_nobody_is_counted_as_skipped_not_never_attempted`
    were verified red against the unfixed tree, verbatim `left: 0 right: 1` for
    both; the other three are the guards that keep the fix from being worse than
    the defect and each was verified red against its own mutant rather than
    written green. Five mutants planted in the PRODUCT code 2026-08-27, all five
    caught: the one-record flag never set, so a governed call is recorded twice
    (`a_governed_tool_call_is_recorded_once_and_not_twice`, `left: 2 right: 1`);
    the emit moved above secret injection, so a scope-denied call is recorded as
    having happened (`a_call_refused_before_it_is_brokered_is_not_recorded_as_a_tool_call`);
    the gated emit narrowed to the allow arm, so a deny keeps no record
    (`a_refusal_the_policy_decided_is_still_recorded_exactly_once`,
    `deny: the refusal left 0 record(s)`); the ungoverned decision written as
    `Some(Allow)` (the same test plus
    `the_brokers_tool_call_record_carries_the_chain_and_what_proved_it`); and the
    emit put behind `if let Some(rid) = record_agent_id`, so the skip is never
    counted. Scenarios: `features/the-record-of-a-brokered-call.feature`, five,
    each bound to a named test. Doc: `docs/23-mcp-broker-v2.md` §3.

    Not a script gate: what would have to be checked is that every route through
    `process` reaching the upstream passes an emit, and the only mechanical form
    of that is a hand-written list of routes, which is the shape invariant 34
    names and this repository has now found six times. The routes are held by
    the tests instead, each naming the refusal it is about.)*

    **Where it says nothing.** The record is written before the POST, so a
    forward that fails at the transport is recorded as brokered. That is not new
    and not narrowed here: the gated site above it has always written before
    forwarding, and moving both after the answer would mean a call the upstream
    ran and never acknowledged goes unrecorded, which is the worse of the two.
    The LLM door is untouched; it keeps no `tool_call` of its own, because the
    tool-use blocks a model emits are the I1 `tool_calls` Parquet column
    (docs/21) and a different measurement.
