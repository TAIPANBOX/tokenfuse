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
./scripts/compat-surface.sh     # invariant 44; --write renders COMPATIBILITY.md
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

   **Fail-open at startup is not the same as silent at startup, and for the
   control plane it was.** Measured 2026-09-17 on the appliance proving run
   (tokenfuse#292): `TOKENFUSE_EVENTS_PATH` set on `tokenfuse-cloud`, pointed
   into the launchers' shared events directory (`root:10001`, mode 2775),
   reached by a process the image had created as uid 10001 with gid 999.
   `tokenfuse_core::agent_event::Exporter::from_env` opened the path, got
   `Permission denied`, handed back the disabled exporter and said nothing;
   the gateway's own wrapper warned on the same failure and the Cloud's
   `main.rs` called the convenience form that did not. Four `budget_exhausted`
   incidents existed and none reached the bus, and the log offered nothing to
   read. So `from_env` now hands back what happened beside the exporter
   (`Startup::Off` / `On` / `OpenFailed { path, error }`) and offers no form
   that swallows the failed case; `Startup::line` carries the one line and its
   level, so the gateway and the Cloud log the same words: the variable, the
   path, the operating system's error, and that the export is OFF. The unset
   case still costs nothing and logs nothing. The images create group 10001
   before the user and put the user in it, so `id` reads `uid=10001 gid=10001`
   (@measured on `debian:bookworm-slim` 2026-09-18: `useradd -r -u 10001`
   alone gives `gid=999` and `touch` in a `root:10001 2775` directory fails
   with `Permission denied`; with `groupadd -g 10001` first the file is
   created as `10001:10001`). The launchers pre-creating the file is their own
   change.
   *(partly gated: the mixed-schema test in `crates/gateway/src/sqlq.rs` covers
   the Parquet read path; the exporter's two promises are held by
   `a_disabled_exporter_does_no_work_at_all`,
   `an_unopenable_path_falls_back_to_disabled_rather_than_failing`,
   `a_directory_as_the_events_path_is_also_fail_open`,
   `an_empty_path_is_treated_as_unset` and
   `a_missing_agent_id_is_skipped_and_counted_never_invented`; the startup
   report by `crates/cloud/tests/events_export_startup.rs`, which runs the
   real `tokenfuse-cloud` binary against a 0500 directory and reads its log
   (`a_control_plane_whose_events_file_cannot_be_created_says_so_at_warn_and_keeps_running`,
   red on the unfixed binary with the whole startup log quoted: the keys
   error, `listening on`, and not one line naming the path; its guard
   `a_control_plane_with_a_writable_events_path_says_the_export_is_enabled`
   green on both sides), by
   `an_unwritable_directory_is_named_at_warn_and_the_export_is_off` in
   `gateway::events` (red on the wording: the old line named the path twice
   and never said the export was off) and by three in `core::agent_event`
   (`from_env_reports_an_unset_variable_as_off_with_nothing_to_log`,
   `from_env_reports_an_opened_file_with_its_path_and_where_the_chain_resumed`,
   `from_env_reports_an_unopenable_path_at_warn_and_the_export_is_off`);
   the images by
   `every_image_that_creates_uid_10001_creates_group_10001_first_and_puts_the_user_in_it`
   in `crates/gateway/tests/image_user_group.rs`, which walks the repository
   for every `Dockerfile*` rather than naming two, panics as having measured
   nothing if it finds none creating uid 10001, and was red naming both files.
   Scenarios: `features/the-events-file-that-cannot-be-created.feature`, six,
   each bound. Not a script gate: nothing stops a third process calling
   `from_env` and matching `OpenFailed` with `{}`, which the compiler cannot
   see; the binary-level test is what holds the Cloud)*
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
   syscall argument at a hard-coded `ctx.read_at::<u64>(24)`, so it is not
   CO-RE: it counts bytes where the port reads a BTF-typed
   `trace_event_raw_sys_enter`, and a layout that changes is a layout this
   crate would follow silently.

   **This sentence said "reads the wrong bytes anywhere else" until
   2026-09-09, and that was wrong.** `struct trace_entry` is 8 bytes, then
   `long id`, then `unsigned long args[6]` from offset 16, so `args[1]` is at
   24 on every LP64 architecture, aarch64 included. Confirmed by running: with
   the architecture refusal lifted in a throwaway copy, the program built for
   aarch64, loaded on Linux 7.0.12 aarch64, and reported both test
   destinations exactly as connected. 32-bit is genuinely different, and the
   refusal covers it.

   **That correction carried a false sentence of its own, corrected the same
   day.** It said the layout was "read off an aarch64 kernel's own BTF". No
   aarch64 BTF was read. The header that was actually consulted is idryx's
   committed `vmlinux.h`, and that one is x86_64's: its `struct pt_regs` runs
   r15, r14, r13, r12, bp, bx down to `orig_ax`, it defines `x86_hw_tss` and
   `desc_struct`, and it has no `user_pt_regs` at all (@measured `grep` over
   `internal/ebpfcapture/bpf/vmlinux.h` in TAIPANBOX/idryx, 2026-09-09).

   The conclusion stands, because neither support it actually rests on
   involves that header: the offset follows from the C types under any LP64
   ABI, and the program was then run on aarch64 and reported correctly. A
   conclusion that is right for an invented reason is worse than one that is
   wrong, because being right stops anybody checking the reason.

   The correction is left here rather than swapped for a better sentence
   because this invariant is the argument for where work happens, and an
   argument resting on a false premise is one somebody re-derives. The
   remaining reasons stand on their own: the port is CO-RE by construction
   rather than by two measurements, and radar is not where the sensor grows.
   `main.rs`'s loopback filter admits ports 11434 and 8000 but not 8001, while
   its own `is_llm` lists 8001 as a vLLM port, so that branch is unreachable
   and a local vLLM on 8001 is never reported. And it drops its own traffic by
   comparing `comm`, which any process can rename with `prctl`; the port
   compares PID.

   The structural half mattered as much: this file held twenty invariants and
   none of them was about radar, the crate had no tests at all, and its CI job
   ran `cargo build` and stopped. The most fragile code in the repository had
   the least holding it. The tests and the `cargo test -p radar` step landed
   the same day.

   A fourth defect, 2026-09-08, found by running idryx's port of this sensor
   (idryx#67): `is_llm` flagged a provider address on ANY port, and a resolver
   choosing a source address per RFC 6724 connect()s every candidate address
   and sends nothing (Go on 53, glibc on 0, musl on 65535), so a process that
   merely resolved api.openai.com printed as one that called it. The flag now
   requires port 443, the one port those providers serve.
   *(test: `a_provider_address_is_llm_traffic_only_on_443`, red before the
   change; bound from `features/radar-provider-flag.feature`)*

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

   **The RSA modulus is bounded too, one layer down from this rule, and that
   was checked rather than assumed.** `algorithms_for_key` names which
   algorithms an RSA key may use and says nothing about how big it may be.
   On the proof path (invariant 30) the key comes from the PRESENTER's own
   proof header, RFC 9449 requires exactly that, so an unauthenticated caller
   at the MCP broker's door picks the modulus a verify attempt runs against,
   the same reachability agent-stack-go#59 (2026-09-16) found on the Go side:
   an all-ones 48 KiB modulus cost that verifier 1.34s against 245us for a
   real 2048-bit key, and the caller needs no matching private key to make a
   verifier pay for it, only bytes shaped like a signature. `jsonwebtoken`
   9.3.1's RSA path goes through `ring` 0.17.14's
   `ring::rsa::verification::verify_rsa_` (`ring-0.17.14/src/rsa/verification.rs:198`),
   which calls `public_key::Inner::from_modulus_and_exponent`, which calls
   `PublicModulus::from_be_bytes` (`ring-0.17.14/src/rsa/public_modulus.rs:39`)
   BEFORE `key.exponentiate`. That function is TWO check sites, not one, run
   back to back right after the modulus bytes are parsed into a big integer
   (line 56) and before the Montgomery setup (line 72). `public_modulus.rs:66-68`
   compares the modulus's byte-rounded bit length against `min_bits`, and
   `min_bits` is the PARAMETER SET's floor, not a fixed constant: it is
   passed in by the caller (`verification.rs:216`, `params.min_bits`) and
   `jsonwebtoken`'s own `RSA_PKCS1_2048_8192_SHA256` (the set RS256 uses)
   sets it to 2048. The 1024 that also appears near this check, at line 62,
   is a different thing: `assert!(min_bits >= MIN_BITS)`, an unconditional
   sanity floor on whatever `min_bits` the caller passes, never the floor a
   real verify runs against. So `public_modulus.rs:66-68` is exactly the
   code that enforces the 2048-bit floor, `KeyRejected::too_small()` on
   anything shorter, and it IS reachable: the modulus comes from an
   unauthenticated presenter's JWK (invariant 30 again), the same
   reachability the 8192-bit ceiling below has, just at the other edge. A
   real 1024-bit and a real 2040-bit RS256 proof, each signed offline the
   same way the 8192-bit fixture below is (ring's signing side refuses a
   key this small: `RsaKeyPair::from_pkcs8` takes a modulus of at least
   2047 bits and at most 4096, so neither a 1024-bit nor an 8192-bit key
   can be signed with through it, and both were signed with
   `openssl dgst -sha256 -sign`,
   outside ring entirely), are both refused here rather than accepted or
   refused somewhere else; `a_2040_bit_rsa_proof_signed_offline_is_refused_below_the_2048_bit_floor`
   below pins the 2040-bit case as a permanent test. And `public_modulus.rs:69-71`
   refuses anything over `PUBLIC_KEY_PUBLIC_MODULUS_MAX_LEN`, hard-coded in
   `ring-0.17.14/src/rsa.rs:31` as `BitLength::from_bits(8192)` and shared by
   every `RSA_PKCS1_*_2048_8192_*`/`RSA_PSS_*_2048_8192_*` parameter set
   `jsonwebtoken` uses. So the same 8192-bit ceiling the Go fix added by hand
   is already enforced here, one dependency down, before any modular
   exponentiation runs, and a modulus over it is `KeyRejected::too_large()`
   at parse time rather than a signature failure after the cost is paid.

   **Measured on both sides of the boundary, not only on an extreme, and the
   first draft of this paragraph over-read its own number.** `@measured`
   `cargo test -p tokenfuse-dpop --release` 2026-09-16, four tests, each
   printing one `verify_proof` call's elapsed time: a real, accepted
   2048-bit signature (`a_2048_bit_rsa_proof_is_accepted_and_verifies`, the
   fixture key `crates/cloud/tests/oidc.rs` also signs OIDC bearer tokens
   with) verifies in about 51-59us; a real, accepted 8192-bit signature at
   ring's own ceiling (`an_8192_bit_rsa_modulus_at_the_ceiling_is_accepted_and_verifies`,
   signed offline with a freshly generated 8192-bit key via `openssl dgst
   -sha256 -sign`, since ring's OWN signing side,
   `RsaKeyPair::from_pkcs8`, caps a private key at 4096 bits,
   `PRIVATE_KEY_PUBLIC_MODULUS_MAX_BITS` at `ring-0.17.14/src/rsa.rs:35`,
   half the verify side's ceiling, so this crate cannot sign its own
   8192-bit fixture) verifies in about 293-307us, real work a caller who
   stays inside the bound can still force, larger than the 2048-bit case
   because the modulus is; and a modulus refused eight bits OVER the
   ceiling, 8200 bits, on a header small enough that the refusal's own cost
   is visible (`an_8200_bit_rsa_modulus_eight_bits_over_the_ceiling_is_refused_before_the_expensive_part`)
   is refused in the tens of microseconds (three isolated `--release` runs
   on this machine, `@measured` 2026-09-16: 44us, 46us, 326us, the last one
   a cold-run outlier), well
   under a fifth of an ACCEPTED verify at the ceiling, which is the number
   that shows no exponentiation ran. The first draft of this line cited
   12-16us; that did not reproduce at that magnitude on a re-measure and is
   widened here rather than re-pinned to a number this sensitive to the
   machine and the run.

   The 48 KiB all-ones case
   (`an_oversized_rsa_modulus_is_refused_before_the_expensive_part_not_after`)
   was re-measured the same way and answers about 165us in release, not the
   2.8ms first written here: that 2.8ms is a real number, `cargo test -p
   tokenfuse-dpop` (the debug profile CI and a plain local run both use)
   still reports it, but it is mostly debug-build base64/JSON parsing of the
   proof's own 64 KiB header (the 48 KiB modulus, base64-inflated by about a
   third, sitting inside the header JSON `verify_proof` decodes before the
   key ever reaches `ring`), not `ring`'s own check; the 8200-bit case above
   isolates that check on a header nowhere near 64 KiB and measures far
   under it in both profiles. And 2.8ms against the Go side's 1.34s is
   roughly 480x, not the three orders of magnitude (roughly 1000x) first
   written here: still two-and-a-half orders, still the same conclusion,
   overstated by about double.

   This bound is `ring`'s, not this crate's own code, so a dependency bump
   that changed the backend's parameter constants could move it without this
   file saying so, the same caveat this invariant already makes about the
   alg-family check two paragraphs up.

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
- **Invariant 6**'s exporter half is now five tests, plus the startup report
  added on 2026-09-18 (tokenfuse#292). Both promises stop being
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

    **A body with no `revocations` array, or a null one, is refused and never
    read as an empty list.** `revocations` carries no `#[serde(default)]`: a
    snapshot silent about the member, or one that names it `null`, is a parse
    error rather than an honest empty list, because those are not the same
    fact and reading the second as the first is how a wrong upstream, a proxy
    in the way, or anyone else who can shape that response empties every
    revocation this process holds. An entry that is not a JSON object is
    refused the same way (an entry `[]` or `["dead"]` would otherwise decode
    positionally into a record `vouchryx` never sends), which is the rule Go's
    `ParseSnapshot` states since agent-stack-go#62. `as_of` keeps its own
    default, since a missing or zero cursor is refused one layer down by
    [`Install::NoCursor`] regardless.
    *(scenarios: `features/revocation.feature`, twenty-two: invariant 48 added
    two and the 2026-09-17 review's fix added a third, each bound to a named
    test. Test: twenty in `delegation::revocations`, eighteen of them run
    against a `check` stubbed to `|_, _, _| false`, which is what the doors
    do today;
    fourteen went red there, verbatim among them `left: Never right: Stale {
    age_secs: 61 }` and `tok-1 was answered from the list: Answer { revoked:
    false, basis: Never }`. One stayed red past the stub and found a real
    defect: a derived `Deserialize` reads `[]` positionally into an empty
    snapshot, so `Snapshot::from_json` now refuses a body that is not a JSON
    object. A twentieth,
    `a_snapshot_with_no_revocations_array_is_an_error_not_an_empty_list`, is
    the Rust twin of the same review's F4 (its probe
    `TestCodexInvariant19MalformedSnapshotCannotEraseKnownRevocation` sits in
    a private evidence archive and is not runnable from here): a
    body missing the member parsed the same way `[]` once did, `install`
    accepted it, and a held revocation for a live jti answered not revoked.
    Eight mutants planted in the product code on 2026-08-26, all eight caught,
    each named with the test that caught it in the pull request; a ninth,
    `#[serde(default)]` restored on `revocations`, caught by the new test on
    2026-09-17. The two worth naming here are the ones the design turns on:
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

37. **`TOKENFUSE_IDENTITY_STRICT` defaults to `enforce`**, since 2026-08-27,
    and `off` is one explicit variable away, which is the difference between a
    default and a prohibition.

    It was `off`, so the binding check this product advertises did nothing until
    somebody set a variable. That is the shape `crate::defaults` already argued
    on 2026-08-06 about `TOKENFUSE_DLP` and `TOKENFUSE_REQUIRE_RUN_ID`: a
    deployment governed on paper, every check green because the checks read
    configuration rather than behaviour.

    **The blast radius is measured, not asserted.** A mismatch needs something
    to mismatch WITH, and both sources are opt-in: the key-binding check needs
    `TOKENFUSE_CLIENT_KEYS` with per-key agent scoping, and
    `agent_id_contradicts_proven_chain` needs a delegation issuer. So a
    deployment that configured neither sees no change, and one that configured
    either had already opted into the identity it is now held to. Two tests say
    so rather than this paragraph:
    `a_deployment_that_opted_into_nothing_is_unaffected` and
    `a_deployment_that_opted_in_is_now_held_to_it`.

    **A misspelt mode exits rather than resolving either way.** Falling back to
    `enforce` refuses traffic the operator did not ask to refuse; falling back
    to `off` disables a check they believe they turned on. Both are worse than
    stopping. Case is not the operator's job: `Off` is `off`, and a deployment
    that wrote it in a compose file means it.

    The decision is split from the environment read (`StrictMode::from_value`)
    for the reason `defaults` splits its own: a default is a claim about what
    happens when nobody configures anything, and **before this change the
    setting whose default it reverses had no test pinning that default at all**.
    *(tests: `the_mode_an_operator_falls_into_is_enforce`, proved red against
    the old value; `every_named_mode_is_honoured_and_off_still_means_off`;
    `a_misspelt_mode_is_refused_rather_than_guessed`;
    `case_is_not_the_operators_job`. Scenarios:
    `features/the-delegation-door.feature`)*

38. **A cap that silently stops accumulating is a cap that silently lies about
    what it measured.** `UsageParser::CAP` (8 MiB, `crates/gateway/src/provider.rs`)
    truncated a response's buffered body with no flag, no count, no log:
    `feed()` just stopped, and `finish()` parsed whatever fit. Its own doc
    comment claimed the settle path "may fall back to the pre-flight estimate"
    once cut, but nothing made that true - a body whose usage arrived early
    (Anthropic's `message_start`, near the front) and whose CUMULATIVE
    `output_tokens` arrived late (the final `message_delta`, exactly what an
    oversized response pushes past the cut) settled on a real, computed,
    silently-short cost, not the estimate the comment promised.

    `feed` now sets `truncated` the moment a byte is dropped, and `finish()`
    returns it beside the `Usage` in a `ParsedUsage`. The settle side is one
    function, `settle::settle_amount`, called by `SettleGuard::settle_now`, which since
    invariant 50 (2026-09-18) is the one settle site for both paths (until then
    `proxy::buffered_managed` was a second caller of the same function) - the same
    one-copy-not-two-agreeing-verbatim-copies shape invariant 29 already holds
    for algorithm rules, applied here so a body that overruns the cap is
    handled identically regardless of which path the client's request took.
    It returns which of three bases the charge rests on: `Parsed` (real usage,
    the cap never touched it), `EstimateNoUsage` (nothing to price, not the
    cap's doing), `EstimateTruncated` (the cap cut it, and whatever partial
    usage survived - even a real-looking, nonzero one - is never priced). A
    truncated settlement gets a `tracing::warn!` naming the model and the
    buffered bytes, and an aggregate in-process counter
    (`KeyStats::record_truncated_settlement`, same shape as the existing
    `unauthorized_since_startup`) surfaced on `GET /v1/keys` as
    `truncated_settlements_since_startup` (`docs/22-key-lifecycle.md`).

    **No Parquet column.** `CallRecord` (`crates/gateway/src/sink.rs`) has 116
    struct-literal constructions across 13 files in two crates, none via
    `Default` or a spread pattern; a fourth `cost_basis` column next to
    `input_tokens`/`output_tokens` was the obvious next step and, measured
    against those 116 sites, was not the small, pattern-following change
    invariant 6's nullable-evolution note describes for this same file, so it
    was not made. The basis is proven at the settle-decision level instead
    (`settle_amount`'s own tests, naming each of the three cases directly) and
    at the ledger level: a trusted partial usage and the honest estimate
    cannot coincide by construction in the test fixtures, which price the
    partial usage at $1.50 against a $1.00 estimate, so a mutant that treats
    truncated as parsed moves a real number, not just a label.

    **Not recording the column is not the same as not recording the shape,
    and the first version of this fix confused the two.** Review on the same
    PR read `focusexport::to_row` (that module's own doc, "Cost basis and
    `x_blocked`"): it infers a row's FOCUS `x_cost_basis` from the CallRecord
    it already has, not from anything new - zero tokens beside a nonzero cost
    reads `"estimated"`, everything else reads `"settled"`. The first version
    of `settle_amount` priced a truncated body on the estimate correctly but
    still returned the PARTIAL parsed usage for the record, so a truncated
    call with real-looking nonzero tokens beside its estimated cost was the
    exact `"settled"` shape - the FOCUS export, and CostCrew reading it, would
    have called an estimated call settled. `settle_amount` now returns
    `Usage::default()` whenever `truncated`, the same all-zero shape a body
    with no usage at all gets, which is a real loss (whatever partial counts
    survived the cut are gone from the record, not only unpriced) traded for
    not lying to a downstream billing export. The `tracing::warn!` was fixed
    alongside it for a related reason: it named "the pre-flight estimate" as
    if charging one were certain, but a refused call whose error body also
    overran the cap settles zero, same as any refusal, so the log line now
    names the actual `settled_microusd` charged instead of asserting which
    case it was.
    *(test: `crates/gateway/src/provider.rs`:
    `a_body_whose_usage_block_lands_after_the_cap_is_reported_truncated` (red
    against the unfixed `feed`, verbatim "a body cut at the cap must say so,
    not parse silently"), `a_chunk_that_exactly_fills_the_cap_is_not_truncated`,
    `a_zero_byte_chunk_after_the_cap_is_not_truncated_by_itself`,
    `a_single_chunk_larger_than_the_cap_is_truncated`.
    `crates/gateway/src/settle.rs`: `settle_amount_prices_real_usage_as_parsed`,
    `settle_amount_falls_back_to_the_estimate_when_the_body_carried_no_usage`,
    `settle_amount_falls_back_to_the_estimate_when_truncated_even_with_partial_usage`,
    `settle_amount_on_no_slot_write_at_all_is_estimate_no_usage`,
    `a_truncated_result_settles_on_the_estimate_and_counts_it`,
    `a_parsed_result_under_the_cap_does_not_touch_the_truncation_counter`,
    `a_body_under_the_cap_with_no_usage_settles_the_estimate_without_counting_as_truncated`.
    `crates/gateway/src/keystats.rs`: `truncated_settlement_counter_is_aggregate_only`,
    `truncated_settlement_counter_is_independent_of_unauthorized`.
    `crates/gateway/src/keysreport.rs`:
    `truncated_settlements_since_startup_reflects_keystats`. Four mutants
    planted in the product code 2026-09-02, each caught: the two
    `truncated = true` assignments deleted from `feed` (caught by the first
    and fourth `provider.rs` tests above); `settle_amount`'s truncated
    short-circuit deleted entirely, so a truncated result is priced AND
    recorded like a parsed one (caught by
    `settle_amount_falls_back_to_the_estimate_when_truncated_even_with_partial_usage`
    and `a_truncated_result_settles_on_the_estimate_and_counts_it`, both on the
    real $1.00-vs-$1.50 figures); the short-circuit's `Usage::default()`
    reverted to the partial `usage` alone, pricing still correct but the
    focusexport regression back (caught by the same two tests, now on the
    zero-vs-500000-token figures); the counter's two increments deleted from
    `KeyStats::record_truncated_settlement` (caught by four tests across three
    files: both in `keystats.rs`, `a_truncated_result_settles_on_the_estimate_and_counts_it`
    in `settle.rs`, `truncated_settlements_since_startup_reflects_keystats` in
    `keysreport.rs`). No `features/*.feature` scenario:
    `scripts/features-are-bound.sh` checks that existing scenarios stay bound,
    it does not require a new one per change, and inventing a Given/When/Then
    not spoken by the user is the failure the Gherkin layer exists to
    avoid.)*

39. **A trace that only reaches disk at a threshold or on exit is a trace an
    operator making a handful of calls cannot see.** Measured on the v0.4.1
    image, plan item A9: with `TOKENFUSE_DATA_DIR` set and five calls made,
    the directory stayed empty until the gateway got SIGINT; `docker stop`
    (SIGTERM) did not flush it either. `ParquetSink::new(&dir, 256)` writes a
    segment at 256 buffered records or on `Drop`, and neither is a promise an
    operator watching a live directory can rely on: 256 calls is a lot of
    silence for a ten-call trial, and `shutdown_signal()` awaited `ctrl_c()`
    only, so the ONE path that did flush (SIGINT, via `Drop`) was not the one
    a container's normal stop actually sends.

    Two independent fixes, because they were two independent gaps.
    `sink::spawn_periodic_flush` ticks `ParquetSink::flush` every two
    seconds, the same cadence `main.rs` already used for `CloudSink` (the
    pattern this mirrors rather than invents); it is wired only when
    `TOKENFUSE_DATA_DIR` is set, same as the sink itself. `shutdown_signal()`
    now selects `ctrl_c()` together with `SIGTERM` on Unix
    (`tokio::signal::unix::signal(SignalKind::terminate())`), with a
    `#[cfg(not(unix))]` arm that never resolves so non-Unix builds keep
    compiling and keep their old ctrl_c-only behaviour. SIGTERM needed no new
    flush logic of its own: axum's graceful shutdown drops the serve future's
    captured state on either signal, so `ParquetSink::drop`'s existing flush
    already ran on SIGTERM once the future was actually told to stop for it.

    **An idle tick must write nothing, or the fix would trade "too rare" for
    "too many empty files".** `ParquetSink::write_batch` already returned
    early on an empty slice, before the segment path is built or the sequence
    counter advances - true before this change and unchanged by it, and
    tested here by name rather than left to be re-derived from reading
    `write_batch`.
    *(test: `a_periodic_flush_reaches_disk_without_shutdown_or_a_full_buffer`,
    verified red against a periodic-flush task with the `flush()` call
    deleted, verbatim `left: 0 right: 1`; and
    `a_periodic_flush_of_an_empty_buffer_writes_no_segment` for the other
    half, both in `gateway::sink`. SIGTERM has no clean unit-test path in this
    workspace (no signal-sending dependency here, and adding one for one test
    is the escalation this repository avoids), so it was verified with a real
    build instead: `TOKENFUSE_DATA_DIR` + `TOKENFUSE_ALLOW_STUB=1`, one call
    with `x-fuse-run-id`, `SIGTERM` sent 26ms later - well under the two-second
    tick, so the periodic path cannot be what wrote the file - and the segment
    was on disk and readable by `tokenfuse sql` after the process exited, its
    whole lifecycle 58ms start to exit.)*

40. **A binary that cannot say what it is has to be run to find out.** Plan item
    A12, measured on the v0.4.3 download: `tokenfuse --version` and `tokenfuse
    --help` both printed the `TOKENFUSE_UPSTREAM` refusal and exited 2, because
    neither flag was a subcommand `main.rs`'s dispatch recognised, so both fell
    through to `_ => serve().await`, which is the one place this binary reads
    that variable at all.

    Both are now answered before the dispatch match even runs, so they cannot
    reach the precondition. `--version`/`-V` prints one line,
    `tokenfuse <version> (<sha>)`; `--help`/`-h` prints every real subcommand,
    read off `main.rs`'s own match arms rather than retyped from memory, plus
    the two variables that decide whether a plain start actually starts. A
    plain start with neither flag is untouched: it reaches the same
    precondition on the same message it always has.

    **The version and sha are stamped at compile time, and an unstamped build
    says so rather than guessing.** `option_env!("TOKENFUSE_VERSION")` /
    `option_env!("TOKENFUSE_GIT_SHA")` read whatever the COMPILER's own
    environment held; `.github/workflows/release.yml` sets both
    (`TOKENFUSE_VERSION=$GITHUB_REF_NAME`, `TOKENFUSE_GIT_SHA=${GITHUB_SHA::7}`)
    and the Dockerfile takes them as build args, verified separately: an ARG
    declared before a `RUN` is a real environment variable to that RUN's shell
    AND its children, `cargo`/`rustc` included, with no `export` needed. A
    plain `cargo build` (every developer checkout, and this crate's own test
    binary) has neither set, and `crates/gateway/Cargo.toml`'s workspace
    `[package] version` is `0.0.1` on every tag, so falling back to a bare
    `CARGO_PKG_VERSION` would print a real-looking release number for a build
    that is not one. The fallback is `-dev`/`dev` instead, which is what
    invariant 4 already asks documentation to do: state a limitation rather
    than bury it.

    Both new names are declared in `components.json`
    (`every_environment_variable_this_repository_reads_is_declared_and_the_reverse`,
    `tests/manifest.rs`) even though neither is read by the running PROCESS
    the way every other entry there is - `option_env!` is a compiler-time
    substitution, not a `std::env::var` call - because that gate scans
    non-test source for the literal `TOKENFUSE_` text and does not
    distinguish the two, and a name it finds undeclared fails it regardless of
    which kind of read introduced it.
    *(test: `crates/gateway/tests/version_and_help.rs`, six, run against the
    real built binary with `TOKENFUSE_UPSTREAM`/`TOKENFUSE_ALLOW_STUB`
    explicitly removed from its environment, so a pass means "answered before
    the precondition check" and not "happened to pass it";
    `version_prints_one_line_and_exits_0` is the one run red against the
    unfixed binary first, verbatim exit `Some(2)` where `Some(0)` was
    asserted, stderr the `TOKENFUSE_UPSTREAM` refusal in full;
    `a_plain_start_with_no_upstream_still_refuses_exactly_as_before` pins the
    unmoved regression case and was already green before this change existed.
    Four in `tests/manifest.rs`, of which
    `every_declared_subcommand_is_one_the_binary_dispatches_on` is the guard
    against `--help`'s list drifting from what `main.rs` actually runs.)*

41. **A door with something behind it still has to be a door.** `/v1/runs`,
    `POST /v1/runs/{id}/kill`, `/v1/keys`, `/v1/policy-plane` and
    `/v1/agent-ids` were registered with no authentication at all. The
    comment beside them said the gateway binds loopback by default, which is
    true and was not the whole picture: the shipped `Dockerfile` sets
    `TOKENFUSE_ADDR=0.0.0.0:4100`, and stack-single documents that port as the
    one "agents elsewhere must reach". Published, anyone who can reach it can
    list every run's budget and spend, list key ids, enumerate agent
    identities, and kill any run.

    The fix mirrors invariant 20's shape rather than inventing a second one.
    `TOKENFUSE_ADMIN_KEYS` (comma-separated bearer keys, same trimming as
    `TOKENFUSE_CLIENT_KEYS`) configured means every one of the five routes
    needs `Authorization: Bearer <key>` regardless of the bind, or `401`.
    Unconfigured on a loopback bind changes nothing. Unconfigured on a
    non-loopback bind refuses every request to the five routes with `403
    admin_keys_required`, with one startup warning naming
    `TOKENFUSE_ADMIN_KEYS`; `TOKENFUSE_ALLOW_OPEN_OBS=1` opts back into the
    old open behaviour, parsed like `TOKENFUSE_MCP_ALLOW_OPEN_BIND` (only `1`
    or `true`), and does not silence the warning.

    **A per-request refusal, not a startup one**, and that is the one place
    this departs from invariant 20's precedent rather than copying it. A bad
    bearer key on `/v1/keys` is not the emergency a vault with a stranger's
    hand in it is, so an operator who forgets the variable on a wide bind
    gets a `403` there and a working `/v1/messages` beside it, not a gateway
    that refuses to start at all.

    Loopback is asked of the standard library
    (`mcpbroker::is_loopback`, reused rather than reimplemented, via
    `adminkeys::bind_is_loopback`), never matched as a string, for the same
    reason invariant 20 asks it: a REFUSAL is wrong in both directions if it
    undercounts or overcounts loopback, and a warning can afford to be looser
    than that.

    Constant-time comparison (`subtle::ConstantTimeEq`, length checked first)
    is new for this repository's own bearer doors: `ClientKeys::resolve` and
    the Cloud's own bearer lookup are plain `HashMap`/`==` by deliberate,
    documented choice, and this does not change either of them. `subtle`
    2.6.1 was already resolved in `Cargo.lock` as a transitive dependency of
    `p256`/`elliptic-curve` (which `crates/dpop` and `crates/delegation`
    already pull into this crate's graph), so naming it directly in
    `crates/gateway/Cargo.toml` adds no new crate to the workspace.

    `/healthz` and `/v1/messages` are never behind this gate: `axum`'s
    `route_layer` applies the middleware only to the sub-router the five
    routes are registered on, merged into the main router afterward.
    *(test: `an_open_bind_with_no_admin_keys_refuses_kill_and_runs`,
    `a_loopback_bind_with_no_admin_keys_keeps_the_routes_open`,
    `a_configured_admin_key_opens_the_routes_and_a_wrong_one_does_not`,
    `the_allow_open_obs_opt_out_is_honoured_and_logged` and
    `healthz_and_messages_are_never_behind_the_admin_gate` in
    `crates/gateway/tests/admin_gate.rs`, run against the real router
    `tokenfuse_gateway::app` builds; thirteen unit tests in
    `gateway::adminkeys` for `AdminKeys::from_spec`, `AdminKeys::matches` and
    `AdminGate::resolve`. All five integration tests were run against the
    unfixed tree first: `adminkeys` did not exist and `AppState` had no
    `with_admin_gate`, so the suite failed to compile. Scenarios:
    `features/admin-gate.feature`, five, each bound to a named test. Not a
    script gate: the five routes are a hand-written list at the call site
    (`lib.rs::app`), the same shape invariant 34 already names, and there is
    no mechanical way to notice a sixth admin-shaped route added outside it.)*

42. **Shadow mode records the refusal it did not make.** The README has said
    since the first release that the budget starts in shadow mode and "records
    what it would block but changes nothing". Until 2026-09-13 that was true of
    `max_steps` and `budget_per_step`, which set `x-fuse-would-block`, and
    false of the run budget itself: the shadow arm called `reserve_unchecked`,
    recorded the spend and said nothing, so a shadow week left no header, no
    event and plain `allow` rows for every call enforce would have refused.
    `BreakerVerdict.would_trip_only` existed and nothing set it. An operator
    sizing a budget before turning enforce on had the ledger total and nothing
    per call. RUN-6 of the 1.0 proving run found it on the released v0.5.0
    image, on the Mac and again under stack-single.

    The fix asks the ledger the checked reserve's own question first,
    `LedgerBackend::would_exceed`, computed by the same rule over the same
    chain (`Ledger::would_exceed` mirrors `Ledger::reserve` line for line
    without reserving), so on the in-process ledger the shadow signal and the
    enforce refusal come from one rule. Not from one lock: the question and
    the `reserve_unchecked` that follows are two acquisitions, so two
    concurrent shadow calls on one run that together exceed the cap can both
    read "fits", and the NEXT call on that run carries the signal. Advisory,
    bounded, written down rather than closed. When it says the call would be
    refused, shadow and warn set
    `x-fuse-would-block: budget_exceeded: <reason>` (appended after any
    `max_steps` or loop reason already there) and emit ONE `breaker_shadow`
    event (medium), the firewall's `taint_shadow` beside `taint_block` being
    the precedent: `breaker_tripped`'s `data` plus `mode` (`shadow` or `warn`),
    and a different type, so a consumer counting refusals never counts a call
    that was forwarded. Then `reserve_unchecked` records the spend exactly as
    before. Enforce is untouched and emits no shadow event.

    Where it says nothing, named so the next reader does not infer it: the
    Parquet row of a shadowed call is still `decision: "allow"` (`CallRecord`
    has no would-block column; `tokenfuse backtest` over the trace is the
    offline way to ask the same question). The unit monthly cap (docs/20) in
    shadow and warn still records nothing at all: `units.reserve_unchecked`
    has no header and no event where enforce refuses `unit_budget_exceeded`
    and emits `unit_cap_exceeded`; the same mirror over
    `UnitLedger::try_reserve` is the obvious next step and is not in this
    change. Without `TOKENFUSE_EVENTS_PATH`, or on a request with no
    `x-fuse-agent-id` (the exporter skips an envelope with no subject), the
    header is the only record and the agent sees it, not the operator. On the
    raft backend the question walks the same chain over the local,
    eventually consistent read (under-reports on a lagging follower,
    over-reports if a budget raise has not replicated), and the raft
    `reserve_unchecked` is older and worse than either: it submits a checked
    `Reserve` and ignores `accepted`, so the state machine refuses an
    over-budget shadow call, reserves nothing, does not advance `steps`, and
    the spend lands only at `Settle`. A `Request::ReserveUnchecked` variant is
    a raft schema decision (invariant 5, `replicated-shape.sh`); HA is compiled
    out of every shipped image, so it waits.
    *(tests: `proxy::tests::shadow_over_run_budget_is_forwarded_and_says_so`,
    `warn_over_run_budget_is_forwarded_and_says_so`,
    `shadow_at_exactly_the_budget_is_not_flagged`,
    `shadow_flags_the_parent_budget_a_child_would_exhaust`,
    `enforce_over_run_budget_emits_breaker_tripped_and_no_shadow`, and
    `ledger::tests::would_exceed_mirrors_reserve_without_reserving`; the three
    behaviours were red on the unfixed tree first. Mutants, each caught by a
    named test: `>=` for `>` in the check, the chain replaced by the own run,
    the event dropped, `breaker_tripped` emitted in its place, the header
    dropped, `reserved` forgotten in the mirror, the header overwritten
    instead of appended. Scenarios: `features/shadow-records-the-refusal.feature`,
    seven, each bound. `contracts/tokenfuse-constants.json` regenerated: 19
    event types. Landed in one motion with two sibling changes, because
    estate-gates C4 reads this crate's `as_wire_str` arms against SPEC 6.2
    and C8 reads SPEC against trailryx's mapping: agent-passport SPEC.md's
    tokenfuse row gains `breaker_shadow` (medium), and
    `trailryx-agentevent` maps it as it maps `taint_shadow`.)*

43. **A settlement is `Parsed` only when a priced token count was parsed.**
    `settle_amount` used to read "did the body carry usage" as
    `usage != Usage::default()`. That was the right question until I1
    (docs/21) added `tool_calls` to `Usage`: a response with no usage block at
    all still parses as JSON, `ToolCallCounter::finish` answers `Some(0)` for
    it, and the struct is no longer default while every token count is zero.
    The cost of zero tokens is zero, so the call settled as `Parsed` for
    nothing: 0 tokens, 0 microusd, `spent_usd` unmoved, for a completion
    delivered in full. On the OpenAI door a caller reaches that state with one
    field, `stream_options: {"include_usage": false}`, which the gateway
    rightly never overrules; a provider that honours the flag then sends no
    usage chunk (OpenAI by its own reference, quoted in docs/26; Ollama and
    Bedrock's OpenAI door as measured). RUN-3 of the 1.0 proving run measured
    it on those two, 2026-09-13, on the released v0.5.0 image (tokenfuse#283).
    Vertex Gemini and OpenRouter, one model each, send usage regardless of the
    flag and settled right. A buffered answer with no `usage` object went
    through the same function and the same hole.

    The fix asks the question the doc always meant: `Usage::carries_priced_tokens`
    (in `tokenfuse-core`, beside the fields it reads and `ModelPrice::cost`'s
    own list, so a fifth priced field is added to both in one file), true when
    any of the four token counts is nonzero. The stub provider asks it the same
    way where it used to compare against `Usage::default()`. Everything else
    keeps its shape: the estimate is what a 2xx with no usage settles on
    (`EstimateNoUsage`), a refusal still settles zero (`provider_refused`), a
    truncated body still settles the estimate and records `Usage::default()`,
    and `tool_calls: Some(0)` stays on the record as the observation it is.
    Two cases the fix newly reaches, both conservative and both the pre-I1
    behaviour: a 2xx whose JSON is an error object, and a 2xx whose usage block
    is explicitly all zero, settle the estimate too; v0.5.0 charged both
    nothing. docs/26's mutant table already named "treat a `null` `usage`
    chunk as parsed usage: every streamed run settles at zero"; the side field
    was the way that mutant shipped.

    Where it says nothing: a response whose only nonzero count is cache reads
    is `Parsed` here, but `CallRecord` carries no cache columns, so its row is
    zero tokens beside a nonzero cost and the FOCUS export labels it
    `estimated` (`focusexport::to_row` reads shape alone); a cache column is
    invariant 6 work, not this change.
    *(tests: `settle::tests::settle_amount_treats_zero_tokens_beside_a_tool_call_count_as_no_usage`,
    `settle_amount_on_an_unknown_model_with_no_tokens_is_still_the_estimate`,
    `settle_amount_prices_a_cache_read_only_response_as_parsed`, and through
    the router with the REAL `UsageParser`, `tests/no_usage_stream_settles_on_the_estimate.rs`:
    `a_stream_with_no_usage_block_settles_on_the_estimate_not_zero` (the
    fixture is Ollama's `include_usage: false` stream, byte shape for byte
    shape), `a_stream_with_usage_null_on_every_chunk_settles_on_the_estimate_not_zero`,
    `a_stream_with_a_usage_block_settles_on_the_usage_not_the_estimate`,
    `a_buffered_answer_with_no_usage_object_settles_on_the_estimate_not_zero`.
    The five no-usage tests were red on the unfixed tree first (`left: 0`,
    `right: the estimate`); the cache-read test and the usage-stream control
    are the guards and pass on both sides. Mutants, each caught by a named
    test: the old guard restored (red in both layers); `carries_priced_tokens`
    always true (six `settle::tests`, `proxy::tests::client_cancel_midstream_still_settles`
    and both router no-usage tests); `unmeasured` zero on a 2xx and the
    streaming settle bypassing `settle_amount` (both by
    `a_stream_with_no_usage_block_settles_on_the_estimate_not_zero`); cache
    tokens not counted (the cache-read test alone). Scenarios:
    `features/a-stream-without-usage-settles-on-the-estimate.feature`, five,
    each bound.)*

44. **The surface `compat/1.0.json` promises is present in the code, and `COMPATIBILITY.md` is rendered from it, never typed.** SemVer's item 5: version 1.0.0 defines the public API, so a 1.0 is a promise about a surface, and a promise nobody can point at is a mood. This repository already published the strings another repository must agree with (`contracts/tokenfuse-constants.json`, invariant 14) and gated its environment names both ways (`crates/gateway/tests/manifest.rs`); the manifest is their union with everything else an operator or an agent depends on without reading the code, written in the 1.0.0 release commit (2026-09-14) and held from it on. From 1.0.0, removing or renaming a frozen name is a new major.

    What is frozen, in the manifest's fifteen kinds: the two shipped binaries (`cli.binaries`) and the gateway's fifteen subcommands and flags plus the Cloud's `--openapi` (`cli.subcommands`); the two listen defaults (`listen.defaults`); 83 environment names, 62 of the gateway's and all 21 of the Cloud's (`env`); the gateway's ten routes (`http.routes`), thirteen request headers (`http.request_headers`) and sixteen response headers (`http.response_headers`); the Cloud's 33 routes and five headers (`http.cloud_routes`, `http.cloud_headers`); the nine BreakerReason wire strings (`breaker.reasons`); the nineteen agent-event types this emitter writes (`agentevent.types`); the sixteen trace Parquet columns (`formats.trace_parquet`) and the constants file's own schema id (`formats.constants`); the three image names (`images`); and the Python SDK's fifteen public names from its `__all__` (`sdk.python`). The status word on a 402/403 and the severity of each event type are not in the manifest because the constants file already carries them, generated, and invariant 14's gate holds that file against the source.

    Ten of the gateway's declared names are deliberately NOT frozen, and the dev-tool component's twelve with them, each named in the manifest's `experimental` list so leaving them out is a statement rather than a gap: `TOKENFUSE_KEYS` and `TOKENFUSE_EVENTS` are in `components.json` and read by nothing (a test fixture in `clientkeys.rs:174`, a hint string in `firewallcli.rs`); `TOKENFUSE_VERSION` and `TOKENFUSE_GIT_SHA` are `option_env!` build stamps, not configuration; `TOKENFUSE_WASM_POLICY` is behind the `wasm` feature and the five `TOKENFUSE_APNS_*` names behind the Cloud's `apns` feature, and no shipped image builds either; the twelve `TOKENFUSE_CLUSTER_*` names are read by a build nobody publishes. The JS SDK's exports are the Python names in camelCase and are held by `sdk/js/test.js`, which calls every one, because this gate's literal rule cannot see an unquoted JavaScript identifier. The agent-event envelope schema (`taipanbox.dev/agent-event/v0.2`) is additive, not frozen: it moves with agent-passport's SPEC in that repository's release, the way trailryx's manifest treats the versions it accepts.

    The check is textual by design and says so: a plain name must appear as a quoted literal (`"name"`, `'name'` or `` `name` ``) in a file the manifest says holds it, so a comment mentioning it does not count. It does not prove a route still answers, a header still means the same thing or a column kept its type; invariants 2, 6 and 14 hold those. It does not prove a name absent from the manifest is not part of the surface.
    *(gate: `scripts/compat-surface.sh`; seven cases in `gates-have-teeth.sh`: a frozen route renamed in `lib.rs`, an env name gone from `components.json`, a subcommand renamed in `main.rs`, `COMPATIBILITY.md` edited by hand, an additive name added that must PASS, the manifest removed, and the constants file a `where` entry names removed, the last two both read as measured nothing rather than as a pass)*

45. **An OpenAI cached token is priced once.** OpenAI's `prompt_tokens` INCLUDES `prompt_tokens_details.cached_tokens`; Anthropic's `input_tokens` excludes `cache_read_input_tokens`. `Usage` keeps the disjoint shape, because that is what `ModelPrice::cost` prices, so the OpenAI parser nets the cached subset out of the prompt count (`apply_openai`, `provider.rs`). Until 2026-09-14 it copied both whole and every cached token was priced at the full input rate and again at the cache-read rate: +14.5 % on a 950/128 `gpt-4o` call (2535 against the provider's 2215 micro-USD), more with a higher hit ratio, in the run's budget as spend nobody was billed (tokenfuse#267, found by a reader of the code; the two tests that pinned the old figures were pinning the defect). A cached count past the prompt count nets to zero rather than wrapping (the ADR-8 direction: a wrapped input would under-charge, never over-charge). The cached count already seen on an earlier chunk keeps counting: a provider that sends `prompt_tokens_details` once and a bare `prompt_tokens` on a later chunk would otherwise reset the input to the whole prompt while the cache-read count stayed, the double charge back under a different chunking (the review's finding, `a_later_chunk_without_the_cached_subset_still_nets_it`, red with the `max` removed).

    Where it says nothing: the pre-flight estimate does not know the hit ratio and still reserves at the full input rate, which is the safe direction; the streaming and buffered OpenAI paths share `apply_openai`, so one fix covers both.
    *(tests: `provider::tests::parses_openai_sse_usage` (its expectation moved from 950 to 822), `an_openai_cached_token_is_priced_once_not_twice`, `an_openai_cached_count_past_the_prompt_count_nets_to_zero_not_wraps`, `an_openai_usage_without_cached_tokens_is_unchanged`, `a_later_chunk_without_the_cached_subset_still_nets_it`; three red on the unfixed parser (`left: 950 right: 822`, `left: 100 right: 0`, `Microusd(2535)` against `Microusd(2215)`); mutants: the netting removed (three tests red) and `saturating_sub` replaced by a wrapping subtraction (the past-the-prompt test red). Scenarios: `features/an-openai-cached-token-is-priced-once.feature`, five, each bound.)*

46. **A one-hour cache write is priced at the one-hour rate, and the total stays the total.** Anthropic bills a 5-minute cache write at 1.25x input and a 1-hour write at 2x, and the usage object says which under `cache_creation` beside the total `cache_creation_input_tokens`; the gateway read the total and priced it all at the 5-minute rate. INT-2 of the 1.0 proving run (2026-09-13, Claude Code through v0.5.0 on haiku 4.5): 140,373 cache-creation tokens on the 1-hour TTL metered at 0.176436 USD against Claude Code's own 0.281716, 37 percent under, the ADR-8 direction reversed (tokenfuse#282). `Usage::cache_write_tokens` stays the total (the trace's figure); `Usage::cache_write_1h_tokens` is the subset (`usage.cache_creation.ephemeral_1h_input_tokens`, parsed in `apply_anthropic`); `ModelPrice::cache_write_1h_per_mtok` is derived by `per_mtok_usd` as 1.6x the 5-minute rate (Anthropic's exact ratio for every model in the book) or named with `with_cache_write_1h_usd`; `cost` prices `total - subset` at the 5-minute rate and the subset at the 1-hour rate, a subset past the total pricing in the over-charging direction. The published book gains `cache_write_1h_per_mtok_microusd` (additive, `compat/1.0.json`); the OpenAI entries name it equal to their one write rate, because no OpenAI usage reports a 1-hour subset and the book must not show a rate no provider charges. Both fields are `#[serde(default)]`: a gateway older than this posts usage and prices without them.

    Where it says nothing: the pre-flight estimate does not know the TTL and reserves at the 5-minute rate, so a 1-hour-heavy call can settle above its reservation; the ledger settles the true figure and the next reservation sees it. The >200K long-context tier is still not modeled. The Parquet trace carries no cache columns (invariant 43's note), so the subset is priced and not recorded per call. And a note that belongs to invariant 45 as much as here: an OpenAI row's `input_tokens` in the trace, the Cloud and the FOCUS export is now the prompt count net of the cached subset, where it used to be the whole prompt, so a sum of tokens across the 1.0.0/1.0.1 boundary is a sum of two definitions; a fully cached prompt with no completion now reads as zero tokens beside a nonzero cost, which `focusexport` labels `estimated`. Cache columns are invariant 6 work.
    *(tests: `pricing::tests::a_one_hour_cache_write_is_priced_at_the_one_hour_rate` (281,716 against 176,436 micro-USD), `a_mixed_cache_write_prices_each_ttl_once`, `a_one_hour_subset_past_the_total_never_prices_negative`, `the_one_hour_write_rate_defaults_to_anthropics_ratio_and_can_be_named`, `a_one_hour_only_usage_carries_priced_tokens`; `provider::tests::parses_the_one_hour_cache_write_subset_from_a_message_start`, `a_cache_write_without_a_ttl_breakdown_is_all_five_minute`; red first as a compile failure on the unfixed tree (no such field). Mutants, each caught by name: the subset priced at the 5-minute rate (three tests), the subset not taken out of the total (three), the constructor's ratio dropped (four). Scenarios: `features/a-one-hour-cache-write-is-priced-at-its-own-rate.feature`, seven, each bound. `scripts/constants.sh` holds the published column.)*

47. **A reachable provider that refuses the call is on the bus too.** Invariant 24 covered a dependency that could not be reached; a provider that answered with a 429 or a 400 (a rate limit, a retired model id) passed its status through and settled zero, both right (#167), and wrote nothing: `dependency_failed` fired from the transport-error arm only, so a notifier never heard about a provider refusing every call. Measured 2026-09-07 on v0.4.3 with a stub answering 429/400/200: three drills, every status right, every expected mail missed, and the drill could not tell a notifier that was down from a gateway that was silent (tokenfuse#260). Now one `dependency_failed` per refusal at the new stage `response` (the answer arrived, and it was a refusal; `DependencyStage::Response`, wire `response`), effect `call_failed`, `detail` naming the status and the model, emitted by `emit_upstream_refused_via` where the status is first known on both managed paths (`buffered_managed` after its settle, `stream_managed` at entry, so a streamed refusal does not wait for the guard; a refused stream whose error body then breaks is one event, the stream arm stays quiet on it). **Which statuses are the provider's, `is_the_providers_refusal`:** every 5xx (529 included), 429, 408, and 404 and 400 (how providers answer a retired or unknown model id: Anthropic 404, Bedrock's door 400); a 401 or 403 is the caller's own forwarded credential and a 413, 415 or 422 the caller's own payload, and those page nobody. `@claude` 2026-09-14, the review's finding: every non-2xx would have paged the operator's notifier at `high` for a tenant with a bad key. The severity is the type's fixed `high`; heraldyx's window keeps a throttling burst to one mail. heraldyx's renderer gives every stage but `stream` the "could not be reached, nothing was charged" sentence, which is false for a refusal that reported usage, so heraldyx gains a `response` sentence and agent-passport's SPEC paragraph on `stage` gains the word, both in changes beside this one; until heraldyx ships it, a refusal renders with the unreachable sentence.

    Where it says nothing: a refusal on the unmanaged pass-through (no run id) and on a managed run that resolved no agent id (`event_agent_id` empty, `Exporter::emit` skips it) are still unrecorded, for invariant 24's reason (no subject to record it against). The money rules are untouched: zero for a refusal that reports nothing, the reported usage for one that generated something.
    *(tests: `proxy::tests::a_reachable_provider_that_refuses_is_recorded_on_the_bus`, `a_reachable_provider_that_refuses_a_stream_is_recorded_on_the_bus`, `a_refusal_with_usage_is_still_billed_and_now_recorded`, all three red on the unfixed tree (`exactly one event, got []`); `a_refused_stream_that_then_breaks_is_recorded_once` (red with the stream arm's guard reverted: `left: 2 right: 1`); `a_callers_own_4xx_is_not_recorded_as_the_providers_failure` (401, 403, 413, 422 nothing; 404, 408, 500, 529 one each; red with the class widened to every non-2xx); and `a_healthy_call_reports_no_dependency_failure` as the guard. Mutants, each caught by name: the buffered emission removed (two red), the streaming emission removed (one), the condition inverted so a healthy call emits (the guard red). Scenarios: `features/a-reachable-provider-that-refuses-is-on-the-bus.feature`, six, each bound.)*

48. **A subject revocation names a party, wherever that party stands in the chain.** `verify_delegation` reads the chain first and asks `revoked` once per entry, the subject and then every actor, root first, first hit refuses. Until 2026-09-17 it asked about `sub` alone, the human at the root, so an entry naming a compromised agent in `act` matched nothing and revoked nobody, while every test of the path had planted the agent as the argument directly and stayed green; the Go verifier in agent-stack-go had the same defect and closes it in its own change (agent-stack-go#61). At most `MAX_CHAIN_ENTRIES` calls, none for a token that failed an earlier step and none for a chain that does not parse. The gateway's `revocations::hook` logs a fail-mode fallback once per request rather than once per entry, so a stale list behind a 32-entry chain is one warning, not 32. `@decided 2026-09-17`: a subject revocation names a party, not a `sub` field.
    Where it says nothing: the age rule of invariant 32 is unchanged and applies to every entry the same way, so under `FailClosed` with a stale list the ROOT entry's fallback refuses before any actor is asked, and the one warning carries `Basis::Stale` and no party.
    *(tests: `tests::a_revocation_naming_any_party_in_the_chain_refuses_the_token`, a seeded sweep of 200 chains of every depth to the cap, red first at case 0 (`agent://acme/a0-1`, position 2 of 3, not honoured); `tests::revocation_is_not_consulted_for_a_token_whose_chain_is_malformed` for the order; mutants: the loop collapsed to the root alone, caught by the sweep, and the hook hoisted above the chain read, caught by the second; scenarios in `features/revocation.feature`)*

49. **A reservation is settled on the chain it was admitted against, exactly once, and a chain
    this ledger cannot check admits nothing.** Until 2026-09-17 `Ledger::settle` walked the run
    tree again and released the estimate on whatever ancestors existed at that moment, so a
    parent that appeared between a child's reserve and its settle lost 800000 of somebody
    else's reservation (F02 of the 2026-09-18 money-path review, @measured `cargo test
    --offline -p tokenfuse-core --test codex_money_review` 2026-09-17 at 80e0d42: parent
    `reserved=0, spent=100000` where 800000 was outstanding); a child naming a parent this
    ledger had never opened was checked against nothing above itself, with no header, no event
    and no log (`ledger.rs:121` `None => break`, `proxy.rs:651-652` opened the child only); a
    parent declared after a run's first call was ignored for the run's life while every trace
    row claimed it (`or_insert` set the parent once); a walk that reached the 64-ancestor cap
    admitted against the truncated set; `settle` after `close_run` was a silent no-op that
    left every ancestor's `reserved` inflated for good; and at a budget of `i64::MAX` the
    saturating sum turned an overflow into an allowed equality (F09).

    A `Reservation` now carries an id, the admitted chain leaf first with each run's
    generation, and the leaf's generation; `settle` applies to those links and only those, and
    a second settle of the same id is `Settlement::NotOutstanding`, never a second charge and
    never a release of a sibling. `close_run` keeps a run's counters (a late settlement lands
    on the closed leaf and on its ancestors) and `open_run` reopens it under a new generation,
    which an old settlement cannot touch: the leaf half of that settlement is dropped, its
    ancestor half still lands, and the trace row is where the leaf's spend then lives.

    `@decided 2026-09-17`, two decisions about the parent header. A child naming a parent this
    gateway has not opened is refused in enforce (402 `budget_exceeded`, the detail naming the
    parent, one `breaker_tripped`), unless the parent has a Cloud-managed budget, in which case
    the parent is opened at that budget as a root on first sight and the child proceeds; the
    policy default is never used to open a parent; shadow and warn forward the call and record
    the refusal the way invariant 42 records a would-block. A parent may be adopted only by a
    run that has no parent yet and against which no reservation has ever been admitted, its
    own or a descendant's (`admitted_ever`, marked on every run of an admitted chain; `steps ==
    0` is not the test, since a child reserving through a parent leaves the parent's steps at
    zero); any other change of parent is a 400 `invalid_request` (`parent_run_changed`,
    `parent_adopted_too_late`, `parent_is_self`), not a money refusal, and every trace row
    carries the parent the ledger holds, never the header. A walk that reaches
    `MAX_CHAIN_DEPTH` with an ancestor still unwalked is refused (402, the detail naming the
    leaf, the last walked run and the unchecked one); a cycle is not a truncation, every member
    is on the chain once. The three admission predicates (`Ledger::reserve`,
    `Ledger::would_exceed`, `UnitLedger::try_reserve`) use `checked_add` and read overflow as
    exceeded. One walker serves the checked reserve, the shadow question and the unchecked
    reserve, and one detail table serves the enforce 402 and the shadow would-block, so none
    of them can drift from another.

    **Where it says nothing.** The raft backend (feature `cluster`, compiled out of every
    shipped image) keeps the older state machine: an unknown parent is still walked past
    silently, a chain at 64 is still truncated, `Settle` walks the live tree, there is no
    generation, exactly-once is per gateway process only, and a late parent is refused
    whenever the local copy shows the run exists without one and silently ignored on a
    follower whose copy lacks the run. Closing that is one raft PR under invariant 5, and this
    change does not move `crates/cluster/src/types.rs`. A restart still loses every open
    reservation and every counter (issue #293, its own design). The Cloud budget map has no
    hierarchy, so a parent opened from it is a root. Three D1 refusals on one run raise the
    Cloud's `budget_exhausted` incident, which pages about a misconfigured coordinator. The
    unit monthly cap in shadow is still uncovered, as invariant 42 says. Opening a parent from
    its Cloud budget writes a log line and no agent-event: no existing type describes it and a
    new one is a cross-repository change (the sibling changes invariant 42 records).
    *(tests: `crates/core/tests/codex_money_review.rs` and `crates/core/tests/fable_missed.rs`,
    the review's probes moved into the suite, seven red at 80e0d42 by the review's own runs and
    @measured `cargo test -p tokenfuse-core --test codex_money_review --test fable_missed
    --no-fail-fast` 2026-09-17 at 6fdef03 (before this change, re-run by the implementer, on the
    review's ORIGINAL files exactly as they had already been copied into the worktree: `codex_f02`
    unmoved, calling `reserve` rather than `reserve_unchecked`, and no `.expect("opens")` anywhere,
    since 6fdef03's `open_run` returns `()`; the COMMITTED forms below, `.expect("opens")`
    throughout and `codex_f02` moved to `reserve_unchecked`, do not compile against 6fdef03 at
    all): the same seven FAILED (`codex_f01`, `codex_f02`, `codex_f09`, `codex_f10`, `missed1`,
    `missed2`, `missed6`), `codex_held_children_race_against_one_parent_with_exact_accounting` and
    `codex_held_seeded_integer_arithmetic_matches_i128_oracle` stayed `ok`; `ledger::tests`:
    `a_child_of_an_unopened_parent_is_refused_and_reserves_nothing`,
    `a_child_of_an_unopened_parent_is_admitted_once_the_parent_opens`,
    `a_parent_declared_after_a_descendants_admission_is_refused`,
    `a_parent_declared_after_an_unchecked_admission_is_refused`,
    `a_parent_declared_before_any_admission_is_adopted`,
    `a_changed_parent_is_refused_and_the_held_one_stays`,
    `a_reservation_settles_on_the_chain_it_was_admitted_against`,
    `a_closed_run_keeps_the_counters_a_late_settlement_needs`,
    `an_old_settlement_never_touches_a_reopened_runs_counters`,
    `a_second_settlement_of_one_reservation_is_an_observable_no_op`,
    `racing_children_with_a_late_parent_are_refused_until_it_opens`,
    `a_walk_that_reaches_the_depth_cap_refuses_and_names_the_unchecked_ancestor`;
    `unitledger::tests::a_saturated_unit_cap_cannot_grant_past_its_ceiling`;
    `money::tests::checked_add_reports_overflow_instead_of_saturating`; `proxy::tests`:
    `a_child_naming_a_parent_this_gateway_has_not_opened_is_refused`,
    `a_cloud_budget_on_the_parent_opens_it_and_admits_the_child`,
    `shadow_records_an_unopened_parent_as_a_would_block_and_accounts_the_leaf`,
    `a_changed_parent_is_a_400_and_the_trace_keeps_the_accepted_parent`,
    `a_changed_or_late_parent_is_a_400_in_shadow_too_and_the_trace_keeps_the_accepted_parent`,
    `an_empty_parent_header_is_treated_as_absent`,
    `a_65_deep_chain_is_refused_at_the_door_naming_the_unchecked_root`;
    `tests/cluster_backend.rs::raft_backend_refuses_a_changed_or_late_parent_from_its_local_read`,
    `raft_backend_settles_two_reservations_back_to_zero_reserved`.
    Red first: the seven probes above, red by assertion at 6fdef03, verbatim: `codex_f01`
    panicked "ADR-2: reserve must check every ancestor, including the root beyond the walk
    cap"; `codex_f02` panicked "ADR-2: settle may only release what this call reserved on that
    ancestor" (left: `Microusd(0)`, right: `Microusd(800000)`); `codex_f09` panicked "ADR-2 and
    money.rs: no headroom remains at i64::MAX; saturation must not turn overflow into an
    allowed equality"; `codex_f10` panicked on `assert_eq!(after, before, ...)`; `missed1`
    panicked "a parent that was never opened must not admit the child's spend unchecked";
    `missed2` panicked "a zero-budget parent declared on the second call must refuse the
    child"; `missed6` panicked on `assert_eq!(p.reserved, Microusd(0), ...)` (left:
    `Microusd(100000)`). A further seven test names were proven red before the product changed,
    each in a TEMPORARY form written to compile against 6fdef03 (`open_run`'s result left as a
    bare statement rather than `.expect`ed, since it returned `()` there), never in their
    committed form, and the temporary form is not always the same shape as the committed one, so
    what is quoted below is what that temporary run actually printed, not a restatement of the
    committed assertion. `a_child_naming_a_parent_this_gateway_has_not_opened_is_refused`,
    `a_65_deep_chain_is_refused_at_the_door_naming_the_unchecked_root` and the `parent_run_changed`
    half of `a_changed_parent_is_a_400_and_the_trace_keeps_the_accepted_parent` each read
    `left: 200 right: 402` or `right: 400`; `shadow_records_an_unopened_parent_as_a_would_block_and_accounts_the_leaf`
    panicked on the missing would-block header; `a_saturated_unit_cap_cannot_grant_past_its_ceiling`
    panicked with `got Ok(Some(UnitReservation { .. }))`.
    `racing_children_with_a_late_parent_are_refused_until_it_opens`'s COMMITTED body matches
    `Err(BudgetError::UnknownParent { .. })`, a variant 6fdef03's `BudgetError` does not carry at
    all (@measured by adding that exact committed body to a copy of 6fdef03's `ledger.rs`,
    2026-09-17: `error[E0599]: no method named `expect` found for unit type `()``, then, with that
    line removed, `error[E0599]: no variant named `UnknownParent` found for enum
    `ledger::BudgetError``), so that exact source is compile-red there for two independent
    reasons, never assertion-red; its temporary stand-in instead counted grants with `.is_ok()`
    and asserted the count was `0`, which is what went red (`left: 16 right: 0`).
    `a_cloud_budget_on_the_parent_opens_it_and_admits_the_child` needed no stand-in to compile
    (6fdef03's `AppState` already carried `set_cloud_budgets`/`cloud_budget`, unrelated to this
    change) and ran red in its COMMITTED form, but not on a 402-vs-200 comparison: call 1's
    `resp1.status() == StatusCode::OK` passes under 6fdef03 too (the old code never opens a
    parent from a Cloud budget, so nothing capped the child there either), and the very next
    line, `st.ledger.snapshot("parent").await.unwrap()`, is what panics: @measured by running
    that exact committed test body against a copy of 6fdef03's `proxy.rs`, 2026-09-17,
    `thread '...' panicked at crates/gateway/src/proxy.rs:5419:58: called
    `Option::unwrap()` on a `None` value` (that line number true of that one measurement only).
    `a_parent_declared_after_an_unchecked_admission_is_refused` (added after review) and
    `an_empty_parent_header_is_treated_as_absent` (added after review) were each proven red by
    deleting or reverting one line of the ALREADY-LANDED product code and restoring it
    (@measured `cargo test -p tokenfuse-core a_parent_declared_after_an_unchecked_admission_is_refused`
    and `cargo test -p tokenfuse-gateway --lib an_empty_parent_header_is_treated_as_absent`
    2026-09-17, each once with the line planted and once restored): with
    `reserve_unchecked`'s `s.admitted_ever = true;` deleted, the first panicked `called
    Result::unwrap_err() on an Ok value: Opened { generation: 1, parent: Some("p"),
    parent_disposition: Adopted, reopened: false }`; with the `.filter(|p| !p.is_empty())` removed
    from the parent header read, the second read `left: 402 right: 200`. Every other new test
    names an API this change adds and so is red by compile against 6fdef03, the weaker form
    invariant 46 already accepts. Fourteen mutants planted in the product code 2026-09-17, each
    caught by the test named in the pull request (the last two are the `reserve_unchecked`
    admitted_ever deletion and the empty-header filter removal, both just above, kept in this
    paragraph rather than renumbered into section 7's twelve since both target a line a
    second-model review named, not a line this spec's own table
    named). Scenarios: `features/hierarchical-budgets.feature`, sixteen, each bound
    (`features-are-bound.sh`: 223 scenarios, 235 bindings, 0 broken). Not a script gate: the rule
    is enforcement code `cargo test` runs; `gates-have-teeth.sh` plants the unknown-parent mutant
    and requires `missed1` to go red.

    **Where it says nothing**, four more facts added after a second-model review: a D1/F01
    refusal's sink row is `decision: "budget_exceeded"` with `cost_microusd = estimate`, the same
    shape a genuine over-budget refusal writes, so `tokenfuse savings`, `focus-export`'s
    `x_blocked` and the Cloud's aggregation count it as avoided spend, though nothing was ever
    priced against a budget that was actually insufficient. After a gateway restart, a
    coordinator's workers are refused (D1) until the coordinator calls again (re-opening the
    parent in the now-empty in-process ledger) or a Cloud budget names the parent; nothing here
    persists across a restart (see the restart-durability line above). The 400 body's
    `accepted_parent` names another run's held parent to a caller who puts that run id in
    `x-fuse-run-id` and any other id in `x-fuse-parent-run-id`; the door has no authentication
    of its own beyond the client keys, when those are on (`resolve_client_key` runs first and
    answers 401 otherwise), so with client keys off this is the same topological fact
    `GET /v1/runs` keeps behind `TOKENFUSE_ADMIN_KEYS` (invariant 41). And N plain gateways behind one address, with no `cluster` feature, each hold
    their own ledger, so a worker whose call lands on a different replica than the one its
    coordinator's `open_run` landed on is refused by D1 even though the coordinator did call.)*

50. **One owner holds a call's reservations from the first one taken to the terminal
    transition, and an unknown outcome keeps its exposure.** Until 2026-09-18 the settle guard
    existed only on the streaming path and only after the provider had answered
    (`proxy.rs:1946` at `e25835c`), so a client that gave up while `Provider::send` was pending
    dropped a bare `Reservation` and a bare `UnitReservation`: both stayed outstanding for the
    life of the run and the month, with no line anywhere saying so (F03 and 3.4 of the
    2026-09-18 money-path review, @measured by the review at 80e0d42:
    `codex_f03_cancel_during_provider_send_releases_reservation` and
    `..._during_buffered_body_...` red with `reserved` still up after the abort). A 2xx whose
    body then broke was settled at zero on both ledgers by a manual arm (`proxy.rs:2094-2097`),
    so a completion the provider generated and billed cost the run nothing and the streaming path
    charged the estimate for the same event (F04 and 3.5, invariant 38 broken on one event).

    `SettleGuard` (`crates/gateway/src/settle.rs`) is now created in `handle` the moment the
    unit reservation block ends, holds the unit half and the run half as `Option`s across every
    await that follows, and decides on `Drop` from one `CallOutcome` state through one pure
    table (`disposition`): reserved and not dispatched, or `send` returned `Err`, releases both
    at zero; a status line arrived and it was a refusal charges what the provider reported, else
    zero (invariant 47); a 2xx arrived charges what the body reported, else the estimate, whether
    the body completed, broke or was abandoned (invariant 43, and now the same answer on both
    paths); and a call handed to the provider that ended before any status line came back is
    RETAINED: neither settled nor released, listed in `AppState.retained`, shown on
    `GET /v1/runs` as `retained` and `retained_usd`, and warned about with the run, the
    reservation id, the amount and the unit. The `allow` trace row is written by the guard in one
    site for both paths; a call that ends before the provider answers writes no row. On the
    streaming path that row's `saved_microusd` stays the zero it carried before the move:
    `handle` passes no `router_route` for a streamed request, so a routed stream's avoided spend
    is not counted, as before, and counting it is a separate decision.

    `@decided 2026-09-17`: a call cancelled before the provider answered leaves no trace row,
    like the send-error arm. `@decided 2026-09-18`: a call whose outcome is unknown after dispatch
    keeps its reservation until it is reconciled and is never settled at zero; completing it at
    the estimate is not chosen. A call that was definitely not sent, and a refusal that reports no
    priced usage, release as before; a 2xx that then breaks settles at the estimate; parsed usage
    settles as parsed.

    Reconciling a retained reservation is not built. What exists: the caller's next call on the
    run may widen `x-fuse-budget-usd` (`open_run` updates an open run's budget), a Cloud budget
    or a unit cap override widens the room the same way, the unit half expires with the UTC
    month, and a restart forgets everything (issue #293). The shape of a real path (an
    admin-keyed `POST /v1/runs/{id}/reconcile` settling or releasing by reservation id, or a
    bounded retention) is an open decision, D8.

    **Where it says nothing.** A cancel during `Provider::send` is read as unknown from the
    line before the await, because `HttpProvider::send` is one `reqwest` future with no point
    the caller can observe between "connecting" and "the head is written"; nothing measured
    whether hyper drops the upstream request when that future is dropped, so the provider may
    still run and bill the retained call, and the estimate is not proven to bound that bill.
    `send` returning `Err` is read as "not sent" and released, and `ProviderError::Upstream`
    cannot say otherwise: a connection reset while awaiting the response head arrives through the
    same arm and releases a reservation for a call the provider may have executed (D9, an open
    decision; the split is `reqwest::Error::is_connect`, in PR 3's file). Whether axum drops the
    handler future on a client disconnect in every phase is not measured here (the live test is
    named in the PR's NOT proven list and was not run). No agent-event type describes a retained
    call; a new type is a cross-repository change (D10). The registry is process-local and
    capped at 8192 entries; past the cap the ledger still holds the reservation and only the
    handle is not kept (`listed=false` on the warn, `Retained::unlisted`). On the raft backend a
    reservation committed while the future is dropped between commit and return is not held by
    anything, as before. The unit half of a retained reservation cannot be settled after the
    month rolls (`UnitLedger::settle` drops a stale window), which any D8 must say.

    *(tests: `crates/gateway/tests/codex_money_review.rs`, the review's F03 and F04 probes and
    three held controls moved into the suite, the send-cancel probe renamed to
    `codex_f03_cancel_during_provider_send_is_retained_not_released` with its assertion moved to
    retention; `settle::tests`: `a_guard_dropped_while_the_provider_holds_the_request_retains_and_warns`,
    `a_guard_dropped_before_dispatch_releases_both_ledgers_and_writes_no_row`,
    `a_guard_holding_only_the_unit_half_releases_it_on_drop`,
    `a_guard_told_the_send_failed_releases_both_and_writes_no_row`,
    `a_second_settle_of_one_guard_changes_nothing`,
    `the_run_and_unit_ledgers_agree_in_every_terminal_state`,
    `every_state_has_the_disposition_the_rule_names`; `proxy::tests`:
    `a_cancel_while_the_provider_holds_the_request_retains_both_ledgers`,
    `a_cancel_while_the_body_is_being_collected_settles_the_estimate_on_both_ledgers`,
    `a_2xx_whose_body_breaks_settles_the_estimate_on_both_ledgers_and_writes_the_row`,
    `a_2xx_whose_body_breaks_after_reporting_usage_settles_that_usage`,
    `the_shadow_twin_of_a_broken_2xx_records_the_estimate_and_no_shadow_event`,
    `a_retained_reservation_is_listed_on_the_runs_endpoint`, and
    `client_cancel_midstream_still_settles` now pinned to the exact estimate;
    `unitledger::tests::reserved_reports_the_outstanding_amount_in_the_current_window`.

    Red first, @measured `cargo test -p tokenfuse-gateway --test codex_money_review` (a trimmed,
    pre-product form keeping E1-E7 exactly as the review wrote them) and a temporary
    `proxy::tests` addition for E9, E10, E11, E12, E20, both at `e25835c` 2026-09-18:
    `codex_f03_..._releases_reservation` (E1's original name and form) and
    `codex_f03_cancel_during_buffered_body_releases_reservation` (E2) both panicked "ADR-2 and
    settle.rs cancellation promise: dropping the request future must release its reservation"
    (left: `Microusd(11535)`, right: `Microusd(0)`); `codex_f04_buffered_body_error_preserves_reported_usage`
    (E3) panicked "invariant 47 money rule: reported generated usage must be settled even if
    delivery fails" (left: `Microusd(0)`, right: `Microusd(7500)`);
    `codex_f04_real_http_2xx_body_error_must_not_silently_settle_zero` (E4) panicked "invariant 43
    and review fallback requirement: upstream answered 200 but its body broke; usage is
    unavailable, so reserve estimate must not become a zero settlement" (left: `Microusd(0)`,
    right: `Microusd(11535)`); the three held controls (E5, E6, E7) were already green, unaffected
    by this change. The temporary `proxy::tests` (no `st.retained`, no `UnitLedger::reserved`, both
    added later in the same commit) read: `a_cancel_while_the_body_is_being_collected_...`
    panicked "released, not leaked" on `worker.reserved`, left `Microusd(8657)` right
    `Microusd(0)`: at e25835c a cancel during `collect` LEAKED the reservation (reserved 8657,
    spent 0, F03's shape) where the fix charges the estimate (@measured
    `cargo test -p tokenfuse-gateway --lib a_cancel_while_the_body_is_being_collected` on a
    `git archive e25835c` copy with the test appended minus its two `units.reserved` lines,
    2026-09-18); `a_2xx_whose_body_breaks_settles_the_estimate_...` left `Microusd(0)` right
    `Microusd(8657)` (settled at zero where the fix charges the estimate); the shadow twin left
    `Microusd(0)` right `Microusd(1757)`; the runs-endpoint listing left `Null` right `1` (no
    `retained` member in the JSON at e25835c). Every other new test (`E8`, `E13` to `E19`, `E21`,
    `E22`) names an API this change adds and so is red by compile against `e25835c`, the weaker
    form invariant 46 already accepts.

    Twelve mutants planted in the product code 2026-09-18, each reverted after; one equivalent.
    M1 (`Unknown => Retain` mutated to `Release`) and M2 (to `Charge{false}`): both caught by
    `a_guard_dropped_while_the_provider_holds_the_request_retains_and_warns`,
    `every_state_has_the_disposition_the_rule_names`,
    `a_cancel_while_the_provider_holds_the_request_retains_both_ledgers` and
    `codex_f03_cancel_during_provider_send_is_retained_not_released`. M3 (`Started` charging zero
    again): caught by `client_cancel_midstream_still_settles`,
    `a_2xx_whose_body_breaks_settles_the_estimate_on_both_ledgers_and_writes_the_row`,
    `the_shadow_twin_of_a_broken_2xx_records_the_estimate_and_no_shadow_event`,
    `every_state_has_the_disposition_the_rule_names`,
    `codex_f04_real_http_2xx_body_error_must_not_silently_settle_zero`,
    `settle::tests::drop_without_complete_settles_with_fallback`, and three of the four
    `no_usage_stream_settles_on_the_estimate.rs` tests (the fourth settles on a parsed usage
    block and cannot move under this mutant). M4 (the unit half's settle deleted from
    `charge`): caught by `a_cancel_while_the_body_is_being_collected_settles_the_estimate_...`,
    `a_2xx_whose_body_breaks_settles_the_estimate_...`,
    `a_2xx_whose_body_breaks_after_reporting_usage_settles_that_usage`,
    `the_run_and_unit_ledgers_agree_in_every_terminal_state` and
    `a_unit_reservation_settles_alongside_the_run_reservation`. M5a (the guard's construction
    moved to after `send` resolves, so nothing owns the reservation during the cancellable
    await): caught by `a_cancel_while_the_provider_holds_the_request_retains_both_ledgers`,
    `a_retained_reservation_is_listed_on_the_runs_endpoint` and
    `codex_f03_cancel_during_provider_send_is_retained_not_released`, reading the LEAK (`reserved`
    still up at the estimate, registry empty) rather than the retention (registry one entry) -
    the two look the same on `reserved` alone, which is invariant 50's own point. M5b
    (`guard.dispatching()` deleted): caught by the same three. The two `proxy` tests fail first
    on the `debug_assert_eq!` inside `answered` during their prior ordinary call (state stayed
    `NotDispatched`, not `Unknown`), a debug-build catch; the probe never reaches `answered`
    and catches it by its money and registry assertions (a `NotDispatched` drop releases, so
    `reserved` reads 0 and the registry is empty), which holds in a release build too. M6 (the
    warn line deleted from `retain`): caught by
    `a_guard_dropped_while_the_provider_holds_the_request_retains_and_warns` (no `retained:` line
    in the captured log). M7 (`settle_now`'s two `take()` calls replaced by `clone()`, so a
    second call settles again): caught by `a_second_settle_of_one_guard_changes_nothing` (unit
    `spent` read `6_000_000`, two rows, not one); `codex_held_stream_drop_before_first_poll_settles_once`
    stayed GREEN under this mutant, which is the point rather than a miss: the run half is
    shielded a second time by invariant 49's own ledger-level exactly-once
    (`Settlement::NotOutstanding`), and the unit ledger has no such guard of its own, which is
    exactly the asymmetry E17 was written to read. M8 (the guard's construction moved to after
    the run-budget match, so the unit half is bare on a refusal): NOT caught by
    `a_run_budget_refusal_releases_the_unit_reservation` as it read before this PR - a
    1_757-microUSD leak against a 1_000_000-microUSD cap does not move a
    `try_reserve(Microusd::from_usd(0.99))` probe that has 10_000 microUSD of slack to spare, so
    the mutant and the clean release were indistinguishable to it. That test now also asserts
    `units.reserved("treasury", ..) == Microusd::ZERO` directly, which reads the exact figure and
    is what actually caught it once added; the loose `try_reserve` check stays alongside it. M9
    (`self.retained.push` deleted, the warn line left in place claiming `listed=true`): caught by
    the same three `proxy`/`settle` tests as M1/M2/M5a plus
    `a_retained_reservation_is_listed_on_the_runs_endpoint`. M10 (`answered` reading every status
    as a success): caught by `a_429_from_the_provider_settles_nothing_as_spend`,
    `a_refused_stream_dropped_without_complete_settles_zero_not_the_estimate` and
    `the_run_and_unit_ledgers_agree_in_every_terminal_state`. M11 (`record_row` deleted from
    `charge`): caught by `a_429_from_the_provider_settles_nothing_as_spend` (one row expected,
    zero written), `a_cancel_while_the_body_is_being_collected_settles_the_estimate_...`,
    `a_2xx_whose_body_breaks_settles_the_estimate_...` and
    `a_second_settle_of_one_guard_changes_nothing`. M12 (`buffered_managed`'s explicit
    `guard.settle_now()` deleted from its `Err` arm): EQUIVALENT by construction, @measured
    `cargo test -p tokenfuse-gateway --lib` and `--tests` 2026-09-18 with the line removed: all
    536 lib tests and every integration test (including the seven moved probes) stayed green,
    because `guard`'s `Drop` settles identically one line later at the `return`. M13
    (`self.step = reservation.step` deleted from `hold_run`, so `x-fuse-step` on every managed
    response and `step` on every `taint_blocked` row read 0 while the `allow` row, which reads
    `run.step`, stays right): SURVIVED the suite as first written, no test asserted the
    header's value; caught since by `managed_request_within_budget_settles_cost` (`x-fuse-step`
    left `"0"` right `"1"`, and `"2"` on a second call of the same run) and
    `tests/router.rs::streaming_request_carries_the_router_header_too` (the streaming site,
    same left/right), @measured `cargo test -p tokenfuse-gateway` with the line removed
    2026-09-18.

    Coverage, @measured `cargo llvm-cov -p tokenfuse-gateway --lib --summary-only` 2026-09-18,
    "before" read from a `git archive e25835c` snapshot built in isolation (this repository's
    shared stash and worktree registry were both off limits to this session) and "after" in the
    worktree: `settle.rs` moved from 1 missed of 546 lines (99.82%) to 26 missed of 990
    (97.37%; the file grew by the registry, the five-state table and the tests that prove them);
    `proxy.rs` from 359 missed of 5907 (93.92%) to 353 missed of 6163 (94.27%); the whole crate
    from 2776 missed of 16864 (83.54%) to 2793 missed of 17591 (84.12%) on the run this figure is
    quoted from, 2795/17591 (84.11%) on an immediate repeat with nothing else changed, which is
    named rather than hidden: a two-line swing across two runs of one async, cancellation-timing
    suite is more likely one of the cancel tests occasionally resolving its race a different way
    than a measurement error, and it does not move either file's own figure. Uncovered that
    matters, all by design: `settle.rs:419-420`, the `retain` arm reached with no run half
    (unreachable by construction - `dispatching` asserts one is held before the state can become
    `Unknown`); `proxy.rs:2113-2125`, the `charge`-result fallback in `buffered_managed`
    (unreachable - `answered` runs before this function is ever called); `settle.rs:229-230`,
    `Retained::push` past its 8192-entry cap (never reached by a test; section 12's own
    NOT-proven list says so). `settle.rs:495-500`'s router-savings arithmetic inside
    `record_row` reads uncovered by this `--lib`-only command but is exercised by
    `tests/router.rs::on_mode_rewrites_the_forwarded_body_and_prices_the_chosen_model`, which runs
    in a separate binary `cargo llvm-cov -p tokenfuse-gateway --lib` does not link.

    Scenarios: `features/settlement-owns-the-call.feature`, twelve, each bound
    (`features-are-bound.sh`: 245 scenarios, 275 bindings, 0 broken, after #303 landed its own). Not a script gate: the rule
    is the guard's disposition table, held by `cargo test`; `gates-have-teeth.sh` plants the
    retain-to-release mutant and requires the guard-level test to go red.)*

51. **A declared chain longer than the record holds is refused at the door, whether or not
    anybody verifies chains, and the two chain caps bound different things.** (Numbered 51
    because a sibling change in flight from the same base on 2026-09-18, the settle guard's,
    takes 50; the number is the only thing the two share.) agent-passport
    SPEC 5.1 bounds `on_behalf_of` at 32 entries and requires it acyclic as a property of the
    chain ITSELF; proving a chain (5.2) is optional and additive. The v0.2 envelope pins
    `maxItems: 32` and `agent-conform` runs the record's validator on every line, so a chain
    longer than that is one no consumer will hold, proven or not. Until 2026-09-18 the entry
    cap lived in the delegation crate alone (invariant 35), where it bounded a TOKEN's chain,
    while a chain a caller merely declared in `x-fuse-on-behalf-of` was split, counted by
    nobody, forwarded, sent to the PDP as unproven and written into every event of the request.
    Measured 2026-09-17 on the appliance proving run with no issuer configured, the launchers'
    default (tokenfuse#297): forty entries, about 1.5 KiB and so inside the 4 KiB byte cap,
    answered 200 with nothing on the bus; every event that request could have written would
    have been quarantined at the record, the shape invariant 35 already refuses for a proven
    chain.

    `@claude` 2026-09-18, the reading this change takes and the pull request states, open to
    being overruled: the cap holds regardless of verification. `chainproof::declared_chain` is
    the one parser both doors call (the LLM proxy and the MCP broker each had a splitter of
    their own), and it refuses more than `MAX_CHAIN_ENTRIES`, read from
    `tokenfuse_delegation` rather than retyped, so a token's chain and a declared chain are
    bounded by one number. The refusal is `400 invalid_request` with code
    `on_behalf_of_over_cap`, the count sent and the cap in the body, before anything is
    resolved, reserved, forwarded or brokered, in every mode (a malformed header is not a
    money decision, so shadow refuses it too), and one `identity_mismatch` on the bus whose
    `data` carries `entries` and `max_entries` and whose envelope carries NO `on_behalf_of`:
    the chain is exactly what the record refuses, so an event carrying it would be quarantined
    with the request it reports. No trace row, like every other 400 here. The 4 KiB byte cap
    on the raw header is unchanged: over it the header is ignored as absent, warned and
    counted, which predates this and is a separate decision.

    **Two caps, two questions, and the README's header contract names both.** `MAX_CHAIN_ENTRIES`
    (32) bounds how many principals ONE request claims to act for, in one header, and is the
    shared spec's number. `MAX_CHAIN_DEPTH` (64, `crates/core/src/ledger.rs`, invariant 49)
    bounds how many runs a call rolls up INTO through `x-fuse-parent-run-id`, across requests,
    and a walk that reaches it is refused rather than truncated. Neither is derived from the
    other and neither moved here.

    **Where it says nothing.** The acyclic rule and the `agent://`/`user://` scheme rule are
    still applied to a TOKEN's chain only; a declared chain's entries stay opaque strings, as
    they were, and widening the parse is a separate decision written down rather than implied.
    The over-cap `identity_mismatch` needs an `x-fuse-agent-id` to be filed under, as every
    event does (SPEC 6.1); without one the exporter skips and counts it. And the byte cap's
    ignore posture means a header both over 4 KiB and over 32 entries is ignored, not refused,
    which is the older rule winning.
    *(tests: `proxy::tests::a_chain_of_forty_entries_is_refused_before_anything_is_forwarded`,
    red on the unfixed tree verbatim `left: 200 right: 400` with the chain forwarded and the
    bus empty; `a_chain_at_exactly_the_cap_is_forwarded_and_recorded_unchanged`, the guard,
    green on both sides; `tests/mcp_broker.rs::a_chain_over_the_cap_is_refused_at_the_mcp_door_too`,
    red the same way with the upstream having seen the call;
    `chainproof::tests::the_header_cap_is_the_delegation_crates_cap_and_not_a_second_number`
    (the 32 written out independently, invariant 14's lesson) and
    `a_declared_chain_is_split_trimmed_and_absent_is_empty`, both compile-red before
    `declared_chain` existed. Scenarios:
    `features/a-chain-longer-than-the-record-holds.feature`, four, each bound. Not a script
    gate: nothing stops a third door reading the header through its own splitter, the shape
    invariant 34 names; the two doors that exist are held by their tests)*
