Feature: A refused run and a fallback-priced call are visible in the fleet view

  An audit of the Cloud and its dashboard after v1.7.0 found the Runs table
  showing a run whose every call was refused 403 as "live", with nothing
  spent and N calls, because the Cloud kept no count of refusals and no
  latest decision; the refused calls per minute the Cloud's series has always
  served were fetched and never drawn. And the basis a call was charged at
  (x-fuse-price: known or fallback) reached only the caller: a fleet view
  could not see spend charged at the fallback rate for a model id the price
  book has no row for, which is up to five times a list price.

  The ask: show a refused state with its reason in the Runs table and draw
  the refused calls; carry the price basis to the Cloud beside owner without
  changing the trace's columns, count fallback-priced calls per run and per
  model, and show a fallback pill on the model and a fleet count.

  @claude 2026-10-08, under delegated authority: only an admitted call has a
  basis (a refusal's figure is an avoided estimate, not a charge); a basis
  that is neither known nor fallback is counted as not reported, as is every
  call from a gateway older than this field, and the fleet tile says how many
  there were instead of reading them as clean; the per-model fold is bounded
  at 256 ids with an "(other models)" bucket because model ids are
  caller-chosen; the latest decision is the latest call's by its own
  timestamp, and a decision the Cloud does not trust is never shown.

  # @test:a_run_reports_its_refused_calls_and_its_latest_decision
  # @test:refusals_and_fallback_prices_reach_the_runs_and_summary_reads
  Scenario: A run whose calls were refused says so
    Given a run with one admitted call and then two calls refused for identity
    When /v1/runs is read
    Then the run reports two refused calls and identity_mismatch as its latest decision
    And an admitted retry makes allow its latest decision without forgetting the refusals

  # @test:the_latest_decision_is_the_latest_call_not_the_last_pushed
  Scenario: A late batch never replaces a later call's decision
    Given a run whose call at time 10 was refused for budget
    When a record of an admitted call at time 5 arrives afterwards
    Then the run's latest decision is still budget_exceeded

  # @test:an_unrecognised_decision_is_never_the_runs_decision_or_a_refusal
  Scenario: A decision the Cloud does not trust is never shown
    Given an admitted call and then a record with a made-up decision
    When /v1/runs is read
    Then the latest decision is allow, no call is counted as refused, and both are counted as calls

  # @test:the_basis_each_call_was_charged_at_reaches_the_cloud
  # @test:the_wire_record_names_the_basis_an_admitted_call_was_charged_at
  Scenario: The gateway tells the Cloud the basis each admitted call was charged at
    Given a gateway pushing to a control plane
    When it admits a call on a listed model and one on a model with no row
    Then the records pushed carry price_basis known and fallback
    And a refused call's record carries no price_basis
    And the trace's sixteen columns are unchanged

  # @test:fallback_priced_calls_are_counted_per_run_and_per_model
  # @test:refusals_and_fallback_prices_reach_the_runs_and_summary_reads
  Scenario: The Cloud counts fallback-priced calls per run and per model
    Given two admitted calls charged at the fallback on claude-sonnet-6, one at a listed rate, and one from a gateway that names no basis
    When /v1/runs and /v1/summary are read
    Then the run reports two fallback-priced calls and the other run one with no basis reported
    And the summary lists claude-sonnet-6 with two calls

  # @test:a_refused_call_or_an_unknown_basis_is_never_a_fallback_charge
  Scenario: A refused call or an unknown basis is never a fallback charge
    Given a refused call marked fallback and an admitted call whose basis is neither word
    When the run is read
    Then no call is counted as fallback-priced and the second is counted as not reported

  # @test:the_fallback_model_fold_is_bounded_and_loses_no_call
  Scenario: The per-model fold is bounded and loses no call
    Given 300 fallback-priced calls on 300 different model ids
    When /v1/summary is read
    Then at most 257 model rows are listed and their calls sum to 300

  # @test:fallback_counts_survive_a_snapshot_round_trip
  Scenario: The fleet counts survive a restart
    Given fallback-priced and unreported calls folded into the store
    When the store is saved and loaded
    Then the summary and the run report the same counts
