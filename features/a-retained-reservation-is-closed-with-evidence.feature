Feature: A retained reservation is closed by a person, with evidence

  A call handed to the provider that ends before any answer comes back is
  retained (invariant 50): its run and unit reservations stay outstanding,
  and since W03 they survive a restart. Nothing could close one.

  The ask (D8, gateway side): an admin route that closes one retained
  reservation. The request names the reservation id, the revision it
  expects, an operation id, the kind of evidence (observed or no_charge),
  the observed cost when observed, and a reference to the evidence. It is
  authorized by a short-lived HMAC token bound to that id and revision,
  verified with a secret from the environment; with the secret unset the
  route is off. Observed settles at the given cost, no_charge releases at
  zero, both halves, exactly once. The same operation with the same content
  answers the recorded result, with different content it is a conflict. The
  closure is written to the retained journal so a restart does not bring
  the reservation back, and startup rewrites the journal with only what is
  still open.

  # @test:an_observed_closure_settles_the_run_at_the_given_cost_exactly_once
  # @test:an_observed_closure_settles_both_ledgers_at_the_cost_on_every_link
  Scenario: Observed evidence settles the reservation at the cost it shows
    Given a gateway holding one retained reservation on a child run under a parent
    When a person closes it as observed at 4321 micro-USD with a valid token
    Then the child and the parent are each charged 4321 micro-USD once and hold nothing reserved
    And the unit half is settled at the same cost and the reservation is no longer listed

  # @test:a_no_charge_closure_releases_both_halves_at_zero
  # @test:a_no_charge_closure_releases_both_ledgers_at_zero
  Scenario: No-charge evidence releases both halves at zero
    Given a unit cap that the retained reservation fills
    When a person closes it as no_charge
    Then no spend is added to any run and nothing stays reserved
    And a call that the cap refused before is admitted

  # @test:the_same_operation_returns_its_recorded_result_and_different_content_conflicts
  # @test:a_replay_answers_the_recorded_result_and_a_conflict_changes_nothing
  Scenario: The same operation answers its recorded result and different content is a conflict
    Given a reservation closed by operation op-same
    When op-same is sent again with the same content, then with a different cost
    Then the first answers the recorded result marked replayed, the second is 409 closure_conflict
    And a different operation for the same reservation is 409 already_closed, and nothing is charged again

  # @test:racing_closures_of_one_reservation_apply_exactly_once
  Scenario: Closures raced against one reservation apply exactly once
    Given sixteen closures of one reservation under sixteen operation ids at the same moment
    Then exactly one is applied and both ledgers move once

  # @test:a_missing_expired_misbound_or_stale_token_changes_nothing
  # @test:a_token_is_bound_signed_and_short_lived_at_its_exact_boundaries
  # @test:hostile_tokens_never_panic_and_never_verify
  Scenario: A token that is missing, expired, forged, misbound or stale changes nothing
    Given a retained reservation
    When a closure arrives with no token, an expired one, one living longer than five minutes, one signed with another secret, one bound to another id or revision, or one bound to a revision the reservation no longer has
    Then it is refused 401, 401, 401, 401, 403 or 409 by name
    And the reservation is still listed with its ledgers unchanged

  # @test:a_closed_reservation_stays_closed_after_a_restart_and_the_journal_keeps_only_open_ones
  # @test:a_closure_on_disk_is_never_restored_and_its_operation_answers_after_a_restart
  Scenario: A closed reservation stays closed across a restart
    Given one closed reservation and one still open, on a gateway with a data directory
    When the gateway is killed and started again on the same data directory
    Then only the open reservation is restored, the operation still answers its recorded result
    And the journal holds exactly the open record

  # @test:a_rewrite_keeps_only_open_records_and_unknown_kinds_with_stable_revisions
  # @test:a_rewrite_that_fails_leaves_the_journal_as_it_was
  # @test:a_closure_excludes_only_the_revision_it_names
  Scenario: Startup rewrites the journal atomically with only what is still open
    Given a journal with open, closed, duplicated, torn and unknown-kind records
    When startup rewrites it
    Then it keeps each open record once and the unknown kind verbatim, with the same revisions
    And a rewrite that fails leaves the journal exactly as it was

  # @test:a_closure_the_journal_cannot_take_changes_nothing
  Scenario: A closure that cannot be made durable closes nothing
    Given a closure record the journal refuses to write
    Then the answer is 500 and both halves stay reserved and listed

  # @test:with_no_closure_secret_the_route_is_off
  # @test:a_closure_secret_too_short_refuses_to_start
  # @test:the_secret_is_off_when_unset_and_refused_when_shorter_than_32_bytes
  Scenario: The route is off without a secret and a weak secret stops the gateway
    Given TOKENFUSE_CLOSURE_SECRET unset
    Then GET /v1/retained and POST /v1/retained/close answer 404 and the reservation stays retained
    And a secret shorter than 32 bytes exits 2 naming the variable before the listener binds

  # @test:malformed_requests_are_refused_before_anything_is_read
  Scenario: A malformed closure request is refused before any token or state is read
    Given an observed closure with no cost, a negative cost, a no_charge closure with a cost, an unknown field or evidence kind, or a bad operation id or evidence reference
    Then each is refused as an invalid request
