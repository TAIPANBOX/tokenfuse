Feature: One owner for a call's reservations, and what each outcome is charged

  A managed call takes up to two reservations before it is forwarded, one on
  the run's budget chain and one on the unit's monthly cap, and until
  2026-09-18 nothing owned them across the awaits that followed. The settle
  guard existed only on the streaming path and only after the provider had
  answered, so a client that gave up while the provider still held the
  request leaked both reservations for the life of the run and of the month
  (F03 and 3.4 of the 2026-09-18 money-path review); a 2xx whose body then
  broke was settled at zero on both, so a completion the provider did and
  billed for cost the run nothing (F04 and 3.5), and the buffered and the
  streaming path disagreed on that one event.

  @decided 2026-09-17: a call cancelled before the provider answered leaves
  no trace row, like the send-error arm.
  @decided 2026-09-18: a call whose outcome is unknown after dispatch keeps
  its reservation until it is reconciled; it is never settled at zero, and
  completing it at the estimate is not chosen. A call that was definitely
  not sent, and a refusal that reports no priced usage, release as before; a
  2xx that then breaks settles at the estimate; parsed usage settles as
  parsed.

  @claude on the shape: one guard, created when the first reservation is
  taken, owns both halves and decides on Drop from the call's outcome state,
  never from whether anybody remembered to call settle. The states are what
  happened on the wire; how much an answered call is charged is the settle
  basis the code already had. Invariant 50.

  # @test:a_guard_dropped_before_dispatch_releases_both_ledgers_and_writes_no_row
  # @test:a_guard_holding_only_the_unit_half_releases_it_on_drop
  # @test:a_run_budget_refusal_releases_the_unit_reservation
  Scenario: Reserved and not yet dispatched
    Given a call whose unit and run reservations are held and whose request has not been handed to the provider
    When the call ends there, or the run's own budget refuses it after the unit half was taken
    Then both reservations are released at zero
    And no trace row is written

  # @test:codex_held_not_sent_error_releases_without_spend_on_both_paths
  # @test:a_guard_told_the_send_failed_releases_both_and_writes_no_row
  Scenario: The request did not reach the provider
    Given a request rejected during construction before transport dispatch
    When the call is forwarded on either path
    Then the caller gets a 502, both reservations are released at zero, and no trace row is written

  # @test:codex_f03_cancel_during_provider_send_is_retained_not_released
  # @test:a_cancel_while_the_provider_holds_the_request_retains_both_ledgers
  # @test:a_guard_dropped_while_the_provider_holds_the_request_retains_and_warns
  # @test:a_retained_reservation_is_listed_on_the_runs_endpoint
  Scenario: The provider holds the request and the call ends before it answers
    Given a call handed to the provider that has not answered
    When the caller disconnects and the request future is dropped
    Then neither reservation is settled or released: the run's and the unit's reserved amounts stay outstanding at the estimate, on the leaf and on its parent, and spent stays zero
    And a warning names the run, the reservation, the amount and the unit
    And the runs endpoint lists the run with the retained count and amount
    And no trace row is written

  # @test:a_429_from_the_provider_settles_nothing_as_spend
  # @test:a_streaming_429_from_the_provider_settles_nothing_as_spend
  # @test:a_refused_stream_dropped_without_complete_settles_zero_not_the_estimate
  Scenario: A refusal that reports no priced usage
    Given a reachable provider answering a non-2xx with no usage
    When the call is forwarded on either path, drained or abandoned
    Then the provider's status passes through, both reservations settle at zero, and the allow row carries cost zero

  # @test:a_refusal_that_reports_usage_settles_that_usage_not_zero
  # @test:a_refused_stream_that_reported_usage_still_settles_it
  Scenario: A refusal that reports what it generated
    Given a provider answering a non-2xx whose usage block prices a partial generation
    When the call settles
    Then both reservations settle at that usage, neither zeroed nor replaced by the estimate

  # @test:codex_f04_real_http_2xx_body_error_must_not_silently_settle_zero
  # @test:a_2xx_whose_body_breaks_settles_the_estimate_on_both_ledgers_and_writes_the_row
  # @test:codex_held_real_http_stream_error_releases_and_uses_estimate
  Scenario: A 2xx whose body breaks before any usage arrived
    Given a provider that answers 200 and then breaks the body, on the buffered path and on the streaming path
    When the break reaches the gateway
    Then both reservations settle at the pre-flight estimate and the allow row carries that estimate
    And the buffered caller gets a 502 while the streaming caller already had its 200
    And one dependency_failed names the stage

  # @test:codex_f04_buffered_body_error_preserves_reported_usage
  # @test:a_2xx_whose_body_breaks_after_reporting_usage_settles_that_usage
  Scenario: A 2xx whose body breaks after the usage was reported
    Given a provider that answers 200, reports usage, and then breaks the body
    When the break reaches the gateway
    Then both reservations settle at the reported usage, not the estimate and not zero

  # @test:codex_f03_cancel_during_buffered_body_releases_reservation
  # @test:a_cancel_while_the_body_is_being_collected_settles_the_estimate_on_both_ledgers
  # @test:client_cancel_midstream_still_settles
  # @test:codex_held_stream_drop_before_first_poll_settles_once
  Scenario: The caller leaves after the provider answered 2xx
    Given a provider that answered 200 and is still sending the body
    When the caller disconnects, during the buffered read or mid-stream
    Then both reservations settle at the estimate, because the provider did the work and the outcome is not unknown
    And the allow row carries the estimate

  # @test:the_shadow_twin_of_a_broken_2xx_records_the_estimate_and_no_shadow_event
  Scenario: Shadow and warn charge the same on a broken 2xx
    Given a gateway in shadow or warn mode whose provider answers 200 and then breaks the body
    When the break reaches the gateway
    Then the run's spend is the estimate and the allow row carries it, so a shadow week does not under-count
    And no breaker_shadow and no breaker_tripped is written for it

  # @test:complete_settles_with_parsed_usage
  # @test:unit_spend_settles_into_the_unit_ledger
  Scenario: Usage was parsed
    Given a provider whose body carries a priced usage block
    When the call completes
    Then both reservations settle at that usage, priced at the book's rate

  # @test:a_second_settle_of_one_guard_changes_nothing
  Scenario: A settlement happens once
    Given a guard that has already settled its call
    When it is asked to settle again, and then dropped
    Then the run and the unit are charged once and one trace row exists

  # @test:the_run_and_unit_ledgers_agree_in_every_terminal_state
  # @test:every_state_has_the_disposition_the_rule_names
  Scenario: The run and the unit ledgers agree in every state
    Given a call with both reservations, driven to each terminal state in turn
    When it ends
    Then the unit's reserved amount is zero exactly when the run's is, both carry the same spend, and only the unknown outcome leaves both outstanding
