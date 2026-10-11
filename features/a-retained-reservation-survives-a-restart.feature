Feature: A retained reservation survives a gateway restart

  A call handed to the provider that ends before any answer comes back is
  retained (invariant 50): its run reservation and its unit reservation stay
  outstanding until somebody reconciles them. The registry and the ledgers
  were process-local, so a restart forgot the exposure and the next call was
  admitted against room the provider may already have billed.

  The ask: persist each retained reservation to an append-only journal under
  the gateway's data directory, and replay it at startup so unit and run
  liability is restored with its original window and ancestor generations.
  Persistence and replay only: no closure path, no admin endpoint, no new
  dependency, and liability rebuilt from the journal, never from settled-spend
  totals.

  # @test:a_retained_reservation_survives_a_gateway_restart
  Scenario: A killed gateway comes back holding the same exposure
    Given a gateway with a data directory, a parent run, and a child call the provider receives and never answers
    When the gateway is killed and started again on the same data directory
    Then the child and its parent each hold the retained amount outstanding and the child lists one retained reservation
    And a call that fits the unit's cap on its own but not beside the restored reservation is refused 402

  # @test:a_retained_reservation_is_journaled_and_a_fresh_process_holds_it_again
  Scenario: A retain is written to disk before the call returns
    Given a settle guard whose call was dispatched and never answered
    When the guard is dropped
    Then the journal holds one record with the reservation's id, chain, unit window and time
    And a fresh ledger and unit ledger that replay it hold the same liability

  # @test:a_restored_reservation_holds_every_link_and_settles_by_its_own_handle
  Scenario: A restored reservation keeps its chain and generations
    Given a reservation admitted on a child and its parent
    When it is restored on a fresh ledger
    Then both runs come back at the generations the chain names, the child under its parent
    And settling it by the same handle releases both links exactly once

  # @test:a_unit_half_from_a_past_month_is_not_restored_and_the_run_half_is
  Scenario: A unit half taken in a month that has rolled over is not put back
    Given a reservation retained in July
    When the gateway restarts in August
    Then the unit holds nothing for it and the run still holds the amount

  # @test:a_superseded_generation_is_dropped_not_credited
  Scenario: A link on a generation a reopen superseded is not credited
    Given two reservations on one run, one before a close and reopen and one after
    When both are restored
    Then the run comes back at the later generation holding only the later amount

  # @test:a_parent_off_the_chain_is_kept_across_the_restore
  Scenario: A parent this gateway never opened is kept
    Given a child whose declared parent was never opened, retained in shadow
    When it is restored and the child's next call declares the same parent
    Then the parent is kept, not refused as adopted too late

  # @test:a_restored_run_still_gets_its_staged_cloud_seed
  Scenario: A restored run still gets its Cloud spend seed
    Given a Cloud seed staged for a run the journal restores
    When the journal is replayed at startup
    Then the run holds the seed as spend beside the restored reservation, and the seed is taken once

  # @test:a_torn_final_line_is_skipped_and_never_fuses_with_the_next_record
  Scenario: A crash in the middle of a write costs only that record
    Given a journal whose last line was cut off by a crash
    When it is read, and a new record is appended after reopening
    Then the torn line is counted and skipped, and every whole record, the new one included, is read

  # @test:a_reservation_retained_past_the_registry_cap_is_still_journaled
  Scenario: The registry's cap bounds what is listed, never what is journaled
    Given a registry already listing its maximum
    When another reservation is retained
    Then it is not listed and it is in the journal

  # @test:an_unreadable_journal_refuses_to_start_before_the_listener_binds
  Scenario: A journal that exists and cannot be read stops the gateway
    Given a data dir whose retained-reservation journal cannot be read
    When the gateway starts
    Then it exits non-zero before the listener binds, naming the journal's path and the error

  # @test:a_missing_or_empty_journal_still_starts
  Scenario: A missing or empty journal still starts
    Given a data dir with no journal, or an empty one
    When the gateway starts
    Then it serves
