Feature: A revocation list something actually consults

  vouchryx has served `GET /v1/revocations` since the day it was written, with
  an `as_of` cursor so a poller can tell an empty list from a failed fetch.
  Measured 2026-08-26: nothing polls it. Both doors in this repository pass
  `revoked: |_, _, _| false`, and no Go enforcement point sets
  `Options.Revoked` either. Zero consumers, in either language.

  Four documents said the opposite in the present tense: vouchryx's own
  `revoke.go`, its README, its feature file, and agent-stack-go's README. So
  "revoking a delegation ends the right to act at every enforcement point at
  once" was a sentence about nothing that ran. This is the library that makes
  it true, and the four sentences are corrected in the same wave.

  The decision those sentences hide is what an enforcement point should do when
  the list it holds has gone old. The estate has answered "a dependency is
  unreachable" twice, both times with an operator-chosen fail mode defaulting
  to open, and this matches that. But a revocation list has a third state the
  other two do not: a PDP you cannot reach tells you nothing, while a list from
  four minutes ago still holds every revocation older than four minutes.

  Background:
    Given an enforcement point holding a revocation list it fetched earlier
    And a delegation token whose signature, binding and expiry are all perfect

  # @test:a_revoked_token_is_refused_by_something_that_actually_read_the_list
  Scenario: A revoked token stops working
    Given the list names that token
    When the enforcement point checks it
    Then the token is refused, and the answer says it came from the list

  # @test:a_token_the_list_does_not_name_is_not_refused
  Scenario: A token nobody revoked keeps working
    Given the list does not name that token
    When the enforcement point checks it
    Then the token is allowed, which is what stops the refusal above from
      being a cache that refuses everything

  # @test:a_subject_revocation_covers_what_was_issued_at_or_before_its_moment
  Scenario: An agent is revoked without being banned
    Given the operator revoked every token issued for that agent up to a moment
    When tokens issued before, during and after that second are checked
    Then the first two are refused and the third is not, so an operator who
      revokes in order to re-issue does not have to wait out a lifetime

  # @test:a_stale_list_still_refuses_what_it_names
  Scenario: A list four minutes old still holds what it already knew
    Given the poller has not succeeded for four minutes
    And the held list names that token
    When the enforcement point checks it
    Then the token is still refused, because nothing un-revokes a token and
      calling a token we know is dead a live one is worse than the outage

  # @test:a_miss_on_a_stale_list_falls_back_to_the_fail_mode
  Scenario: A list too old to be complete stops answering for absence
    Given the poller has not succeeded for longer than the maximum age
    And the held list does not name that token
    When the enforcement point checks it
    Then the operator's fail mode answers instead of the list, because a miss
      is an inference from the list being complete and completeness is the
      property that expired

  # @test:a_list_exactly_at_the_maximum_age_is_still_trusted_for_a_miss
  Scenario: The boundary is the boundary
    Given the held list is exactly at the maximum age
    When a token the list does not name is checked
    Then it is allowed from the list rather than by the fail mode, so "stale"
      cannot quietly become "anything that is not this instant"

  # @test:a_list_nobody_ever_fetched_says_so_rather_than_reading_as_empty
  Scenario: A poller nobody wired is not an empty list
    Given no list has ever been fetched
    When any token is checked
    Then the fail mode answers, and the answer says nothing was ever fetched
      rather than saying the list was empty, because a poller that has never
      once succeeded is a configuration fault and will not clear itself

  # @test:an_answer_from_the_list_is_never_reported_as_a_fallback
  Scenario: An operator can tell a real answer from a fallback
    Given a list young enough to answer
    When tokens both in it and absent from it are checked
    Then neither answer is reported as a fallback, so a count of fallbacks
      measures outages rather than traffic

  # @test:a_cursor_that_moved_backwards_is_refused_and_does_not_reset_the_age
  Scenario: An answer describing an earlier moment never replaces a later one
    Given the enforcement point holds a list with a cursor
    When a fetch returns a list whose cursor is earlier than the one held
    Then it is refused and counted, the newer list is kept, and the age is not
      reset, because installing it would make a view that had stopped moving
      start reading as fresh

  # @test:a_cursor_that_did_not_move_is_accepted_because_a_second_is_a_coarse_clock
  Scenario: Two fetches in one second are not a fault
    Given the cursor is a Unix second
    When two fetches return the same cursor
    Then the second is applied, because refusing it would break any poller
      faster than once a second

  # @test:a_snapshot_with_no_cursor_is_refused_rather_than_aged_from_nothing
  Scenario: A list with no cursor cannot be aged, so it is not installed
    Given a fetch returns a list carrying no `as_of` at all
    When it is offered to the cache
    Then it is refused, and the enforcement point still reports never having
      fetched anything

  # @test:an_entry_naming_neither_a_token_nor_a_subject_matches_nothing
  Scenario: A malformed entry revokes nothing rather than everything
    Given an entry that names neither a token id nor a subject
    When any token is checked against it
    Then it matches nothing, because comparing two empty ids would revoke
      every token that carries none

  # @test:an_entry_past_its_own_expiry_stops_matching
  Scenario: An entry stops being load-bearing when the last token it could match has expired
    Given an entry carrying its own expiry
    When a token is checked before and after that moment
    Then it matches only before, so the list does not grow for ever

  # @test:an_entry_with_no_stated_expiry_is_kept_rather_than_dropped
  Scenario: An entry with no stated expiry is kept rather than dropped
    Given a producer that stated no expiry on an entry
    When a token it names is checked long afterwards
    Then it still matches, because dropping an entry early makes a revoked
      token work and keeping one late only outlives a token that has expired

  # @test:the_hook_is_the_shape_verify_delegation_takes_and_shows_the_caller_the_basis
  Scenario: Wiring it into the verifier shows the caller what the answer rested on
    Given an enforcement point wiring this into `verify_delegation`
    When it checks a revoked token and a live one
    Then it gets the plain answer the verifier needs, and separately sees what
      each answer rested on, so a fallback cannot pass unnoticed

  # @test:the_body_vouchryx_serves_parses_into_this
  Scenario: The body vouchryx actually serves is the body this reads
    Given a response copied from a live `GET /v1/revocations`
    When it is parsed
    Then both entry shapes come through with their cursor

  # @test:a_body_that_is_not_a_list_at_all_is_an_error_rather_than_an_empty_list
  Scenario: Something else answering on that port is not an empty list
    Given a body that is not a revocations object
    When it is parsed
    Then it is an error rather than an empty list, including the JSON array
      that a derived deserializer would otherwise read positionally into an
      empty snapshot

  # @test:an_empty_list_is_a_list_and_not_a_failure
  Scenario: An empty list is knowledge
    Given a fetch that succeeded and returned no revocations
    When a token is checked
    Then it is answered from that list rather than by the fail mode
