Feature: A policy plane that answers with an error status is reported by that status

  First seen 2026-09-24 on a live gateway in wardryx shadow mode: a request
  with no x-fuse-agent-id made wardryx answer 400 with its own message, and the
  gateway logged that wardryx's answer was not valid JSON and called the plane
  unreachable. A wrong key (401) and a 5xx read the same way, which sends an
  operator to a parser when the PDP said what was wrong. @measured
  `cargo test -p tokenfuse-gateway --test wardryx a_pdp_refusal_in_shadow`
  against 3fe4f6e with this change's tests added 2026-09-24: red, the trail
  detail reading "wardryx unreachable (wardryx response was not valid JSON".

  @decided 2026-09-24: an answer outside 2xx is its own error kind naming the
  status, checked before the body is decoded; the failmode decides exactly as
  it did and the answer is never cached; a 2xx whose body does not decode stays
  a decode error; the policy-plane accounting and the dependency_failed event
  stay correct. The last two scenarios are @claude: the same kind for the
  filter-tools route, and a bound on what a hostile answer can put in a line.

  # @test:a_refusal_is_logged_and_reasoned_by_its_status_not_as_bad_json
  # @test:a_pdp_refusal_in_shadow_reaches_the_trail_by_its_status_not_as_bad_json
  Scenario: A refusal is named by its status, not as bad JSON
    Given the wardryx hook is on
    And wardryx answers 400 with its own message
    When the gateway asks it about a call
    Then the logged error and the reason both name the status and wardryx's message
    And neither says the answer was invalid JSON or that wardryx was unreachable

  # @test:every_non_2xx_names_its_status_and_the_failmode_is_unchanged
  Scenario: The failmode decides a refusal exactly as before
    Given wardryx answers 401, 403, 500, 503 or a status with no standard phrase
    When the gateway asks it about a call
    Then failmode open allows the call and failmode closed denies it
    And the reason names the status and what wardryx said, or the standard phrase

  # @test:a_refusal_is_counted_as_a_fallback_and_never_cached
  Scenario: A refusal is never cached and never counted as a verdict
    Given the decision cache would reuse an answer for a minute
    And wardryx answers 401
    When the same call is asked about twice
    Then wardryx is asked twice
    And both answers are counted as fallbacks and neither as a verdict

  # @test:a_wrong_key_401_is_recorded_as_a_refusal_and_still_fails_closed
  Scenario: The trail records a refusal by its status
    Given the gateway exports agent events and enforces with failmode closed
    When wardryx answers 401 because the gateway's key is wrong
    Then the call is refused
    And one dependency_failed event names the policy plane, stage decide and effect denied_unasked
    And its detail names the status and wardryx's message

  # @test:a_2xx_that_does_not_decode_stays_a_decode_error
  Scenario: A 2xx that does not decode stays a decode error
    Given wardryx answers 200 with a body that is not a decision
    When the gateway asks it about a call
    Then the reason says the answer was not valid JSON

  # @test:a_pdp_nobody_can_reach_is_still_called_unreachable
  Scenario: A plane nobody can reach is still called unreachable
    Given nothing listens at the wardryx address
    When the gateway asks it about a call
    Then the reason says wardryx is unreachable

  # @test:a_filter_tools_refusal_names_its_status_and_what_wardryx_said
  # @test:a_wardryx_without_the_route_is_named_once_and_measures_nothing
  Scenario: The filter-tools route reports a refusal the same way and a missing route as its own kind
    Given shadow tool pruning is on
    When wardryx answers the filter-tools question with 401 and its own message
    Then the one warning names the status and the message and does not say the request failed
    But when wardryx answers 404 the warning says the route is missing

  # @test:a_hostile_refusal_body_becomes_one_short_line
  # @test:a_refusal_whose_body_never_ends_is_reported_without_waiting_for_it
  Scenario: A hostile answer cannot break the line it is quoted into
    Given wardryx, or something in front of it, answers 400 with control characters, invisible characters, a long message, or a body that never ends
    When the gateway asks it about a call
    Then the reason is one line of bounded length with no control or invisible character
    And a body that never ends is dropped at its cap rather than waited on
