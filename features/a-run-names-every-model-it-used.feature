Feature: A run in the fleet view names every model it used and a gateway's kill

  A run on forge on 2026-10-14 spent 96% of its money on Opus and then made
  one call on Haiku. The Cloud's run row named one model, the last to arrive,
  so the row read Haiku and the console's assistant said the run used Haiku.
  A run killed on one gateway's own admin route still read not killed in the
  Cloud, because nothing about that kill reached it.

  @decided 2026-10-14: the Cloud keeps, per run, the list of models with each
  one's calls and spend, bounded, and how many times the run changed model;
  the run's model is the one of its latest call by time; the run API returns
  them; a run a gateway refused as killed reads killed in the Cloud. Existing
  readers keep working.

  @claude 2026-10-14: only an admitted call (allow, cache_hit) counts as a
  model the run used; a refusal names a model it never ran. The list keeps 16
  ids and counts the rest under "(other models)", since model ids are chosen
  by the caller. A gateway's kill is learned from its "killed" refusal row and
  is shown, never added to the Cloud's own kill list.

  # @test:a_run_that_changed_model_says_which_and_how_often
  Scenario: A run that went from Opus to Haiku says both, and how often it changed
    Given a run with two Opus calls and then one Haiku call, pushed newest first
    When /v1/runs is read
    Then the run's model is Haiku, the latest call by its own time
    And its models list Haiku with one call and Opus with two, each with its spend
    And it changed model once
    And after one more Opus call it changed model twice

  # @test:an_older_record_never_takes_the_model_from_a_later_call
  Scenario: A record that arrives late does not rename the run
    Given a run whose newer call was pushed before an older one
    When /v1/runs is read
    Then the run's model is the newer call's
    And both models are in its list

  # @test:a_refusal_names_no_model_the_run_used_and_changes_nothing
  Scenario: A refused call is not a model the run used
    Given a run with one admitted Haiku call and one Opus call refused for budget
    When /v1/runs is read
    Then its models list only Haiku
    And it changed model zero times

  # @test:a_run_a_gateway_refused_as_killed_reads_killed
  Scenario: A run a gateway refused as killed reads killed in the fleet view
    Given a gateway that refused a call on a run because the run is killed there
    When /v1/runs is read
    Then the run reads killed
    And the Cloud's own kill list does not name it
