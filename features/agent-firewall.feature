Feature: The agent firewall says what it did, and can be told what to do

  The ask, verbatim, @yurii 2026-08-26: "роби по максимуму глибокий сервіс,
  тобто наш фільтр, щоб можна було його налаштовувати та мати повну
  статистику: на якому етапі, що було зроблено, що отримав агент, як діяв і
  так далі."

  What was there before. The firewall has been able to refuse a dangerous
  action since Ring 3.1 shipped, and it was correct. It was also mute. A
  refusal wrote one prose sentence, so a week of them could be read one at a
  time and never counted. Becoming untrusted, which is the thing that CAUSES
  every refusal, was written nowhere at all. And shadow mode, which docs/07
  B.9 names as the on-ramp every operator is supposed to start on, emitted
  no event whatsoever: it set a response header, so the only party told that
  a dangerous action had been permitted was the agent that had just been
  talked into it.

  Its policy was also a Rust literal. Adding one of your own tools to the
  source map meant a recompile and a redeploy, which is why in practice
  nobody ever adjusted it and every box ran the same nine starter tool names.

  Background:
    Given a gateway with the agent firewall switched on
    And the event stream is configured

  # @test:becoming_tainted_is_recorded_not_only_being_blocked
  Scenario: A run reads the web and the fact is written down
    Given an agent whose history shows it called a web search
    When it makes its next call
    Then the stream carries one event saying the run became untrusted
    And that event names the tool that carried the label in
    And it carries the run's full label set, so a later refusal needs no
      re-derivation

  # @test:a_shadow_would_block_is_recorded
  Scenario: Shadow mode permits a dangerous action and says so
    Given the firewall is in shadow
    And a run that has already touched the web
    When the model asks to run a shell
    Then the caller still gets its answer, because shadow does not block
    And the stream carries a would-block event at the medium band
    And an operator can therefore count a week of them before deciding

  # @test:the_record_says_which_rule_fired_at_which_stage_and_over_what
  Scenario: A refusal can be grouped, not only read
    Given the firewall is enforcing
    And a run that has already touched the web
    When the model asks to run a shell
    Then the call is refused
    And the record names the stage, the mode, the rule, the labels it was
      carrying, what was denied, and the tool it asked for by name

  # @test:a_policy_can_be_changed_without_a_rebuild
  Scenario: An operator writes their own policy
    Given a policy file naming their own tools, capabilities and one rule
    When the gateway loads it
    Then their rule is what decides, and no rebuild was needed

  # @test:one_tool_can_carry_more_than_one_label
  Scenario: One source carries more than one label
    Given a tool whose output is both an upload and personal data
    When the policy file gives it both labels
    Then a rule about either of them can fire

  # @test:anti_exfiltration_cannot_be_dropped_in_enforce_mode
  Scenario: The rule an operator cannot delete by accident
    Given a policy file that names only the operator's own rule
    When the gateway loads it in enforce mode
    Then anti-exfiltration is put back, first in the order
    And secrets plus an outbound capability is still refused

  # @test:shadow_mode_does_not_get_the_floor_forced_on_it
  Scenario: Shadow measures the operator's policy and not ours
    Given the same file loaded in shadow mode
    When the gateway loads it
    Then only the operator's own rule is present, so the week's numbers
      describe the policy they actually wrote

  # @test:a_config_that_cannot_be_read_stops_the_box_rather_than_falling_back
  Scenario: A broken policy file stops the gateway
    Given a policy file with a misspelled key or an unknown mode
    When the gateway starts
    Then it refuses to start rather than quietly running the built-in policy

  # @test:the_error_says_what_to_fix
  Scenario: The refusal names the field
    Given a policy file whose mode is not one of the three
    When the gateway refuses it
    Then the message names the field, the bad value, and the accepted ones

  # @test:an_empty_config_is_the_off_switch_not_the_starter_policy
  Scenario: An empty policy is empty
    Given a policy file that is an empty object
    When the gateway loads it
    Then nothing is classified and nothing is refused, rather than the
      built-in starter policy appearing in its place

  # @test:acquisitions_count_runs_not_events
  Scenario: The report counts runs, not chatter
    Given one run that read the web on several turns
    When the report is produced
    Then that label shows one run per run, so a chatty agent does not read
      as a fleet-wide problem

  # @test:the_enforce_projection_counts_only_what_shadow_let_through
  Scenario: The number the shadow week exists to produce
    Given a window containing both refusals and would-blocks
    When the report is produced
    Then it says how many actions turning enforcement on would refuse, over
      how many runs and agents, and which rule and agent carry most of it
    And it counts only what shadow let through, never what was already
      refused

  # @test:the_report_answers_all_four_questions
  Scenario: The report answers what was asked of it
    Given a window with an acquisition and a would-block
    When the report is produced
    Then it says how runs became untrusted, what the filter decided, what the
      agents tried to do, and at which stage

  # @test:an_empty_read_says_it_measured_nothing_rather_than_all_clear
  Scenario: Nothing measured is not the same as nothing found
    Given an event file with no firewall events in it
    When the report is produced
    Then it says it measured nothing and names the switch that would have
      produced some, rather than printing an all-clear
