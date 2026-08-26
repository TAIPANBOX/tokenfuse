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

  # ---------------------------------------------------------------------
  # 2026-08-26, the second pass. @yurii, on reading what the first pass did
  # NOT do: "Це рівень 1 із docs/07 B.7, дорадчий: шлюз бачить tool_use у
  # відповіді моделі, а виконує інструмент клієнт. Той, хто ігнорує 403,
  # нічим із цього не спиняється. Рівні 2 і 3 не побудовані. Спадкування
  # taint у під-ранах не побудоване. Фаєрвол досі за замовчуванням off."
  # ---------------------------------------------------------------------

  # @test:a_sub_run_cannot_launder_its_parents_taint
  Scenario: A sub-agent cannot be used to wash the taint off
    Given a run that has read the web and is therefore untrusted
    And a child run whose own history is spotless
    When the child asks to run a shell
    Then it is refused, because it is judged against what its parent touched
    And the record says the labels came from a parent run, naming which

  # @test:a_run_that_declares_itself_its_own_ancestor_does_not_hang_the_box
  Scenario: A parent chain that loops does not take the gateway down
    Given two runs each declaring the other as its parent
    When either of them makes a call
    Then it is answered, rather than spinning inside a lock on the request path

  # @test:an_executor_can_ask_before_it_runs_the_tool
  Scenario: An executor asks permission before running a tool
    Given an executor that will act on the answer
    When it asks whether a tainted run may run a shell
    Then it is told no, before the tool has run rather than after

  # @test:the_two_doors_answer_the_same_way_about_one_run
  Scenario: Asking first and being judged after give the same answer
    Given one run and one tool
    When an executor asks, and the same run's model answer is judged
    Then both say the same thing, naming the same rule

  # @test:a_firewall_that_is_off_says_allow_and_ungoverned_not_just_allow
  Scenario: Permitted and unjudged are not the same answer
    Given a gateway whose firewall is off
    When an executor asks whether it may run a tool
    Then it is told the call is allowed and that nothing judged it, so it
      cannot record a governance gap as a permission

  # @test:the_mcp_door_refuses_a_tool_a_tainted_run_may_not_use
  Scenario: The MCP door stops it whether or not anybody asked
    Given a broker pointed at a gateway that judges
    When a tainted run calls a tool through it
    Then the call is refused before any secret is injected and before the
      upstream is reached

  # @test:an_allowed_tool_still_reaches_the_upstream
  Scenario: The MCP door lets ordinary work through
    Given the same broker and a call nothing objects to
    When it is made
    Then it reaches the upstream unchanged

  # @test:a_call_with_no_run_id_is_refused_only_when_the_gate_is_fail_closed
  Scenario: A call with no run cannot be judged, and that is the operator's call
    Given an MCP call carrying no run identity
    When the gate is fail-open, then fail-closed
    Then it is let through in the first case and refused in the second, and
      the refusal names the header that would fix it

  # @test:a_gateway_that_cannot_be_reached_does_not_silently_become_permission
  Scenario: A judge that cannot be reached is recorded, not assumed
    Given a broker whose gateway is down
    When a tool call arrives
    Then fail-open lets it through and records that nothing governed it

  # @test:the_default_is_shadow_so_a_box_that_asked_for_nothing_still_measures
  Scenario: A box that configured nothing still measures
    Given a gateway started with no firewall setting at all
    When it runs
    Then the firewall is in shadow, refusing nothing and recording everything
    And setting it to off still turns it off

  # @test:the_record_says_which_instruction_the_turn_carried
  Scenario: Which instruction the turn carried
    Given a run that became untrusted and then tried something dangerous
    When both events are written
    Then each carries the same hash of the instruction that turn was given
    And no word of the instruction appears anywhere on the bus

  # @test:a_turn_with_no_instruction_records_no_hash_rather_than_an_empty_one
  Scenario: A turn with no instruction says so
    Given an agent-driven turn carrying only tool results
    When it is recorded
    Then the instruction field is absent rather than empty, because "we looked
      and there was nothing" is a different claim from "this turn had none"

  # @test:the_same_instruction_hashes_to_the_same_value_across_turns
  Scenario: Four incidents from one instruction are recognisable as one
    Given the same instruction given on turn one and again on turn five
    When both are hashed
    Then they are the same value, so incidents group by what caused them

  # @test:it_is_a_hash_and_carries_no_word_of_the_prompt
  Scenario: The instruction is stored by hash and only by hash
    Given an instruction containing a passphrase and a card number
    When it is hashed
    Then the result carries neither, and there is nothing here to erase

  # @test:an_inherited_label_is_not_reported_as_a_tool_this_run_called
  Scenario: The report does not send you looking for a tool that is a run
    Given one run that read the web and one that inherited it
    When the report is produced
    Then the tool is credited once and the inheritance is counted separately
