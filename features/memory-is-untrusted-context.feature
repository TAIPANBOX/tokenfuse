Feature: Memory is untrusted context

  An agent's memory can carry an instruction somebody planted, and the model
  reads it as though the user had said it. So a run whose prompt holds memory
  is untrusted, the same way a run that read a web page is, and a later send
  is refused the same way.

  Measured 2026-10-12: an instruction planted in an agent's memory, put into
  the prompt, labelled nothing, so a later send_email was allowed.

  # @test:a_memory_label_declared_in_the_prompt_stops_a_later_send
  Scenario: A memory label declared in the prompt stops a later send
    Given the starter policy in enforce mode
    And the caller declares memory in the x-fuse-taint header
    When the model answers by asking to send an email
    Then the call is refused with 403 under the rule no-exec-after-untrusted

  # @test:a_recalled_memory_is_labelled_memory_not_unclassified
  Scenario: A recalled memory is labelled memory, not unclassified
    Given the starter policy in enforce mode
    And the conversation earlier called the recall tool
    When the model answers by asking to send an email
    Then the run records the label memory, and not unclassified
    And the call is refused with 403

  # @test:why_returns_memory_as_well
  Scenario: The why tool returns memory as well
    Given the starter policy in enforce mode
    And the conversation earlier called the why tool
    Then the run records the label memory for that tool

  # @test:the_starter_policy_denies_memory_after_exec
  Scenario: The starter policy denies a send after memory and maps both memory tools
    Given the built-in starter policy
    Then the no-exec-after-untrusted rule names memory among its labels
    And recall and why are both mapped to memory

  # @test:a_policy_file_with_no_memory_rule_still_refuses_a_memory_run
  Scenario: A policy file with no memory rule still refuses a send after memory
    Given a policy file in enforce mode with a rule of its own and no rule naming memory
    And the caller declares memory in the x-fuse-taint header
    When the model answers by asking to send an email
    Then the call is refused with 403 under the rule no-action-after-memory

  # @test:an_operator_rule_that_names_memory_is_not_given_a_second_floor
  Scenario: A policy file that already names memory gets no second rule
    Given a policy file in enforce mode with a rule that names memory
    Then the firewall adds no rule for memory of its own

  # @test:in_shadow_a_memory_label_is_recorded_and_nothing_is_refused
  Scenario: In shadow mode memory is recorded and nothing is refused
    Given the starter policy in shadow mode
    And the caller declares memory in the x-fuse-taint header
    When the model answers by asking to send an email
    Then the call is answered 200
    And the would-block is recorded as a shadow event

  # @test:a_memory_label_on_a_text_only_answer_refuses_nothing
  Scenario: A memory label on a text-only answer refuses nothing
    Given the starter policy in enforce mode
    And the caller declares memory in the x-fuse-taint header
    When the model answers with text only
    Then the call is answered 200
    And the label is recorded

  # @test:with_the_firewall_off_memory_is_not_labelled
  Scenario: With the firewall off, memory is not labelled at all
    Given the firewall is off
    And the caller declares memory in the x-fuse-taint header
    Then no taint event is written
