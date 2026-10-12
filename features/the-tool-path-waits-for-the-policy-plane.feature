Feature: The MCP broker waits for the policy plane long enough to hear a deny

  With no timeout variable set, the broker's tool path used the model path's
  50 ms deadline for the policy plane. A deny that took longer (the ordinary
  case when wardryx sits behind the typed-signal proxy, which itself waits up
  to 150 ms) arrived after the broker had given up, and the default failmode,
  open, let the denied call through. Fail-open stays the default, and
  destructive tools stay a matter of deny rules in policy; what changes is that
  the tool path gets its own default deadline, 1000 ms, while the model path
  keeps 50 ms and an operator's explicit choice still governs both.

  # @test:a_deny_slower_than_the_model_paths_deadline_still_refuses_the_tool_call
  # @test:with_nothing_set_the_tool_path_waits_1000_ms_and_the_model_path_50
  Scenario: A deny that takes 120 ms is honoured when nothing is configured
    Given a broker started with no timeout variable and the default failmode
    And a policy plane that answers deny after about 120 ms
    When an agent makes a tools/call
    Then the call is refused as the policy plane decided
    And nothing is forwarded to the upstream MCP server

  # @test:an_explicit_shared_timeout_still_governs_the_tool_path
  # @test:an_explicit_shared_timeout_is_the_deadline_of_both_paths
  # @test:with_only_the_shared_timeout_set_the_tool_path_gets_it_too
  Scenario: An operator who set the shared timeout keeps it on the tool path
    Given TOKENFUSE_WARDRYX_TIMEOUT_MS is set to 50 and the tool path's own variable is not
    When the broker's policy hook is built
    Then a tools/call waits 50 ms, as the operator chose
    And the same 120 ms deny arrives late and the failmode decides the call

  # @test:with_nothing_set_the_tool_path_waits_1000_ms_and_the_model_path_50
  # @test:an_unreadable_shared_timeout_is_not_an_operators_choice
  Scenario: The model path keeps its 50 ms default
    Given no timeout variable is set, or the shared one does not parse
    When the hook is built
    Then a decide for a model call waits 50 ms
    And a decide for a tool call waits 1000 ms

  # @test:the_tool_paths_own_variable_wins_over_the_shared_one_and_the_default
  # @test:the_environment_names_reach_the_tool_timeout
  # @test:a_set_tool_timeout_is_read_and_a_set_unusable_one_is_the_shared_budget
  Scenario: The tool path's own variable comes first
    Given TOKENFUSE_MCP_WARDRYX_TIMEOUT_MS is a positive number of milliseconds
    When the hook is built
    Then the tool path waits that long, whatever the shared value is
    And the model path still waits the shared value or 50 ms

  # @test:an_unusable_tool_timeout_falls_back_by_the_precedence_and_warns_once
  # @test:an_unset_tool_timeout_takes_the_shared_budget_the_operator_set_or_1000
  Scenario: An unusable tool-path value falls back by the same order, with one warning
    Given TOKENFUSE_MCP_WARDRYX_TIMEOUT_MS is zero, negative or not a number
    When the hook is built
    Then the tool path uses the shared value if the operator set one, else 1000 ms
    And exactly one warning names the value it could not use
    And a blank value is read as unset and warns about nothing
