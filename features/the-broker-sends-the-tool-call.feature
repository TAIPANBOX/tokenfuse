Feature: The MCP broker tells the policy plane which call it is about to make

  The broker asks the policy plane about every tools/call before it injects
  secrets, and used to say only the tool's name. A policy that depends on what
  a call does (its arguments, the server it goes to) had nothing to read. The
  decide request now also carries the concrete call. It is generic: any
  argument-aware policy can use it. The model path has no pending call, so it
  sends none.

  # @test:the_decide_body_for_a_tools_call_carries_name_arguments_and_target
  # @test:a_call_under_the_cap_keeps_its_arguments_exactly
  # @test:the_wire_body_for_a_call_names_the_call
  Scenario: A tools/call is put to the policy plane with its name, arguments and target
    Given the broker has a policy plane configured and routes to its default upstream
    When an agent calls the tool "gh_api" with arguments {"repo": "acme/widgets", "n": 3}
    Then the decide request carries tool_call with the name "gh_api"
    And its arguments are exactly {"repo": "acme/widgets", "n": 3}
    And its target is the host and port of the default upstream
    And the tool_names the plane has always received are unchanged

  # @test:a_named_upstream_is_the_target_by_its_name
  Scenario: A named upstream is the target by its name
    Given the broker has an upstream named "backup"
    When an agent calls a tool with the header x-fuse-mcp-upstream: backup
    Then the tool_call target is "backup"

  # @test:a_secret_handle_reaches_the_pdp_as_the_handle_and_never_as_the_value
  Scenario: A secret handle reaches the policy plane as the handle and never as the secret
    Given the vault holds a secret named "gh"
    When an agent calls a tool with the argument "Bearer {{secret:gh}}"
    Then the policy plane is shown "Bearer {{secret:gh}}"
    And no part of the decide request contains the secret's value
    And the upstream receives the call with the value injected

  # @test:oversized_arguments_are_replaced_by_the_flag_and_still_forwarded_whole
  # @test:an_oversized_call_goes_out_as_valid_json_without_arguments_and_flagged
  # @test:a_call_over_the_cap_loses_its_arguments_and_says_so
  Scenario: Arguments over 16 KiB are replaced by a flag, never cut short
    Given the arguments serialize to more than 16 KiB
    When the agent makes the call
    Then the decide request carries tool_call without arguments
    And it carries arguments_truncated true
    And the upstream still receives the whole call

  # @test:the_cap_is_on_serialized_bytes_and_inclusive
  # @test:arguments_at_the_cap_are_sent_and_a_call_with_none_says_nothing_of_truncation
  # @test:a_call_with_no_arguments_is_not_called_truncated
  Scenario: The cap is exactly 16 KiB and a call with no arguments is not called truncated
    Given arguments that serialize to exactly 16384 bytes
    When the agent makes the call
    Then the arguments are sent whole
    And one byte more is replaced by the flag
    And a call that carries no arguments sends neither arguments nor the flag

  # @test:the_llm_paths_decide_body_has_no_tool_call_even_with_tools_offered
  # @test:a_decide_with_no_call_has_no_tool_call_member_at_all
  Scenario: The model path sends no tool_call
    Given a model request that offers a tool but has chosen no call
    When the gateway puts it to the policy plane
    Then the decide request has no tool_call member at all

  # @test:a_tool_call_gets_the_tool_budget_and_a_model_call_keeps_the_shared_one
  # @test:the_environment_names_reach_the_tool_timeout
  Scenario: A tool call can have its own timeout and the model path keeps the shared one
    Given TOKENFUSE_WARDRYX_TIMEOUT_MS is 80 and TOKENFUSE_MCP_WARDRYX_TIMEOUT_MS is 900
    When the policy plane takes 300 ms to answer
    Then a decide carrying a tool_call gets its verdict
    And a decide without one falls back as an unreachable plane

  # @test:the_tool_timeout_defaults_to_the_shared_budget
  # @test:with_only_the_shared_timeout_set_the_tool_path_gets_it_too
  # @test:a_set_tool_timeout_is_read_and_a_set_unusable_one_is_the_shared_budget
  Scenario: Unset means the shared value and an unusable value does too
    Given TOKENFUSE_MCP_WARDRYX_TIMEOUT_MS is unset, blank, zero, negative or not a number
    When the broker's policy hook is built
    Then the tool path's timeout is TOKENFUSE_WARDRYX_TIMEOUT_MS

  # @test:hostile_arguments_never_panic_and_the_broker_keeps_serving
  # @test:arguments_that_serialize_to_exactly_the_cap_in_many_shapes_never_panic
  Scenario: Hostile arguments never take the broker down
    Given arguments nested past the parser's limit, a million-character string, a wide object, non-object shapes and invalid UTF-8
    When each is sent as a tools/call
    Then none of them panics or gets a server error
    And every request that reached the policy plane was valid JSON within the cap
    And a normal call right afterwards is served
