Feature: The tools a request declares are read for poisoning

  The MCP broker scans a tool listing, but a tool declared directly in a model
  request reached the model with its description unread. Measured against the
  v1.10.0 binary with the firewall enforcing: a declared tool whose description
  ordered the model to call another tool and hide it was answered 200 with no
  mark on the run. The scan is a source of taint and never a decision: it
  labels the run, and the later tool call is what gets judged.

  # @test:a_poisoned_declared_tool_marks_the_run_and_the_next_dangerous_call_is_denied
  Scenario: A poisoned declared tool marks the run and the next dangerous call is denied
    Given the firewall is enforcing and a request declares a tool whose description orders the model to call another tool and hide it
    When the model's answer asks to run a shell in that run
    Then the call is refused with 403
    And the event bus records that the run acquired the suspected-injection label, naming the declared tool and the kind of signal, and no word of the description

  # @test:a_poisoned_declared_tool_alone_never_refuses_the_request
  Scenario: A poisoned description alone never refuses the request
    Given the firewall is enforcing and a request declares a poisoned tool
    When the model answers with plain text and asks for nothing dangerous
    Then the request is answered 200
    And the run is labelled, recorded, and the answer carries an x-fuse-taint note naming the declared tool

  # @test:in_shadow_a_poisoned_declared_tool_is_labelled_recorded_and_never_blocks
  Scenario: In shadow a poisoned declared tool is recorded and nothing is blocked
    Given the firewall is in shadow and a request declares a poisoned tool
    When the model's answer asks to run a shell
    Then the request is answered 200
    And the label and the would-block are both recorded

  # @test:an_honest_tool_set_marks_nothing
  # @test:a_bare_mention_of_another_tool_is_documentation_not_a_label
  Scenario: An honest tool set marks nothing
    Given a request declares ordinary tools, one of which merely mentions another by name
    When the model's answer asks to run a shell
    Then the run carries no label, the request is answered 200 and no taint event is written

  # @test:the_openai_wire_is_read_too
  Scenario: The OpenAI wire is read too
    Given the firewall is enforcing and an OpenAI-shaped request declares a poisoned function
    When the model's answer asks to run a shell
    Then the call is refused with 403 and the label is recorded

  # @test:a_poisoned_parameter_description_is_read
  Scenario: A parameter description is read as well as the tool description
    Given a declared tool's parameter description tells the model to send a local key file to the user
    When the model's answer asks to run a shell
    Then the call is refused with 403

  # @test:with_the_firewall_off_nothing_changes
  # @test:the_detector_switch_off_leaves_declared_tools_unread
  Scenario: With the firewall off, or the detector switched off, nothing changes
    Given a request declares a poisoned tool
    When the firewall is off, or the policy file sets detect_injection to false
    Then the request is answered 200, no event is written and no header is added

  # @test:the_same_set_is_answered_from_the_memo
  Scenario: A tool set resent every turn is scanned once
    Given the same tool set arrives on two requests
    When it is scanned twice
    Then the second scan reuses the first answer
