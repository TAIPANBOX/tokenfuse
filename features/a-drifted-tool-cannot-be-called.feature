Feature: A tool whose definition changed after approval cannot be called

  The broker already refuses the listing of a tool whose definition changed
  since it was pinned (a rug-pull). Clients cache listings, so the agent can
  still call the changed tool by name, and until now the broker forwarded that
  call and answered it.

  Measured 2026-10-12 against the v1.10.0 release binary: scan in block mode,
  a lock pinned from an approved listing, the upstream changed one tool's
  description. `tools/list` was refused with -32003 and the next `tools/call`
  of that tool was forwarded and answered.

  The broker remembers what it saw, per upstream and tool name, in this process
  only. It does not fetch listings on its own, so it learns of a change only
  when a client lists again. A restart forgets it; so does re-pinning the lock.

  Background:
    Given an MCP credential-broker with a lock pinned from an approved listing
    And an upstream serving two tools, get_order_status and list_orders

  # @test:a_drifted_tool_is_refused_before_anything_is_forwarded
  Scenario: Block mode refuses a call to a tool it saw change
    Given scan is in block mode
    And the upstream changed get_order_status and a client listed tools again
    When the agent calls get_order_status
    Then the call is refused with the rug-pull code, naming the tool and saying
      it changed since it was pinned
    And the upstream never received the call
    And one tool_call record says it was refused for that reason

  # @test:warn_mode_forwards_a_drifted_tool_call_and_records_it_once
  Scenario: Warn mode forwards the call
    Given scan is in warn mode
    And the upstream changed get_order_status and a client listed tools again
    When the agent calls get_order_status
    Then the call is answered by the upstream
    And exactly one tool_call record is written

  # @test:a_tool_that_matches_the_lock_again_can_be_called_again
  Scenario: The refusal clears when the listing matches the lock again
    Given scan is in block mode and get_order_status is refused as changed
    When the upstream serves the approved definition and a client lists again
    Then the agent can call get_order_status and the upstream answers

  # @test:another_tool_on_the_same_upstream_is_not_refused
  Scenario: Other tools on the same upstream are unaffected
    Given scan is in block mode and get_order_status is refused as changed
    When the agent calls list_orders
    Then the call is answered by the upstream

  # @test:a_second_upstream_with_the_same_tool_name_is_not_refused
  Scenario: A second upstream with the same tool name is unaffected
    Given two upstreams both serving get_order_status, only the first changed
    And scan is in block mode and a client listed both
    When the agent calls get_order_status on the second upstream
    Then the call is answered by the second upstream
    And the same call on the first upstream is refused

  # @test:scan_off_or_no_lock_leaves_a_changed_tool_callable
  Scenario: Without scan or without a lock nothing changes
    Given scan is off with a lock, and separately scan is in block mode with no
      lock
    When a changed tool is listed and then called
    Then the call is forwarded and answered in both

  # @test:the_stdio_transport_refuses_a_drifted_tool_call_too
  Scenario: The stdio transport refuses the same call
    Given scan is in block mode over the stdio path
    And the upstream changed get_order_status and the client listed tools again
    When the agent calls get_order_status
    Then the call is refused with the rug-pull code and not forwarded

  # @test:a_change_the_client_never_re_listed_is_not_seen
  Scenario: A change the broker never saw is not refused
    Given scan is in block mode and the lock is pinned
    And the upstream changed get_order_status but no client listed again
    When the agent calls get_order_status
    Then the call is forwarded, because the broker does not fetch listings on
      its own and has seen nothing change
