Feature: The MCP broker lists what the policy does not forbid

  The broker used to hand an agent every tool the upstream MCP server listed,
  whatever the agent's policy said. It now leaves out of a tools/list answer
  the tools wardryx's deny_tool rule forbids that agent by name, and nothing
  else. A tool the agent merely holds no grant for stays in the list, because
  its call is the one held for the owner's approval, and the owner can only be
  asked about a tool the agent can see. The list is what an agent is shown and
  never the boundary: every call is still judged at the gate.

  # @test:a_tool_the_policy_denies_by_name_is_not_listed
  Scenario: A tool the policy denies by name is not listed
    Given wardryx enforces a policy whose deny_tool names wire_transfer for the agent
    And the upstream lists lookup, wire_transfer and send_email
    When the agent asks the broker for tools/list
    Then the answer lists lookup and send_email, in that order
    And wardryx was asked once, about that agent and the three listed names

  # @test:a_tool_the_agent_holds_no_grant_for_stays_listed_and_its_call_is_held
  Scenario: A tool with no grant stays listed and its call is held for a person
    Given wardryx enforces a policy under which no grant covers deploy
    When the agent asks the broker for tools/list
    Then deploy is listed
    And when the agent calls deploy, the call is held for approval and the refusal names the approval

  # @test:a_tool_refused_under_any_other_rule_stays_listed
  Scenario: Only deny_tool takes a tool out of the list
    Given wardryx refuses wire_transfer under deny_tool, deploy under allow_tool and ship under another rule
    When the agent asks the broker for tools/list
    Then deploy and ship are listed and wire_transfer is not

  # @test:shadow_lists_every_tool_and_says_how_many_it_would_leave_out
  Scenario: Shadow leaves everything in and says what enforce would leave out
    Given wardryx runs in shadow with a deny_tool naming wire_transfer
    When the agent asks the broker for tools/list
    Then every listed tool is in the answer
    And the answer says one tool would be left out

  # @test:with_the_hook_off_nothing_is_asked_and_the_answer_is_the_upstreams
  Scenario: With the policy hook off the list is the upstream's
    Given the wardryx hook is off
    When the agent asks the broker for tools/list
    Then the answer is exactly what the upstream sent, and wardryx is asked nothing

  # @test:a_listing_that_names_no_agent_asks_nothing
  Scenario: A listing that names no agent asks nothing
    Given wardryx enforces a deny_tool naming wire_transfer
    When a caller with no agent id, or a blank one, asks for tools/list
    Then the answer is exactly what the upstream sent, and wardryx is asked nothing

  # @test:a_policy_plane_that_refuses_leaves_the_list_whole_and_says_so
  Scenario: A policy plane that refuses the question leaves the list whole
    Given wardryx answers filter-tools with a server error
    When the agent asks the broker for tools/list
    Then every listed tool is in the answer
    And the log names the refusal and its status

  # @test:an_unreachable_policy_plane_leaves_the_list_whole_and_says_so
  Scenario: A policy plane nobody can reach leaves the list whole
    Given wardryx cannot be reached
    When the agent asks the broker for tools/list
    Then every listed tool is in the answer, and the log says the filter-tools call failed

  # @test:a_failed_answer_is_not_kept_so_the_next_listing_is_narrowed
  Scenario: A failed answer is never cached
    Given wardryx fails one filter-tools question and answers the next
    When the agent asks for tools/list twice
    Then the first answer is whole, the second leaves wire_transfer out, and wardryx was asked twice

  # @test:a_wardryx_without_the_route_is_named_once_and_the_list_stays_whole
  Scenario: A wardryx that predates the route is named once
    Given wardryx answers not found on filter-tools
    When the agent asks for tools/list twice
    Then both answers are whole, and exactly one warning names the missing route

  # @test:a_repeated_listing_is_answered_from_the_cache
  Scenario: A repeated listing is answered from the cache
    Given wardryx denies wire_transfer by name and the cache keeps answers for a minute
    When the agent asks for tools/list twice
    Then both answers leave wire_transfer out, and wardryx was asked once

  # @test:the_cache_never_answers_for_another_agent
  Scenario: The cache never answers for another agent
    Given wardryx denies wire_transfer by name to one agent and not to another
    When each agent asks for tools/list
    Then each answer follows that agent's own policy, and wardryx was asked twice

  # @test:hostile_listings_never_panic_and_only_tools_denied_by_name_leave
  Scenario: A hostile listing loses only the tools denied by name
    Given an upstream answers with generated tool arrays holding malformed elements, over 120 seeds
    And with answers that carry no tools array at all
    When the agent asks for tools/list
    Then only an element whose string name deny_tool refuses is left out, the rest keep their order
    And an answer with no tools array goes back exactly as it came
