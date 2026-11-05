Feature: A run's label comes from what it did, not from what it called it

  The ask, paraphrased, `@decided 2026-11-04`: close the gap where a run's taint is
  decided on a tool name the agent reported, so the network act behind the name is
  invisible. An agent must not be able to take a label off or avoid it by changing
  a name. The name may stay as a fallback signal; an observed act is the stronger
  one.

  What was there before. A run's history is the conversation the caller sends, so
  "has this run touched an untrusted source" was answered by a string the agent
  wrote. A fetch reported under a name the policy trusts carried that name's
  labels, and a fetch left out of the conversation carried none. The MCP broker
  made the connection and saw the server answer, and told nobody.

  Where this stops, said once: a label follows an act that passed through an
  enforcement point. A process that opens its own socket passes through none. A
  search the provider runs on its own infrastructure is seen in its answer and
  labels the run, and no domain policy reaches it.

  Background:
    Given a gateway with the agent firewall enforcing
    And an MCP broker in front of a server the operator classified as web

  # @test:a_read_through_a_classified_upstream_labels_the_run_before_the_answer_returns
  Scenario: The run carries the label before the agent has the page
    Given a run that has touched nothing
    When the agent reads a page through the broker
    Then the agent gets the page
    And by the time it has, the run already carries the web label

  # @test:a_renamed_tool_carries_the_label_of_the_server_that_answered
  Scenario: Renaming the tool changes nothing
    Given a tool name the policy trusts
    When the agent reads a page through the broker under that name
    And the conversation reports the trusted name
    Then the run carries the web label anyway
    And the same conversation on a run that read nothing is not refused

  # @test:a_conversation_that_never_mentions_the_fetch_is_judged_on_the_act
  Scenario: Leaving the fetch out of the conversation changes nothing
    Given the agent read a page through the broker
    When its next call to the model mentions no tool at all
    And the model asks to run a shell
    Then the answer is refused

  # @test:the_name_map_still_labels_what_no_enforcement_point_saw
  Scenario: The name is still a signal where nothing saw the act
    Given a conversation reporting a web fetch that no broker saw
    When the model asks to run a shell
    Then the answer is refused, on the name alone

  # @test:a_classified_upstream_refuses_a_call_that_names_no_run
  Scenario: Leaving out the run id is not a way around the label
    When the agent calls the classified server naming no run
    Then the call is refused
    And nothing reaches the server

  # @test:an_answer_is_withheld_when_the_gateway_cannot_take_the_label
  Scenario: A label that cannot be recorded keeps the page back
    Given the gateway cannot take a label
    When the agent reads a page through the broker
    Then the agent gets a refusal and not the page
    And the record says the call was denied with nothing governing it

  # @test:the_default_route_to_a_classified_server_is_labelled_too
  Scenario: The classification follows the server and not the route
    Given the classified server is also the default upstream
    When the agent reads a page naming no upstream
    Then the run carries the web label

  # @test:an_unclassified_upstream_is_not_reported
  Scenario: A server nobody classified behaves as it always did
    Given a server the operator did not classify
    When the agent calls it naming no run
    Then the answer comes back
    And the gateway is told nothing

  # @test:an_act_on_another_callers_run_is_refused
  Scenario: A caller cannot put a label on a run it does not own
    Given a run another client key opened
    When a caller reports an act on it
    Then the report is refused and the run is unchanged

  # @test:a_firewall_that_is_off_takes_no_label_and_the_answer_still_returns
  Scenario: A firewall that is off keeps nothing back
    Given the agent firewall is off
    When the agent reads a page through the broker
    Then the agent gets the page

  # @test:the_record_names_the_server_and_the_stage_and_no_url
  Scenario: The record says who saw it and keeps no address
    When the agent reads a page through the broker, twice
    Then the stream carries one event saying the run became untrusted
    And it names the server and the MCP stage
    And no part of the address is on the stream

  # @test:an_answer_the_upstream_marked_as_an_error_still_labels_the_run
  Scenario: An answer marked as an error still reached the model
    When the server answers with its error flag set
    Then the run carries the web label

  # @test:a_new_read_after_a_clearance_labels_the_run_again
  Scenario: A human's clearance covers what was read, not what comes next
    Given a run a human cleared of the web label
    When the agent reads another page through the broker
    Then the run carries the web label again

  # @test:the_label_is_asked_for_under_the_callers_own_key
  Scenario: The broker adds no authority of its own
    When a caller with a gateway key reads a page through the broker
    Then the gateway is told under that caller's key

  # @test:a_classified_upstream_with_no_gateway_stops_the_broker
  Scenario: A classification with nobody to tell does not start
    Given a classified upstream and no gateway named
    When the broker starts
    Then it exits naming both variables

  # @test:a_classification_naming_no_upstream_stops_the_broker
  Scenario: A classification of a server that is not configured does not start
    Given a classification naming an upstream the broker does not have
    When the broker starts
    Then it exits naming the variable and the name

  # @test:a_search_the_provider_ran_labels_the_run
  Scenario: A search the provider ran labels the run from its answer
    Given a run that has touched nothing
    When the provider's answer records a web search it ran
    Then the run carries the web label
    And the record names the tool and the model stage

  # @test:a_tool_call_in_the_same_answer_as_a_provider_search_is_judged_with_its_label
  Scenario: A shell asked for in the answer that searched is judged after the search
    When one answer records a provider search and asks to run a shell
    Then the answer is refused

  # @test:a_streamed_search_the_provider_ran_labels_the_run
  Scenario: A streamed provider search labels the run too
    When a streamed answer records a web search the provider ran
    Then the agent gets the stream
    And the run carries the web label

  # @test:a_client_that_leaves_a_stream_early_does_not_leave_the_label_behind
  Scenario: Leaving a stream early does not leave the label behind
    When the agent has the text of a streamed answer that searched
    And the stream has not ended
    Then the run already carries the web label

  # @test:a_streamed_tool_call_after_a_provider_search_is_judged_with_its_label
  Scenario: A streamed shell after a provider search is judged after the search
    When a streamed answer records a provider search and asks to run a shell
    Then the tool call does not reach the agent

  # @test:a_citation_on_the_openai_wire_labels_the_run
  Scenario: A search on the OpenAI wire labels the run
    Given a run that has touched nothing
    When the provider's answer cites a page it searched, with no tool block
    Then the agent gets the answer
    And the run carries the web label

  # @test:a_tool_call_in_the_same_answer_as_a_citation_is_judged_with_its_label
  Scenario: A shell asked for in the answer that cited is refused
    When one answer carries a citation and asks for a shell
    Then the shell is refused and its call does not reach the agent

  # @test:a_streamed_citation_on_the_openai_wire_labels_the_run
  Scenario: A streamed citation labels the run
    When a citation arrives in a delta of a stream
    Then the agent gets the text and the run carries the web label

  # @test:a_citation_in_a_closing_message_chunk_labels_the_run
  Scenario: A citation in a closing message labels the run
    When a stream closes with a whole message that carries a citation
    Then the agent gets the text and the run carries the web label

  # @test:a_classified_upstream_is_told_the_run_and_an_unclassified_one_is_not
  Scenario: The server the run read through hears which run it was
    Given a server the operator classified and a server nobody classified
    When a run calls each of them through the broker
    Then the classified server is told the run, so its record joins the rest of it
    And the other server hears nothing about the run

  # @test:a_redirect_from_an_upstream_is_not_followed
  Scenario: An upstream cannot send the call to another host
    Given a call on its way out carries the secrets the broker wrote and the run
    When the upstream answers with a redirect that keeps the body
    Then the broker does not follow it, and the second host hears nothing
