Feature: A tool call in a streamed answer is judged as it is in a buffered one

  Measured 2026-10-14 on a router agent that streams through the OpenAI door:
  the run was tainted, the starter rule denies writing after untrusted input,
  and a write_file call the model streamed back reached the agent and ran.

  @claude 2026-10-14, the shape asked for: a streamed tool call is held until
  it is complete, judged exactly as a buffered one is, and forwarded or
  replaced by the same refusal in a form the stream can carry; text keeps
  streaming. Invariant 104.

  # @test:a_streamed_anthropic_tool_call_the_taint_denies_is_refused
  # @test:a_streamed_openai_tool_call_the_taint_denies_is_refused
  Scenario: A denied tool call never reaches a streaming agent, on either wire
    Given a run tainted by the web, in enforce
    When the model streams text and then a write_file tool call
    Then the text reaches the agent
    And no part of the tool call does, neither its name, its id nor its arguments
    And one taint_block names write_file on the bus

  # @test:the_refusal_is_the_event_each_wires_clients_raise_on
  Scenario: The refusal is an error the agent's client library raises
    Given the same denied call
    Then the stream ends with one error event carrying taint_blocked and the reason
    And on the Anthropic wire it is an event named error, on the OpenAI wire a chunk holding error with a code
    And nothing follows it

  # @test:an_untainted_streamed_tool_call_is_forwarded_byte_for_byte
  # @test:with_the_firewall_off_a_stream_is_never_held_or_changed
  Scenario: A tool call nothing denies, or a firewall that is off, changes no byte
    Given a run with no taint, or a gateway with the firewall off
    When the model streams a tool call
    Then the agent receives exactly the bytes the provider sent

  # @test:shadow_forwards_a_denied_streamed_tool_call_and_records_it
  Scenario: Shadow forwards and records what enforce would refuse
    Given a tainted run in shadow
    When the model streams a tool call the taint denies
    Then the agent receives exactly the bytes the provider sent
    And one taint_shadow names the tool on the bus

  # @test:a_streamed_tool_calls_output_taints_the_next_turn
  # @test:the_buffered_answer_is_still_refused_with_a_403
  Scenario: A streamed tool call taints the turns after it, as a buffered one does
    Given an untainted run whose model streams a web search
    When the next turn's model asks to run a shell
    Then that turn is refused 403 taint_blocked

  # @test:chunking_never_changes_what_is_held_across_a_sweep
  # @test:hostile_bytes_never_panic_and_are_never_lost
  # @test:crlf_and_cr_line_endings_split_events_the_same_way
  # @test:an_openai_name_split_across_deltas_is_read_whole
  # @test:a_tool_call_in_an_unterminated_final_event_is_still_held
  Scenario: However the bytes arrive, the same events are held
    Given an answer cut into chunks of any size, with any line ending
    When the gate splits it into events
    Then nothing of a tool call is forwarded early, the names are the same, and no byte is lost
