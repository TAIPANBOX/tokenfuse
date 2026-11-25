Feature: A streamed read is judged on what its arguments carry
  Every door judges a tool call's arguments with the same function, on that
  call's own capability, up to a 64 KiB cap.

  # @test:a_streamed_anthropic_read_carrying_data_after_private_data_is_refused
  Scenario: A streamed Anthropic read carrying data after private data is refused
    Given a run that has read a private file
    When the model streams a fetch_url call whose URL carries encoded data in three fragments
    Then the call does not reach the agent and the refusal names the read rule

  # @test:a_streamed_openai_read_carrying_data_after_private_data_is_refused
  Scenario: A streamed OpenAI read carrying data after private data is refused
    Given a run that has read a private file
    When the model streams the same call through the OpenAI door
    Then the call does not reach the agent and the refusal names the read rule

  # @test:shadow_forwards_a_streamed_read_carrying_data_and_records_it
  Scenario: Shadow forwards the call and records the would-block
    Given the firewall in shadow mode and a run that has read a private file
    When the model streams a read carrying encoded data
    Then the stream is forwarded byte for byte and one taint_shadow names the read rule

  # @test:a_streamed_read_over_the_argument_cap_after_private_data_is_refused
  Scenario: Arguments over the cap are never judged on a prefix
    Given a run that has read a private file
    When the model streams a read whose arguments are 70,000 bytes
    Then the call is refused as over the cap

  # @test:a_streamed_read_after_web_only_is_forwarded
  Scenario: A read after web input alone is not judged on its arguments
    Given a run that has read only the web
    When the model streams a read carrying encoded data
    Then the stream is forwarded unchanged

  # @test:a_large_argument_on_another_call_does_not_refuse_a_clean_read
  Scenario: A read is judged on its own arguments
    Given a run that has read a private file
    When one answer asks for a clean fetch_url and a read_file with an encoded path
    Then the answer is allowed

  # @test:a_buffered_read_with_unreadable_arguments_after_private_data_is_refused
  Scenario: Unreadable arguments on a read after private data are refused
    Given a run that has read a private file
    When the model asks for a read whose argument text is not JSON
    Then the call is refused by the read rule

  # @test:the_check_refuses_a_read_whose_arguments_carry_data
  Scenario: The tool-call check judges the arguments it is sent
    Given a run that has read a private file
    When an executor asks the check about fetch_url with arguments carrying encoded data
    Then the check answers deny and says the arguments were judged

  # @test:the_broker_sends_arguments_to_the_check_and_oversized_ones_as_truncated
  Scenario: The broker sends a tool call's arguments to the check
    Given an MCP broker with a taint gateway
    When an agent calls a tool with small arguments and then with arguments over the cap
    Then the check receives the first whole and the second flagged as left out

  # @test:arguments_at_the_cap_are_read_and_one_byte_over_is_over_the_cap
  Scenario: The cap is inclusive
    Given argument text of exactly 65,536 bytes and of 65,537 bytes
    When each is read
    Then the first is parsed and the second is over the cap

  # @test:anthropic_argument_fragments_are_joined_at_any_chunking
  Scenario: Argument fragments are joined however the stream is cut
    Given an Anthropic stream with a tool call
    When it arrives in chunks of any size
    Then the held call carries the same arguments

  # @test:two_interleaved_openai_calls_keep_their_own_arguments
  Scenario: Interleaved calls keep their own arguments
    Given two OpenAI tool calls whose fragments interleave
    When the stream ends
    Then each call carries its own arguments

  # @test:a_buffered_answer_the_gateway_cannot_parse_is_refused_after_untrusted_input
  Scenario: An answer the gateway cannot parse is not an answer with no calls
    Given a run that has read the web
    When the model's answer carries a tool input nested past the parser's depth
    Then the answer is refused, and with no untrusted input it is allowed

  # @test:arguments_sent_as_json_text_are_read_as_the_object_they_hold
  Scenario: Arguments sent as JSON text are read as the object they hold
    Given arguments sent as a string of JSON, once or twice encoded
    When they are read
    Then the URL caps see the URL inside

  # @test:an_orphan_fragment_is_joined_onto_the_last_block_not_dropped
  Scenario: A fragment no block opened is not dropped
    Given an argument fragment whose index no tool_use block opened
    When the stream ends
    Then it is joined onto the most recent block
