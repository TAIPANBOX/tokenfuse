Feature: Usage is read from SSE events, not from lines

  The 2026-09-18 money-path review (F06) put it this way: an SSE event with
  two data fields represents their contents joined by a newline, and neither
  individual line needs to be valid JSON; the parser read each data line as a
  complete document, so the final usage disappeared while the initial input
  usage stayed nonzero and settlement chose Parsed, not the estimate. On the
  Anthropic door a message_delta split across two data lines settled 30
  micro-USD against 15030: the whole output cost gone, silently. The review
  called it a break of the parser's SSE contract; that contract is the
  event-stream grammar, and this feature is the grammar as the parser now
  keeps it. Invariant 55.

  @fable 2026-09-18: read the body as events first, per the grammar; a final
  event the body ends without a blank line for is still dispatched, and an
  event whose JSON does not parse is skipped without failing its siblings.

  # @test:codex_f06_multiline_sse_usage_is_not_silently_partial
  # @test:a_multi_line_data_event_is_one_document
  Scenario: A usage event split across two data lines is priced whole
    Given an Anthropic stream whose message_start says 10 input tokens
    And whose message_delta carries its usage object across two data lines
    When the gateway settles the call on claude-sonnet
    Then it settles 15030 micro-USD, 10 at the input rate and 1000 at the output rate
    And not 30, the output cost silently gone

  # @test:a_multi_line_openai_usage_event_is_one_document
  Scenario: An OpenAI usage event split across data lines nets once
    Given an OpenAI stream whose usage chunk is spread over three data lines
    When the gateway parses the stream
    Then the usage holds 822 input tokens, 128 cache-read tokens and 120 output tokens

  # @test:crlf_endings_frame_events_like_lf
  # @test:a_cr_only_body_frames_events
  # @test:a_body_split_at_random_offsets_with_any_line_ending_parses_identically
  Scenario: A line ends at CRLF, LF or CR, and the framing does not depend on how the bytes arrived
    Given the same stream framed with each of the three line endings
    And fed to the parser in chunks cut at random byte offsets, two hundred times
    When the gateway parses each one
    Then every parse yields the same usage and the same tool-call count

  # @test:a_comment_line_inside_an_event_does_not_split_it_and_one_between_events_is_not_data
  # @test:event_id_and_retry_lines_do_not_touch_the_data
  Scenario: Comments, event names, ids and retry hints carry no data
    Given a stream with a comment line inside a two-line usage event
    And event, id and retry lines above another
    And a comment line between events that happens to look like a usage object
    When the gateway parses the stream
    Then the two-line events are read whole and the comment prices nothing

  # @test:data_with_no_space_after_the_colon_is_data
  # @test:data_with_two_spaces_keeps_the_second_space
  # @test:an_indented_data_line_is_still_a_data_field
  # @test:a_whitespace_only_line_is_a_field_line_not_a_blank_line
  Scenario: The field is the text before the first colon, and one space after it is not data
    Given data lines with no space after the colon, with two spaces, with the field name indented, and an event with a whitespace-only line inside it
    When the gateway parses each
    Then the first three are data, exactly one space removed from the value, and the whitespace-only line neither splits the event nor dispatches it

  # @test:an_empty_data_event_is_not_dispatched_but_marks_the_body_sse
  # @test:done_as_the_whole_data_of_an_event_is_the_sentinel_and_drops_nothing_else
  # @test:an_event_whose_joined_json_fails_is_skipped_and_its_siblings_are_not
  Scenario: An empty event, the [DONE] sentinel and an event that is not JSON price nothing and lose nothing
    Given a stream with an empty data event, a [DONE] event and an event whose joined text is not JSON
    And usage events beside them
    When the gateway parses the stream
    Then the usage events are priced and the three others are skipped

  # @test:a_body_ending_without_the_final_blank_line_still_dispatches_its_last_event
  Scenario: A provider that omits the last blank line still has its last event read
    Given a stream whose final message_delta is not followed by a blank line
    When the body ends
    Then the delta's output tokens are priced, because nothing can follow the end of a body

  # @test:an_event_cut_by_the_cap_is_truncated_and_nothing_parsed_from_it_is_priced
  Scenario: An event cut by the buffer cap is never priced
    Given a body whose second usage event straddles the parser's cap
    When the gateway settles
    Then the settlement is the estimate on a truncated basis, and no token count from that body reaches the record

  # @test:hostile_sse_bodies_never_panic
  Scenario: Hostile bytes never take the parser down
    Given two hundred bodies of random bytes, stray field prefixes, a megabyte comment line and a megabyte unterminated data line
    When the gateway parses each, whole and byte by byte
    Then it never panics and both feeds agree
