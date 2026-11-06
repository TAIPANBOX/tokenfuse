Feature: Usage that stops short of its final event

  A provider reports what a call used across a stream: Anthropic's opening event
  carries the input count and an opening output count, and the output it bills
  arrives in the final message_delta; OpenAI's arrives in the usage chunk. A body
  that ends or breaks before that event holds an input count that looks like a
  whole answer. A read-only review on 2026-09-18 found both shapes
  (tokenfuse#308, tokenfuse#309): a clean end settled on the opening counters and
  priced the output at nothing, and a break dropped usage that had arrived.

  @decided 2026-11-05: a call whose usage stopped short is charged the input side
  as reported and the output side at the request's cap, the most the provider can
  bill. @claude on the shape: "the last word" is an event, not a count, because a
  real opening event says output_tokens 1 and a rule looking for zero would pass
  it. Invariants 43 and 47.

  # @test:a_clean_stream_with_no_final_usage_event_charges_the_reported_input_and_the_output_cap
  # @test:the_opening_output_count_is_not_the_final_one
  # @test:the_opening_counters_are_never_the_last_word_even_closed_cleanly
  Scenario: A stream that ends cleanly without its final usage event
    Given a 200 stream that opens with an input count and closes with message_stop
    And no message_delta ever carried the output
    When the call settles
    Then the run is charged the reported input and the output at the request's cap
    And it is not charged the opening counters alone

  # @test:a_complete_stream_settles_on_its_usage_not_the_cap
  # @test:an_openai_stream_with_its_usage_chunk_settles_on_that_usage
  # @test:complete_usage_is_never_capped
  Scenario: A stream that finished settles as reported
    Given a 200 stream that carried its final usage event
    When the call settles
    Then the run is charged that usage and the cap plays no part

  # @test:an_openai_stream_whose_usage_names_no_output_charges_the_output_cap
  # @test:an_openai_usage_is_the_last_word_only_with_an_output_figure
  Scenario: An OpenAI usage object that names no output
    Given a 200 stream whose usage object carries prompt_tokens and nothing about the output
    When the call settles
    Then the run is charged the reported input and the output at the request's cap

  # @test:an_openai_stream_that_ends_without_its_usage_chunk_stays_on_the_estimate
  Scenario: A stream that asked for its usage chunk and never got one
    Given a 200 stream with include_usage set that ends with no usage chunk
    When the call settles
    Then nothing was reported, so the run is charged the pre-flight estimate

  # @test:the_settlement_is_never_below_what_the_provider_already_reported
  # @test:a_reported_output_above_the_cap_is_kept
  Scenario: The charge is never below what the provider already reported
    Given a prompt written to the one-hour cache, which the estimate prices at the input rate
    And a stream that stopped short after reporting it
    When the call settles
    Then the run is charged the reported cache write at its own rate and the output at the cap
    And a reported output above the cap is kept rather than lowered to it

  # @test:the_cap_counts_every_completion
  # @test:a_request_with_no_cap_is_charged_the_output_the_estimate_assumes
  # @test:the_output_cap_is_the_request_cap_for_every_completion
  Scenario: The cap is the one the estimate reserved against
    Given a request asking for two completions, or naming no max_tokens at all
    When its usage stops short
    Then the output is charged at the cap times the completions, or the assumed 1024

  # @test:a_refusal_that_stopped_short_charges_what_it_reported_and_no_cap
  # @test:a_refused_call_that_stopped_short_is_not_given_the_cap_by_the_guard
  # @test:a_refusal_has_no_cap_to_assume_so_what_it_reported_stays_parsed
  Scenario: A refusal has no generation to assume
    Given a 429 whose body reported an opening count and stopped
    When the call settles
    Then the run is charged what the provider reported and no cap

  # @test:a_whole_json_answer_is_complete_whatever_it_reports
  # @test:a_whole_json_document_is_complete_whatever_it_reports
  Scenario: A whole JSON answer has no later event to wait for
    Given a non-streaming answer whose usage names only the input
    When the call settles
    Then the run is charged what it reported

  # @test:a_break_after_the_final_usage_event_settles_on_that_usage
  # @test:an_openai_break_after_the_usage_chunk_settles_on_that_usage
  # @test:codex_f04_real_http_2xx_body_error_settles_the_usage_already_received
  # @test:codex_held_real_http_stream_error_settles_the_usage_already_received
  # @test:the_final_delta_is_the_last_word_with_or_without_the_close_behind_it
  Scenario: A body that breaks after the final usage event
    Given a real HTTP 200 that wrote its final usage event and then lost the connection
    When the break reaches the gateway
    Then the run is charged that usage, not the estimate

  # @test:a_break_after_only_the_opening_counters_charges_the_output_cap
  Scenario: A body that breaks after only the opening counters
    Given a real HTTP 200 that wrote message_start and some text and then lost the connection
    When the break reaches the gateway
    Then the run is charged the reported input and the output at the cap

  # @test:a_break_after_a_delta_that_is_still_open_charges_the_output_cap
  # @test:an_openai_break_on_a_running_total_charges_the_output_cap
  # @test:a_delta_that_says_the_message_is_open_is_a_running_figure_until_the_close
  # @test:an_openai_usage_on_an_open_choice_is_a_running_figure_until_the_close
  # @test:one_open_choice_among_finished_ones_keeps_the_figure_running
  Scenario: A running figure is not the last word
    Given an event that carries an output figure and says the message is still open
    When the body breaks right after it
    Then the run is charged the reported input and the output at the cap, not the figure so far

  # @test:a_close_after_an_open_delta_makes_that_figure_the_final_one
  # @test:a_running_total_closed_by_done_is_the_final_one
  Scenario: A clean close makes the last figure final
    Given a stream whose last output figure rode an event that said the message was open
    When the stream closes cleanly with message_stop or [DONE]
    Then the run is charged that figure, because a clean close says nothing follows

  # @test:a_break_before_anything_priced_stays_on_the_estimate
  # @test:codex_f04_real_http_2xx_body_error_must_not_silently_settle_zero
  # @test:codex_held_real_http_stream_error_releases_and_uses_estimate
  Scenario: A body that breaks before anything priced arrived
    Given a real HTTP 200 that lost the connection with no token count read
    When the break reaches the gateway
    Then the run is charged the pre-flight estimate, as before

  # @test:usage_that_stopped_short_records_no_token_counts_and_keeps_the_observation
  # @test:a_stopped_short_settlement_says_so_at_warn_and_is_not_counted_as_truncated
  Scenario: The record says a charge rests on an assumption
    Given a settlement whose output side is the cap
    When the row is written
    Then it carries no token counts beside the cost, so the FOCUS export labels it estimated
    And one warn line names the model, the cap and the amount

  # @test:a_stream_cut_at_any_byte_is_complete_exactly_from_its_final_event_on
  Scenario: A body can break at any byte
    Given a stream cut at every byte in turn, on both wires
    When the parser reads what arrived
    Then it claims the last word exactly from the byte the final event closes on, and never before
