Feature: A thinking model's reasoning is charged as the output its provider bills

  Measured 2026-10-07 against Vertex AI's OpenAI-compatible endpoint, model
  google/gemini-2.5-flash, one non-streamed answer: completion_tokens 59,
  completion_tokens_details.reasoning_tokens 560, prompt_tokens 14,
  total_tokens 633. Google's completion_tokens leaves the reasoning out
  (633 = 14 + 59 + 560) and Google bills reasoning at the output rate, while
  OpenAI's completion_tokens already includes it (total = prompt +
  completion). The gateway read completion_tokens alone, so every Gemini
  thinking call through the OpenAI door settled about a tenth of its output,
  the direction a budget breaker must never err in (ADR-8).

  The ask: charge the output the provider actually bills, take the gap
  between the total and the prompt when it is larger than the completion
  count, never add the reasoning detail on top of a completion count that
  already holds it, and keep every usage without a total exactly as it was.

  @claude 2026-10-07, under delegated authority: the output is the larger of
  completion_tokens and total_tokens less the gross prompt_tokens (cached
  subset included, as the provider reports it), computed from the figures
  seen across the whole body so the chunk order cannot matter. A total with
  no prompt count is charged whole as output, the over-charging side.

  # @test:a_vertex_reasoning_usage_is_charged_its_reasoning_as_output
  # @test:a_vertex_thinking_call_through_the_openai_door_settles_its_reasoning
  Scenario: The measured Vertex call is charged its reasoning
    Given a Vertex AI answer reporting prompt_tokens 14, completion_tokens 59, reasoning_tokens 560 and total_tokens 633
    And gemini-2.5-flash at 0.30 input and 2.50 output USD per Mtok
    When the gateway settles the call through the OpenAI door
    Then the usage holds 14 input tokens and 619 output tokens
    And the run is charged 1552 micro-USD, not the 152 the visible answer alone would cost

  # @test:an_openai_reasoning_usage_is_not_counted_twice
  Scenario: OpenAI's own reasoning usage is not counted twice
    Given an OpenAI answer reporting prompt_tokens 14, completion_tokens 619, reasoning_tokens 560 and total_tokens 633
    When the gateway parses it
    Then the output is 619 tokens, not 1179

  # @test:a_usage_without_total_tokens_keeps_the_completion_count
  Scenario: A usage without a total is read as before
    Given a usage reporting prompt_tokens 14, completion_tokens 59 and reasoning_tokens 560 and no total_tokens
    When the gateway parses it
    Then the output is 59 tokens, the completion count

  # @test:a_total_below_prompt_plus_completion_never_lowers_the_output
  Scenario: A total smaller than its parts never lowers the output and never wraps
    Given a usage reporting prompt_tokens 100 and completion_tokens 50
    And a total_tokens of 120, of 10, of 0, or the largest number a u64 holds
    When the gateway parses it
    Then the output is never below 50 tokens and nothing underflows or panics

  # @test:a_streamed_vertex_final_chunk_is_charged_its_reasoning
  # @test:a_streamed_vertex_thinking_call_settles_its_reasoning
  Scenario: The streamed final usage chunk is charged its reasoning too
    Given a Vertex AI stream whose content chunks carry a null usage
    And whose final chunk carries the measured usage
    When the gateway settles the stream
    Then the run is charged 1552 micro-USD

  # @test:the_total_and_the_prompt_count_on_separate_chunks_still_give_the_gap
  Scenario: The figures on separate chunks give the same output in any order
    Given the prompt count, the completion count and the total on separate chunks
    And the total arriving before, after, or together with the completion count, with the prompt count first or last
    When the gateway parses the stream
    Then the output is 619 tokens every time

  # @test:a_vertex_usage_with_cached_tokens_nets_the_cache_and_keeps_the_reasoning
  Scenario: Cached tokens beside the reasoning are netted once and the reasoning is kept
    Given a usage reporting prompt_tokens 1000 with cached_tokens 800, completion_tokens 59, reasoning_tokens 560 and total_tokens 1619
    When the gateway parses it
    Then the usage holds 200 input tokens, 800 cache-read tokens and 619 output tokens

  # @test:a_total_with_no_prompt_count_is_charged_whole_as_output
  Scenario: A total with no prompt count is charged whole as output
    Given a usage reporting completion_tokens 5 and total_tokens 73 and no prompt_tokens
    When the gateway parses it
    Then the output is 73 tokens, the over-charging side, rather than leaving the unreported prompt unpriced
