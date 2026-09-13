Feature: A stream without a usage block settles on the estimate, never at zero

  On the OpenAI door the gateway asks the provider for a usage chunk on every
  stream and never overrules a caller who set stream_options.include_usage
  themselves. A caller who sets it to false against a provider that honours it
  (OpenAI, Ollama, Bedrock's OpenAI door) gets a stream with no usage anywhere.
  RUN-3 of the 1.0 proving run measured on 2026-09-13, on the released v0.5.0
  image, that such a stream settled at zero: 0 tokens, 0 microusd, the run's
  spent_usd unmoved, for a completion delivered in full (tokenfuse#283).

  @decided 2026-09-13: fixed the same day. "Usage was parsed" means a priced
  token count came out of the body, not that the parsed struct differs from
  its default; the tool-call count that rides alongside is an observation and
  is kept on the record without deciding the amount. Invariant 43.

  # @test:a_stream_with_no_usage_block_settles_on_the_estimate_not_zero
  Scenario: A stream that reports no usage settles on the estimate
    Given a gateway in enforce mode on the OpenAI door
    And a provider that streams content chunks and [DONE] with no usage block
    When a caller streams a completion with stream_options.include_usage set to false
    Then the completion is delivered with HTTP 200
    And the run's spent equals the pre-flight estimate the gateway reserved
    And the reservation is released

  # @test:a_stream_with_a_usage_block_settles_on_the_usage_not_the_estimate
  Scenario: A stream that reports usage settles on that usage
    Given the same gateway and a provider whose final chunk carries usage
    When a caller streams a completion
    Then the run's spent equals the usage priced at the book's rate for that model
    And it is not the estimate

  # @test:a_buffered_answer_with_no_usage_object_settles_on_the_estimate_not_zero
  Scenario: A buffered answer with no usage object settles on the estimate
    Given the same gateway and a provider whose JSON answer has no usage object
    When a caller sends a completion without stream
    Then the run's spent equals the pre-flight estimate, not zero

  # @test:settle_amount_treats_zero_tokens_beside_a_tool_call_count_as_no_usage
  Scenario: A tool-call count beside zero tokens is not usage
    Given a parsed usage of zero tokens and a tool-call count of zero
    When the settlement amount is decided
    Then the basis is the estimate with no usage
    And the tool-call count stays on the record
