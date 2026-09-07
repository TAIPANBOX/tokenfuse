Feature: The OpenAI door, a second front on one gateway

  `POST /v1/chat/completions` is served by the same handler and the same
  enforcement pipeline as `/v1/messages` (docs/26-the-openai-door.md). One
  process forwards to one upstream shape, so a caller who uses the wrong door
  is refused loudly rather than forwarded, and the money path treats `n`
  (how many completions a call asks for and is billed for) and the newer
  output-limit field the way the provider's own reference says a caller
  should be charged.

  # @test:the_openai_door_prefers_max_completion_tokens_over_the_deprecated_name
  Scenario: The newer output-limit field wins when both are present
    Given a request carrying both `max_tokens` and `max_completion_tokens`
    When the OpenAI door reads the output-token limit
    Then it prices against `max_completion_tokens`, because the provider's own
      reference calls `max_tokens` deprecated and refuses it outright on
      o-series models

  # @test:a_nonsense_completion_count_is_one_and_never_zero
  Scenario: A nonsense completion count never reads as free
    Given `n` absent, zero, negative, a string, or an object
    When the OpenAI door reads how many completions were asked for
    Then it falls back to one, never to zero, because a completion count read
      as zero would price the call as free

  # @test:four_completions_are_reserved_for_before_the_call_is_forwarded
  Scenario: The estimate is billed for every completion asked for, not one
    Given a run budget that admits one completion of a given size but not four
    And a request asking for `n: 4` at that size
    When the call reaches the gateway
    Then it is refused with 402, because an estimate that ignored `n` would
      have priced this call as if it asked for one and forwarded it

  # @test:a_gateway_pointed_at_anthropic_refuses_the_openai_door_before_it_reserves_anything
  Scenario: A caller at the wrong door is refused before a cent is reserved
    Given a gateway declared for the Anthropic wire
    When a caller sends an OpenAI-shaped request to `/v1/chat/completions`
    Then it is refused with 400 naming `TOKENFUSE_WIRE`, and the ledger never
      hears of that run id at all, because forwarding the wrong shape to the
      wrong upstream would turn a configuration mistake into a provider error
      with a settled reservation behind it

  # @test:a_streamed_openai_request_is_asked_to_report_its_usage
  # @test:a_streamed_openai_request_reaching_the_provider_carries_the_usage_request
  Scenario: A streamed call is asked to report its own usage
    Given an OpenAI request that streams and does not mention `stream_options`
    When the gateway prepares the body it is about to forward
    Then `stream_options.include_usage` is set to true, because without it a
      streamed run settles on the pre-flight estimate instead of measured
      usage on every call an ordinary SDK makes

  # @test:a_caller_that_already_answered_the_question_is_not_overruled
  Scenario: A caller's own answer about usage reporting is never overwritten
    Given an OpenAI request that already sets `stream_options.include_usage`,
      to true or to false
    When the gateway prepares the body it is about to forward
    Then that value is left exactly as the caller wrote it

  # @test:a_stream_with_null_usage_on_every_chunk_but_the_last_still_settles_on_the_last_chunk
  Scenario: A null usage on every chunk but the last is not a zero
    Given a stream whose non-final chunks all carry `"usage": null`, exactly as
      the provider's own reference documents once usage reporting is asked for
    When the final chunk arrives carrying the real totals
    Then the run settles on those totals, never on an empty usage read off one
      of the earlier null chunks

  # @test:the_openai_door_refuses_in_the_envelope_its_clients_parse
  Scenario: A refusal on the OpenAI door speaks the OpenAI convention
    Given a run the Breaker has stopped over budget
    When the OpenAI door renders the refusal
    Then the body carries `message`, `code`, and `param: null` alongside the
      fields this gateway always wrote, and the Anthropic door's refusal for
      the same verdict carries none of the three, unmoved from what it always
      wrote
