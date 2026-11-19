Feature: The trace and the FOCUS export carry cache and reasoning tokens

  A FinOps tool reading the FOCUS export saw one input and one output figure
  per call: it could not tell a cache read from a fresh token, a one-hour cache
  write from a five-minute one, or how much of the output was reasoning, though
  the price book already priced each of them apart. FOCUS 1.5, a release
  candidate to be ratified on 2026-12-03, names these token kinds.

  @decided 2026-11-19: the trace gains nullable per-call cache and reasoning
  columns filled from what the provider returned, the default export carries
  them as x_ columns, and --spec 1.5 writes the release-candidate names with
  one row per token kind. Old trace files keep reading. Invariant 148.

  # @test:the_export_carries_the_cache_and_reasoning_counts_each_call_was_priced_with
  Scenario: Each call's row carries the counts it was priced with
    Given a gateway writing its trace to Parquet
    When an Anthropic call reads 300 cached tokens and writes 1000, 600 of them for an hour
    And an OpenAI call reads 128 cached tokens and reports zero reasoning tokens
    And a Vertex AI call reports 560 reasoning tokens
    Then the default export's last four columns are the cache read, cache write, one-hour write and reasoning counts
    And the Anthropic row reads 300, 1000, 600 and blank
    And the OpenAI row reads 128, 0, 0 and 0
    And the Vertex AI row keeps 619 output tokens and reads 560 reasoning tokens

  # @test:spec_1_5_writes_one_row_per_token_kind_and_the_parts_sum_to_the_call
  Scenario: FOCUS 1.5 names write one row per token kind
    Given the same three calls in the trace
    When the export runs with --spec 1.5
    Then the Anthropic call is four rows: input uncached, cache read, cache write and output
    And each row names its token direction and cache action in SkuPriceDetails, with the model's id, developer, family and version
    And each row's cost is its kind's share at the price book's rate
    And every call's rows sum to the cost the default export records for it
    And the reasoning tokens stay inside the output row and are named there

  # @test:a_trace_written_before_the_columns_existed_still_reads_everywhere
  Scenario: A trace written before the columns existed still reads
    Given a trace segment written before the four columns existed beside a current one
    When sql, backtest and both export shapes read the directory
    Then the old row reads NULL or blank in the new columns
    And its FOCUS 1.5 input row names no cache action, because its cache state is unknown

  # @test:an_unknown_spec_is_refused_and_writes_nothing
  Scenario: An unknown spec is refused
    When the export runs with --spec 9.9
    Then it exits non-zero, names the flag, and writes no file
