Feature: Gemini on Vertex AI is priced at the rate Google lists, not the fallback

  The built-in price book carried rows for Claude and three OpenAI models and
  none for Gemini, so every Gemini call through the OpenAI door settled at the
  15 / 75 USD per Mtok fallback unless an operator file named it. The call
  measured on 2026-10-07 through Vertex AI's OpenAI-compatible endpoint
  (google/gemini-2.5-flash, 14 input and 619 output tokens, the reasoning
  counted as output) costs 1552 micro-USD at Google's rate and settled at
  46635.

  The ask: rows for the current Gemini models sold on Vertex AI's
  OpenAI-compatible endpoint, under the ids that endpoint takes, each rate read
  from Google's pricing page on the day it was read and cited beside the rows,
  the output rate being the one that covers response and reasoning, and any
  context-length tier priced at its higher rate, said so.

  @claude 2026-10-08, under delegated authority: the Gemini 3 family is priced
  at the page's "Non-global" rate, because the model id does not say which
  endpoint served it; Gemini 3.6, 3.7 and 3.8 Flash at their standard rate,
  not the introductory one Google pays back as a credit until 2026-12-31; text
  input, not the higher audio input rate some models list.

  # @test:every_gemini_id_on_vertex_prices_at_its_list_rate
  # @test:a_gemini_id_on_vertex_is_priced_known_at_its_list_rate
  Scenario: Every current Gemini text model on Vertex has a row at its rate
    Given the ids google/gemini-3.8-flash, -3.8-flash-cyber, -3.7-flash, -3.6-flash, -3.5-flash, -3.5-flash-lite, -3.1-flash-lite, -2.5-pro, -2.5-flash and -2.5-flash-lite
    When the gateway prices a call to any of them
    Then it uses that model's own row, written out by hand from Google's page
    And the answer says x-fuse-price known

  # @test:the_measured_vertex_gemini_call_settles_at_list_not_the_fallback
  # @test:the_shipped_book_prices_the_measured_vertex_call_at_its_list_rate
  Scenario: The measured Vertex call settles at Google's rate
    Given the measured google/gemini-2.5-flash call of 14 input and 619 output tokens
    When the shipped price book settles it
    Then the run is charged 1552 micro-USD, not the 46635 the fallback charged

  # @test:gemini_2_5_pro_is_priced_at_its_long_context_rate
  Scenario: A context-length tier is priced at its higher rate
    Given Gemini 2.5 Pro is listed at 1.25 / 10.00 up to 200K input tokens and 2.50 / 15.00 above
    When the book prices it
    Then it holds 2.50 input, 15.00 output and 0.25 cached input, the higher tier

  # @test:the_fallback_is_at_least_every_row_in_every_column
  Scenario: No Gemini row is dearer than the fallback
    Given the fallback that prices a model nobody listed
    When every row of the book is compared with it
    Then no Gemini row exceeds it in any column
