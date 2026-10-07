Feature: The price book prices every model a vendor lists, and says when it guesses

  A model with no price-book row is charged at the conservative fallback
  rate, 15 / 75 USD per million tokens. That is the safe direction for a
  budget cap, but it was up to five times the list price of claude-sonnet-5
  and of every Claude model reached through Bedrock, Google Cloud or
  OpenRouter (tokenfuse#305, #313), and nothing said so. The book now has a
  row for each id the vendors list, each rate read from the vendor's page on
  a named date; a model nobody has priced still falls back and says so; and
  an operator can supply rows of their own in a file read once at startup.

  # @test:every_vendor_listed_id_prices_at_its_list_rate
  # @test:a_listed_model_is_priced_known_at_its_list_rate
  Scenario: Every listed id is priced at its vendor's rate
    Given the price book the gateway ships
    When a call names claude-sonnet-5, anthropic/claude-sonnet-5, claude-opus-5-5 or a Bedrock global profile
    Then the response says x-fuse-price: known
    And the call costs the vendor's list rate

  # @test:the_measured_sonnet_5_call_settles_at_list_not_the_fallback
  Scenario: The measured claude-sonnet-5 call costs its list price
    Given a claude-sonnet-5 call with 2874 input and 200 output tokens
    When it is priced
    Then it costs 7748 micro-USD, not the 58110 the fallback charged

  # @test:every_vendor_listed_id_prices_at_its_list_rate
  # @test:a_listed_model_is_priced_known_at_its_list_rate
  Scenario: An id that may name a regional endpoint is priced with the regional premium
    Given a bare Bedrock id, a Bedrock us, eu, jp or apac profile, or a Google Cloud dated id
    When it is priced
    Then the rate is list plus 10 percent, the over-charging side

  # @test:a_truly_unknown_id_still_falls_back
  # @test:a_model_nobody_priced_still_says_fallback
  Scenario: A model nobody priced still falls back and says so
    Given a model id with no row
    When a call names it
    Then it is priced at the 15 / 75 fallback
    And the response says x-fuse-price: fallback

  # @test:a_streamed_answer_says_which_price_it_was_reserved_at
  Scenario: A streamed answer says which price it was reserved at
    Given a streamed call
    When the answer's headers are sent
    Then they carry x-fuse-price, known or fallback

  # @test:the_fallback_is_logged_once_per_model
  Scenario: The fallback is said once per model
    Given three calls on one unpriced model and one on another
    When they are priced
    Then each unpriced model is warned about exactly once
    And a priced model is never warned about

  # @test:a_row_overrides_the_built_in_rate_and_a_new_id_is_added
  # @test:the_binary_prices_with_the_operators_rows
  Scenario: An operator's file overrides a built-in row and adds new ones
    Given TOKENFUSE_PRICE_BOOK names a file with claude-sonnet-5 at the regional rate and a free local model
    When the gateway starts and prices calls
    Then claude-sonnet-5 costs the file's rate and the local model costs nothing
    And a model in neither still falls back

  # @test:hostile_files_are_refused_and_say_why
  # @test:the_size_and_row_caps_hold
  # @test:hostile_bytes_never_panic_and_never_slip_a_bound
  # @test:an_unusable_price_book_exits_2_and_names_the_variable
  Scenario: A file that cannot be trusted stops the gateway
    Given a file with a negative, fractional or absurd rate, an unknown or missing key, a duplicate id, a fallback, no rows, or more than the size or row cap
    When the gateway starts
    Then it exits with status 2 and names TOKENFUSE_PRICE_BOOK
    And it never runs on the built-in book in its place
