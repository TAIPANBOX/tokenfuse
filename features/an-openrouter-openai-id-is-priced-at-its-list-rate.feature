Feature: An OpenRouter openai/ model id is priced at OpenAI's list rate

  Measured 2026-10-14 on forge through the OpenAI door over OpenRouter: the
  openai/ ids had no row, so a call settled at the fallback, thirty times and
  more its list price, and small run budgets were refused before their first
  call.

  @decided 2026-10-14: a vendor/model id is priced at the vendor's row when the
  bare model is known; an unknown id keeps the fallback. Invariant 107.

  # @test:the_measured_openrouter_call_is_priced_at_openais_list_rate
  Scenario: The measured call is charged its list price
    Given a call on openai/gpt-4.1-mini that used 14 input and 2 output tokens
    Then it is priced known and charged 0.000009, where the fallback charged 0.000360

  # @test:a_small_budget_is_no_longer_refused_before_its_first_call
  Scenario: A small budget admits its first call
    Given a run budget of 0.004 and a call allowed 1024 output tokens
    Then the call is admitted

  # @test:the_gpt_4_1_family_is_priced_under_its_own_ids
  # @test:the_gpt_4_1_family_is_priced_at_its_list_rate
  Scenario: The GPT-4.1 family has rows
    Then gpt-4.1, gpt-4.1-mini and gpt-4.1-nano are priced at OpenAI's list, bare and under openai/

  # @test:every_openai_id_is_priced_under_its_openrouter_name_too
  Scenario: Every OpenAI row is also its OpenRouter name, long tier included
    Then each openai/ twin prices a short and a long call exactly as its bare id does

  # @test:an_openai_id_the_book_does_not_know_still_takes_the_fallback
  Scenario: An id the book does not know keeps the fallback
    Given a call on openai/gpt-9-turbo
    Then it is priced at the fallback
