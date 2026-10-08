Feature: The price book a gateway charges with is readable from the gateway

  TOKENFUSE_PRICE_BOOK replaces built-in rows or adds rows at startup, and
  until now the only record of what it did was one startup log line with two
  counts. A model id the book has no row for is charged at the fallback, up
  to five times a list price, and the only trace of that was the x-fuse-price
  header on each answer and one warn line per model.

  The ask: make the active price book visible on the gateway, behind the
  same admin-key rules as the other observability routes, with the merged
  book's size and what the operator's file replaced and added.

  @claude 2026-10-08, under delegated authority: a small read route,
  GET /v1/price-book, rather than a field on /v1/policy-plane, which reports
  on the policy PDP. It also names the model ids the fallback has priced
  since the process started, because those are the ids an operator needs a
  row for; they are caller-chosen, so the list is bounded and the route is
  behind the admin gate.

  # @test:the_price_book_route_names_the_operators_rows_and_the_fallback
  Scenario: The route names what the operator's file replaced and added
    Given a gateway started with a TOKENFUSE_PRICE_BOOK file replacing claude-sonnet-5 and adding my-local-model
    When GET /v1/price-book is read
    Then it reports one more row than the built-in book and that a file is in effect
    And it names claude-sonnet-5 as replaced and my-local-model as added
    And it gives the fallback rates of 15 and 75 USD per million tokens

  # @test:the_price_book_route_names_the_operators_rows_and_the_fallback
  Scenario: Without a file the built-in book is the whole book
    Given a gateway started with no TOKENFUSE_PRICE_BOOK
    When GET /v1/price-book is read
    Then its rows equal the built-in book's and nothing is replaced or added

  # @test:the_price_book_route_names_the_operators_rows_and_the_fallback
  Scenario: A model the book has no row for is named once it is charged at the fallback
    Given a gateway that has charged no call at the fallback
    When a call on claude-sonnet-6, which has no row, is priced
    Then GET /v1/price-book names claude-sonnet-6 among the fallback-priced model ids

  # @test:the_price_book_route_is_behind_the_admin_gate
  Scenario: The route sits behind the admin gate
    Given an open bind with no admin keys, and then a gateway with an admin key
    When GET /v1/price-book is requested with no key, and then with the key
    Then the open bind refuses it 403 admin_keys_required
    And the keyed gateway refuses it 401 without the key and answers with it

  # @test:caller_chosen_ids_are_bounded_in_count_and_length
  Scenario: Caller-chosen model ids are bounded in the report
    Given 502 fallback-priced model ids, one of them a megabyte long and one cut inside a two-byte character
    When the report is built
    Then it lists at most 100 ids, each cut at 256 bytes with its length named, and gives the total
