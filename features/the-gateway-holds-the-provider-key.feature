Feature: The gateway holds the provider key

  Finding F-002 of the agent-security review of 2026-10-17: the agents held the
  LLM provider key, and the gateway forwarded whatever provider credential the
  caller sent. An agent with any outbound tool could call the provider directly
  with the key it already held, and nothing metered that call. The gateway
  forwarded the caller's own key upstream and held none of its own.

  @decided 2026-10-17: the gateway holds the provider key of each door in a file
  and sends it upstream itself. A caller's own provider credential is never
  forwarded: it is accepted only when it is a gateway credential, so an SDK that
  is given the gateway key works unchanged. A gateway that is not brokered says
  so at startup and on its health detail, and launchers always broker.

  # @test:a_caller_supplied_x_api_key_is_refused_when_brokered
  # @test:a_caller_supplied_provider_key_never_reaches_the_upstream
  Scenario: A caller's own provider key is refused and never reaches the upstream
    Given the gateway holds its provider key and client keys are on
    When a caller sends its own provider key in x-api-key or authorization
    Then the answer is 401 provider_credential_refused and the upstream sees no request
    And the presented key appears in no answer and no record
    When a caller sends the gateway key alone
    Then the upstream receives the gateway-held provider key and nothing of the caller's

  # @test:a_stock_sdk_key_is_the_gateway_key_on_the_anthropic_door
  Scenario: A stock SDK authenticates with the gateway key alone
    Given the gateway holds its provider key for the Anthropic door
    When an SDK sends the gateway key in x-api-key and no other credential
    Then the call is admitted and the upstream receives the provider key in x-api-key

  # @test:a_gateway_key_as_bearer_is_the_credential_on_the_openai_door
  # @test:the_default_upstream_auth_follows_the_wire
  Scenario: The OpenAI door takes the gateway key as a bearer and sends the provider key as a bearer
    Given the gateway holds its provider key for the OpenAI door
    When an SDK sends the gateway key as Authorization Bearer
    Then the call is admitted and the upstream receives the provider key as Authorization Bearer
    And without a configured auth word the Anthropic door sends x-api-key and the OpenAI door sends a bearer

  # @test:a_brokered_provider_says_it_holds_its_key
  # @test:a_key_file_with_a_trailing_newline_is_read_without_it
  # @test:a_provider_key_never_appears_in_debug_output
  # @test:a_brokered_gateway_says_so_at_startup_without_the_key
  Scenario: A brokered gateway reads its key from a file and never prints it
    Given the provider key is in a file ending with a newline
    When the gateway starts with that file
    Then the key is read without the newline and reported as held by the gateway
    And the key appears in no debug output and no startup line

  # @test:an_unreadable_upstream_key_file_refuses_to_start
  # @test:an_empty_upstream_key_file_refuses_to_start
  # @test:an_unknown_upstream_auth_word_refuses_to_start
  # @test:an_upstream_auth_without_a_key_file_refuses_to_start
  Scenario: A key file that cannot be used stops the start
    Given the gateway is configured with a key file it cannot use
    When it starts
    Then it exits with status 2 naming the variable that is wrong
    And it does not serve

  # @test:an_unbrokered_gateway_says_so_at_startup
  # @test:an_unbrokered_gateway_says_so_on_healthz
  Scenario: An unbrokered gateway says so on startup and on its health detail
    Given the gateway has an upstream and no key file
    When it starts and when its health detail is read
    Then both say that the provider key comes from the caller
