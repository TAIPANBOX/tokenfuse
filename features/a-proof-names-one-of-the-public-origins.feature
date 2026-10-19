Feature: A delegation proof names one of the public origins the operator configured

  A gateway is reached at a public name by its clients and at another name by the
  containers beside it. The operator names each origin this process is reached at,
  and a proof is accepted when the address it names is one of them at the route's
  own path. The address the caller says it reached is never read from a Host header.

  # @test:a_proof_addressed_to_a_second_configured_origin_is_accepted_on_the_openai_door
  Scenario: A proof addressed to the second configured origin is accepted
    Given the operator configured the public origin and the internal origin of the gateway
    When an agent presents a delegation proof addressed to the internal origin for a chat completion
    Then the call is answered 200

  # @test:the_first_origin_spelled_with_its_default_port_is_the_same_origin
  Scenario: The same origin spelled with its default port is the same origin
    Given the operator configured the public origin of the gateway
    When an agent presents a delegation proof addressed to that origin with its default port written out
    Then the call is answered 200

  # @test:a_host_header_naming_a_configured_origin_does_not_admit_an_htu_that_is_not_one
  Scenario: A Host header naming a configured origin admits nothing the proof does not name
    Given the operator configured the public origin and the internal origin of the gateway
    When an agent presents a proof addressed to an unlisted origin and a Host header naming a listed one
    Then the call is answered 401

  # @test:a_proof_naming_an_unlisted_origin_is_refused
  Scenario: A proof addressed to an origin nobody listed is refused
    Given the operator configured the public origin and the internal origin of the gateway
    When an agent presents a proof addressed to an origin the operator did not list
    Then the call is answered 401

  # @test:a_proof_with_user_information_in_its_htu_is_refused
  Scenario: A proof whose address carries user information is refused
    Given the operator configured the public origin of the gateway
    When an agent presents a proof whose address carries user information before the host
    Then the call is answered 401

  # @test:a_proof_with_a_fragment_in_its_htu_is_refused
  Scenario: A proof whose address carries a fragment is refused
    Given the operator configured the public origin of the gateway
    When an agent presents a proof whose address ends in a fragment
    Then the call is answered 401

  # @test:a_configured_origin_at_a_path_in_front_of_the_route_is_refused
  Scenario: A configured origin with a path in front of the route is refused
    Given the operator configured the public origin and the internal origin of the gateway
    When an agent presents a proof addressed to the internal origin with a path before the route
    Then the call is answered 401

  # @test:an_agent_token_proof_addressed_to_a_second_configured_origin_is_accepted
  Scenario: An agent token's proof addressed to the second configured origin is accepted
    Given the operator configured the public origin and the internal origin of the gateway
    And the agent token door is on in accept mode
    When an agent presents its own token with a proof addressed to the internal origin
    Then the call is answered 200

  # @test:a_proof_addressed_to_a_second_configured_origin_opens_the_door
  Scenario: A proof addressed to a second configured origin opens the MCP broker's door
    Given the operator configured the public origin and the internal origin of the broker
    When a client presents a proof of possession addressed to the internal origin
    Then the broker admits the client

  # @test:a_list_with_a_bad_entry_refuses_to_start_at_the_mcp_door
  Scenario: A list with an entry that is not an origin refuses to start the broker
    Given the operator's origin list has a trailing comma, a path, user information or a bad port in it
    When the broker reads the list
    Then it refuses to start

  # @test:the_single_origin_and_the_list_are_one_set_and_a_bad_entry_names_its_variable
  Scenario: The single origin and the list are read as one set
    Given the operator set the single origin and a list that repeats it
    When the gateway reads its delegation origins
    Then the origin is named once, and an empty entry names the list's variable
