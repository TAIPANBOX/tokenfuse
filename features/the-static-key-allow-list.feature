Feature: Under require, a static client key is admitted only when it is listed

  The agent-security review of 2026-10-18 found that a static client key is the
  strongest credential a caller can hold, and that a key shared by a namespace
  stops no single agent. Agent tokens (invariant 123) are the replacement; a
  client that cannot sign DPoP proofs still needs a key until it is moved.

  @decided 2026-10-19: static client keys stop being the default credential. The
  doors require agent tokens, and a static key is admitted only for a named list
  of clients that cannot sign DPoP proofs. The rule is written here in paraphrase.

  The choices inside it are @claude, under delegated authority: the list is a
  comma-separated set of key ids, never secrets; it is read only under require,
  and a list set while the mode is not require refuses to start rather than being
  ignored; a listed key is admitted exactly as under accept, so its records say
  client-key; and the 401 for a refused key is the same body whether the key is
  unknown or merely unlisted, because a body that told the two apart would tell a
  caller which keys are real.

  # @test:the_static_key_list_is_refused_unless_require_is_on
  # @test:a_list_of_separators_alone_names_no_key_and_is_refused
  # @test:a_blank_static_key_list_is_no_list_in_any_mode
  # @test:the_static_key_list_reads_its_entries_trimmed
  # @test:the_static_key_list_names_an_id_the_key_set_does_not_configure
  # @test:a_static_key_list_outside_require_stops_the_gateway_naming_it
  # @test:a_static_key_list_naming_an_unconfigured_key_stops_the_gateway_naming_the_id
  # @test:a_static_key_list_outside_require_stops_the_broker_naming_it
  Scenario: A list set outside require stops the process before it serves
    Given TOKENFUSE_AGENT_TOKENS is accept or off
    And TOKENFUSE_AGENT_TOKENS_STATIC_KEYS names a key id
    When the gateway starts
    Then it exits 2 before listening, naming the list variable

  # @test:the_static_key_list_names_an_id_the_key_set_does_not_configure
  # @test:a_static_key_list_naming_an_unconfigured_key_stops_the_gateway_naming_the_id
  Scenario: A listed key id that the client key set does not configure stops the process
    Given TOKENFUSE_AGENT_TOKENS is require
    And TOKENFUSE_AGENT_TOKENS_STATIC_KEYS names a key id that TOKENFUSE_CLIENT_KEYS does not configure
    When the gateway starts
    Then it exits 2 before listening, naming that key id

  # @test:require_admits_an_allow_listed_static_key_as_accept_does
  Scenario: A listed static key is admitted under require and recorded as the key
    Given TOKENFUSE_AGENT_TOKENS is require
    And the static key for key-a is listed
    When the key-a caller sends a call with its static key
    Then the call is admitted
    And the record files it under key-a

  # @test:require_refuses_an_unlisted_static_key_and_an_unknown_one_the_same_way
  Scenario: An unlisted key and an unknown key get the same refusal under require
    Given TOKENFUSE_AGENT_TOKENS is require
    And only key-a is listed
    When a caller sends the static key of key-b, which is configured but not listed
    And another caller sends a key nobody configured
    Then both are answered 401 agent_token_required with the same body
    And the body names TOKENFUSE_AGENT_TOKENS_STATIC_KEYS

  # @test:require_with_no_list_refuses_every_static_key_as_before
  Scenario: Under require with no list, every static key is still refused
    Given TOKENFUSE_AGENT_TOKENS is require
    And TOKENFUSE_AGENT_TOKENS_STATIC_KEYS is unset
    When a caller sends a configured static key
    Then the call is refused 401 agent_token_required

  # @test:a_token_beside_a_listed_key_is_still_refused_under_require
  Scenario: A token beside a listed key is still two credentials and refused
    Given TOKENFUSE_AGENT_TOKENS is require
    And the static key for key-a is listed
    When the caller sends its agent token and key-a's static key on one call
    Then the call is refused 401 agent_token_refused
