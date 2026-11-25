Feature: The MCP broker sends an upstream its own credential
  tokenfuse#364: an MCP server that answers only its own token can sit behind
  the broker, with the token read from the operator's file and never taken from
  the caller.

  # @test:the_broker_sends_each_upstream_its_own_credential_and_never_the_callers
  Scenario: Each upstream gets its own token and never the caller's
    Given a file naming a token for the default upstream and none for another
    When a caller sends its own Authorization to each upstream through the broker
    Then the default upstream receives the file's token and the other receives none

  # @test:each_upstream_gets_its_own_bearer_token_keyed_by_server
  Scenario: The token is held by server and marked sensitive
    Given files for the default and a named upstream
    When the value is read
    Then each server holds its own bearer token, never printed by Debug

  # @test:one_bad_entry_refuses_the_whole_value_and_never_names_the_token
  Scenario: One bad entry stops the broker
    Given a value with a malformed entry, an unknown name, a repeated name, or a file that is missing, empty, too large or not a header value
    When the value is read
    Then it is refused naming the variable and never the token

  # @test:unset_or_blank_credentials_send_nothing
  Scenario: Unset sends nothing
    Given the variable unset or blank
    When the value is read
    Then no upstream gets a credential
