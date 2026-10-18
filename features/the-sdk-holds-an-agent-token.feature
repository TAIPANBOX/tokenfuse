Feature: An agent's SDK holds its own token and signs each request

  The Python and JS SDKs get an agent token from vouchryx with the agent's own
  ES256 key, cache it, and send every request to a TokenFuse door with a fresh
  DPoP proof. A server may ask for a nonce; the helper answers each challenge
  once and never loops. The key and the token stay out of logs and errors.

  Both SDKs run the same scenarios. Each scenario is bound to a test of the
  same name in sdk/python/tests and in sdk/js/test.js.

  # @test:test_fetches_a_token_and_sends_it_with_a_fresh_proof
  Scenario: The helper gets a token and sends it with a proof for each request
    Given an agent enrolled at vouchryx with an enrolment key
    When the agent calls a door twice
    Then both calls carry "DPoP <token>" with a proof signed by the agent key
    And vouchryx was asked once

  # @test:test_refreshes_at_eighty_percent_of_the_lifetime
  Scenario: A cached token is refreshed at eighty percent of its life
    Given a token that lives 300 seconds
    When the agent calls the door at 239 seconds and again at 240 seconds
    Then vouchryx was asked once before 240 seconds and twice after

  # @test:test_each_proof_names_its_request_and_its_token
  Scenario: Each proof names its method, its URL without query, its token and a fresh jti
    Given a request to a door with a query string
    When the agent sends it
    Then the proof has htm, htu without the query, iat, a jti of at least 96 bits, and ath of the token

  # @test:test_a_nonce_challenge_is_retried_once_with_the_nonce
  Scenario: A door's nonce challenge is answered by one retry carrying the nonce
    Given a door that answers 401 use_dpop_nonce with a DPoP-Nonce header
    When the agent sends a request
    Then the agent retries once, and the retry's proof carries that nonce

  # @test:test_the_newest_nonce_is_used_next
  Scenario: The newest nonce the server sent is used on the next request
    Given a door that rotates its nonce on a 200 answer
    When the agent sends two requests
    Then the second proof carries the rotated nonce

  # @test:test_a_second_challenge_is_not_retried
  Scenario: A second nonce challenge is handed back and not retried again
    Given a door that challenges every proof
    When the agent sends a request
    Then the agent sent exactly two requests and returns the second 401

  # @test:test_a_token_request_nonce_challenge_is_retried_once
  Scenario: A nonce challenge from vouchryx on the token request is retried once
    Given vouchryx answers 400 use_dpop_nonce to the first token request
    When the agent fetches its token
    Then the second token request carries a proof with that nonce and the token is issued

  # @test:test_the_enrolment_key_is_form_encoded_in_basic
  Scenario: The enrolment key goes in client_secret_basic with the client id form-encoded
    Given an agent id that contains a colon and slashes
    When the agent asks vouchryx for a token
    Then the Basic credential decodes to the form-encoded id and secret, and nothing else

  # @test:test_a_workload_token_is_sent_as_the_client_assertion
  Scenario: A workload token is sent as the RFC 7523 client assertion
    Given a workload token that the platform rotates
    When the agent asks vouchryx for a token
    Then the request carries that token as client_assertion, read at the time of the request

  # @test:test_the_token_and_the_key_never_reach_a_log_or_an_error
  Scenario: The token and the key never appear in a log line or an error message
    Given a door and vouchryx that both refuse
    When the agent sends requests and the refusals are raised
    Then no log line and no error message contains the token, the key or the enrolment secret

  # @test:test_the_key_must_be_an_es256_key
  Scenario: A key that is not a P-256 private key is refused before any request
    Given a private key on another curve
    When the agent is created
    Then the helper refuses it and sends nothing
