Feature: An ambiguous send failure keeps its exposure

  @measured cargo test -p tokenfuse-gateway --test send_failure_retention 2026-09-23:
  a redirect from the provider reached a second host, and a refused connection
  on the request's only hop was conservatively retained rather than released.

  # @test:a_post_received_before_eof_retains_both_ledgers_on_both_paths
  Scenario: The provider accepted the POST but never answered
    Given the upstream consumed the complete request body
    When the connection closes before a response head on either path
    Then child, parent and unit keep the same reserve with zero spend and one retained handle

  # @test:a_redirect_from_the_provider_is_not_followed_and_the_key_stays_home
  Scenario: A redirect from the provider is not followed
    Given the provider answers the POST with a redirect to another host
    When the gateway forwards it on either path
    Then the redirect is not followed, the key and the body never reach the other host, and the refusal releases both reservations at zero

  # @test:a_refused_connection_on_the_only_hop_releases_both_ledgers
  Scenario: A connection the provider never accepted is not a call
    Given nothing listens at the provider's address
    When the call is forwarded on either path
    Then the caller gets a 502, child, parent and unit are released at zero and nothing is retained

  # @test:a_request_that_cannot_be_built_releases_both_ledgers
  Scenario: Request construction fails before dispatch
    Given an invalid endpoint that cannot build a request
    When the adapter rejects it before executing transport
    Then child, parent and unit release at zero and retain no handle on both paths
