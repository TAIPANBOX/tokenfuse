Feature: An ambiguous send failure keeps its exposure

  @measured cargo test -p tokenfuse-gateway --test send_failure_retention 2026-09-19:
  a complete POST followed by EOF or a failing redirect released its reservation.

  # @test:a_post_received_before_eof_retains_both_ledgers_on_both_paths
  Scenario: The provider accepted the POST but never answered
    Given the upstream consumed the complete request body
    When the connection closes before a response head on either path
    Then child, parent and unit keep the same reserve with zero spend and one retained handle

  # @test:a_post_redirected_to_a_refused_connection_is_not_unsent
  Scenario: A redirect fails after the original POST arrived
    Given the original upstream consumed the POST and redirected it
    When the redirected connection is refused
    Then the original call remains retained on both paths

  # @test:a_connect_error_without_dispatch_evidence_conservatively_retains
  Scenario: A transport error has no proof of non-dispatch
    Given a refused connection without dispatch evidence
    When the HTTP adapter reports its error
    Then it conservatively retains both reservations on both paths

  # @test:a_request_that_cannot_be_built_releases_both_ledgers
  Scenario: Request construction fails before dispatch
    Given an invalid endpoint that cannot build a request
    When the adapter rejects it before executing transport
    Then child, parent and unit release at zero and retain no handle on both paths
