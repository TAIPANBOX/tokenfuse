Feature: The agent-token door publishes its protected resource metadata

  The MCP authorization specification (revision 2026-07-28) requires an MCP server
  to publish RFC 9728 protected resource metadata. The broker published it only for
  the cross app access door, so an agent that met the broker with its own token
  found no document, and a refusal named none.

  @decided 2026-10-18: the broker publishes the document whenever the agent-token
  door is on, not only with XAA, and a refused agent token is challenged with the
  DPoP scheme naming that document.

  The choices inside it are @claude: the document's fields come from the delegation
  door's own configuration; the challenge's origin comes from the configured
  resource, never from a Host header; an error parameter is sent only for a token
  that was presented; and the two documents that can share a process must not
  contradict each other.

  # @test:accept_serves_the_document_without_credentials
  Scenario: Under accept the document is served without a credential
    Given the agent-token door accepts tokens
    When a client fetches the well-known path with no credential
    Then the document names the resource, the issuer and ES256, and does not require bound tokens

  # @test:require_serves_the_document_with_bound_tokens_required
  Scenario: Under require the document says bound tokens are required
    Given the agent-token door requires tokens
    When a client fetches the well-known path
    Then the document says a DPoP-bound access token is required

  # @test:a_path_resource_serves_its_suffixed_document
  # @test:a_path_resource_challenge_names_its_suffixed_document
  Scenario: A resource with a path is published at its suffixed twin
    Given the delegation audience is a resource with a path
    When a client fetches the path-suffixed well-known path, or is refused at that path
    Then the document and the challenge both name the path-suffixed document

  # @test:with_both_doors_off_no_document_is_served
  Scenario: With both doors off nothing new is routed
    Given neither the agent-token door nor XAA is on
    When a client fetches the well-known path
    Then the answer is 404, as it was before this change

  # @test:a_refused_token_is_challenged_with_dpop_and_invalid_token
  # @test:a_missing_credential_under_require_is_challenged_without_an_error_parameter
  # @test:the_challenge_origin_comes_from_configuration_not_the_host_header
  # @test:the_document_and_the_challenge_name_the_same_resource
  # @test:a_refused_token_gets_the_agent_token_refused_body
  # @test:a_missing_credential_under_require_gets_the_agent_token_required_body
  Scenario: A refused or missing agent token is challenged from configuration
    Given the agent-token door is on
    When a call carries a refused token, or no credential under require
    Then the answer is 401 with a DPoP challenge naming the document, built from the configured resource, with the error parameter only for a presented token, and the agent door's own body

  # @test:with_xaa_the_document_adds_the_agent_fields_and_never_requires_bound_tokens
  # @test:xaa_alone_serves_the_xaa_document_unchanged
  # @test:with_xaa_a_refused_agent_token_is_still_challenged_with_dpop
  Scenario: XAA and the agent door share one document without contradicting each other
    Given XAA is on beside the agent-token door
    When a client fetches the document, or presents a refused agent token
    Then the document is XAA's with the agent fields added and never requires bound tokens, and with XAA alone it is unchanged

  # @test:an_agent_audience_that_is_not_https_refuses_to_start
  # @test:an_xaa_resource_that_differs_from_the_agent_audience_refuses_to_start
  Scenario: A resource that cannot be one document refuses to start
    Given the agent-token door is on
    When the audience is not an absolute https URL, or XAA names another resource
    Then the process exits with status 2 naming the variable that is wrong
