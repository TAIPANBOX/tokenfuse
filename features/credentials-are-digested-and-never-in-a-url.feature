Feature: The control plane holds its org keys as digests, and the dashboard's key stays out of the query

  Measured by the agent-security review of 2026-10-17: the Cloud's org-key map
  was keyed by the raw secret, and the Next.js dashboard read its key from a
  query parameter, which the server, the access log and the Referer header all
  see. Invariant 133.

  @decided 2026-10-17: org keys are held and looked up by digest, and the
  dashboard takes its key from the URL fragment, then strips it from the address bar.

  # @test:the_map_is_keyed_by_digest_and_never_by_the_raw_secret
  # @test:digest_is_sha256_hex_with_a_prefix
  Scenario: The map that authenticates a bearer holds no raw secret
    Given an org key spec
    When the control plane parses it
    Then the map is keyed by the SHA-256 digest and never by the secret

  # @test:the_dashboard_reads_its_key_from_the_fragment_before_the_query
  # @test:the_dashboard_takes_the_key_out_of_the_address_bar_once_it_has_read_it
  Scenario: The dashboard connects from a fragment key and removes it from the address bar
    Given a dashboard link that carries the key in the fragment
    When the dashboard opens it
    Then it connects with that key and the address bar no longer shows it
