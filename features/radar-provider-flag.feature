Feature: Radar flags a provider address as LLM traffic only on the port the provider serves

  Radar flags a connect() as "LLM provider" when its destination address
  resolved from a known provider hostname, and it did so on any port. A
  resolver choosing a source address per RFC 6724 connect()s a UDP socket to
  every candidate address of a multi-address name and sends nothing: Go on
  port 53, glibc on port 0, musl on 65535. The tracepoint sees each one, so a
  process that merely resolved api.openai.com was printed as one that called
  it. Measured 2026-09-08 on idryx's sensor, which shares this classifier's
  shape (TAIPANBOX/idryx#67); radar's own README called the capture "TCP",
  which it is not.

  # @test:a_provider_address_is_llm_traffic_only_on_443
  Scenario: A resolver's probe to a provider address is not an API call
    Given a captured connect() whose destination is a known LLM provider address
    When the destination port is 53, 65535 or any other port the provider does not serve
    Then radar prints the connection without the "LLM provider" flag
    And the same address on port 443 is still flagged "LLM provider"
