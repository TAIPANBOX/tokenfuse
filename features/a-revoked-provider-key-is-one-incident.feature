Feature: A fleet on a revoked or rotated provider key is one incident
  tokenfuse#312: a provider's 401 and 403 answers are counted by the caller that
  made them, apart from the provider's health, and three in ten minutes open one
  incident and one event on the bus.

  # @test:a_providers_401_or_403_is_counted_for_the_cloud_by_the_caller
  Scenario: The gateway counts a refused credential by the caller
    Given a provider that answers 401, 403, 429 or 200
    When an agent's call is answered, buffered or streamed
    Then a 401 or 403 is counted for the Cloud under the agent and a 429 only as the provider's health

  # @test:refused_credentials_are_reported_by_caller_and_bounded
  Scenario: The report carries refused credentials by caller, bounded
    Given refused credentials for two callers and more callers than the bound
    When the gateway reports
    Then the report names each caller's count and keeps the overflow under the empty caller

  # @test:three_refused_credentials_open_one_incident_and_one_event_under_the_agent
  Scenario: Three refused credentials open one incident and one event
    Given a provider that refused one agent's credential three times in ten minutes
    When the Cloud folds the reports
    Then one medium incident is open and one dependency_failed is on the bus under the agent, however many more follow

  # @test:a_caller_with_no_agent_is_filed_under_its_key_and_not_exported
  Scenario: A caller with no agent is filed under its key and not exported
    Given refused credentials reported for a key and no agent
    When the incident opens
    Then it names the key and nothing goes on the bus

  # @test:three_refused_credentials_are_one_auth_incident_on_the_incidents_api
  Scenario: The incident is on the API
    Given three reports of one agent's refused credential from a site's key
    When the incidents are listed
    Then one provider_auth_refused incident names the provider, the agent and the site
