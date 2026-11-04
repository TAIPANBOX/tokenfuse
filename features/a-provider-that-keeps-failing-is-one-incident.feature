Feature: A provider that keeps failing is one incident

  The gateway puts a dependency_failed on the bus for every call a provider
  fails, and every call is its own run. An hour of a provider answering 503 is
  thousands of events, and a notifier that keys its window on the run sends a
  mail for each of them. The control plane folds a provider's failures into
  one incident per provider, on the console and in the API.

  This is the console and the API only. The incident names a provider and no
  agent or run, the agent-event envelope requires a subject, and no event type
  is added, so nothing new reaches the bus.

  Background:
    Given a control plane whose provider threshold is three failed calls in ten minutes

  # @test:a_provider_under_the_threshold_opens_nothing
  # @test:the_failure_that_reaches_the_threshold_opens_one_incident_for_that_provider
  # @test:a_storm_of_failures_is_one_incident_whose_count_is_the_storm
  Scenario: A storm of failures is one incident whose count is the storm
    Given a provider that has failed twice
    Then no incident is open
    When it fails a third time
    Then one incident dependency_failed:provider:<name> is open at severity high with three occurrences
    When it fails four hundred and ninety-seven more times
    Then there is still one incident, with five hundred occurrences

  # @test:the_failure_that_reaches_the_threshold_opens_one_incident_for_that_provider
  Scenario: The incident names a provider and neither an agent nor a run
    Given an incident opened for a provider
    Then it has no agent id, no run id and no reporting source
    And it is not exported to the agent-event bus

  # @test:a_report_that_carries_a_count_counts_every_failure_in_it
  # @test:later_failures_add_to_the_incident_that_is_already_open
  Scenario: A report counts every failure it carries
    Given a gateway reports seven failures in one report
    Then the incident opens with seven occurrences
    When it reports five more
    Then the incident has twelve occurrences

  # @test:two_providers_are_two_incidents
  # @test:a_provider_failing_in_one_org_is_not_counted_in_another
  Scenario: Providers and orgs are counted apart
    Given two providers each failing three times
    Then there are two incidents
    And two orgs each seeing two failures of one provider open nothing

  # @test:failures_older_than_the_window_do_not_count
  # @test:failures_inside_the_window_do_count
  # @test:the_window_slides_rather_than_resetting
  Scenario: The count is a window that slides
    Given two failures and then a third eleven minutes later
    Then nothing opens, because the first two have left the window
    And two failures and a third nine minutes later do open an incident

  # @test:the_threshold_is_the_configured_one
  # @test:a_zero_count_and_a_blank_provider_open_nothing
  Scenario: The threshold is configurable and a blank report opens nothing
    Given the threshold is one, then five
    Then one failure opens at one and four do not at five
    And a zero count and a blank provider name open nothing

  # @test:an_ingest_key_an_admin_key_and_a_site_bound_ingest_key_may_report
  # @test:a_viewer_is_forbidden_and_a_caller_with_no_key_is_unauthorized_and_nothing_is_counted
  # @test:three_reported_failures_are_one_incident_on_the_incidents_api
  Scenario: Only a key that may push telemetry may report, and the incident reads from the API
    Given keys with the admin, ingest and viewer roles and no key at all
    When each reports failures
    Then the admin and ingest keys are accepted
    And the viewer is refused and the caller with no key is unauthorized, and neither opens anything
    And three reported failures show as one incident on the incidents API

  # @test:a_body_over_the_limit_is_refused_before_it_is_counted
  # @test:more_entries_than_allowed_are_refused_and_none_is_counted
  # @test:a_malformed_report_is_a_bad_request_and_counts_nothing
  # @test:an_empty_report_a_blank_provider_and_a_zero_count_are_accepted_as_nothing
  Scenario: A report is bounded in size and in entries and refused when malformed
    Given a body over sixteen kibibytes, sixty-five entries, and reports with a negative, fractional, missing or overflowing count
    Then each is refused without counting anything
    And an empty report or a blank provider is accepted as nothing

  # @test:a_hostile_label_is_sanitised_and_bounded
  # @test:hostile_labels_cannot_open_an_incident_apiece
  # @test:a_provider_already_tracked_keeps_its_own_incident_when_the_cap_is_full
  # @test:a_provider_name_cannot_carry_markup_into_an_incident
  Scenario: A provider name is not trusted
    Given labels with markup, line breaks, path segments, control characters, non-ASCII text and ten thousand characters
    Then each becomes at most a hundred and twenty-eight characters of letters, digits and . _ : -
    And a hundred and ninety-two different names open at most sixty-five incidents, the last in one visible other bucket
    And a provider that was already tracked keeps its own incident when the cap is full

  # @test:an_absurd_count_is_clamped_and_cannot_overflow
  # @test:the_summary_names_the_provider_and_is_bounded_and_clean
  # @test:a_summary_with_no_detail_still_reads
  Scenario: A count and a detail are not trusted either
    Given a report whose count is the largest 64-bit integer, twice
    Then each is clamped to a million and nothing overflows
    And the summary names the provider and the detail has no control characters and at most a hundred and sixty

  # @test:only_a_provider_failure_is_counted_for_the_cloud_incident
  # @test:only_a_providers_health_statuses_are_counted_for_the_cloud
  Scenario: Only the provider's failures are counted at the gateway
    Given dependency_failed events for the policy plane, the control plane and the provider
    Then only the provider's are counted for the report
    And of a provider's refusals only a 5xx, a 408 and a 429 are, not the 400 or 404 a caller can provoke with a model id of its own

  # @test:the_text_of_a_transport_error_never_goes_to_the_cloud
  Scenario: The Cloud is told a fixed class and never the text of the error
    Given a send that fails with an error message naming the upstream URL with a credential in its query
    Then the Cloud's copy says send failed and carries neither the URL nor the credential
    And the caller's model is not sent either

  # @test:a_site_bound_report_is_filed_under_its_site
  # @test:two_sites_reporting_one_provider_are_two_incidents_that_never_add_up
  # @test:a_key_bound_to_no_site_is_counted_apart_from_every_site
  # @test:a_key_bound_to_one_site_cannot_add_to_another_sites_count
  # @test:the_site_comes_from_the_key_and_never_from_the_body
  Scenario: A key bound to one site cannot add to another site's count
    Given two keys bound to two different sites, each reporting two failures of one provider
    Then nothing opens, because the sites are counted apart
    And each site's own third failure opens an incident filed under that site
    And a body that names another site is filed under the site of the key

  # @test:a_provider_that_stopped_failing_gives_its_slot_back
  # @test:the_provider_cap_is_per_site_so_one_site_cannot_crowd_out_another
  # @test:a_site_name_is_sanitised_and_a_blank_one_is_no_site
  Scenario: Labels that stopped failing do not crowd out a real provider
    Given sixty-four providers that failed once and then stopped, past the window
    When a real provider fails three times
    Then it opens its own incident, not the shared bucket
    And one site's flood of labels does not touch another site's cap

  # @test:a_storm_of_failures_is_one_report_with_the_count
  # @test:nothing_counted_sends_nothing
  # @test:a_flush_clears_the_count_so_the_next_report_is_only_what_is_new
  Scenario: A thousand failures in two seconds are one report
    Given a gateway that has counted a thousand provider failures
    When it flushes
    Then one POST carries the provider, the count of a thousand and the last detail, with the Cloud key
    And a flush with nothing counted sends nothing, and the next report holds only what is new

  # @test:a_refused_report_is_dropped_and_not_replayed
  # @test:an_unreachable_cloud_drops_the_report_and_does_not_hang
  # @test:noting_with_no_reporter_installed_is_a_no_op
  Scenario: A report that cannot be delivered is dropped, never queued
    Given a Cloud that refuses the report, and a Cloud that cannot be reached
    Then the counted failures are dropped and the next flush has nothing to send
    And an unreachable Cloud does not hold the flush
    And a gateway with no Cloud counts nothing

  # @test:the_detail_is_cut_and_stripped_of_control_characters
  # @test:the_provider_label_is_the_authority_of_the_upstream
  # @test:a_credential_written_into_the_upstream_url_is_not_in_the_label
  Scenario: What leaves the gateway is bounded and carries no credential
    Given a failure detail with control characters and ten thousand characters
    And an upstream URL with a user and a password in it
    Then the detail sent has none of the control characters and at most a hundred and sixty characters
    And the provider label is the host and port and nothing of the credential
