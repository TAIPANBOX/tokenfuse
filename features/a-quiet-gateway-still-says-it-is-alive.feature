Feature: A quiet gateway still says it is alive

  Measured 2026-09-26 on a two-site run (a GCP hub and a site at home).
  Invariant 65 gave the Cloud `GET /v1/gateways` with `last_push_millis` set
  by the Cloud's OWN clock, and the Cloud already counts an empty push as a
  heartbeat. But the gateway (`crates/gateway/src/cloudsink.rs`, `CloudSink`)
  only pushes when it has records, so an idle but healthy site and a dead
  site look identical once both have been quiet for five minutes - the
  dashboard's "silent" label does not distinguish "nothing happened" from
  "nothing can happen here any more". Measured: `pushes=2` after two bursts
  of calls and nothing at all in between.

  @decided 2026-09-26: the site's liveness must be visible on its own, not
  only as a side effect of it having something to report. The gateway now
  pushes an empty batch on a timer when it has been otherwise quiet, sharing
  one clock with real pushes so traffic never triggers a redundant one.

  @claude - what this does NOT do: this is an interval, not a real-time
  signal - a site can go quiet for up to the configured interval before the
  next heartbeat is due, and `GET /v1/gateways` still has no detector paging
  anybody when a site goes silent past that (unlike `run_stalled`, invariant
  60, for a run). A heartbeat proves the gateway process and its network path
  to the Cloud, and nothing about whether the agents behind it are healthy.

  # @test:cloud_heartbeat_default_when_unset_or_empty
  # @test:cloud_heartbeat_zero_is_off
  # @test:cloud_heartbeat_junk_is_the_default
  # @test:cloud_heartbeat_small_positive_values_clamp_to_the_minimum
  # @test:cloud_heartbeat_thirty_is_thirty
  Scenario: The heartbeat interval is parsed once, safely
    Given TOKENFUSE_CLOUD_HEARTBEAT_SECONDS unset, empty, "0", a small positive value, junk, or a plain number
    When it is parsed at startup
    Then unset or empty is the default of 30 seconds
    And "0" turns heartbeats off
    And a value below 5 seconds is clamped up to 5, with one warning
    And a value that is not a non-negative integer is the default of 30, with one warning
    And any other non-negative integer is used as given

  # @test:an_idle_gateway_sends_a_heartbeat
  Scenario: An idle gateway still pushes
    Given a gateway connected to a Cloud with a short heartbeat interval
    And no call has been made since it started
    When the interval elapses
    Then it POSTs an empty records array to /v1/ingest

  # @test:a_gateway_with_traffic_sends_no_heartbeat
  Scenario: Traffic resets the heartbeat clock
    Given a gateway pushing real records more often than the heartbeat interval
    When several intervals elapse
    Then no empty push is ever sent - every push the Cloud receives carries records

  # @test:a_failed_heartbeat_is_never_queued
  Scenario: A failed heartbeat is lost, not queued
    Given a gateway connected to a Cloud it cannot currently reach
    When a heartbeat tick fails
    Then it is not added to the retry queue
    And once the Cloud is reachable again, nothing "recovers" as a replayed heartbeat

  # @test:no_heartbeat_while_the_queue_drains
  Scenario: The drain itself proves liveness
    Given a gateway whose retry queue is not empty
    When a heartbeat tick would otherwise fire
    Then it is skipped - the drain already answers the question a heartbeat would ask

  # @test:heartbeats_off_when_zero
  Scenario: Zero means off, not fast
    Given a heartbeat interval of zero seconds
    When the gateway runs for several times what the default interval would be
    Then no heartbeat is ever sent
