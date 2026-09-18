Feature: Telemetry pushed while the control plane is down is queued, not dropped

  Measured 2026-09-17 on the appliance proving run (tokenfuse#294): with the
  control plane stopped for about 40 seconds the gateway served three calls,
  each 200 and allowed by the policy plane. After the control plane came back,
  /v1/units for that unit stayed at 72 calls, and forty later calls raised it
  to 112, so the three made during the outage never arrived; the gateway's
  log said nothing about them in that window.

  @decided 2026-09-18: a status answer from the control plane is a refusal,
  warned once per status (invariant 13), never queued; the sink has no agent
  subject, so no agent-event type is added for it.

  @claude on the shape: a bounded in-memory queue in the sink, appended
  behind while it holds anything, drained from the front in batch-sized
  chunks by one drainer, oldest dropped first past the cap; the request path
  stays a buffer push. Invariant 53.

  # @test:records_pushed_during_an_outage_arrive_in_order_after_recovery
  Scenario: Records pushed during an outage arrive after it, in order
    Given a control plane that cannot be reached
    When three batches of telemetry are pushed during the outage
    Then nothing is lost, and once the control plane answers again every record arrives in the order it was recorded
    And one line says the queue drained and how many records were replayed

  # @test:one_transition_line_per_outage
  Scenario: The outage is said once
    Given a control plane that cannot be reached
    When several pushes fail
    Then one warning says records are being queued, and each failed attempt logs at debug
    And a later outage is said again

  # @test:the_cap_drops_the_oldest_and_says_so_once
  Scenario: A full queue drops the oldest records and says so once
    Given an outage long enough to fill the queue
    When more records arrive than the cap holds
    Then the oldest are dropped first, one warning says so, and the drained line counts them

  # @test:a_refusal_is_never_queued
  # @test:a_refused_push_is_visible_to_the_operator
  Scenario: A refusal is not an outage
    Given a control plane that answers every push with 403
    When telemetry is pushed
    Then nothing is queued, and the refusal is reported once as before

  # @test:a_drain_that_fails_midway_keeps_the_rest_in_order
  # @test:a_push_that_never_gets_an_answer_is_bounded_and_queued
  Scenario: A relapse keeps what is left, and a silent plane is bounded
    Given a control plane that answers one chunk of the replay and then goes away, or one that accepts a push and never answers
    When the drain runs
    Then the unanswered chunk goes back to the front and the rest wait in order for the next attempt

  # @test:record_and_flush_return_without_waiting_for_the_control_plane
  Scenario: The request path never waits for the control plane
    Given a control plane that accepts a connection and never answers
    When calls are recorded and flushed
    Then recording and flushing return at once; the wait belongs to the background push alone
