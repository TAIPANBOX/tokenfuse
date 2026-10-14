Feature: A call the gateway answered reaches the Cloud when the gateway is stopped

  On GCP on 2026-10-14 a gateway pod was deleted while an agent loop ran
  through it. The agent had 43 answered calls; the Cloud held 41, and the
  restarted gateway took its run spend from those 41. The two missing calls
  were held in the gateway's memory between two pushes when it stopped.

  @decided 2026-10-14: spend reports are made durable across a stop, by
  delivering them before the process exits and/or by a local spool replayed
  on start, so a served call is never missing from the Cloud.

  @claude 2026-10-14: this change takes the first half. A stop by SIGTERM or
  SIGINT delivers what the gateway holds within 5 s and names what it could
  not deliver; a SIGKILL is not covered, and the spool is a follow-up because
  replaying it needs the Cloud to recognise a record it already has.

  # @test:a_call_served_just_before_sigterm_reaches_the_cloud
  Scenario: Calls answered just before SIGTERM are in the Cloud once the gateway has exited
    Given a gateway pushing to a Cloud
    And three calls it answered less than a flush interval ago
    When the gateway is sent SIGTERM and exits
    Then the Cloud holds all three calls

  # @test:a_stop_while_the_cloud_does_not_answer_says_what_was_not_delivered
  # @test:the_exit_flush_is_bounded_and_says_what_it_could_not_deliver
  Scenario: A Cloud that never answers cannot hold the exit, and the loss is named
    Given a Cloud that takes a push and never answers
    And three calls the gateway answered
    When the gateway is stopped
    Then it exits within its bound
    And it warns that three records did not reach the Cloud

  # @test:the_exit_flush_delivers_the_queue_then_the_buffer_in_order
  Scenario: What an outage queued goes out before what came after it
    Given two records queued while the Cloud was unreachable and one record buffered since
    When the Cloud answers again and the gateway stops
    Then the Cloud receives the queued two and then the buffered one, in that order

  # @test:a_push_on_the_wire_at_exit_is_counted_when_it_never_lands
  # @test:a_closing_sink_starts_no_push_of_its_own
  Scenario: A push already on the wire is waited for, and nothing new starts
    Given a push the Cloud has not yet answered when the gateway begins to stop
    When the stop's time runs out before the answer
    Then those records are counted as not delivered
    And no flush tick starts a push of its own while the gateway is stopping
