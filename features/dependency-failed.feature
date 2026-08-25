Feature: The box's own dependency fails, and somebody is told

  The ask, verbatim, 2026-08-25: "коли лягає апстрім, шлюз чисто вертає 502,
  і жоден план цього не записує; у конверті подій немає типу для того, що
  зламалась власна залежність коробки."

  Measured before this feature existed: point the gateway's upstream at a dead
  port and it degrades correctly, 502, no hang, no invented answer, and the
  reservation released at zero. Nothing anywhere records that it happened. The
  fourteen types in the envelope are every one of them about the agent
  misbehaving or the box refusing it; none is about the box's own dependency
  dying. So an operator whose provider goes down sees agents stop working and
  gets no alert, from a stack whose whole purpose is telling them what their
  agents are doing.

  The provider is not the only dependency. A policy plane that cannot be
  reached is the same fact one plane over, and under the default fail-open it
  is the worse one: the call proceeds, ungoverned, and the trail says a
  policy allowed it.

  Background:
    Given a gateway an operator is running
    And the event stream is configured

  # @test:a_provider_that_cannot_be_reached_is_recorded
  Scenario: The provider is unreachable
    Given the upstream refuses the connection
    When an agent makes a call
    Then the caller still gets a clean 502 and nothing invents an answer
    And the event stream carries one event naming the provider as the failure
    And it says what the box did about it, so a reader is not left guessing

  # @test:a_healthy_call_reports_no_dependency_failure
  Scenario: A working day writes nothing
    Given every dependency answers
    When an agent makes a call
    Then no dependency-failure event is written at all

  # @test:a_stream_that_dies_mid_answer_is_recorded
  Scenario: The provider dies halfway through an answer
    Given the upstream accepted the call and then stopped mid-stream
    When the agent is reading the answer
    Then the failure is recorded, because the caller already has a 200 and the
      status line can no longer say anything

  # @test:a_response_body_that_cannot_be_read_is_recorded
  Scenario: The answer arrives and cannot be read
    Given the upstream answered and the body could not be collected
    When the call is settled
    Then the failure is recorded under the same type, naming the stage it
      happened at

  # @test:a_call_with_no_identity_reports_no_dependency_failure
  Scenario: A call nobody can attribute
    Given a call carrying no run id and no agent id
    When its upstream is unreachable
    Then no event is written, because the envelope requires an identity and
      inventing one would put a name on something that did not do it

  # @test:an_unreachable_policy_plane_is_recorded_when_it_fails_open
  Scenario: Governance is silently off
    Given the policy plane cannot be reached
    And the gateway is configured to fail open
    When an agent makes a call
    Then the call proceeds, which is what fail-open means
    And the event stream says the policy plane was the dependency that failed
    And it says the call went through ungoverned, rather than leaving a
      reader to infer it from an absence

  # @test:an_unreachable_policy_plane_is_recorded_when_it_fails_closed
  Scenario: The refusal is not the whole story
    Given the policy plane cannot be reached
    And the gateway is configured to fail closed
    When an agent makes a call
    Then the call is refused
    And the event stream still says the plane was unreachable, because
      "a policy denied this" and "nobody could be asked" are different facts

  # @test:an_unreachable_policy_plane_in_shadow_mode_reports_what_actually_happened
  Scenario: Watching a plane that is not answering
    Given the policy plane cannot be reached
    And the gateway is only shadowing, so it blocks nothing whatever the failmode says
    When an agent makes a call
    Then the event says the call went through
    And it does not report a refusal, because the configuration is not what happened

  # @test:a_policy_plane_that_answered_is_not_reported_as_unreachable
  Scenario: A plane that answered is not reported as dead
    Given the policy plane answers every call
    When it denies one
    Then no dependency-failure event is written, because nothing failed

  # @test:the_dependency_failed_event_carries_the_high_band
  Scenario: An operator is woken by this
    When a dependency-failure event is written
    Then its severity is high, fixed by the type and not chosen at the call site
    And that clears the notifier's floor, so a person is actually told
