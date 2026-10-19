Feature: A paired device's credential is held as a digest, and a restart does not reopen a replay

  Measured by the agent-security review of 2026-10-17: a paired device's bearer
  token was the map key of the snapshot, so the state file held every live
  device token in clear, and the replay ring lived only in memory, so a request
  signed in the two minutes before a restart could be replayed after it.
  Invariant 132.

  @decided 2026-10-17: device credentials are stored as digests, and a request
  signed before this process started is refused, and a nonce seen before a
  restart is still refused after it.

  # @test:a_device_token_is_stored_as_its_digest_and_never_in_the_snapshot
  Scenario: A device keeps working and its token is not in the state file
    Given a paired device
    When the control plane writes its state
    Then the device token appears nowhere in the file and its digest does

  # @test:a_snapshot_with_raw_device_tokens_is_migrated_and_rewritten_hashed
  Scenario: A state file from an older version still authenticates the device
    Given a state file that holds a raw device token as its key
    When the control plane loads it and writes it again
    Then the device still authenticates and the raw token is gone from the file

  # @test:a_device_request_signed_before_a_restart_is_refused_after_it
  # @test:a_device_request_signed_after_the_restart_is_accepted
  Scenario: A request signed before the process started is refused, one after is not
    Given a device that signed a request before a restart
    When the replacement process receives it
    Then the request is refused, and a fresh one from the same device is accepted

  # @test:a_nonce_recorded_before_a_restart_is_refused_after_it
  # @test:a_nonce_outside_the_window_is_forgotten_and_one_inside_it_survives_a_load
  Scenario: A nonce seen before a restart is still refused after it, within the window
    Given a device request accepted once before a restart
    When the same signed request is sent to the replacement process
    Then it is refused, and a nonce older than the 120 second window is forgotten on load
