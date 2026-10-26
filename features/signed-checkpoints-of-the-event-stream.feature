Feature: The gateway signs checkpoints of its own event stream, and a witness can check them

  A producer signs checkpoints of its own agent-event stream so that a witness
  outside the writers (keyryx) can prove later that the stream was not rewritten.
  The records are agent-passport SPEC 6.5.1 format v1, the same bytes a Go
  producer writes, signed by a key keyryx certifies. Nothing changes until an
  operator turns it on, and the events are never held up or dropped for it.

  # @test:nothing_configured_is_off
  # @test:checkpoints_off_leave_the_stream_byte_for_byte_as_before
  Scenario: Nothing configured, nothing changes
    Given no checkpoints directory is configured
    When the gateway writes events
    Then no checkpoint file is created and the stream is written exactly as before

  # @test:the_vector_records_are_reproduced_byte_for_byte
  # @test:a_writer_over_the_vector_stream_writes_the_vector_sidecar_byte_for_byte
  # @test:the_vendored_vectors_are_agent_passports_byte_for_byte
  Scenario: The records are the bytes agent-passport's vectors pin
    Given agent-passport's checkpoint vectors, the stream and the signatures they carry
    When this writer hashes that stream and writes its checkpoint file
    Then every record and every signing input is the vector's, byte for byte

  # @test:every_64_lines_writes_one_record
  Scenario: A checkpoint every 64 events
    Given checkpoints are on
    When the gateway writes 64 events
    Then one checkpoint record names 64 lines, and 63 events alone wrote none

  # @test:ten_seconds_with_lines_waiting_writes_a_record_and_an_idle_stream_writes_none
  Scenario: A checkpoint after 10 seconds when events are waiting
    Given three events written and no record since
    When 10 seconds have passed
    Then a checkpoint names the three, and a stream with nothing new waiting gets none

  # @test:close_writes_a_close_record_naming_the_whole_stream
  # @test:the_gateway_signs_checkpoints_of_its_stream_and_closes_them_on_sigterm
  # @test:the_mcp_broker_signs_its_own_stream_and_closes_it_on_sigterm
  Scenario: A close record on a clean close
    Given the gateway or the MCP broker is writing events with checkpoints on
    When it is stopped with SIGTERM
    Then the last record is a close record naming every line in the stream

  # @test:a_stream_left_torn_gets_a_resume_record_and_its_fragment_is_terminated
  # @test:a_stream_ending_in_a_malformed_line_gets_a_resume_naming_the_last_event
  # @test:a_stream_the_exporter_chains_from_gets_no_resume
  Scenario: A resume record when the stream's tail cannot be chained from
    Given a stream a crash left ending in a fragment or a malformed line
    When the gateway opens it again
    Then a resume record names the last well-formed event, and the next event is not glued onto the fragment

  # @test:lines_another_writer_appended_are_read_back_into_the_prefix
  # @test:a_shortened_stream_is_hashed_again_from_byte_zero
  Scenario: The prefix is the stream's bytes as they stand
    Given lines this writer did not write were appended, or the stream was cut shorter
    When the next record is due
    Then its prefix is the SHA-256 of the stream's first N bytes as the file holds them

  # @test:prev_chains_from_genesis_through_every_record_and_across_a_reopen
  # @test:a_torn_record_in_the_sidecar_is_cut_before_the_next_is_appended
  Scenario: Each record chains to the one before it
    Given a checkpoint file with records in it, its last one possibly torn
    When the gateway writes another record, after a restart or not
    Then its prev is the SHA-256 of the last complete record, and the first record of a file carries 64 zeros

  # @test:a_key_is_certified_by_proving_possession_to_keyryx
  # @test:the_stream_gets_signed_records_that_verify_under_the_certified_key
  # @test:a_record_signed_by_a_held_key_verifies_under_its_jwk
  Scenario: Records are signed by a key keyryx certified
    Given keyryx custody grants this gateway a delegated key name
    When the gateway generates a key in memory and proves to keyryx that it holds it
    Then its records are signed ES256 over their canonical bytes and verify under the certified key

  # @test:a_statement_that_does_not_certify_this_key_is_refused
  Scenario: A statement that certifies something else is not used
    Given keyryx answers with a statement for another key, owner, life or time
    When the gateway reads it
    Then the key is not kept and no record is signed with it

  # @test:a_statement_with_no_signatures_is_refused
  Scenario: A statement that carries no signatures is not used
    Given keyryx answers with a statement whose signatures are missing or an empty list
    When the gateway reads it
    Then the key is not kept: the witness verifies a statement's signatures, and one with none has nothing to verify

  # @test:a_key_signs_only_inside_its_statement_window_in_whole_seconds
  # @test:a_key_past_its_statement_is_never_used_and_the_record_is_unsigned
  # @test:a_key_that_runs_out_mid_stream_gives_unsigned_records_not_stale_signatures
  Scenario: A key signs only while its statement is valid
    Given a key whose statement runs out
    When a record is due after it ran out
    Then the record is unsigned rather than signed by a key the witness would refuse

  # @test:a_key_is_renewed_at_half_its_life_and_run_out_keys_are_dropped
  Scenario: A key is renewed at half its life
    Given a certified key
    When half its life has passed
    Then a new key is asked for, and keys that ran out are dropped

  # @test:a_keyryx_that_is_down_at_start_gives_unsigned_records_until_a_key_is_certified
  # @test:an_unsigned_record_is_written_when_no_key_is_valid_and_counted_as_unsigned
  Scenario: With no certified key a record is written unsigned, never dropped
    Given keyryx cannot be reached when the gateway starts
    When records fall due
    Then each is written unsigned with an unsigned_reason, the gateway serves as usual, and records are signed again once a key is certified

  # @test:a_directory_with_anything_missing_refuses_to_start_naming_each
  # @test:an_unusable_value_refuses_to_start
  # @test:a_checkpoint_directory_with_no_keyryx_refuses_to_start_in_both_processes
  Scenario: Checkpoints turned on and unusable refuse to start
    Given a checkpoints directory with a keyryx setting missing or unusable
    When the gateway or the MCP broker starts
    Then it exits 2 naming what is missing

  # @test:a_second_writer_cannot_attach_to_a_held_sidecar
  # @test:a_sidecar_in_the_streams_own_directory_is_refused
  Scenario: Only one writer writes a stream's checkpoints, in a directory of their own
    Given one process holds a stream's checkpoint file
    When a second writer tries to attach, or the file would sit beside the stream
    Then it is refused

  # @test:a_refusal_carries_its_status_and_never_the_credential
  # @test:a_redirect_from_keyryx_is_not_followed
  Scenario: The keyryx credential stays home
    Given keyryx refuses a request, or answers with a redirect
    When the gateway reports it
    Then the error names the status and never the credential, and the redirect is not followed

  # @test:hostile_streams_never_panic_and_every_record_written_verifies
  # @test:hostile_streams_signed_with_a_real_key_verify
  # @test:hostile_sidecars_never_panic_and_the_next_record_chains_from_the_last_complete_line
  Scenario: Hostile bytes in the stream or the checkpoint file
    Given garbage, torn fragments, foreign lines and long lines in the stream or its checkpoint file
    When the gateway writes and checkpoints events among them
    Then nothing panics and every record it writes verifies against the stream
