Feature: An events file that cannot be created is said out loud, and the image runs in the group the directory expects

  Issue #292, measured 2026-09-17 on the appliance proving run. The launchers
  share one events directory between the gateways and the control plane, owned
  root:10001 with mode 2775, so a process in group 10001 may create files in
  it. Both images created their user with `useradd -r -u 10001` and no group of
  that id, so the process ran as uid 10001 with gid 999 and could not create
  the file. The Cloud's exporter opened the path, got a permission error, and
  handed back the disabled exporter with no message. TOKENFUSE_EVENTS_PATH was
  set, four budget_exhausted incidents existed in /v1/incidents, and neither
  the notifier nor the record saw one; nothing in the log said why. With the
  file pre-created as 10001:10001 the same binary logged that the export was
  enabled and the next incident reached the bus within seconds.

  The gateway already warned on the same open failure; the control plane did
  not, because the convenience constructor in tokenfuse-core swallowed the
  error and that crate has no logging of its own. Both processes now read the
  variable through one function that hands back what happened beside the
  exporter, and each process logs it in the same words: a chosen silence and a
  forgotten log line look identical from outside, so the constructor no longer
  offers the silent form at all.

  The ask, in plain words: on an open failure, log one line at warn naming the
  path and the error and saying the export is off; create group 10001 before
  the user in every Dockerfile that creates uid 10001, so the gid matches the
  launchers' directory. The launchers pre-creating the file is their own
  change and is not held here.

  # @test:a_control_plane_whose_events_file_cannot_be_created_says_so_at_warn_and_keeps_running
  Scenario: The control plane cannot create the events file
    Given TOKENFUSE_EVENTS_PATH names a file in a directory the control plane may not write to
    When the control plane starts
    Then it prints one line at warn naming the path and the operating system's error
    And that line says the export is off
    And the control plane goes on to serve, with the exporter disabled rather than the process dead

  # @test:a_control_plane_with_a_writable_events_path_says_the_export_is_enabled
  Scenario: The same start with a writable path is enabled, which is what makes the warning above a measurement
    Given TOKENFUSE_EVENTS_PATH names a file the control plane can create
    When the control plane starts
    Then it prints that the export is enabled and nothing at warn about the path

  # @test:an_unwritable_directory_is_named_at_warn_and_the_export_is_off
  Scenario: The gateway says the same thing in the same words
    Given TOKENFUSE_EVENTS_PATH names a file in a directory the gateway may not write to
    When the gateway builds its exporter at startup
    Then it logs one line at warn naming the path and the error and saying the export is off
    And the exporter is the disabled one, so a request costs nothing

  # @test:from_env_reports_an_unset_variable_as_off_with_nothing_to_log
  Scenario: Unset stays silent and free
    Given TOKENFUSE_EVENTS_PATH is unset or empty
    When either process reads it at startup
    Then there is nothing to log about the export and the exporter is the zero-cost one

  # @test:from_env_reports_an_opened_file_with_its_path_and_where_the_chain_resumed
  Scenario: A path that opens is reported as on, with the chain it resumed from
    Given TOKENFUSE_EVENTS_PATH names a file this process can append to
    When either process reads it at startup
    Then the outcome says the export is on, names the path, and says whether the hash chain resumed or started fresh

  # @test:every_image_that_creates_uid_10001_creates_group_10001_first_and_puts_the_user_in_it
  Scenario: The images run as 10001:10001, not 10001:999
    Given the two Dockerfiles that create the runtime user with uid 10001
    When the runtime stage creates that user
    Then a group with gid 10001 is created first and the user is put in it
    And a process in the image can therefore create files in a directory owned root:10001 with mode 2775
