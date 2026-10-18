Feature: The issuer's key set is fetched, polled and replaced, and is never trusted when it could not be read

  A vouchryx key rotation needed a restart of every door, because the key set
  was a file read once at start. The set can also be served by a URL and polled,
  so a rotation reaches a running door within a poll. A door that cannot read its
  set at start does not start, and a poll that fails keeps the keys the door
  already holds. A key the polled set no longer names stops verifying.

  Background:
    Given a delegation door with an issuer configured

  # @test:naming_no_key_url_leaves_the_file_behaviour_alone
  Scenario: No key URL keeps the key file as it was
    Given no key URL is named
    When the door starts
    Then the key file decides the keys, as before this feature existed

  # @test:a_key_url_together_with_a_key_file_refuses_to_start
  Scenario: A key URL and a key file together refuse to start
    Given both a key URL and a key file are named
    When the door starts
    Then it refuses to start and names both variables, because one set must be the source

  # @test:a_key_url_with_no_issuer_refuses_to_start
  Scenario: A key URL needs an issuer to verify against
    Given a key URL and no issuer
    When the door starts
    Then it refuses to start, since a key set with no issuer verifies nothing

  # @test:a_key_url_that_is_not_absolute_http_is_refused
  Scenario: A key URL must be an absolute http or https address
    Given a key URL that is a relative path, a bare host or a file address
    When the door starts
    Then it refuses to start

  # @test:the_interval_defaults_and_a_bad_one_is_refused
  Scenario: The poll interval defaults to a minute, and a bad one is refused
    Given a key URL and no interval
    When the door starts
    Then it polls once a minute
    And an interval that is not a positive number of milliseconds refuses to start

  # @test:an_empty_or_unparsable_key_set_is_never_installed
  Scenario: A key set that holds no keys, or is not a key set, is never installed
    Given a body that is not a key set, or a key set with no keys
    When the door reads it
    Then the body is refused, so a door never trusts a set that would refuse every token

  # @test:a_key_set_over_the_size_cap_is_refused_before_it_is_read
  Scenario: A key set over the size cap is refused
    Given a body larger than the cap
    When the door reads it
    Then the body is refused without being parsed

  # @test:a_first_fetch_that_fails_refuses_to_start
  Scenario: A door that cannot fetch its key set at start does not start
    Given the key URL answers nothing
    When the door starts
    Then it refuses to start, because a door holding no keys refuses every delegation while reporting itself as on

  # @test:a_poll_installs_the_set_the_server_now_holds
  Scenario: A poll replaces the key set
    Given a door that started with a key set
    And the server now serves a rotated key under the same key id
    When the door polls
    Then a token signed with the rotated key verifies
    And a token signed with the key it replaced does not

  # @test:a_removed_key_stops_verifying_after_a_poll
  Scenario: A key the set no longer names stops verifying
    Given a door that started with a key set naming a key
    When a poll returns a set that no longer names that key
    Then a token signed with that key is refused

  # @test:an_unknown_kid_is_refused_even_when_the_only_key_held_would_verify
  Scenario: A token whose key id the set does not name is refused
    Given a key set that holds the issuer's key under a different key id
    When a token names the key id the set does not hold
    Then the token is refused, even though the one key held would have verified its signature

  # @test:a_failed_poll_keeps_the_keys_already_held
  Scenario: A failed poll keeps the keys already held
    Given a door that started with a key set
    When the server answers an error to a poll
    Then the poll is reported as failed
    And a token signed with a held key still verifies
