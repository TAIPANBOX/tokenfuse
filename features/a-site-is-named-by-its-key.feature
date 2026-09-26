Feature: A gateway's site is named by the key it pushed with

  Measured 2026-09-26 while designing a two-site deployment: `WireRecord`
  carries no gateway identity at all. Two sites pushing telemetry to one
  Cloud cannot be told apart in `/v1/runs`, `/v1/owners`, or anywhere else -
  their spend mixes into one org-wide pile - and a site that stops pushing
  is invisible: nothing distinguishes "this site is quiet" from "this org has
  no traffic right now". tokenfuse#296 is the related issue.

  @decided 2026-09-26: each site gets its own Cloud ingest key, and the Cloud
  names the site from the KEY, never from anything in the request body or
  headers - the same principle invariant 15 already holds for identity
  generally (a caller can choose a header; it cannot choose which secret it
  holds). A key spec's optional 4th segment (`key:org:role:site`) binds it to
  one site. The gateway binary itself is not changed at all: it still just
  POSTs to `/v1/ingest` with whatever key it was configured with.

  A second, narrower credential rides along: an `ingest` role (alongside
  `admin`/`viewer`) that may push telemetry and read what a viewer reads, but
  cannot kill a run, set a budget, or pair a device. Without it, every remote
  site would need to hold a full org-admin secret just to phone home. The
  recommended form for a site's key is `secret:org:ingest:site-name`.

  @claude - what this does NOT do: the key names the site, but the gateway
  PROCESS itself is still not authenticated cryptographically (the plane
  cannot tell "the real gateway at site-a pushed this" from "someone holding
  site-a's key did" - the same gap `Store::ingest`'s own honesty note already
  names). A site's silence is now visible on `GET /v1/gateways`
  (`last_push_millis`), but it raises no incident yet - nothing pages anybody
  when a site goes quiet, unlike `run_stalled` (invariant 60) for a run. And a
  stolen site key can still push arbitrary telemetry as that site, same as any
  other credential compromise.

  # @test:a_fourth_segment_is_parsed_as_the_site
  # @test:an_empty_fourth_segment_means_no_site
  # @test:an_invalid_site_name_skips_the_whole_entry
  # @test:five_segments_are_malformed_and_skipped
  # @test:three_segment_specs_parse_exactly_as_before
  Scenario: The key spec's optional 4th segment names a site
    Given a key spec with a 4th segment
    When it is parsed
    Then a non-empty, valid site name is kept, an empty one means no site, and an invalid or extra segment fails the WHOLE entry closed
    And a spec with 2 or 3 segments parses exactly as it always did

  # @test:a_key_bound_to_a_site_attributes_every_record_it_pushes_to_that_site
  # @test:an_unbound_key_pushes_into_the_unnamed_bucket
  # @test:the_run_keeps_the_last_named_site
  Scenario: A push is attributed to the pushing key's site
    Given a key bound to a site, and a key bound to none
    When each pushes a batch of call records
    Then the bound key's records land under its site in GET /v1/gateways
    And the unbound key's records land under the literal "unnamed" bucket
    And a run keeps the last site named by a push on it, the same "last non-empty wins" rule unit and owner use

  # @test:a_record_cannot_choose_its_site
  Scenario: A record cannot choose its own site
    Given a batch pushed with a key bound to "real", carrying a record with an extra "site" and "gateway" field naming "spoofed"
    When the control plane ingests it
    Then only "real" appears anywhere in GET /v1/gateways
    And "spoofed" never appears - a body field that isn't part of the wire shape is silently ignored, not read as an override

  # @test:last_push_is_server_time_not_the_records_timestamp
  # @test:an_empty_batch_is_a_heartbeat
  # @test:blocked_rows_count_as_calls_but_not_as_spend_at_the_gateway_level
  Scenario: A site's liveness is read from the plane's own clock, not the gateway's
    Given records whose own timestamps are far in the past and far in the future
    When they are pushed
    Then last_push_millis is the CONTROL PLANE's clock at the moment of the push, never a record's timestamp
    And an empty batch still counts as a push - a heartbeat - and moves last_push_millis
    And a blocked row counts as a call but never as spend, the same gate org-wide totals use

  # @test:a_site_past_the_cap_folds_into_unnamed
  # @test:gateways_survive_a_snapshot_round_trip
  # @test:an_old_snapshot_without_gateways_loads_empty
  Scenario: Site cardinality is bounded, and the ledger survives a restart
    Given an org already at its maximum number of distinct sites
    When a brand new site name pushes
    Then it folds into "unnamed" rather than evicting an existing site's counters
    And every site's counters survive a save-and-load round trip
    And a snapshot saved before this feature existed loads with no sites, never a guess backfilled from old data

  # @test:an_ingest_key_may_push_telemetry
  # @test:an_ingest_key_cannot_kill_a_run_or_set_a_budget
  # @test:an_ingest_key_may_read_units_and_unit_budgets
  # @test:a_viewer_key_still_cannot_ingest
  Scenario: The ingest role is a narrow, site-scoped credential
    Given an org key with role "ingest"
    When it is used against every route the control plane exposes
    Then it may push telemetry to /v1/ingest, attributed to its own site
    And it may read exactly what a viewer may read, including the two polls the gateway itself makes
    But it is refused, exactly like a viewer, on every mutation - killing a run, setting a run or unit budget, and pairing a device
    And a plain viewer key is still refused at /v1/ingest, unchanged by the new role existing beside it

  # @test:gateways_endpoint_requires_a_credential_and_a_viewer_may_read
  Scenario: GET /v1/gateways is a read like any other
    Given no credential, and a viewer credential
    When each requests GET /v1/gateways
    Then the uncredentialed request is refused
    And the viewer reads the same per-site rollup an admin or ingest key would see
