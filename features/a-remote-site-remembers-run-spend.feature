Feature: A remote site's gateway remembers what a run has already spent

  @decided 2026-10-05: a remote site's gateway must seed its per-run spend
  from the hub after a restart or a hub migration, without the site being
  able to read more than it could before. The hub entry gains one route for
  this, answered only about the caller site's own runs.

  Measured 2026-10-05 (forge -> GCP hub migration): run mig-flint had 2566
  uUSD at the hub and a 4500 budget; the site gateway, restarted behind the
  hub's public entry, logged that pending run spend could not be seeded,
  because the entry answers GET /v1/runs 404 by design (it lists the whole
  org). The next call, estimated at about 2550, was admitted. At home, with
  an in-cluster gateway that seeds, the same call at the same budget got 402.

  @claude on the shape, invariant 75: the Cloud answers GET /v1/run-spend
  only to an org key bound to a site, only about runs whose site is that
  site, with three fields per run. The gateway asks it first and falls back
  to GET /v1/runs only on 403 or 404.

  # @test:a_site_key_reads_the_spend_of_its_own_sites_runs_only
  Scenario: A site reads the spend of its own runs and no other site's
    Given the hub holds mig-flint at 2566 uUSD pushed by site flint and mig-brume pushed by site brume
    When site flint asks for its run spend
    Then it is told mig-flint at 2566 uUSD and nothing about mig-brume

  # @test:a_site_gateway_seeds_from_its_sites_route_when_the_org_list_is_closed
  Scenario: A site gateway behind the hub entry seeds its runs after a restart
    Given a hub whose entry answers the org-wide run list 404
    And whose site route reports mig-flint at 2566 uUSD
    When the site gateway starts
    Then mig-flint's 2566 uUSD is staged for its first call here
    And the org-wide run list is never asked

  # @test:a_restarted_gateway_refuses_a_run_the_cloud_reported_already_at_its_budget
  Scenario: The seeded spend is what the next call is checked against
    Given a run whose seeded spend leaves less room than the next call's estimate
    When the restarted gateway is asked for that call
    Then the call is refused 402 before the provider is reached

  # @test:a_row_carries_exactly_run_id_spend_and_killed
  Scenario: A site is told three things per run and nothing more
    Given a run the site pushed with an agent id
    When the site asks for its run spend
    Then each row carries the run id, its spend and whether it is killed, and no other field

  # @test:a_key_bound_to_no_site_is_refused_whatever_its_role
  # @test:a_site_bound_key_of_any_role_is_scoped_to_its_site
  Scenario: A key that names no site is refused, whatever its role
    Given an admin key, a viewer key and an ingest key, none bound to a site
    When each asks for run spend
    Then each is refused 403 and told about no run
    And an admin key bound to a site is told about that site's runs only

  # @test:the_same_site_name_in_another_org_reads_nothing_of_this_one
  # @test:no_key_or_an_unknown_key_is_unauthorized
  Scenario: The org and the site both come from the key
    Given another organization with a site of the same name
    When that site asks for run spend
    Then it is told about none of this organization's runs
    And a request with no key or an unknown key is refused 401

  # @test:a_killed_run_says_so
  # @test:since_millis_selects_runs_and_the_window_header_names_it
  Scenario: The site read keeps the run list's window and kill marks
    Given a site run that was killed and a site run last seen before the window
    When the site asks for its run spend since the window start
    Then the killed run says so, the old run is left out, and the applied window is named

  # @test:a_refused_or_absent_site_route_falls_back_to_the_org_list
  Scenario: An in-cluster gateway or an older Cloud keeps today's seed
    Given a Cloud that answers the site route 403 for a key bound to no site, or 404 because it is older
    When the gateway starts
    Then it seeds from the org-wide run list, as it did before

  # @test:an_empty_site_answer_never_falls_back_to_the_org_list
  # @test:only_403_or_404_on_the_site_route_falls_back
  Scenario: Only a refusal or an absent route sends the gateway to the org-wide list
    Given a site route that answers an empty list, 401, or a server error
    When the gateway starts
    Then it never asks the org-wide run list and seeds nothing it was not told about its own site

  # @test:a_run_last_pushed_by_another_site_belongs_to_that_site
  Scenario: A run that moved to another site is that site's now
    Given a run pushed first by flint and then by brume
    When flint asks for its run spend
    Then flint is not told about it and brume is told its whole spend
