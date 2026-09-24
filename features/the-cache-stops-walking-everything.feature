Feature: The semantic cache stops walking everything under one lock

  A repeated request used to cost the same linear walk, under one global
  lock, as a request the cache had never seen. This adds an exact-match
  index so a repeat is found in O(1) with no similarity walk at all, and
  replaces a duplicate put instead of growing the partition forever.

  # @test:identical_core_twice_replaces_not_appends
  Scenario: A repeated put replaces, it does not append
    Given a partition already holds one entry for a core text
    When the same core text is put again with a new response
    Then the partition still holds exactly one entry
    And a lookup serves the newer response

  # @test:an_exact_hit_never_walks_similarity
  Scenario: An exact repeat costs no embedding and no walk
    Given a partition holds an entry for a core text
    When the identical core text is looked up
    Then no embedding is computed and no similarity walk runs

  # @test:a_miss_still_falls_through_to_the_similarity_walk
  Scenario: A genuinely new core still gets the similarity walk
    Given a partition holds an entry for one core text
    When a materially different core text is looked up
    Then the embedder is called and the similarity walk runs as before

  # @test:hash_collision_never_serves_the_wrong_response
  Scenario: A bucket collision never serves the wrong response
    Given two different core texts are forced into the same exact-index bucket
    When each of their own texts is looked up through that bucket
    Then each lookup serves only its own response, verified by digest

  # @test:an_expired_exact_entry_is_not_served
  Scenario: An expired exact match is not served
    Given a partition holds an entry past its TTL
    When the identical core text is looked up
    Then no hit is returned

  # @test:expired_entries_disappear_after_a_put
  Scenario: Expiry is swept in put, not get
    Given a partition holds an expired entry
    When a later put runs
    Then the expired entry and its exact-index bucket are both gone

  # @test:eviction_keeps_the_exact_index_in_step
  Scenario: Eviction keeps the exact-match index consistent
    Given a partition is filled past its entry cap
    When the oldest entries are evicted
    Then the exact-index carries exactly as many ids as there are live entries

  # @test:concurrent_get_and_put_never_deadlock_or_cross_wires
  Scenario: Concurrent readers are never serialized against each other
    Given many threads put and get against the same partition concurrently
    When they all finish
    Then nothing deadlocks and no thread is ever served another thread's response
