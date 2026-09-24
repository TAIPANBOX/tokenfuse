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

  # @test:a_refreshed_entry_is_not_evicted_as_if_it_were_still_the_oldest
  Scenario: A refresh is not treated as still the oldest entry
    Given a partition at its cap holds an entry that is then refreshed
    When one more entry is inserted past the cap
    Then the refreshed entry survives and the next-oldest untouched entry is evicted

  # @test:a_refreshed_entry_moves_to_the_back_of_fifo_order_not_out_of_it
  Scenario: A refresh moves an entry to the back of FIFO order, not out of it
    Given a refreshed entry and several newer entries inserted afterward
    When enough newer entries arrive to make the refreshed one the oldest again
    Then the refreshed entry is evicted in its turn and the newer entries survive

  # @test:entity_guard_blocks_a_near_identical_pair_that_would_otherwise_hit
  Scenario: The entity guard is proven against a pair that would otherwise hit
    Given two cores whose similarity is confirmed above threshold but whose entities differ
    When the second core is looked up
    Then no hit is returned
