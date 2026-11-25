Feature: Shadow samples the cache's similarity walk
  tokenfuse#329: in shadow the walk over stored entries runs for a sample of the
  new prompts, so measuring a would-hit rate does not cost half the throughput.

  # @test:shadow_walks_one_lookup_in_n_and_on_walks_every_one
  Scenario: Shadow walks one lookup in N and on walks every one
    Given one stored entry and ten new prompts near it
    When the cache is in shadow at one in ten, in shadow at one in one, and on
    Then shadow at one in ten walks once, and the other two walk ten times

  # @test:shadow_never_samples_an_exact_repeat
  Scenario: An exact repeat is never sampled
    Given a stored prompt
    When shadow looks it up ten times
    Then every lookup finds it

  # @test:shadow_samples_one_walk_in_ten_unless_told_otherwise
  Scenario: The sample defaults to one in ten
    Given TOKENFUSE_CACHE_SHADOW_SAMPLE_EVERY unset, blank, valid or unusable
    When it is read
    Then an unusable value is the default of ten
