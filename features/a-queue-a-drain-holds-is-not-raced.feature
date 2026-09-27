Feature: A queue a drain is still responsible for is never raced by a fresh send

  tokenfuse#344's CI ran cloudsink::tests::the_cap_drops_the_oldest_and_says_so_once
  once and it failed: the first record the control plane received back was
  r05646 where r00026 was expected. A rerun passed; 75 local repeats did not
  reproduce it. drain()'s own loop pops a chunk off the queue before it knows
  whether that chunk's post will succeed, so the queue reads empty for the
  whole await of that one POST even though a chunk is still in flight and will
  be pushed back to the front on failure. A ship() call landing in that exact
  window read "nothing queued" and took the fast (direct-send) path too,
  racing the drain's own retry to push to the front last.

  @claude on the shape: ship() must also check draining, not is_holding()
  alone, since draining stays true for a drain's whole loop, every pop/post/
  push-back cycle included, closing exactly the window is_holding() alone
  could not see. Invariant 71.

  # @test:a_ship_call_while_a_drain_is_in_progress_appends_rather_than_racing_it
  Scenario: A ship() call while a drain is in progress appends behind it
    Given a drain is in progress and the queue happens to read empty mid-loop
    When a fresh batch is shipped
    Then it is appended to the queue synchronously, never sent directly
    And it cannot resolve out of order with the drain's own retry

  # @test:a_ship_call_with_no_drain_in_progress_still_takes_the_fast_path
  Scenario: With no drain in progress, a ship() call still sends directly
    Given no drain is in progress and nothing is queued
    When a fresh batch is shipped
    Then it is sent directly rather than queued first
    And the healthy-path throughput this fast path exists for is unchanged
