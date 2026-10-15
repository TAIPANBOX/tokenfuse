Feature: A DLP finding the scanner lets through is on the bus

  agent-passport SPEC 6.2 registered dlp_shadow under tokenfuse on 2026-10-14
  and trailryx maps it, but no emit site produced it: a shadow or mask finding
  was a note on the answer and nothing else, so the week an operator watches
  before turning block on left nothing on the bus to decide with.

  @decided 2026-10-14: shadow DLP findings go on the bus. Invariant 114.

  # @test:a_secret_found_in_shadow_is_one_dlp_shadow_on_the_bus
  Scenario: A secret found in shadow is one dlp_shadow, kinds and counts only
    Given the secret scan in shadow mode
    When an agent sends a prompt carrying an AWS access key
    Then the prompt is forwarded
    And one dlp_shadow at medium names aws_access_key once, the mode shadow and the agent
    And the key itself is nowhere on the line

  # @test:pii_masked_on_its_way_is_one_dlp_shadow_in_mask_mode
  Scenario: PII masked on its way is one dlp_shadow in mask mode
    Given the PII scan in mask mode
    When an agent sends a prompt carrying an email address and a card number
    Then one dlp_shadow names pii_card and pii_email once each, the mode mask
    And neither the address nor the digits are in its data

  # @test:each_scanner_that_let_a_finding_through_is_its_own_event_in_its_own_mode
  Scenario: Each scanner reports in its own mode
    Given the secret scan in mask mode and the PII scan in shadow mode
    When a prompt carries a key and an email address
    Then there are two dlp_shadow events, the secret in mask and the email in shadow

  # @test:a_prompt_a_scanner_refused_writes_no_dlp_shadow
  Scenario: A prompt a scanner refused writes no dlp_shadow
    Given the secret scan blocks, or the secret scan shadows and the PII scan blocks
    When a prompt carries what the blocking scan refuses
    Then the call is refused 403
    And no dlp_shadow is written, since nothing was let through

  # @test:a_prompt_with_nothing_found_writes_no_dlp_shadow
  Scenario: A clean prompt writes nothing
    Given both scans in shadow mode
    When a prompt carries no secret and no PII
    Then no dlp_shadow is written

  # @test:dlp_shadow_is_on_the_wire_at_the_band_of_the_other_shadow_findings
  Scenario: The band is fixed at medium, beside taint_shadow and below dlp_block
    Given the event type dlp_shadow
    Then its wire string is dlp_shadow and its severity medium
    And that is taint_shadow's band and not dlp_block's

  # @test:dlp_shadow_data_counts_kinds_and_never_carries_a_span
  Scenario: The data counts kinds and never carries a matched span
    Given PII findings of two email addresses and one card
    When the event data is built
    Then counts reads pii_card 1 and pii_email 2
    And no matched text is in it, and an unresolved unit is null
