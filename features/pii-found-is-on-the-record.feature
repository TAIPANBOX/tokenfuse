Feature: PII found and let through is on the record, as kinds and counts

  Measured 2026-10-14 on forge: PII found in shadow mode was a note on the
  answer and nothing else, so no dashboard could show what shadow mode found.

  @decided 2026-10-14: the finding goes onto the trace and the fleet view now,
  as kinds and counts, never the text; the bus event follows its registry row.
  Invariant 106.

  # @test:shadow_records_the_kinds_it_found_and_never_the_text
  # @test:kind_counts_name_each_kind_and_how_often_never_the_text
  Scenario: Shadow records the kinds it found
    Given a gateway scanning for PII in shadow
    When a prompt carries an email address and a card number
    Then the call is forwarded
    And its trace row names pii_card=1,pii_email=1 and neither the address nor the number

  # @test:mask_records_what_it_redacted
  Scenario: Mask records what it redacted
    Given a gateway masking PII
    When the same prompt is sent
    Then the row names the same kinds and counts

  # @test:nothing_found_or_the_scan_off_records_nothing
  Scenario: Nothing found, or the scan off, records nothing
    Then the row carries no PII column value

  # @test:pii_a_gateway_let_through_reaches_the_runs_and_summary_reads
  Scenario: The fleet view counts the calls and the kinds
    Given two admitted records of one run naming PII and one record of another naming none
    Then the first run counts two PII calls and the second none
    And the summary counts two calls, email in two and card in one

  # @test:a_findings_string_without_the_scanners_shape_is_not_counted
  # @test:pii_findings_are_read_only_in_the_scanners_shape
  Scenario: A string not shaped like the scanner's output is not counted
    Given a record whose findings are markup, upper case, zero, too large or malformed
    Then nothing is counted and nothing is shown
