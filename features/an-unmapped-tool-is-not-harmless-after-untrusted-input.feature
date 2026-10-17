Feature: A tool the policy names nowhere is not harmless after untrusted input

  The agent-security review of 2026-10-17 (finding F-003) read that the agent
  firewall failed closed on sources and open on actions: the output of a tool
  the source map does not name was labelled unclassified, but a tool the
  capability map does not name requested nothing, so a run that had read a web
  page could call http_request, fetch, slack_post or any MCP tool outside the
  nine starter names with what it had read in the arguments, and no rule had
  anything to deny.

  @decided 2026-10-17: close the agent-security findings of that review,
  starting with defaults and small fixes, on the hybrid architecture (identity
  from vouchryx, key custody and record witness off the request path). For this
  finding: a tool the policy names in neither map exercises the capability
  unclassified, and the starter policy denies it after untrusted input; a run
  with no untrusted label behaves exactly as before; shadow records what
  enforce would do. That a tool the source map names counts as classified is
  @claude, so a search after a search is not refused.

  # @test:a_tainted_run_calling_an_unmapped_tool_is_refused_in_enforce
  # @test:an_unmapped_tool_in_a_tainted_run_is_denied_at_the_check
  Scenario: An unmapped tool after a web read is refused in enforce
    Given the starter policy in enforce mode
    And a run that has read the web
    When the model asks for a tool neither map names
    Then the answer is refused with 403
    And the record names the rule no-exec-after-untrusted and the capability unclassified

  # @test:in_shadow_an_unmapped_tool_after_untrusted_input_is_recorded_not_refused
  Scenario: Shadow records what enforce would refuse
    Given the starter policy in shadow mode
    And a run that has read the web
    When the model asks for a tool neither map names
    Then the answer is forwarded
    And one taint_shadow names the capability unclassified

  # @test:a_clean_run_calling_an_unmapped_tool_is_unchanged
  # @test:an_unmapped_tool_in_a_clean_run_is_still_allowed_at_the_check
  Scenario: A run with no untrusted label is unchanged
    Given the starter policy in enforce mode
    And a run that has read nothing untrusted
    When the model asks for a tool neither map names
    Then the answer is forwarded and nothing is recorded as refused

  # @test:a_tainted_run_calling_a_classified_source_again_is_not_refused
  Scenario: A tool the source map names is classified
    Given a run that has read the web through web_search
    When the model asks for web_search again
    Then the answer is forwarded

  # @test:a_run_carrying_only_secrets_is_judged_as_before
  Scenario: A sensitivity label is not an untrusted source
    Given a run that has read a secret and nothing untrusted
    When the model asks for a tool neither map names
    Then the anti-exfiltration rule judges it exactly as before

  # @test:with_the_firewall_off_an_unmapped_tool_is_not_judged
  Scenario: The firewall switched off judges nothing
    Given the firewall is off
    When a web-tainted run asks for a tool neither map names
    Then the answer is forwarded and nothing is recorded
