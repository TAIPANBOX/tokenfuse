Feature: An unclassified tool is named, once

  The starter policy treats the output of every tool its source map does not
  name as untrusted, under the label unclassified. An operator could not see
  which names those were, so a tool whose output was refused for that reason
  had nothing in the log that said so.

  Now the gateway names each such tool once per process, in one warning, and
  says how to classify it. The names it remembers are bounded.

  # @test:an_unclassified_tool_is_named_once_in_the_log
  Scenario: An unclassified tool is named once in the log, however often it is called
    Given the starter policy in enforce mode
    And the conversation earlier called a tool the source map does not name
    When two calls arrive that carry that tool
    Then the log names that tool exactly once
    And the warning says to classify it in the file named by TOKENFUSE_FIREWALL_CONFIG

  # @test:a_classified_tool_is_not_named
  Scenario: A tool the source map classifies is not named
    Given the starter policy in enforce mode
    And the conversation earlier called a tool the source map names
    When a call arrives that carries that tool
    Then the log names no tool

  # @test:in_shadow_an_unclassified_tool_is_named_too
  Scenario: In shadow mode an unclassified tool is named too
    Given the starter policy in shadow mode
    And the conversation earlier called a tool the source map does not name
    When a call arrives that carries that tool
    Then the log names that tool exactly once

  # @test:off_names_nothing
  Scenario: With the firewall off, no tool is named
    Given the firewall is off
    When a tool the source map does not name is seen
    Then the log names no tool

  # @test:the_names_remembered_are_capped_and_the_cap_is_said_once
  Scenario: Past the cap, names are not remembered and one line says so
    Given more distinct unclassified tool names than the process remembers
    When each of them is seen
    Then exactly the remembered number of names is logged
    And one line says that further names will not be named
    And a name seen again past the cap logs nothing
