Feature: The semantic cache is off unless an operator turns it on

  Shadow mode cost every eligible call a walk under one lock, whether or not
  anybody had ever asked for the cache. Defaulting to off means a deployment
  that configures nothing pays nothing for a feature it never requested.

  # @test:cache_is_off_when_nothing_is_configured
  Scenario: Nothing configured means off
    Given TOKENFUSE_CACHE is unset
    When the gateway starts
    Then the semantic cache mode is off

  # @test:every_named_cache_mode_is_honoured
  Scenario Outline: Every named value is honoured
    Given TOKENFUSE_CACHE is "<value>"
    When the gateway starts
    Then the semantic cache mode is <mode>

    Examples:
      | value  | mode   |
      | off    | off    |
      | shadow | shadow |
      | on     | on     |

  # @test:an_unrecognised_cache_value_is_off_not_a_guess
  Scenario: An unrecognised value is off, not a guess
    Given TOKENFUSE_CACHE is "enforce"
    When the gateway starts
    Then the semantic cache mode is off
    And one warning names the value it could not parse
