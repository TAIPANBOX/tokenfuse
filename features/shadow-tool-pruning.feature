Feature: Shadow tool-pruning measures and never modifies

  A denied tool offered to the model refuses the whole call today; nothing
  removes just the denied tools and forwards the rest, and nothing measures
  how many input tokens are spent on schemas of tools an agent may never use.
  This measures, in shadow only, and changes nothing about the forwarded call.

  # @test:off_makes_no_filter_call
  Scenario: The setting is off by default
    Given TOKENFUSE_TOOLS_PRUNE is unset
    When a request declaring tools reaches a gateway with the wardryx hook on
    Then the wardryx policy service never receives a filter-tools call

  # @test:shadow_pruning_never_changes_the_forwarded_body_anthropic
  # @test:shadow_pruning_never_changes_the_forwarded_body_openai
  Scenario: Shadow pruning never changes the forwarded request
    Given TOKENFUSE_TOOLS_PRUNE is shadow and a request declares three tools
    And the wardryx policy would deny one of them
    When the gateway forwards the request to the model provider, on either wire shape
    Then the body the provider receives is byte-identical to the body the caller sent

  # @test:shadow_records_the_tools_the_policy_would_remove
  Scenario: A shadow measurement is recorded and reported
    Given TOKENFUSE_TOOLS_PRUNE is shadow and a request declares three tools
    And the wardryx policy would deny one of them
    When the gateway forwards the call
    Then the trace records how many tools were offered, how many would be pruned, and their estimated token cost
    And the response carries a header with the same numbers

  # @test:a_wardryx_without_the_route_is_named_once_and_measures_nothing
  Scenario: A wardryx that predates the filter-tools route
    Given TOKENFUSE_TOOLS_PRUNE is shadow and the wardryx service answers not found on filter-tools
    When two separate requests each declare tools and are forwarded
    Then both calls succeed, nothing is measured on either, and exactly one warning names the missing route

  # @test:a_filter_outage_in_shadow_costs_only_a_warn_line
  Scenario: A filter-tools outage costs one warning and nothing else
    Given TOKENFUSE_TOOLS_PRUNE is shadow and the wardryx service answers with a server error on filter-tools
    When a request declaring tools is forwarded
    Then the call still succeeds, nothing is measured, and one warning is logged
