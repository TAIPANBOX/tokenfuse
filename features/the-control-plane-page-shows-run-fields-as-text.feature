Feature: The control-plane page shows run fields as text

  A run id and a model name are chosen by whoever calls a gateway, and the
  Cloud stores them as sent. The page the Cloud serves at / puts them into the
  runs table as text, so a value that looks like markup is shown and never
  parsed in the operator's browser (CLAUDE.md invariant 102).

  # @test:the_served_page_never_parses_a_run_field_as_markup
  Scenario: A run id and a model reach the runs table as text
    Given the page the Cloud serves at /
    When it builds a row of the runs table
    Then the run id and the model are set as text on the elements it creates
    And no value from the API is assigned to the page as markup

  # @test:the_served_page_names_no_removed_key_and_calls_its_savings_all_time
  Scenario: The page names no removed key and calls its savings figure all time
    Given the page the Cloud serves at /
    When an operator reads the key field and the savings tile
    Then the key field suggests no devkey, a credential that no longer exists
    And the savings tile does not say "this month" of a total with no month boundary
