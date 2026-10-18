Feature: A read of another system's data does not carry the run's private data out

  The agent-security review of 2026-10-17 found that a read tool (fetch_url,
  browse, web_search) was a source and nothing else: nothing judged what it
  sent, so a run that had read a secret or a private file could put that data
  in a URL and fetch it. The decision recorded for this wave, in English and
  without quotation: a read tool is also a network read; a run that read a
  secret cannot fetch; after private data a read is judged on what its
  arguments carry; an operator's policy file gets the floor that denies an
  unmapped tool after untrusted input; remember is a write.

  The arguments are judged at the caps in the design (512 bytes of path and
  query, no run of 64 base64 characters, at most 8 query parameters), and the
  secret and PII kinds the scanners already know. The caps are @claude, chosen
  to be the least a legitimate read needs, and open to reversal.

  # @test:read_tools_are_network_read_as_well_as_sources
  Scenario: A read tool is both a source and a network read
    Given the starter policy in enforce mode
    When the policy is asked about fetch_url, browse, web_search, http_get and fetch
    Then fetch_url, browse and web_search are sources that label their output web
    And each of fetch_url, browse and web_search exercises the capability network_read
    And http_get and fetch are named in neither map, so they are unclassified and refused after untrusted input

  # @test:anti_exfiltration_denies_a_read_after_secrets
  Scenario: A run that read a secret cannot fetch
    Given the starter policy in enforce mode
    And a run that has read a secret
    When the model asks for a network read
    Then the call is refused by anti-exfiltration with the capability network_read denied

  # @test:the_anti_exfiltration_floor_also_denies_a_read
  Scenario: A policy file that names no anti-exfiltration rule still refuses a read after secrets
    Given an operator policy file in enforce mode with a rule of its own
    When the file is loaded
    Then anti-exfiltration is back in front and denies network_read

  # @test:evaluate_never_judges_the_read_rule_on_labels_alone
  Scenario: The read rule is never refused on its labels alone
    Given a run that holds private data
    When the model asks for a network read
    Then the label alone does not refuse the call, its arguments decide

  # @test:the_starter_policy_carries_the_read_rule
  Scenario: The starter policy names the read rule over the private-data labels
    Given the starter policy in enforce mode
    Then the rule read-tool-carries-data reads file, email and memory
    And it denies network_read

  # @test:a_read_after_private_data_with_a_clean_url_is_allowed
  Scenario: A read after private data with an ordinary URL is allowed
    Given a run that has read a file
    When the model fetches a URL with a path and two query parameters
    Then the call is allowed

  # @test:a_read_after_private_data_whose_url_carries_a_secret_is_denied
  Scenario: A read after private data whose URL carries a secret is refused
    Given a run that has read a file
    When the model fetches a URL that holds an AWS access key
    Then the call is refused by read-tool-carries-data with network_read denied

  # @test:a_read_after_email_carrying_pii_is_denied_only_when_pii_blocks
  Scenario: PII in a read after private data is refused only where PII blocks
    Given a run that has read an email
    When the model fetches a URL that holds an email address
    Then the call is refused when the PII scan blocks
    And it is let through when the PII scan only observes

  # @test:the_url_cap_is_512_bytes_of_path_and_query_inclusive
  Scenario: The URL cap is 512 bytes of path and query, inclusive
    Given a run that has read a file
    When the model fetches a URL whose path and query are 512 bytes
    Then the call is allowed
    When the same URL is 513 bytes
    Then the call is refused

  # @test:an_encoded_run_of_64_characters_is_data_and_63_is_not
  Scenario: A run of 64 encoded characters in a read is data
    Given a run that has read a file
    When the model fetches a URL with 63 hexadecimal characters in a query value
    Then the call is allowed
    When the query value has 64 hexadecimal characters
    Then the call is refused

  # @test:at_most_eight_query_parameters
  Scenario: A read after private data carries at most eight query parameters
    Given a run that has read a file
    When the model fetches a URL with eight query parameters
    Then the call is allowed
    When the URL has nine
    Then the call is refused

  # @test:a_secret_nested_anywhere_in_the_arguments_is_found
  Scenario: A secret nested deep in the arguments is found
    Given a run whose prompt holds memory
    When the model's read carries a secret inside a nested argument
    Then the call is refused

  # @test:the_findings_name_the_kind_and_never_the_text
  Scenario: The findings name what the arguments carried, never the text
    Given a read whose URL holds an AWS access key
    When its arguments are judged
    Then the finding names aws_access_key
    And the key itself appears nowhere in the finding

  # @test:a_read_after_web_alone_is_not_judged_by_its_arguments
  Scenario: A read after web input alone is not judged by its arguments
    Given a run that has read only the web
    When the model fetches a URL of 700 bytes
    Then the call is allowed

  # @test:a_seeded_sweep_of_url_shapes_agrees_with_the_length_and_parameter_caps
  Scenario: Two hundred seeded URL shapes agree with the length and parameter caps
    Given a run that has read a file
    When two hundred URL shapes are judged, with seeded path lengths and parameter counts
    Then every verdict agrees with the path cap and the parameter cap written out independently

  # @test:remember_is_a_write_not_an_unmapped_tool
  Scenario: remember is a write
    Given the starter policy in enforce mode
    Then the capability of remember is write

  # @test:a_tainted_run_that_remembers_is_refused_as_a_write
  Scenario: A tainted run that remembers is refused as a write
    Given a run that has read the web
    When the model asks to remember a fact
    Then the call is refused by no-exec-after-untrusted with write denied

  # @test:an_operator_file_with_no_unmapped_rule_gets_the_untrusted_floor
  Scenario: An operator's file that names no rule for unmapped tools gets the floor
    Given an operator policy file in enforce mode that names only a secrets rule
    When the file is loaded
    Then a rule denies the unclassified capability

  # @test:the_floor_refuses_an_unmapped_tool_after_web_taint
  Scenario: The floor refuses an unmapped tool after web input
    Given an operator policy file in enforce mode that names only a secrets rule
    And a run that has read the web
    When the model asks for a tool neither map names
    Then the call is refused

  # @test:shadow_files_get_no_unmapped_floor
  Scenario: A shadow file gets no floor
    Given an operator policy file in shadow mode
    When the file is loaded
    Then no rule denies the unclassified capability

  # @test:an_operator_rule_that_already_denies_unmapped_tools_gets_no_second_floor
  Scenario: An operator's own rule for unmapped tools is not given a second one
    Given an operator policy file in enforce mode that denies unclassified after web input
    When the file is loaded
    Then exactly one rule denies the unclassified capability
