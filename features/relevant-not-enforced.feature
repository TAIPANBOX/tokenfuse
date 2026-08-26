Feature: What this product enforces, and what it is merely relevant to

  The decision, verbatim, 2026-08-26: "3a (c)".

  That was his answer to a question with three options about ISO/IEC 23894 and
  OWASP ASI07, both of which the catalog refuses to map and both of which
  carried an argued `@claude` note saying why. Option (c) was: confirm the two
  refusals, and add a third category beside the catalog for frameworks this
  product is RELEVANT to and does not enforce. The wording of the option is
  `@claude`; the choice is his.

  Why the category needed to exist at all. A row in the catalog is a claim
  about what the CODE ENFORCES, anchored to a wire string, a finding kind or an
  incident kind this product really emits, and the module refuses to mis-cite a
  standard because mis-citing one is itself an over-claim. ISO 23894 is
  guidance on an AI risk-management PROCESS built on ISO 31000, and enforcing a
  process is not a thing code does. So there was nowhere honest to put it: in
  the catalog it is a false claim, and left out entirely it disappears, along
  with the true and useful thing beside it, which is that a customer under
  23894 can put this product's enforcement decisions in their risk file as
  evidence.

  Background:
    Given the compliance catalog and the framework lists it publishes

  # @test:iso_23894_is_relevant_and_is_not_a_control_this_product_enforces
  Scenario: A framework we enforce no part of has somewhere honest to go
    Given ISO/IEC 23894, which describes a risk-management process
    When the catalog is read
    Then 23894 is listed as a framework this product is relevant to
    And it is not in the list of frameworks this product enforces
    And no control claims it

  # @test:a_framework_is_enforced_or_merely_relevant_and_never_both
  Scenario: The two kinds can never be read as one
    Given a framework named in the relevant-not-enforced list
    When anything asks which frameworks this product enforces
    Then that framework is not among them
    And the two lists share no identifier at all, so no surface can show one as the other

  # @test:a_framework_this_product_only_relates_to_is_cited_by_no_control
  Scenario: A relevance claim cannot be promoted by citing it from a control
    Given a control in the catalog
    When it lists the external controls it maps to
    Then none of them names a framework from the relevant-not-enforced list
    Because that list would then be printed in the auditor's table beside the word covered

  # @test:every_relevant_framework_says_what_this_product_does_not_do
  Scenario: Relevance always arrives with its own limit
    Given a framework in the relevant-not-enforced list
    Then it says why a customer under it reaches for this product
    And it says what this product does not do about it
    And it says where the obligation is actually discharged
    And the list is never empty, because an empty list would satisfy all of the above and mean nothing

  # @test:the_report_presents_the_enforced_and_the_merely_relevant_apart
  Scenario: The evidence pack keeps them in separate places
    Given a compliance report generated for an auditor
    When the report is serialized
    Then the enforced frameworks and the merely relevant ones are two separate fields
    And no merely-relevant framework appears inside the enforced list

  # @test:asi07_is_still_absent_and_did_not_come_back_as_a_relevant_framework
  Scenario: A refused control does not come back as a relevance claim
    Given OWASP ASI07, refused because the agents here do not talk to each other across a trust boundary
    When the relevant-not-enforced list is read
    Then ASI07 is not in it
    Because a control this product does not have at all is not something to be relevant about
