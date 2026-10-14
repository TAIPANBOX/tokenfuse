Feature: The FOCUS export names the price basis and the PII let through

  A FinOps tool that reads only the FOCUS export could not tell a call charged
  at the fallback from one charged at a list price, nor see PII the scanner let
  through in shadow mode: the first rode the Cloud wire alone, the second the
  trace alone.

  @decided 2026-10-14: both reach the export, appended, empty for older rows.
  Invariant 109.

  # @test:the_export_names_the_price_basis_and_the_pii_let_through
  Scenario: The export carries both columns, last
    Given a gateway scanning for PII in shadow, writing its trace to Parquet
    When one call on a listed model carries an email address and a card number
    And another call names a model the price book does not know
    Then the export's last two columns are x_price_basis and x_pii_findings
    And the first row reads known and pii_card=1,pii_email=1
    And the second reads fallback and nothing
    And neither the address nor the number appears anywhere in the file

  # @test:the_focus_export_columns_are_published_in_export_order
  Scenario: The columns are published in export order
    Then the published focus_export.columns end with x_price_basis and x_pii_findings
